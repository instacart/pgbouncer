/*
 * PgBouncer - Lightweight connection pooler for PostgreSQL.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Query logging
 */

#include "bouncer.h"

#include <errno.h>
#include <sys/file.h>
#include <time.h>

#define LOG_BUFFER_SIZE 1024 * 1024 * 2 /* 2 MB */

/* File id to prevent accidental collision, appended to file name such as 'pktlog.001' */
/*
 * Each file contains a chunk of the memory buffer, in an indexed manner
 * This allows to the pgbouncer to always be able to write to a new file (in flight write),
 * whereas the replayer is still consuming the previously files.
 *
 * The replayer knows the file is ready by it's name - pgbouncer atomicly rename the file
 * after flushing.
 *
 * To tweak the ingestion we can adjust the chunk size, the time between flushes
 * and the number os files.
 *
 *  - chunk size:
 *     - lower bound concerns: this also controls the biggest query
 *       we could log, so it's wise to big at least 2mb
 *     - upper bound: this is the biggest amount of space in tmpfs, which is in the ram
 *       2mb * 1024 files equals to 2gb
 *
 * - time between flushes: lower intervals have lower latency for replay,
 *       but also use more cpu time - the amount of bytes written per second
 *       should not be affected by the flush interval,
 *       unless the cpu becomes the bottleneck ~ flushing every 1ms
 *
 * - number of files: the biggest, the more tolerant pgbouncer is with
 *       the replayer lagging behind, the total time is calculated by
 *       number of files * time between flushes
 *
 *       i.e.
 *            256 * 100ms = 25.6 seconds [space: 2mb * 256 = 512mb]
 *            256 * 50ms = 12.8 seconds
 *            1024 * 25ms = 25.6 seconds
 *            4096 * 25ms = 102.4 seconds [space: 2mb * 4096 = 8gb]
 *            24 * 50ms = 1.2 seconds [space: 2mb * 24 = 48mb]
 */
#define FILE_ID_MAX 24
static uint16_t file_id = 0;

static const char *reload_command = "RELOAD";
static const char connect_char = '!';
static const char fragment_char = '*';

/* Flush packets 4 times per second - every 250ms */
static struct timeval buffer_drain_period = {0, USEC / 4};
static struct event buffer_drain_ev;

/* The buffer */
static char *buf = NULL;
static size_t len = 0;

static void log_flush_buffer(void);
static void log_shutdown(void);
static void log_init(void);
void log_buffer_flush_cb(evutil_socket_t sock, short flags, void *arg);
static bool log_ensure_buffer_space(uint32_t n);

/*
 * Flush the buffer every .1 of a second
 */
void log_setup(void) {
  if (event_assign(&buffer_drain_ev, pgb_event_base, -1, EV_PERSIST, log_buffer_flush_cb, NULL) == -1) {
    log_info("Could not assign event: %s", strerror(errno));
    return;
  }

  if (event_add(&buffer_drain_ev, &buffer_drain_period) == -1) {
    log_info("Could not schedule event: %s", strerror(errno));
    return;
  }
}

/*
 * Initialize the packet logger.
 */
void log_init(void) {
  if (buf != NULL)
    return;

  /* Allocate the buffer */
  buf = malloc(LOG_BUFFER_SIZE);

  if (buf == NULL) {
    log_info("Could not allocate packet logging buffer");
    return;
  }

  memset(buf, 0, LOG_BUFFER_SIZE);
  len = 0;

  log_info("Packet logging initialized");
}


/*
 * Shutdown the packet logger.
 */
static void log_shutdown(void) {
  if (buf == NULL)
    return;

  /* Free mem */
  free(buf);
  buf = NULL;
  len = 0;

  log_info("Packet logging shut down");
}

/*
 * Log reload command to buffer.
 */
void log_reload_to_buffer(void) {
  log_noise("log_reload_to_buffer");

  if (cf_shutdown)
    return;

  uint32_t ignored_field = 0,
           reload_strlen = strlen(reload_command) + 1, /* add terminator to keep compliant with Postgres */
           pkt_len = sizeof(uint8_t) + sizeof(uint32_t) + reload_strlen,
           net_pkt_len = htonl(pkt_len);

  uint8_t pkt_type = 0;

  log_noise("log_reload_to_buffer: log_ensure_buffer_space");
  uint32_t total_packet_size = sizeof(ignored_field) + /* net_client_id (ignored) */
                               sizeof(ignored_field) + /* net_packet_id (ignored) */
                               sizeof(ignored_field) + /* net_query_interval (ignored) */
                               pkt_len +
                               sizeof(char) +
                               pkt_len +
                               sizeof(uint8_t);

  if (!log_ensure_buffer_space(total_packet_size))
    return;

  log_noise("log_reload_to_buffer: writing net_client_id (ignored)");
  memcpy(buf + len, &ignored_field, sizeof(ignored_field));
  len += sizeof(ignored_field);

  log_noise("log_reload_to_buffer: writing net_packet_id (ignored)");
  memcpy(buf + len, &ignored_field, sizeof(ignored_field));
  len += sizeof(ignored_field);

  log_noise("log_reload_to_buffer: writing net_query_interval (ignored)");
  memcpy(buf + len, &ignored_field, sizeof(ignored_field));
  len += sizeof(ignored_field);

  log_noise("log_reload_to_buffer: writing net_buf_size");
  memcpy(buf + len, &net_pkt_len, sizeof(net_pkt_len));
  len += sizeof(net_pkt_len);

  log_noise("log_pkt_to_buffer: writing pkt_type (ignored)");
  memcpy(buf + len, &pkt_type, sizeof(pkt_type));
  len += sizeof(pkt_type);

  log_noise("log_pkt_to_buffer: writing net_pkt_len");
  memcpy(buf + len, &net_pkt_len, sizeof(net_pkt_len));
  len += sizeof(net_pkt_len);

  log_noise("log_pkt_to_buffer: writing payload ('RELOAD')");
  strncpy(buf + len, reload_command, reload_strlen);
  len += reload_strlen;

  log_info("Sent RELOAD command to replayer");
}

void log_connect_to_buffer(bool connected, PgSocket *client) {
  log_noise("log_connect_to_buffer");

  if (cf_shutdown)
    return;

  if (connected) // interested only in disconnections
    return;

  uint32_t net_client_id = htonl(client->client_id),
           ignored_field = 0,
           pkt_len = sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint8_t), /* type, len, flag */
           net_pkt_len = htonl(pkt_len);

  uint8_t connected_value = connected ? 1 : 0;

  log_noise("log_connect_to_buffer: log_ensure_buffer_space");
  uint32_t total_packet_size = sizeof(net_client_id) +
                               sizeof(ignored_field) + /* net_packet_id (ignored) */
                               sizeof(ignored_field) + /* net_query_interval (ignored) */
                               pkt_len +
                               sizeof(char) +
                               pkt_len +
                               sizeof(uint8_t);

  if (!log_ensure_buffer_space(total_packet_size))
    return;

  log_noise("log_connect_to_buffer: writing net_client_id");
  memcpy(buf + len, &net_client_id, sizeof(net_client_id));
  len += sizeof(net_client_id);

  log_noise("log_connect_to_buffer: writing net_packet_id (ignored)");
  memcpy(buf + len, &ignored_field, sizeof(ignored_field));
  len += sizeof(ignored_field);

  log_noise("log_connect_to_buffer: writing net_query_interval (ignored)");
  memcpy(buf + len, &ignored_field, sizeof(ignored_field));
  len += sizeof(ignored_field);

  log_noise("log_connect_to_buffer: writing net_buf_size");
  memcpy(buf + len, &net_pkt_len, sizeof(net_pkt_len));
  len += sizeof(net_pkt_len);

  log_noise("log_connect_to_buffer: writing pkt_type (connect_char)");
  memcpy(buf + len, &connect_char, sizeof(char));
  len += sizeof(char);

  log_noise("log_connect_to_buffer: writing net_pkt_len");
  memcpy(buf + len, &net_pkt_len, sizeof(net_pkt_len));
  len += sizeof(net_pkt_len);

  log_noise("log_connect_to_buffer: writing connected_value");
  memcpy(buf + len, &connected_value, sizeof(uint8_t));
  len += sizeof(uint8_t);
}

/* Log only supported packets.
 * P - prepared statement
 * B - bind params to prepared statement
 * E - execute prepared statement
 * Q - query, execute immediately
 */
bool log_is_packet_type_supported(PktHdr *pkt) {
  switch (pkt->type) {
    case 'E':
    case 'Q':
    case 'P':
    case 'B':
      break;
    default:
      return false;
  }
  return true;
}


/*
 * Log packet fragment (i.e. any subsequent parts that comes after the header)
 */
void log_pkt_fragment_to_buffer(struct SBuf *sbuf) {
  log_noise("log_pkt_fragment_to_buffer");

  /* If the bouncer is shutting down, the buffer is gone. */
  if (cf_shutdown)
    return;

  /*
    packet format:

    field      client_id   packet_id   query_interval  buf_len   pkt_type   pkt_len    pkt_payload
    size       [4]         [4]         [4]             [4]       [1]        [4]        {buf_len - 4 - 1}
  */

  uint32_t buf_size = sbuf->io->recv_pos;
  uint32_t net_client_id = htonl(sbuf->client_id);
  uint32_t net_packet_id = htonl(sbuf->packet_id);
  uint32_t net_buf_size = htonl(buf_size);
  uint32_t ignored_field = 0;

  if (cf_log_packets_debug) {
    log_info("--[fragment]-------");
    uint32_t hex_size = (buf_size * 2) + 1; // two char per byte, plus terminator
    char hex[hex_size]; 
    bin2hex(sbuf->io->buf, buf_size, hex, sizeof(hex));
    log_info("   client_id:  %u", sbuf->client_id);
    log_info("   packet_id:  %u", sbuf->packet_id);
    log_info("   buf_size:   %u", buf_size);
    log_info("   data:       %s", hex);
    log_info("   ascii:      %s", sbuf->io->buf);
    log_info("-------------------");
  }

  /* Buffer full, drop the packet logging on the floor.
   * No logging since this function is called for each incoming packet.
   *
   * pkt->len = packet size
   * + 16 bytes of metadata
   */
  log_noise("log_pkt_fragment_to_buffer: log_ensure_buffer_space");

  uint32_t total_packet_size = sizeof(net_client_id) +
                               sizeof(net_packet_id) +
                               sizeof(ignored_field) + /* net_query_interval (ignored) */
                               sizeof(net_buf_size) +
                               sizeof(char) +
                               buf_size;

  if (!log_ensure_buffer_space(total_packet_size))
    return;

  log_noise("log_pkt_fragment_to_buffer: writing net_client_id");
  memcpy(buf + len, &net_client_id, sizeof(net_client_id));
  len += sizeof(net_client_id);

  log_noise("log_pkt_fragment_to_buffer: writing net_packet_id");
  memcpy(buf + len, &net_packet_id, sizeof(net_packet_id));
  len += sizeof(net_packet_id);

  log_noise("log_pkt_fragment_to_buffer: writing net_query_interval (ignored)");
  memcpy(buf + len, &ignored_field, sizeof(ignored_field));
  len += sizeof(ignored_field);

  log_noise("log_pkt_fragment_to_buffer: writing net_buf_size");
  memcpy(buf + len, &net_buf_size, sizeof(net_buf_size));
  len += sizeof(net_buf_size);

  log_noise("log_connect_to_buffer: writing pkt_type (fragment_char)");
  memcpy(buf + len, &fragment_char, sizeof(char));
  len += sizeof(char);

  log_noise("log_pkt_fragment_to_buffer: writing pkt fragment");
  memcpy(buf + len, sbuf->io->buf, buf_size);
  len += buf_size;
}

/*
 * Log packet into the buffer.
 */
void log_pkt_to_buffer(PktHdr *pkt, PgSocket *client) {
  log_noise("log_pkt_to_buffer");

  /* If the bouncer is shutting down, the buffer is gone. */
  if (cf_shutdown)
    return;

  /*
    packet format:

    field      client_id   packet_id   query_interval  buf_len   pkt_type   pkt_len    pkt_payload
    size       [4]         [4]         [4]             [4]       [1]        [4]        {buf_len - 4 - 1}
  */

  bool is_incomplete = incomplete_pkt(pkt);
  uint32_t buf_size = mbuf_written(&pkt->data);
  uint32_t data_size = buf_size;
  if (!is_incomplete) {
    buf_size -= 1;  // ignore terminator
    data_size -= 4 + 1;  // ignore len (4 bytes) and type (1 byte)
  }
  
  uint32_t net_client_id = htonl(client->client_id);
  uint32_t net_packet_id = htonl(client->sbuf.packet_id);
  uint32_t net_buf_size = htonl(buf_size);
  uint32_t query_interval = 0, net_query_interval;
  

  if (cf_log_packets_debug) {
    log_info("--[header]---------");
    log_info("   client_id:  %u", client->client_id);
    log_info("   packet_id:  %u", client->sbuf.packet_id);
    log_info("   pkt type:   %c", pkt->type);
    log_info("   pkt len:    %u", pkt->len);
    log_info("   buf size:   %u", buf_size);
    log_info("   data size:  %u", data_size);
    log_info("   incomplete: %u", is_incomplete);

    uint32_t hex_size = (data_size * 2) + 1; // two char per byte, plus terminator
    char hex[hex_size]; 
    bin2hex(pkt->data.data + pkt->data.read_pos, data_size, hex, sizeof(hex));

    // log prevent the entire packet from printing, it will chop at ~2000 bytes
    log_info("   data:       %s", hex);
    log_info("   ascii:      %s", (pkt->data.data + pkt->data.read_pos));
    log_info("-------------------");
  }

  /*
  log_noise("log_pkt_to_buffer: checking for incomplete_pkt");
  if (incomplete_pkt(pkt))
    return;
  */

  if (!log_is_packet_type_supported(pkt)) {
    return;
  }

  /* Buffer full, drop the packet logging on the floor.
   * No logging since this function is called for each incoming packet.
   *
   * pkt->len = packet size
   * + 16 bytes of metadata
   */
  log_noise("log_pkt_to_buffer: log_ensure_buffer_space");

  uint32_t total_packet_size = sizeof(net_client_id) +
                               sizeof(net_packet_id) +
                               sizeof(net_query_interval) +
                               sizeof(net_buf_size) +
                               buf_size;

  if (!log_ensure_buffer_space(total_packet_size))
    return;

  /* record intervals between packets */
  log_noise("log_pkt_to_buffer: calc interval");
  if (client->last_pkt > 0) {
    usec_t query_interval_usec = get_cached_time() - client->last_pkt;

    if (query_interval_usec > UINT32_MAX) {
      query_interval = UINT32_MAX; /* up to about an hour between queries */
    } else {
      query_interval = (uint32_t)query_interval_usec;
    }
  }
  client->last_pkt = get_cached_time();

  net_query_interval = htonl(query_interval);

  log_noise("log_pkt_to_buffer: writing net_client_id");
  memcpy(buf + len, &net_client_id, sizeof(net_client_id));
  len += sizeof(net_client_id);

  log_noise("log_pkt_to_buffer: writing net_packet_id");
  memcpy(buf + len, &net_packet_id, sizeof(net_packet_id));
  len += sizeof(net_packet_id);

  log_noise("log_pkt_to_buffer: writing net_query_interval");
  memcpy(buf + len, &net_query_interval, sizeof(net_query_interval));
  len += sizeof(net_query_interval);

  log_noise("log_pkt_to_buffer: writing net_buf_size");
  memcpy(buf + len, &net_buf_size, sizeof(net_buf_size));
  len += sizeof(net_buf_size);

  log_noise("log_pkt_to_buffer: writing pkt data");
  memcpy(buf + len, pkt->data.data, buf_size);
  len += buf_size;
}

/*
 * Check if we have space in the buffer to append n bytes - if we don't, disable logging
 */
static bool log_ensure_buffer_space(uint32_t n) {
  if (len + n > LOG_BUFFER_SIZE) {
    log_info("Warning - Buffer full - current buffer size: %zu, bytes required: %u", len, n);
    return false;
  }
  return true;
}


/*
 * Check if the files we are going to touch dont exist - if they do, disable logging
 */
/*
static bool log_ensure_file_dont_exist(char *file) {
  struct stat info;
  if (stat(file, &info) != -1) {
    char time[50];
    strftime(time, 50, "%Y-%m-%d %H:%M:%S", localtime(&info.st_mtime));
    log_info("Warning - Packet log file exists: %s, size: %lld bytes, modified_at: %s", file, info.st_size, time);
    return false;
  }
  return true;
}
*/



/*
 * Flush the packets to disk.
 *
 * Since the log files will be read by a different process, it uses the file name to communicate state.
 *
 * This process always write to the next available file_id, and rotate to 0 when it reaches the max value.
 *
 * During the write, a file named 'pktlog.000.w' will be filled with the buffer, after done flushing,
 * the file get renamed to 'pktlog.000' indicating it's ready to be consumed.
 * 
 * After consumption, the process consuming the log files needs to remove them
 * from the directory to allow the name reuse after rotation.
 */
static void log_flush_buffer(void) {
  int fd;

  /* Don't waste time on an empty buffer - no traffic on the bouncer */
  if (len < 1)
    return;

  /* In-flight write file */
  char next_fname[strlen(cf_log_packets_file)+9];   /* .001.w */
  snprintf(next_fname, strlen(cf_log_packets_file)+9, "%s.%05d.w", cf_log_packets_file, file_id);

  /* Available file */
  char next_fname_available[strlen(cf_log_packets_file) + 7];   /* .001 */
  snprintf(next_fname_available, strlen(cf_log_packets_file)+7, "%s.%05d", cf_log_packets_file, file_id);

  /* Check both files */
  /*
  This is commented to allow pgbouncer to overwrite existing files
  It means we may lose packets, but we guarantee the buffer is being flushed (other wise it will be kept full and stop logging anyways)
  */
  // if (!log_ensure_file_dont_exist(next_fname))
  //  return;

  // if (!log_ensure_file_dont_exist(next_fname_available))
  //  return; 

  fd = open(next_fname, O_EXCL | O_APPEND | O_CREAT | O_WRONLY, S_IWUSR | S_IRUSR);
  if (fd == -1) {
    log_info("Could not open packet log file: %s", strerror(errno));
    return;
  }

  /* Flush the packets to the log file */
  write(fd, buf, len);

  /* Close the log file */
  fsync(fd);
  close(fd);

  log_noise("Flushed %lu bytes to packet log file: %s", len, next_fname);

  /* Clear the buffer since it's an append buffer */
  memset(buf, 0, len);
  len = 0;

  if (rename(next_fname, next_fname_available) != 0) {
      log_info("Error: unable to rename file '%s' to '%s'", next_fname, next_fname_available);
  }
  else {
    log_noise("Renamed '%s' to '%s'", next_fname, next_fname_available);
  }

  /* Increment file id */
  if (file_id == FILE_ID_MAX)
    file_id = 0;
  else
    file_id++;
}

/*
 * Callback for the event loop.
 */
void log_buffer_flush_cb(evutil_socket_t sock, short flags, void *arg) {
  /* Handle shutdown (best-effort since we are not the only event) */
  if (cf_shutdown && cf_log_packets) {
    log_flush_buffer();
    log_shutdown();
  }

  /* Handle enabled packet logging */
  else if (cf_log_packets) {
    if (buf == NULL)
      log_init();

    if (len > 0)
      log_flush_buffer();
  }

  /* Handle packet logging being disabled */
  else {
    if (buf != NULL) {
      log_flush_buffer();
      log_shutdown();
    }
  }
}
