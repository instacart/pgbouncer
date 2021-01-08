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
#define FILE_ID_MAX 255
static uint8_t file_id = 0;

static const char *reload_command = "RELOAD";
static const char connect_char = '!';

/* Flush packets to log every 0.1 of a second */
static struct timeval buffer_drain_period = {0, USEC / 10};
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
  /* reload command len + pkt length + type */
  int reload_len = strlen(reload_command);
  uint32_t pkt_len = htonl(reload_len + sizeof(uint32_t));

  /* Reload again if you don't see changes because of this */
  if (!log_ensure_buffer_space(reload_len + sizeof(uint32_t))) {
    log_info("Can't issue RELOAD command to replayer, buffer full");
    return;
  }

  /* empty client id */
  memset(buf + len, 0, sizeof(uint32_t));
  len += sizeof(uint32_t);

  /* 0 interval */
  memset(buf + len, 0, sizeof(uint32_t));
  len += sizeof(uint32_t);

  /* no type */
  memset(buf + len, 0, sizeof(char));
  len += sizeof(char);

  /* length of the reload command */
  memcpy(buf + len, &pkt_len, sizeof(uint32_t));
  len += sizeof(uint32_t);

  /* reload itself */
  strncpy(buf + len, reload_command, reload_len);
  len += reload_len;

  log_info("Sent RELOAD command to replayer");
}

void log_connect_to_buffer(bool connected, PgSocket *client) {
  uint32_t net_client_id = htonl(client->client_id),
           query_interval = 0, net_query_interval,
           pkt_len = sizeof(uint8_t) + sizeof(uint32_t),
           net_pkt_len = htonl(pkt_len);

  if (cf_shutdown)
    return;

  if (!log_ensure_buffer_space(sizeof(net_client_id) + sizeof(net_query_interval) + sizeof(char) + pkt_len))
    return;

  if (client->last_pkt > 0 && !connected) {
    usec_t query_interval_usec = get_cached_time() - client->last_pkt;

    if (query_interval_usec > UINT32_MAX) {
      query_interval = UINT32_MAX; /* up to about an hour between queries */
    } else {
      query_interval = (uint32_t)query_interval_usec;
    }
  }

  net_query_interval = htonl(query_interval);

  memcpy(buf + len, &net_client_id, sizeof(net_client_id));
  len += sizeof(net_client_id);

  memcpy(buf + len, &net_query_interval, sizeof(net_query_interval));
  len += sizeof(net_query_interval);

  memcpy(buf + len, &connect_char, sizeof(char));
  len += sizeof(char);

  memcpy(buf + len, &net_pkt_len, sizeof(net_pkt_len));
  len += sizeof(net_pkt_len);

  memcpy(buf + len, &connected, sizeof(uint8_t));
  len += sizeof(uint8_t);
}

/*
 * Log packet into the buffer.
 */
void log_pkt_to_buffer(PktHdr *pkt, PgSocket *client) {
  uint32_t net_client_id = htonl(client->client_id),
           query_interval = 0, net_query_interval;

  /* If the bouncer is shutting down, the buffer is gone. */
  if (cf_shutdown)
    return;

  /* record intervals between packets */
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
  /* Buffer full, drop the packet logging on the floor.
   * No logging since this function is called for each incoming packet.
   *
   * pkt->len = packet size
   * + 16 bytes of metadata
   */
  if (!log_ensure_buffer_space(sizeof(net_client_id) + sizeof(net_query_interval) + pkt->len))
    return;

  /* Log only supported packets.
   * P - prepared statement
   * B - bind params to prepared statement
   * E - execute prepared statement
   * Q - query, execute immediately
   */
  switch (pkt->type) {
    case 'E':
    case 'Q':
    case 'P':
    case 'B':
      break;
    default:
      return;
  }

  /*
   * Write the packet to the log file.
   *
   * Format:
   *
   * client_id - 4 bytes, unsigned
   * interval    4 bytes, unsigned
   * packet    - pkt->len bytes, raw
   *             first byte of the packet is the type
   *             next 4 bytes of the packet are the length
   */
  memcpy(buf + len, &net_client_id, sizeof(net_client_id));
  len += sizeof(net_client_id);

  memcpy(buf + len, &net_query_interval, sizeof(net_query_interval));
  len += sizeof(net_query_interval);

  memcpy(buf + len, pkt->data.data, pkt->len);
  len += pkt->len;
}

/*
 * Check if we have space in the buffer to append n bytes - if we don't, disable logging
 */
static bool log_ensure_buffer_space(uint32_t n) {
  if (len + n > LOG_BUFFER_SIZE) {
    log_info("Warning - Disabled packet logging, buffer full - current buffer size: %zu, bytes required: %u", len, n);
    cf_log_packets = 0;
    log_shutdown();
    return false;
  }
  return true;
}

/*
 * Check if the files we are going to touch dont exist - if they do, disable logging
 */
static bool log_ensure_file_dont_exist(char *file) {
  struct stat info;
  if (stat(file, &info) != -1) {
    char time[50];
    strftime(time, 50, "%Y-%m-%d %H:%M:%S", localtime(&info.st_mtime));
    log_info("Warning - Disabled packet logging, packet log file exists: %s, size: %lld bytes, modified_at: %s", file, info.st_size, time);
    cf_log_packets = 0;
    log_shutdown();
    return false;
  }
  return true;
}

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
  char next_fname[strlen(cf_log_packets_file)+7];   /* .001.w */
  snprintf(next_fname, strlen(cf_log_packets_file)+7, "%s.%03d.w", cf_log_packets_file, file_id);

  /* Available file */
  char next_fname_available[strlen(cf_log_packets_file) + 5];   /* .001 */
  snprintf(next_fname_available, strlen(cf_log_packets_file)+5, "%s.%03d", cf_log_packets_file, file_id);

  /* Check both files */
  if (!log_ensure_file_dont_exist(next_fname))
    return;

  if (!log_ensure_file_dont_exist(next_fname_available))
    return;

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

  log_info("Flushed %lu bytes to packet log file: %s", len, next_fname);

  /* Clear the buffer since it's an append buffer */
  memset(buf, 0, len);
  len = 0;

  if (rename(next_fname, next_fname_available) != 0) {
      log_info("Error: unable to rename file '%s' to '%s'", next_fname, next_fname_available);
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
