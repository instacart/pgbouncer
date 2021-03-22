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
  log_info("log_setup");

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
  log_info("log_init");

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
  log_info("log_shutdown");

  if (buf == NULL)
    return;

  /* Free mem */
  free(buf);
  buf = NULL;
  len = 0;

  log_info("Packet logging shut down");
}



/*
 * Log packet into the buffer.
 */
void log_pkt_to_buffer(PktHdr *pkt, PgSocket *client) {
  uint32_t net_client_id = htonl(client->client_id);

  log_info("log_pkt_to_buffer");

  /* If the bouncer is shutting down, the buffer is gone. */
  if (cf_shutdown)
    return;

  log_info("log_pkt_to_buffer: checking for incomplete_pkt");

  if (incomplete_pkt(pkt))
    return;

  /* Buffer full, drop the packet logging on the floor.
   * No logging since this function is called for each incoming packet.
   */
  log_info("log_pkt_to_buffer: checking for log_ensure_buffer_space");
  if (!log_ensure_buffer_space(sizeof(net_client_id) + 4 + pkt->len))
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

  log_info("log_pkt_to_buffer: writing net_client_id");

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

  log_info("log_pkt_to_buffer: writing interval (0)");

  memcpy(buf + len, 0, 4);
  len += 4;

  log_info("log_pkt_to_buffer: writing pkt->data.data");

  memcpy(buf + len, pkt->data.data, pkt->len);
  len += pkt->len;
}

/*
 * Check if we have space in the buffer to append n bytes
 */
static bool log_ensure_buffer_space(uint32_t n) {
  log_info("log_ensure_buffer_space");
  if (len + n > LOG_BUFFER_SIZE) {
    log_info("Warning - Buffer full - current buffer size: %zu, bytes required: %u", len, n);
    return false;
  }
  return true;
}

/*
 * Check if the files we are going to touch dont exist
 */
static bool log_ensure_file_dont_exist(char *file) {
  log_info("log_ensure_file_dont_exist");
  struct stat info;
  if (stat(file, &info) != -1) {
    char time[50];
    strftime(time, 50, "%Y-%m-%d %H:%M:%S", localtime(&info.st_mtime));
    log_info("Warning - Packet log file exists: %s, size: %lld bytes, modified_at: %s", file, info.st_size, time);
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
  char next_fname[strlen(cf_log_packets_file)+9];   /* .00001.w */
  snprintf(next_fname, strlen(cf_log_packets_file)+9, "%s.%05d.w", cf_log_packets_file, file_id);

  /* Available file */
  char next_fname_available[strlen(cf_log_packets_file) + 7];   /* .00001 */
  snprintf(next_fname_available, strlen(cf_log_packets_file)+7, "%s.%05d", cf_log_packets_file, file_id);

  /* Check both files */
  /*
  This is commented to allow pgbouncer to overwrite existing files
  It means we may lose packets, but we guarantee the buffer is being flushed (other wise it will be kept full and stop logging anyways)
  */

  if (!log_ensure_file_dont_exist(next_fname))
    return;

  if (!log_ensure_file_dont_exist(next_fname_available))
    return;

  fd = open(next_fname, O_EXCL | O_CREAT | O_WRONLY, S_IWUSR | S_IRUSR);
  if (fd == -1) {
    log_info("Could not open packet log file: %s", strerror(errno));
    return;
  }

  /* Flush the packets to the log file */
  write(fd, buf, len);

  /* Close the log file */
  fsync(fd);
  close(fd);

  // log_info("Flushed %lu bytes to packet log file: %s", len, next_fname);

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
  log_info("log_buffer_flush_cb");

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
