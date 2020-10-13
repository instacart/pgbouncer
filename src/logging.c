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

#include <sys/file.h>
#include <errno.h>

#define LOG_BUFFER_SIZE 1024 * 1024 /* 1 MB */
#define MAX_LOG_FILE_SIZE 1024 * 1024 * 25 /* 25 MB; if we get this far, the replayer isn't doing its job */

/* Flush packets to log every 0.1 of a second */
static struct timeval buffer_drain_period = {0, USEC / 10};
static struct event buffer_drain_ev;

/* The buffer */
static char *buf = NULL;
static size_t len = 0;

static void log_flush_buffer(void);
static void log_touch(void);
void log_buffer_flush_cb(evutil_socket_t sock, short flags, void *arg);

/*
 * Initialize the packet logger.
 */
void log_init(void) {
  if (buf != NULL) {
    return;
  }

  /* Allocate the buffer */
  buf = malloc(LOG_BUFFER_SIZE);
  memset(buf, 0, LOG_BUFFER_SIZE);
  len = 0;

  /* Flush the buffer every .1 of a second */
  event_assign(&buffer_drain_ev, pgb_event_base, -1, EV_PERSIST, log_buffer_flush_cb, NULL);
  event_add(&buffer_drain_ev, &buffer_drain_period);

  log_info("Packet logging initialized");
}


/*
 * Shutdown the packet logger.
 */
void log_shutdown(void) {
  if (buf == NULL) {
    return;
  }

  /* Flush the buffer */
  log_flush_buffer();

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
  /* Buffer full, drop the packet logging on the floor.
   * No logging since this function is called very often.
   * This would happen because the buffer isn't being drained, 
   * which has a log line already.
   *
   * pkt->len = packet size
   * + 5 bytes of metadata
   */
  if (len + pkt->len + sizeof(uint32_t) > LOG_BUFFER_SIZE) {
    return;
  }

  /* Log only supported packets.
   *
   * P - prepared statement
   * B - bind params to prepared statement
   * E - execute prepared statement
   * Q - query, execute immediately
   */
  switch(pkt->type) {
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
   * packet    - pkt->len bytes, raw
   * delimiter - 1 byte, 0x19 (EM)
   **/
  uint32_t net_ci = htonl(client->client_id);
  memcpy(buf + len, &net_ci, sizeof(uint32_t));
  memcpy(buf + len + sizeof(uint32_t), pkt->data.data, pkt->len);
  buf[len + sizeof(uint32_t) + pkt->len] = '\x19';
  len += (pkt->len + 5);
}

/*
 * Flush the packets to disk.
 */
static void log_flush_buffer(void) {
  int tmp_fd, fd;
  struct stat info;
  char tmp_fname[strlen(cf_log_packets_file)+6];

  /* Don't waste time on an empty buffer - no traffic on the bouncer */
  if (len < 1) {
    return;
  }

  if (stat(cf_log_packets_file, &info) != -1) {
    if (info.st_size > MAX_LOG_FILE_SIZE) {
      log_info("Dropping packet logging: packet log file %s is %lld bytes which is too large", cf_log_packets_file, info.st_size);
      return;
    }
  }

  /* No log file, the replayer is not doing it's job correctly */
  else {
    log_info("Could not stat log file %s: %s", cf_log_packets_file, strerror(errno));
    log_touch();
  }

  /*
   * Get a shared lock on a .lock file.
   * The replayer takes an exclusive lock on this file and prevents
   * us from opening up the file descriptor for the time it takes it to rename
   * the file. This forces us to write to a new log file.
   */
  snprintf(tmp_fname, strlen(cf_log_packets_file) + 6, "%s.lock", cf_log_packets_file);
  tmp_fd = open(tmp_fname, O_CREAT, S_IWUSR | S_IRUSR);
  if (flock(tmp_fd, LOCK_SH | LOCK_NB) == -1) {
    log_info("Could not acquire lock file for packet logging: %s", strerror(errno));

    /* Try again in .1 of a second */
    return;
  }

  /* Open the log file in append mode */
  fd = open(cf_log_packets_file, O_APPEND | O_CREAT | O_WRONLY, S_IWUSR | S_IRUSR);
  if (fd == -1) {
    log_info("Could not open packet log file: %s", strerror(errno));
    return;
  }

  /* Flush the packets to the log file */
  write(fd, buf, len);

  /* Close the log file and release the lock file */
  fsync(fd);
  close(fd);
  flock(tmp_fd, LOCK_UN);
  close(tmp_fd);

  log_info("Flushed %lu bytes to packet log buffer", len);

  /* Clear the buffer since it's an append buffer */
  memset(buf, 0, len);
  len = 0;
}

/*
 * Touch the log file (or create it).
 */
static void log_touch(void) {
  /* Touch the logfile */
  int fd = open(cf_log_packets_file, O_APPEND | O_CREAT | O_WRONLY, S_IWUSR | S_IRUSR);
  if (fd != -1) {
    close(fd);
  }
}

/*
 * Callback for the event loop.
 */
void log_buffer_flush_cb(evutil_socket_t sock, short flags, void *arg) {
  /* Flush packets to file */
  log_flush_buffer();
}
