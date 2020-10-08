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

#define LOG_BUFFER_SIZE 1024 * 1024 /* 1 MB */
#define MAX_LOG_FILE_SIZE 1024 * 1024 * 25 /* 25 MB; if we get this far, the replayer isn't doing its job */

/* Flush packets to log every 0.1 of a second */
static struct timeval buffer_drain_period = {0, USEC / 10};
static struct event buffer_drain_ev;

/* The buffer */
static char *buf;
static size_t len;

static void log_flush_buffer(void);
void log_buffer_flush_cb(evutil_socket_t sock, short flags, void *arg);

/*
 * Initialize the packet logger.
 */
void log_init() {
  buf = malloc(LOG_BUFFER_SIZE);
  len = 0;

  /* Touch the logfile */
  int fd = open(cf_log_packets_file, O_APPEND | O_CREAT | O_WRONLY, S_IWUSR | S_IRUSR);
  if (fd != -1) {
    close(fd);
  }

  /* launch buffer flusher */
  event_assign(&buffer_drain_ev, pgb_event_base, -1, EV_PERSIST, log_buffer_flush_cb, NULL);
  event_add(&buffer_drain_ev, &buffer_drain_period);

  log_info("Packet logging initialized.");
}


/*
 * Shutdown the packet logger.
 */
void log_shutdown() {
  log_flush_buffer(); /* Flush */
  free(buf);
  len = 0;

  log_info("Packet logging shut down.");
}

/*
 * Log packet into the buffer.
 */
void log_pkt_to_buffer(PktHdr *pkt, PgSocket *client) {
  /* Buffer full, drop the packet logging on the floor */
  if (len + pkt->len + 5 > LOG_BUFFER_SIZE) {
    return;
  }

  /* Log only supported packets */
  switch(pkt->type) {
    case 'E':
    case 'Q':
    case 'P':
    case 'B':
      break;
    default:
      return;
  }

  /* Copy the packet into our buffer, along with client_id & delimeter. */
  uint32_t net_ci = htonl(client->client_id);
  memcpy(buf + len, &net_ci, 4);
  memcpy(buf + len + 4, pkt->data.data, pkt->len);
  buf[len + 4 + pkt->len] = '\x19';
  len += (pkt->len + 5);
}

/*
 * Flush the packets to disk.
 */
static void log_flush_buffer() {
  int tmp_fd, fd;
  char tmp_fname[strlen(cf_log_packets_file)+6];
  snprintf(tmp_fname, strlen(cf_log_packets_file) + 6, "%s.lock", cf_log_packets_file);

  /* acquire a lock on our lock file */
  tmp_fd = open(tmp_fname, O_CREAT | O_SHLOCK, S_IWUSR | S_IRUSR);

  /* open our log file append only */
  fd = open(cf_log_packets_file, O_APPEND | O_CREAT | O_WRONLY, S_IWUSR | S_IRUSR);

  /* flush the buffer */
  write(fd, buf, len);

  /* close our file and release the lock */
  fsync(fd);
  close(fd);
  close(tmp_fd);

  log_info("Flushed %lu bytes to packet log buffer", len);

  /* Clear the buffer */
  memset(buf, 0, len);
  len = 0;
}

/*
 * Callback for the event loop.
 */
void log_buffer_flush_cb(evutil_socket_t sock, short flags, void *arg) {
  if (len > 0) {
    struct stat info;

    if (stat(cf_log_packets_file, &info)) {
      log_info("Could not stat %s logfile. Dropping packet logging on the floor", cf_log_packets_file);
      return;
    }

    if (info.st_size > MAX_LOG_FILE_SIZE) {
      log_info("Packet log file %s is %lld bytes which is too large. Dropping packet logging on the floor", cf_log_packets_file, info.st_size);
      return;
    }

    log_flush_buffer();
  }
}
