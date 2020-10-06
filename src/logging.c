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

#define LOG_BUFFER_SIZE 1024 * 1024 * 1024 /* 1 MB */

/* do full maintenance 10x per second */
static struct timeval buffer_drain_period = {0, USEC / 10};
static struct event buffer_drain_ev;

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
void log_pkt_to_buffer(PktHdr *pkt) {
  /* Buffer full, drop the packet logging on the floor */
  if (len + pkt->len + 1 > LOG_BUFFER_SIZE) {
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

  /* Copy the packet into our buffer */
  memcpy(buf + len, pkt->data.data, pkt->len);
  buf[len + pkt->len] = '\x19';
  len += (pkt->len + 1);
}

/*
 * Flush the packets to disk.
 */
static void log_flush_buffer() {
  int tmp_fd, fd;
  const char *fname = "/tmp/pktlog";
  char tmp_fname[strlen(fname)+6];
  snprintf(tmp_fname, strlen(fname) + 6, "%s.lock", fname);

  /* acquire a lock on our lock file */
  tmp_fd = open(tmp_fname, O_CREAT | O_EXLOCK, S_IWUSR | S_IRUSR);

  /* open our log file append only */
  fd = open(fname, O_APPEND | O_CREAT | O_WRONLY, S_IWUSR | S_IRUSR);

  /* "client id" */
  // write(fd, &client->query_start, 8); /* 8 bytes 64 bit integer */

  /* flush the buffer */
  write(fd, buf, len);

  /* close our file and release the lock */
  fsync(fd);
  close(fd);
  close(tmp_fd);

  /* Clear the buffer */
  memset(buf, 0, len);
  len = 0;
}

/*
 * Callback for the event loop.
 */
void log_buffer_flush_cb(evutil_socket_t sock, short flags, void *arg) {
  if (len > 0) {
    log_info("Flushed packet log buffer.");
    log_flush_buffer();
  }
}
