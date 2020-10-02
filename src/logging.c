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

/* log a client packet to a file */
void log_client_pkt(PktHdr *pkt, const char *fname)
{
  int tmp_fd, fd;
  char tmp_fname[strlen(fname)+5];
  char pkt_sep[] = {'\x19'};
  snprintf(tmp_fname, strlen(fname) + 6, "%s.lock", fname);

  /* acquire a lock on our lock file */
  tmp_fd = open(tmp_fname, O_CREAT | O_EXLOCK, S_IWUSR | S_IRUSR);

  /* open our log file append only */
  fd = open(fname, O_APPEND | O_CREAT | O_WRONLY, S_IWUSR | S_IRUSR);

  /* write the packet; the data includes the packet type */
  write(fd, pkt->data.data, pkt->len);
  /* write out packet separator */
  write(fd, &pkt_sep, 1);

  /* close our file and release the lock */
  fsync(fd);
  close(fd);
  close(tmp_fd);
}
