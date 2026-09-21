/*
 * Copyright (c) 2026 Dick Olsson <hi@senzilla.io>
 *
 * Permission to use, copy, modify, and distribute this software for any
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
 * The child run of one helper program: two pipes, one fork(2), and
 * one execv(3). helper.h states the interface.
 *
 * The parent polls the two pipes together. A one-way loop deadlocks
 * on a child that answers before it reads the whole input, and the
 * render helper takes a whole vault file on its standard input
 * (PROG-QR-3). poll(2) therefore drives the write and the read of
 * one run.
 *
 * The two pipes carry the close-on-exec flag, and dup2(2) clears
 * that flag on the new descriptor. The child therefore holds its
 * standard input and its standard output, and it holds no other end
 * of a pipe. A failed exec gives no answer: the child exits 127,
 * and the parent reads that status.
 *
 * This file starts a child of PROG-SPLIT-1, and it knows no
 * argument and no protocol of a helper. The caller reads the text
 * of the answer.
 */

#include <sys/types.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "helper.h"

/*
 * The directory of the three installed programs. src/lib/Makefile
 * gives the value, under LOCALBASE (PROG-PORT-2), and a build
 * without that value stops here.
 */
#ifndef HELPER_DIR
#error HELPER_DIR must name the directory of the helper programs
#endif

/* The file name of each helper, in the order of the enum. */
static const char *const helper_file[HELPER_MAX] = {
	"fugupass-scan",
	"fugupass-qr",
	"fugupass-repl"
};

static const char	*helper_dir(void);

/*
 * helper_dir():
 *	The directory of the three helper programs. The build gives
 *	it as HELPER_DIR. A regress build takes the value of
 *	FUGUPASS_HELPERS in place of it, so a test can put a double
 *	in place of a helper (PROG-SPLIT-11). A relative value names
 *	a directory of the working directory of the moment, so the
 *	call takes an absolute value only.
 */
static const char *
helper_dir(void)
{
#ifdef FUGUPASS_REGRESS
	const char	*dir;

	if ((dir = getenv("FUGUPASS_HELPERS")) != NULL && dir[0] == '/')
		return dir;
#endif
	return HELPER_DIR;
}

const char *
helper_path(enum helper which)
{
	static char	path[HELPER_MAX][PATH_MAX];
	int		len;

	if ((unsigned int)which >= HELPER_MAX)
		return NULL;
	len = snprintf(path[which], sizeof(path[which]), "%s/%s",
	    helper_dir(), helper_file[which]);
	if (len < 0 || (size_t)len >= sizeof(path[which]))
		return NULL;
	return path[which];
}

int
helper_run(enum helper which, const char *in, size_t inlen, char *out,
    size_t outsize, size_t *outlen)
{
	struct pollfd	 pfd[2];
	const char	*path;
	char		*argv[2];
	char		 extra = '\0';
	pid_t		 pid = -1, done;
	ssize_t		 n;
	size_t		 len = 0, sent = 0;
	int		 inpipe[2], outpipe[2];
	int		 nfds, ri, wi, rfd, wfd, status;
	int		 eof = 0, rv = -1;

	*outlen = 0;
	if (out == NULL || outsize == 0)
		return -1;
	if (in == NULL)
		inlen = 0;
	if ((path = helper_path(which)) == NULL) {
		explicit_bzero(out, outsize);
		return -1;
	}
	if (pipe2(inpipe, O_CLOEXEC) == -1) {
		explicit_bzero(out, outsize);
		return -1;
	}
	if (pipe2(outpipe, O_CLOEXEC) == -1) {
		close(inpipe[0]);
		close(inpipe[1]);
		explicit_bzero(out, outsize);
		return -1;
	}

	argv[0] = (char *)path;
	argv[1] = NULL;

	/*
	 * The write end of the parent takes O_NONBLOCK. A blocking
	 * write of more than PIPE_BUF bytes waits for the whole
	 * input, and a child that fills the answer pipe stops
	 * reading: the two processes then wait for each other. The
	 * child holds the other end of the pipe, and that end keeps
	 * the blocking mode of it.
	 */
	if (fcntl(inpipe[1], F_SETFL, O_NONBLOCK) == -1 ||
	    (pid = fork()) == -1) {
		close(inpipe[0]);
		close(inpipe[1]);
		close(outpipe[0]);
		close(outpipe[1]);
		explicit_bzero(out, outsize);
		return -1;
	}
	if (pid == 0) {
		/*
		 * dup2(2) clears the close-on-exec flag of the new
		 * descriptor, so the two standard descriptors of the
		 * child stay open over the exec.
		 */
		if (dup2(inpipe[0], STDIN_FILENO) == -1 ||
		    dup2(outpipe[1], STDOUT_FILENO) == -1)
			_exit(127);
		execv(path, argv);
		_exit(127);
	}

	close(inpipe[0]);
	close(outpipe[1]);
	wfd = inpipe[1];
	rfd = outpipe[0];
	if (inlen == 0) {
		close(wfd);
		wfd = -1;
	}

	while (eof == 0) {
		nfds = 0;
		wi = -1;
		if (wfd != -1) {
			pfd[nfds].fd = wfd;
			pfd[nfds].events = POLLOUT;
			wi = nfds++;
		}
		ri = nfds;
		pfd[nfds].fd = rfd;
		pfd[nfds].events = POLLIN;
		nfds++;

		if (poll(pfd, nfds, INFTIM) == -1) {
			if (errno == EINTR)
				continue;
			break;
		}

		/*
		 * A child that exits early leaves the write end with
		 * EPIPE. The run then fails, because the child took a
		 * part of the input only.
		 */
		if (wi != -1 && pfd[wi].revents != 0) {
			n = write(wfd, in + sent, inlen - sent);
			if (n == -1) {
				if (errno != EINTR && errno != EAGAIN) {
					close(wfd);
					wfd = -1;
				}
			} else {
				sent += (size_t)n;
				if (sent == inlen) {
					close(wfd);
					wfd = -1;
				}
			}
		}

		if (pfd[ri].revents == 0)
			continue;

		/*
		 * The last byte of out takes the terminator. With no
		 * room left, one more byte of the child ends the run,
		 * and the end of the stream ends it as well.
		 */
		if (len + 1 == outsize) {
			n = read(rfd, &extra, 1);
			if (n == -1 && (errno == EINTR || errno == EAGAIN))
				continue;
			if (n != 0)
				break;
			eof = 1;
			break;
		}
		n = read(rfd, out + len, outsize - 1 - len);
		if (n == -1) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			break;
		}
		if (n == 0) {
			eof = 1;
			break;
		}
		len += (size_t)n;
	}

	if (wfd != -1)
		close(wfd);
	close(rfd);

	while ((done = waitpid(pid, &status, 0)) == -1 && errno == EINTR)
		;

	if (done == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
	    eof != 0 && sent == inlen && memchr(out, '\0', len) == NULL) {
		out[len] = '\0';
		*outlen = len;
		rv = 0;
	} else
		explicit_bzero(out, outsize);

	explicit_bzero(&extra, sizeof(extra));
	return rv;
}
