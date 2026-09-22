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
 * The interactive session of the core process. iface.h states the
 * interface.
 *
 * session_open() runs first, so the passphrase enters the core
 * process through the terminal, before a child of it exists
 * (PROG-REPL-1, PROG-IFACE-3). The spawn follows, and the interface
 * process owns the terminal at the prompt (PROG-IFACE-4).
 *
 * The request loop reads one line of the request pipe, it splits
 * that line into the argument list of one command, and it gives the
 * list to commands_run() of commands.h (PROG-IFACE-12,
 * PROG-ONESHOT-2). Each output record of the command takes the sink
 * of this file, and the sink writes one reply line (PROG-IFACE-13).
 * One end line follows the records, and it carries the outcome of
 * the command (PROG-IFACE-11).
 *
 * No secret crosses the two pipes (PROG-IFACE-3). A secret goes from
 * the core process to the terminal, and the report of a failure goes
 * to the standard error of the core process (PROG-OUTPUT-1).
 *
 * poll(2) measures the idle time of the session: the stdio promise
 * of the pledge covers that call, and a wait of poll(2) needs no
 * signal handler (PROG-SPLIT-3). A deadline with no request line
 * locks the session (PROG-REPL-7).
 *
 * The lock closes the reply pipe, and session_close() clears every
 * session secret (SEC-MEMORY-1). The closed pipe ends the interface
 * process, and the session waits for it (PROG-IFACE-6).
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "commands.h"
#include "helper.h"
#include "iface.h"
#include "session.h"
#include "vault.h"

/* The two descriptors of the interface process (PROG-IFACE-10). */
#define REQUEST_FD	3
#define REPLY_FD	4

/*
 * The frame of the reply pipe (PROG-IFACE-11). A reply line carries
 * one output record after LINE_TAG, and one end line carries the
 * outcome of the command.
 */
#define LINE_TAG	'>'
#define END_OK		"=ok\n"
#define END_FAIL	"=fail\n"

/*
 * The bytes of one request line and of one output record, without
 * the line feed. A record comes from one line of a vault file, and a
 * request line names an entry of such a line, so both take the line
 * of VAULT-FORMAT-5. That line counts the line feed inside its
 * 4096 bytes, so the text of it takes one byte less
 * (PROG-IFACE-12).
 */
#define TEXT_MAX	(VAULT_LINE_MAX - 1)

/*
 * The words of one request line. A command takes one -f option per
 * row of a field table, and that option and its value are two words.
 * The rest of a command line takes the eight words above that count
 * (PROG-ONESHOT-8).
 */
#define WORD_MAX	(2 * VAULT_TABLE_MAX + 8)

/* The outcome of one read of the request pipe. */
enum request {
	REQUEST_LINE,	/* one request line, at the buffer of the caller */
	REQUEST_LONG,	/* a line that the buffer of the caller does not take */
	REQUEST_IDLE,	/* the timeout with no request line */
	REQUEST_END	/* the end of the request pipe, and a failure */
};

/* The interface process of one session, and the request pipe of it. */
struct iface {
	pid_t	 pid;			/* the interface process */
	int	 request;		/* the read end of the request pipe */
	int	 reply;			/* the write end of the reply pipe */
	char	 buf[TEXT_MAX + 1];	/* the bytes of the request pipe */
	size_t	 len;			/* the bytes at buf */
	int	 drop;			/* a line of more than TEXT_MAX bytes */
};

/*
 * The reply pipe of the session, for record(). commands_sink() takes
 * a function of one record, and that function reads this descriptor.
 * The core process runs one session at a time, so one descriptor
 * serves it.
 */
static int	 reply_fd = -1;

/* A failed write of the reply pipe. The request loop then ends. */
static int	 reply_fail;

static int		 write_all(int, const char *, size_t);
static void		 record(const char *);
static int		 spawn(struct iface *);
static int		 ready(int, const struct timespec *);
static enum request	 request_read(struct iface *, unsigned int, char *,
			     size_t);
static int		 split(char *, char **, int);

/*
 * write_all(fd, data, len):
 *	The len bytes at data, to the descriptor fd. write(2) can
 *	take a part of them, so the loop continues with the rest. The
 *	call gives 0 for the whole write, and -1 for a failure.
 */
static int
write_all(int fd, const char *data, size_t len)
{
	ssize_t	 n;
	size_t	 at = 0;

	while (at < len) {
		n = write(fd, data + at, len - at);
		if (n == -1) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		at += (size_t)n;
	}
	return 0;
}

/*
 * record(text):
 *	One output record of a command, as one reply line of the
 *	reply pipe (PROG-IFACE-11, PROG-IFACE-13). commands_sink() of
 *	commands.h takes this function for the session.
 *
 *	The line holds the tag, the record, and the line feed. A
 *	record holds no line feed of its own, because it comes from
 *	one line of a vault file (VAULT-FORMAT-5). record() of
 *	commands.c bounds the record at that same line, so the buffer
 *	below takes each record of this sink. The check of the
 *	snprintf(3) below guards that buffer alone.
 *
 *	A failed write leaves the flag of this file, and the request
 *	loop then ends the session. The sink reports no failure to
 *	the command, because the standard output of a one-shot
 *	subcommand reports none either.
 */
static void
record(const char *text)
{
	char	 line[TEXT_MAX + 3];
	int	 n;

	if (reply_fd == -1 || reply_fail)
		return;
	n = snprintf(line, sizeof(line), "%c%s\n", LINE_TAG, text);
	if (n < 0 || (size_t)n >= sizeof(line)) {
		warnx("the record of the command does not fit one reply line");
		reply_fail = 1;
		return;
	}
	if (write_all(reply_fd, line, (size_t)n) != 0)
		reply_fail = 1;
}

/*
 * spawn(ifc):
 *	Start the interface process with the two pipes of
 *	PROG-IFACE-10: the write end of the request pipe on the
 *	descriptor 3, and the read end of the reply pipe on the
 *	descriptor 4. The parent keeps the other end of each pipe.
 *
 *	The two pipes carry the close-on-exec flag, and dup2(2)
 *	clears that flag on the new descriptor. The dup(2) loops
 *	first move each end above the two numbers of the protocol, so
 *	neither dup2(2) call takes the end of the other one away, and
 *	each new descriptor differs from its source. closefrom(2)
 *	then closes every other descriptor of the child.
 *
 *	The call gives 0, and -1 for a failed pipe and a failed fork.
 *	A failed exec gives no failure here: the child exits 127, and
 *	the closed request pipe ends the session.
 */
static int
spawn(struct iface *ifc)
{
	const char	*path;
	char		*argv[2];
	pid_t		 pid;
	int		 req[2], rep[2], w, r;

	if ((path = helper_path(HELPER_REPL)) == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (pipe2(req, O_CLOEXEC) == -1)
		return -1;
	if (pipe2(rep, O_CLOEXEC) == -1) {
		close(req[0]);
		close(req[1]);
		return -1;
	}

	argv[0] = (char *)path;
	argv[1] = NULL;
	if ((pid = fork()) == -1) {
		close(req[0]);
		close(req[1]);
		close(rep[0]);
		close(rep[1]);
		return -1;
	}
	if (pid == 0) {
		w = req[1];
		r = rep[0];
		while (w <= REPLY_FD) {
			if ((w = dup(w)) == -1)
				_exit(127);
		}
		while (r <= REPLY_FD) {
			if ((r = dup(r)) == -1)
				_exit(127);
		}
		if (dup2(w, REQUEST_FD) == -1 || dup2(r, REPLY_FD) == -1)
			_exit(127);
		closefrom(REPLY_FD + 1);
		execv(path, argv);
		_exit(127);
	}

	close(req[1]);
	close(rep[0]);
	ifc->pid = pid;
	ifc->request = req[0];
	ifc->reply = rep[1];
	return 0;
}

/*
 * ready(fd, deadline):
 *	Wait for a byte of the descriptor fd, until the deadline of
 *	the monotonic clock. The call gives 1 for a readable
 *	descriptor, 0 at the deadline, and -1 for a failure.
 *
 *	poll(2) takes the milliseconds of the wait as an int, so a
 *	long timeout takes more than one call of it. A signal ends a
 *	wait as well, and the loop then waits for the rest of the
 *	time.
 */
static int
ready(int fd, const struct timespec *deadline)
{
	struct pollfd	 pfd;
	struct timespec	 now, left;
	int		 ms, n;

	pfd.fd = fd;
	pfd.events = POLLIN;
	for (;;) {
		if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
			return -1;
		if (timespeccmp(&now, deadline, >=))
			return 0;
		timespecsub(deadline, &now, &left);
		if (left.tv_sec >= INT_MAX / 1000)
			ms = INT_MAX;
		else
			ms = (int)(left.tv_sec * 1000 +
			    left.tv_nsec / 1000000);
		if ((n = poll(&pfd, 1, ms)) == -1) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n != 0)
			return 1;
	}
}

/*
 * request_read(ifc, timeout, out, outsize):
 *	One request line of the request pipe, without the line feed,
 *	to the outsize bytes at out (PROG-IFACE-11).
 *
 *	The wait starts at this call, so the timeout seconds measure
 *	the time with no request line (PROG-REPL-7). The buffer of
 *	ifc keeps the bytes after that line for the next call.
 *
 *	REQUEST_LINE gives one line at out. REQUEST_LONG names a line
 *	of more bytes than the two buffers take, and the call drops
 *	that line whole. REQUEST_IDLE names the timeout, and
 *	REQUEST_END names the end of the pipe and a failure.
 */
static enum request
request_read(struct iface *ifc, unsigned int timeout, char *out, size_t outsize)
{
	struct timespec	 deadline;
	char		*nl;
	ssize_t		 n;
	size_t		 linelen, rest;
	int		 drop;

	if (clock_gettime(CLOCK_MONOTONIC, &deadline) == -1)
		return REQUEST_END;
	deadline.tv_sec += timeout;

	for (;;) {
		if ((nl = memchr(ifc->buf, '\n', ifc->len)) != NULL) {
			linelen = (size_t)(nl - ifc->buf);
			rest = ifc->len - linelen - 1;
			drop = ifc->drop || linelen >= outsize;
			if (!drop) {
				memcpy(out, ifc->buf, linelen);
				out[linelen] = '\0';
			}
			memmove(ifc->buf, nl + 1, rest);
			ifc->len = rest;
			ifc->drop = 0;
			return drop ? REQUEST_LONG : REQUEST_LINE;
		}

		/*
		 * A full buffer without a line feed holds a line of
		 * more bytes than one request line takes. The bytes
		 * of it go, and the flag drops the rest of that line
		 * as well.
		 */
		if (ifc->len == sizeof(ifc->buf)) {
			ifc->drop = 1;
			ifc->len = 0;
		}

		switch (ready(ifc->request, &deadline)) {
		case 1:
			break;
		case 0:
			return REQUEST_IDLE;
		default:
			return REQUEST_END;
		}
		n = read(ifc->request, ifc->buf + ifc->len,
		    sizeof(ifc->buf) - ifc->len);
		if (n == -1) {
			if (errno == EINTR)
				continue;
			return REQUEST_END;
		}
		if (n == 0)
			return REQUEST_END;
		ifc->len += (size_t)n;
	}
}

/*
 * split(line, argv, max):
 *	Split the request line line at each space and at each tab,
 *	and give the words of it to argv (PROG-IFACE-12). argv takes
 *	max words and the NULL after the last one, and the call
 *	writes a terminator into line after each word.
 *
 *	The call gives the count of the words, and -1 for a line of
 *	more than max words.
 */
static int
split(char *line, char **argv, int max)
{
	int	 argc = 0;

	for (;;) {
		line += strspn(line, " \t");
		if (*line == '\0')
			break;
		if (argc == max)
			return -1;
		argv[argc++] = line;
		line += strcspn(line, " \t");
		if (*line != '\0')
			*line++ = '\0';
	}
	argv[argc] = NULL;
	return argc;
}

int
iface_session(const char *vault)
{
	const struct vault_config	*cfg;
	struct iface			 ifc;
	struct session			*s = NULL;
	char				 line[TEXT_MAX + 1];
	char				*argv[WORD_MAX + 1];
	const char			*end;
	unsigned int			 timeout;
	int				 argc, status, done = 0, rv = 0;

	memset(&ifc, 0, sizeof(ifc));
	if (session_open(vault, &s) != 0)
		return 1;

	cfg = session_config(s);
	timeout = cfg != NULL && cfg->lock_timeout != 0 ? cfg->lock_timeout :
	    IFACE_LOCK_TIMEOUT_DEFAULT;

	if (spawn(&ifc) != 0) {
		warn("the interface process");
		session_close(s);
		return 1;
	}
	reply_fail = 0;
	reply_fd = ifc.reply;
	commands_sink(record);

	while (!done) {
		switch (request_read(&ifc, timeout, line, sizeof(line))) {
		case REQUEST_LINE:
			argc = split(line, argv, WORD_MAX);
			if (argc == -1)
				warnx("the request line holds more than %d "
				    "words", WORD_MAX);
			else if (argc == 0)
				warnx("the request line holds no command");
			end = argc > 0 && commands_run(s, argc, argv) == 0 ?
			    END_OK : END_FAIL;
			break;
		case REQUEST_LONG:
			warnx("the request line holds more than %d bytes",
			    VAULT_LINE_MAX);
			end = END_FAIL;
			break;
		case REQUEST_IDLE:
			warnx("the session locks: %u seconds with no request",
			    timeout);
			end = NULL;
			break;
		default:
			end = NULL;
			break;
		}

		/*
		 * The end line closes the reply of one request
		 * (PROG-IFACE-11). A failed write of it, and a failed
		 * write of a record, each name an interface process
		 * that ended, so the session locks as well.
		 */
		if (end == NULL || reply_fail ||
		    write_all(ifc.reply, end, strlen(end)) != 0)
			done = 1;
	}

	/*
	 * The lock (PROG-REPL-7). The closed reply pipe ends the
	 * interface process, and session_close() clears every session
	 * secret (SEC-MEMORY-1, PROG-IFACE-6).
	 */
	commands_sink(NULL);
	reply_fd = -1;
	close(ifc.reply);
	close(ifc.request);
	session_close(s);
	if (waitpid(ifc.pid, &status, 0) == -1 || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0)
		rv = 1;
	return rv;
}
