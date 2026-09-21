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
 * The helper boundary. The core process runs a helper program as a
 * child, it writes text to the standard input of that child, and it
 * reads the standard output of that child as text. Text crosses the
 * boundary, and image data crosses no pipe: the core process parses
 * no camera frame and no QR image (PROG-SPLIT-1, PROG-SPLIT-2).
 *
 * helper_path() gives the path of one helper program. The core
 * process unveils each of the three paths with the x permission
 * (PROG-SPLIT-3), so the list of the sandbox and the list of the
 * child runs come from this one function.
 *
 * HELPER_DIR names the directory of the three programs, and the
 * build gives that value. The port installs the programs there
 * (PROG-PORT-2). A regress build takes the directory from the
 * environment variable FUGUPASS_HELPERS, so a test can put a double
 * in place of a helper (PROG-SPLIT-11). src/lib/Makefile makes that
 * build, and the service build holds no such path.
 *
 * helper_run() runs one helper program and gives the text of it
 * back. The interface process needs two pipes and a whole session,
 * so PROG-IFACE takes another path than this function.
 *
 * The text of a run can be a secret: the scan helper gives the
 * master, and the render helper takes a secret on its standard
 * input (PROG-OUTPUT-2). A failed run clears the output buffer, and
 * the caller clears each buffer that it owns (SEC-MEMORY-1).
 */

#ifndef HELPER_H
#define HELPER_H

#include <stddef.h>

/* The three helper programs of the core process (PROG-SPLIT-1). */
enum helper {
	HELPER_SCAN,	/* fugupass-scan: the camera and the QR decode */
	HELPER_QR,	/* fugupass-qr: the QR render of the standard input */
	HELPER_REPL,	/* fugupass-repl: the interface process */
	HELPER_MAX
};

/*
 * helper_path(which):
 *	The path of the helper program which. The call gives NULL for
 *	a value outside the enum, and for a path that PATH_MAX does
 *	not take.
 *
 *	The path stands in a buffer of this file, one buffer for each
 *	helper. A second call of the same helper overwrites that
 *	buffer, so a caller that keeps a path copies it.
 */
const char	*helper_path(enum helper);

/*
 * helper_run(which, in, inlen, out, outsize, outlen):
 *	Run the helper program which as a child. The call writes the
 *	inlen bytes at in to the standard input of the child, and it
 *	reads the standard output of the child to the outsize bytes
 *	at out. The bytes of the answer go to outlen, and out takes a
 *	terminator after them.
 *
 *	in can be NULL, and the child then reads the end of its input
 *	at once. The answer is text, so outsize must take the answer
 *	and one terminator.
 *
 *	The call gives 0 when the child exits 0, when the whole input
 *	reaches the child, and when the answer fits. It gives -1 on
 *	every other outcome: a failed fork(2), a failed execv(3), a
 *	child that exits with another status, a child that a signal
 *	stops, an answer of more bytes than outsize takes, and an
 *	answer that holds a NUL byte. A failure clears out, and it
 *	writes 0 to outlen (SEC-MEMORY-1).
 *
 *	The caller must ignore SIGPIPE, because a child that exits
 *	early closes the pipe of its standard input. main() of
 *	fugupass.c ignores that signal.
 */
int	helper_run(enum helper, const char *, size_t, char *, size_t,
	    size_t *);

#endif /* HELPER_H */
