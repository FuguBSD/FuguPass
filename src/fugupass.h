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
 * The passphrase read of the core process. fugupass.c holds the
 * sandbox, the subcommand frame, and these two functions, and a
 * subcommand of that frame takes them from here.
 *
 * The passphrase enters through readpassphrase(3), from the
 * terminal (SEC-MEMORY-4, PROG-IFACE-3). No argument and no
 * environment variable carries it, so no process list and no
 * environment holds it. A creation reads it twice and needs a match
 * (CER-CREATE-4).
 *
 * The buffer of a read is a secret. A failed read clears the buffer
 * of the caller, and the caller clears that buffer after a read
 * that gives 0 (SEC-MEMORY-1). pin_secret() is the one consumer of
 * the bytes (KEY-PIN-3).
 */

#ifndef FUGUPASS_H
#define FUGUPASS_H

#include <stddef.h>

/*
 * The bytes of one passphrase, with the terminator. A passphrase
 * has no length limit in the design (KEY-PIN-1), and this value is
 * the room that the reader gives one.
 */
#define FUGUPASS_PASS_MAX	1024

/* The second passphrase of a creation is another passphrase. */
#define FUGUPASS_EMISMATCH	(-2)

/*
 * fugupass_passphrase(prompt, buf, bufsize):
 *	One passphrase of the terminal, to the bufsize bytes at buf,
 *	with a terminator. prompt stands before the read, and the
 *	terminal shows no typed byte.
 *
 *	The call gives 0, and -1 on a failure: a read that fails, a
 *	process with no terminal, an empty passphrase, and a
 *	passphrase that bufsize does not take. A failure clears buf.
 */
int	fugupass_passphrase(const char *, char *, size_t);

/*
 * fugupass_passphrase_new(buf, bufsize):
 *	One new passphrase of the terminal, to the bufsize bytes at
 *	buf, with a terminator. The call reads twice and compares the
 *	two with timingsafe_bcmp(3) (CER-CREATE-4, SEC-MEMORY-2).
 *	The second read takes a buffer of this file, so bufsize must
 *	be FUGUPASS_PASS_MAX bytes or fewer.
 *
 *	The call gives 0 for a match. It gives FUGUPASS_EMISMATCH for
 *	two different passphrases, and -1 for each failure of
 *	fugupass_passphrase(). Both outcomes clear buf, and each one
 *	clears the second buffer as well.
 */
int	fugupass_passphrase_new(char *, size_t);

/*
 * fugupass_confirm(prompt):
 *	One confirmation of the terminal. prompt stands before the
 *	read, and the terminal shows each typed byte. The call gives
 *	0 for the word yes, and -1 for every other answer and for
 *	each failure of the read.
 *
 *	A ceremony takes an explicit confirmation before it replaces
 *	the records of another machine (CER-PROVISION-3). The read
 *	takes the terminal, as a passphrase read does, so no
 *	argument and no pipe confirms in its place.
 */
int	fugupass_confirm(const char *);

#endif /* FUGUPASS_H */
