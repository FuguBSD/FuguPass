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
 * The render helper of PROG-QR. fugupass-qr.c holds main() of the
 * program, and qr.c holds every other part of it. src/regress/qr.c
 * calls the same two functions, so the test proves the sandbox and
 * the render that the program runs.
 *
 * The bytes on the standard input decide the shape (PROG-QR-7). A
 * mnemonic takes the Standard SeedQR form of PROG-QR-6: version 2,
 * level L, numeric mode, and mask pattern 0. Every other input is a
 * vault file, and it takes the shape of PROG-QR-8.
 *
 * libqrencode of the ports tree makes each code (PROG-QR-5), and it
 * picks a mask by penalty score. qr.c therefore re-masks a mnemonic
 * code to pattern 0.
 *
 * The bytes on the standard input can be a secret: the words of a
 * mnemonic are the master of the vault (PROG-OUTPUT-2). qr_run()
 * erases each buffer of its own on every exit path (SEC-MEMORY-1).
 * The render reaches the terminal, and that is the one output of
 * the secret (PROG-OUTPUT-1).
 */

#ifndef QR_H
#define QR_H

#include <stdio.h>

/* The promises of the render helper (PROG-SPLIT-5). */
#define QR_PROMISES	"stdio"

/* The light modules on each side of a code (PROG-QR-9). */
#define QR_QUIET	4

/*
 * The bytes of the one-code capacity (PROG-QR-8). A longer input
 * is a report, and no code (PROG-QR-3, VAULT-BACKUP-4).
 */
#define QR_VAULT_MAX	2953

/* The words and the digits of a Standard SeedQR (PROG-QR-6, D-22). */
#define QR_WORDS	12
#define QR_DIGITS	48

/* The version of a mnemonic code, and its modules on each side. */
#define QR_MNEMONIC_VERSION	2
#define QR_MNEMONIC_WIDTH	25

/*
 * qr_sandbox():
 *	The sandbox of the render helper. The call sets RLIMIT_CORE
 *	to zero, and it then pledges QR_PROMISES (SEC-MEMORY-3,
 *	PROG-SPLIT-5). main() of fugupass-qr.c makes this one call
 *	first, so the core limit is the first act of the program.
 *
 *	The call gives 0, and -1 on a failure. errno then names the
 *	failed call.
 */
int	qr_sandbox(void);

/*
 * qr_run(in, out, err):
 *	Read the stream in to its end, and write the QR code of
 *	those bytes to the stream out, in UTF-8 half blocks
 *	(PROG-QR-1). A failure writes one report line to the stream
 *	err.
 *
 *	The call gives the exit status of the program: 0 on a pass,
 *	and 1 on a failure. An input of more than QR_VAULT_MAX bytes
 *	is such a failure, and the report of it names that bound
 *	(PROG-QR-3).
 *
 *	Every failure of the input and of the encode comes before
 *	the first write, so such a failure leaves out empty. A
 *	failed write to out is the one failure that can leave a part
 *	of a code there.
 *
 *	The call erases each buffer of its own before it gives back
 *	(SEC-MEMORY-1).
 */
int	qr_run(FILE *, FILE *, FILE *);

#endif /* QR_H */
