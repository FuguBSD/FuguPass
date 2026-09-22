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
 * fugupass-qr, the render helper of PROG-SPLIT-1. The program reads
 * the standard input and writes one QR code to the standard output,
 * in UTF-8 half blocks (PROG-QR-1).
 *
 * qr.c holds the sandbox and the render, and src/regress/qr.c reads
 * the same two functions. This file holds main() alone, so the test
 * proves the code that this program runs.
 *
 * The program takes no argument and no option. The core process
 * runs it through helper.h, and that boundary passes text on the
 * two pipes alone.
 */

#include <err.h>
#include <stdio.h>

#include "qr.h"

int
main(int argc, char *argv[])
{
	/*
	 * The sandbox comes first, before the command line: the core
	 * limit of SEC-MEMORY-3 is the first act of this program,
	 * and the pledge of PROG-SPLIT-5 is the second one.
	 */
	if (qr_sandbox() != 0)
		err(1, "the sandbox of fugupass-qr");
	if (argc != 1)
		errx(1, "usage: %s", argv[0]);
	return qr_run(stdin, stdout, stderr);
}
