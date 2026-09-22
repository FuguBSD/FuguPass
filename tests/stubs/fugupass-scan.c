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
 * The double of the scan helper. The real fugupass-scan reads the
 * camera and decodes a SeedQR, and this program prints the fixed
 * test master of tests/vectors/derive.h (TEST-KAT-4). A ceremony of
 * the interop harness therefore needs no camera and no plate.
 *
 * The core process runs a helper as a child, and it reads one line
 * of the standard output of that child (PROG-SPLIT-2). This program
 * writes that one line, and it exits 0.
 *
 * The unveil list of the core process holds the path of this double
 * with the x permission, and with no r permission (PROG-SPLIT-3).
 * The list reaches this child, and an interpreter reads the program
 * text of a script. A shell script therefore cannot stand here, and
 * this double is a compiled program. tests/harness builds it in the
 * guest, into the directory that FUGUPASS_HELPERS names
 * (PROG-SPLIT-11).
 *
 * The test master is a public constant of the tests, so this file
 * holds no secret and clears nothing.
 */

#include <stdio.h>

#include "vectors/derive.h"

int
main(void)
{
	if (printf("%s\n", KAT_TEST_MASTER) < 0)
		return 1;
	return fflush(stdout) == 0 ? 0 : 1;
}
