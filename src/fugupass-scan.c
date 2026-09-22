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
 * fugupass-scan, the scan helper of PROG-SPLIT-1. The program reads
 * frames of one video device, it decodes a Standard SeedQR of them,
 * and it writes the 12 words of that code to the standard output
 * (PROG-SCAN-1, PROG-SCAN-5).
 *
 * scan.c holds the sandbox, the capture and the decode, and
 * src/regress/scan.c reads the same functions. This file holds main()
 * alone, so the test proves the code that this program runs.
 *
 * The program takes at most one argument: the path of the video
 * device (PROG-SCAN-8). The core process runs it with no argument,
 * through helper.h, and that boundary passes text on the two pipes
 * alone.
 */

#include <err.h>
#include <stdio.h>

#include "scan.h"

int
main(int argc, char *argv[])
{
	const char	*device = SCAN_DEVICE;

	/*
	 * The core limit comes first, before the command line: no
	 * crash of this program writes the master to a core file
	 * (SEC-MEMORY-3). The pledge call of PROG-SPLIT-4 comes after
	 * the open of the device, inside scan_run().
	 */
	if (scan_nocore() != 0)
		err(1, "the core limit of fugupass-scan");
	if (argc == 2)
		device = argv[1];
	else if (argc != 1)
		errx(1, "usage: %s [device]", argv[0]);
	return scan_run(device, stdout, stderr);
}
