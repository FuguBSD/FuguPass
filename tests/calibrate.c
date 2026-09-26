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
 * The round-count timer of bcrypt_pbkdf(3) (TEST-CALIBRATE-1). The
 * program runs the KDF at each count of a fixed table, with the
 * passphrase shape of KEY-PIN-3: a 32-byte salt and a 32-byte
 * output. It prints one line per count on the standard output: the
 * count, one space, and the median wall time of RUNS runs in
 * milliseconds. clock_gettime(2) with CLOCK_MONOTONIC is the timer.
 * A failed call prints the reason on the standard error, and the
 * program exits 1.
 *
 * Build and run on OpenBSD, from the repository root:
 *
 *	cc -Wall -Wextra -Werror -o calibrate tests/calibrate.c -lutil
 *	./calibrate
 *
 * The authoritative run is on real OpenBSD hardware, the laptop of
 * the operator (TEST-CALIBRATE-4). A guest gives a shape check of
 * the curve and no count. docs/analysis/kdf-calibration.md records
 * each run, and the operator picks the default round count from
 * the hardware run (TEST-CALIBRATE-2).
 *
 * src/Makefile does not build this program, and no gate runs it
 * (PROG-BUILD). The passphrase and the salt are public constants,
 * so the program clears nothing.
 */

#include <sys/types.h>

#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <util.h>

/*
 * The table covers 16 rounds, the count of the interop harness, and
 * the counts around it, up to the count that passes about two
 * seconds on a laptop of 2026.
 */
static const unsigned int counts[] = {
	1, 2, 4, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 640
};

#define RUNS	5

static const char	 pass[] = "calibration passphrase";
static const uint8_t	 salt[] = "fugupass/v1/pin-salt/calibration";

static int
compare(const void *a, const void *b)
{
	const int64_t	*x = a, *y = b;

	return (*x > *y) - (*x < *y);
}

/* The wall time of one call at the count rounds, in nanoseconds. */
static int64_t
one_run(unsigned int rounds)
{
	struct timespec	 start, stop;
	uint8_t		 key[32];

	if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
		err(1, "clock_gettime");
	if (bcrypt_pbkdf(pass, sizeof(pass) - 1, salt, sizeof(salt) - 1,
	    key, sizeof(key), rounds) != 0)
		errx(1, "bcrypt_pbkdf failed at %u rounds", rounds);
	if (clock_gettime(CLOCK_MONOTONIC, &stop) != 0)
		err(1, "clock_gettime");

	return (int64_t)(stop.tv_sec - start.tv_sec) * 1000000000LL +
	    (int64_t)(stop.tv_nsec - start.tv_nsec);
}

int
main(void)
{
	int64_t		 ns[RUNS];
	size_t		 i, run;

	for (i = 0; i < sizeof(counts) / sizeof(counts[0]); i++) {
		for (run = 0; run < RUNS; run++)
			ns[run] = one_run(counts[i]);
		qsort(ns, RUNS, sizeof(ns[0]), compare);
		printf("%u %.1f\n", counts[i], (double)ns[RUNS / 2] / 1e6);
	}

	return 0;
}
