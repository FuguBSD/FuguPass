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
 * The scan helper of PROG-SCAN. fugupass-scan.c holds main() of the
 * program, and scan.c holds every other part of it. src/regress/scan.c
 * calls the same functions, so the test proves the decode that the
 * program runs.
 *
 * The program takes the Standard SeedQR form alone: 48 digits in QR
 * numeric mode, four digits for each word of the BIP39 English list
 * (PROG-SCAN-2, D-22). A code in byte mode, a digit count that is not
 * 48, and a group of four digits that names no word are each a
 * failure (PROG-SCAN-3, PROG-SCAN-10). The program computes no
 * checksum, and the master gate of KEY-MASTER-6 does.
 *
 * quirc of src/quirc decodes each frame. That directory holds the
 * license of the library and the record of its origin (PROG-QR-5,
 * PROG-BUILD-5).
 *
 * The 12 words are the master of a vault (KEY-MASTER-1), so they are
 * a secret. scan_decode() erases each buffer of its own, and the
 * caller erases the line (SEC-MEMORY-1). The residue of quirc is
 * outside this file: the decoder frees the grids and the capstones of
 * one frame without an erasure. The helper runs for one scan, and
 * the two limits of RLIMIT_CORE are zero (SEC-MEMORY-3).
 */

#ifndef SCAN_H
#define SCAN_H

#include <stdio.h>

#include "wordlist.h"

/*
 * The promises of the scan helper (PROG-SPLIT-4). The program makes
 * this pledge call after it opens the video device, and it unveils no
 * path: a child of execve(2) cannot unveil, so the core process
 * carries the video devices in its list.
 */
#define SCAN_PROMISES	"stdio video"

/* The video device of a run with no argument (PROG-SCAN-8). */
#define SCAN_DEVICE	"/dev/video"

/* The words and the digits of a Standard SeedQR (PROG-SCAN-2, D-22). */
#define SCAN_WORDS	12
#define SCAN_DIGITS	48

/*
 * The seconds of one scan (PROG-SCAN-9). The helper reads frames for
 * this time, and it then reports and gives up.
 */
#define SCAN_SECONDS	60

/*
 * The bytes of the output line: 12 words of at most WORDLIST_MAX
 * bytes, one separator after each word, and one terminator
 * (PROG-SCAN-5).
 */
#define SCAN_LINE_MAX	(SCAN_WORDS * (WORDLIST_MAX + 1) + 1)

/*
 * The outcome of one decode. Each value names one cause, so a test
 * proves the cause of a failure and not the failure alone.
 */
enum scan_result {
	SCAN_OK = 0,	/* one Standard SeedQR of 12 words */
	SCAN_MEMORY,	/* the decoder takes no memory */
	SCAN_NO_CODE,	/* the frame holds no QR code */
	SCAN_CORRUPT,	/* the decode of a code fails */
	SCAN_MODE,	/* a code is outside numeric mode (D-22) */
	SCAN_COUNT,	/* the digits are not SCAN_DIGITS (D-22) */
	SCAN_INDEX	/* four digits name no word of the list */
};

/*
 * One open frame stream: the descriptor of the device, the name of
 * it, and the frame geometry that the device gave. scan_run() fills
 * this structure from the device, and scan_frames() reads it.
 */
struct scan_stream {
	const char	*device;	/* the path, for each report */
	int		 fd;		/* the open device */
	int		 w;		/* the pixels of one row */
	int		 h;		/* the rows of one frame */
	int		 stride;	/* the bytes of one row */
	size_t		 framelen;	/* the bytes of one frame */
};

/*
 * scan_nocore():
 *	Hold the soft limit and the hard limit of RLIMIT_CORE at zero
 *	(SEC-MEMORY-3). main() of fugupass-scan.c makes this one call
 *	first, so the core limit is the first act of the program.
 *
 *	The call gives 0, and -1 on a failure. errno then names the
 *	failed call.
 */
int	scan_nocore(void);

/*
 * scan_decode(gray, w, h, line):
 *	Decode the QR codes of one frame. The frame is w by h grey
 *	bytes at gray, one byte for each pixel. The 12 words go to the
 *	SCAN_LINE_MAX bytes at line, on one line of text with one line
 *	feed and one terminator (PROG-SCAN-5).
 *
 *	The call gives SCAN_OK for a Standard SeedQR of 12 words, and
 *	it then writes line. It gives the cause of the failure for
 *	every other frame, and it then writes no byte of line. A frame
 *	of more than one code gives SCAN_OK when one code of it is such
 *	a SeedQR, and the cause of the last failed code when no code of
 *	it is.
 *
 *	The words are the master of a vault, so the caller erases line
 *	(SEC-MEMORY-1).
 */
enum scan_result	 scan_decode(const unsigned char *, int, int, char *);

/*
 * scan_strerror(result):
 *	The report text of one outcome of scan_decode(). The text
 *	names the cause, and it holds no line feed.
 */
const char		*scan_strerror(enum scan_result);

/*
 * scan_frames(st, seconds, out, err):
 *	Read frames of the open stream st for seconds seconds, and
 *	write the 12 words of the first Standard SeedQR to the stream
 *	out (PROG-SCAN-1). The loop waits for each frame with poll(2),
 *	because read(2) on video(4) takes no timeout and blocks
 *	without end. The loop gives up at that bound, and it then
 *	writes one report line to the stream err (PROG-SCAN-9).
 *	A stream that gives no frame and a stream that gives frames
 *	of no SeedQR take one report each, so the report names the
 *	cause (PROG-SCAN-13).
 *
 *	The call gives 0 on a scan, and 1 on a failure. It takes and
 *	frees the two frame buffers, and it erases each buffer of its
 *	own (SEC-MEMORY-1). It closes no descriptor of st.
 */
int			 scan_frames(const struct scan_stream *, int, FILE *,
			     FILE *);

/*
 * scan_run(device, out, err):
 *	Open the video device device, read frames of it, and write the
 *	12 words of the first Standard SeedQR to the stream out
 *	(PROG-SCAN-1). A failure writes one report line to the stream
 *	err, and a report of the device names it (PROG-SCAN-7).
 *
 *	The call opens the device, and it then pledges SCAN_PROMISES
 *	(PROG-SPLIT-4). It asks the device for the frame format, and
 *	it gives the open stream to scan_frames() for SCAN_SECONDS
 *	seconds (PROG-SCAN-9).
 *
 *	The call gives the exit status of the program: 0 on a scan, and
 *	1 on a failure. It erases each buffer of its own (SEC-MEMORY-1).
 */
int			 scan_run(const char *, FILE *, FILE *);

#endif /* SCAN_H */
