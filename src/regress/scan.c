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
 * The tests of the scan helper (PROG-SCAN, TEST-KAT-3, SEC-MEMORY-3).
 * scan.c of the directory above holds the sandbox and the decode, and
 * fugupass-scan.c calls the same functions. This test therefore reads
 * the code that the program runs.
 *
 * No probe opens a camera. Each probe rasterizes one picture of
 * tests/vectors/seedqr into a grey image of one byte for each pixel,
 * with a quiet zone of 4 light modules on each side, and it gives
 * that image to scan_decode(). A dark module is the byte 0x00, and a
 * light module is the byte 0xff. One module takes one pixel, so the
 * image is the smallest one that carries the code.
 *
 * The three negative pictures each decode as a QR code, and each one
 * fails for a cause of its own: the Compact SeedQR is byte mode, the
 * 24-word SeedQR holds 96 digits, and the last one holds four digits
 * above 2047. Each probe reads the cause and not the failure alone,
 * so a gate that disappears cannot pass a probe by another gate.
 *
 * setrlimit(2) holds for the life of a process, so the core-limit
 * probe runs in a child of its own.
 *
 * No probe opens a camera, so the probe of the scan bound gives the
 * frame loop the read end of a pipe. The write end of that pipe
 * stays open and carries no byte, so the descriptor never holds a
 * frame and a read of it blocks without end. That probe runs in a
 * child of its own as well, and the parent kills a child that the
 * bound of PROG-SCAN-9 does not end.
 *
 * The program prints nothing on a pass, and it exits 0. A wrong value
 * prints the probe to the standard error, and the program exits 1.
 *
 * The 12 words below are public test data, so this test clears
 * nothing.
 */

#include <sys/types.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <limits.h>
#include <paths.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "scan.h"
#include "wordlist.h"

/* The directory of the pictures, from the build. */
#ifndef SEEDQR_DIR
#error "SEEDQR_DIR must name the directory of the pictures"
#endif

/*
 * The light modules on each side of the raster. The plan of this
 * change asks for 4, and the SeedQR form carries that quiet zone.
 */
#define QUIET		4

/* The largest picture side that a probe reads, in modules. */
#define PICTURE_MAX	64

/* The largest raster side, in pixels. */
#define RASTER_MAX	(PICTURE_MAX + 2 * QUIET)

/*
 * The words and the digits of a Standard SeedQR, as literals.
 * SCAN_WORDS and SCAN_DIGITS of scan.h are values under test, so a
 * probe must not read them. PROG-SCAN-2 and D-22 state these counts.
 */
#define WORDS		12
#define DIGITS		48

/*
 * The 12 words and the 48 digits of test vector 4
 * (tests/vectors/seedqr/SOURCE.md).
 */
#define VECTOR4_WORDS \
	"forum undo fragile fade shy sign arrest garment culture tube " \
	"off merit"
#define VECTOR4_DIGITS \
	"073318950739065415961602009907670428187212261116"

/*
 * The bytes after the output buffer of a probe. scan_decode() writes
 * SCAN_LINE_MAX bytes at most, and a probe reads these bytes back to
 * prove that bound.
 */
#define GUARD		16
#define GUARD_BYTE	0x7f

/*
 * The seconds of the probe of the scan bound. DEADLINE_SECONDS is
 * the bound that the probe gives the frame loop, and DEADLINE_KILL
 * is the wait of the parent for the child. A loop that reads before
 * it waits blocks without end, and the parent then reaches that
 * second value.
 */
#define DEADLINE_SECONDS	2
#define DEADLINE_KILL		20

/* The bytes of the report that the probe of the bound reads. */
#define DEADLINE_REPORT		256

/* One rasterized picture. side holds the pixels of one side. */
struct raster {
	int		side;
	unsigned char	pix[RASTER_MAX * RASTER_MAX];
};

static int	 read_raster(const char *, struct raster *);
static enum scan_result	 decode(const struct raster *, char *);
static int	 test_vector4(void);
static int	 test_line(void);
static int	 test_blank(void);
static int	 test_reject(const char *, enum scan_result, const char *);
static int	 test_nocore(void);
static int	 test_deadline(void);

/*
 * read_raster(name, r):
 *	The picture name of SEEDQR_DIR, as a grey image of one byte
 *	for each pixel. The file holds one square of the characters #
 *	and ., with one line feed after each row. A # is a dark
 *	module, and a . is a light module.
 *
 *	The raster carries a quiet zone of QUIET light modules on each
 *	side, and one module takes one pixel.
 */
static int
read_raster(const char *name, struct raster *r)
{
	char	 path[PATH_MAX], line[PICTURE_MAX + 2];
	FILE	*f;
	size_t	 len;
	int	 rows = 0, cols = -1, c, rv = -1;

	if (snprintf(path, sizeof(path), "%s/%s", SEEDQR_DIR, name) < 0)
		errx(1, "the path of the picture %s", name);
	if ((f = fopen(path, "r")) == NULL) {
		warn("%s", path);
		return -1;
	}
	memset(r, 0, sizeof(*r));
	memset(r->pix, 0xff, sizeof(r->pix));
	while (fgets(line, sizeof(line), f) != NULL) {
		len = strlen(line);
		if (len < 2 || line[len - 1] != '\n') {
			warnx("%s: the row %d is no row of at most %d "
			    "characters and one line feed", path, rows + 1,
			    PICTURE_MAX);
			goto out;
		}
		len--;
		if (cols == -1)
			cols = (int)len;
		else if ((int)len != cols) {
			warnx("%s: the row %d holds %zu characters, and the "
			    "first row holds %d", path, rows + 1, len, cols);
			goto out;
		}
		if (rows >= PICTURE_MAX) {
			warnx("%s: the picture holds more than %d rows", path,
			    PICTURE_MAX);
			goto out;
		}
		for (c = 0; c < cols; c++) {
			if (line[c] == '.')
				continue;
			if (line[c] != '#') {
				warnx("%s: the row %d holds the character "
				    "0x%02x, and a picture holds # and . "
				    "alone", path, rows + 1,
				    (unsigned char)line[c]);
				goto out;
			}
			r->pix[(QUIET + rows) * (cols + 2 * QUIET) +
			    QUIET + c] = 0x00;
		}
		rows++;
	}
	if (rows < 1 || rows != cols) {
		warnx("%s: the picture is %d rows of %d characters, and a "
		    "picture is square", path, rows, cols);
		goto out;
	}
	r->side = rows + 2 * QUIET;
	rv = 0;
out:
	fclose(f);
	return rv;
}

/*
 * decode(r, line):
 *	scan_decode() of the raster r, into the SCAN_LINE_MAX bytes at
 *	line. The caller gives a buffer of SCAN_LINE_MAX + GUARD
 *	bytes, and this call proves that scan_decode() writes no byte
 *	of the guard.
 */
static enum scan_result
decode(const struct raster *r, char *line)
{
	enum scan_result	 result;
	int			 i;

	memset(line, GUARD_BYTE, SCAN_LINE_MAX + GUARD);
	result = scan_decode(r->pix, r->side, r->side, line);
	for (i = 0; i < GUARD; i++) {
		if ((unsigned char)line[SCAN_LINE_MAX + i] != GUARD_BYTE)
			errx(1, "scan_decode writes the byte %d after the "
			    "%d bytes of the line", SCAN_LINE_MAX + i,
			    SCAN_LINE_MAX);
	}
	return result;
}

/*
 * test_vector4():
 *	The raster of test vector 4 must decode to the 12 words of
 *	that vector, and the index of each word must be the group of
 *	four digits of the 48 (TEST-KAT-3, PROG-SCAN-2).
 *
 *	FuguSeed draws the picture, and FuguPass reads it. The two
 *	projects therefore agree on one public vector.
 */
static int
test_vector4(void)
{
	static const char	 digits[] = VECTOR4_DIGITS;
	struct raster		 r;
	char			 line[SCAN_LINE_MAX + GUARD];
	char			 word[WORDLIST_MAX + 1], group[5];
	enum scan_result	 result;
	const char		*at;
	size_t			 index, len;
	int			 i;

	if (read_raster("vector4.picture", &r) != 0)
		return -1;
	if ((result = decode(&r, line)) != SCAN_OK) {
		warnx("the raster of test vector 4 gives no mnemonic: %s",
		    scan_strerror(result));
		return -1;
	}
	if (strcmp(line, VECTOR4_WORDS "\n") != 0) {
		warnx("the raster of test vector 4 gives \"%s\", and the 12 "
		    "words of it are \"%s\"", line, VECTOR4_WORDS);
		return -1;
	}

	/*
	 * The words carry the digits of the Standard SeedQR. The
	 * probe maps each word back to its index, and it compares that
	 * index with the group of four digits of the vector.
	 */
	at = line;
	for (i = 0; i < WORDS; i++) {
		len = strcspn(at, " \n");
		if (len == 0 || len > WORDLIST_MAX) {
			warnx("the word %d of the line is %zu bytes", i + 1,
			    len);
			return -1;
		}
		memcpy(word, at, len);
		word[len] = '\0';
		if (wordlist_index(word, len, &index) != 0) {
			warnx("the word %d of the line is \"%s\", and the "
			    "BIP39 English list holds no such word", i + 1,
			    word);
			return -1;
		}
		if (snprintf(group, sizeof(group), "%04zu", index) != 4 ||
		    memcmp(group, &digits[i * 4], 4) != 0) {
			warnx("the word %d of the line is \"%s\" of the index "
			    "%zu, and the digits %d to %d of test vector 4 "
			    "are \"%.4s\"", i + 1, word, index, i * 4 + 1,
			    i * 4 + 4, &digits[i * 4]);
			return -1;
		}
		at += len + 1;
	}
	if (strlen(digits) != (size_t)DIGITS) {
		warnx("the digits of test vector 4 are %zu, and a Standard "
		    "SeedQR of 12 words holds %d", strlen(digits), DIGITS);
		return -1;
	}
	return 0;
}

/*
 * test_line():
 *	The output is one line of 12 words and nothing else
 *	(PROG-SCAN-5, PROG-SCAN-1). One space stands between two
 *	words, one line feed ends the line, and the line holds no
 *	other byte.
 */
static int
test_line(void)
{
	struct raster		 r;
	char			 line[SCAN_LINE_MAX + GUARD];
	enum scan_result	 result;
	size_t			 i, len;
	int			 spaces = 0;

	if (read_raster("vector4.picture", &r) != 0)
		return -1;
	if ((result = decode(&r, line)) != SCAN_OK) {
		warnx("the raster of test vector 4 gives no mnemonic: %s",
		    scan_strerror(result));
		return -1;
	}
	len = strlen(line);
	if (len < 2 || line[len - 1] != '\n') {
		warnx("the output is %zu bytes, and one line feed must end "
		    "one line of 12 words", len);
		return -1;
	}
	for (i = 0; i < len - 1; i++) {
		if (line[i] == ' ') {
			if (i == 0 || line[i - 1] == ' ') {
				warnx("the output holds a space at the "
				    "offset %zu, and one space stands "
				    "between two words", i);
				return -1;
			}
			spaces++;
			continue;
		}
		if (line[i] < 'a' || line[i] > 'z') {
			warnx("the output holds the byte 0x%02x at the offset "
			    "%zu, and a line of 12 words holds the letters "
			    "and the spaces alone", (unsigned char)line[i], i);
			return -1;
		}
	}
	if (line[len - 2] == ' ') {
		warnx("one space stands before the line feed of the output");
		return -1;
	}
	if (spaces != WORDS - 1) {
		warnx("the output holds %d spaces, and a line of %d words "
		    "holds %d", spaces, WORDS, WORDS - 1);
		return -1;
	}
	return 0;
}

/*
 * test_blank():
 *	A frame of light pixels alone holds no QR code, and the decode
 *	of it must give SCAN_NO_CODE. The probe proves that
 *	scan_decode() reads the image, and that it gives no canned
 *	answer.
 */
static int
test_blank(void)
{
	struct raster		 r;
	char			 line[SCAN_LINE_MAX + GUARD];
	enum scan_result	 result;

	memset(&r, 0, sizeof(r));
	memset(r.pix, 0xff, sizeof(r.pix));
	r.side = 25 + 2 * QUIET;	/* the side of a version 2 raster */
	if ((result = decode(&r, line)) != SCAN_NO_CODE) {
		warnx("a frame of light pixels gives \"%s\", and a frame of "
		    "no QR code gives \"%s\"", scan_strerror(result),
		    scan_strerror(SCAN_NO_CODE));
		return -1;
	}
	return 0;
}

/*
 * test_reject(name, want, why):
 *	The picture name must fail with the cause want (TEST-KAT-3,
 *	D-22). The probe reads the cause, so a picture that fails for
 *	another reason fails this probe as well.
 *
 *	A failed decode writes no byte of the line, and the probe
 *	reads the whole buffer back.
 */
static int
test_reject(const char *name, enum scan_result want, const char *why)
{
	struct raster		 r;
	char			 line[SCAN_LINE_MAX + GUARD];
	enum scan_result	 result;
	int			 i;

	if (read_raster(name, &r) != 0)
		return -1;
	if ((result = decode(&r, line)) != want) {
		warnx("the raster of %s gives \"%s\", and %s gives \"%s\"",
		    name, scan_strerror(result), why, scan_strerror(want));
		return -1;
	}
	for (i = 0; i < SCAN_LINE_MAX + GUARD; i++) {
		if ((unsigned char)line[i] != GUARD_BYTE) {
			warnx("the failed decode of %s writes the byte %d of "
			    "the line, and a failure writes no byte of it",
			    name, i);
			return -1;
		}
	}
	return 0;
}

/*
 * test_nocore():
 *	getrlimit(2) after the core-limit call of the helper must read
 *	a soft limit of zero and a hard limit of zero (SEC-MEMORY-3).
 *
 *	A child takes the limits of its parent, so the child below
 *	writes the state that the rule answers first: a soft limit of
 *	zero, and the hard limit of this process above it. A call that
 *	reads the soft limit alone writes nothing there, and the hard
 *	limit of the child then stays above zero. The probe therefore
 *	proves the call and not the inheritance.
 */
static int
test_nocore(void)
{
	struct rlimit	 rl;
	pid_t		 pid, done;
	int		 status;

	if (getrlimit(RLIMIT_CORE, &rl) == -1) {
		warn("getrlimit");
		return -1;
	}
	if (rl.rlim_max == 0) {
		warnx("the hard core limit of this process is zero, so the "
		    "probe proves no call of the helper");
		return -1;
	}

	if ((pid = fork()) == -1) {
		warn("fork");
		return -1;
	}
	if (pid == 0) {
		struct rlimit	 soft = { 0, rl.rlim_max }, got;

		if (setrlimit(RLIMIT_CORE, &soft) == -1)
			_exit(5);
		if (scan_nocore() != 0)
			_exit(2);
		if (getrlimit(RLIMIT_CORE, &got) == -1)
			_exit(3);
		if (got.rlim_cur != 0 || got.rlim_max != 0)
			_exit(4);
		_exit(0);
	}
	while ((done = waitpid(pid, &status, 0)) == -1 && errno == EINTR)
		;
	if (done != pid) {
		warn("waitpid");
		return -1;
	}
	if (!WIFEXITED(status)) {
		warnx("the probe of the core limit: the signal %d stops the "
		    "child", WTERMSIG(status));
		return -1;
	}
	switch (WEXITSTATUS(status)) {
	case 0:
		return 0;
	case 2:
		warnx("the probe of the core limit: the sandbox call fails");
		break;
	case 3:
		warnx("the probe of the core limit: the getrlimit call fails");
		break;
	case 4:
		warnx("a core limit after the sandbox call of the helper is "
		    "not zero, and SEC-MEMORY-3 asks for zero in both");
		break;
	case 5:
		warnx("the probe of the core limit: the child writes no soft "
		    "zero with a hard limit above it");
		break;
	default:
		warnx("the probe of the core limit: the child exits %d",
		    WEXITSTATUS(status));
		break;
	}
	return -1;
}

/*
 * test_deadline():
 *	The frame loop must end at the bound of one scan
 *	(PROG-SCAN-9). read(2) on video(4) takes no timeout, so a
 *	device that opens and gives no frame would hold the ceremony
 *	of the caller without end.
 *
 *	The probe gives the loop the read end of a pipe. Both ends
 *	stay open and no byte enters that pipe, so the descriptor
 *	never holds a frame. A loop that waits for each frame ends
 *	at the bound and gives 1. A loop that reads first blocks
 *	without end, and the parent kills the child of it.
 *
 *	The probe reads the seconds of the run as well. A loop that
 *	gives up before the bound fails the scan of a slow camera.
 *
 *	The standard error of the child goes to a second pipe, and
 *	the probe reads the report of it. The pipe of the frames
 *	carries no byte, so the loop takes the branch of a stream
 *	that gives no frame. That report must name the device and
 *	the cause, and the probe reads both (PROG-SCAN-9,
 *	PROG-SCAN-13). The report of a stream that gives frames of
 *	no SeedQR names the cause alone, and this probe reaches no
 *	such stream.
 */
static int
test_deadline(void)
{
	struct scan_stream	 st;
	FILE			*null, *err;
	char			 report[DEADLINE_REPORT];
	time_t			 start, spent;
	ssize_t			 n;
	pid_t			 pid, got;
	int			 fds[2], out[2], status, i, rv = -1;

	if (pipe(fds) == -1) {
		warn("the probe of the scan bound: pipe");
		return -1;
	}
	if (pipe(out) == -1) {
		warn("the probe of the scan bound: pipe");
		close(fds[0]);
		close(fds[1]);
		return -1;
	}
	memset(&st, 0, sizeof(st));
	st.device = "the pipe of the probe";
	st.fd = fds[0];
	st.w = 8;
	st.h = 8;
	st.stride = 2 * st.w;
	st.framelen = (size_t)st.stride * st.h;

	start = time(NULL);
	if ((pid = fork()) == -1) {
		warn("the probe of the scan bound: fork");
		goto out;
	}
	if (pid == 0) {
		int	 status_child;

		if ((null = fopen(_PATH_DEVNULL, "w")) == NULL)
			_exit(3);
		if ((err = fdopen(out[1], "w")) == NULL)
			_exit(4);
		status_child = scan_frames(&st, DEADLINE_SECONDS, null, err);

		/*
		 * _exit(2) flushes no stream of stdio, and the parent
		 * reads the report of this stream.
		 */
		if (fflush(err) == EOF)
			_exit(5);
		_exit(status_child);
	}

	/*
	 * The read of the report ends at the last write end of the
	 * pipe, so this process closes its own write end here.
	 */
	close(out[1]);
	out[1] = -1;

	for (i = 0; i < DEADLINE_KILL; i++) {
		if ((got = waitpid(pid, &status, WNOHANG)) == -1) {
			warn("the probe of the scan bound: waitpid");
			goto out;
		}
		if (got == pid)
			break;
		sleep(1);
	}
	if (i == DEADLINE_KILL) {
		kill(pid, SIGKILL);
		waitpid(pid, &status, 0);
		warnx("the frame loop reads a stream that gives no frame, "
		    "and it does not end in %d seconds. PROG-SCAN-9 bounds "
		    "one scan", DEADLINE_KILL);
		goto out;
	}
	spent = time(NULL) - start;
	if (!WIFEXITED(status)) {
		warnx("the probe of the scan bound: the signal %d stops the "
		    "child", WTERMSIG(status));
		goto out;
	}
	if (WEXITSTATUS(status) == 3) {
		warnx("the probe of the scan bound: the child opens no %s",
		    _PATH_DEVNULL);
		goto out;
	}
	if (WEXITSTATUS(status) == 4 || WEXITSTATUS(status) == 5) {
		warnx("the probe of the scan bound: the child writes no "
		    "report to the pipe of it");
		goto out;
	}
	if (WEXITSTATUS(status) != 1) {
		warnx("the frame loop gives the status %d at the bound of "
		    "one scan, and a failed scan gives 1",
		    WEXITSTATUS(status));
		goto out;
	}
	if (spent < DEADLINE_SECONDS) {
		warnx("the frame loop gives up after %lld seconds, and the "
		    "bound of this probe is %d", (long long)spent,
		    DEADLINE_SECONDS);
		goto out;
	}
	if ((n = read(out[0], report, sizeof(report) - 1)) == -1) {
		warn("the probe of the scan bound: the read of the report");
		goto out;
	}
	report[n] = '\0';
	if (strstr(report, st.device) == NULL ||
	    strstr(report, "gives no frame") == NULL) {
		warnx("the report at the bound is \"%s\", and it must name "
		    "the device and the cause that ends the scan", report);
		goto out;
	}
	rv = 0;
out:
	close(fds[0]);
	close(fds[1]);
	close(out[0]);
	if (out[1] != -1)
		close(out[1]);
	return rv;
}

int
main(int argc, char *argv[])
{
	int	 rv = 0;

	if (argc != 1)
		errx(1, "usage: %s", argv[0]);

	/* Every probe runs, so one run reports every wrong value. */
	if (test_vector4() != 0)
		rv = 1;
	if (test_line() != 0)
		rv = 1;
	if (test_blank() != 0)
		rv = 1;
	if (test_reject("compact.picture", SCAN_MODE,
	    "a Compact SeedQR of byte mode") != 0)
		rv = 1;
	if (test_reject("words24.picture", SCAN_COUNT,
	    "a Standard SeedQR of 24 words and 96 digits") != 0)
		rv = 1;
	if (test_reject("overflow.picture", SCAN_INDEX,
	    "48 digits with a group above 2047") != 0)
		rv = 1;
	if (test_nocore() != 0)
		rv = 1;
	if (test_deadline() != 0)
		rv = 1;
	return rv;
}
