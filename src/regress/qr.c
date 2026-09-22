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
 * The tests of the render helper (PROG-QR, PROG-SPLIT-5,
 * SEC-MEMORY-3). qr.c of the directory above holds the sandbox and
 * the render, and fugupass-qr.c calls the same two functions. This
 * test therefore reads the code that the program runs.
 *
 * qr_run() takes three streams, so each probe drives it with
 * fmemopen(3) and open_memstream(3). No probe writes a file.
 *
 * parse() maps the half blocks of a render back to modules, so each
 * probe reads modules and not characters. The map of this file is
 * the reverse of PROG-QR-9, and it stands here again: the test then
 * proves the render against the rule, and not against itself.
 *
 * The mnemonic probe compares the modules with the picture of test
 * vector 4, at tests/vectors/seedqr/vector4.picture. FuguSeed draws
 * that picture, and its mask pattern is 0 (PROG-QR-6). libqrencode
 * picks pattern 5 for this vector, so the probe fails when the
 * re-mask step of qr.c is absent.
 *
 * pledge(2) and setrlimit(2) hold for the life of a process, so the
 * two sandbox probes each run in a child of their own.
 *
 * The program prints nothing on a pass, and it exits 0. A wrong
 * value prints the probe to the standard error, and the program
 * exits 1.
 *
 * The 12 words below are public test data, so this test clears
 * nothing.
 */

#include <sys/types.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "qr.h"
#include "seal.h"

/* The modules on each side of the picture of test vector 4. */
#define PICTURE_SIDE	25

/*
 * The light modules on each side of a code, as a literal.
 * QR_QUIET of qr.h is the value under test, so the probe must not
 * read it. PROG-QR-9 states this count.
 */
#define QUIET		4

/*
 * The rows and the columns of a parsed render. A version 40 code is
 * 177 modules, the two quiet zones add 8, and an odd row count adds
 * one pad row.
 */
#define GRID_MAX	186

/*
 * The one-code capacity of PROG-QR-8, as a literal and as text.
 * QR_VAULT_MAX of qr.h is the value under test, so the probe must
 * not read it. A run of qrencode(1) in the OpenBSD guest took 2953
 * bytes at level L in byte mode, and it refused 2954. The report of
 * a longer file must name that count (PROG-QR-8).
 */
#define CAPACITY	2953
#define CAPACITY_TEXT	"2953"

/* The 12 words of test vector 4 (tests/vectors/seedqr/SOURCE.md). */
#define VECTOR4_WORDS \
	"forum undo fragile fade shy sign arrest garment culture tube " \
	"off merit"

/* The file of the picture of test vector 4, from the build. */
#ifndef QR_PICTURE
#error "QR_PICTURE must name the picture of test vector 4"
#endif

/* The 7 by 7 finder pattern of every QR code (6.3.3 of ISO/IEC 18004). */
static const char *const finder[7] = {
	"#######",
	"#.....#",
	"#.###.#",
	"#.###.#",
	"#.###.#",
	"#.....#",
	"#######"
};

/* One parsed render: side modules on each side, 1 dark and 0 light. */
struct grid {
	int		side;
	unsigned char	mod[GRID_MAX][GRID_MAX];
};

static int	 run(const unsigned char *, size_t, char **, size_t *,
		    char **, size_t *);
static int	 parse(const char *, size_t, struct grid *);
static int	 probe_quiet(const struct grid *);
static int	 probe_finders(const struct grid *);
static int	 read_picture(char [PICTURE_SIDE][PICTURE_SIDE]);
static int	 test_picture(void);
static int	 test_shape(void);
static int	 test_vault(void);
static int	 test_capacity(void);
static int	 test_pledge(void);
static int	 test_nocore(void);

/*
 * run(in, inlen, out, outlen, errtext, errlen):
 *	Drive qr_run() with the inlen bytes at in, and give back the
 *	two output streams. The caller frees out and errtext.
 *
 *	The call gives the status of qr_run(). A failure of this
 *	harness stops the program, because such a failure proves
 *	nothing about the helper.
 */
static int
run(const unsigned char *in, size_t inlen, char **out, size_t *outlen,
    char **errtext, size_t *errlen)
{
	FILE	*fin, *fout, *ferr;
	int	 rv;

	if ((fin = fmemopen((void *)in, inlen, "r")) == NULL)
		err(1, "fmemopen");
	if ((fout = open_memstream(out, outlen)) == NULL)
		err(1, "open_memstream");
	if ((ferr = open_memstream(errtext, errlen)) == NULL)
		err(1, "open_memstream");

	rv = qr_run(fin, fout, ferr);

	fclose(fin);
	if (fclose(fout) == EOF)
		err(1, "fclose");
	if (fclose(ferr) == EOF)
		err(1, "fclose");
	return rv;
}

/*
 * parse(text, len, g):
 *	Map the len bytes at text back to modules (PROG-QR-9). One
 *	character carries two module rows, and the ink of the
 *	terminal is a light module.
 *
 *	The call gives 0, and -1 for a byte that no rule of
 *	PROG-QR-9 writes, for a line of another length, and for a
 *	last line that no line feed ends.
 */
static int
parse(const char *text, size_t len, struct grid *g)
{
	size_t	 i = 0;
	int	 row = 0, col, side = -1, up, low;

	memset(g, 0, sizeof(*g));
	while (i < len) {
		col = 0;
		while (i < len && text[i] != '\n') {
			if (text[i] == ' ') {
				up = 1;
				low = 1;
				i++;
			} else if (len - i >= 3 &&
			    memcmp(text + i, "\xe2\x96\x88", 3) == 0) {
				up = 0;
				low = 0;
				i += 3;
			} else if (len - i >= 3 &&
			    memcmp(text + i, "\xe2\x96\x80", 3) == 0) {
				up = 0;
				low = 1;
				i += 3;
			} else if (len - i >= 3 &&
			    memcmp(text + i, "\xe2\x96\x84", 3) == 0) {
				up = 1;
				low = 0;
				i += 3;
			} else {
				warnx("the render holds the byte 0x%02x at "
				    "offset %zu, and PROG-QR-9 writes four "
				    "characters", (unsigned char)text[i], i);
				return -1;
			}
			if (col >= GRID_MAX || row + 1 >= GRID_MAX) {
				warnx("the render is larger than %d modules",
				    GRID_MAX);
				return -1;
			}
			g->mod[row][col] = (unsigned char)up;
			g->mod[row + 1][col] = (unsigned char)low;
			col++;
		}
		if (i >= len) {
			warnx("no line feed ends the last line of the render");
			return -1;
		}
		i++;
		if (side == -1)
			side = col;
		else if (col != side) {
			warnx("a line of the render holds %d characters, and "
			    "the first line holds %d", col, side);
			return -1;
		}
		row += 2;
	}
	if (side < 1) {
		warnx("the render holds no line");
		return -1;
	}
	if (row != side && row != side + 1) {
		warnx("the render holds %d module rows, and it is %d "
		    "modules wide", row, side);
		return -1;
	}
	if (row == side + 1) {
		for (col = 0; col < side; col++) {
			if (g->mod[side][col] != 0) {
				warnx("the pad row of the render holds a dark "
				    "module at column %d", col);
				return -1;
			}
		}
	}
	g->side = side;
	return 0;
}

/*
 * probe_quiet(g):
 *	The render must carry a quiet zone of QUIET light modules
 *	on each of the four sides (PROG-QR-9).
 */
static int
probe_quiet(const struct grid *g)
{
	int	 r, c;

	for (r = 0; r < g->side; r++) {
		for (c = 0; c < g->side; c++) {
			if (r >= QUIET && r < g->side - QUIET &&
			    c >= QUIET && c < g->side - QUIET)
				continue;
			if (g->mod[r][c] != 0) {
				warnx("the module at row %d and column %d is "
				    "dark, and the quiet zone of %d modules "
				    "is light", r, c, QUIET);
				return -1;
			}
		}
	}
	return 0;
}

/*
 * probe_finders(g):
 *	The three finder patterns of one code, at the three corners
 *	inside the quiet zone. A render that holds them is one code.
 */
static int
probe_finders(const struct grid *g)
{
	int	 width = g->side - 2 * QUIET;
	int	 corner[3][2], k, r, c, dark;

	if (width < 21) {
		warnx("the code is %d modules wide, and 21 is the smallest "
		    "QR code", width);
		return -1;
	}
	corner[0][0] = 0;		/* the top-left finder */
	corner[0][1] = 0;
	corner[1][0] = 0;		/* the top-right finder */
	corner[1][1] = width - 7;
	corner[2][0] = width - 7;	/* the bottom-left finder */
	corner[2][1] = 0;

	for (k = 0; k < 3; k++) {
		for (r = 0; r < 7; r++) {
			for (c = 0; c < 7; c++) {
				dark = g->mod[QUIET + corner[k][0] + r]
				    [QUIET + corner[k][1] + c];
				if (dark != (finder[r][c] == '#')) {
					warnx("the finder pattern %d of the "
					    "render is wrong at row %d and "
					    "column %d", k, r, c);
					return -1;
				}
			}
		}
	}
	return 0;
}

/*
 * read_picture(pic):
 *	The picture of test vector 4, from the file of QR_PICTURE.
 *	The file holds PICTURE_SIDE rows of PICTURE_SIDE characters,
 *	with one line feed after each row.
 */
static int
read_picture(char pic[PICTURE_SIDE][PICTURE_SIDE])
{
	FILE	*f;
	char	 line[PICTURE_SIDE + 2];
	int	 r, rv = -1;

	if ((f = fopen(QR_PICTURE, "r")) == NULL) {
		warn("%s", QR_PICTURE);
		return -1;
	}
	for (r = 0; r < PICTURE_SIDE; r++) {
		if (fgets(line, sizeof(line), f) == NULL) {
			warnx("%s: the row %d is absent", QR_PICTURE, r + 1);
			goto out;
		}
		if (strlen(line) != PICTURE_SIDE + 1 ||
		    line[PICTURE_SIDE] != '\n') {
			warnx("%s: the row %d is not %d characters and one "
			    "line feed", QR_PICTURE, r + 1, PICTURE_SIDE);
			goto out;
		}
		memcpy(pic[r], line, PICTURE_SIDE);
	}
	if (fgetc(f) != EOF) {
		warnx("%s: the file holds more than %d rows", QR_PICTURE,
		    PICTURE_SIDE);
		goto out;
	}
	rv = 0;
out:
	fclose(f);
	return rv;
}

/*
 * test_picture():
 *	The render of the 12 words of test vector 4 must equal the
 *	picture of FuguSeed, module for module, and it must carry the
 *	quiet zone of PROG-QR-9.
 *
 *	The picture holds mask pattern 0, and libqrencode picks
 *	pattern 5 for this vector. The probe therefore fails when the
 *	re-mask step of qr.c is absent (PROG-QR-6).
 */
static int
test_picture(void)
{
	char		 pic[PICTURE_SIDE][PICTURE_SIDE];
	struct grid	 g;
	char		*out = NULL, *errtext = NULL;
	size_t		 outlen = 0, errlen = 0;
	const char	*words = VECTOR4_WORDS;
	int		 r, c, dark, rv = -1;

	if (read_picture(pic) != 0)
		return -1;
	if (run((const unsigned char *)words, strlen(words), &out, &outlen,
	    &errtext, &errlen) != 0) {
		warnx("the render of the 12 words fails: %.*s", (int)errlen,
		    errtext);
		goto out;
	}
	if (parse(out, outlen, &g) != 0)
		goto out;
	if (g.side != PICTURE_SIDE + 2 * QUIET) {
		warnx("the render is %d modules wide, and a version 2 code "
		    "with the quiet zone is %d", g.side,
		    PICTURE_SIDE + 2 * QUIET);
		goto out;
	}
	if (probe_quiet(&g) != 0)
		goto out;
	if (probe_finders(&g) != 0)
		goto out;
	for (r = 0; r < PICTURE_SIDE; r++) {
		for (c = 0; c < PICTURE_SIDE; c++) {
			dark = g.mod[QUIET + r][QUIET + c];
			if (dark != (pic[r][c] == '#')) {
				warnx("the module at row %d and column %d of "
				    "the code is %s, and the picture of test "
				    "vector 4 holds %c", r, c,
				    dark ? "dark" : "light", pic[r][c]);
				goto out;
			}
		}
	}
	rv = 0;
out:
	free(out);
	free(errtext);
	return rv;
}

/*
 * test_shape():
 *	The shape comes from the bytes of the input (PROG-QR-7). One
 *	line feed at the end changes no module. A word outside the
 *	BIP39 list and a count of 11 words each take the vault
 *	shape, so neither one gives a version 2 code.
 */
static int
test_shape(void)
{
	static const char	*const other[2] = {
		/* one word outside the BIP39 English list */
		"forum undo fragile fade shy sign arrest garment culture "
		    "tube off zzzzzz",
		/* 11 words, and PROG-QR-7 takes 12 */
		"forum undo fragile fade shy sign arrest garment culture "
		    "tube off"
	};
	char		*plain = NULL, *feed = NULL, *out = NULL;
	char		*errtext = NULL;
	size_t		 plainlen = 0, feedlen = 0, outlen = 0, errlen = 0;
	char		 buf[128];
	struct grid	 g;
	const char	*words = VECTOR4_WORDS;
	size_t		 k;
	int		 n, rv = -1;

	if (run((const unsigned char *)words, strlen(words), &plain, &plainlen,
	    &errtext, &errlen) != 0) {
		warnx("the render of the 12 words fails: %.*s", (int)errlen,
		    errtext);
		goto out;
	}
	free(errtext);
	errtext = NULL;

	n = snprintf(buf, sizeof(buf), "%s\n", words);
	if (n < 0 || (size_t)n >= sizeof(buf))
		errx(1, "the 12 words and one line feed do not fit");
	if (run((const unsigned char *)buf, (size_t)n, &feed, &feedlen,
	    &errtext, &errlen) != 0) {
		warnx("the render of the 12 words and one line feed fails: "
		    "%.*s", (int)errlen, errtext);
		goto out;
	}
	if (feedlen != plainlen || memcmp(feed, plain, plainlen) != 0) {
		warnx("one line feed at the end of the 12 words changes the "
		    "render, and PROG-QR-7 takes that byte");
		goto out;
	}
	free(errtext);
	errtext = NULL;

	for (k = 0; k < sizeof(other) / sizeof(other[0]); k++) {
		if (run((const unsigned char *)other[k], strlen(other[k]),
		    &out, &outlen, &errtext, &errlen) != 0) {
			warnx("the render of \"%s\" fails: %.*s", other[k],
			    (int)errlen, errtext);
			goto out;
		}
		if (parse(out, outlen, &g) != 0)
			goto out;
		if (g.side == PICTURE_SIDE + 2 * QUIET) {
			warnx("\"%s\" renders as a version 2 code, and "
			    "PROG-QR-7 takes %d words of the BIP39 list "
			    "alone", other[k], QR_WORDS);
			goto out;
		}
		if (probe_quiet(&g) != 0)
			goto out;
		free(out);
		free(errtext);
		out = errtext = NULL;
	}
	rv = 0;
out:
	free(plain);
	free(feed);
	free(out);
	free(errtext);
	return rv;
}

/*
 * test_vault():
 *	A vault file of one sealed entry must render as one code
 *	(PROG-QR-3, VAULT-BACKUP-4). The probe seals one password
 *	entry of the line format, and it reads the three finder
 *	patterns of the render (VAULT-FORMAT-1, ENTRY-TYPES-5).
 */
static int
test_vault(void)
{
	static const unsigned char	 key[SEAL_KEYLEN] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
	};
	static const char		 plain[] =
		"password: the-test-value-of-the-render-probe\n"
		"type: password\n"
		"slots: 3\n"
		"username: alice\n"
		"url: https://example.com/login\n"
		"version: 1\n";
	unsigned char	 sealed[sizeof(plain) - 1 + SEAL_OVERHEAD];
	struct grid	 g;
	char		*out = NULL, *errtext = NULL;
	size_t		 outlen = 0, errlen = 0;
	int		 rv = -1;

	if (seal_seal(key, sizeof(key), (const unsigned char *)plain,
	    sizeof(plain) - 1, sealed, sizeof(sealed)) != 0) {
		warnx("the seal of the entry file fails");
		return -1;
	}
	if (run(sealed, sizeof(sealed), &out, &outlen, &errtext,
	    &errlen) != 0) {
		warnx("the render of the sealed entry fails: %.*s",
		    (int)errlen, errtext);
		goto out;
	}
	if (parse(out, outlen, &g) != 0)
		goto out;
	if (probe_quiet(&g) != 0)
		goto out;
	if (probe_finders(&g) != 0)
		goto out;
	rv = 0;
out:
	free(out);
	free(errtext);
	return rv;
}

/*
 * test_capacity():
 *	A file of the one-code capacity must render as one code, and
 *	a longer file must give a report and no code (PROG-QR-3,
 *	PROG-QR-8, VAULT-BACKUP-4).
 */
static int
test_capacity(void)
{
	unsigned char	*big;
	struct grid	 g;
	char		*out = NULL, *errtext = NULL;
	size_t		 outlen = 0, errlen = 0;
	int		 rv = -1;

	if ((big = malloc(CAPACITY + 1)) == NULL)
		err(1, "malloc");
	memset(big, 'a', CAPACITY + 1);

	if (run(big, CAPACITY, &out, &outlen, &errtext, &errlen) != 0) {
		warnx("a file of %d bytes gives no code, and that count is "
		    "the one-code capacity: %.*s", CAPACITY, (int)errlen,
		    errtext);
		goto out;
	}
	if (parse(out, outlen, &g) != 0)
		goto out;
	if (probe_finders(&g) != 0)
		goto out;
	free(out);
	free(errtext);
	out = errtext = NULL;

	if (run(big, CAPACITY + 1, &out, &outlen, &errtext, &errlen) == 0) {
		warnx("a file of %d bytes gives a code, and the one-code "
		    "capacity is %d bytes", CAPACITY + 1, CAPACITY);
		goto out;
	}
	if (outlen != 0) {
		warnx("a file above the capacity writes %zu bytes of a code, "
		    "and PROG-QR-3 writes a report alone", outlen);
		goto out;
	}
	if (errlen == 0) {
		warnx("a file above the capacity writes no report, and "
		    "PROG-QR-3 asks for one");
		goto out;
	}
	/*
	 * open_memstream(3) ends the buffer with a terminator, so
	 * the report reads as a string here. The report must name
	 * the capacity, and a report of another failure names no
	 * count (PROG-QR-8).
	 */
	if (strstr(errtext, CAPACITY_TEXT) == NULL) {
		warnx("the report of a file above the capacity does not name "
		    "%s bytes: %.*s", CAPACITY_TEXT, (int)errlen, errtext);
		goto out;
	}
	rv = 0;
out:
	free(big);
	free(out);
	free(errtext);
	return rv;
}

/*
 * test_pledge():
 *	The promise set of the helper is "stdio" alone, and an open
 *	of a file needs a promise outside it (PROG-SPLIT-5). The
 *	kernel kills a child of such a call with SIGABRT.
 *
 *	The child sets the two limits of RLIMIT_CORE to zero inside
 *	qr_sandbox(), so the abort writes no core file.
 */
static int
test_pledge(void)
{
	pid_t	 pid, done;
	int	 fd, status;

	if ((pid = fork()) == -1) {
		warn("fork");
		return -1;
	}
	if (pid == 0) {
		if (qr_sandbox() != 0)
			_exit(2);
		if ((fd = open("/etc/passwd", O_RDONLY)) == -1)
			_exit(3);
		close(fd);
		_exit(0);
	}
	while ((done = waitpid(pid, &status, 0)) == -1 && errno == EINTR)
		;
	if (done != pid) {
		warn("waitpid");
		return -1;
	}
	if (WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT)
		return 0;
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		warnx("the pledge \"%s\" of the helper takes an open of a "
		    "file", QR_PROMISES);
		return -1;
	}
	if (WIFEXITED(status) && WEXITSTATUS(status) == 2) {
		warnx("the probe of the pledge: the sandbox call fails");
		return -1;
	}
	if (WIFEXITED(status) && WEXITSTATUS(status) == 3) {
		warnx("the probe of the pledge: the open fails for another "
		    "reason");
		return -1;
	}
	warnx("the probe of the pledge: the status of the child is %d, and "
	    "SIGABRT is the outcome of a violation", status);
	return -1;
}

/*
 * test_nocore():
 *	getrlimit(2) after the core-limit call of the helper must
 *	read a soft limit of zero and a hard limit of zero
 *	(SEC-MEMORY-3).
 *
 *	A child takes the limits of its parent, so the child below
 *	writes the state that the rule answers first: a soft limit of
 *	zero, and the hard limit of this process above it. A call
 *	that reads the soft limit alone writes nothing there, and the
 *	hard limit of the child then stays above zero. The probe
 *	therefore proves the call and not the inheritance.
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
		if (qr_sandbox() != 0)
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

int
main(int argc, char *argv[])
{
	int	 rv = 0;

	if (argc != 1)
		errx(1, "usage: %s", argv[0]);

	/* Every probe runs, so one run reports every wrong value. */
	if (test_picture() != 0)
		rv = 1;
	if (test_shape() != 0)
		rv = 1;
	if (test_vault() != 0)
		rv = 1;
	if (test_capacity() != 0)
		rv = 1;
	if (test_pledge() != 0)
		rv = 1;
	if (test_nocore() != 0)
		rv = 1;
	return rv;
}
