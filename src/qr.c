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
 * The render helper of PROG-QR. qr.h states the interface.
 *
 * libqrencode of the ports tree makes each code (PROG-QR-5). The
 * QRcode structure of that library gives one byte of each module.
 * Bit 0 of a byte is the dark module, and bit 7 of it marks a
 * module outside the encoding region: a finder pattern, a
 * separator, a timing pattern, an alignment pattern, the format
 * information, and the dark module. A run of libqrencode 4.1.1 in
 * the OpenBSD guest printed each byte of a version 2 code, and the
 * bytes carry those two bits.
 *
 * The library picks the mask pattern of a code by penalty score.
 * The same run picked pattern 5 for test vector 4, and PROG-QR-6
 * asks for pattern 0. remask() therefore rewrites a mnemonic code.
 *
 * The residue of the library is outside this file. QRinput_free()
 * of libqrencode releases the digit buffer of the input without an
 * erasure, so the 48 digits of a mnemonic stay in the freed heap of
 * this process. The helper carries no other secret, it runs for one
 * render, and RLIMIT_CORE is zero (SEC-MEMORY-3).
 */

#include <sys/types.h>
#include <sys/resource.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <qrencode.h>

#include "qr.h"
#include "wordlist.h"

/* Bit 7 of a module byte: the module sits outside the encoding region. */
#define QR_NONDATA	0x80

/*
 * The 15 format bits of a code at level L with mask pattern 0
 * (Table 25 of ISO/IEC 18004), and the value that every format
 * string carries in an exclusive-or (8.9 of that standard). The
 * first character of each string belongs to the first row of
 * format_one below.
 */
#define QR_FORMAT_L0	"111011111000100"
#define QR_FORMAT_XOR	"101010000010010"

/*
 * The 15 positions of the first copy of the format information, as
 * a row and a column (Figure 25 of ISO/IEC 18004). The second copy
 * depends on the width of the code, and format_two() gives it.
 */
static const int format_one[15][2] = {
	{ 8, 0 }, { 8, 1 }, { 8, 2 }, { 8, 3 }, { 8, 4 },
	{ 8, 5 }, { 8, 7 }, { 8, 8 }, { 7, 8 }, { 5, 8 },
	{ 4, 8 }, { 3, 8 }, { 2, 8 }, { 1, 8 }, { 0, 8 }
};

/*
 * The four characters of the render (PROG-QR-9). One character
 * carries two module rows, and the ink of the terminal is a light
 * module. The index is the dark bit of the upper module, then the
 * dark bit of the lower one.
 */
static const char *const blocks[4] = {
	"\xe2\x96\x88",		/* U+2588: two light modules */
	"\xe2\x96\x80",		/* U+2580: light above dark */
	"\xe2\x96\x84",		/* U+2584: dark above light */
	" "			/* two dark modules */
};

static void	 format_two(int, int, int *, int *);
static int	 read_mask(const QRcode *);
static int	 mask_bit(int, int, int);
static void	 set_module(QRcode *, int, int, int);
static void	 remask(QRcode *);
static int	 module(const QRcode *, int, int);
static int	 render(const QRcode *, FILE *);
static int	 mnemonic_digits(const unsigned char *, size_t, char *);

int
qr_sandbox(void)
{
	struct rlimit	 limit, nocore = { 0, 0 };

	/*
	 * The core limit comes first, before every other act of the
	 * program: no crash of it writes a secret to a core file
	 * (SEC-MEMORY-3).
	 *
	 * A child of the core process inherits the two zero limits of
	 * that process, and the execpromises of it hold no proc
	 * promise (PROG-SPLIT-3). setrlimit(2) needs that promise, and
	 * the kernel kills a child that calls it. The call below
	 * therefore reads the two limits first, and it calls
	 * setrlimit(2) only when one of them is not zero. getrlimit(2)
	 * needs the stdio promise alone (SEC-MEMORY-3).
	 *
	 * The zero of the soft limit stops every core file, and the
	 * zero of the hard limit stops a raise of the soft one.
	 */
	if (getrlimit(RLIMIT_CORE, &limit) == -1)
		return -1;
	if ((limit.rlim_cur != 0 || limit.rlim_max != 0) &&
	    setrlimit(RLIMIT_CORE, &nocore) == -1)
		return -1;
	if (pledge(QR_PROMISES, NULL) == -1)
		return -1;
	return 0;
}

/*
 * format_two(width, i, row, col):
 *	The position of the format bit i of the second copy, in a
 *	code of width modules (Figure 25 of ISO/IEC 18004). The
 *	first seven bits stand in column 8, from the last row up.
 *	The other eight stand in row 8, at the last eight columns.
 */
static void
format_two(int width, int i, int *row, int *col)
{
	if (i < 7) {
		*row = width - 1 - i;
		*col = 8;
	} else {
		*row = 8;
		*col = width - 15 + i;
	}
}

/*
 * read_mask(qr):
 *	The mask pattern of the code qr, from the first copy of its
 *	format information. The exclusive-or of QR_FORMAT_XOR gives
 *	back the five data bits of that field, and the mask number
 *	is bit 2, bit 3 and bit 4 of them.
 */
static int
read_mask(const QRcode *qr)
{
	int	 i, bit, mask = 0;

	for (i = 2; i <= 4; i++) {
		bit = qr->data[format_one[i][0] * qr->width +
		    format_one[i][1]] & 1;
		bit ^= QR_FORMAT_XOR[i] - '0';
		mask = (mask << 1) | bit;
	}
	return mask;
}

/*
 * mask_bit(pattern, row, col):
 *	1 when the mask pattern inverts the module at row and col,
 *	and 0 when it does not (Table 10 of ISO/IEC 18004).
 */
static int
mask_bit(int pattern, int row, int col)
{
	switch (pattern) {
	case 0:
		return (row + col) % 2 == 0;
	case 1:
		return row % 2 == 0;
	case 2:
		return col % 3 == 0;
	case 3:
		return (row + col) % 3 == 0;
	case 4:
		return (row / 2 + col / 3) % 2 == 0;
	case 5:
		return ((row * col) % 2 + (row * col) % 3) == 0;
	case 6:
		return (((row * col) % 2 + (row * col) % 3) % 2) == 0;
	case 7:
		return (((row + col) % 2 + (row * col) % 3) % 2) == 0;
	default:
		return 0;
	}
}

/*
 * set_module(qr, row, col, dark):
 *	Write the dark bit dark to the module at row and col of the
 *	code qr. The other bits of the byte carry the class of the
 *	module, and the call keeps them.
 */
static void
set_module(QRcode *qr, int row, int col, int dark)
{
	unsigned char	*m = &qr->data[row * qr->width + col];

	*m = (unsigned char)((*m & ~1) | dark);
}

/*
 * remask(qr):
 *	Move the code qr to mask pattern 0 (PROG-QR-6). The call
 *	reads the pattern of the library from the format
 *	information, it undoes that pattern over each module of the
 *	encoding region, it applies pattern 0 there, and it then
 *	writes QR_FORMAT_L0 to both copies of the format
 *	information.
 */
static void
remask(QRcode *qr)
{
	int	 old, row, col, i, bit, width = qr->width;

	old = read_mask(qr);
	for (row = 0; row < width; row++) {
		for (col = 0; col < width; col++) {
			if (qr->data[row * width + col] & QR_NONDATA)
				continue;
			if (mask_bit(old, row, col) != mask_bit(0, row, col))
				qr->data[row * width + col] ^= 1;
		}
	}
	for (i = 0; i < 15; i++) {
		bit = QR_FORMAT_L0[i] - '0';
		set_module(qr, format_one[i][0], format_one[i][1], bit);
		format_two(width, i, &row, &col);
		set_module(qr, row, col, bit);
	}
}

/*
 * module(qr, row, col):
 *	The dark bit of the module at row and col of the render.
 *	The render carries a quiet zone of QR_QUIET light modules on
 *	each side, so a position outside the code is light
 *	(PROG-QR-9). A row below the last one is light as well, and
 *	the last character of an odd row count reads it.
 */
static int
module(const QRcode *qr, int row, int col)
{
	int	 r = row - QR_QUIET, c = col - QR_QUIET;

	if (r < 0 || c < 0 || r >= qr->width || c >= qr->width)
		return 0;
	return qr->data[r * qr->width + c] & 1;
}

/*
 * render(qr, out):
 *	Write the code qr to the stream out, in UTF-8 half blocks
 *	(PROG-QR-1, PROG-QR-9). One character carries two module
 *	rows, so the render takes half the lines of the module
 *	count.
 *
 *	The call gives 0, and -1 when a write to out fails.
 */
static int
render(const QRcode *qr, FILE *out)
{
	int	 side = qr->width + 2 * QR_QUIET;
	int	 row, col, up, low;

	for (row = 0; row < side; row += 2) {
		for (col = 0; col < side; col++) {
			up = module(qr, row, col);
			low = module(qr, row + 1, col);
			if (fputs(blocks[up * 2 + low], out) == EOF)
				return -1;
		}
		if (fputc('\n', out) == EOF)
			return -1;
	}
	return 0;
}

/*
 * mnemonic_digits(in, len, digits):
 *	The Standard SeedQR digits of the len bytes at in, to the
 *	QR_DIGITS + 1 bytes at digits (PROG-QR-7). The input is a
 *	mnemonic when it holds QR_WORDS words of the BIP39 English
 *	list, with one space between two words and at most one line
 *	feed at the end. The digits are the zero-based index of each
 *	word, in four decimal digits (PROG-SCAN-2, D-22).
 *
 *	The call gives 0 for a mnemonic, and -1 for every other
 *	input. The caller renders every other input as a vault file.
 *
 *	A word is a secret, and wordlist_index() compares it with
 *	timingsafe_bcmp(3) (SEC-MEMORY-2).
 */
static int
mnemonic_digits(const unsigned char *in, size_t len, char *digits)
{
	size_t	 i, start = 0, index;
	int	 words = 0;

	if (len > 0 && in[len - 1] == '\n')
		len--;
	for (i = 0; i <= len; i++) {
		if (i < len && in[i] != ' ')
			continue;
		if (words == QR_WORDS)
			return -1;
		if (wordlist_index((const char *)in + start, i - start,
		    &index) != 0)
			return -1;
		if (snprintf(digits + words * 4, 5, "%04zu", index) != 4)
			return -1;
		words++;
		start = i + 1;
	}
	if (words != QR_WORDS)
		return -1;
	return 0;
}

int
qr_run(FILE *in, FILE *out, FILE *err)
{
	unsigned char	 buf[QR_VAULT_MAX + 1];
	char		 digits[QR_DIGITS + 1];
	QRinput		*input = NULL;
	QRcode		*qr = NULL;
	size_t		 len;
	int		 rv = 1;

	len = fread(buf, 1, sizeof(buf), in);
	if (ferror(in)) {
		fprintf(err, "fugupass-qr: the read of the input fails\n");
		goto out;
	}
	if (len == 0) {
		fprintf(err, "fugupass-qr: the input holds no byte\n");
		goto out;
	}
	if (len > QR_VAULT_MAX) {
		fprintf(err, "fugupass-qr: the input is longer than %d "
		    "bytes, and one QR code takes no more\n", QR_VAULT_MAX);
		goto out;
	}

	if (mnemonic_digits(buf, len, digits) == 0) {
		/* The Standard SeedQR shape (PROG-QR-2, PROG-QR-6). */
		if ((input = QRinput_new2(QR_MNEMONIC_VERSION,
		    QR_ECLEVEL_L)) == NULL ||
		    QRinput_append(input, QR_MODE_NUM, QR_DIGITS,
		    (const unsigned char *)digits) != 0 ||
		    (qr = QRcode_encodeInput(input)) == NULL) {
			fprintf(err, "fugupass-qr: the encode of the "
			    "mnemonic fails\n");
			goto out;
		}
		if (qr->version != QR_MNEMONIC_VERSION ||
		    qr->width != QR_MNEMONIC_WIDTH) {
			fprintf(err, "fugupass-qr: the mnemonic code is "
			    "version %d, and version %d is the one form\n",
			    qr->version, QR_MNEMONIC_VERSION);
			goto out;
		}
		remask(qr);
	} else {
		/* The vault-file shape (PROG-QR-3, PROG-QR-8). */
		qr = QRcode_encodeData((int)len, buf, 0, QR_ECLEVEL_L);
		if (qr == NULL) {
			fprintf(err, "fugupass-qr: the encode of the file "
			    "fails\n");
			goto out;
		}
	}

	if (render(qr, out) != 0) {
		fprintf(err, "fugupass-qr: the write of the code fails\n");
		goto out;
	}
	if (fflush(out) == EOF) {
		fprintf(err, "fugupass-qr: the write of the code fails\n");
		goto out;
	}
	rv = 0;
out:
	if (qr != NULL) {
		explicit_bzero(qr->data, (size_t)qr->width * qr->width);
		QRcode_free(qr);
	}
	if (input != NULL)
		QRinput_free(input);
	explicit_bzero(buf, sizeof(buf));
	explicit_bzero(digits, sizeof(digits));
	return rv;
}
