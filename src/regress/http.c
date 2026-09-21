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
 * The driver of the transport tests. src/regress/http.t starts a
 * fixture server, and it runs this program against that server. A
 * test of a transport needs a peer, so the tests live in the Perl
 * file, and this program holds no test of its own.
 *
 * The program prints one line on the standard output, and it exits
 * 0. The line names the state that src/http.c reports:
 *
 *	ok <hex>	The call gave the bytes, as lower-case hex.
 *	http <status>	The oracle gave another status.
 *	transport	The transport failed.
 *	reader		The reader refused the body.
 *
 * The two modes are:
 *
 *	http post <url> <hex>	One POST of the hex bytes to the URL.
 *	http data <file>	One read of the body in the file.
 *
 * The post mode proves the three states of http_post(), and the
 * data mode proves the reader without a socket. A wrong argument
 * exits 1 with a message, and no state line.
 *
 * The bytes of this program are public test values, so it holds no
 * secret and it clears nothing.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "http.h"

/* The bytes of the longest body of the data mode. */
#define BODY_MAX	(2 * HTTP_BODY_MAX)

static int	 hexbytes(const char *, unsigned char *, size_t, size_t *);
static int	 readfile(const char *, char *, size_t, size_t *);
static void	 report(int, const char *, int, const unsigned char *,
		    size_t);

/*
 * The bytes of one lower-case hex string, to out. An odd length, a
 * byte that is not a hex digit, and a string that is longer than
 * size bytes each answer -1.
 */
static int
hexbytes(const char *hex, unsigned char *out, size_t size, size_t *len)
{
	size_t		 i, n;
	unsigned int	 byte;

	n = strlen(hex);
	if (n % 2 != 0 || n / 2 > size)
		return -1;
	for (i = 0; i < n; i += 2) {
		if (strchr("0123456789abcdef", hex[i]) == NULL ||
		    strchr("0123456789abcdef", hex[i + 1]) == NULL)
			return -1;
		if (sscanf(hex + i, "%2x", &byte) != 1)
			return -1;
		out[i / 2] = (unsigned char)byte;
	}
	*len = n / 2;
	return 0;
}

/*
 * The whole file at path, to the size bytes at buf. A file that
 * does not open, and a file of more than size bytes, each answer
 * -1.
 */
static int
readfile(const char *path, char *buf, size_t size, size_t *len)
{
	FILE	*fp;
	size_t	 n;
	int	 rv = -1;

	if ((fp = fopen(path, "r")) == NULL)
		return -1;
	n = fread(buf, 1, size, fp);
	if (ferror(fp) == 0 && feof(fp) != 0) {
		*len = n;
		rv = 0;
	}
	fclose(fp);
	return rv;
}

/*
 * The one line of one answer. fail names the failure state of the
 * mode, and the other three states read the same in both modes.
 */
static void
report(int answer, const char *fail, int status, const unsigned char *out,
    size_t outlen)
{
	size_t	 i;

	if (answer == HTTP_ESTATUS) {
		printf("http %d\n", status);
		return;
	}
	if (answer != 0) {
		printf("%s\n", fail);
		return;
	}
	printf("ok ");
	for (i = 0; i < outlen; i++)
		printf("%02x", out[i]);
	printf("\n");
}

int
main(int argc, char *argv[])
{
	unsigned char	 req[HTTP_DATA_MAX];
	unsigned char	 out[HTTP_DATA_MAX];
	char		 body[BODY_MAX];
	size_t		 reqlen = 0, bodylen = 0, outlen = 0;
	int		 answer, status = 0;

	if (argc == 4 && strcmp(argv[1], "post") == 0) {
		if (hexbytes(argv[3], req, sizeof(req), &reqlen) != 0)
			errx(1, "the request is not hex: %s", argv[3]);
		answer = http_post(argv[2], req, reqlen, out, sizeof(out),
		    &outlen, &status);
		report(answer, "transport", status, out, outlen);
		return 0;
	}
	if (argc == 3 && strcmp(argv[1], "data") == 0) {
		if (readfile(argv[2], body, sizeof(body), &bodylen) != 0)
			errx(1, "the body does not read: %s", argv[2]);
		answer = http_data(body, bodylen, out, sizeof(out), &outlen);
		report(answer, "reader", 0, out, outlen);
		return 0;
	}
	fprintf(stderr, "usage: http post <url> <hex>\n");
	fprintf(stderr, "       http data <file>\n");
	return 1;
}
