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
 * The transport: the URL, the socket, the POST, and the strict
 * reader of the answer. http.h states the interface and the three
 * states.
 *
 * The scanner below mirrors the reader of FuguOracle, byte for byte
 * (FuguOracle PROTO-HTTP-7). The two sides therefore accept one
 * shape, and neither side accepts a shape that the other refuses.
 *
 * One request goes out, and one answer comes back. The connection
 * carries the header Connection: close, so the server closes the
 * stream after the answer, and the reader needs no length header
 * and no decoder of a chunked body.
 *
 * The bytes of this file travel on the wire: a sealed envelope, an
 * answer of the oracle, and the base64 of each one. envelope.c
 * holds each secret of a request, and it clears the plaintext
 * (SEC-MEMORY-1). This file clears each buffer that holds a body as
 * well, because a body of the wire must not stay on the stack.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <tls.h>
#include <unistd.h>

#include "http.h"

/* The one member that the scanner reads (FuguOracle PROTO-HTTP-7). */
#define DATA_NAME	"data"

/* The bytes of a number, of true, of false, and of null. */
#define TOKEN_BYTES	"+-.0123456789Eaeflnrstu"

/*
 * The base64 of one body, with the NUL byte. The writer needs the
 * base64 of HTTP_DATA_MAX bytes only. The reader takes a value as
 * long as one whole body, the bound of the reader of FuguOracle
 * (FuguOracle http.c).
 */
#define B64_MAX		(HTTP_BODY_MAX + 1)

/* The seconds of one read and of one write on the socket. */
#define CONN_TIMEOUT	30

/* The bytes of the head of a request, with the NUL byte. */
#define HEAD_MAX	768

/* The shortest status line: HTTP/1.1 200 with one byte after it. */
#define STATUS_MIN	13

/* The parts of one URL. */
struct url {
	char	 host[256];	/* the host, without the brackets */
	char	 port[8];	/* the port, as digits */
	char	 authority[264];	/* the host and the port, as given */
	char	 path[256];	/* the path, from the solidus */
	int	 secure;	/* 1 for the scheme https */
};

/* One connection: a socket, and the TLS layer of a https URL. */
struct conn {
	int		 fd;
	struct tls	*tls;
};

/* The cursor of the scanner: the next byte, and the end of the body. */
struct scan {
	const char	*p;
	const char	*end;
};

static int	 copy(char *, size_t, const char *, size_t);
static int	 printable(const char *);
static int	 portnum(const char *);
static int	 url_parse(const char *, struct url *);
static int	 dial(const struct url *);
static int	 conn_open(struct conn *, const struct url *);
static void	 conn_close(struct conn *);
static ssize_t	 conn_read(struct conn *, void *, size_t);
static ssize_t	 conn_write(struct conn *, const void *, size_t);
static int	 write_all(struct conn *, const char *, size_t);
static int	 read_all(struct conn *, char *, size_t, size_t *);
static int	 status_of(const char *, size_t, int *);
static int	 body_of(const char *, size_t, const char **, size_t *);
static void	 skip_ws(struct scan *);
static int	 take(struct scan *, char);
static int	 scan_string(struct scan *, const char **, size_t *, int *);
static int	 scan_token(struct scan *);
static int	 scan_value(struct scan *);
static int	 scan_data(const char *, size_t, const char **, size_t *);

/* The len bytes at src, as a string at dst. A long src answers -1. */
static int
copy(char *dst, size_t size, const char *src, size_t len)
{
	if (len >= size)
		return -1;
	memcpy(dst, src, len);
	dst[len] = '\0';
	return 0;
}

/*
 * The graphic bytes of a URL. A space, a control byte, and a byte
 * above the ASCII range each answer -1. The test stops a carriage
 * return and a line feed, so no part of a URL can add a header.
 */
static int
printable(const char *s)
{
	for (; *s != '\0'; s++)
		if (*s < '!' || *s > '~')
			return -1;
	return 0;
}

/* The port of a URL, as digits of at most 65535. */
static int
portnum(const char *s)
{
	long	 n = 0;

	if (*s == '\0')
		return -1;
	for (; *s != '\0'; s++) {
		if (*s < '0' || *s > '9')
			return -1;
		n = n * 10 + (*s - '0');
		if (n > 65535)
			return -1;
	}
	return 0;
}

/*
 * The parts of one URL. The scheme gives the default port and the
 * TLS layer, the authority gives the host and the port, and the
 * rest is the path. A literal address of IPv6 stands in brackets,
 * and the colon of the port stands after the closing bracket. An
 * empty path is the root path.
 */
static int
url_parse(const char *url, struct url *u)
{
	const char	*rest, *authend, *hostend, *port;

	memset(u, 0, sizeof(*u));
	if (strncmp(url, "http://", 7) == 0) {
		rest = url + 7;
		if (copy(u->port, sizeof(u->port), "80", 2) != 0)
			return -1;
	} else if (strncmp(url, "https://", 8) == 0) {
		rest = url + 8;
		u->secure = 1;
		if (copy(u->port, sizeof(u->port), "443", 3) != 0)
			return -1;
	} else
		return -1;

	if ((authend = strchr(rest, '/')) == NULL)
		authend = rest + strlen(rest);
	if (copy(u->authority, sizeof(u->authority), rest,
	    (size_t)(authend - rest)) != 0)
		return -1;
	if (*rest == '[') {
		hostend = memchr(rest, ']', (size_t)(authend - rest));
		if (hostend == NULL)
			return -1;
		if (copy(u->host, sizeof(u->host), rest + 1,
		    (size_t)(hostend - rest - 1)) != 0)
			return -1;
		port = hostend + 1;
	} else {
		hostend = memchr(rest, ':', (size_t)(authend - rest));
		if (hostend == NULL)
			hostend = authend;
		if (copy(u->host, sizeof(u->host), rest,
		    (size_t)(hostend - rest)) != 0)
			return -1;
		port = hostend;
	}
	if (u->host[0] == '\0')
		return -1;
	if (port < authend) {
		if (*port != ':')
			return -1;
		if (copy(u->port, sizeof(u->port), port + 1,
		    (size_t)(authend - port - 1)) != 0)
			return -1;
		if (portnum(u->port) != 0)
			return -1;
	} else if (port != authend)
		return -1;
	if (*authend == '\0') {
		if (copy(u->path, sizeof(u->path), "/", 1) != 0)
			return -1;
	} else if (copy(u->path, sizeof(u->path), authend,
	    strlen(authend)) != 0)
		return -1;
	if (printable(u->authority) != 0 || printable(u->path) != 0)
		return -1;
	return 0;
}

/*
 * One connected socket to the host and the port of a URL. The
 * socket takes a receive timeout and a send timeout, so a silent
 * peer cannot hold the core process. connect(2) keeps the timeout
 * of the kernel.
 */
static int
dial(const struct url *u)
{
	struct addrinfo	 hints, *res, *ai;
	struct timeval	 tv;
	int		 fd = -1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(u->host, u->port, &hints, &res) != 0)
		return -1;
	for (ai = res; ai != NULL; ai = ai->ai_next) {
		fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd == -1)
			continue;
		if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
			break;
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	if (fd == -1)
		return -1;
	tv.tv_sec = CONN_TIMEOUT;
	tv.tv_usec = 0;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1 ||
	    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == -1) {
		close(fd);
		return -1;
	}
	return fd;
}

/*
 * The connection of one request. A http URL gives a plain socket,
 * and a https URL adds the TLS layer of libtls over that socket.
 * libtls reads the trust anchors of HTTP_CA_FILE, and it proves the
 * name of the host. The envelope authenticates the oracle, and TLS
 * is not the authenticator (ORC-CONFORM-4).
 */
static int
conn_open(struct conn *c, const struct url *u)
{
	struct tls_config	*cfg;

	c->fd = -1;
	c->tls = NULL;
	if ((c->fd = dial(u)) == -1)
		return -1;
	if (u->secure == 0)
		return 0;
	if ((cfg = tls_config_new()) == NULL)
		return -1;
	if (tls_config_set_ca_file(cfg, HTTP_CA_FILE) != 0 ||
	    (c->tls = tls_client()) == NULL ||
	    tls_configure(c->tls, cfg) != 0 ||
	    tls_connect_socket(c->tls, c->fd, u->host) != 0) {
		tls_config_free(cfg);
		return -1;
	}
	tls_config_free(cfg);
	return 0;
}

/* The close of one connection. A second call changes nothing. */
static void
conn_close(struct conn *c)
{
	if (c->tls != NULL) {
		tls_close(c->tls);
		tls_free(c->tls);
		c->tls = NULL;
	}
	if (c->fd != -1) {
		close(c->fd);
		c->fd = -1;
	}
}

/*
 * One read of the connection. The answer is the bytes, 0 at the end
 * of the stream, and -1 on a failure. The socket blocks, so a want
 * of libtls repeats the call.
 */
static ssize_t
conn_read(struct conn *c, void *buf, size_t size)
{
	ssize_t	 r;

	for (;;) {
		if (c->tls != NULL) {
			r = tls_read(c->tls, buf, size);
			if (r == TLS_WANT_POLLIN || r == TLS_WANT_POLLOUT)
				continue;
			return r;
		}
		if ((r = read(c->fd, buf, size)) == -1 && errno == EINTR)
			continue;
		return r;
	}
}

/* One write of the connection, under the rules of conn_read(). */
static ssize_t
conn_write(struct conn *c, const void *buf, size_t size)
{
	ssize_t	 w;

	for (;;) {
		if (c->tls != NULL) {
			w = tls_write(c->tls, buf, size);
			if (w == TLS_WANT_POLLIN || w == TLS_WANT_POLLOUT)
				continue;
			return w;
		}
		if ((w = write(c->fd, buf, size)) == -1 && errno == EINTR)
			continue;
		return w;
	}
}

/* The len bytes at buf, to the connection. A short write repeats. */
static int
write_all(struct conn *c, const char *buf, size_t len)
{
	size_t	 off = 0;
	ssize_t	 w;

	while (off < len) {
		if ((w = conn_write(c, buf + off, len - off)) <= 0)
			return -1;
		off += (size_t)w;
	}
	return 0;
}

/*
 * The whole answer of the connection, to the size bytes at buf. The
 * read runs to the end of the stream, and len takes the bytes. An
 * answer of more than size bytes answers -1, and the one byte after
 * the buffer is the evidence of it.
 */
static int
read_all(struct conn *c, char *buf, size_t size, size_t *len)
{
	char	 over;
	size_t	 off = 0;
	ssize_t	 r;

	*len = 0;
	while (off < size) {
		if ((r = conn_read(c, buf + off, size - off)) == -1)
			return -1;
		if (r == 0) {
			*len = off;
			return 0;
		}
		off += (size_t)r;
	}
	if (conn_read(c, &over, 1) != 0)
		return -1;
	*len = off;
	return 0;
}

/*
 * The status of one answer. The status line holds the version, one
 * space, three digits, and one byte after them. Every other shape
 * answers -1.
 */
static int
status_of(const char *resp, size_t len, int *status)
{
	int	 i, n = 0;

	if (len < STATUS_MIN || memcmp(resp, "HTTP/1.", 7) != 0)
		return -1;
	if (resp[7] != '0' && resp[7] != '1')
		return -1;
	if (resp[8] != ' ')
		return -1;
	for (i = 9; i < 12; i++) {
		if (resp[i] < '0' || resp[i] > '9')
			return -1;
		n = n * 10 + (resp[i] - '0');
	}
	if (resp[12] != ' ' && resp[12] != '\r')
		return -1;
	*status = n;
	return 0;
}

/* The body of one answer: the bytes after the empty line. */
static int
body_of(const char *resp, size_t len, const char **body, size_t *bodylen)
{
	const char	*p;

	if ((p = memmem(resp, len, "\r\n\r\n", 4)) == NULL)
		return -1;
	*body = p + 4;
	*bodylen = len - (size_t)(p + 4 - resp);
	return 0;
}

/* Step over the insignificant whitespace of JSON. */
static void
skip_ws(struct scan *s)
{
	while (s->p < s->end && (*s->p == ' ' || *s->p == '\t' ||
	    *s->p == '\n' || *s->p == '\r'))
		s->p++;
}

/* Take one byte c. Every other byte answers -1, and it stays. */
static int
take(struct scan *s, char c)
{
	if (s->p == s->end || *s->p != c)
		return -1;
	s->p++;
	return 0;
}

/*
 * The span of one JSON string. The cursor stands on the opening
 * quote, and a 0 answer leaves it after the closing quote. val and
 * len take the bytes between the quotes, and esc answers 1 for a
 * string with an escape sequence. A control byte and an unterminated
 * string each answer -1. The control byte test refuses the NUL byte,
 * so the decoder below reads the whole value of a data member.
 */
static int
scan_string(struct scan *s, const char **val, size_t *len, int *esc)
{
	const char	*start;

	*esc = 0;
	if (take(s, '"') != 0)
		return -1;
	start = s->p;
	while (s->p < s->end && *s->p != '"') {
		if ((unsigned char)*s->p < 0x20)
			return -1;
		if (*s->p == '\\') {
			*esc = 1;
			if (++s->p == s->end)
				return -1;
		}
		s->p++;
	}
	if (take(s, '"') != 0)
		return -1;
	*val = start;
	*len = (size_t)(s->p - 1 - start);
	return 0;
}

/* Step over one number, one true, one false, or one null. */
static int
scan_token(struct scan *s)
{
	const char	*start = s->p;

	while (s->p < s->end && *s->p != '\0' &&
	    strchr(TOKEN_BYTES, *s->p) != NULL)
		s->p++;
	return s->p == start ? -1 : 0;
}

/*
 * Step over the value of an unknown member. A string carries its
 * own escape sequences, and an object or an array runs to the byte
 * that closes it. The scanner reads the extent of such a value, and
 * it reads no grammar inside it. Every other value is one token.
 * The cursor stops on the byte after the value.
 */
static int
scan_value(struct scan *s)
{
	const char	*val;
	size_t		 len, depth = 0;
	int		 esc;

	do {
		if (s->p == s->end)
			return -1;
		switch (*s->p) {
		case '"':
			if (scan_string(s, &val, &len, &esc) != 0)
				return -1;
			break;
		case '{':
		case '[':
			depth++;
			s->p++;
			break;
		case '}':
		case ']':
			if (depth == 0)
				return -1;
			depth--;
			s->p++;
			break;
		case ',':
		case ':':
			if (depth == 0)
				return -1;
			s->p++;
			break;
		default:
			if (scan_token(s) != 0)
				return -1;
			break;
		}
		skip_ws(s);
	} while (depth > 0);
	return 0;
}

/*
 * The base64 value of the data member of one body. val and len take
 * the bytes of the value. The scanner accepts one object with one
 * data member of a string, and it steps over each other member. A
 * second data member, a data member with an escape sequence, a data
 * member of another type, a byte after the object, and every other
 * shape answer -1. An object with no data member answers -1 as
 * well, because this file reads one shape only.
 */
static int
scan_data(const char *body, size_t body_len, const char **val, size_t *len)
{
	struct scan	 s;
	const char	*name;
	size_t		 name_len;
	int		 esc, found = 0;

	s.p = body;
	s.end = body + body_len;
	skip_ws(&s);
	if (take(&s, '{') != 0)
		return -1;
	skip_ws(&s);
	for (;;) {
		if (scan_string(&s, &name, &name_len, &esc) != 0)
			return -1;
		skip_ws(&s);
		if (take(&s, ':') != 0)
			return -1;
		skip_ws(&s);
		if (esc == 0 && name_len == sizeof(DATA_NAME) - 1 &&
		    memcmp(name, DATA_NAME, name_len) == 0) {
			if (found)
				return -1;
			if (scan_string(&s, val, len, &esc) != 0 || esc != 0)
				return -1;
			found = 1;
		} else if (scan_value(&s) != 0)
			return -1;
		skip_ws(&s);
		if (take(&s, ',') != 0)
			break;
		skip_ws(&s);
	}
	if (take(&s, '}') != 0)
		return -1;
	skip_ws(&s);
	return found && s.p == s.end ? 0 : -1;
}

int
http_data(const char *body, size_t bodylen, unsigned char *out,
    size_t outsize, size_t *outlen)
{
	char		 b64[B64_MAX];
	const char	*val;
	size_t		 len;
	int		 n, rv = -1;

	*outlen = 0;

	/*
	 * b64_pton(3) reads a string, and the value of the member
	 * holds no NUL byte, so the copy below terminates it. A
	 * value that is longer than one body cannot come from an
	 * oracle, and copy() refuses it.
	 */
	if (scan_data(body, bodylen, &val, &len) != 0)
		goto out;
	if (copy(b64, sizeof(b64), val, len) != 0)
		goto out;
	if ((n = b64_pton(b64, out, outsize)) < 0)
		goto out;
	*outlen = (size_t)n;
	rv = 0;
out:
	explicit_bzero(b64, sizeof(b64));
	if (rv != 0)
		explicit_bzero(out, outsize);
	return rv;
}

int
http_post(const char *url, const unsigned char *req, size_t reqlen,
    unsigned char *out, size_t outsize, size_t *outlen, int *status)
{
	struct url	 u;
	struct conn	 c;
	char		 b64[B64_MAX];
	char		 request[HEAD_MAX + HTTP_BODY_MAX];
	char		 resp[HTTP_BODY_MAX];
	const char	*body;
	size_t		 resplen, bodylen;
	int		 code = 0, n, rv = -1;

	*outlen = 0;
	*status = 0;
	c.fd = -1;
	c.tls = NULL;
	if (reqlen == 0 || reqlen > HTTP_DATA_MAX)
		goto out;
	if (url_parse(url, &u) != 0)
		goto out;
	if (b64_ntop(req, reqlen, b64, sizeof(b64)) < 0)
		goto out;
	n = snprintf(request, sizeof(request),
	    "POST %s HTTP/1.1\r\n"
	    "Host: %s\r\n"
	    "Content-Type: application/json\r\n"
	    "Content-Length: %zu\r\n"
	    "Connection: close\r\n"
	    "\r\n"
	    "{\"data\": \"%s\"}",
	    u.path, u.authority, HTTP_WRAP_LEN + strlen(b64), b64);
	if (n < 0 || (size_t)n >= sizeof(request))
		goto out;
	if (conn_open(&c, &u) != 0)
		goto out;
	if (write_all(&c, request, (size_t)n) != 0)
		goto out;
	if (read_all(&c, resp, sizeof(resp), &resplen) != 0)
		goto out;
	if (status_of(resp, resplen, &code) != 0)
		goto out;
	if (code != 200) {
		*status = code;
		rv = HTTP_ESTATUS;
		goto out;
	}
	if (body_of(resp, resplen, &body, &bodylen) != 0)
		goto out;
	if (http_data(body, bodylen, out, outsize, outlen) != 0)
		goto out;
	rv = 0;
out:
	conn_close(&c);
	explicit_bzero(b64, sizeof(b64));
	explicit_bzero(request, sizeof(request));
	explicit_bzero(resp, sizeof(resp));
	if (rv != 0) {
		explicit_bzero(out, outsize);
		*outlen = 0;
	}
	return rv;
}
