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
 * The transport of the oracle protocol. This file sends one request
 * to a conforming oracle, and it reads the one answer of that
 * oracle (ORC-CONFORM-1). The transport is HTTP/1.1 over a socket,
 * or over libtls of the base system, and it runs in the core
 * process. The promises of that process hold inet and dns, and no
 * other program of FuguPass reaches the network (PROG-SPLIT-3,
 * PROG-SPLIT-6).
 *
 * The body of a request and the body of an answer each hold one
 * JSON object with one data member, and the value of that member is
 * the base64 of an envelope. http_data() reads the member with a
 * strict scanner, the mirror of the reader of the oracle (FuguOracle
 * PROTO-HTTP-7). No JSON library enters this file. b64_ntop(3) and
 * b64_pton(3) of libc make the two base64 steps, and b64_pton(3)
 * refuses a value that is not canonical.
 *
 * This file knows no envelope, no record, and no counter. It moves
 * bytes, and envelope.c reads them.
 *
 * http_post() reports three states, and a caller must hold the
 * three apart:
 *
 *	0		The oracle answered 200, and out holds the
 *			decoded bytes of the data member.
 *	HTTP_ESTATUS	The oracle answered another status, and
 *			status holds that status.
 *	-1		The transport failed. The name lookup, the
 *			socket, the TLS layer, or the reader stopped
 *			the request, and no body reached the caller.
 *
 * A fourth state belongs to envelope.h. ENVELOPE_EAUTH reports a
 * body that fails the authentication of the oracle (ORC-CONFORM-4),
 * and this file never gives that value. One caller of both files
 * can therefore report the four states as four values.
 *
 * Each buffer that holds a body gets explicit_bzero(3) on each exit
 * path, and a failure clears the output buffer of the caller
 * (SEC-MEMORY-1).
 */

#ifndef HTTP_H
#define HTTP_H

#include <stddef.h>

/*
 * The bytes of one body. The oracle refuses a longer request body
 * (FuguOracle PROTO-HTTP-2), and this file reads no longer answer.
 * One read takes the head of an answer and the body of it together,
 * so a long head leaves less room for the body.
 */
#define HTTP_BODY_MAX	4096

/* The bytes of the wrapper of one body: {"data": ""} */
#define HTTP_WRAP_LEN	12

/*
 * The bytes that one body carries, after the base64 step. The
 * wrapper takes the other bytes of the body.
 */
#define HTTP_DATA_MAX	((HTTP_BODY_MAX - HTTP_WRAP_LEN) / 4 * 3)

/*
 * The answer of an oracle that gives a status other than 200. The
 * state is neither a transport failure nor the authentication
 * failure of envelope.h. The value -2 belongs to ENVELOPE_EAUTH, so
 * this file steps over it.
 */
#define HTTP_ESTATUS	(-3)

/*
 * The file of the trust anchors that a https URL needs. libtls
 * reads it, and the unveil list of the core process must hold it
 * with the r permission (PROG-SPLIT-3).
 */
#define HTTP_CA_FILE	"/etc/ssl/cert.pem"

/*
 * http_post(url, req, reqlen, out, outsize, outlen, status):
 *	One POST of the reqlen bytes at req to url, and the bytes of
 *	the answer to out. url holds the scheme http or the scheme
 *	https, a host, an optional port, and the path. A literal
 *	address of IPv6 stands in brackets. The caller appends the
 *	path of the operation to the provisioned URL of the oracle
 *	(FuguOracle CLIENT-PROVISION-1).
 *
 *	reqlen counts at most HTTP_DATA_MAX bytes, outsize counts the
 *	room at out, and outlen takes the length of the answer. The
 *	answer of the oracle is one response envelope, so a caller of
 *	the protocol gives ENVELOPE_RESPONSE_LEN bytes of room.
 *
 *	status takes the status of an HTTP_ESTATUS answer, and 0 on
 *	each other answer. The three states stand in the comment
 *	above.
 *
 *	The request carries the header Connection: close, so the
 *	answer ends at the end of the stream. The socket takes a
 *	receive timeout and a send timeout, and connect(2) keeps the
 *	timeout of the kernel.
 */
int	http_post(const char *, const unsigned char *, size_t,
	    unsigned char *, size_t, size_t *, int *);

/*
 * http_data(body, bodylen, out, outsize, outlen):
 *	The decoded bytes of the data member of one body, to out.
 *	body holds the bodylen bytes of a JSON object, outsize counts
 *	the room at out, and outlen takes the length of the bytes.
 *
 *	The scanner takes one object with one data member of a
 *	string, and it steps over each other member. It accepts the
 *	insignificant whitespace of JSON. A second data member, a
 *	data member with an escape sequence, a data member of another
 *	type, a body with no data member, a byte after the object,
 *	and every other shape each answer -1. A value that is longer
 *	than one body, and a value that b64_pton(3) refuses, answer
 *	-1 as well.
 *
 *	http_post() reads the body of an answer with this function,
 *	and a -1 of it is a transport failure. The function is public
 *	because src/regress/http proves the reader without a socket.
 */
int	http_data(const char *, size_t, unsigned char *, size_t, size_t *);

#endif /* HTTP_H */
