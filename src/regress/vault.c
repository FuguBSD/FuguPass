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
 * The tests of the vault on disk. The parts here are the seal and
 * the open of it (TEST-KAT-2). tests/vectors/seal.h holds the
 * vectors, and every test reads them from there. A test needs no
 * network and no oracle (TEST-KAT-5).
 *
 * The program prints nothing on a pass, and it exits 0. A wrong
 * value prints the test, the value and the vector to the standard
 * error, and the program exits 1. Every test runs on each run, so
 * one run reports every wrong value.
 *
 * The values of the tests are public constants of the tests, so
 * this file holds no secret and clears nothing.
 */

#include <sys/param.h>

#include <err.h>
#include <stdio.h>
#include <string.h>

#include "seal.h"

/*
 * The vectors, one directory below tests. Two files carry the name
 * seal.h: the interface of the source, and the vectors of it. The
 * include above takes the interface, and the include below carries
 * the directory name, which the source directory does not hold. No
 * order of the search path can exchange the two files.
 */
#include "vectors/seal.h"

/*
 * Each of the two files sets a guard of its own, and both of them
 * must enter this file. A build that reaches a wrong file stops
 * here.
 */
#if !defined(SEAL_H) || !defined(VECTORS_SEAL_H)
#error an include of vault.c reached the wrong seal.h
#endif

/* The vectors and the seal must name one version (VAULT-SEAL-1). */
#if KAT_SEAL_VERSION != SEAL_VERSION
#error the vectors and the seal name two versions
#endif

/* The longest plaintext of a vector, and the sealed form of it. */
#define PLAIN_MAX	128
#define SEALED_MAX	(PLAIN_MAX + SEAL_OVERHEAD)

/* The name of one test in a message, with the terminator. */
#define NAMELEN		80

/*
 * The plaintext of the round trip: one secret field, and then one
 * metadata field (VAULT-FORMAT-1, VAULT-FORMAT-4). The round trip
 * takes no vector, because a seal draws its own nonce. The value
 * of the secret field is a public test constant.
 */
static const unsigned char	roundtrip[] =
    "candidate-password: the-test-value-of-the-seal-vectors\n"
    "slot: 17\n";

/* The bytes of that plaintext, with no terminator, and sealed. */
#define ROUNDTRIP_LEN	(sizeof(roundtrip) - 1)
#define SEALED_LEN	(ROUNDTRIP_LEN + SEAL_OVERHEAD)

/* The rows of the vectors: the nonce, the plaintext, and the body. */
static const struct {
	const char	*nonce;
	const char	*plain;
	const char	*body;
} vectors[KAT_SEAL_COUNT] = KAT_SEAL_VECTORS;

/*
 * hexdigit(c):
 *	The value of the lower-case hex digit c, or -1 for another
 *	character.
 */
static int
hexdigit(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	return -1;
}

/*
 * hexsize(name, text, out):
 *	The byte count of the hex text at text, to out. A count of
 *	characters that no byte count gives prints the failure and
 *	gives -1.
 */
static int
hexsize(const char *name, const char *text, size_t *out)
{
	size_t	 len;

	len = strlen(text);
	if (len == 0 || len % 2 != 0) {
		warnx("%s: the vector holds %zu characters, and one byte "
		    "takes two of them", name, len);
		return -1;
	}
	*out = len / 2;
	return 0;
}

/*
 * hexbytes(name, text, out, outlen):
 *	The outlen bytes of the hex text at text, to out. A text of
 *	another length, or a character that is not lower-case hex,
 *	prints the failure and gives -1.
 */
static int
hexbytes(const char *name, const char *text, unsigned char *out, size_t outlen)
{
	size_t	 i, len;
	int	 hi, lo;

	len = strlen(text);
	if (len != 2 * outlen) {
		warnx("%s: the vector holds %zu characters, and the test "
		    "takes %zu bytes", name, len, outlen);
		return -1;
	}
	for (i = 0; i < outlen; i++) {
		hi = hexdigit(text[2 * i]);
		lo = hexdigit(text[2 * i + 1]);
		if (hi < 0 || lo < 0) {
			warnx("%s: the vector holds a character that is not "
			    "lower-case hex", name);
			return -1;
		}
		out[i] = (unsigned char)((hi << 4) | lo);
	}
	return 0;
}

/*
 * hexcheck(name, value, len, want):
 *	Compare the len bytes at value with the hex text at want. A
 *	difference prints the two values, and gives -1.
 */
static int
hexcheck(const char *name, const unsigned char *value, size_t len,
    const char *want)
{
	char	 got[2 * PLAIN_MAX + 1];
	size_t	 i;

	if (len > PLAIN_MAX) {
		warnx("%s: %zu bytes are too many for a vector", name, len);
		return -1;
	}
	for (i = 0; i < len; i++)
		snprintf(&got[2 * i], 3, "%02x", value[i]);
	got[2 * len] = '\0';
	if (strcmp(got, want) != 0) {
		warnx("%s: the value is %s, and the vector is %s", name, got,
		    want);
		return -1;
	}
	return 0;
}

/*
 * vectorseal(name, at, sealed, sealedlen, plainlen):
 *	The sealed value of the row at, to sealed, with the byte
 *	count of it to sealedlen and the byte count of the plaintext
 *	to plainlen. The value is the version byte, the nonce of the
 *	row, and then the body of the row (VAULT-SEAL-1).
 *
 *	A row that does not fit the buffer prints the failure and
 *	gives -1. That one gate holds the plaintext of the row to
 *	PLAIN_MAX bytes too, because a seal adds SEAL_OVERHEAD bytes
 *	to a plaintext.
 */
static int
vectorseal(const char *name, size_t at, unsigned char *sealed,
    size_t *sealedlen, size_t *plainlen)
{
	size_t	 bodylen;

	if (hexsize(name, vectors[at].plain, plainlen) != 0)
		return -1;
	if (hexsize(name, vectors[at].body, &bodylen) != 0)
		return -1;
	if (bodylen != *plainlen + SEAL_TAGLEN) {
		warnx("%s: the body holds %zu bytes, and the plaintext and "
		    "the tag take %zu", name, bodylen,
		    *plainlen + SEAL_TAGLEN);
		return -1;
	}
	*sealedlen = SEAL_OFF_BODY + bodylen;
	if (*sealedlen > SEALED_MAX) {
		warnx("%s: the sealed value holds %zu bytes, and the buffer "
		    "takes %d", name, *sealedlen, SEALED_MAX);
		return -1;
	}
	sealed[SEAL_OFF_VERSION] = KAT_SEAL_VERSION;
	if (hexbytes(name, vectors[at].nonce, &sealed[SEAL_OFF_NONCE],
	    SEAL_NONCELEN) != 0)
		return -1;
	return hexbytes(name, vectors[at].body, &sealed[SEAL_OFF_BODY],
	    bodylen);
}

/*
 * changed(key, sealed, at):
 *	Change the byte at the index at of a copy of the sealed
 *	value at sealed, and open the copy. It gives the result of
 *	the open, so 0 reports that the open takes the changed
 *	value.
 */
static int
changed(const unsigned char *key, const unsigned char *sealed, size_t at)
{
	unsigned char	 bad[SEALED_LEN];
	unsigned char	 got[ROUNDTRIP_LEN];

	memcpy(bad, sealed, sizeof(bad));
	bad[at] ^= 0x01;
	return seal_open(key, SEAL_KEYLEN, bad, sizeof(bad), got,
	    sizeof(got));
}

/*
 * test_vector():
 *	Each vector opens to the plaintext of it (TEST-KAT-2). The
 *	bodies come from the cryptography module of PyPI, and not
 *	from seal_seal(), so a matched pair of defects in the seal
 *	and the open cannot hide here. A wrong offset, wrong
 *	additional data, and a wrong nonce each fail this test
 *	(VAULT-SEAL-1, VAULT-SEAL-5).
 */
static int
test_vector(void)
{
	unsigned char	 key[SEAL_KEYLEN];
	unsigned char	 sealed[SEALED_MAX];
	unsigned char	 got[PLAIN_MAX];
	char		 name[NAMELEN];
	size_t		 at, sealedlen, plainlen;
	int		 rv = 0;

	if (hexbytes("the seal key", KAT_SEAL_KEY, key, sizeof(key)) != 0)
		return -1;
	for (at = 0; at < nitems(vectors); at++) {
		snprintf(name, sizeof(name), "the seal vector %zu", at + 1);
		if (vectorseal(name, at, sealed, &sealedlen,
		    &plainlen) != 0) {
			rv = -1;
			continue;
		}
		if (seal_open(key, sizeof(key), sealed, sealedlen, got,
		    plainlen) != 0) {
			warnx("%s: the open fails", name);
			rv = -1;
			continue;
		}
		if (hexcheck(name, got, plainlen, vectors[at].plain) != 0)
			rv = -1;
	}

	/*
	 * The tool reads one version (VAULT-SEAL-1). The body below
	 * carries the plaintext and the nonce of the first row under
	 * another version byte, and the tag of it is right. The open
	 * must fail on the version byte alone.
	 */
	if (vectorseal("the seal vector 1", 0, sealed, &sealedlen,
	    &plainlen) != 0)
		return -1;
	sealed[SEAL_OFF_VERSION] = KAT_SEAL_OTHER;
	if (hexbytes("the body of the other version", KAT_SEAL_OTHER_BODY,
	    &sealed[SEAL_OFF_BODY], plainlen + SEAL_TAGLEN) != 0)
		return -1;
	if (seal_open(key, sizeof(key), sealed, sealedlen, got,
	    plainlen) == 0) {
		warnx("a seal of another version: the open takes it");
		rv = -1;
	}
	return rv;
}

/*
 * test_roundtrip():
 *	A seal and then an open give the plaintext back
 *	(TEST-KAT-2). A changed byte of the version, of the nonce,
 *	of the body and of the tag fails the open, and a wrong key
 *	fails it too (VAULT-SEAL-4, VAULT-SEAL-5).
 */
static int
test_roundtrip(void)
{
	static const struct {
		size_t		 at;
		const char	*part;
	} spot[] = {
		{ SEAL_OFF_VERSION, "version byte" },
		{ SEAL_OFF_NONCE, "first byte of the nonce" },
		{ SEAL_OFF_NONCE + SEAL_NONCELEN - 1,
		    "last byte of the nonce" },
		{ SEAL_OFF_BODY, "first byte of the body" },
		{ SEALED_LEN - 1, "last byte of the tag" },
	};
	unsigned char	 key[SEAL_KEYLEN];
	unsigned char	 sealed[SEALED_LEN];
	unsigned char	 got[ROUNDTRIP_LEN];
	size_t		 i;
	int		 rv = 0;

	if (hexbytes("the seal key", KAT_SEAL_KEY, key, sizeof(key)) != 0)
		return -1;
	if (seal_seal(key, sizeof(key), roundtrip, ROUNDTRIP_LEN, sealed,
	    sizeof(sealed)) != 0) {
		warnx("the seal: the call fails");
		return -1;
	}
	if (sealed[SEAL_OFF_VERSION] != SEAL_VERSION) {
		warnx("the seal: the version byte is %02x, and the layout "
		    "takes %02x", sealed[SEAL_OFF_VERSION], SEAL_VERSION);
		rv = -1;
	}
	if (seal_open(key, sizeof(key), sealed, sizeof(sealed), got,
	    sizeof(got)) != 0) {
		warnx("the open of a seal: the call fails");
		return -1;
	}
	if (memcmp(got, roundtrip, sizeof(got)) != 0) {
		warnx("the open of a seal: the plaintext differs from the "
		    "input");
		rv = -1;
	}

	/*
	 * Every changed byte must fail the open. The version byte
	 * is the additional data, so the tag covers it too
	 * (VAULT-SEAL-5).
	 */
	for (i = 0; i < nitems(spot); i++)
		if (changed(key, sealed, spot[i].at) == 0) {
			warnx("a changed %s: the open takes it",
			    spot[i].part);
			rv = -1;
		}

	/*
	 * A wrong key gives the one failure of the seal
	 * (VAULT-SEAL-4). A junk oracle answer, a wrong passphrase,
	 * a wiped record and a stale wrap each reach the open with
	 * a wrong key.
	 */
	key[0] ^= 0x01;
	if (seal_open(key, sizeof(key), sealed, sizeof(sealed), got,
	    sizeof(got)) == 0) {
		warnx("a wrong key: the open takes it");
		rv = -1;
	}
	return rv;
}

/*
 * test_reject():
 *	The gates of seal_seal() give a failure (seal.h). Each case
 *	below names the mutation that it catches, and each of those
 *	mutations turns a caller error into a wrong file.
 *
 *	The other halves of the gates carry no case, because
 *	another path gives -1 for the same call. EVP_AEAD_CTX_init()
 *	rejects a keylen other than SEAL_KEYLEN. The AEAD rejects an
 *	outlen below the sum, because that sum is the output of it.
 *	The two halves of the gate of seal_open() hold each other:
 *	a sealedlen of SEAL_OVERHEAD or less makes the difference
 *	wrap, and no outlen matches the wrapped value.
 */
static int
test_reject(void)
{
	unsigned char	 key[SEAL_KEYLEN];
	unsigned char	 sealed[SEALED_LEN + 1];
	int		 rv = 0;

	if (hexbytes("the seal key", KAT_SEAL_KEY, key, sizeof(key)) != 0)
		return -1;

	/*
	 * A plaintext of 0 bytes gives -1 (seal.h). A removal of
	 * that half of the gate seals the empty plaintext, and the
	 * caller writes a vault file that holds no field.
	 */
	if (seal_seal(key, sizeof(key), roundtrip, 0, sealed,
	    SEAL_OVERHEAD) == 0) {
		warnx("a plaintext of no byte: the seal takes it");
		rv = -1;
	}

	/*
	 * An outlen other than the sum gives -1 (seal.h). A removal
	 * of that half of the gate seals the plaintext into the head
	 * of the buffer, and it leaves the last byte untouched. The
	 * caller then writes a file with one stale byte at the end
	 * of it.
	 */
	if (seal_seal(key, sizeof(key), roundtrip, ROUNDTRIP_LEN, sealed,
	    sizeof(sealed)) == 0) {
		warnx("a long output: the seal takes it");
		rv = -1;
	}
	return rv;
}

/*
 * test_nonce():
 *	Two seals of one plaintext write two nonces (VAULT-SEAL-3).
 *	One nonce under one key twice breaks the AEAD, so a fixed
 *	nonce or a missed draw must fail here.
 */
static int
test_nonce(void)
{
	unsigned char	 key[SEAL_KEYLEN];
	unsigned char	 first[SEALED_LEN];
	unsigned char	 second[SEALED_LEN];

	if (hexbytes("the seal key", KAT_SEAL_KEY, key, sizeof(key)) != 0)
		return -1;
	if (seal_seal(key, sizeof(key), roundtrip, ROUNDTRIP_LEN, first,
	    sizeof(first)) != 0 ||
	    seal_seal(key, sizeof(key), roundtrip, ROUNDTRIP_LEN, second,
	    sizeof(second)) != 0) {
		warnx("two seals: a call fails");
		return -1;
	}
	if (memcmp(&first[SEAL_OFF_NONCE], &second[SEAL_OFF_NONCE],
	    SEAL_NONCELEN) == 0) {
		warnx("two seals of one plaintext: the two nonces are equal");
		return -1;
	}
	if (memcmp(&first[SEAL_OFF_BODY], &second[SEAL_OFF_BODY],
	    ROUNDTRIP_LEN + SEAL_TAGLEN) == 0) {
		warnx("two seals of one plaintext: the two bodies are equal");
		return -1;
	}
	return 0;
}

int
main(void)
{
	int	 rv = 0;

	rv |= test_vector();
	rv |= test_roundtrip();
	rv |= test_reject();
	rv |= test_nonce();
	return rv != 0;
}
