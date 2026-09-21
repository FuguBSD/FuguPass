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
 * The known-answer tests of the request envelope (ORC-CONFORM-4,
 * ORC-CONFORM-5). The parts are the tweaked oracle key, the shared
 * secret, the two key halves of both labels, the signed message, the
 * signature, the two request forms, and the open of the response.
 *
 * tests/vectors/oracle.h holds the vectors, and FuguOracle owns
 * them. The generator of that repository writes both sides of each
 * transcript, with the ephemeral private key, so a client reads the
 * same file. A test needs no network and no oracle.
 *
 * The program prints nothing on a pass, and it exits 0. A wrong
 * value prints the test, the value and the vector to the standard
 * error, and the program exits 1. Every test runs on each run, so
 * one run reports every wrong value.
 *
 * The values of the tests are public constants of the tests, so this
 * file holds no secret and clears nothing.
 */

#include <sys/param.h>

#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <secp256k1.h>
#include <secp256k1_recovery.h>

#include "envelope.h"

/*
 * The vectors, one directory below tests. The include carries the
 * directory name, which the source directory does not hold, so no
 * order of the search path can reach another file of the name.
 */
#include "vectors/oracle.h"

/*
 * Each of the two files sets a guard of its own, and both must enter
 * this file. A build that reaches a wrong file stops here.
 */
#if !defined(ENVELOPE_H) || !defined(VECTORS_ORACLE_H)
#error an include of envelope.c reached the wrong header
#endif

/* The longest vector of the file is the 229-byte set_pin envelope. */
#define VECMAX		256

/* The name of one test in a message, with the terminator. */
#define NAMELEN		80

/* The plaintext room of one response envelope, for the open. */
#define PLAINMAX	(ENVELOPE_RESPONSE_LEN - ENVELOPE_OVERHEAD)

/* The byte that a mutation writes over a buffer of a test. */
#define SENTINEL	0xa5

/*
 * One request of the transcript. Each row holds the ephemeral key,
 * the counter, the tweaked oracle key of the pair, and the bytes of
 * the request that the vectors carry.
 */
static const struct {
	const char	*name;
	const char	*ckepriv;
	const char	*cke;
	uint32_t	 counter;
	const char	*qprime;
	int		 parity;
	const char	*msghash;
	const char	*entropy;	/* NULL for the 97-byte form */
	const char	*payload;
	const char	*iv;
	const char	*envelope;
	size_t		 ptlen;
	size_t		 envlen;
} requests[] = {
	{ "the set_pin request", V_SET_CKE_PRIV, V_SET_CKE, V_SET_COUNTER,
	    V_SET_QPRIME, V_SET_QPRIME_PARITY, V_SET_MSGHASH, V_ENTROPY,
	    V_SET_PAYLOAD, V_SET_IV, V_SET_ENVELOPE, ENVELOPE_SET_PTLEN,
	    ENVELOPE_SET_LEN },
	{ "the get_pin request", V_GET_CKE_PRIV, V_GET_CKE, V_GET_COUNTER,
	    V_GET_QPRIME, V_GET_QPRIME_PARITY, V_GET_MSGHASH, NULL,
	    V_GET_PAYLOAD, V_GET_IV, V_GET_ENVELOPE, ENVELOPE_GET_PTLEN,
	    ENVELOPE_GET_LEN },
};

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
 * hexload(name, text, out):
 *	Every byte of the hex text at text, to the VECMAX bytes at
 *	out. The answer is the count of the bytes, or 0 for a text
 *	that the buffer cannot hold and for a text of an odd length.
 */
static size_t
hexload(const char *name, const char *text, unsigned char *out)
{
	size_t	 len;

	len = strlen(text);
	if (len % 2 != 0 || len / 2 > VECMAX) {
		warnx("%s: the vector holds %zu characters", name, len);
		return 0;
	}
	if (hexbytes(name, text, out, len / 2) != 0)
		return 0;
	return len / 2;
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
	char	 got[2 * VECMAX + 1];
	size_t	 i;

	if (len > VECMAX) {
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
 * qprime_bytes(name, xonly, parity, out):
 *	The tweaked oracle key of a vector, in the compressed form of
 *	ENVELOPE_PUBKEYLEN bytes at out. The vectors hold the x-only
 *	key and the parity bit apart, and the prefix byte of the
 *	compressed form carries the parity.
 */
static int
qprime_bytes(const char *name, const char *xonly, int parity,
    unsigned char *out)
{
	out[0] = (unsigned char)(0x02 + parity);
	return hexbytes(name, xonly, out + 1, ENVELOPE_XONLYLEN);
}

/*
 * recovercheck(name, hash, sig, want):
 *	Recover the public key of the signature of ENVELOPE_SIGLEN
 *	bytes at sig, over the ENVELOPE_HASHLEN bytes at hash, and
 *	compare it with the hex text at want (FuguOracle
 *	PROTO-PAYLOAD-4). The oracle runs this step over every
 *	payload, so the answer is the identity of the client. The
 *	library serves it here, because a client signs and never
 *	recovers.
 */
static int
recovercheck(const char *name, const unsigned char *hash,
    const unsigned char *sig, const char *want)
{
	secp256k1_ecdsa_recoverable_signature	 rsig;
	secp256k1_pubkey			 pubkey;
	unsigned char				 out[ENVELOPE_PUBKEYLEN];
	size_t					 len = sizeof(out);
	int					 recid;

	/* The header byte of the signature holds the recovery id. */
	recid = (sig[0] - 27) & 3;
	if (secp256k1_ecdsa_recoverable_signature_parse_compact(
	    secp256k1_context_static, &rsig, sig + 1, recid) != 1) {
		warnx("%s: the library rejects the compact signature", name);
		return -1;
	}
	if (secp256k1_ecdsa_recover(secp256k1_context_static, &pubkey, &rsig,
	    hash) != 1) {
		warnx("%s: the recovery of the public key fails", name);
		return -1;
	}
	if (secp256k1_ec_pubkey_serialize(secp256k1_context_static, out, &len,
	    &pubkey, SECP256K1_EC_COMPRESSED) != 1 ||
	    len != ENVELOPE_PUBKEYLEN) {
		warnx("%s: the serialization of the public key fails", name);
		return -1;
	}
	return hexcheck(name, out, len, want);
}

/*
 * test_draw():
 *	The draw of one request gives a key that the curve takes, and
 *	two draws differ (ORC-CONFORM-5, SEC-ENTROPY-4). This test
 *	reads no vector, because every draw is fresh.
 */
static int
test_draw(void)
{
	unsigned char	 first[ENVELOPE_KEYLEN], second[ENVELOPE_KEYLEN];
	unsigned char	 iv1[ENVELOPE_IVLEN], iv2[ENVELOPE_IVLEN];
	int		 rv = 0;

	envelope_draw(first, iv1);
	envelope_draw(second, iv2);
	if (secp256k1_ec_seckey_verify(secp256k1_context_static, first) != 1 ||
	    secp256k1_ec_seckey_verify(secp256k1_context_static,
	    second) != 1) {
		warnx("the draw: the curve rejects the key");
		rv = -1;
	}
	if (memcmp(first, second, sizeof(first)) == 0) {
		warnx("the draw: two ephemeral keys are equal");
		rv = -1;
	}
	if (memcmp(iv1, iv2, sizeof(iv1)) == 0) {
		warnx("the draw: two initialization vectors are equal");
		rv = -1;
	}
	return rv;
}

/*
 * test_tweak():
 *	The tweaked oracle key Q' of each request of the vectors
 *	matches, in the x-only key and in the Y parity (FuguOracle
 *	PROTO-TWEAK-4). The client reaches Q' from the provisioned
 *	static public key, and it holds no private key of the oracle.
 */
static int
test_tweak(void)
{
	unsigned char	 pub[ENVELOPE_PUBKEYLEN], cke[ENVELOPE_PUBKEYLEN];
	unsigned char	 got[ENVELOPE_PUBKEYLEN];
	char		 name[NAMELEN];
	size_t		 c;
	int		 rv = 0;

	if (hexbytes("the static public key", V_STATIC_PUB, pub,
	    sizeof(pub)) != 0)
		return -1;

	/* The row of the vectors that stands outside the transcript. */
	if (hexbytes("the tweak cke", V_TWEAK_CKE, cke, sizeof(cke)) != 0)
		return -1;
	if (envelope_tweak(pub, cke, V_TWEAK_COUNTER, got) != 0) {
		warnx("the tweaked key: the call fails");
		rv = -1;
	} else {
		if (got[0] != 0x02 + V_TWEAK_QPRIME_PARITY) {
			warnx("the tweaked key: the prefix byte is %02x, and "
			    "the parity of the vector is %d", got[0],
			    V_TWEAK_QPRIME_PARITY);
			rv = -1;
		}
		if (hexcheck("the tweaked key", got + 1, ENVELOPE_XONLYLEN,
		    V_TWEAK_QPRIME) != 0)
			rv = -1;
	}

	for (c = 0; c < nitems(requests); c++) {
		snprintf(name, sizeof(name), "the tweaked key of %s",
		    requests[c].name);
		if (hexbytes(name, requests[c].cke, cke, sizeof(cke)) != 0) {
			rv = -1;
			continue;
		}
		if (envelope_tweak(pub, cke, requests[c].counter, got) != 0) {
			warnx("%s: the call fails", name);
			rv = -1;
			continue;
		}
		if (got[0] != 0x02 + requests[c].parity) {
			warnx("%s: the prefix byte is %02x, and the parity of "
			    "the vector is %d", name, got[0],
			    requests[c].parity);
			rv = -1;
		}
		if (hexcheck(name, got + 1, ENVELOPE_XONLYLEN,
		    requests[c].qprime) != 0)
			rv = -1;
	}
	return rv;
}

/*
 * test_keys():
 *	The shared secret of the client side matches, and the two key
 *	halves of both labels match (FuguOracle PROTO-ENCRYPT-1,
 *	FuguOracle PROTO-ENCRYPT-2). The client runs the ECDH with
 *	its ephemeral private key and Q', and the oracle runs it with
 *	d' and cke. Both reach the one secret that the two labels
 *	split (FuguOracle PROTO-ENCRYPT-5).
 */
static int
test_keys(void)
{
	unsigned char	 priv[ENVELOPE_KEYLEN];
	unsigned char	 qprime[ENVELOPE_PUBKEYLEN];
	unsigned char	 shared[ENVELOPE_HASHLEN];
	unsigned char	 enckey[ENVELOPE_KEYLEN], mackey[ENVELOPE_KEYLEN];
	int		 rv = 0;

	if (hexbytes("the tweak cke private key", V_TWEAK_CKE_PRIV, priv,
	    sizeof(priv)) != 0)
		return -1;
	if (qprime_bytes("the tweaked key", V_TWEAK_QPRIME,
	    V_TWEAK_QPRIME_PARITY, qprime) != 0)
		return -1;

	if (envelope_shared(priv, qprime, shared) != 0) {
		warnx("the shared secret: the call fails");
		rv = -1;
	} else if (hexcheck("the shared secret", shared, sizeof(shared),
	    V_TWEAK_SHARED) != 0)
		rv = -1;

	if (envelope_keys(priv, qprime, ENVELOPE_LABEL_REQUEST, enckey,
	    mackey) != 0) {
		warnx("the request keys: the call fails");
		rv = -1;
	} else {
		if (hexcheck("the request enc key", enckey, sizeof(enckey),
		    V_TWEAK_REQUEST_ENC_KEY) != 0)
			rv = -1;
		if (hexcheck("the request mac key", mackey, sizeof(mackey),
		    V_TWEAK_REQUEST_MAC_KEY) != 0)
			rv = -1;
	}

	if (envelope_keys(priv, qprime, ENVELOPE_LABEL_RESPONSE, enckey,
	    mackey) != 0) {
		warnx("the response keys: the call fails");
		rv = -1;
	} else {
		if (hexcheck("the response enc key", enckey, sizeof(enckey),
		    V_TWEAK_RESPONSE_ENC_KEY) != 0)
			rv = -1;
		if (hexcheck("the response mac key", mackey, sizeof(mackey),
		    V_TWEAK_RESPONSE_MAC_KEY) != 0)
			rv = -1;
	}
	return rv;
}

/*
 * test_payload():
 *	The signed message of each payload form matches, and the
 *	signature of it matches the bytes of the transcript
 *	(FuguOracle PROTO-PAYLOAD-2, FuguOracle PROTO-PAYLOAD-3). The
 *	recovery of each signature gives the client public key, so
 *	the oracle addresses the record of that client.
 */
static int
test_payload(void)
{
	unsigned char	 cke[ENVELOPE_PUBKEYLEN];
	unsigned char	 client[ENVELOPE_KEYLEN];
	unsigned char	 pin[ENVELOPE_PINLEN];
	unsigned char	 entropy[ENVELOPE_ENTROPYLEN];
	unsigned char	 payload[VECMAX];
	unsigned char	 hash[ENVELOPE_HASHLEN];
	unsigned char	 sig[ENVELOPE_SIGLEN];
	char		 name[NAMELEN];
	size_t		 c, len;
	int		 rv = 0;

	if (hexbytes("the client private key", V_CLIENT_PRIV, client,
	    sizeof(client)) != 0)
		return -1;
	if (hexbytes("the pin secret", V_PIN_SECRET, pin, sizeof(pin)) != 0)
		return -1;
	if (hexbytes("the entropy", V_ENTROPY, entropy,
	    sizeof(entropy)) != 0)
		return -1;

	for (c = 0; c < nitems(requests); c++) {
		if (hexbytes(requests[c].name, requests[c].cke, cke,
		    sizeof(cke)) != 0) {
			rv = -1;
			continue;
		}
		if ((len = hexload(requests[c].name, requests[c].payload,
		    payload)) == 0) {
			rv = -1;
			continue;
		}

		/* The two payload forms hold 129 bytes and 97 bytes. */
		snprintf(name, sizeof(name), "the payload length of %s",
		    requests[c].name);
		if (len != requests[c].ptlen) {
			warnx("%s: the vector holds %zu bytes, and the form "
			    "takes %zu bytes", name, len, requests[c].ptlen);
			rv = -1;
			continue;
		}

		snprintf(name, sizeof(name), "the signed message of %s",
		    requests[c].name);
		if (envelope_hash(cke, requests[c].counter, pin,
		    requests[c].entropy != NULL ? entropy : NULL, hash) != 0) {
			warnx("%s: the call fails", name);
			rv = -1;
			continue;
		}
		if (hexcheck(name, hash, sizeof(hash),
		    requests[c].msghash) != 0)
			rv = -1;

		snprintf(name, sizeof(name), "the signature of %s",
		    requests[c].name);
		if (envelope_sign(client, hash, sig) != 0) {
			warnx("%s: the call fails", name);
			rv = -1;
			continue;
		}
		if (memcmp(sig, payload + len - ENVELOPE_SIGLEN,
		    sizeof(sig)) != 0) {
			warnx("%s: the signature differs from the transcript",
			    name);
			rv = -1;
		}
		snprintf(name, sizeof(name), "the recovered key of %s",
		    requests[c].name);
		if (recovercheck(name, hash, sig, V_CLIENT_PUB) != 0)
			rv = -1;
	}
	return rv;
}

/*
 * test_request():
 *	The request envelope of each form equals the bytes of the
 *	transcript, with the ephemeral key and the IV of the vector
 *	(FuguOracle PROTO-ENVELOPE). The envelope holds cke, the
 *	counter, the IV, the ciphertext and the tag, so this test
 *	covers every step of one request.
 */
static int
test_request(void)
{
	unsigned char	 pub[ENVELOPE_PUBKEYLEN];
	unsigned char	 ckepriv[ENVELOPE_KEYLEN];
	unsigned char	 client[ENVELOPE_KEYLEN];
	unsigned char	 pin[ENVELOPE_PINLEN];
	unsigned char	 entropy[ENVELOPE_ENTROPYLEN];
	unsigned char	 iv[ENVELOPE_IVLEN];
	unsigned char	 out[ENVELOPE_REQUEST_MAX];
	char		 name[NAMELEN];
	size_t		 c, len = 0;
	int		 rv = 0;

	if (hexbytes("the static public key", V_STATIC_PUB, pub,
	    sizeof(pub)) != 0)
		return -1;
	if (hexbytes("the client private key", V_CLIENT_PRIV, client,
	    sizeof(client)) != 0)
		return -1;
	if (hexbytes("the pin secret", V_PIN_SECRET, pin, sizeof(pin)) != 0)
		return -1;
	if (hexbytes("the entropy", V_ENTROPY, entropy,
	    sizeof(entropy)) != 0)
		return -1;

	for (c = 0; c < nitems(requests); c++) {
		snprintf(name, sizeof(name), "the envelope of %s",
		    requests[c].name);
		if (hexbytes(name, requests[c].ckepriv, ckepriv,
		    sizeof(ckepriv)) != 0 ||
		    hexbytes(name, requests[c].iv, iv, sizeof(iv)) != 0) {
			rv = -1;
			continue;
		}
		if (envelope_request(pub, ckepriv, iv, requests[c].counter,
		    client, pin,
		    requests[c].entropy != NULL ? entropy : NULL, out,
		    sizeof(out), &len) != 0) {
			warnx("%s: the call fails", name);
			rv = -1;
			continue;
		}
		if (len != requests[c].envlen) {
			warnx("%s: the envelope holds %zu bytes, and the form "
			    "takes %zu bytes", name, len, requests[c].envlen);
			rv = -1;
			continue;
		}
		if (hexcheck(name, out, len, requests[c].envelope) != 0)
			rv = -1;
	}
	return rv;
}

/*
 * test_response():
 *	The response of the transcript opens to the key of the
 *	vector, and a changed tag byte gives the authentication
 *	failure (ORC-CONFORM-4, FuguOracle PROTO-RESPONSE-1). The
 *	open leaves the plaintext buffer untouched on a wrong tag, so
 *	that buffer is the evidence of the order: the tag answers
 *	before the decrypt starts.
 */
static int
test_response(void)
{
	unsigned char	 pub[ENVELOPE_PUBKEYLEN];
	unsigned char	 ckepriv[ENVELOPE_KEYLEN];
	unsigned char	 qprime[ENVELOPE_PUBKEYLEN];
	unsigned char	 enckey[ENVELOPE_KEYLEN], mackey[ENVELOPE_KEYLEN];
	unsigned char	 body[VECMAX];
	unsigned char	 mask[ENVELOPE_MASKLEN];
	unsigned char	 plain[PLAINMAX];
	unsigned char	 untouched[PLAINMAX];
	size_t		 len, plainlen = 0;
	int		 answer, rv = 0;

	memset(untouched, SENTINEL, sizeof(untouched));

	if (hexbytes("the static public key", V_STATIC_PUB, pub,
	    sizeof(pub)) != 0)
		return -1;
	if (hexbytes("the get_pin cke private key", V_GET_CKE_PRIV, ckepriv,
	    sizeof(ckepriv)) != 0)
		return -1;
	memset(body, 0, sizeof(body));
	if ((len = hexload("the response envelope", V_RESPONSE_ENC,
	    body)) == 0)
		return -1;
	if (len != ENVELOPE_RESPONSE_LEN) {
		warnx("the response envelope: the vector holds %zu bytes, and "
		    "the protocol fixes %d bytes", len,
		    ENVELOPE_RESPONSE_LEN);
		return -1;
	}

	/* The answer of the get_pin request of the transcript. */
	memset(mask, SENTINEL, sizeof(mask));
	if (envelope_response(pub, ckepriv, V_GET_COUNTER, body, len, mask,
	    sizeof(mask)) != 0) {
		warnx("the response: the call fails");
		rv = -1;
	} else if (hexcheck("the response", mask, sizeof(mask),
	    V_RESPONSE_PAYLOAD) != 0)
		rv = -1;

	/* One changed tag byte is an authentication failure. */
	body[len - 1] ^= 0x01;
	memset(mask, SENTINEL, sizeof(mask));
	answer = envelope_response(pub, ckepriv, V_GET_COUNTER, body, len,
	    mask, sizeof(mask));
	if (answer != ENVELOPE_EAUTH) {
		warnx("the changed tag: the answer is %d, and the rule is %d",
		    answer, ENVELOPE_EAUTH);
		rv = -1;
	}
	if (memcmp(mask, untouched, sizeof(mask)) != 0) {
		warnx("the changed tag: the call writes the answer buffer");
		rv = -1;
	}

	/*
	 * The same changed tag against the open, with the room of
	 * the whole ciphertext. A decrypt of the body fills those 48
	 * bytes, so the untouched buffer proves that no decrypt ran.
	 */
	if (qprime_bytes("the tweaked key of the get_pin request",
	    V_GET_QPRIME, V_GET_QPRIME_PARITY, qprime) != 0)
		return -1;
	if (envelope_keys(ckepriv, qprime, ENVELOPE_LABEL_RESPONSE, enckey,
	    mackey) != 0) {
		warnx("the response keys: the call fails");
		return -1;
	}
	memset(plain, SENTINEL, sizeof(plain));
	answer = envelope_open(enckey, mackey, body, len, plain,
	    sizeof(plain), &plainlen);
	if (answer != ENVELOPE_EAUTH) {
		warnx("the open of the changed tag: the answer is %d, and the "
		    "rule is %d", answer, ENVELOPE_EAUTH);
		rv = -1;
	}
	if (plainlen != 0) {
		warnx("the open of the changed tag: the length is %zu, and "
		    "the rule is 0", plainlen);
		rv = -1;
	}
	if (memcmp(plain, untouched, sizeof(plain)) != 0) {
		warnx("the open of the changed tag: the decrypt ran before "
		    "the tag");
		rv = -1;
	}

	/* The open of the whole body answers the key of the vector. */
	body[len - 1] ^= 0x01;
	memset(plain, SENTINEL, sizeof(plain));
	if (envelope_open(enckey, mackey, body, len, plain, sizeof(plain),
	    &plainlen) != 0) {
		warnx("the open: the call fails");
		rv = -1;
	} else if (plainlen != ENVELOPE_MASKLEN) {
		warnx("the open: the plaintext holds %zu bytes, and the rule "
		    "is %d", plainlen, ENVELOPE_MASKLEN);
		rv = -1;
	} else if (hexcheck("the open", plain, plainlen,
	    V_RESPONSE_PAYLOAD) != 0)
		rv = -1;

	/*
	 * A body of another length authenticates nothing. The long
	 * body holds one block more than the protocol allows, and
	 * its answer must be the authentication failure too. Without
	 * the length gate of the response, the open would answer the
	 * usage failure of a small buffer.
	 */
	answer = envelope_response(pub, ckepriv, V_GET_COUNTER, body, len - 1,
	    mask, sizeof(mask));
	if (answer != ENVELOPE_EAUTH) {
		warnx("the short body: the answer is %d, and the rule is %d",
		    answer, ENVELOPE_EAUTH);
		rv = -1;
	}
	answer = envelope_response(pub, ckepriv, V_GET_COUNTER, body,
	    len + ENVELOPE_BLOCKLEN, mask, sizeof(mask));
	if (answer != ENVELOPE_EAUTH) {
		warnx("the long body: the answer is %d, and the rule is %d",
		    answer, ENVELOPE_EAUTH);
		rv = -1;
	}

	/*
	 * Another static public key authenticates nothing. The MAC
	 * of the envelope comes from the provisioned key of that
	 * oracle, and TLS is not the authenticator (ORC-CONFORM-4).
	 * The client key of the vectors stands here for the key of
	 * another oracle: it is a point of the curve, so the tweak
	 * and the ECDH give an answer, and the tag of it is wrong.
	 */
	if (hexbytes("the other public key", V_CLIENT_PUB, pub,
	    sizeof(pub)) != 0)
		return -1;
	answer = envelope_response(pub, ckepriv, V_GET_COUNTER, body, len,
	    mask, sizeof(mask));
	if (answer != ENVELOPE_EAUTH) {
		warnx("the other oracle key: the answer is %d, and the rule "
		    "is %d", answer, ENVELOPE_EAUTH);
		rv = -1;
	}
	return rv;
}

int
main(void)
{
	int	 rv = 0;

	rv |= test_draw();
	rv |= test_tweak();
	rv |= test_keys();
	rv |= test_payload();
	rv |= test_request();
	rv |= test_response();
	return rv != 0;
}
