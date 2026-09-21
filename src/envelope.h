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
 * The request envelope of the oracle protocol. FuguPass speaks
 * version 2 of the blind_pin_server protocol to any conforming
 * oracle (ORC-CONFORM-1). This file holds the client side of one
 * request: the tweak of the oracle key, the two envelope keys, the
 * signature of the payload, the seal of the request, and the open of
 * the response. envelope.c states the steps, and the vectors of
 * FuguOracle pin every one of them.
 *
 * This file mirrors the cipher shim of FuguOracle, and the protocol
 * fixes the length of each buffer below. A pointer of a fixed length
 * therefore carries no length argument, and the contract of each
 * function names the length that the pointer must hold. The other
 * headers of this tree pass a length with each buffer, because the
 * caller of them chooses the length.
 *
 * Every primitive comes from libsecp256k1 and from libcrypto, and no
 * other library enters this file (D-15). Every function but
 * envelope_draw() is bytes in, bytes out: it reads its arguments
 * only, and it touches no file, no socket, and no clock.
 * envelope_draw() draws the keypair and the IV of a request, and the
 * randomized library context draws a blinding seed that changes no
 * answer. Every vector of a transcript therefore applies to every
 * other function.
 *
 * envelope_draw() gives nothing, and every other function gives 0,
 * or -1 on a failure. envelope_open() and envelope_response() give
 * ENVELOPE_EAUTH in place of -1 for a body that fails the
 * authentication of the oracle (ORC-CONFORM-4). Each function clears
 * every secret of the call on each exit path (SEC-MEMORY-1).
 */

#ifndef ENVELOPE_H
#define ENVELOPE_H

#include <stddef.h>
#include <stdint.h>

/*
 * The lengths of the protocol, in bytes (FuguOracle PROTO-ENVELOPE,
 * FuguOracle PROTO-PAYLOAD). They are the lengths of the wire, and
 * not the lengths of the derivation in derive.h.
 */
#define ENVELOPE_KEYLEN		32	/* a private key or a derived key */
#define ENVELOPE_PUBKEYLEN	33	/* a public key, SEC1 compressed */
#define ENVELOPE_XONLYLEN	32	/* a public key, x-only */
#define ENVELOPE_HASHLEN	32	/* a SHA-256 or HMAC-SHA256 value */
#define ENVELOPE_SIGLEN		65	/* a recoverable signature */
#define ENVELOPE_BLOCKLEN	16	/* the AES block */
#define ENVELOPE_IVLEN		16	/* the CBC initialization vector */
#define ENVELOPE_TAGLEN		32	/* the HMAC-SHA256 tag */
#define ENVELOPE_COUNTERLEN	4	/* the replay counter, uint32 LE */
#define ENVELOPE_PINLEN		32	/* the pin secret of a payload */
#define ENVELOPE_ENTROPYLEN	32	/* the entropy of a set_pin payload */
#define ENVELOPE_MASKLEN	32	/* the key that a response carries */

/* The bytes that an envelope adds to its ciphertext. */
#define ENVELOPE_OVERHEAD	(ENVELOPE_IVLEN + ENVELOPE_TAGLEN)

/* The head of a request: cke and the replay counter. */
#define ENVELOPE_HEADERLEN	(ENVELOPE_PUBKEYLEN + ENVELOPE_COUNTERLEN)

/* The two payload forms: the get_pin form, and the set_pin form. */
#define ENVELOPE_GET_PTLEN	(ENVELOPE_PINLEN + ENVELOPE_SIGLEN)
#define ENVELOPE_SET_PTLEN	(ENVELOPE_PINLEN + ENVELOPE_ENTROPYLEN + \
				    ENVELOPE_SIGLEN)

/*
 * The two request envelopes, and the one response envelope. The
 * padding of the 97-byte form and of the 129-byte form each add 15
 * bytes, and the padding of the 32-byte response adds a full block.
 */
#define ENVELOPE_GET_LEN	197
#define ENVELOPE_SET_LEN	229
#define ENVELOPE_REQUEST_MAX	ENVELOPE_SET_LEN
#define ENVELOPE_RESPONSE_LEN	96

/*
 * The answer of a body that fails the authentication of the oracle:
 * a wrong length, a wrong tag, or a failed decrypt (ORC-CONFORM-4).
 * The state is neither an HTTP error nor a transport failure, and
 * the caller must hold the three apart.
 */
#define ENVELOPE_EAUTH		(-2)

/*
 * The two direction labels of the key split. The NUL byte of the
 * string is not part of the label.
 */
#define ENVELOPE_LABEL_REQUEST	"blind_oracle_request"
#define ENVELOPE_LABEL_RESPONSE	"blind_oracle_response"

/*
 * envelope_draw(ckepriv, iv):
 *	The ephemeral private key of ENVELOPE_KEYLEN bytes at
 *	ckepriv, and the IV of ENVELOPE_IVLEN bytes at iv, from
 *	arc4random(3) (ORC-CONFORM-5, SEC-ENTROPY-4). Every request
 *	draws both again.
 *
 *	This function draws the keypair and the IV, and no other
 *	value. ORC-CONFORM-5 asks for 32 fresh bytes of arc4random(3)
 *	in each set_pin request as well. The caller draws those
 *	bytes, and it gives them to envelope_request() as the entropy
 *	argument. The service mixes them into the key share that it
 *	stores (FuguOracle OPS-SET-3).
 *
 *	Every other function takes the bytes of a draw as an
 *	argument, so the known-answer vectors of FuguOracle apply to
 *	them. The draw repeats until the curve takes the key, and the
 *	curve rejects one scalar in about 2^128.
 */
void	envelope_draw(unsigned char *, unsigned char *);

/*
 * envelope_tweak(pub, cke, counter, out):
 *	The request public key Q' of one request, to the
 *	ENVELOPE_PUBKEYLEN bytes at out (FuguOracle PROTO-TWEAK-4).
 *	pub is the provisioned static public key of the oracle, of
 *	ENVELOPE_PUBKEYLEN bytes, and cke is the ephemeral public key
 *	of ENVELOPE_PUBKEYLEN bytes.
 *
 *	The client holds no private key of the oracle, so it adds the
 *	tagged scalar to the x-only key of pub with
 *	secp256k1_xonly_pubkey_tweak_add(). out holds the compressed
 *	form, so it carries the Y parity of Q'. The ECDH step hashes
 *	the compressed point, and a client that drops the parity
 *	computes another secret.
 */
int	envelope_tweak(const unsigned char *, const unsigned char *, uint32_t,
	    unsigned char *);

/*
 * envelope_shared(priv, pub, out):
 *	The ECDH secret of the private key of ENVELOPE_KEYLEN bytes
 *	at priv and the public key of ENVELOPE_PUBKEYLEN bytes at
 *	pub, to the ENVELOPE_HASHLEN bytes at out (FuguOracle
 *	PROTO-ENCRYPT-1). The hash function is the default one of the
 *	library: the SHA-256 of the compressed shared point.
 *
 *	envelope_keys() splits this secret, and a caller of the
 *	protocol needs the split only. The known-answer test of the
 *	step reads this entry point.
 */
int	envelope_shared(const unsigned char *, const unsigned char *,
	    unsigned char *);

/*
 * envelope_keys(priv, pub, label, enckey, mackey):
 *	The two envelope keys of one direction, each of
 *	ENVELOPE_KEYLEN bytes (FuguOracle PROTO-ENCRYPT-2). label is
 *	ENVELOPE_LABEL_REQUEST or ENVELOPE_LABEL_RESPONSE, and the
 *	HMAC-SHA512 of the label under the ECDH secret splits into
 *	the two keys. Both directions share the secret, and the label
 *	is the one difference.
 */
int	envelope_keys(const unsigned char *, const unsigned char *,
	    const char *, unsigned char *, unsigned char *);

/*
 * envelope_hash(cke, counter, pin, entropy, out):
 *	The signed message hash of one payload, to the
 *	ENVELOPE_HASHLEN bytes at out (FuguOracle PROTO-PAYLOAD-3).
 *	The message is cke, the counter as uint32 LE, the pin secret
 *	of ENVELOPE_PINLEN bytes at pin, and the entropy of
 *	ENVELOPE_ENTROPYLEN bytes at entropy. A NULL entropy makes
 *	the message of the 97-byte payload form.
 */
int	envelope_hash(const unsigned char *, uint32_t, const unsigned char *,
	    const unsigned char *, unsigned char *);

/*
 * envelope_sign(priv, hash, out):
 *	The recoverable signature of the ENVELOPE_HASHLEN bytes at
 *	hash, under the client private key of ENVELOPE_KEYLEN bytes
 *	at priv, to the ENVELOPE_SIGLEN bytes at out (FuguOracle
 *	PROTO-PAYLOAD-2). The header byte holds 27 + 4 + recid, and
 *	the 64 bytes after it hold the compact form. The nonce comes
 *	from the default function of the library, so the answer of
 *	one hash and one key never changes.
 */
int	envelope_sign(const unsigned char *, const unsigned char *,
	    unsigned char *);

/*
 * envelope_open(enckey, mackey, env, envlen, out, outsize, outlen):
 *	The plaintext of the envlen bytes of the envelope at env, to
 *	out. The envelope holds the IV, the ciphertext, and the tag.
 *	enckey and mackey each hold ENVELOPE_KEYLEN bytes, outsize
 *	counts at least envlen minus ENVELOPE_OVERHEAD bytes, and
 *	outlen takes the length of the plaintext.
 *
 *	The tag check runs before the decrypt (FuguOracle
 *	PROTO-ENCRYPT-3). A wrong length and a wrong tag each leave
 *	out untouched, and that answer is the evidence of the order.
 *	A failed decrypt clears outsize bytes, because the buffer can
 *	then hold a part of a plaintext. Each of the three gives
 *	ENVELOPE_EAUTH. A small outsize and a library failure give
 *	-1.
 */
int	envelope_open(const unsigned char *, const unsigned char *,
	    const unsigned char *, size_t, unsigned char *, size_t, size_t *);

/*
 * envelope_request(pub, ckepriv, iv, counter, client, pin, entropy,
 *     out, outsize, outlen):
 *	One request envelope, to out (FuguOracle PROTO-ENVELOPE). The
 *	arguments are the provisioned static public key of the oracle
 *	of ENVELOPE_PUBKEYLEN bytes at pub, the ephemeral private key
 *	of ENVELOPE_KEYLEN bytes at ckepriv, the IV of ENVELOPE_IVLEN
 *	bytes at iv, the replay counter, the client private key of
 *	ENVELOPE_KEYLEN bytes at client, the pin secret of
 *	ENVELOPE_PINLEN bytes at pin, and the entropy of
 *	ENVELOPE_ENTROPYLEN bytes at entropy.
 *
 *	A NULL entropy makes the 97-byte payload form, and an
 *	entropy makes the 129-byte form. A set_pin request needs the
 *	129-byte form (FuguOracle OPS-SET-1), and a get_pin request
 *	takes either form. The oracle ignores the entropy of a
 *	get_pin payload (FuguOracle PROTO-PAYLOAD, FuguOracle
 *	OPS-GET-1). outsize therefore counts at least ENVELOPE_GET_LEN
 *	bytes, or ENVELOPE_SET_LEN bytes for the longer form.
 *	ENVELOPE_REQUEST_MAX counts for both, and outlen takes the
 *	length of the envelope.
 *
 *	envelope_draw() gives ckepriv and iv of a live request, and
 *	each request draws them again (ORC-CONFORM-5). A failure
 *	clears outsize bytes.
 */
int	envelope_request(const unsigned char *, const unsigned char *,
	    const unsigned char *, uint32_t, const unsigned char *,
	    const unsigned char *, const unsigned char *, unsigned char *,
	    size_t, size_t *);

/*
 * envelope_response(pub, ckepriv, counter, body, bodylen, out,
 *     outlen):
 *	The key of one response body, to the ENVELOPE_MASKLEN bytes
 *	at out (FuguOracle PROTO-RESPONSE-1). pub, ckepriv and
 *	counter are the three values of the request that the body
 *	answers, and body holds the bodylen decoded bytes of the
 *	data member.
 *
 *	The response keys derive from the same ECDH secret as the
 *	request, under the response label. The envelope MAC therefore
 *	authenticates the oracle, and TLS is not the authenticator
 *	(ORC-CONFORM-4). A bodylen other than ENVELOPE_RESPONSE_LEN,
 *	a wrong tag, and a failed decrypt each give ENVELOPE_EAUTH. A
 *	failure of any kind leaves out untouched, and the caller
 *	clears the buffer that it owns.
 */
int	envelope_response(const unsigned char *, const unsigned char *,
	    uint32_t, const unsigned char *, size_t, unsigned char *, size_t);

#endif /* ENVELOPE_H */
