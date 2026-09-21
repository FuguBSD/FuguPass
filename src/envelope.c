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
 * The request envelope: the tweak of the oracle key, the ECDH split,
 * the signature of the payload, the seal of the request, and the
 * open of the response. envelope.h states the interface.
 *
 * The steps mirror the cipher shim of FuguOracle, and the two sides
 * of the transcript in tests/vectors/oracle.h pin each one. A change
 * of a step that the vectors cover fails src/regress/envelope.
 *
 * Each secret lives in a stack buffer, and each exit path clears it
 * under one goto out (SEC-MEMORY-1). The tag comparison of the open
 * runs in constant time (SEC-MEMORY-2).
 */

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_recovery.h>

#include "envelope.h"

/*
 * The tag of the BIP341 tweak, without its NUL byte (FuguOracle
 * PROTO-TWEAK-2).
 */
#define TAPTWEAK	"TapTweak"

/* The header byte of a signature marks a compressed key: 27 + 4. */
#define SIG_HEADER	31

static secp256k1_context	*context(void);
static size_t			 padded(size_t);
static void			 counter_bytes(uint32_t, unsigned char *);
static int			 hmac_evp(const EVP_MD *,
				    const unsigned char *, size_t,
				    const unsigned char *, size_t,
				    unsigned char *, size_t);
static int			 aes_cbc(const unsigned char *,
				    const unsigned char *, int,
				    const unsigned char *, size_t,
				    unsigned char *, size_t, size_t *);
static int			 tweak_input(const unsigned char *, uint32_t,
				    unsigned char *);
static int			 seal(const unsigned char *,
				    const unsigned char *,
				    const unsigned char *,
				    const unsigned char *, size_t,
				    unsigned char *, size_t, size_t *);

/*
 * The library context. Every call that takes a private key needs a
 * context that the caller randomized, and the static context of the
 * library takes no randomization. The 32 blinding bytes come from
 * arc4random_buf(3), and the blinding changes no answer. The core
 * process sends many requests, so this context lives from the first
 * request to the exit of the program.
 */
static secp256k1_context *
context(void)
{
	static secp256k1_context	*ctx;
	unsigned char			 seed[32];

	if (ctx != NULL)
		return ctx;
	if ((ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE)) == NULL)
		return NULL;
	arc4random_buf(seed, sizeof(seed));
	if (secp256k1_context_randomize(ctx, seed) != 1) {
		secp256k1_context_destroy(ctx);
		ctx = NULL;
	}
	explicit_bzero(seed, sizeof(seed));
	return ctx;
}

/*
 * The length of the PKCS#7 padded form of a plaintext. A block
 * aligned plaintext takes a full pad block.
 */
static size_t
padded(size_t len)
{
	return len - len % ENVELOPE_BLOCKLEN + ENVELOPE_BLOCKLEN;
}

/*
 * The replay counter, to the ENVELOPE_COUNTERLEN bytes at out. The
 * counter travels in little-endian byte order (FuguOracle
 * PROTO-ENVELOPE).
 */
static void
counter_bytes(uint32_t counter, unsigned char *out)
{
	out[0] = (unsigned char)counter;
	out[1] = (unsigned char)(counter >> 8);
	out[2] = (unsigned char)(counter >> 16);
	out[3] = (unsigned char)(counter >> 24);
}

/*
 * One HMAC of the message under the key, with the digest that the
 * caller names. outlen states the digest length that the caller
 * expects, and another length gives -1.
 */
static int
hmac_evp(const EVP_MD *md, const unsigned char *key, size_t keylen,
    const unsigned char *msg, size_t msglen, unsigned char *out,
    size_t outlen)
{
	unsigned int	 len = 0;

	if (keylen > INT_MAX)
		return -1;
	if (HMAC(md, key, (int)keylen, msg, msglen, out, &len) == NULL)
		return -1;
	if (len != outlen) {
		explicit_bzero(out, outlen);
		return -1;
	}
	return 0;
}

/*
 * One AES-256-CBC operation with PKCS#7 padding. The EVP layer
 * writes the padded length on an encryption, and at most the input
 * length on a decryption, so outsize covers both in one test. A
 * failure clears the whole output buffer, because it can hold a part
 * of a plaintext.
 */
static int
aes_cbc(const unsigned char *key, const unsigned char *iv, int encrypt,
    const unsigned char *in, size_t inlen, unsigned char *out, size_t outsize,
    size_t *outlen)
{
	EVP_CIPHER_CTX	*ctx = NULL;
	int		 len, total;
	int		 rv = -1;

	*outlen = 0;
	if (inlen > INT_MAX || outsize > INT_MAX)
		goto out;
	if (outsize < (encrypt ? padded(inlen) : inlen))
		goto out;
	if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
		goto out;
	if (EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv,
	    encrypt) != 1)
		goto out;
	if (EVP_CipherUpdate(ctx, out, &len, in, (int)inlen) != 1)
		goto out;
	total = len;
	if (EVP_CipherFinal_ex(ctx, out + total, &len) != 1)
		goto out;
	total += len;
	*outlen = (size_t)total;
	rv = 0;
out:
	EVP_CIPHER_CTX_free(ctx);
	if (rv != 0)
		explicit_bzero(out, outsize);
	return rv;
}

/*
 * The tweak input m = H(HMAC(key = cke, msg = replay_counter)) of one
 * request (FuguOracle PROTO-TWEAK-1). cke holds ENVELOPE_PUBKEYLEN
 * bytes, and out takes ENVELOPE_HASHLEN bytes.
 */
static int
tweak_input(const unsigned char *cke, uint32_t counter, unsigned char *out)
{
	unsigned char	 le[ENVELOPE_COUNTERLEN];
	unsigned char	 mac[ENVELOPE_HASHLEN];
	int		 rv = -1;

	counter_bytes(counter, le);
	if (hmac_evp(EVP_sha256(), cke, ENVELOPE_PUBKEYLEN, le, sizeof(le),
	    mac, sizeof(mac)) != 0)
		goto out;
	if (SHA256(mac, sizeof(mac), out) == NULL)
		goto out;
	rv = 0;
out:
	explicit_bzero(mac, sizeof(mac));
	if (rv != 0)
		explicit_bzero(out, ENVELOPE_HASHLEN);
	return rv;
}

int
envelope_pubkey(const unsigned char *priv, unsigned char *out)
{
	secp256k1_context	*ctx;
	secp256k1_pubkey	 pubkey;
	size_t			 len = ENVELOPE_PUBKEYLEN;
	int			 rv = -1;

	memset(&pubkey, 0, sizeof(pubkey));
	if ((ctx = context()) == NULL)
		goto out;
	if (secp256k1_ec_pubkey_create(ctx, &pubkey, priv) != 1)
		goto out;
	if (secp256k1_ec_pubkey_serialize(ctx, out, &len, &pubkey,
	    SECP256K1_EC_COMPRESSED) != 1)
		goto out;
	if (len != ENVELOPE_PUBKEYLEN)
		goto out;
	rv = 0;
out:
	explicit_bzero(&pubkey, sizeof(pubkey));
	if (rv != 0)
		explicit_bzero(out, ENVELOPE_PUBKEYLEN);
	return rv;
}

/*
 * The envelope of the ptlen bytes at pt, with the IV of
 * ENVELOPE_IVLEN bytes at iv (FuguOracle PROTO-ENCRYPT-4). The
 * caller draws the IV, so the vectors of a transcript apply. outsize
 * counts at least ENVELOPE_IVLEN plus the padded length plus
 * ENVELOPE_TAGLEN bytes, and outlen takes the length of the
 * envelope. A failure clears outsize bytes.
 */
static int
seal(const unsigned char *enckey, const unsigned char *mackey,
    const unsigned char *iv, const unsigned char *pt, size_t ptlen,
    unsigned char *out, size_t outsize, size_t *outlen)
{
	size_t	 ctlen = 0;
	int	 rv = -1;

	*outlen = 0;
	if (ptlen > INT_MAX)
		return -1;
	if (outsize < ENVELOPE_IVLEN + padded(ptlen) + ENVELOPE_TAGLEN)
		return -1;
	memcpy(out, iv, ENVELOPE_IVLEN);
	if (aes_cbc(enckey, iv, 1, pt, ptlen, out + ENVELOPE_IVLEN,
	    outsize - ENVELOPE_IVLEN - ENVELOPE_TAGLEN, &ctlen) != 0)
		goto out;

	/* The tag covers the IV and the ciphertext. */
	if (hmac_evp(EVP_sha256(), mackey, ENVELOPE_KEYLEN, out,
	    ENVELOPE_IVLEN + ctlen, out + ENVELOPE_IVLEN + ctlen,
	    ENVELOPE_TAGLEN) != 0)
		goto out;
	*outlen = ENVELOPE_IVLEN + ctlen + ENVELOPE_TAGLEN;
	rv = 0;
out:
	if (rv != 0) {
		explicit_bzero(out, outsize);
		*outlen = 0;
	}
	return rv;
}

void
envelope_draw(unsigned char *ckepriv, unsigned char *iv)
{
	/*
	 * The curve rejects 0, and it rejects the group order or
	 * more. The verify step needs no randomized context, because
	 * it holds no multiplication.
	 */
	do {
		arc4random_buf(ckepriv, ENVELOPE_KEYLEN);
	} while (secp256k1_ec_seckey_verify(secp256k1_context_static,
	    ckepriv) != 1);
	arc4random_buf(iv, ENVELOPE_IVLEN);
}

int
envelope_tweak(const unsigned char *pub, const unsigned char *cke,
    uint32_t counter, unsigned char *out)
{
	secp256k1_context	*ctx;
	secp256k1_pubkey	 pubkey, tweaked;
	secp256k1_xonly_pubkey	 xonly;
	unsigned char		 tagged[ENVELOPE_XONLYLEN + ENVELOPE_HASHLEN];
	unsigned char		 tweak[ENVELOPE_HASHLEN];
	size_t			 len = ENVELOPE_PUBKEYLEN;
	int			 rv = -1;

	memset(&pubkey, 0, sizeof(pubkey));
	memset(&tweaked, 0, sizeof(tweaked));
	memset(&xonly, 0, sizeof(xonly));
	if ((ctx = context()) == NULL)
		goto out;

	/*
	 * The tagged hash covers the x-only key of the oracle and m,
	 * and the sum is Q' = Q + t * G (FuguOracle PROTO-TWEAK-2,
	 * FuguOracle PROTO-TWEAK-4).
	 */
	if (secp256k1_ec_pubkey_parse(ctx, &pubkey, pub,
	    ENVELOPE_PUBKEYLEN) != 1)
		goto out;
	if (secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly, NULL,
	    &pubkey) != 1)
		goto out;
	if (secp256k1_xonly_pubkey_serialize(ctx, tagged, &xonly) != 1)
		goto out;
	if (tweak_input(cke, counter, tagged + ENVELOPE_XONLYLEN) != 0)
		goto out;
	if (secp256k1_tagged_sha256(ctx, tweak,
	    (const unsigned char *)TAPTWEAK, sizeof(TAPTWEAK) - 1, tagged,
	    sizeof(tagged)) != 1)
		goto out;
	if (secp256k1_xonly_pubkey_tweak_add(ctx, &tweaked, &xonly,
	    tweak) != 1)
		goto out;

	/* The compressed form carries the Y parity of Q'. */
	if (secp256k1_ec_pubkey_serialize(ctx, out, &len, &tweaked,
	    SECP256K1_EC_COMPRESSED) != 1)
		goto out;
	if (len != ENVELOPE_PUBKEYLEN)
		goto out;
	rv = 0;
out:
	explicit_bzero(tagged, sizeof(tagged));
	explicit_bzero(tweak, sizeof(tweak));
	if (rv != 0)
		explicit_bzero(out, ENVELOPE_PUBKEYLEN);
	return rv;
}

int
envelope_shared(const unsigned char *priv, const unsigned char *pub,
    unsigned char *out)
{
	secp256k1_context	*ctx;
	secp256k1_pubkey	 pubkey;
	int			 rv = -1;

	memset(&pubkey, 0, sizeof(pubkey));
	if ((ctx = context()) == NULL)
		goto out;
	if (secp256k1_ec_pubkey_parse(ctx, &pubkey, pub,
	    ENVELOPE_PUBKEYLEN) != 1)
		goto out;
	if (secp256k1_ecdh(ctx, out, &pubkey, priv, NULL, NULL) != 1)
		goto out;
	rv = 0;
out:
	explicit_bzero(&pubkey, sizeof(pubkey));
	if (rv != 0)
		explicit_bzero(out, ENVELOPE_HASHLEN);
	return rv;
}

int
envelope_keys(const unsigned char *priv, const unsigned char *pub,
    const char *label, unsigned char *enckey, unsigned char *mackey)
{
	unsigned char	 shared[ENVELOPE_HASHLEN];
	unsigned char	 keys[2 * ENVELOPE_KEYLEN];
	int		 rv = -1;

	/* The HMAC-SHA512 of the label splits the secret. */
	if (envelope_shared(priv, pub, shared) != 0)
		goto out;
	if (hmac_evp(EVP_sha512(), shared, sizeof(shared),
	    (const unsigned char *)label, strlen(label), keys,
	    sizeof(keys)) != 0)
		goto out;
	memcpy(enckey, keys, ENVELOPE_KEYLEN);
	memcpy(mackey, keys + ENVELOPE_KEYLEN, ENVELOPE_KEYLEN);
	rv = 0;
out:
	explicit_bzero(shared, sizeof(shared));
	explicit_bzero(keys, sizeof(keys));
	if (rv != 0) {
		explicit_bzero(enckey, ENVELOPE_KEYLEN);
		explicit_bzero(mackey, ENVELOPE_KEYLEN);
	}
	return rv;
}

int
envelope_hash(const unsigned char *cke, uint32_t counter,
    const unsigned char *pin, const unsigned char *entropy,
    unsigned char *out)
{
	unsigned char	 msg[ENVELOPE_HEADERLEN + ENVELOPE_PINLEN +
			     ENVELOPE_ENTROPYLEN];
	size_t		 len;
	int		 rv = -1;

	/*
	 * The message holds the head of the envelope and the payload
	 * before the signature. The 97-byte form carries no entropy,
	 * so its message holds 69 bytes.
	 */
	memcpy(msg, cke, ENVELOPE_PUBKEYLEN);
	counter_bytes(counter, msg + ENVELOPE_PUBKEYLEN);
	memcpy(msg + ENVELOPE_HEADERLEN, pin, ENVELOPE_PINLEN);
	len = ENVELOPE_HEADERLEN + ENVELOPE_PINLEN;
	if (entropy != NULL) {
		memcpy(msg + len, entropy, ENVELOPE_ENTROPYLEN);
		len += ENVELOPE_ENTROPYLEN;
	}
	if (SHA256(msg, len, out) != NULL)
		rv = 0;
	explicit_bzero(msg, sizeof(msg));
	if (rv != 0)
		explicit_bzero(out, ENVELOPE_HASHLEN);
	return rv;
}

int
envelope_sign(const unsigned char *priv, const unsigned char *hash,
    unsigned char *out)
{
	secp256k1_context			*ctx;
	secp256k1_ecdsa_recoverable_signature	 rsig;
	int					 recid = -1;
	int					 rv = -1;

	memset(&rsig, 0, sizeof(rsig));
	if ((ctx = context()) == NULL)
		goto out;
	if (secp256k1_ecdsa_sign_recoverable(ctx, &rsig, hash, priv, NULL,
	    NULL) != 1)
		goto out;
	if (secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx,
	    out + 1, &recid, &rsig) != 1)
		goto out;
	if (recid < 0 || recid > 3)
		goto out;
	out[0] = (unsigned char)(SIG_HEADER + recid);
	rv = 0;
out:
	explicit_bzero(&rsig, sizeof(rsig));
	if (rv != 0)
		explicit_bzero(out, ENVELOPE_SIGLEN);
	return rv;
}

int
envelope_open(const unsigned char *enckey, const unsigned char *mackey,
    const unsigned char *env, size_t envlen, unsigned char *out,
    size_t outsize, size_t *outlen)
{
	unsigned char	 tag[ENVELOPE_TAGLEN];
	size_t		 ctlen;
	int		 rv = ENVELOPE_EAUTH;

	*outlen = 0;
	if (envlen < ENVELOPE_OVERHEAD + ENVELOPE_BLOCKLEN)
		goto out;
	ctlen = envlen - ENVELOPE_OVERHEAD;
	if (ctlen % ENVELOPE_BLOCKLEN != 0)
		goto out;
	if (outsize < ctlen) {
		rv = -1;
		goto out;
	}

	/*
	 * The tag covers the IV and the ciphertext, and it answers
	 * before the decrypt starts (FuguOracle PROTO-ENCRYPT-3).
	 */
	if (hmac_evp(EVP_sha256(), mackey, ENVELOPE_KEYLEN, env,
	    ENVELOPE_IVLEN + ctlen, tag, sizeof(tag)) != 0) {
		rv = -1;
		goto out;
	}
	if (timingsafe_bcmp(tag, env + ENVELOPE_IVLEN + ctlen,
	    ENVELOPE_TAGLEN) != 0)
		goto out;
	if (aes_cbc(enckey, env, 0, env + ENVELOPE_IVLEN, ctlen, out, outsize,
	    outlen) != 0)
		goto out;
	rv = 0;
out:
	explicit_bzero(tag, sizeof(tag));
	return rv;
}

int
envelope_request(const unsigned char *pub, const unsigned char *ckepriv,
    const unsigned char *iv, uint32_t counter, const unsigned char *client,
    const unsigned char *pin, const unsigned char *entropy,
    unsigned char *out, size_t outsize, size_t *outlen)
{
	unsigned char	 qprime[ENVELOPE_PUBKEYLEN];
	unsigned char	 enckey[ENVELOPE_KEYLEN];
	unsigned char	 mackey[ENVELOPE_KEYLEN];
	unsigned char	 hash[ENVELOPE_HASHLEN];
	unsigned char	 pt[ENVELOPE_SET_PTLEN];
	size_t		 ptlen, envlen = 0;
	int		 rv = -1;

	*outlen = 0;
	ptlen = entropy != NULL ? ENVELOPE_SET_PTLEN : ENVELOPE_GET_PTLEN;
	if (outsize < ENVELOPE_HEADERLEN + ENVELOPE_IVLEN + padded(ptlen) +
	    ENVELOPE_TAGLEN)
		return -1;

	/*
	 * cke and the counter lead the envelope, and the steps after
	 * them read cke from out (FuguOracle PROTO-ENVELOPE).
	 */
	if (envelope_pubkey(ckepriv, out) != 0)
		goto out;
	counter_bytes(counter, out + ENVELOPE_PUBKEYLEN);
	if (envelope_tweak(pub, out, counter, qprime) != 0)
		goto out;
	if (envelope_keys(ckepriv, qprime, ENVELOPE_LABEL_REQUEST, enckey,
	    mackey) != 0)
		goto out;

	/*
	 * The payload is the pin secret, the entropy of the 129-byte
	 * form, and the signature of the message hash (FuguOracle
	 * PROTO-PAYLOAD-1).
	 */
	if (envelope_hash(out, counter, pin, entropy, hash) != 0)
		goto out;
	memcpy(pt, pin, ENVELOPE_PINLEN);
	if (entropy != NULL)
		memcpy(pt + ENVELOPE_PINLEN, entropy, ENVELOPE_ENTROPYLEN);
	if (envelope_sign(client, hash, pt + ptlen - ENVELOPE_SIGLEN) != 0)
		goto out;
	if (seal(enckey, mackey, iv, pt, ptlen, out + ENVELOPE_HEADERLEN,
	    outsize - ENVELOPE_HEADERLEN, &envlen) != 0)
		goto out;
	*outlen = ENVELOPE_HEADERLEN + envlen;
	rv = 0;
out:
	explicit_bzero(enckey, sizeof(enckey));
	explicit_bzero(mackey, sizeof(mackey));
	explicit_bzero(hash, sizeof(hash));
	explicit_bzero(pt, sizeof(pt));
	if (rv != 0) {
		explicit_bzero(out, outsize);
		*outlen = 0;
	}
	return rv;
}

int
envelope_response(const unsigned char *pub, const unsigned char *ckepriv,
    uint32_t counter, const unsigned char *body, size_t bodylen,
    unsigned char *out, size_t outlen)
{
	unsigned char	 cke[ENVELOPE_PUBKEYLEN];
	unsigned char	 qprime[ENVELOPE_PUBKEYLEN];
	unsigned char	 enckey[ENVELOPE_KEYLEN];
	unsigned char	 mackey[ENVELOPE_KEYLEN];
	unsigned char	 plain[ENVELOPE_RESPONSE_LEN - ENVELOPE_OVERHEAD];
	size_t		 plainlen = 0;
	int		 rv = -1;

	if (outlen != ENVELOPE_MASKLEN)
		return -1;

	/*
	 * The response keys come from the ECDH secret of the request,
	 * under the response label (FuguOracle PROTO-ENCRYPT-5).
	 */
	if (envelope_pubkey(ckepriv, cke) != 0)
		goto out;
	if (envelope_tweak(pub, cke, counter, qprime) != 0)
		goto out;
	if (envelope_keys(ckepriv, qprime, ENVELOPE_LABEL_RESPONSE, enckey,
	    mackey) != 0)
		goto out;

	/*
	 * The oracle answers one key of ENVELOPE_MASKLEN bytes in an
	 * envelope of ENVELOPE_RESPONSE_LEN bytes (FuguOracle
	 * PROTO-RESPONSE-1, FuguOracle PROTO-RESPONSE-2). Another
	 * length is an authentication failure, and the open answers
	 * the tag and the decrypt (ORC-CONFORM-4).
	 */
	if (bodylen != ENVELOPE_RESPONSE_LEN) {
		rv = ENVELOPE_EAUTH;
		goto out;
	}
	if ((rv = envelope_open(enckey, mackey, body, bodylen, plain,
	    sizeof(plain), &plainlen)) != 0)
		goto out;
	if (plainlen != ENVELOPE_MASKLEN) {
		rv = ENVELOPE_EAUTH;
		goto out;
	}
	memcpy(out, plain, ENVELOPE_MASKLEN);
out:
	explicit_bzero(enckey, sizeof(enckey));
	explicit_bzero(mackey, sizeof(mackey));
	explicit_bzero(plain, sizeof(plain));
	return rv;
}
