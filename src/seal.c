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
 * The seal: one AEAD call for a write, and one for a read, over the
 * layout of VAULT-SEAL. seal.h states the interface.
 *
 * The AEAD comes from libcrypto, through the EVP_AEAD interface of
 * LibreSSL (VAULT-SEAL-2, D-15). EVP_aead_chacha20_poly1305() is
 * the construction of RFC 8439: a 32-byte key, a 12-byte nonce, and
 * a 16-byte tag. No other library enters this file.
 *
 * The nonce comes from arc4random_buf(3) (VAULT-SEAL-3,
 * SEC-ENTROPY-4). A nonce is public and ephemeral, and it is not a
 * stored secret, so the draw holds to SEC-ENTROPY-1.
 *
 * The key of the AEAD lives in the context alone, and
 * EVP_AEAD_CTX_free() clears that copy of it.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "seal.h"

/*
 * The bytes of the additional authenticated data: the version
 * field of the layout (VAULT-SEAL-5). Each call below takes that
 * field of its own buffer, so the tag covers the byte that the
 * file holds.
 */
#define AADLEN	(SEAL_OFF_NONCE - SEAL_OFF_VERSION)

/*
 * aead_ctx(key, keylen):
 *	A ChaCha20-Poly1305 context of the key of keylen bytes at
 *	key, or NULL on a failure. The caller frees it with
 *	EVP_AEAD_CTX_free(), which clears the key of the context.
 */
static EVP_AEAD_CTX *
aead_ctx(const unsigned char *key, size_t keylen)
{
	EVP_AEAD_CTX	*ctx;

	if ((ctx = EVP_AEAD_CTX_new()) == NULL)
		return NULL;

	/*
	 * The tag length is the full tag of the layout, and not a
	 * truncation of it.
	 */
	if (EVP_AEAD_CTX_init(ctx, EVP_aead_chacha20_poly1305(), key, keylen,
	    SEAL_TAGLEN, NULL) != 1) {
		EVP_AEAD_CTX_free(ctx);
		return NULL;
	}
	return ctx;
}

int
seal_seal(const unsigned char *key, size_t keylen, const unsigned char *plain,
    size_t plainlen, unsigned char *out, size_t outlen)
{
	EVP_AEAD_CTX	*ctx = NULL;
	size_t		 bodylen = 0;
	int		 rv = -1;

	/*
	 * A plaintext of 0 bytes is no vault file, and the second
	 * gate below stops the overflow of the sum.
	 */
	if (keylen != SEAL_KEYLEN || plainlen == 0 ||
	    plainlen > SIZE_MAX - SEAL_OVERHEAD ||
	    outlen != plainlen + SEAL_OVERHEAD)
		return -1;

	out[SEAL_OFF_VERSION] = SEAL_VERSION;
	arc4random_buf(&out[SEAL_OFF_NONCE], SEAL_NONCELEN);

	if ((ctx = aead_ctx(key, keylen)) == NULL)
		goto out;
	if (EVP_AEAD_CTX_seal(ctx, &out[SEAL_OFF_BODY], &bodylen,
	    outlen - SEAL_OFF_BODY, &out[SEAL_OFF_NONCE], SEAL_NONCELEN,
	    plain, plainlen, &out[SEAL_OFF_VERSION], AADLEN) != 1)
		goto out;
	if (bodylen != plainlen + SEAL_TAGLEN)
		goto out;
	rv = 0;
out:
	EVP_AEAD_CTX_free(ctx);
	if (rv != 0)
		explicit_bzero(out, outlen);
	return rv;
}

int
seal_open(const unsigned char *key, size_t keylen, const unsigned char *sealed,
    size_t sealedlen, unsigned char *out, size_t outlen)
{
	EVP_AEAD_CTX	*ctx = NULL;
	size_t		 plainlen = 0;
	int		 rv = -1;

	if (keylen != SEAL_KEYLEN || sealedlen <= SEAL_OVERHEAD ||
	    outlen != sealedlen - SEAL_OVERHEAD)
		return -1;

	/* The tool reads seal version 0x01 alone (VAULT-SEAL-1). */
	if (sealed[SEAL_OFF_VERSION] != SEAL_VERSION)
		goto out;
	if ((ctx = aead_ctx(key, keylen)) == NULL)
		goto out;
	if (EVP_AEAD_CTX_open(ctx, out, &plainlen, outlen,
	    &sealed[SEAL_OFF_NONCE], SEAL_NONCELEN, &sealed[SEAL_OFF_BODY],
	    sealedlen - SEAL_OFF_BODY, &sealed[SEAL_OFF_VERSION],
	    AADLEN) != 1)
		goto out;
	if (plainlen != outlen)
		goto out;
	rv = 0;
out:
	EVP_AEAD_CTX_free(ctx);

	/*
	 * Every failure above gives this one -1, with no message and
	 * no cause, so a caller learns nothing of the key
	 * (VAULT-SEAL-4).
	 */
	if (rv != 0)
		explicit_bzero(out, outlen);
	return rv;
}
