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
 * The seal of a vault file. One sealed file is the version byte,
 * then a fresh 12-byte nonce, then the body: the ChaCha20-Poly1305
 * ciphertext and the 16-byte tag (VAULT-SEAL-1). The AEAD comes
 * from libcrypto (VAULT-SEAL-2, D-13, D-15).
 *
 * seal_seal() draws the nonce of each write from arc4random(3)
 * (VAULT-SEAL-3, SEC-ENTROPY-4), so two seals of one plaintext give
 * two sealed values. The AEAD takes the version byte as the
 * additional authenticated data (VAULT-SEAL-5).
 *
 * seal_open() gives one failure for every wrong key, and it names
 * no cause (VAULT-SEAL-4). A junk oracle answer, a wrong
 * passphrase, a wiped record, and a stale wrap each give a wrong
 * key, and each one ends in that failure.
 *
 * Both functions take buffers and lengths, and return 0, or -1 on a
 * failure. A failed call leaves no plaintext in the output buffer
 * (SEC-MEMORY-1).
 *
 * The key and the plaintext are secrets. Each caller clears the
 * buffers that it owns, and it erases an entry key directly after
 * the call (SEC-MEMORY-6).
 */

#ifndef SEAL_H
#define SEAL_H

#include <stddef.h>

#define SEAL_VERSION	0x01	/* the one seal version (VAULT-SEAL-1) */
#define SEAL_KEYLEN	32	/* the key bytes of the AEAD */
#define SEAL_NONCELEN	12	/* the nonce bytes of the AEAD */
#define SEAL_TAGLEN	16	/* the tag bytes of the AEAD */

/* The offsets of the three fields of the layout (VAULT-SEAL-1). */
#define SEAL_OFF_VERSION	0
#define SEAL_OFF_NONCE		1
#define SEAL_OFF_BODY		(SEAL_OFF_NONCE + SEAL_NONCELEN)

/* The bytes that a seal adds to a plaintext: the head and the tag. */
#define SEAL_OVERHEAD		(SEAL_OFF_BODY + SEAL_TAGLEN)

/*
 * seal_seal(key, keylen, plain, plainlen, out, outlen):
 *	Seal the plainlen bytes at plain under the key of keylen
 *	bytes at key, to the outlen bytes at out (VAULT-SEAL-1).
 *	keylen must be SEAL_KEYLEN, plainlen must be 1 or more, and
 *	outlen must be plainlen plus SEAL_OVERHEAD.
 *
 *	The call writes the version byte, then a new nonce, then the
 *	body of plainlen plus SEAL_TAGLEN bytes (VAULT-SEAL-3).
 */
int	seal_seal(const unsigned char *, size_t, const unsigned char *,
	    size_t, unsigned char *, size_t);

/*
 * seal_open(key, keylen, sealed, sealedlen, out, outlen):
 *	Open the sealedlen bytes at sealed under the key of keylen
 *	bytes at key, to the outlen bytes at out. keylen must be
 *	SEAL_KEYLEN, sealedlen must be more than SEAL_OVERHEAD, and
 *	outlen must be sealedlen less SEAL_OVERHEAD.
 *
 *	A version byte other than SEAL_VERSION, a changed byte, and
 *	a wrong key each give -1, and the call names no cause
 *	(VAULT-SEAL-1, VAULT-SEAL-4).
 */
int	seal_open(const unsigned char *, size_t, const unsigned char *,
	    size_t, unsigned char *, size_t);

#endif /* SEAL_H */
