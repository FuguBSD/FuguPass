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
 * The share split. One 32-byte secret splits across the oracle set,
 * byte-wise, with Shamir over GF(256) (KEY-SHARE-2). Any k shares
 * give the secret back. The coefficients derive from the secret
 * (KEY-SHARE-3), so k - 1 shares determine it. The claim against
 * k - 1 shares is therefore computational: only the cost of a
 * search protects the secret. docs/analysis/share-split.md states
 * that bound.
 *
 * share_split() gives the share of one oracle. No function here
 * gives every share at once, so a caller cannot hold a share set
 * between two uses (KEY-SHARE-8). Each call derives the coefficients
 * again from the split secret (KEY-SHARE-3).
 *
 * share_mul() and share_inv() are the field arithmetic, and each one
 * gives a field element in place of a status. Every other function
 * takes buffers and lengths, and returns 0, or -1 on a failure. A
 * failed call leaves no secret in an output buffer, and every
 * function clears each temporary on each exit path (SEC-MEMORY-1).
 *
 * A share is a secret, and it must not persist on disk
 * (KEY-SHARE-8). Each caller clears the buffers that it owns.
 */

#ifndef SHARE_H
#define SHARE_H

#include <stddef.h>

#include "derive.h"

/*
 * share_mul(a, b):
 *	The product of a and b in GF(256). The field polynomial is
 *	x^8 + x^4 + x^3 + x + 1 (KEY-SHARE-2). The loop holds no
 *	branch and reads no table, so the product takes constant
 *	time.
 */
unsigned char	share_mul(unsigned char, unsigned char);

/*
 * share_inv(a):
 *	The multiplicative inverse of a in GF(256) (KEY-SHARE-2). The
 *	inverse is a to the power of 254, from 7 squares and 7
 *	products of share_mul(), so it takes constant time. The field
 *	holds no inverse of 0, and this function gives 0 for it.
 */
unsigned char	share_inv(unsigned char);

/*
 * share_split(secret, secretlen, threshold, oracle, out, outlen):
 *	The share of the oracle index oracle, from the split of the
 *	secret of secretlen bytes at secret, at the threshold
 *	threshold, to the outlen bytes at out (KEY-SHARE-5).
 *
 *	Four gates give -1, and each one rejects the call before the
 *	split: a secretlen other than DERIVE_KEYLEN, an outlen other
 *	than DERIVE_KEYLEN, a threshold outside 1 to
 *	DERIVE_ORACLE_MAX, and an oracle index outside 1 to
 *	DERIVE_ORACLE_MAX. The oracle index is 1-based (KEY-SHARE-5),
 *	and p_b(0) is the secret itself (KEY-SHARE-4).
 *
 *	The caller holds the vault rule that the threshold is the
 *	count of the oracle positions or fewer (KEY-SHARE-1). With a
 *	threshold of 1, the share equals the secret (KEY-SHARE-7).
 */
int	share_split(const unsigned char *, size_t, unsigned int, unsigned int,
	    unsigned char *, size_t);

/*
 * share_combine(index, shares, count, out, outlen):
 *	The secret of the count shares at shares, to the outlen bytes
 *	at out (KEY-SHARE-6). shares holds count shares of
 *	DERIVE_KEYLEN bytes each, and index holds the oracle index of
 *	each share, in the same order.
 *
 *	Four gates give -1, and each one rejects the call before the
 *	interpolation: an outlen other than DERIVE_KEYLEN, a count of
 *	0, a count above DERIVE_ORACLE_MAX, and an index outside 1 to
 *	DERIVE_ORACLE_MAX. A repeated index gives -1 too, because two
 *	equal indexes give a divisor of 0.
 *
 *	count must equal the threshold of the split. A count of 1 to
 *	the threshold minus one gives a value other than the secret,
 *	and no function can see that case.
 */
int	share_combine(const unsigned int *, const unsigned char *, size_t,
	    unsigned char *, size_t);

#endif /* SHARE_H */
