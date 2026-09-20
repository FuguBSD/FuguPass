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
 * The share split: the arithmetic of GF(256), the derived
 * coefficients, the evaluation at one oracle index, and the
 * reconstruction. share.h states the interface.
 *
 * The arithmetic runs on a shift-and-reduce loop with no table, so
 * no memory access depends on a secret byte (D-15). No function of
 * this file branches on a secret byte, and the count of the steps
 * comes from the threshold and the count of the shares. Both are
 * public parameters of the vault.
 *
 * The coefficients come from derive_f(), the one derivation function
 * of the specification (KEY-DERIVE-1). No other library enters this
 * file.
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "derive.h"
#include "share.h"

/*
 * The label of a coefficient of the split (KEY-SHARE-3). The label
 * ends with a solidus, and the table of keys.md holds the complete
 * list of the labels (KEY-DERIVE-2).
 */
static const char	label_shamir[] = DERIVE_LABEL_PREFIX "shamir/";

/*
 * The field polynomial of GF(256) is x^8 + x^4 + x^3 + x + 1, or
 * 0x11b (KEY-SHARE-2). A product leaves the field when bit 8 stands,
 * and the shift below drops that bit. The low 8 bits of the
 * polynomial reduce the rest.
 */
#define FIELD_LOW	0x1b

/*
 * share_coeff(secret, secretlen, threshold, index, out, outlen):
 *	Coefficient index of the split of the secret of secretlen
 *	bytes at secret, at the threshold threshold, to the outlen
 *	bytes at out (KEY-SHARE-3). The coefficient derives from the
 *	split secret, and no coefficient comes from the system RNG
 *	(SEC-ENTROPY-7).
 */
static int
share_coeff(const unsigned char *secret, size_t secretlen,
    unsigned int threshold, unsigned int index, unsigned char *out,
    size_t outlen)
{
	/*
	 * The label, the threshold, one solidus, the coefficient
	 * index, and the terminator. Each index is unpadded decimal
	 * ASCII of 3 digits or fewer.
	 */
	char	 label[sizeof(label_shamir) + 8];
	int	 n, rv = -1;

	n = snprintf(label, sizeof(label), "%s%u/%u", label_shamir, threshold,
	    index);
	if (n < 0 || (size_t)n >= sizeof(label))
		goto out;
	rv = derive_f(secret, secretlen, label, (size_t)n, out, outlen);
out:
	explicit_bzero(label, sizeof(label));
	return rv;
}

unsigned char
share_mul(unsigned char a, unsigned char b)
{
	unsigned char	 product = 0, mask;
	int		 i;

	/*
	 * The loop runs 8 times for every pair. Each step adds a to
	 * the product when the low bit of b stands, and each step
	 * doubles a. A mask of 0x00 or 0xff carries each decision,
	 * so the loop holds no branch.
	 */
	for (i = 0; i < 8; i++) {
		mask = (unsigned char)-(b & 1);
		product ^= (unsigned char)(a & mask);
		mask = (unsigned char)-(a >> 7);
		a = (unsigned char)(a << 1);
		a ^= (unsigned char)(FIELD_LOW & mask);
		b = (unsigned char)(b >> 1);
	}
	return product;
}

unsigned char
share_inv(unsigned char a)
{
	unsigned char	 square = a, inverse = 1;
	int		 i;

	/*
	 * The nonzero elements form a group of 255 elements, so a to
	 * the power of 255 is 1, and a to the power of 254 is the
	 * inverse. The loop squares a 7 times, and it multiplies the
	 * powers 2, 4, 8, 16, 32, 64 and 128 together. The sum of
	 * those exponents is 254. The chain gives 0 for an input of
	 * 0, and it holds no branch.
	 */
	for (i = 0; i < 7; i++) {
		square = share_mul(square, square);
		inverse = share_mul(inverse, square);
	}
	return inverse;
}

int
share_split(const unsigned char *secret, size_t secretlen,
    unsigned int threshold, unsigned int oracle, unsigned char *out,
    size_t outlen)
{
	unsigned char	 coeff[DERIVE_KEYLEN];
	unsigned char	 x;
	size_t		 b;
	unsigned int	 j;
	int		 rv = -1;

	if (secretlen != DERIVE_KEYLEN || outlen != DERIVE_KEYLEN)
		return -1;
	if (threshold == 0 || threshold > DERIVE_ORACLE_MAX)
		return -1;
	if (oracle == 0 || oracle > DERIVE_ORACLE_MAX)
		return -1;

	/*
	 * The evaluation point of oracle i is i, and the polynomial
	 * of byte b is p_b(x) (KEY-SHARE-4, KEY-SHARE-5). Horner
	 * takes the coefficients from the highest one down: the sum
	 * starts at 0, each step multiplies it by x and adds the next
	 * coefficient, and the last step adds the secret at x^0.
	 *
	 * A threshold of 1 runs no step of the loop, so the share
	 * equals the secret. No branch and no special case makes that
	 * case (KEY-SHARE-7).
	 */
	x = (unsigned char)oracle;
	memset(out, 0, outlen);
	for (j = threshold - 1; j >= 1; j--) {
		if (share_coeff(secret, secretlen, threshold, j, coeff,
		    sizeof(coeff)) != 0)
			goto out;
		for (b = 0; b < outlen; b++)
			out[b] = (unsigned char)(share_mul(out[b], x) ^
			    coeff[b]);
	}
	for (b = 0; b < outlen; b++)
		out[b] = (unsigned char)(share_mul(out[b], x) ^ secret[b]);
	rv = 0;
out:
	explicit_bzero(coeff, sizeof(coeff));
	if (rv != 0)
		explicit_bzero(out, outlen);
	return rv;
}

int
share_combine(const unsigned int *index, const unsigned char *shares,
    size_t count, unsigned char *out, size_t outlen)
{
	unsigned char	 numerator, divisor, weight;
	size_t		 i, m, b;

	if (outlen != DERIVE_KEYLEN || count == 0 ||
	    count > DERIVE_ORACLE_MAX)
		return -1;

	/*
	 * An oracle index is public, so this gate branches on it. Two
	 * equal indexes give a divisor of 0, and the field holds no
	 * inverse of 0.
	 */
	for (i = 0; i < count; i++) {
		if (index[i] == 0 || index[i] > DERIVE_ORACLE_MAX)
			return -1;
		for (m = 0; m < i; m++)
			if (index[m] == index[i])
				return -1;
	}

	/*
	 * The interpolation runs at x = 0, byte-wise. The weight of
	 * share i is the product of m / (m ^ i) over each other index
	 * m, and the secret is the sum of the weighted shares
	 * (KEY-SHARE-6).
	 */
	memset(out, 0, outlen);
	for (i = 0; i < count; i++) {
		numerator = 1;
		divisor = 1;
		for (m = 0; m < count; m++) {
			if (m == i)
				continue;
			numerator = share_mul(numerator,
			    (unsigned char)index[m]);
			divisor = share_mul(divisor,
			    (unsigned char)(index[m] ^ index[i]));
		}
		weight = share_mul(numerator, share_inv(divisor));
		for (b = 0; b < outlen; b++)
			out[b] = (unsigned char)(out[b] ^
			    share_mul(shares[i * DERIVE_KEYLEN + b], weight));
	}
	return 0;
}
