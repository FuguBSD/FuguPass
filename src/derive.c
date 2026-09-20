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
 * The derivation core: the gate of the master, the BIP39 seed, the
 * function f, and two labels of the table of keys.md. derive.h
 * states the interface.
 *
 * The primitives come from libcrypto, and no other library enters
 * this file (D-15). The table of keys.md is the complete list of the
 * labels (KEY-DERIVE-2), and each label of this file comes from that
 * table.
 */

#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "derive.h"
#include "wordlist.h"

/*
 * The bits of the master. Each of the 12 words carries 11 bits, so
 * the master is 132 bits: 128 bits of entropy, and then 4 bits of
 * checksum. The checksum is the first 4 bits of the SHA-256 of the
 * entropy.
 */
#define WORD_BITS	11			/* the bits of one index */
#define MASTER_ENTROPY	16			/* the bytes of entropy */
#define MASTER_BYTES	((DERIVE_WORDS * WORD_BITS + 7) / 8)

/* The BIP39 seed. The salt is the fixed string of an empty passphrase. */
#define ROOT_ROUNDS	2048
#define ROOT_SALT	"mnemonic"

/*
 * The labels of the two keys of this file. Every label carries the
 * prefix, and the table of keys.md holds the complete list
 * (KEY-DERIVE-2).
 */
#define LABEL_PREFIX	"fugupass/v1/"

static const char	label_entry_key[] = LABEL_PREFIX "entry-key";
static const char	label_plate_check[] = LABEL_PREFIX "plate-check";

/*
 * master_sum(index, err, errlen):
 *	Prove the BIP39 checksum of the DERIVE_WORDS indexes at
 *	index. The bits of the master are the master itself, so this
 *	function clears them on each exit path.
 */
static int
master_sum(const size_t *index, char *err, size_t errlen)
{
	unsigned char	 bits[MASTER_BYTES];
	unsigned char	 digest[SHA256_DIGEST_LENGTH];
	unsigned char	 want[1];
	size_t		 i, bit, at;
	int		 rv = -1;

	/* The index of word i sits at bit i * 11, the high bit first. */
	memset(bits, 0, sizeof(bits));
	for (at = 0; at < DERIVE_WORDS * WORD_BITS; at++) {
		i = at / WORD_BITS;
		bit = WORD_BITS - 1 - at % WORD_BITS;
		if ((index[i] >> bit) & 1)
			bits[at / 8] |= (unsigned char)(0x80 >> (at % 8));
	}
	SHA256(bits, MASTER_ENTROPY, digest);

	/*
	 * The 4 bits of the checksum sit at the top of the byte after
	 * the entropy. The 4 bits below them are zero in both values,
	 * so one masked byte compares them.
	 */
	want[0] = digest[0] & 0xf0;
	if (timingsafe_bcmp(want, &bits[MASTER_ENTROPY], sizeof(want)) != 0) {
		snprintf(err, errlen, "the checksum is bad");
		goto out;
	}
	rv = 0;
out:
	explicit_bzero(bits, sizeof(bits));
	explicit_bzero(digest, sizeof(digest));
	explicit_bzero(want, sizeof(want));
	return rv;
}

/*
 * The messages of the gate name the count, the position, or the
 * checksum, and they hold no word of the BIP39 list (KEY-MASTER-6).
 * The rule bans a word of the scanned master, and a message of no
 * list word at all holds to the rule for every master.
 */
int
derive_master_check(const char *line, size_t linelen, char *err, size_t errlen)
{
	size_t	 index[DERIVE_WORDS];
	size_t	 i, count, start, end;
	int	 rv = -1;

	/* One space separates two words, so the spaces give the count. */
	count = 1;
	for (i = 0; i < linelen; i++)
		if (line[i] == ' ')
			count++;
	if (count != DERIVE_WORDS) {
		snprintf(err, errlen, "the count is %zu, not %d", count,
		    DERIVE_WORDS);
		goto out;
	}

	start = 0;
	for (i = 0; i < DERIVE_WORDS; i++) {
		for (end = start; end < linelen && line[end] != ' '; end++)
			continue;
		if (wordlist_index(&line[start], end - start, &index[i]) != 0) {
			snprintf(err, errlen,
			    "%zu of %d is not in the BIP39 set", i + 1,
			    DERIVE_WORDS);
			goto out;
		}
		start = end + 1;
	}
	rv = master_sum(index, err, errlen);
out:
	explicit_bzero(index, sizeof(index));
	return rv;
}

int
derive_root(const char *line, size_t linelen, unsigned char *root,
    size_t rootlen)
{
	if (rootlen != DERIVE_ROOTLEN || linelen > (size_t)INT_MAX)
		return -1;

	/*
	 * The gate holds the line to the words of the English list,
	 * so the line is ASCII. BIP39 asks for the NFKD form of the
	 * mnemonic, and ASCII text is already in that form.
	 */
	if (derive_master_check(line, linelen, NULL, 0) != 0)
		return -1;
	if (PKCS5_PBKDF2_HMAC(line, (int)linelen,
	    (const unsigned char *)ROOT_SALT, (int)sizeof(ROOT_SALT) - 1,
	    ROOT_ROUNDS, EVP_sha512(), (int)rootlen, root) != 1) {
		explicit_bzero(root, rootlen);
		return -1;
	}
	return 0;
}

int
derive_f(const unsigned char *key, size_t keylen, const char *label,
    size_t labellen, unsigned char *out, size_t outlen)
{
	unsigned int	 len = 0;

	if (keylen == 0 || keylen > (size_t)INT_MAX || labellen == 0 ||
	    outlen != DERIVE_KEYLEN)
		return -1;
	if (HMAC(EVP_sha256(), key, (int)keylen, (const unsigned char *)label,
	    labellen, out, &len) == NULL || len != DERIVE_KEYLEN) {
		explicit_bzero(out, outlen);
		return -1;
	}
	return 0;
}

int
derive_entry_key(const unsigned char *root, size_t rootlen, uint32_t slot,
    unsigned char *out, size_t outlen)
{
	/* The label, the 10 digits of the index, and the terminator. */
	char	 label[sizeof(label_entry_key) + 10];
	int	 n, rv = -1;

	/* A slot index stays below 2^31 (KEY-ENTRY-1). */
	if (rootlen != DERIVE_ROOTLEN || slot > INT32_MAX)
		return -1;

	/* The suffix is the slot index, as unpadded decimal ASCII. */
	n = snprintf(label, sizeof(label), "%s%" PRIu32, label_entry_key, slot);
	if (n < 0 || (size_t)n >= sizeof(label))
		goto out;
	rv = derive_f(root, rootlen, label, (size_t)n, out, outlen);
out:
	explicit_bzero(label, sizeof(label));
	return rv;
}

int
derive_plate_check(const unsigned char *root, size_t rootlen,
    unsigned char *out, size_t outlen)
{
	if (rootlen != DERIVE_ROOTLEN)
		return -1;
	return derive_f(root, rootlen, label_plate_check,
	    sizeof(label_plate_check) - 1, out, outlen);
}
