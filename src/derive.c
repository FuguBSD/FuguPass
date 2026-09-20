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
 * function f, the gate of a machine name, and nine labels of the
 * table of keys.md. derive.h states the interface.
 *
 * The primitives come from libcrypto, and no other library enters
 * this file (D-15). The reduction of a client key takes the BN
 * functions of that library, because libsecp256k1 gives no scalar
 * arithmetic (KEY-CLIENT-2).
 *
 * The table of keys.md is the complete list of the labels
 * (KEY-DERIVE-2), and each label of this file comes from that table.
 * The label functions below stand in the order of that table.
 */

#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/bn.h>
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
 * The labels of this file, in the order of the table of keys.md. The
 * coefficient label of the split is the one label of the table that
 * share.c holds (KEY-SHARE-3).
 */
static const char	label_entry_key[] = DERIVE_LABEL_PREFIX "entry-key";
static const char	label_device_factor[] = DERIVE_LABEL_PREFIX
			    "device-factor";
static const char	label_client_key[] = DERIVE_LABEL_PREFIX "client-key";
static const char	label_pin_salt[] = DERIVE_LABEL_PREFIX "pin-salt";
static const char	label_wrap[] = DERIVE_LABEL_PREFIX "wrap";
static const char	label_index_key[] = DERIVE_LABEL_PREFIX "index-key";
static const char	label_wrap_index[] = DERIVE_LABEL_PREFIX "wrap-index";
static const char	label_canary_check[] = DERIVE_LABEL_PREFIX
			    "canary-check";
static const char	label_plate_check[] = DERIVE_LABEL_PREFIX "plate-check";

/*
 * One label of a record, with its suffix and the terminator. The
 * longest one is the label, the oracle index of 3 digits, one
 * solidus, and the slot index of 10 digits. Each helper below proves
 * the length of the label that it writes.
 */
#define LABEL_MAX	48

/*
 * The order q of the secp256k1 group, less one, as 32 big-endian
 * bytes. SEC 2 version 2, section 2.4.1, fixes q. A client key is
 * the remainder of the key material modulo this value, and then one
 * more, so the key stays in 1 to q - 1 (KEY-CLIENT-2).
 */
static const unsigned char order_minus_one[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
	0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
	0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40
};

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
 * key_record(key, keylen, label, oracle, slot, out, outlen):
 *	f of the key of keylen bytes at key, and the label with the
 *	suffix i/e, to the outlen bytes at out. The suffix is the
 *	oracle index, one solidus, and the slot index, as unpadded
 *	decimal ASCII.
 */
static int
key_record(const unsigned char *key, size_t keylen, const char *label,
    unsigned int oracle, uint32_t slot, unsigned char *out, size_t outlen)
{
	char	 buf[LABEL_MAX];
	int	 n, rv = -1;

	/* A slot index stays below 2^31 (KEY-ENTRY-1). */
	if (keylen != DERIVE_KEYLEN || oracle == 0 ||
	    oracle > DERIVE_ORACLE_MAX || slot > INT32_MAX)
		return -1;

	n = snprintf(buf, sizeof(buf), "%s%u/%" PRIu32, label, oracle, slot);
	if (n < 0 || (size_t)n >= sizeof(buf))
		goto out;
	rv = derive_f(key, keylen, buf, (size_t)n, out, outlen);
out:
	explicit_bzero(buf, sizeof(buf));
	return rv;
}

/*
 * key_canary(key, keylen, label, oracle, out, outlen):
 *	f of the key of keylen bytes at key, and the label with the
 *	suffix i/canary, to the outlen bytes at out. The literal
 *	canary stands in place of the slot index (KEY-CLIENT-3,
 *	KEY-PIN-2).
 */
static int
key_canary(const unsigned char *key, size_t keylen, const char *label,
    unsigned int oracle, unsigned char *out, size_t outlen)
{
	char	 buf[LABEL_MAX];
	int	 n, rv = -1;

	if (keylen != DERIVE_KEYLEN || oracle == 0 ||
	    oracle > DERIVE_ORACLE_MAX)
		return -1;

	n = snprintf(buf, sizeof(buf), "%s%u/canary", label, oracle);
	if (n < 0 || (size_t)n >= sizeof(buf))
		goto out;
	rv = derive_f(key, keylen, buf, (size_t)n, out, outlen);
out:
	explicit_bzero(buf, sizeof(buf));
	return rv;
}

/*
 * key_oracle(key, keylen, label, oracle, out, outlen):
 *	f of the key of keylen bytes at key, and the label with the
 *	suffix i, to the outlen bytes at out. The suffix is the
 *	oracle index alone, as unpadded decimal ASCII.
 */
static int
key_oracle(const unsigned char *key, size_t keylen, const char *label,
    unsigned int oracle, unsigned char *out, size_t outlen)
{
	char	 buf[LABEL_MAX];
	int	 n, rv = -1;

	if (keylen != DERIVE_KEYLEN || oracle == 0 ||
	    oracle > DERIVE_ORACLE_MAX)
		return -1;

	n = snprintf(buf, sizeof(buf), "%s%u", label, oracle);
	if (n < 0 || (size_t)n >= sizeof(buf))
		goto out;
	rv = derive_f(key, keylen, buf, (size_t)n, out, outlen);
out:
	explicit_bzero(buf, sizeof(buf));
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
derive_machine_check(const char *name, size_t namelen)
{
	unsigned char	 c;
	size_t		 i;

	if (namelen == 0 || namelen > DERIVE_MACHINE_MAX)
		return -1;

	/*
	 * The set is the lowercase ASCII letters, the digits, and
	 * the hyphen (KEY-DEVICE-3). The byte comparisons take no
	 * locale, and a byte above 0x7f falls outside each set.
	 */
	for (i = 0; i < namelen; i++) {
		c = (unsigned char)name[i];
		if ((c < 'a' || c > 'z') && (c < '0' || c > '9') &&
		    c != '-')
			return -1;
	}
	return 0;
}

int
derive_device_factor(const unsigned char *root, size_t rootlen,
    const char *name, size_t namelen, unsigned char *out, size_t outlen)
{
	/* The label, the longest machine name, and the terminator. */
	char	 label[sizeof(label_device_factor) + DERIVE_MACHINE_MAX];
	int	 n, rv = -1;

	if (rootlen != DERIVE_ROOTLEN)
		return -1;
	if (derive_machine_check(name, namelen) != 0)
		return -1;

	/*
	 * The suffix is the UTF-8 bytes of the machine name. The
	 * gate holds the name to ASCII, and ASCII text is its own
	 * UTF-8 form.
	 */
	n = snprintf(label, sizeof(label), "%s%.*s", label_device_factor,
	    (int)namelen, name);
	if (n < 0 || (size_t)n >= sizeof(label))
		goto out;
	rv = derive_f(root, rootlen, label, (size_t)n, out, outlen);
out:
	explicit_bzero(label, sizeof(label));
	return rv;
}

int
derive_client_reduce(const unsigned char *t, size_t tlen, unsigned char *out,
    size_t outlen)
{
	BN_CTX		*ctx = NULL;
	BIGNUM		*num = NULL, *mod = NULL, *key = NULL;
	int		 rv = -1;

	if (tlen != DERIVE_KEYLEN || outlen != DERIVE_KEYLEN)
		return -1;

	if ((ctx = BN_CTX_new()) == NULL)
		goto out;
	if ((num = BN_bin2bn(t, (int)tlen, NULL)) == NULL)
		goto out;
	if ((mod = BN_bin2bn(order_minus_one, (int)sizeof(order_minus_one),
	    NULL)) == NULL)
		goto out;
	if ((key = BN_new()) == NULL)
		goto out;

	/*
	 * The key material is a secret, and the flag asks libcrypto
	 * for the constant-time path of the division.
	 */
	BN_set_flags(num, BN_FLG_CONSTTIME);
	if (BN_mod(key, num, mod, ctx) != 1)
		goto out;
	if (BN_add_word(key, 1) != 1)
		goto out;
	if (BN_bn2binpad(key, out, (int)outlen) != (int)outlen)
		goto out;
	rv = 0;
out:
	BN_clear_free(key);
	BN_clear_free(num);
	BN_free(mod);
	BN_CTX_free(ctx);
	if (rv != 0)
		explicit_bzero(out, outlen);
	return rv;
}

int
derive_client_key(const unsigned char *x, size_t xlen, unsigned int oracle,
    uint32_t slot, unsigned char *out, size_t outlen)
{
	unsigned char	 t[DERIVE_KEYLEN];
	int		 rv = -1;

	if (outlen != DERIVE_KEYLEN)
		return -1;

	/* The key material is t_ei, and the reduction gives ck_ei. */
	if (key_record(x, xlen, label_client_key, oracle, slot, t,
	    sizeof(t)) != 0)
		goto out;
	rv = derive_client_reduce(t, sizeof(t), out, outlen);
out:
	explicit_bzero(t, sizeof(t));
	if (rv != 0)
		explicit_bzero(out, outlen);
	return rv;
}

int
derive_client_key_canary(const unsigned char *x, size_t xlen,
    unsigned int oracle, unsigned char *out, size_t outlen)
{
	unsigned char	 t[DERIVE_KEYLEN];
	int		 rv = -1;

	if (outlen != DERIVE_KEYLEN)
		return -1;

	if (key_canary(x, xlen, label_client_key, oracle, t, sizeof(t)) != 0)
		goto out;
	rv = derive_client_reduce(t, sizeof(t), out, outlen);
out:
	explicit_bzero(t, sizeof(t));
	if (rv != 0)
		explicit_bzero(out, outlen);
	return rv;
}

int
derive_pin_salt(const unsigned char *x, size_t xlen, unsigned int oracle,
    uint32_t slot, unsigned char *out, size_t outlen)
{
	return key_record(x, xlen, label_pin_salt, oracle, slot, out, outlen);
}

int
derive_pin_salt_canary(const unsigned char *x, size_t xlen,
    unsigned int oracle, unsigned char *out, size_t outlen)
{
	return key_canary(x, xlen, label_pin_salt, oracle, out, outlen);
}

int
derive_wrap_key(const unsigned char *mask, size_t masklen,
    unsigned int oracle, uint32_t slot, unsigned char *out, size_t outlen)
{
	return key_record(mask, masklen, label_wrap, oracle, slot, out, outlen);
}

int
derive_index_key(const unsigned char *root, size_t rootlen,
    unsigned char *out, size_t outlen)
{
	if (rootlen != DERIVE_ROOTLEN)
		return -1;
	return derive_f(root, rootlen, label_index_key,
	    sizeof(label_index_key) - 1, out, outlen);
}

int
derive_index_wrap_key(const unsigned char *mask, size_t masklen,
    unsigned int oracle, unsigned char *out, size_t outlen)
{
	return key_oracle(mask, masklen, label_wrap_index, oracle, out, outlen);
}

int
derive_canary_check_key(const unsigned char *mask, size_t masklen,
    unsigned int oracle, unsigned char *out, size_t outlen)
{
	return key_oracle(mask, masklen, label_canary_check, oracle, out,
	    outlen);
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
