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
 * The BIP85 applications: the BIP32 master, one hardened step, the
 * DRNG, and the two applications of the specification. bip85.h
 * states the interface.
 *
 * The hash primitives and the Base64 text come from libcrypto, and
 * the scalar addition of the curve comes from libsecp256k1. No other
 * library enters this file (D-15).
 *
 * Every step of every path is hardened, so this file computes no
 * public key. A hardened step needs the private key of the parent
 * only.
 */

#include <sys/param.h>

#include <stdint.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <secp256k1.h>

#include "bip85.h"
#include "wordlist.h"

/*
 * The fixed HMAC key of the BIP32 master, as the 12 bytes of its
 * ASCII string. BIP32 fixes that string, and D-21 bans the first
 * word of it, so the bytes stand here in place of the text.
 */
static const unsigned char master_key[] = {
	0x42, 0x69, 0x74, 0x63, 0x6f, 0x69, 0x6e, 0x20,
	0x73, 0x65, 0x65, 0x64
};

/* The fixed HMAC key of the DRNG of BIP85. */
static const char drng_key[] = "bip-entropy-from-k";

/*
 * The steps of a path. BIP85 fixes the first step, and the
 * application fixes the steps after it. Each index carries the
 * hardened bit.
 */
#define HARDENED	0x80000000U
#define STEP_BIP85	83696968	/* the first step of every path */
#define STEP_PWD_BASE64	707764		/* the application of the password */
#define STEP_BIP39	39		/* the application of the mnemonic */
#define STEP_ENGLISH	0		/* the English list of BIP39 */

/*
 * The bits of a child mnemonic. Each of the 12 words carries 11
 * bits: 128 bits of entropy, and then 4 bits of checksum.
 */
#define WORD_BITS	11
#define CHILD_ENTROPY	16
#define CHILD_BYTES	((BIP85_WORDS * WORD_BITS + 7) / 8)

/* The Base64 text of the entropy, with the padding and the terminator. */
#define B64_MAX		(4 * ((BIP85_ENTLEN + 2) / 3) + 1)

/*
 * bip85_child(key, chain, index):
 *	One hardened step, in place: the BIP85_KEYLEN bytes at key
 *	and the BIP85_CHAINLEN bytes at chain become the child of
 *	index. index must carry the hardened bit. A failure clears
 *	both buffers.
 */
static int
bip85_child(unsigned char *key, unsigned char *chain, uint32_t index)
{
	unsigned char	 data[1 + BIP85_KEYLEN + 4];
	unsigned char	 hash[SHA512_DIGEST_LENGTH];
	unsigned int	 len = 0;
	int		 rv = -1;

	/*
	 * The message of a hardened step is one zero byte, the
	 * private key of the parent, and the index. The index is
	 * big-endian, and the chain code of the parent is the key of
	 * the HMAC.
	 */
	data[0] = 0;
	memcpy(&data[1], key, BIP85_KEYLEN);
	data[1 + BIP85_KEYLEN] = (unsigned char)(index >> 24);
	data[2 + BIP85_KEYLEN] = (unsigned char)(index >> 16);
	data[3 + BIP85_KEYLEN] = (unsigned char)(index >> 8);
	data[4 + BIP85_KEYLEN] = (unsigned char)index;
	if (HMAC(EVP_sha512(), chain, BIP85_CHAINLEN, data, sizeof(data),
	    hash, &len) == NULL || len != SHA512_DIGEST_LENGTH)
		goto out;

	/*
	 * The private key of the child is the sum of the parent key
	 * and the first half of the hash, modulo the order of the
	 * group. The addition fails for a half that the curve
	 * rejects, and for a sum of zero. Each path of this file is
	 * fixed, so no other index can follow such a step.
	 */
	if (secp256k1_ec_seckey_tweak_add(secp256k1_context_static, key,
	    hash) != 1)
		goto out;
	memcpy(chain, &hash[BIP85_KEYLEN], BIP85_CHAINLEN);
	rv = 0;
out:
	explicit_bzero(data, sizeof(data));
	explicit_bzero(hash, sizeof(hash));
	if (rv != 0) {
		explicit_bzero(key, BIP85_KEYLEN);
		explicit_bzero(chain, BIP85_CHAINLEN);
	}
	return rv;
}

/*
 * bip85_entropy(root, rootlen, path, steps, out):
 *	The BIP85_ENTLEN bytes of the DRNG of the path of steps
 *	indexes at path, from the seed of rootlen bytes at root, to
 *	out. No index of path carries the hardened bit, and this
 *	function hardens every step.
 */
static int
bip85_entropy(const unsigned char *root, size_t rootlen, const uint32_t *path,
    size_t steps, unsigned char *out)
{
	unsigned char	 key[BIP85_KEYLEN];
	unsigned char	 chain[BIP85_CHAINLEN];
	size_t		 i;
	int		 rv = -1;

	if (bip85_master(root, rootlen, key, sizeof(key), chain,
	    sizeof(chain)) != 0)
		goto out;
	for (i = 0; i < steps; i++)
		if (bip85_child(key, chain, path[i] | HARDENED) != 0)
			goto out;
	rv = bip85_drng(key, sizeof(key), out, BIP85_ENTLEN);
out:
	explicit_bzero(key, sizeof(key));
	explicit_bzero(chain, sizeof(chain));
	if (rv != 0)
		explicit_bzero(out, BIP85_ENTLEN);
	return rv;
}

int
bip85_master(const unsigned char *root, size_t rootlen, unsigned char *key,
    size_t keylen, unsigned char *chain, size_t chainlen)
{
	unsigned char	 hash[SHA512_DIGEST_LENGTH];
	unsigned int	 len = 0;
	int		 rv = -1;

	if (rootlen != DERIVE_ROOTLEN || keylen != BIP85_KEYLEN ||
	    chainlen != BIP85_CHAINLEN)
		return -1;

	if (HMAC(EVP_sha512(), master_key, (int)sizeof(master_key), root,
	    rootlen, hash, &len) == NULL || len != SHA512_DIGEST_LENGTH)
		goto out;

	/*
	 * The curve rejects a first half of zero, and a first
	 * half of the order of the group or more.
	 */
	if (secp256k1_ec_seckey_verify(secp256k1_context_static, hash) != 1)
		goto out;
	memcpy(key, hash, BIP85_KEYLEN);
	memcpy(chain, &hash[BIP85_KEYLEN], BIP85_CHAINLEN);
	rv = 0;
out:
	explicit_bzero(hash, sizeof(hash));
	if (rv != 0) {
		explicit_bzero(key, keylen);
		explicit_bzero(chain, chainlen);
	}
	return rv;
}

int
bip85_drng(const unsigned char *key, size_t keylen, unsigned char *out,
    size_t outlen)
{
	unsigned int	 len = 0;

	if (keylen != BIP85_KEYLEN || outlen != BIP85_ENTLEN)
		return -1;
	if (HMAC(EVP_sha512(), drng_key, (int)sizeof(drng_key) - 1, key,
	    keylen, out, &len) == NULL || len != BIP85_ENTLEN) {
		explicit_bzero(out, outlen);
		return -1;
	}
	return 0;
}

int
bip85_pwd_base64(const unsigned char *root, size_t rootlen, uint32_t slot,
    char *out, size_t outlen)
{
	const uint32_t	 path[] = { STEP_BIP85, STEP_PWD_BASE64, BIP85_PWDLEN,
			     slot };
	unsigned char	 entropy[BIP85_ENTLEN];
	unsigned char	 text[B64_MAX];
	int		 rv = -1;

	/* A slot index stays below 2^31 (KEY-ENTRY-1). */
	if (outlen < BIP85_PWD_MAX || slot > INT32_MAX)
		return -1;

	if (bip85_entropy(root, rootlen, path, nitems(path), entropy) != 0)
		goto out;

	/*
	 * The password is the first 21 characters of the Base64 text
	 * of the entropy. EVP_EncodeBlock() writes that text with a
	 * terminator, and it writes no line feed. The text of 64
	 * bytes is 88 characters, so 21 characters are always there.
	 */
	if (EVP_EncodeBlock(text, entropy, (int)sizeof(entropy)) !=
	    (int)(B64_MAX - 1))
		goto out;
	memcpy(out, text, BIP85_PWDLEN);
	out[BIP85_PWDLEN] = '\0';
	rv = 0;
out:
	explicit_bzero(entropy, sizeof(entropy));
	explicit_bzero(text, sizeof(text));
	if (rv != 0)
		explicit_bzero(out, outlen);
	return rv;
}

int
bip85_bip39(const unsigned char *root, size_t rootlen, uint32_t slot,
    char *out, size_t outlen)
{
	const uint32_t	 path[] = { STEP_BIP85, STEP_BIP39, STEP_ENGLISH,
			     BIP85_WORDS, slot };
	unsigned char	 entropy[BIP85_ENTLEN];
	unsigned char	 bits[CHILD_BYTES];
	unsigned char	 digest[SHA256_DIGEST_LENGTH];
	char		 word[WORDLIST_MAX + 1];
	size_t		 i, at, index, wordlen, len = 0;
	int		 rv = -1;

	/* A slot index stays below 2^31 (KEY-ENTRY-1). */
	if (outlen < BIP85_MNEMONIC_MAX || slot > INT32_MAX)
		return -1;

	if (bip85_entropy(root, rootlen, path, nitems(path), entropy) != 0)
		goto out;

	/*
	 * The mnemonic takes the first 16 bytes of the entropy: 128
	 * bits for 12 words. The 4 bits of the checksum follow them
	 * at the top of the next byte, and they are the first 4 bits
	 * of the SHA-256 of the 16 bytes.
	 */
	memset(bits, 0, sizeof(bits));
	memcpy(bits, entropy, CHILD_ENTROPY);
	SHA256(bits, CHILD_ENTROPY, digest);
	bits[CHILD_ENTROPY] = digest[0] & 0xf0;

	/* The index of word i sits at bit i * 11, the high bit first. */
	for (i = 0; i < BIP85_WORDS; i++) {
		index = 0;
		for (at = i * WORD_BITS; at < (i + 1) * WORD_BITS; at++)
			index = (index << 1) |
			    ((bits[at / 8] >> (7 - at % 8)) & 1);
		if (wordlist_word(index, word, sizeof(word)) != 0)
			goto out;
		if (i > 0)
			out[len++] = ' ';
		wordlen = strlen(word);
		memcpy(&out[len], word, wordlen);
		len += wordlen;
	}
	out[len] = '\0';
	rv = 0;
out:
	explicit_bzero(entropy, sizeof(entropy));
	explicit_bzero(bits, sizeof(bits));
	explicit_bzero(digest, sizeof(digest));
	explicit_bzero(word, sizeof(word));
	if (rv != 0)
		explicit_bzero(out, outlen);
	return rv;
}
