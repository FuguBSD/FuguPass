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
 * The BIP85 applications. BIP85 derives a child secret from one
 * seed, through a hardened BIP32 path and one HMAC-SHA512 step. Each
 * application of the standard gets its own path. FuguPass takes two
 * of them: a password, and a child mnemonic of 12 words
 * (KEY-BIP85-1, KEY-BIP85-2).
 *
 * Both applications take root, the BIP39 seed of the master, as the
 * BIP32 seed (KEY-BIP85-3). The BIP85 index of a slot is the slot
 * index (KEY-BIP85-4). The length of the password and the count of
 * the words are fixed constants, because a recovery from the plate
 * alone reads no metadata (KEY-BIP85-8).
 *
 * Every function takes buffers and lengths, and returns 0, or -1 on
 * a failure. A failed call leaves no secret in an output buffer, and
 * every function clears each temporary on each exit path
 * (SEC-MEMORY-1).
 *
 * Each output of this file is a secret, and each caller clears the
 * buffers that it owns.
 */

#ifndef BIP85_H
#define BIP85_H

#include <stddef.h>
#include <stdint.h>

#include "derive.h"
#include "wordlist.h"

#define BIP85_KEYLEN	32	/* the bytes of a BIP32 private key */
#define BIP85_CHAINLEN	32	/* the bytes of a BIP32 chain code */
#define BIP85_ENTLEN	64	/* the bytes that the DRNG gives */
#define BIP85_PWDLEN	21	/* the characters of a password */
#define BIP85_WORDS	12	/* the words of a child mnemonic */

/* One password, with the terminator. */
#define BIP85_PWD_MAX		(BIP85_PWDLEN + 1)

/* One child mnemonic: 12 words, 11 spaces, and a terminator. */
#define BIP85_MNEMONIC_MAX	(BIP85_WORDS * (WORDLIST_MAX + 1))

/*
 * bip85_master(root, rootlen, key, keylen, chain, chainlen):
 *	The BIP32 master of the seed of rootlen bytes at root, to the
 *	keylen bytes at key and the chainlen bytes at chain. rootlen
 *	must be DERIVE_ROOTLEN, keylen must be BIP85_KEYLEN, and
 *	chainlen must be BIP85_CHAINLEN. A key that the curve rejects
 *	is a failure.
 */
int	bip85_master(const unsigned char *, size_t, unsigned char *, size_t,
	    unsigned char *, size_t);

/*
 * bip85_drng(key, keylen, out, outlen):
 *	The DRNG of the private key of keylen bytes at key, to the
 *	outlen bytes at out. keylen must be BIP85_KEYLEN, and outlen
 *	must be BIP85_ENTLEN. The DRNG is HMAC-SHA512 with the fixed
 *	key of BIP85, and the BIP85 document names its output the
 *	derived entropy. Each application takes the bytes that it
 *	needs, and it drops the others.
 */
int	bip85_drng(const unsigned char *, size_t, unsigned char *, size_t);

/*
 * bip85_pwd_base64(root, rootlen, slot, out, outlen):
 *	The password of the slot index slot, to the outlen bytes at
 *	out, with a terminator (KEY-BIP85-1). rootlen must be
 *	DERIVE_ROOTLEN, and outlen must be BIP85_PWD_MAX or more. The
 *	password is 21 characters of the Base64 set. A slot index
 *	below 2^31 is valid (KEY-ENTRY-1).
 */
int	bip85_pwd_base64(const unsigned char *, size_t, uint32_t, char *,
	    size_t);

/*
 * bip85_bip39(root, rootlen, slot, out, outlen):
 *	The child mnemonic of the slot index slot, to the outlen
 *	bytes at out, with a terminator (KEY-BIP85-2). rootlen must
 *	be DERIVE_ROOTLEN, and outlen must be BIP85_MNEMONIC_MAX or
 *	more. The mnemonic holds 12 words of the BIP39 English list,
 *	with one space between two words. A slot index below 2^31 is
 *	valid (KEY-ENTRY-1).
 */
int	bip85_bip39(const unsigned char *, size_t, uint32_t, char *, size_t);

#endif /* BIP85_H */
