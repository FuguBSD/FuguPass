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
 * The derivation core. Every vault key comes from one master: a
 * BIP39 mnemonic of 12 words. This file gives the root of that tree.
 *
 * derive_master_check() is the gate of the master, and derive_root()
 * makes root, the BIP39 seed of the master. derive_f() is the one
 * derivation function of the specification (KEY-DERIVE-1). Each
 * label of the table of keys.md gets a function of its own. This
 * file holds nine of the ten labels, and share.c holds the
 * coefficient label of the split (KEY-SHARE-3).
 *
 * The label of a record carries the suffix i/e: the oracle index,
 * one solidus, and the slot index. The canary form of a label
 * carries the suffix i/canary, and it gets a function of its own. No
 * caller gives a suffix, so no caller can build a wrong label.
 *
 * Every function takes buffers and lengths, and returns 0, or -1 on
 * a failure. A failed call leaves no secret in an output buffer, and
 * every function clears each temporary on each exit path
 * (SEC-MEMORY-1).
 *
 * The master and root are secrets, and they must not persist on disk
 * (KEY-MASTER-3, SEC-ENTROPY-6). Each caller clears the buffers that
 * it owns.
 */

#ifndef DERIVE_H
#define DERIVE_H

#include <stddef.h>
#include <stdint.h>

#include "wordlist.h"

#define DERIVE_WORDS	12	/* the words of the master (KEY-MASTER-1) */
#define DERIVE_ROOTLEN	64	/* the bytes of root, the BIP39 seed */
#define DERIVE_KEYLEN	32	/* the bytes that f gives (KEY-DERIVE-1) */
#define DERIVE_ERRLEN	64	/* a message of the gate, with the terminator */

/* The prefix of every derivation label (KEY-DERIVE-2). */
#define DERIVE_LABEL_PREFIX	"fugupass/v1/"

/* The bytes of a machine name (KEY-DEVICE-3). */
#define DERIVE_MACHINE_MAX	64

/* The highest oracle index: a vault holds 255 positions (KEY-SHARE-1). */
#define DERIVE_ORACLE_MAX	255

/* One master line: 12 words, 11 spaces, and a terminator. */
#define DERIVE_MASTER_MAX	(DERIVE_WORDS * (WORDLIST_MAX + 1))

/*
 * derive_master_check(line, linelen, err, errlen):
 *	Prove the master of linelen bytes at line. The line holds 12
 *	words of the BIP39 English list, with one space between two
 *	words, and no other byte. A failure is a count other than 12,
 *	a word that the list does not hold, and a wrong BIP39
 *	checksum.
 *
 *	A failure writes a message of errlen bytes or fewer to err,
 *	with a terminator. DERIVE_ERRLEN bytes are sufficient for
 *	every message. A message names the count, the position, or
 *	the checksum, and it holds no word of the list
 *	(KEY-MASTER-6). With errlen of 0, the call writes no message,
 *	and err can be NULL.
 */
int	derive_master_check(const char *, size_t, char *, size_t);

/*
 * derive_root(line, linelen, root, rootlen):
 *	The BIP39 seed of the master of linelen bytes at line, to the
 *	rootlen bytes at root. rootlen must be DERIVE_ROOTLEN. The
 *	BIP39 passphrase is empty (KEY-MASTER-4). The call proves the
 *	master first, and it gives -1 for a master that the gate
 *	rejects.
 */
int	derive_root(const char *, size_t, unsigned char *, size_t);

/*
 * derive_f(key, keylen, label, labellen, out, outlen):
 *	f(key, label): HMAC-SHA256 with the key of keylen bytes at
 *	key, and the message of labellen bytes at label, to the
 *	outlen bytes at out. outlen must be DERIVE_KEYLEN.
 *
 *	The key must be a high-entropy key, and a typed passphrase
 *	must not enter here (KEY-DERIVE-3, KEY-DERIVE-4). The caller
 *	holds that rule, because no code can measure it.
 */
int	derive_f(const unsigned char *, size_t, const char *, size_t,
	    unsigned char *, size_t);

/*
 * derive_entry_key(root, rootlen, slot, out, outlen):
 *	The entry key of the slot index slot, to the outlen bytes at
 *	out (KEY-ENTRY-2). rootlen must be DERIVE_ROOTLEN, and outlen
 *	must be DERIVE_KEYLEN. A slot index below 2^31 is valid
 *	(KEY-ENTRY-1).
 */
int	derive_entry_key(const unsigned char *, size_t, uint32_t,
	    unsigned char *, size_t);

/*
 * derive_plate_check(root, rootlen, out, outlen):
 *	The plate check value, to the outlen bytes at out
 *	(KEY-MASTER-5). rootlen must be DERIVE_ROOTLEN, and outlen
 *	must be DERIVE_KEYLEN. This one-way value can persist on
 *	disk.
 */
int	derive_plate_check(const unsigned char *, size_t, unsigned char *,
	    size_t);

/*
 * derive_machine_check(name, namelen):
 *	Prove the machine name of namelen bytes at name. The name
 *	holds lowercase ASCII letters, digits and hyphens only, and
 *	it holds 1 to DERIVE_MACHINE_MAX bytes (KEY-DEVICE-3). No
 *	other name passes. The machine name is not secret.
 */
int	derive_machine_check(const char *, size_t);

/*
 * derive_device_factor(root, rootlen, name, namelen, out, outlen):
 *	The device factor of the machine name of namelen bytes at
 *	name, to the outlen bytes at out (KEY-DEVICE-1). rootlen
 *	must be DERIVE_ROOTLEN, and outlen must be DERIVE_KEYLEN.
 *	The call proves the name first, and it gives -1 for a name
 *	that the gate rejects.
 *
 *	The suffix is the UTF-8 bytes of the machine name. The gate
 *	holds the name to ASCII, and ASCII text is its own UTF-8
 *	form. The device factor derives from the master, and it
 *	comes from no other source (SEC-ENTROPY-3).
 */
int	derive_device_factor(const unsigned char *, size_t, const char *,
	    size_t, unsigned char *, size_t);

/*
 * derive_client_reduce(t, tlen, out, outlen):
 *	The client key of the key material of tlen bytes at t, to
 *	the outlen bytes at out: (t mod (q - 1)) + 1, where q is the
 *	secp256k1 group order (KEY-CLIENT-2). The function reads t
 *	as a big-endian integer, and it writes 32 big-endian bytes.
 *	tlen and outlen must be DERIVE_KEYLEN.
 *
 *	The output is 1 to q - 1, so the curve accepts it.
 *	derive_client_key() makes the material and calls this
 *	function. A known-answer test calls it with a fixed
 *	material, because the material of a record is a secret.
 */
int	derive_client_reduce(const unsigned char *, size_t, unsigned char *,
	    size_t);

/*
 * derive_client_key(x, xlen, oracle, slot, out, outlen):
 *	The client key of the record of the slot index slot at the
 *	oracle index oracle, to the outlen bytes at out
 *	(KEY-CLIENT-1, KEY-CLIENT-2). x is the device factor of xlen
 *	bytes, xlen must be DERIVE_KEYLEN, and outlen must be
 *	DERIVE_KEYLEN.
 *
 *	The output is a secp256k1 private key of 1 to q - 1, and the
 *	curve accepts it. No passphrase enters the key
 *	(KEY-CLIENT-4). The oracle index is 1-based, and it is 1 to
 *	DERIVE_ORACLE_MAX. A slot index below 2^31 is valid
 *	(KEY-ENTRY-1).
 */
int	derive_client_key(const unsigned char *, size_t, unsigned int, uint32_t,
	    unsigned char *, size_t);

/*
 * derive_client_key_canary(x, xlen, oracle, out, outlen):
 *	The canary client key of the oracle index oracle, to the
 *	outlen bytes at out (KEY-CLIENT-3). The suffix holds the
 *	literal canary in place of the slot index. Each other rule
 *	of derive_client_key() holds here.
 */
int	derive_client_key_canary(const unsigned char *, size_t, unsigned int,
	    unsigned char *, size_t);

/*
 * derive_pin_salt(x, xlen, oracle, slot, out, outlen):
 *	The pin salt of the record of the slot index slot at the
 *	oracle index oracle, to the outlen bytes at out (KEY-PIN-2).
 *	x is the device factor of xlen bytes, xlen must be
 *	DERIVE_KEYLEN, and outlen must be DERIVE_KEYLEN. A salt
 *	derives from the device factor, and a salt is not random
 *	(SEC-ENTROPY-5).
 */
int	derive_pin_salt(const unsigned char *, size_t, unsigned int, uint32_t,
	    unsigned char *, size_t);

/*
 * derive_pin_salt_canary(x, xlen, oracle, out, outlen):
 *	The canary pin salt of the oracle index oracle, to the
 *	outlen bytes at out (KEY-PIN-2). The suffix holds the
 *	literal canary in place of the slot index. Each other rule
 *	of derive_pin_salt() holds here.
 */
int	derive_pin_salt_canary(const unsigned char *, size_t, unsigned int,
	    unsigned char *, size_t);

/*
 * derive_wrap_key(mask, masklen, oracle, slot, out, outlen):
 *	The wrap key of the record of the slot index slot at the
 *	oracle index oracle, to the outlen bytes at out (KEY-MASK-3).
 *	mask is the answer of that oracle for that record, of
 *	masklen bytes. masklen must be DERIVE_KEYLEN, and outlen
 *	must be DERIVE_KEYLEN. The client must not store a mask
 *	(KEY-MASK-2).
 */
int	derive_wrap_key(const unsigned char *, size_t, unsigned int, uint32_t,
	    unsigned char *, size_t);

/*
 * derive_index_key(root, rootlen, out, outlen):
 *	The index key of the vault, to the outlen bytes at out
 *	(KEY-MASK-6). rootlen must be DERIVE_ROOTLEN, and outlen
 *	must be DERIVE_KEYLEN. The label takes no suffix.
 */
int	derive_index_key(const unsigned char *, size_t, unsigned char *,
	    size_t);

/*
 * derive_index_wrap_key(mask, masklen, oracle, out, outlen):
 *	The index wrap key of the oracle index oracle, to the outlen
 *	bytes at out (KEY-MASK-7). mask is the canary mask of that
 *	oracle, of masklen bytes. masklen must be DERIVE_KEYLEN, and
 *	outlen must be DERIVE_KEYLEN. The suffix is the oracle
 *	index.
 */
int	derive_index_wrap_key(const unsigned char *, size_t, unsigned int,
	    unsigned char *, size_t);

/*
 * derive_canary_check_key(mask, masklen, oracle, out, outlen):
 *	The seal key of the canary check of the oracle index oracle,
 *	to the outlen bytes at out (KEY-MASK-5). mask is the canary
 *	mask of that oracle, of masklen bytes. masklen must be
 *	DERIVE_KEYLEN, and outlen must be DERIVE_KEYLEN. The suffix
 *	is the oracle index.
 */
int	derive_canary_check_key(const unsigned char *, size_t, unsigned int,
	    unsigned char *, size_t);

#endif /* DERIVE_H */
