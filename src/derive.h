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
 * label of the table of keys.md gets a function of its own, and this
 * file holds two of them: the entry key (KEY-ENTRY-2) and the plate
 * check value (KEY-MASTER-5).
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

#endif /* DERIVE_H */
