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
 * The session of the core process: the unlock, the quorum, the
 * canary checks, the index open, the quorum reveal with
 * substitution, and the heal of a dead index wrap.
 *
 * session_open() runs the unlock in one order (PROG-REPL-1). It
 * reads the passphrase once, and it selects the quorum from the
 * reachable oracles in list order. It prefers an oracle that holds
 * a live index wrap of this machine (ORC-QUORUM-2). It verifies
 * the canary of one oracle at a time, and it stops at the first
 * canary failure, before any entry record (ORC-CANARY-1,
 * ORC-CANARY-4). The same k canary answers open the index
 * (ORC-CANARY-3, VAULT-INDEX-3).
 *
 * A command of the session takes the open index from
 * session_list() and session_index(), and it reveals one entry
 * with session_reveal(). Each call of this file sits above the
 * record client, so a command adds no oracle call of its own
 * (PROG-ONESHOT-2).
 *
 * One reveal is k get_pin requests and one decrypt (ORC-QUORUM-3,
 * ORC-QUORUM-4). A decrypt failure, an HTTP error, and a transport
 * failure each substitute the next reachable oracle, after the
 * canary check of that oracle. The substitutions stop when no
 * untried oracle remains (ORC-QUORUM-5). Below k reachable oracles
 * the session performs no reveal (ORC-QUORUM-6).
 *
 * session_consume() and session_seal() are the pair of one
 * consumption: the reveal of the slot file, and the entry file
 * under the entry key of that slot (ENTRY-POOL-4). The entry key
 * lives between the two calls, and it leaves memory at the seal
 * write (SEC-MEMORY-6). The caller writes the index between them,
 * with session_index_write(), so the index holds the consumed slot
 * before the entry file exists (ENTRY-POOL-8).
 *
 * session_close() clears every secret of the session on each exit
 * path (SEC-MEMORY-1). The plaintext of a reveal belongs to the
 * session, and the next reveal and the close clear it.
 *
 * This file holds no entry model: the field table of a type, the
 * pool, the rotation and the shadow audit sit above it
 * (ENTRY-TYPES-5, ENTRY-POOL, ENTRY-ROTATION, ENTRY-SHADOW). It
 * holds no change marker, so a session runs while a passphrase
 * change is incomplete (ORC-ENROLL-10). It holds no idle lock
 * (PROG-REPL-7), and it opens no vault without an oracle
 * (PROG-REPL-6).
 */

#ifndef SESSION_H
#define SESSION_H

#include <stddef.h>
#include <stdint.h>

#include "vault.h"

/* The bytes of the plaintext of one entry file or one slot file. */
#define SESSION_PLAIN_MAX	65536

/* The bytes of the plaintext of the index. */
#define SESSION_INDEX_MAX	262144

/* The session of one vault. session.c holds the members of it. */
struct session;

/*
 * One entry of the open index (VAULT-INDEX-2). The four strings
 * are the four parts of the entry value, and they live until the
 * session closes or writes the index (VAULT-FORMAT).
 *
 * file is the entry file name of the current version, of
 * 2 * DERIVE_KEYLEN bytes. type is the type name of the entry, and
 * this file resolves no type name: the entry model above it holds
 * the types (ENTRY-TYPES-1). slots is the slot list of every
 * version, and slot is the current slot: the last index of that
 * list (ENTRY-ROTATION-2). The entry name comes last in the value,
 * so it can hold a space.
 */
struct session_entry {
	const char	*file;
	const char	*type;
	const char	*slots;
	const char	*name;
	uint32_t	 slot;
};

/*
 * session_open(vault, out):
 *	Unlock the vault directory vault, and give the session of it
 *	to out. The call gives 0 for an open session, and -1 for a
 *	session that does not open.
 *
 *	The call reads the config file, the device factor of this
 *	machine, and the passphrase (PROG-REPL-1, SEC-MEMORY-4). It
 *	then verifies the canaries of the quorum, and it opens the
 *	index through the index wraps of the quorum (ORC-CANARY-3,
 *	VAULT-INDEX-3).
 *
 *	A canary failure, fewer than k reachable oracles, and an
 *	index decrypt failure each give -1, with a report of the
 *	cause set (ORC-CANARY-4, ORC-QUORUM-6, VAULT-INDEX-6). A
 *	quorum that covers fewer than k live index wraps gives 0 with
 *	a report: the session opens, and session_index() gives NULL,
 *	so the session resolves no entry name (ORC-CANARY-8).
 *
 *	An open session holds the passphrase and the index key, and
 *	session_close() clears them (SEC-MEMORY-1).
 */
int	session_open(const char *, struct session **);

/*
 * session_close(s):
 *	End the session s, and clear every secret of it with
 *	explicit_bzero(3) (SEC-MEMORY-1). The secrets are the
 *	passphrase, the device factor, the index key, the entry key
 *	of a consumption, the plaintext of the last reveal, and the
 *	plaintext of the index. A NULL session takes no action.
 */
void	session_close(struct session *);

/*
 * session_config(s):
 *	The config file of the session (VAULT-CONFIG-1). The values
 *	live until the session closes.
 */
const struct vault_config *session_config(const struct session *);

/*
 * session_list(s, count):
 *	The entries of the open index, and the count of them to
 *	count. The call gives NULL with a count of 0 for a session
 *	that holds no open index.
 *
 *	The entries come in the order of the index file. The list
 *	lives until the session closes or writes the index.
 */
const struct session_entry *session_list(const struct session *, size_t *);

/*
 * session_index(s, len):
 *	The plaintext of the open index, of len bytes, in the line
 *	format (VAULT-FORMAT-1). The call gives NULL with a length of
 *	0 for a session that holds no open index.
 *
 *	The caller reads the pool state, the machine registry and the
 *	verification date from this text, and it composes the text of
 *	session_index_write() from it (VAULT-INDEX-2). The text lives
 *	until the session closes or writes the index.
 */
const char *session_index(const struct session *, size_t *);

/*
 * session_index_write(s, text, textlen):
 *	Seal the textlen bytes at text under the index key, and write
 *	the index of the vault (VAULT-INDEX-1, VAULT-ATOMIC-1). The
 *	session takes the text as its open index.
 *
 *	The scanner of the index gates the text before the write, so
 *	a text that breaks the line format writes no file
 *	(VAULT-FORMAT-6). A session that holds no open index gives
 *	-1, and every other failure gives -1 as well.
 */
int	session_index_write(struct session *, const char *, size_t);

/*
 * session_slot_ready(s, slot):
 *	0 when this machine holds wraps of the slot index slot at k
 *	or more live oracles, and -1 for every other slot
 *	(ENTRY-POOL-3, KEY-MASK-4). A new entry takes a slot that
 *	this call accepts.
 */
int	session_slot_ready(const struct session *, uint32_t);

/*
 * session_reveal(s, slot, plain, plainlen):
 *	Reveal the entry file of the slot index slot, and give the
 *	plaintext of it to plain, of plainlen bytes (ORC-QUORUM-3,
 *	ORC-QUORUM-4).
 *
 *	The call sends one get_pin per quorum oracle, reconstructs
 *	the entry key from the k shares, and decrypts the file of
 *	that key (KEY-SHARE-6, VAULT-SEAL-4). A decrypt failure, an
 *	HTTP error, and a transport failure each substitute an
 *	oracle and try again, until no untried oracle remains
 *	(ORC-QUORUM-5). Each failed attempt names its quorum.
 *
 *	The entry key leaves memory directly after the decrypt
 *	(SEC-MEMORY-6). The plaintext belongs to the session, and the
 *	next reveal and session_close() clear it.
 */
int	session_reveal(struct session *, uint32_t, const char **, size_t *);

/*
 * session_consume(s, slot, plain, plainlen):
 *	The reveal of session_reveal(), and the entry key of the slot
 *	stays in the session for session_seal() (ENTRY-POOL-4). The
 *	call writes no file, so the records and the wraps of the slot
 *	stay as they are (ENTRY-POOL-5).
 *
 *	The caller verifies the two candidates of the slot file
 *	before it consumes the slot (ENTRY-POOL-9), and it writes the
 *	index before the entry file (ENTRY-POOL-8). session_drop()
 *	ends a consumption that writes no entry file.
 */
int	session_consume(struct session *, uint32_t, const char **, size_t *);

/*
 * session_file(s):
 *	The entry file name of the last reveal: the lowercase hex of
 *	H(K_e) of that slot (VAULT-LAYOUT-5). The caller writes the
 *	name in the entry line of the index (VAULT-INDEX-2). The call
 *	gives NULL before the first reveal of the session.
 */
const char *session_file(const struct session *);

/*
 * session_seal(s, plain, plainlen):
 *	Seal the plainlen bytes at plain under the entry key of the
 *	consumption, and write the entry file of that slot
 *	(VAULT-SEAL-1, VAULT-ATOMIC-1). The file takes the name of
 *	session_file() (VAULT-LAYOUT-5).
 *
 *	The call gives -1 without a consumption of session_consume().
 *	The entry key leaves memory after the write, on each exit
 *	path (SEC-MEMORY-6). The plaintext belongs to the caller, and
 *	the caller clears it.
 */
int	session_seal(struct session *, const char *, size_t);

/*
 * session_drop(s):
 *	Clear the entry key of a consumption, with no seal write
 *	(SEC-MEMORY-6). A consumption that stops before the entry
 *	file takes this call.
 */
void	session_drop(struct session *);

/*
 * session_canary(s, oracle):
 *	Re-enroll the canary record of the oracle index oracle, and
 *	hold this machine's index wrap of that oracle
 *	(ORC-CANARY-5, ORC-CANARY-8, ORC-CANARY-11).
 *
 *	The enrollment takes two reads of the passphrase, so the call
 *	reads it again and requires the value of the unlock
 *	(ORC-CANARY-6, SEC-MEMORY-2). The unlock verified that value
 *	at the canary record of each quorum oracle, so this step
 *	holds a verifier (ORC-CANARY-1).
 *
 *	The fresh canary mask kills this machine's index wrap of the
 *	oracle. A session that holds the index key re-wraps the index
 *	share at once, and a session without it deletes the wrap file
 *	and reports the dead state (ORC-CANARY-8).
 */
int	session_canary(struct session *, unsigned int);

#endif /* SESSION_H */
