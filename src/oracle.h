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
 * The record client. Each entry holds one record at each oracle, on
 * each machine, and each machine holds one canary record at each
 * oracle (ORC-RECORDS-1, ORC-RECORDS-2). To the oracle, every
 * record is an independent client. Each record takes its own client
 * key, and each record burns its own strikes (ORC-RECORDS-3).
 *
 * One record takes one request. An enrollment is one set_pin, and a
 * reveal is one get_pin (ORC-CONFORM-2, ORC-ENROLL-1, ORC-REVEAL-1).
 * A caller that enrolls a slot at each live oracle calls
 * oracle_enroll() once per oracle, and this file holds no loop over
 * the oracle set.
 *
 * The context names one live position of the config file, and every
 * call reads the two provisioned values of that position
 * (ORC-PROVISION-1). The oracle index is the 1-based position of the
 * ordered list, and it enters each label and each share point
 * (ORC-PROVISION-5). A retired position holds no oracle, and every
 * call of this file rejects one (ORC-PROVISION-9).
 *
 * The four states of one request are four values, and the caller
 * must hold the four apart (ORC-REVEAL-6, ORC-REVEAL-8):
 *
 *	ORACLE_ESTATUS		The oracle answered a status other than
 *				200. The request is no attempt, and the
 *				caller can send it again.
 *	ORACLE_ETRANSPORT	The transport failed, and no answer
 *				reached this file. The state is
 *				ambiguous: the oracle can hold a
 *				counted attempt.
 *	ORACLE_EAUTH		A 200 answer failed the envelope MAC or
 *				the decrypt. The tool must report a
 *				provisioning fault or a transport fault.
 *	ORACLE_EJUNK		The answer is junk, and this file saw
 *				the cause. The canary round trip is the
 *				one call that sees it.
 *
 * A reveal cannot see a junk answer, because junk carries the bytes
 * of a mask (ORC-REVEAL-4). oracle_reveal() therefore gives 0 with a
 * candidate share, and the decrypt of the caller decides
 * (VAULT-SEAL-4). A -1 is a local failure: a bad argument, a
 * derivation, or a file. A local failure after the request leaves
 * the record enrolled at the oracle. The status number of an HTTP
 * error stays in http.c, and the state is the report.
 *
 * Every request takes the next counter of its record, and it
 * persists that counter in the counters file before the send
 * (ORC-COUNTER-1, ORC-COUNTER-2). The counters file is
 * machine-local, and it holds no secret (ORC-COUNTER-3). A caller
 * therefore needs the machine-local directory of the vault for each
 * call of this file.
 *
 * The passphrase enters a request as the pin secret alone
 * (ORC-CONFORM-3, KEY-PIN-3). The client key of a record takes the
 * device factor, and no passphrase (ORC-CONFORM-2, KEY-CLIENT-4).
 *
 * This file reconstructs no entry key, and it opens no entry:
 * ORC-QUORUM holds that work. It creates no vault, and it drives no
 * terminal. The caller reads each passphrase, and it writes each
 * report. The session canary check of ORC-CANARY-1 is absent as
 * well, and the dead index wrap of a canary re-enrollment stays for
 * the caller (ORC-CANARY-8).
 *
 * Each function clears every secret of the call on each exit path
 * (SEC-MEMORY-1). The caller clears the buffers that it owns, and it
 * erases K_e directly after the last use of it (SEC-MEMORY-6).
 */

#ifndef ORACLE_H
#define ORACLE_H

#include <stddef.h>
#include <stdint.h>

#include "envelope.h"
#include "http.h"
#include "vault.h"

/*
 * The bytes of the canary check value: 32 zero bytes
 * (ORC-CANARY-2).
 */
#define ORACLE_CHECKLEN		32

/*
 * The four states of one request. Two of them carry the value of
 * the layer that saw the state, so one value names one state across
 * this tree.
 */
#define ORACLE_EAUTH		ENVELOPE_EAUTH
#define ORACLE_ESTATUS		HTTP_ESTATUS
#define ORACLE_ETRANSPORT	(-4)
#define ORACLE_EJUNK		(-5)

/*
 * The context of one record client. It names the vault directory,
 * the config of the vault, the machine, the passphrase, and one
 * position of the oracle list.
 *
 * config holds the two provisioned values of each position, the
 * threshold k, and the round count (ORC-PROVISION-1,
 * ORC-PROVISION-2, KEY-PIN-5). vault_config_read() gives it, and it
 * holds the position rule of the file (VAULT-CONFIG-6).
 *
 * factor is the device factor X of this machine, of DERIVE_KEYLEN
 * bytes (KEY-DEVICE-1). pass is the typed passphrase (KEY-PIN-1).
 * Both are secrets, and the caller clears them.
 *
 * oracle is the 1-based position of this oracle in the list
 * (ORC-PROVISION-5). The context lives for one oracle, and a caller
 * that reaches a second oracle takes a second context.
 */
struct oracle_ctx {
	const char			*vault;		/* the directory */
	const struct vault_config	*config;
	const unsigned char		*factor;	/* X */
	size_t				 factorlen;
	const char			*pass;
	size_t				 passlen;
	unsigned int			 oracle;	/* the index i */
};

/*
 * oracle_enroll(ctx, slot, key, keylen):
 *	Enroll the record of the slot index slot at the oracle of
 *	ctx, and persist the wrap of it (ORC-ENROLL-1, ORC-ENROLL-3).
 *	key is the entry key K_e of that slot, of keylen bytes, and
 *	keylen must be DERIVE_KEYLEN.
 *
 *	The request is one set_pin under ck_ei, with pin_ei as the
 *	pin secret, and with 32 fresh bytes of arc4random(3)
 *	(ORC-CONFORM-5, SEC-ENTROPY-4). Every failure of a set_pin
 *	carries an HTTP error status, so a state other than 0 stops
 *	the call before the wrap (ORC-ENROLL-2).
 *
 *	The answer is the mask s_ei. The call re-derives share(K_e,
 *	i) at the threshold of the config, computes
 *	c_ei = share(K_e, i) XOR f(s_ei, "fugupass/v1/wrap" || i/e),
 *	and writes c_ei to machine/wrap.<e>.<i> (KEY-MASK-3,
 *	KEY-MASK-4, KEY-SHARE-5, VAULT-ATOMIC-1). It then erases the
 *	mask and the share (ORC-ENROLL-3).
 *
 *	A passphrase change re-enrolls each record of the machine
 *	(ORC-ENROLL-4 to ORC-ENROLL-12), and that loop is absent.
 */
int	oracle_enroll(const struct oracle_ctx *, uint32_t,
	    const unsigned char *, size_t);

/*
 * oracle_reveal(ctx, slot, out, outlen, maskout):
 *	Reveal the record of the slot index slot at the oracle of
 *	ctx, and give the share of that oracle to the outlen bytes at
 *	out. outlen must be DERIVE_KEYLEN.
 *
 *	The request is one get_pin under ck_ei, with pin_ei as the
 *	pin secret (ORC-REVEAL-1). The call unmasks the share as
 *	share(K_e, i) = c_ei XOR f(s_ei, "fugupass/v1/wrap" || i/e),
 *	from the wrap file of the record (ORC-REVEAL-3, KEY-MASK-3).
 *
 *	maskout takes the answer plaintext s_ei, of ENVELOPE_MASKLEN
 *	bytes, and a caller of the tool gives NULL. The call erases
 *	the mask at a NULL maskout, as it erases every other secret
 *	of the call.
 *
 *	The mask-stability test is the one caller that gives a
 *	buffer (ORC-REVEAL-2, TEST-MASK-1). The test compares the
 *	mask of two reveals, and a re-enrollment changes that value.
 *	The share of two reveals stays the same, because
 *	share(K_e, i) takes no mask (KEY-SHARE-5). The test clears
 *	the buffer that it gives (SEC-MEMORY-1).
 *
 *	The share is a candidate: a wrong passphrase, a wiped record,
 *	and a counter violation each give junk of the same shape
 *	(ORC-REVEAL-4). The caller reconstructs K_e from k shares and
 *	decrypts the entry, and that decrypt is the one junk detector
 *	(ORC-QUORUM-4, VAULT-SEAL-4).
 *
 *	The share must not persist on disk, and the caller clears out
 *	(KEY-SHARE-8).
 */
int	oracle_reveal(const struct oracle_ctx *, uint32_t, unsigned char *,
	    size_t, unsigned char *);

/*
 * oracle_canary_enroll(ctx, again, againlen):
 *	Enroll the canary record of the oracle of ctx, prove it, and
 *	persist the canary check seal of it (ORC-CANARY-11).
 *
 *	A canary enrollment takes two reads of the passphrase, and it
 *	stops at a mismatch (ORC-CANARY-6). pass of ctx is the first
 *	read, and the againlen bytes at again are the second one. The
 *	caller reads both with readpassphrase(3), and it warns that
 *	no verifier exists at this step.
 *
 *	The call sends one set_pin, and then one immediate get_pin
 *	(ORC-CANARY-7). An answer other than the enrolled mask gives
 *	ORACLE_EJUNK, and the call persists nothing. The call then
 *	seals the canary check value of 32 zero bytes under
 *	f(s_canary_i, "fugupass/v1/canary-check" || i), and it writes
 *	the seal to machine/canary.<i> (ORC-CANARY-2, KEY-MASK-5,
 *	VAULT-ATOMIC-1).
 *
 *	A canary record guards nothing that derives from the master,
 *	so a caller can re-enroll one at any time (ORC-CANARY-5). A
 *	re-enrollment replaces the canary mask of the oracle, and it
 *	therefore kills this machine's index wrap of that oracle. The
 *	caller holds that rule (ORC-CANARY-8).
 */
int	oracle_canary_enroll(const struct oracle_ctx *, const char *, size_t);

/*
 * oracle_canary_index(ctx, again, againlen, idxkey, idxkeylen):
 *	The canary enrollment of oracle_canary_enroll(), and this
 *	machine's index wrap of the oracle of ctx. idxkey holds the
 *	index key K_idx, of DERIVE_KEYLEN bytes.
 *
 *	The canary mask of the enrollment wraps the index share, so
 *	the call sends no request beyond the two of the canary
 *	(ORC-CANARY-3). The wrap is
 *	c_idx_i = share(K_idx, i) XOR
 *	f(s_canary_i, "fugupass/v1/wrap-index" || i), and the call
 *	writes it to machine/wrap.index.<i> (KEY-MASK-7,
 *	VAULT-ATOMIC-1).
 *
 *	A ceremony that holds K_idx takes this call, and every other
 *	caller takes oracle_canary_enroll() (CER-CREATE-5,
 *	ORC-ENROLL-6). The caller erases K_idx after its last use
 *	(SEC-MEMORY-5).
 */
int	oracle_canary_index(const struct oracle_ctx *, const char *, size_t,
	    const unsigned char *, size_t);

#endif /* ORACLE_H */
