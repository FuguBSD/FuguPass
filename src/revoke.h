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
 * The revocation kit of one machine (ORC-REVOKE-6). The kit names
 * the machine, and, for each live oracle of the set, the record
 * file name of each record of that machine at that oracle. An
 * operator of an oracle deletes a record by that name
 * (ORC-REVOKE-5).
 *
 * The tool derives the kit at each call, and it prints the kit on
 * the standard output (PROG-ONESHOT-7). No file of the vault holds
 * a kit: a stored kit is a copy of derived data, and each refill
 * enrolls records that such a copy does not name (CER-REFILL).
 *
 * revoke_run() is the revocation from the plate (ORC-REVOKE-3,
 * ORC-REVOKE-4). It derives the client keys of a named machine
 * from the plate, and it sends one revocation request per record
 * of that machine at each chosen oracle: the lock, or the
 * replacement (ORC-REVOKE-8). A lock retires the machine name, and
 * the call marks the name in the registry of the index
 * (ORC-REVOKE-11, VAULT-INDEX-7). The report directs the owner to
 * the remaining records and to a passphrase change
 * (ORC-REVOKE-12).
 *
 * revoke.c holds the derivation and the request loop. oracle.c
 * holds the one request that sends the revocation counter, and
 * ceremony.c holds the index rewrite of the mark.
 */

#ifndef REVOKE_H
#define REVOKE_H

/*
 * revoke_kit(vault, machine):
 *	Print the revocation kit of one machine of the vault
 *	directory vault on the standard output (ORC-REVOKE-6,
 *	PROG-ONESHOT-7). The first line holds the word machine and
 *	the machine name. Each live oracle then takes one line of
 *	the word oracle, its index and its URL, and one line of the
 *	word record, the index and a record file name for each
 *	record of the machine at that oracle. The canary record
 *	comes last at each oracle.
 *
 *	A NULL machine takes this machine. The name and the oracle
 *	set come from the config file, the device factor from the
 *	factor file, and the record set from the wrap files of the
 *	machine-local set. One wrap file names one record of this
 *	machine, so every slot of every refill on this machine
 *	stands in the kit. The call reads no passphrase, opens no
 *	session, and sends no request (KEY-CLIENT-4).
 *
 *	A machine name takes the plate. A scan gives the master, the
 *	master gives the device factor of that name, and the client
 *	keys follow (KEY-DEVICE-4, ORC-REVOKE-4). The master gives
 *	K_idx as well, and the index of the vault opens under it
 *	(VAULT-INDEX-4). The record set is then each slot index
 *	below the next free slot index of the index, and the canary.
 *	Every refill of every machine raises that index, so no
 *	constant bounds the kit (CER-REFILL-2). A plate of another
 *	vault does not open the index, and the call fails. The call
 *	writes no file, and the factor of the named machine leaves
 *	memory before the return (KEY-DEVICE-2).
 *
 *	The call gives 0, and -1 with a report on the standard error.
 */
int	revoke_kit(const char *, const char *);

/*
 * revoke_run(vault, machine, replace, position, count):
 *	Revoke the records of the machine machine at the chosen
 *	oracles of the vault directory vault, from the plate
 *	(ORC-REVOKE-3, ORC-REVOKE-4). The plate gives the device
 *	factor of the name, and the index of the vault gives the
 *	slot set of the machine, as the kit of a named machine takes
 *	them (KEY-DEVICE-4, VAULT-INDEX-4). The records of the
 *	machine at one oracle are one record of each slot below the
 *	next free slot index, and the canary record.
 *
 *	position holds count 1-based positions of the config, and a
 *	count of 0 chooses every live position. The owner chooses
 *	each oracle (ORC-REVOKE-3). A named retired position stops
 *	the call before any request, and a retired position of the
 *	default set takes no request: it holds no URL, and the
 *	report says so (ORC-PROVISION-9).
 *
 *	A replace of 0 sends the lock: one wrong attempt per record
 *	at the revocation counter. The record then answers junk to
 *	every caller, and no later set_pin of it passes
 *	(ORC-REVOKE-8). A replace of 1 sends one set_pin replacement
 *	per record, under fresh key material. The call continues
 *	over every record and every chosen oracle after a failed
 *	request, and it counts the failures of each oracle.
 *
 *	A lock that landed at any oracle retires the name. The call
 *	then marks the name retired in the machine registry of the
 *	index, sealed under the index key of the plate
 *	(ORC-REVOKE-11, VAULT-INDEX-7). The replacement retires no
 *	name.
 *
 *	The report goes to the standard error. It names each oracle
 *	of a landed lock or replacement with its record count, each
 *	oracle of an incomplete one with the last state, and each
 *	live position and each retired position that got no complete
 *	lock. It directs the owner to lock or delete the remaining
 *	records there, and it names the kit subcommand for them. It
 *	states the count of locks that denies a quorum, and it
 *	directs the owner to a passphrase change on every other
 *	machine when the passphrase may be known (ORC-REVOKE-10,
 *	ORC-REVOKE-12).
 *
 *	The call writes no file but the index, and it writes no
 *	counters file: the counters of this machine never hold a
 *	record of another machine (ORC-COUNTER-2). The factor of the
 *	named machine, root and K_idx leave memory before the return
 *	(KEY-DEVICE-2, SEC-MEMORY-5).
 *
 *	The call gives 0 when every request of every chosen live
 *	position answered and the mark reached the disk. It gives -1
 *	with a report otherwise.
 */
int	revoke_run(const char *, const char *, int, const unsigned int *,
	    size_t);

#endif /* REVOKE_H */
