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
 * revoke.c holds the derivation. The lock and the replacement of
 * ORC-REVOKE join this file.
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

#endif /* REVOKE_H */
