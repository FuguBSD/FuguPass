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
 * The ceremonies of the core process. A ceremony is a procedure
 * with the master present, and the master reaches this file from a
 * plate scan alone (CER-CREATE-1, KEY-MASTER-3).
 *
 * ceremony_create() is vault creation, the first ceremony. It runs
 * the eight steps of CER-CREATE in rule order, and ceremony.c states
 * the step of each function.
 *
 * ceremony_refill() is the pool refill. It extends the free slots of
 * one vault on one machine (CER-REFILL). It runs the slot loop of
 * CER-CREATE-6 for each new slot, so the two ceremonies hold one
 * slot loop.
 *
 * ceremony_provision() is machine provisioning. It adds this machine
 * to an existing vault, from a copy of the shared set and a plate
 * scan (CER-PROVISION). It enrolls this machine's records for each
 * existing slot with the enrollment loop of the two other
 * ceremonies, and a re-run covers the pairs with no wrap alone
 * (CER-PROVISION-12).
 */

#ifndef CEREMONY_H
#define CEREMONY_H

/*
 * The slots of a new pool, and the low watermark of it. The pool
 * size is tunable, and CEREMONY_POOL_SIZE is the default of it
 * (ENTRY-POOL-2). CEREMONY_POOL_MAX is the bound of the tunable,
 * because the index text of a ceremony takes one row of each slot.
 */
#define CEREMONY_POOL_SIZE	64	/* ENTRY-POOL-2 */
#define CEREMONY_POOL_MAX	255	/* ENTRY-POOL-2 */
#define CEREMONY_POOL_WATERMARK	8	/* ENTRY-POOL-6 */

/*
 * The arguments of one vault creation. The command line of the
 * create subcommand carries each of them (PROG-ONESHOT-5,
 * PROG-ONESHOT-6).
 */
struct ceremony_create {
	const char		*vault;		/* the vault directory */
	const char		*machine;	/* KEY-DEVICE-3 */
	const char *const	*oracle;	/* one value per position */
	unsigned int		 count;		/* n, the value count */
	unsigned int		 threshold;	/* k */
	unsigned int		 rounds;	/* kdf-rounds, KEY-PIN-5 */
	unsigned int		 pool;		/* pool-size, ENTRY-POOL-2 */
	int			 full;		/* provision -a, CER-PROVISION-17 */
};

/*
 * ceremony_create(arg):
 *	The vault creation ceremony, in the vault directory of arg
 *	(CER-CREATE). The call gives 0 when each of the eight steps
 *	passes, and -1 when one step fails.
 *
 *	Each oracle value of arg holds one position of the ordered
 *	set: the static public key hex, one space, then the URL
 *	(ORC-PROVISION-1, PROG-ONESHOT-6). Position 1 comes first,
 *	and the position of a value is the oracle index of it
 *	(ORC-PROVISION-5).
 *
 *	The pool of arg holds the slots of the new pool, and it takes
 *	1 to CEREMONY_POOL_MAX (ENTRY-POOL-2). The caller gives
 *	CEREMONY_POOL_SIZE for the default.
 *
 *	The call reads the master from the scan helper, and it reads
 *	the passphrase twice from the terminal (CER-CREATE-1,
 *	CER-CREATE-4). It writes the report of a failed step to the
 *	standard error, and it names the oracle of a failed
 *	enrollment (CER-CREATE-6).
 *
 *	The call erases M, root, K_idx, every K_e, every share, and
 *	every mask before it exits, on every path (CER-CREATE-8,
 *	SEC-MEMORY-5).
 */
int	ceremony_create(const struct ceremony_create *);

/*
 * ceremony_refill(vault):
 *	The pool refill ceremony, in the vault directory vault
 *	(CER-REFILL). The call gives 0 for a complete refill, and -1
 *	for a failure of one step.
 *
 *	The call reads the config file of the vault, so it takes no
 *	oracle set and no tunable of a command line. The count of the
 *	new slots is the pool size of that file, and a file with no
 *	such line gives CEREMONY_POOL_SIZE (ENTRY-POOL-2).
 *
 *	The call reads the master from the scan helper, and it reads
 *	the passphrase once from the terminal (CER-REFILL-1,
 *	CER-REFILL-7). The canary record of each live oracle verifies
 *	that passphrase before the slot loop, and a failure of one
 *	canary sends no set_pin.
 *
 *	The new slots take the indexes after the pool-next line of
 *	the index, so the refill writes no file of an existing entry
 *	(CER-REFILL-2, CER-REFILL-4). The index takes the new pool
 *	state after the slot loop, and an interrupted refill leaves
 *	it as it was. A re-run is therefore safe.
 *
 *	While the change marker exists, the call refuses to start and
 *	it names the resume command (CER-REFILL-8).
 *
 *	The call erases M, root, K_idx, every new K_e, every share,
 *	and every mask before it exits, on every path (CER-REFILL-6,
 *	SEC-MEMORY-5).
 */
int	ceremony_refill(const char *);

/*
 * ceremony_provision(arg):
 *	The machine provisioning ceremony, in the vault directory of
 *	arg (CER-PROVISION). The call gives 0 when each step passes,
 *	and -1 when one step fails.
 *
 *	arg holds the command line form of a creation: the machine
 *	name, the ordered oracle set, the threshold and the round
 *	count (PROG-ONESHOT-6). The config file is machine-local, so
 *	the list comes from the command line, and every machine of a
 *	vault records the same list and the same threshold
 *	(VAULT-LAYOUT-4, ORC-PROVISION-8). The pool of arg is the
 *	pool size of the config file of this machine, and the
 *	ceremony makes no pool.
 *
 *	The shared set must stand in the vault directory before the
 *	call (CER-PROVISION-2). The call refuses a directory with no
 *	index, and it names the copy as the path.
 *
 *	The call reads the master from the scan helper, and it opens
 *	the index under K_idx of that plate (CER-PROVISION-1,
 *	VAULT-INDEX-4). It refuses a machine name that the registry
 *	marks retired, and it names a new machine name as the path.
 *	It takes an explicit confirmation from the terminal before it
 *	replaces the records of a registered name that this machine
 *	holds no config of (CER-PROVISION-3). It reads the passphrase
 *	twice from the terminal (CER-PROVISION-5).
 *
 *	A run on a provisioned machine is a re-run (CER-PROVISION-12).
 *	It takes the config of this machine as the gate of the
 *	command line. A command line that matches verifies the
 *	passphrase at each sealed canary before any set_pin, heals each
 *	dead index wrap, seals each stale canary check value again, and
 *	enrolls the pairs with no wrap of this machine alone.
 *
 *	A command line that changes the config is a variant. The
 *	ceremony writes the new config before any enrollment
 *	(CER-PROVISION-13). An added oracle takes the next free
 *	position, and the loop enrolls the new pairs (CER-PROVISION-14).
 *	A retirement or a replacement deletes this machine's files of
 *	that position first, and the report directs the owner to the
 *	revocation kit (CER-PROVISION-16, ORC-PROVISION-6, REC-WIPE-2).
 *	A threshold change re-splits every share and re-enrolls every
 *	record under a threshold marker, and it re-runs from the start
 *	(CER-PROVISION-15).
 *
 *	The -a run of full of arg re-enrolls every record of this
 *	machine under one passphrase, and it removes a passphrase marker
 *	at the end (CER-PROVISION-17, ORC-ENROLL-12).
 *
 *	While the change marker exists, the call refuses to start,
 *	unless it is the threshold re-run or the full run
 *	(CER-PROVISION-18). A refused call names the resume or the
 *	re-run.
 *
 *	The call erases M, root, K_idx, every K_e, every share, and
 *	every mask before it exits, on every path (CER-PROVISION-10,
 *	SEC-MEMORY-5).
 */
int	ceremony_provision(const struct ceremony_create *);

#endif /* CEREMONY_H */
