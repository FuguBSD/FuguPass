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
 * the nine steps of CER-CREATE in rule order, and ceremony.c states
 * the step of each function.
 */

#ifndef CEREMONY_H
#define CEREMONY_H

/* The slots of a new pool, and the low watermark of it. */
#define CEREMONY_POOL_SIZE	64	/* ENTRY-POOL-2 */
#define CEREMONY_POOL_WATERMARK	8	/* ENTRY-POOL-6 */

/* The leaf name of the revocation kit, in the machine-local set. */
#define CEREMONY_KIT_FILE	"revocation-kit"

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
};

/*
 * ceremony_create(arg):
 *	The vault creation ceremony, in the vault directory of arg
 *	(CER-CREATE). The call gives 0 when each of the nine steps
 *	passes, and -1 when one step fails.
 *
 *	Each oracle value of arg holds one position of the ordered
 *	set: the static public key hex, one space, then the URL
 *	(ORC-PROVISION-1, PROG-ONESHOT-6). Position 1 comes first,
 *	and the position of a value is the oracle index of it
 *	(ORC-PROVISION-5).
 *
 *	The call reads the master from the scan helper, and it reads
 *	the passphrase twice from the terminal (CER-CREATE-1,
 *	CER-CREATE-4). It writes the report of a failed step to the
 *	standard error, and it names the oracle of a failed
 *	enrollment (CER-CREATE-6).
 *
 *	The call erases M, root, K_idx, every K_e, every share, and
 *	every mask before it exits, on every path (CER-CREATE-8,
 *	SEC-MEMORY-5). The kit holds no secret, so the export of it
 *	follows that erasure (CER-CREATE-9).
 */
int	ceremony_create(const struct ceremony_create *);

#endif /* CEREMONY_H */
