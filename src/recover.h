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
 * The two recovery paths of the plate (REC-PLATE, REC-VAULT). A
 * recovery reads the plate and the shared set alone, and it touches
 * no oracle and no passphrase (REC-PRINCIPLE-4, D-04). recover.c
 * holds the derivation loop, and recover.h states the one entry
 * point of it.
 *
 * recover_run() scans the plate, and it then takes one of two paths
 * from the state of the vault directory. A directory with a shared
 * set takes the plate-plus-files path: the tool re-derives the entry
 * key of each slot, matches the entry file by the name H(K_e), and
 * opens the file under that key (REC-VAULT-1, REC-VAULT-2). It opens
 * the index under K_idx from root for the entry names, and a stale
 * or absent index degrades the names alone (REC-VAULT-3,
 * REC-RESTORE-5). A directory with no shared set takes the
 * plate-alone path: the tool re-derives the entry key of every slot
 * from 0 to the ceiling, and it re-materializes both BIP85
 * candidates of each slot (REC-PLATE-1). The default ceiling is
 * RECOVER_CEILING slots, and the caller raises it (REC-PLATE-2).
 *
 * A recovered secret prints to the terminal, one entry at a time,
 * and it reaches no file (PROG-OUTPUT-1, PROG-OUTPUT-4). The master
 * and root leave memory before the return (SEC-MEMORY-5).
 */

#ifndef RECOVER_H
#define RECOVER_H

/* The default scan ceiling of the plate-alone path (REC-PLATE-2). */
#define RECOVER_CEILING	1024

/*
 * recover_run(vault, ceiling):
 *	Recover the entries of the vault directory vault from the
 *	plate (REC-PLATE, REC-VAULT). The call scans the plate, and a
 *	vault directory with a shared set takes the plate-plus-files
 *	path, and a directory with none takes the plate-alone path.
 *	ceiling bounds the slot scan of each path, and it must be 1 or
 *	more (REC-PLATE-2).
 *
 *	The plate-plus-files path prints each recovered entry name on
 *	the standard output, and each secret on the terminal, in slot
 *	order (PROG-ONESHOT-3, PROG-OUTPUT-1). It skips a free pool
 *	slot file, and it names an entry by its file name when the
 *	index does not open (REC-RESTORE-5). The plate-alone path
 *	prints the two BIP85 candidates of each slot on the terminal,
 *	and it reports the scanned range on the standard output.
 *
 *	The call reads no passphrase, opens no session, and sends no
 *	request (REC-PRINCIPLE-4). It writes no file of the vault. The
 *	master and root leave memory before the return (SEC-MEMORY-5).
 *
 *	The call gives 0 when each scanned slot recovers, and -1 with
 *	a report on the standard error otherwise.
 */
int	recover_run(const char *, unsigned int);

#endif /* RECOVER_H */
