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
 * The passphrase change of the core process: the verification, the
 * re-enrollment loop, the change marker, and the resume.
 *
 * A passphrase change re-enrolls every record of this machine at
 * every live oracle, and it takes no master (ORC-ENROLL-4). Each
 * slot reconstructs its entry key through the quorum under the old
 * passphrase, and each record takes one set_pin under the new one.
 * A change of one machine leaves the records of every other machine
 * as they are (ORC-ENROLL-7).
 *
 * change_passphrase() starts a change, and change_resume() completes
 * an incomplete one. The two calls run one loop, and the marker
 * holds the two apart: a start writes a marker, and a resume reads
 * one (ORC-ENROLL-10).
 *
 * change_pending() gives the marker state of a vault. While the
 * marker exists, a session must refuse reveals and must name
 * CHANGE_RESUME_CMD (ORC-ENROLL-10). That refusal and the
 * subcommands of the tool are absent.
 *
 * The steps come from the other files of the tree. oracle.c holds
 * each record, each mask and each wrap, share.c holds the
 * reconstruction, seal.c holds the seal, vault.c holds every path,
 * the writer and the scanner, and fugupass.c reads each passphrase.
 * This file adds the order, the marker and the reports.
 *
 * Each call clears every secret of the change on each exit path
 * (SEC-MEMORY-1). The secrets are the two passphrases, the device
 * factor, the index key, and each entry key of the loop.
 */

#ifndef CHANGE_H
#define CHANGE_H

/*
 * The command that completes an incomplete change. A session names
 * it while the marker exists (ORC-ENROLL-10).
 */
#define CHANGE_RESUME_CMD	"fugupass resume"

/*
 * change_pending(vault):
 *	1 when the vault directory vault holds a change marker, and 0
 *	when it holds none (ORC-ENROLL-10). A failure of the lookup
 *	gives -1, with a report of the cause.
 *
 *	The caller refuses a reveal at 1 and at -1, because neither
 *	state proves a complete change.
 */
int	change_pending(const char *);

/*
 * change_passphrase(vault):
 *	The passphrase change of the vault directory vault
 *	(ORC-ENROLL-4). The call gives 0 for a complete change, and
 *	-1 for an incomplete one.
 *
 *	The call reads the old passphrase twice and the new
 *	passphrase twice, and each pair must match (ORC-ENROLL-8). It
 *	verifies the old passphrase at the canary record of each live
 *	oracle, and it re-enrolls a canary that fails for a
 *	record-side cause (ORC-CANARY-4, ORC-CANARY-5). A mistyped
 *	old passphrase stops the change at the first canary, before
 *	any set_pin.
 *
 *	The loop takes each slot in turn, and each live oracle of a
 *	slot in list order (ORC-ENROLL-5). Before the first set_pin
 *	of a slot, the call reconstructs the entry key through the
 *	quorum and decrypts the file of that slot (ORC-ENROLL-9). A
 *	decrypt failure with no untried reachable oracle stops the
 *	change before any set_pin of that slot, and the report names
 *	the slot and each quorum. The canary records come last, one
 *	per oracle (ORC-ENROLL-10).
 *
 *	The marker reaches the disk before the first set_pin, and one
 *	done line follows the persisted writes of each record
 *	(ORC-ENROLL-10). The last re-enrollment removes the marker. A
 *	vault that already holds a marker gives -1, and the report
 *	names CHANGE_RESUME_CMD.
 *
 *	A live oracle that no request reaches leaves the change
 *	incomplete, and the marker stays (ORC-ENROLL-11).
 */
int	change_passphrase(const char *);

/*
 * change_resume(vault):
 *	The rest of an incomplete passphrase change of the vault
 *	directory vault (ORC-ENROLL-10). The call gives 0 for a
 *	complete change, and -1 for an incomplete one. A vault that
 *	holds no marker gives -1.
 *
 *	The marker splits the records of this machine. The call takes
 *	the new pin for every record of the marker list, and the old
 *	pin for every other record. It verifies the new passphrase at
 *	each canary of that list, and the old passphrase at every
 *	other canary. The change then resumes at the first unmigrated
 *	record.
 *
 *	The call reads both passphrases again, and every other rule
 *	of change_passphrase() holds.
 */
int	change_resume(const char *);

#endif /* CHANGE_H */
