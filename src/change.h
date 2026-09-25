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
 * CHANGE_RESUME_CMD (ORC-ENROLL-10). session.c holds that refusal,
 * and fugupass.c holds the passwd and the resume subcommands.
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
 * The two kinds of the change marker (VAULT-FORMAT). A passphrase
 * change writes the first one, and a threshold change of the
 * provisioning ceremony writes the second (ORC-ENROLL-10,
 * CER-PROVISION-15, CER-PROVISION-18).
 */
#define CHANGE_KIND_PASSPHRASE	"passphrase"
#define CHANGE_KIND_THRESHOLD	"threshold"

/*
 * The command that completes an incomplete change. A refusal names
 * the resume of a passphrase change, or the re-run of a threshold
 * change (ORC-ENROLL-10, CER-PROVISION-18).
 */
#define CHANGE_RESUME_CMD	"fugupass resume"
#define CHANGE_RERUN_CMD	"fugupass provision"

/*
 * The classification of change_kind(). A negative value is a read
 * failure or a marker with no kind that a command reads.
 */
#define CHANGE_NONE		0	/* no marker */
#define CHANGE_PASSPHRASE	1	/* an incomplete passphrase change */
#define CHANGE_THRESHOLD	2	/* an incomplete threshold change */

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
 * change_kind(vault):
 *	The kind of the change marker of the vault directory vault:
 *	CHANGE_NONE, CHANGE_PASSPHRASE, or CHANGE_THRESHOLD
 *	(ORC-ENROLL-10, CER-PROVISION-15). A read failure and a
 *	marker with an unknown kind each give -1.
 *
 *	The call reads the first line of the marker file, so it takes
 *	no allocation for a long marker.
 */
int	change_kind(const char *);

/*
 * change_refuse(vault):
 *	1 when the vault directory vault holds a change marker, with a
 *	report to the standard error that names the kind and the
 *	command that completes it (ORC-ENROLL-10, CER-PROVISION-18). 0
 *	when it holds none. A read failure and an unknown kind each
 *	give -1, with a report. A ceremony or a session that must not
 *	run under a marker takes this call.
 */
int	change_refuse(const char *);

/*
 * change_marker_write(vault, kind):
 *	Write the change marker of the vault directory vault, with the
 *	kind line kind and no done line (VAULT-LAYOUT-4,
 *	VAULT-ATOMIC-1). A threshold change of the provisioning
 *	ceremony writes the marker with this call before the first
 *	set_pin (CER-PROVISION-15). The call gives 0, and -1 on a
 *	failure.
 */
int	change_marker_write(const char *, const char *);

/*
 * change_marker_remove(vault):
 *	Remove the change marker of the vault directory vault
 *	(ORC-ENROLL-12, CER-PROVISION-15, CER-PROVISION-17). A full
 *	re-enrollment run and a threshold change each take this call
 *	after the last wrap. An absent marker gives 0. The call gives
 *	-1 on a failure.
 */
int	change_marker_remove(const char *);

/*
 * change_passphrase(vault):
 *	The passphrase change of the vault directory vault
 *	(ORC-ENROLL-4). The call gives 0 for a complete change, and
 *	-1 for an incomplete one.
 *
 *	The call reads the old passphrase twice and the new
 *	passphrase twice, and each pair must match (ORC-ENROLL-8).
 *	The two reads of the old passphrase are the reads of a canary
 *	enrollment under it (ORC-CANARY-6). The call verifies the old
 *	passphrase at the canary record of each live oracle, and it
 *	re-enrolls a canary that fails for a record-side cause
 *	(ORC-CANARY-4, ORC-CANARY-5). A mistyped old passphrase stops
 *	the change at the first canary of that passphrase, before any
 *	set_pin.
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
 *	incomplete, and the marker stays (ORC-ENROLL-11). A call that
 *	starts with fewer than k reachable oracles stops before the
 *	marker write, and before the first re-enrollment. It
 *	therefore sends no set_pin, and it writes no marker.
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
