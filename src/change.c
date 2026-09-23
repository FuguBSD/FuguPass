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
 * The passphrase change. change.h states the interface.
 *
 * run() holds the order of the change: the config, the device
 * factor, the records of this machine, the marker, the two
 * passphrases, the verification, the slot loop, the canary loop, and
 * the removal of the marker (ORC-ENROLL-5, ORC-ENROLL-8,
 * ORC-ENROLL-10).
 *
 * verify() runs the verification of ORC-ENROLL-8. It checks one
 * canary per live oracle, in list order. A failure at the first
 * canary holds the typo case, and it stops the change before any
 * set_pin (ORC-CANARY-4). A failure after a pass at another oracle
 * excludes the typo, so that canary takes a re-enrollment
 * (ORC-CANARY-5). The same checks carry this machine's index shares,
 * so the index key reaches the state with no request of its own
 * (ORC-CANARY-3, VAULT-INDEX-3).
 *
 * slots_read() gives the records of this machine. One wrap file
 * names one record, and the slots of those files are the slots of
 * this machine (KEY-MASK-4, VAULT-LAYOUT). vault_path() writes each
 * one of those names, so this file reads a name back through that
 * same call, and it holds no name of the layout.
 *
 * reconstruct() holds the gate of ORC-ENROLL-9. It reveals one share
 * per quorum oracle, reconstructs the entry key, and decrypts the
 * file of the slot. A decrypt failure substitutes the next untried
 * reachable oracle, and the substitutions end when no oracle remains
 * (ORC-QUORUM-5). Each record of one slot takes one request at the
 * most, so the reconstruction burns one strike per record at the
 * most (ORC-QUORUM-8, ORC-REVEAL-5). verify() checked the canary of
 * each reachable oracle, so a substitute needs no canary check of
 * its own.
 *
 * The marker records the progress (ORC-ENROLL-10). marker_start()
 * writes it before the first set_pin of the change, and
 * marker_done() appends one done line after the persisted writes of
 * one record. The file is plaintext in the line format
 * (VAULT-FORMAT-1), and each write of it is atomic
 * (VAULT-ATOMIC-1). A failure of the change leaves the marker, and
 * change_resume() reads it.
 *
 * The secrets of the change live in one struct state. The allocation
 * of it never moves, so one explicit_bzero(3) of it clears each one
 * (SEC-MEMORY-1). Each entry key lives in the slot that holds it,
 * and that slot clears it on each exit path (SEC-MEMORY-6). Every
 * share and every mask lives in oracle.c, and that file clears each
 * one (ORC-ENROLL-3).
 *
 * Every report goes to the standard error (PROG-ONESHOT-3).
 */

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "change.h"
#include "derive.h"
#include "fugupass.h"
#include "oracle.h"
#include "seal.h"
#include "session.h"
#include "share.h"
#include "vault.h"

/* The kind of the marker of a passphrase change (VAULT-FORMAT). */
#define MARKER_KIND	"passphrase"

/* The first line of the marker file (VAULT-FORMAT-1). */
#define MARKER_HEAD	"kind: " MARKER_KIND "\n"

/*
 * The bytes of one done line: the field name, the colon, the space,
 * the record name and the line feed. A record name takes a slot
 * index of 10 digits, one hyphen, and an oracle index of 3 digits at
 * the most (ORC-COUNTER-2, VAULT-FORMAT-7).
 */
#define DONE_MAX	(sizeof("done: ") + 10 + 1 + 3 + 1)

/*
 * The bytes of the longest file that this file reads, and one more.
 * A count of this value names a file that is too long (vault.h). The
 * index is the longest one, and session.h states the two plaintext
 * bounds of the vault.
 */
#define RAW_MAX		(SESSION_INDEX_MAX + SEAL_OVERHEAD + 1)

/* The slots of the first allocation of the slot list. */
#define SLOT_MIN	64

/* The records of the first allocation of the marker list. */
#define DONE_MIN	64

/* The file of the slot does not open (VAULT-SEAL-4). */
#define EDECRYPT	(-2)

/* The state of one oracle in this change, for the reports. */
#define STATE_PASS	0	/* the canary check of it passes */
#define STATE_UNTRIED	1	/* the change sent no request to it */

/*
 * One record of this machine: one slot at one oracle, or the canary
 * of one oracle (ORC-RECORDS-1, ORC-RECORDS-2). The marker names a
 * record by this pair (ORC-ENROLL-10).
 */
struct record {
	uint32_t	 slot;
	unsigned int	 oracle;
	int		 canary;
};

/*
 * The state of one change. The two passphrases, the device factor
 * and the index key are the secrets of it, and they leave memory in
 * state_free() (SEC-MEMORY-1, SEC-MEMORY-5).
 *
 * slot holds the slots of this machine, in ascending order, and each
 * one once. done holds the records of the marker list, and marker
 * holds the text of that file.
 *
 * reach holds the reachable oracles in list order, and the first k
 * of them are the quorum of a reconstruction (ORC-QUORUM-2).
 * state[i] is the last state of oracle i, for the reports. passed
 * counts the canary checks that passed, and first is the oracle of
 * the first one, because a canary failure after a pass excludes the
 * typo (ORC-CANARY-4).
 *
 * opened states that idxkey holds K_idx of this vault, and the index
 * read of verify() proves it (ORC-ENROLL-6).
 */
struct state {
	struct vault_config	 config;
	char			 vault[PATH_MAX];
	unsigned char		 factor[DERIVE_KEYLEN];	/* X */
	char			 oldpass[FUGUPASS_PASS_MAX];
	size_t			 oldlen;
	char			 newpass[FUGUPASS_PASS_MAX];
	size_t			 newlen;
	unsigned char		 idxkey[DERIVE_KEYLEN];	/* K_idx */
	int			 opened;
	uint32_t		*slot;
	size_t			 slotlen;
	size_t			 slotmax;
	struct record		*done;
	size_t			 donelen;
	size_t			 donemax;
	char			*marker;
	size_t			 markerlen;
	size_t			 markermax;
	unsigned int		 reach[DERIVE_ORACLE_MAX];
	unsigned int		 reachlen;
	unsigned int		 passed;
	unsigned int		 first;
	int			 state[DERIVE_ORACLE_MAX + 1];
	unsigned char		*raw;	/* one sealed file */
	unsigned char		*plain;	/* the plaintext of it */
};

/* The argument of the scanner of the marker file. */
struct parse {
	struct state	*st;
	int		 kind;	/* the file holds the kind line */
};

static const char	*state_text(int);
static void		 ctx_of(struct oracle_ctx *, const struct state *,
			     unsigned int, int);
static struct state	*state_new(const char *);
static void		 state_free(struct state *);
static int		 config_read(struct state *);
static int		 factor_read(struct state *);
static int		 slot_cmp(const void *, const void *);
static int		 slot_add(struct state *, uint32_t);
static int		 slots_read(struct state *);
static int		 done_add(struct state *, uint32_t, unsigned int, int);
static int		 migrated(const struct state *, uint32_t, unsigned int,
			     int);
static int		 record_name(uint32_t, unsigned int, int, char *,
			     size_t);
static int		 marker_alloc(struct state *);
static int		 marker_write(const struct state *);
static int		 marker_start(struct state *);
static int		 marker_line(const struct vault_line *, void *);
static int		 marker_read(struct state *);
static int		 marker_done(struct state *, uint32_t, unsigned int,
			     int);
static int		 marker_remove(const struct state *);
static int		 read_twice(const char *, const char *, char *, size_t);
static int		 pass_read(struct state *);
static void		 canary_report(const struct state *, unsigned int);
static int		 canary_take(struct state *, unsigned int,
			     unsigned char *, int *);
static int		 canary_repair(struct state *, unsigned int);
static int		 index_open(struct state *);
static void		 reach_report(const struct state *);
static int		 verify(struct state *);
static int		 slot_open(struct state *, const unsigned char *);
static void		 quorum_name(const struct state *, const unsigned int *,
			     unsigned int);
static int		 reconstruct(struct state *, uint32_t, unsigned char *);
static int		 slot_done(const struct state *, uint32_t);
static int		 slot_change(struct state *, uint32_t);
static int		 canaries(struct state *);
static int		 run(struct state *, int);

/*
 * state_text(state):
 *	The text of one state of one oracle of this change. The states
 *	of a request come from oracle.h, and the two states of this
 *	file cover an oracle that answered a canary check and an
 *	oracle that took no request.
 */
static const char *
state_text(int state)
{
	if (state == STATE_UNTRIED)
		return "the change sent no request";
	if (state == STATE_PASS)
		return "the canary check passes";
	return oracle_state_text(state);
}

/*
 * ctx_of(ctx, st, oracle, fresh):
 *	The record context of the oracle index oracle, from the state
 *	st. fresh takes the new passphrase, and 0 takes the old one
 *	(ORC-ENROLL-10). oracle.c gates each field of the context.
 */
static void
ctx_of(struct oracle_ctx *ctx, const struct state *st, unsigned int oracle,
    int fresh)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->vault = st->vault;
	ctx->config = &st->config;
	ctx->factor = st->factor;
	ctx->factorlen = sizeof(st->factor);
	ctx->pass = fresh ? st->newpass : st->oldpass;
	ctx->passlen = fresh ? st->newlen : st->oldlen;
	ctx->oracle = oracle;
}

/*
 * state_new(vault):
 *	The state of one change of the vault directory vault, or NULL
 *	for a failure. The config of the state takes about 100
 *	kilobytes, so the state sits on the heap (vault.h).
 */
static struct state *
state_new(const char *vault)
{
	struct state	*st;
	int		 n;

	if ((st = calloc(1, sizeof(*st))) == NULL) {
		warn("the change");
		return NULL;
	}
	n = snprintf(st->vault, sizeof(st->vault), "%s", vault);
	if (n < 0 || (size_t)n >= sizeof(st->vault)) {
		warnx("%s: the path of the vault does not fit", vault);
		state_free(st);
		return NULL;
	}

	/* The two buffers hold one sealed file and the plaintext. */
	st->raw = malloc(RAW_MAX);
	st->plain = malloc(SESSION_INDEX_MAX);
	if (st->raw == NULL || st->plain == NULL) {
		warn("the change");
		state_free(st);
		return NULL;
	}
	return st;
}

/*
 * state_free(st):
 *	End the state st, and clear every secret of it with
 *	explicit_bzero(3) (SEC-MEMORY-1). The two buffers hold vault
 *	data, and the struct holds the two passphrases, the device
 *	factor and the index key. The marker holds no secret, and the
 *	slot list holds none.
 */
static void
state_free(struct state *st)
{
	if (st == NULL)
		return;
	if (st->raw != NULL) {
		explicit_bzero(st->raw, RAW_MAX);
		free(st->raw);
	}
	if (st->plain != NULL) {
		explicit_bzero(st->plain, SESSION_INDEX_MAX);
		free(st->plain);
	}
	free(st->marker);
	free(st->slot);
	free(st->done);
	explicit_bzero(st, sizeof(*st));
	free(st);
}

/*
 * config_read(st):
 *	The config file of the vault, to the state (VAULT-CONFIG-1,
 *	VAULT-CONFIG-2). The reader holds the position rule of the
 *	file, so this step adds no gate (VAULT-CONFIG-6).
 */
static int
config_read(struct state *st)
{
	char	 path[PATH_MAX];
	size_t	 len = 0;

	if (vault_path(path, sizeof(path), st->vault, VAULT_FILE_CONFIG,
	    NULL) != 0)
		return -1;
	if (vault_read(path, st->raw, RAW_MAX, &len) != 0) {
		warn("%s", path);
		return -1;
	}
	if (len == 0 || len == RAW_MAX) {
		warnx("%s: the config file is absent or too long", path);
		return -1;
	}
	if (vault_config_read((const char *)st->raw, len, &st->config) != 0) {
		warnx("%s: an oracle position or the threshold is wrong", path);
		return -1;
	}
	return 0;
}

/*
 * factor_read(st):
 *	The device factor X of this machine, to the state
 *	(KEY-DEVICE-1, KEY-DEVICE-2). The factor is a secret, and it
 *	leaves memory in state_free().
 */
static int
factor_read(struct state *st)
{
	char	 path[PATH_MAX];
	size_t	 len = 0;

	if (vault_path(path, sizeof(path), st->vault, VAULT_FILE_FACTOR,
	    NULL) != 0)
		return -1;
	if (vault_read(path, st->raw, DERIVE_KEYLEN + 1, &len) != 0) {
		warn("%s", path);
		return -1;
	}
	if (len != DERIVE_KEYLEN) {
		warnx("%s: the device factor of this machine is absent", path);
		return -1;
	}
	memcpy(st->factor, st->raw, sizeof(st->factor));
	explicit_bzero(st->raw, DERIVE_KEYLEN);
	return 0;
}

/*
 * slot_cmp(a, b):
 *	The order of two slot indexes, for qsort(3). The slot list
 *	comes in ascending order, so a resume takes the slots of this
 *	machine in the order of the first run.
 */
static int
slot_cmp(const void *a, const void *b)
{
	uint32_t	 x = *(const uint32_t *)a;
	uint32_t	 y = *(const uint32_t *)b;

	if (x < y)
		return -1;
	return x > y;
}

/*
 * slot_add(st, slot):
 *	Add the slot index slot to the slot list of the state. The
 *	list grows by a doubling, and a failure of it gives -1.
 */
static int
slot_add(struct state *st, uint32_t slot)
{
	uint32_t	*at;
	size_t		 max;

	if (st->slotlen == st->slotmax) {
		max = st->slotmax == 0 ? SLOT_MIN : 2 * st->slotmax;
		if ((at = reallocarray(st->slot, max, sizeof(*at))) == NULL) {
			warn("the slots of this machine");
			return -1;
		}
		st->slot = at;
		st->slotmax = max;
	}
	st->slot[st->slotlen++] = slot;
	return 0;
}

/*
 * slots_read(st):
 *	The slots of this machine, to the state (ORC-ENROLL-4). One
 *	wrap file names one record of one slot at one oracle
 *	(KEY-MASK-4, VAULT-LAYOUT).
 *
 *	The walk reads the machine-local directory. It takes the two
 *	indexes of a name, and it asks vault_path() for the path of
 *	that pair. A path that differs from the name names another
 *	file, and the walk steps over it. The layout therefore stays
 *	in vault.c, and this file holds no name of it.
 *
 *	The list comes in ascending order, and it holds each slot
 *	once. A lost wrap file of one record leaves the slot in the
 *	list, because the other records of that slot name it.
 */
static int
slots_read(struct state *st)
{
	struct vault_at	 at;
	char		 dir[PATH_MAX];
	char		 name[PATH_MAX];
	char		 path[PATH_MAX];
	struct dirent	*ent;
	const char	*head, *tail;
	DIR		*dp;
	uint32_t	 slot, oracle;
	size_t		 i, keep;
	int		 n, rv = -1;

	n = snprintf(dir, sizeof(dir), "%s/%s", st->vault, VAULT_MACHINE_DIR);
	if (n < 0 || (size_t)n >= sizeof(dir)) {
		warnx("%s: the path of the machine directory does not fit",
		    st->vault);
		return -1;
	}
	if ((dp = opendir(dir)) == NULL) {
		warn("%s", dir);
		return -1;
	}

	while ((ent = readdir(dp)) != NULL) {
		if ((head = strchr(ent->d_name, '.')) == NULL ||
		    (tail = strchr(&head[1], '.')) == NULL)
			continue;
		if (vault_number(&head[1], (size_t)(tail - head) - 1,
		    VAULT_SLOT_MAX, &slot) != 0)
			continue;
		if (vault_number(&tail[1], strlen(&tail[1]), DERIVE_ORACLE_MAX,
		    &oracle) != 0 || oracle == 0)
			continue;
		memset(&at, 0, sizeof(at));
		at.slot = slot;
		at.oracle = (unsigned int)oracle;
		if (vault_path(path, sizeof(path), st->vault, VAULT_FILE_WRAP,
		    &at) != 0)
			continue;
		n = snprintf(name, sizeof(name), "%s/%s", dir, ent->d_name);
		if (n < 0 || (size_t)n >= sizeof(name) ||
		    strcmp(name, path) != 0)
			continue;
		if (slot_add(st, slot) != 0)
			goto out;
	}

	/* The sort gives the order, and the walk gives each slot once. */
	if (st->slotlen > 0)
		qsort(st->slot, st->slotlen, sizeof(*st->slot), slot_cmp);
	for (i = 0, keep = 0; i < st->slotlen; i++) {
		if (keep > 0 && st->slot[keep - 1] == st->slot[i])
			continue;
		st->slot[keep++] = st->slot[i];
	}
	st->slotlen = keep;
	rv = 0;
out:
	closedir(dp);
	return rv;
}

/*
 * done_add(st, slot, oracle, canary):
 *	Add one record to the marker list of the state. The list
 *	mirrors the done lines of the marker file (ORC-ENROLL-10).
 */
static int
done_add(struct state *st, uint32_t slot, unsigned int oracle, int canary)
{
	struct record	*at;
	size_t		 max;

	if (st->donelen == st->donemax) {
		max = st->donemax == 0 ? DONE_MIN : 2 * st->donemax;
		if ((at = reallocarray(st->done, max, sizeof(*at))) == NULL) {
			warn("the records of the change marker");
			return -1;
		}
		st->done = at;
		st->donemax = max;
	}
	st->done[st->donelen].slot = slot;
	st->done[st->donelen].oracle = oracle;
	st->done[st->donelen].canary = canary;
	st->donelen++;
	return 0;
}

/*
 * migrated(st, slot, oracle, canary):
 *	1 when the marker list holds the record, and 0 when it holds
 *	none. A record of the list answers the new passphrase, and
 *	every other record answers the old one (ORC-ENROLL-10). A
 *	canary takes no slot index.
 */
static int
migrated(const struct state *st, uint32_t slot, unsigned int oracle, int canary)
{
	size_t	 i;

	for (i = 0; i < st->donelen; i++) {
		if (st->done[i].oracle != oracle ||
		    st->done[i].canary != canary)
			continue;
		if (canary || st->done[i].slot == slot)
			return 1;
	}
	return 0;
}

/*
 * record_name(slot, oracle, canary, out, outlen):
 *	The record name of one record of this machine, to the outlen
 *	bytes at out. The name is <e>-<i>, or canary-<i>
 *	(ORC-COUNTER-2, VAULT-FORMAT).
 */
static int
record_name(uint32_t slot, unsigned int oracle, int canary, char *out,
    size_t outlen)
{
	int	 n;

	if (canary)
		n = snprintf(out, outlen, "canary-%u", oracle);
	else
		n = snprintf(out, outlen, "%" PRIu32 "-%u", slot, oracle);
	if (n < 0 || (size_t)n >= outlen)
		return -1;
	return 0;
}

/*
 * marker_alloc(st):
 *	The buffer of the marker text. The marker takes the kind line,
 *	one done line of each record of this machine, and one done
 *	line of each canary (ORC-ENROLL-10). The records of this
 *	machine are the slots of slots_read() at the positions of the
 *	oracle list.
 */
static int
marker_alloc(struct state *st)
{
	size_t	 max;

	max = sizeof(MARKER_HEAD) +
	    (st->slotlen + 1) * st->config.count * DONE_MAX + 1;
	if ((st->marker = malloc(max)) == NULL) {
		warn("the change marker");
		return -1;
	}
	st->markermax = max;
	st->markerlen = 0;
	return 0;
}

/*
 * marker_write(st):
 *	Write the marker text of the state to the marker file of this
 *	machine (VAULT-LAYOUT-4, VAULT-ATOMIC-1). A crashed write
 *	leaves no torn file, so the marker holds the done lines of the
 *	last complete write (VAULT-ATOMIC-2).
 */
static int
marker_write(const struct state *st)
{
	char	 path[PATH_MAX];

	if (vault_path(path, sizeof(path), st->vault, VAULT_FILE_CHANGE,
	    NULL) != 0)
		return -1;
	if (vault_write(path, (const unsigned char *)st->marker,
	    st->markerlen) != 0) {
		warn("%s", path);
		return -1;
	}
	return 0;
}

/*
 * marker_start(st):
 *	The marker of a change that starts, with the kind line and no
 *	done line. The file reaches the disk before the first set_pin
 *	of the change (ORC-ENROLL-10).
 */
static int
marker_start(struct state *st)
{
	st->markerlen = sizeof(MARKER_HEAD) - 1;
	memcpy(st->marker, MARKER_HEAD, st->markerlen);
	return marker_write(st);
}

/*
 * marker_line(line, arg):
 *	Take one line of the marker file to the parse at arg. The kind
 *	line names the change kind, and each done line names one
 *	re-enrolled record (ORC-ENROLL-10, VAULT-FORMAT).
 *
 *	The scanner holds the form of a record name, so the parse
 *	takes the oracle index after the hyphen, and the slot index
 *	before it.
 */
static int
marker_line(const struct vault_line *line, void *arg)
{
	static const char	 canary[] = "canary-";
	struct parse		*p = arg;
	const char		*hyphen;
	uint32_t		 slot = 0, oracle = 0;
	int			 is_canary;

	if (strcmp(line->field->name, "kind") == 0) {
		if (strcmp(line->value, MARKER_KIND) != 0) {
			warnx("the marker holds the change kind %s, and this "
			    "command completes a passphrase change",
			    line->value);
			return -1;
		}
		p->kind = 1;
		return 0;
	}

	if ((hyphen = strchr(line->value, '-')) == NULL)
		return -1;
	is_canary = strncmp(line->value, canary, sizeof(canary) - 1) == 0;
	if (vault_number(&hyphen[1], strlen(&hyphen[1]), DERIVE_ORACLE_MAX,
	    &oracle) != 0 || oracle == 0)
		return -1;
	if (!is_canary && vault_number(line->value,
	    (size_t)(hyphen - line->value), VAULT_SLOT_MAX, &slot) != 0)
		return -1;
	return done_add(p->st, slot, (unsigned int)oracle, is_canary);
}

/*
 * marker_read(st):
 *	The marker file of this machine, to the state. The text stays
 *	in the buffer of the state, and marker_done() appends to it.
 *
 *	The call gives -1 for an absent file, for a file that the
 *	buffer does not take, for a file without a kind line, and for
 *	a kind other than a passphrase change.
 */
static int
marker_read(struct state *st)
{
	struct parse	 p;
	char		 path[PATH_MAX];
	size_t		 len = 0;

	memset(&p, 0, sizeof(p));
	p.st = st;
	if (vault_path(path, sizeof(path), st->vault, VAULT_FILE_CHANGE,
	    NULL) != 0)
		return -1;
	if (vault_read(path, (unsigned char *)st->marker, st->markermax,
	    &len) != 0) {
		warn("%s", path);
		return -1;
	}
	if (len == 0 || len == st->markermax) {
		warnx("%s: the change marker is absent or too long", path);
		return -1;
	}
	st->markerlen = len;
	if (vault_scan(st->marker, len, vault_change_fields, marker_line,
	    &p) != 0) {
		warnx("%s: the marker holds a line that the reader rejects",
		    path);
		return -1;
	}
	if (!p.kind) {
		warnx("%s: the marker holds no kind line", path);
		return -1;
	}
	return 0;
}

/*
 * marker_done(st, slot, oracle, canary):
 *	Append the done line of one record to the marker, and write
 *	the file (ORC-ENROLL-10). The caller takes this call after the
 *	persisted writes of that record, and before the next set_pin.
 */
static int
marker_done(struct state *st, uint32_t slot, unsigned int oracle, int canary)
{
	char	 name[DONE_MAX];
	int	 n;

	if (record_name(slot, oracle, canary, name, sizeof(name)) != 0 ||
	    st->markerlen + DONE_MAX >= st->markermax) {
		warnx("the change marker: the done line does not fit");
		return -1;
	}
	n = snprintf(&st->marker[st->markerlen], st->markermax - st->markerlen,
	    "done: %s\n", name);
	if (n < 0 || (size_t)n >= st->markermax - st->markerlen) {
		warnx("the change marker: the done line does not fit");
		return -1;
	}
	st->markerlen += (size_t)n;
	if (marker_write(st) != 0)
		return -1;
	return done_add(st, slot, oracle, canary);
}

/*
 * marker_remove(st):
 *	Remove the marker file of this machine. The change takes this
 *	call after the last re-enrollment (ORC-ENROLL-10). A session
 *	then reveals again.
 */
static int
marker_remove(const struct state *st)
{
	char	 path[PATH_MAX];

	if (vault_path(path, sizeof(path), st->vault, VAULT_FILE_CHANGE,
	    NULL) != 0)
		return -1;
	if (unlink(path) == -1 && errno != ENOENT) {
		warn("%s", path);
		return -1;
	}
	return 0;
}

/*
 * read_twice(first, second, buf, bufsize):
 *	One passphrase of the terminal, to the bufsize bytes at buf.
 *	The call reads twice, under the two prompts, and it compares
 *	the two reads in constant time (ORC-ENROLL-8, SEC-MEMORY-2,
 *	SEC-MEMORY-4).
 *
 *	fugupass_passphrase_new() reads one new passphrase under the
 *	prompts of a creation. A change needs other prompts, so it
 *	names the pair here.
 *
 *	A failed read and a mismatch each give -1, and each one clears
 *	buf.
 */
static int
read_twice(const char *first, const char *second, char *buf, size_t bufsize)
{
	char	 again[FUGUPASS_PASS_MAX];
	size_t	 len;
	int	 rv = -1;

	if (bufsize == 0 || bufsize > sizeof(again))
		return -1;
	if (fugupass_passphrase(first, buf, bufsize) != 0) {
		warnx("the passphrase: the read fails");
		return -1;
	}
	if (fugupass_passphrase(second, again, bufsize) != 0) {
		warnx("the passphrase: the read fails");
		goto out;
	}
	len = strlen(buf);
	if (len != strlen(again) || timingsafe_bcmp(buf, again, len) != 0) {
		warnx("the passphrase: the two reads differ");
		goto out;
	}
	rv = 0;
out:
	explicit_bzero(again, sizeof(again));
	if (rv != 0)
		explicit_bzero(buf, bufsize);
	return rv;
}

/*
 * pass_read(st):
 *	The old passphrase and the new passphrase, to the state. The
 *	change reads the new one twice, and the pair must match
 *	(ORC-ENROLL-8). It reads the old one once, because the canary
 *	checks of verify() verify that one at each live oracle.
 */
static int
pass_read(struct state *st)
{
	if (fugupass_passphrase("Old passphrase: ", st->oldpass,
	    sizeof(st->oldpass)) != 0) {
		warnx("the passphrase: the read fails");
		return -1;
	}
	st->oldlen = strlen(st->oldpass);
	if (read_twice("New passphrase: ", "New passphrase again: ",
	    st->newpass, sizeof(st->newpass)) != 0)
		return -1;
	st->newlen = strlen(st->newpass);
	return 0;
}

/*
 * canary_report(st, oracle):
 *	The report of one canary check failure (ORC-CANARY-4,
 *	ORC-CANARY-9). A junk answer names no cause, so the report
 *	names the cause set.
 *
 *	A failure at the first canary of the change holds the typo
 *	case. A failure after a pass at another oracle excludes the
 *	typo, because the passphrase opened the canary check seal of
 *	that other oracle.
 */
static void
canary_report(const struct state *st, unsigned int oracle)
{
	const char	*url = st->config.oracle[oracle - 1].url;

	warnx("the canary of oracle %u (%s): the check fails", oracle, url);
	if (st->passed == 0)
		warnx("the cause is the passphrase, or, at oracle %u, a wiped "
		    "canary record, a counter behind the record, or a stale "
		    "canary check seal of this machine", oracle);
	else
		warnx("the passphrase passed at oracle %u, so the cause sits "
		    "at oracle %u: a wiped canary record, a counter behind "
		    "the record, or a stale canary check seal of this "
		    "machine", st->first, oracle);
}

/*
 * canary_take(st, oracle, share, live):
 *	The canary check of the oracle index oracle, and this
 *	machine's index share of it to share (ORC-CANARY-1,
 *	ORC-CANARY-3). live takes 1 for a live index wrap of that
 *	oracle.
 *
 *	The record takes the passphrase that it answers: the new one
 *	for a canary of the marker list, and the old one for every
 *	other canary (ORC-ENROLL-10).
 */
static int
canary_take(struct state *st, unsigned int oracle, unsigned char *share,
    int *live)
{
	struct oracle_ctx	 ctx;
	int			 rv;

	ctx_of(&ctx, st, oracle, migrated(st, 0, oracle, 1));
	rv = oracle_canary_check(&ctx, NULL, 0, share, DERIVE_KEYLEN, live);
	st->state[oracle] = rv;
	if (rv == ORACLE_EJUNK)
		canary_report(st, oracle);
	else if (rv == 0) {
		if (st->passed == 0)
			st->first = oracle;
		st->passed++;
	} else
		warnx("the canary of oracle %u (%s): %s", oracle,
		    st->config.oracle[oracle - 1].url, oracle_state_text(rv));
	return rv;
}

/*
 * canary_repair(st, oracle):
 *	The re-enrollment of one canary record that fails for a
 *	record-side cause (ORC-ENROLL-8, ORC-CANARY-5). The change
 *	takes this call before the first re-enrollment of the loop.
 *
 *	The record takes the passphrase that it must answer, as
 *	canary_take() does. The change holds no index key here, so the
 *	enrollment takes this machine's index wrap of that oracle away
 *	(ORC-CANARY-8). The canary loop of the change writes that wrap
 *	again, while the change holds K_idx (ORC-ENROLL-6).
 *
 *	The fresh record answers that passphrase, so the state of the
 *	oracle becomes a pass.
 */
static int
canary_repair(struct state *st, unsigned int oracle)
{
	struct oracle_ctx	 ctx;
	const char		*url = st->config.oracle[oracle - 1].url;
	int			 fresh, n;

	fresh = migrated(st, 0, oracle, 1);
	ctx_of(&ctx, st, oracle, fresh);
	n = oracle_canary_enroll(&ctx, fresh ? st->newpass : st->oldpass,
	    fresh ? st->newlen : st->oldlen);
	if (n != 0) {
		warnx("the canary of oracle %u (%s): the re-enrollment of it "
		    "fails, and %s", oracle, url, oracle_state_text(n));
		return -1;
	}
	warnx("the canary of oracle %u (%s) is enrolled again, and the index "
	    "wrap of it is gone", oracle, url);
	st->state[oracle] = STATE_PASS;
	return 0;
}

/*
 * index_open(st):
 *	The index of the vault, under the index key of the state
 *	(VAULT-INDEX-1, VAULT-INDEX-3). The open proves the
 *	reconstructed key, and the change needs no line of the file.
 *	The plaintext therefore leaves memory here (SEC-MEMORY-1).
 *
 *	The change needs K_idx for the canary loop, and for that loop
 *	alone (ORC-ENROLL-6). A failed open gives -1, and the change
 *	runs without K_idx.
 */
static int
index_open(struct state *st)
{
	char	 path[PATH_MAX];
	size_t	 len = 0;
	int	 rv = -1;

	if (vault_path(path, sizeof(path), st->vault, VAULT_FILE_INDEX,
	    NULL) != 0)
		return -1;
	if (vault_read(path, st->raw, RAW_MAX, &len) != 0) {
		warn("%s", path);
		return -1;
	}
	if (len <= SEAL_OVERHEAD || len > SESSION_INDEX_MAX + SEAL_OVERHEAD) {
		warnx("%s: the index is absent, or it is not a sealed file of "
		    "this vault", path);
		goto out;
	}
	if (seal_open(st->idxkey, sizeof(st->idxkey), st->raw, len, st->plain,
	    len - SEAL_OVERHEAD) != 0) {
		warnx("%s: the index does not open under the index key of the "
		    "canary masks", path);
		goto out;
	}
	rv = 0;
out:
	explicit_bzero(st->raw, RAW_MAX);
	explicit_bzero(st->plain, SESSION_INDEX_MAX);
	return rv;
}

/*
 * reach_report(st):
 *	The report of a change with fewer than k reachable oracles
 *	(ORC-QUORUM-6). No quorum reconstructs an entry key, so the
 *	change sends no set_pin. The report names the state of each
 *	live position, and the states of a request stay apart
 *	(ORC-REVEAL-6, ORC-REVEAL-8).
 */
static void
reach_report(const struct state *st)
{
	unsigned int	 i;

	warnx("the quorum takes %u reachable oracles, and %u answered",
	    st->config.threshold, st->reachlen);
	for (i = 1; i <= st->config.count; i++) {
		if (st->config.oracle[i - 1].retired)
			continue;
		warnx("oracle %u (%s): %s", i, st->config.oracle[i - 1].url,
		    state_text(st->state[i]));
	}
	warnx("the change sends no set_pin");
}

/*
 * verify(st):
 *	The verification of ORC-ENROLL-8, before any re-enrollment.
 *	The walk checks one canary per live oracle, in list order.
 *
 *	A junk answer at the first canary holds the typo case, and it
 *	stops the change (ORC-CANARY-4). A junk answer after a pass
 *	excludes the typo, so that canary takes a re-enrollment
 *	(ORC-CANARY-5). Every other failure names an oracle that no
 *	request reaches, and the walk steps over it.
 *
 *	The same answers carry this machine's index shares, so K_idx
 *	reaches the state with no request of its own (ORC-CANARY-3).
 *	The index read proves that key (VAULT-INDEX-6). A change
 *	without K_idx runs, and its canary loop takes each index wrap
 *	of this machine away (ORC-ENROLL-6, ORC-CANARY-8).
 *
 *	A change needs every live oracle reachable, so the report
 *	names each live oracle that stays out of reach
 *	(ORC-ENROLL-11).
 */
static int
verify(struct state *st)
{
	unsigned char	 shares[DERIVE_ORACLE_MAX * DERIVE_KEYLEN];
	unsigned int	 point[DERIVE_ORACLE_MAX];
	unsigned int	 i, count = 0;
	int		 live, rv, ok = -1;

	memset(shares, 0, sizeof(shares));
	memset(point, 0, sizeof(point));
	for (i = 1; i <= st->config.count; i++)
		st->state[i] = STATE_UNTRIED;

	for (i = 1; i <= st->config.count; i++) {
		if (st->config.oracle[i - 1].retired)
			continue;
		rv = canary_take(st, i, &shares[count * DERIVE_KEYLEN], &live);
		if (rv == ORACLE_EJUNK) {
			if (st->passed == 0) {
				warnx("the change sends no set_pin");
				goto out;
			}
			if (canary_repair(st, i) == 0)
				st->reach[st->reachlen++] = i;
			continue;
		}
		if (rv != 0)
			continue;
		st->reach[st->reachlen++] = i;
		if (live)
			point[count++] = i;
	}

	if (st->reachlen < st->config.threshold) {
		reach_report(st);
		goto out;
	}
	for (i = 1; i <= st->config.count; i++) {
		if (st->config.oracle[i - 1].retired ||
		    st->state[i] == STATE_PASS)
			continue;
		warnx("oracle %u (%s) stays out of reach, so the change stays "
		    "incomplete, and the marker stays", i,
		    st->config.oracle[i - 1].url);
	}

	/*
	 * The index opens while k canary answers carry a live index
	 * wrap of this machine (ORC-CANARY-8, VAULT-INDEX-3).
	 */
	if (count >= st->config.threshold &&
	    share_combine(point, shares, st->config.threshold, st->idxkey,
	    sizeof(st->idxkey)) == 0 && index_open(st) == 0)
		st->opened = 1;
	if (!st->opened) {
		explicit_bzero(st->idxkey, sizeof(st->idxkey));
		warnx("the change holds no index key, so each canary "
		    "re-enrollment takes the index wrap of its oracle away");
		warnx("the provisioning ceremony writes the index wraps of "
		    "this machine again");
	}
	ok = 0;
out:
	explicit_bzero(shares, sizeof(shares));
	return ok;
}

/*
 * slot_open(st, key):
 *	The file of the slot of the entry key key, under that key. The
 *	file name is the lowercase hex of H(K_e) (VAULT-LAYOUT-5), so
 *	a key of a wrong reconstruction names another file.
 *
 *	The open is the verification of ORC-ENROLL-9, and the change
 *	needs no line of the file. The plaintext therefore leaves
 *	memory here (SEC-MEMORY-1).
 *
 *	The call gives EDECRYPT for an absent file and for a failed
 *	open, because both carry one cause: this quorum gives no entry
 *	key of that slot (VAULT-SEAL-4). It gives -1 for a failure of
 *	this machine, and 0 for a file that opens.
 */
static int
slot_open(struct state *st, const unsigned char *key)
{
	struct vault_at	 at;
	char		 name[VAULT_NAMELEN];
	char		 path[PATH_MAX];
	size_t		 len = 0;
	int		 rv = -1;

	if (vault_entry_name(key, DERIVE_KEYLEN, name, sizeof(name)) != 0)
		return -1;
	memset(&at, 0, sizeof(at));
	at.name = name;
	if (vault_path(path, sizeof(path), st->vault, VAULT_FILE_ENTRY,
	    &at) != 0)
		return -1;
	if (vault_read(path, st->raw, RAW_MAX, &len) != 0) {
		warn("%s", path);
		return -1;
	}
	if (len == 0) {
		rv = EDECRYPT;
		goto out;
	}
	if (len <= SEAL_OVERHEAD || len > SESSION_PLAIN_MAX + SEAL_OVERHEAD) {
		warnx("%s: the file is not a sealed file of this vault", path);
		goto out;
	}
	if (seal_open(key, DERIVE_KEYLEN, st->raw, len, st->plain,
	    len - SEAL_OVERHEAD) != 0) {
		rv = EDECRYPT;
		goto out;
	}
	rv = 0;
out:
	explicit_bzero(st->raw, RAW_MAX);
	explicit_bzero(st->plain, SESSION_INDEX_MAX);
	return rv;
}

/*
 * quorum_name(st, quorum, len):
 *	The oracles of one quorum of len places, for a failure report.
 *	Every quorum failure names the oracles of the attempt
 *	(ORC-ENROLL-9, ORC-QUORUM-5).
 */
static void
quorum_name(const struct state *st, const unsigned int *quorum,
    unsigned int len)
{
	unsigned int	 i;

	for (i = 0; i < len; i++)
		warnx("the attempt holds oracle %u (%s) in the quorum",
		    quorum[i], st->config.oracle[quorum[i] - 1].url);
}

/*
 * reconstruct(st, slot, key):
 *	The entry key of the slot index slot, to the DERIVE_KEYLEN
 *	bytes at key (ORC-ENROLL-4, ORC-ENROLL-9). The quorum takes
 *	the first k reachable oracles, in list order.
 *
 *	Each record of the quorum takes one get_pin, under the
 *	passphrase that the marker names for it (ORC-ENROLL-10). The
 *	call reconstructs the key from the k shares, and it opens the
 *	file of the slot (KEY-SHARE-6, VAULT-SEAL-4).
 *
 *	A failed request and a failed open each substitute the next
 *	untried reachable oracle, and the shares of the other places
 *	stay (ORC-QUORUM-5). One record therefore takes one request at
 *	the most, so a wrong pin burns one strike at the most
 *	(ORC-QUORUM-8, ORC-REVEAL-5). verify() checked the canary of
 *	each reachable oracle, so a substitute takes no canary check
 *	of its own (ORC-CANARY-1).
 *
 *	A failure with no untried reachable oracle gives -1. The
 *	change then stops before any set_pin of that slot, and the
 *	report names the slot and each quorum (ORC-ENROLL-9).
 */
static int
reconstruct(struct state *st, uint32_t slot, unsigned char *key)
{
	unsigned char		 shares[DERIVE_ORACLE_MAX * DERIVE_KEYLEN];
	unsigned int		 quorum[DERIVE_ORACLE_MAX];
	int			 have[DERIVE_ORACLE_MAX];
	struct oracle_ctx	 ctx;
	unsigned int		 i, k, next = 0, tries = 0, victim = 0;
	int			 n, fail, rv = -1;

	memset(shares, 0, sizeof(shares));
	memset(have, 0, sizeof(have));
	k = st->config.threshold;
	if (st->reachlen < k) {
		warnx("slot %" PRIu32 ": the change reaches fewer than %u "
		    "oracles", slot, k);
		return -1;
	}
	for (i = 0; i < k; i++)
		quorum[i] = st->reach[next++];

	for (;;) {
		fail = 0;
		for (i = 0; i < k; i++) {
			if (have[i])
				continue;
			ctx_of(&ctx, st, quorum[i],
			    migrated(st, slot, quorum[i], 0));
			n = oracle_reveal(&ctx, slot,
			    &shares[i * DERIVE_KEYLEN], DERIVE_KEYLEN, NULL);
			if (n == 0) {
				have[i] = 1;
				continue;
			}
			st->state[quorum[i]] = n;
			warnx("slot %" PRIu32 " at oracle %u (%s): %s", slot,
			    quorum[i], st->config.oracle[quorum[i] - 1].url,
			    oracle_state_text(n));
			victim = i;
			fail = 1;
			break;
		}

		if (!fail) {
			if (share_combine(quorum, shares, k, key,
			    DERIVE_KEYLEN) != 0)
				goto out;
			n = slot_open(st, key);
			if (n == 0) {
				rv = 0;
				goto out;
			}
			if (n != EDECRYPT)
				goto out;
			warnx("slot %" PRIu32 ": the file of this quorum does "
			    "not open", slot);
			victim = tries % k;
		}

		quorum_name(st, quorum, k);
		if (next >= st->reachlen) {
			warnx("slot %" PRIu32 ": no untried reachable oracle "
			    "remains, and the change sends no set_pin of this "
			    "slot", slot);
			goto out;
		}
		quorum[victim] = st->reach[next++];
		have[victim] = 0;
		tries++;
	}
out:
	explicit_bzero(shares, sizeof(shares));
	if (rv != 0)
		explicit_bzero(key, DERIVE_KEYLEN);
	return rv;
}

/*
 * slot_done(st, slot):
 *	1 when the marker list holds the record of the slot index slot
 *	at each live oracle, and 0 when one record stays. A resumed
 *	change starts at the first unmigrated record, so it reveals no
 *	slot of a 1 (ORC-ENROLL-10).
 */
static int
slot_done(const struct state *st, uint32_t slot)
{
	unsigned int	 i;

	for (i = 1; i <= st->config.count; i++) {
		if (st->config.oracle[i - 1].retired)
			continue;
		if (!migrated(st, slot, i, 0))
			return 0;
	}
	return 1;
}

/*
 * slot_change(st, slot):
 *	The re-enrollment of the slot index slot at each live oracle,
 *	in list order (ORC-ENROLL-4, ORC-ENROLL-5). The reconstruction
 *	of the entry key comes first, and it holds the gate of
 *	ORC-ENROLL-9.
 *
 *	oracle_enroll() sends one set_pin under the new pin, and it
 *	persists the wrap of that oracle (ORC-ENROLL-2, ORC-ENROLL-3).
 *	The done line of the record follows that write, and it comes
 *	before the next set_pin (ORC-ENROLL-10).
 *
 *	The entry key leaves memory at each exit of the slot
 *	(SEC-MEMORY-6).
 */
static int
slot_change(struct state *st, uint32_t slot)
{
	struct oracle_ctx	 ctx;
	unsigned char		 key[DERIVE_KEYLEN];
	unsigned int		 i;
	int			 n, rv = -1;

	if (slot_done(st, slot))
		return 0;
	memset(key, 0, sizeof(key));
	if (reconstruct(st, slot, key) != 0)
		goto out;
	for (i = 1; i <= st->config.count; i++) {
		if (st->config.oracle[i - 1].retired ||
		    migrated(st, slot, i, 0))
			continue;
		ctx_of(&ctx, st, i, 1);
		n = oracle_enroll(&ctx, slot, key, sizeof(key));
		if (n != 0) {
			warnx("slot %" PRIu32 " at oracle %u (%s): %s", slot,
			    i, st->config.oracle[i - 1].url,
			    oracle_state_text(n));
			goto out;
		}
		if (marker_done(st, slot, i, 0) != 0)
			goto out;
	}
	rv = 0;
out:
	explicit_bzero(key, sizeof(key));
	return rv;
}

/*
 * canaries(st):
 *	The re-enrollment of the canary record of each live oracle,
 *	last of the change (ORC-ENROLL-5, ORC-ENROLL-10). An
 *	interrupted change therefore verifies with the old passphrase
 *	at every oracle whose canary stays.
 *
 *	Each enrollment seals the fresh canary check value
 *	(ORC-CANARY-11). A change that holds K_idx re-wraps this
 *	machine's index share of that oracle under the fresh canary
 *	mask, and a change without K_idx leaves no wrap file
 *	(ORC-ENROLL-6, ORC-CANARY-8). The report of that state names
 *	the provisioning ceremony.
 *
 *	pass_read() read the new passphrase twice, so the enrollment
 *	takes that matched value for both reads (ORC-CANARY-6).
 */
static int
canaries(struct state *st)
{
	struct oracle_ctx	 ctx;
	unsigned int		 i;
	int			 n;

	for (i = 1; i <= st->config.count; i++) {
		if (st->config.oracle[i - 1].retired ||
		    migrated(st, 0, i, 1))
			continue;
		ctx_of(&ctx, st, i, 1);
		if (st->opened)
			n = oracle_canary_index(&ctx, st->newpass, st->newlen,
			    st->idxkey, sizeof(st->idxkey));
		else
			n = oracle_canary_enroll(&ctx, st->newpass,
			    st->newlen);
		if (n != 0) {
			warnx("the canary of oracle %u (%s): %s", i,
			    st->config.oracle[i - 1].url, oracle_state_text(n));
			return -1;
		}
		if (!st->opened)
			warnx("the index wrap of oracle %u is gone: the "
			    "provisioning ceremony writes it again", i);
		if (marker_done(st, 0, i, 1) != 0)
			return -1;
	}
	return 0;
}

/*
 * run(st, resume):
 *	The change, in the order of ORC-ENROLL. resume takes the
 *	marker of an incomplete change, and 0 writes a fresh one.
 *
 *	The marker reaches the disk before the first set_pin of the
 *	change, and the removal of it follows the last re-enrollment
 *	(ORC-ENROLL-10). A canary re-enrollment of verify() comes
 *	before the change starts, so it takes no marker
 *	(ORC-ENROLL-8).
 *
 *	A failure after the first set_pin leaves the marker, and the
 *	change stays incomplete (ORC-ENROLL-11).
 */
static int
run(struct state *st, int resume)
{
	size_t	 i;

	if (config_read(st) != 0 || factor_read(st) != 0)
		return -1;
	if (slots_read(st) != 0)
		return -1;
	if (marker_alloc(st) != 0)
		return -1;
	if (resume && marker_read(st) != 0)
		return -1;
	if (pass_read(st) != 0)
		return -1;
	if (verify(st) != 0)
		return -1;
	if (!resume && marker_start(st) != 0)
		return -1;
	for (i = 0; i < st->slotlen; i++)
		if (slot_change(st, st->slot[i]) != 0)
			return -1;
	if (canaries(st) != 0)
		return -1;
	return marker_remove(st);
}

int
change_pending(const char *vault)
{
	char	 path[PATH_MAX];

	if (vault == NULL)
		return -1;
	if (vault_path(path, sizeof(path), vault, VAULT_FILE_CHANGE,
	    NULL) != 0) {
		warnx("%s: the path of the change marker does not fit", vault);
		return -1;
	}
	if (access(path, R_OK) == 0)
		return 1;
	if (errno == ENOENT)
		return 0;
	warn("%s", path);
	return -1;
}

int
change_passphrase(const char *vault)
{
	struct state	*st;
	int		 rv;

	if (vault == NULL)
		return -1;
	if ((rv = change_pending(vault)) != 0) {
		if (rv == 1)
			warnx("this vault holds an incomplete change, and "
			    "\"%s\" completes it", CHANGE_RESUME_CMD);
		return -1;
	}
	if ((st = state_new(vault)) == NULL)
		return -1;
	rv = run(st, 0);
	state_free(st);
	if (rv != 0 && change_pending(vault) == 1)
		warnx("the change stays incomplete, and \"%s\" completes it",
		    CHANGE_RESUME_CMD);
	return rv;
}

int
change_resume(const char *vault)
{
	struct state	*st;
	int		 rv;

	if (vault == NULL)
		return -1;
	if ((rv = change_pending(vault)) != 1) {
		if (rv == 0)
			warnx("this vault holds no incomplete change");
		return -1;
	}
	if ((st = state_new(vault)) == NULL)
		return -1;
	rv = run(st, 1);
	state_free(st);
	if (rv != 0 && change_pending(vault) == 1)
		warnx("the change stays incomplete, and \"%s\" completes it",
		    CHANGE_RESUME_CMD);
	return rv;
}
