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
 * The session core. session.h states the interface.
 *
 * unlock() runs the open in one order: the config, the device
 * factor, the passphrase, the canary of each quorum oracle, and the
 * index (PROG-REPL-1, ORC-CANARY-4, VAULT-INDEX-3).
 *
 * candidates() holds the order of ORC-QUORUM-2: the live positions
 * in list order, and the positions that hold a live index wrap of
 * this machine first. quorum_take() walks that list and takes the
 * first k oracles that answer a canary check. An oracle that fails
 * the request is unreachable, and the walk steps over it
 * (ORC-PROVISION-9). A canary check that fails in that walk stops
 * the session, before any entry record (ORC-CANARY-1,
 * ORC-CANARY-4).
 *
 * heal() re-wraps each dead index wrap of this machine, after the
 * index opens. A canary check that fails there leaves that one wrap
 * dead, and the session runs (ORC-CANARY-8).
 *
 * reveal() holds the quorum event: one get_pin per quorum oracle,
 * one reconstruction, and one decrypt (ORC-QUORUM-3, ORC-QUORUM-4).
 * The entry file name is the hex of H(K_e), so a wrong
 * reconstruction names another file (VAULT-LAYOUT-5). An absent
 * file and a failed open therefore carry one state: the decrypt
 * failure of this quorum, and it names no oracle.
 *
 * substitute() takes the next untried candidate, after the canary
 * check of it (ORC-QUORUM-5). The substitutions end when that list
 * runs out. The session quorum keeps each substitution, so a later
 * reveal of the session takes the same oracles.
 *
 * The steps come from the other files of the tree. oracle.c holds
 * each record, each mask and each wrap, share.c holds the
 * reconstruction, seal.c holds the seal, vault.c holds every path,
 * the reader, the writer and the scanner, and fugupass.c reads the
 * passphrase. This file adds the order, the substitution and the
 * reports.
 *
 * The secrets of the session live in one struct session, and the
 * allocation of it never moves, so one explicit_bzero(3) of it
 * clears each one (SEC-MEMORY-1). The plaintext of a reveal lives
 * in a buffer of the session, and session_close() clears it. Every
 * share lives in the call that takes it, and that call clears it
 * (KEY-SHARE-8).
 *
 * Every report goes to the standard error, so the records of
 * stdout stay script-friendly (PROG-ONESHOT-3).
 */

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

#include "derive.h"
#include "fugupass.h"
#include "oracle.h"
#include "seal.h"
#include "session.h"
#include "share.h"
#include "vault.h"

/*
 * The bytes of the longest file that this file reads, and one
 * more. A count of this value names a file that is too long
 * (vault.h).
 */
#define RAW_MAX		(SESSION_INDEX_MAX + SEAL_OVERHEAD + 1)

/*
 * The bytes of the shortest entry line of the index: the name, the
 * colon and the space, the file name, one space, one byte of the
 * type name, one space, one slot index, one space, one byte of the
 * entry name, and the line feed (VAULT-FORMAT-1, VAULT-VALUE_ENTRY).
 */
#define ENTRY_LINE_MIN	(sizeof("entry: ") - 1 + 2 * DERIVE_KEYLEN + 7)

/* The state of one oracle in this session, for the reports. */
#define STATE_PASS	0	/* the canary check of it passes */
#define STATE_UNTRIED	1	/* the session sent no request to it */

/* The entry file of the attempt does not open (VAULT-SEAL-4). */
#define EDECRYPT	(-2)

/*
 * The session of one vault. The passphrase, the device factor, the
 * index key and the entry key of a consumption are the secrets of
 * the struct. The three buffers hold a plaintext each, and
 * session_close() clears them.
 *
 * quorum holds the k oracle indexes of the session quorum, and
 * cand holds the candidates of ORC-QUORUM-2, in preference order.
 * next is the first untried candidate, so one walk serves the open
 * and every substitution of the session (ORC-QUORUM-5).
 *
 * state[i] is the last state of oracle i, for the report of a
 * refusal (ORC-QUORUM-6). passed counts the canary checks that
 * passed, and first is the oracle of the first one, because a
 * canary failure after a pass excludes the typo (ORC-CANARY-4).
 */
struct session {
	struct vault_config	 config;
	char			 vault[PATH_MAX];
	unsigned char		 factor[DERIVE_KEYLEN];	/* X */
	char			 pass[FUGUPASS_PASS_MAX];
	size_t			 passlen;
	unsigned char		 idxkey[DERIVE_KEYLEN];	/* K_idx */
	unsigned char		 key[DERIVE_KEYLEN];	/* K_e, held */
	int			 held;			/* key holds K_e */
	int			 opened;		/* the index is open */
	char			 file[VAULT_NAMELEN];
	unsigned int		 cand[DERIVE_ORACLE_MAX];
	unsigned int		 candlen;
	unsigned int		 next;
	unsigned int		 quorum[DERIVE_ORACLE_MAX];
	unsigned int		 quorumlen;
	unsigned int		 passed;
	unsigned int		 first;
	int			 state[DERIVE_ORACLE_MAX + 1];
	unsigned char		*raw;		/* one sealed file */
	char			*plain;		/* one entry plaintext */
	size_t			 plainlen;
	char			*text;		/* the index plaintext */
	size_t			 textlen;
	char			*arena;		/* the parts of each entry */
	size_t			 arenalen;
	struct session_entry	*list;
	size_t			 listlen;
	size_t			 listmax;
};

static const char	*state_text(int);
static void		 ctx_of(struct oracle_ctx *, const struct session *,
			     unsigned int);
static int		 config_read(struct session *);
static int		 factor_read(struct session *);
static int		 wrap_live(const struct session *, unsigned int);
static void		 candidates(struct session *);
static void		 canary_report(const struct session *, unsigned int);
static int		 canary_take(struct session *, unsigned int,
			     const unsigned char *, unsigned char *, int *);
static void		 quorum_report(const struct session *);
static int		 quorum_take(struct session *, unsigned char *, int *);
static void		 quorum_name(const struct session *);
static int		 last_slot(const char *, uint32_t *);
static int		 index_line(const struct vault_line *, void *);
static int		 index_gate(const struct vault_line *, void *);
static int		 index_parse(struct session *);
static void		 index_report(const struct session *, const char *);
static int		 index_open(struct session *);
static void		 index_dead(const struct session *);
static void		 heal(struct session *);
static int		 unlock(struct session *);
static int		 substitute(struct session *, unsigned int);
static int		 entry_open(struct session *, const unsigned char *);
static int		 reveal(struct session *, uint32_t, int);

/*
 * state_text(state):
 *	The text of one state of one oracle of this session. The
 *	states of a request come from oracle.h, and the two states of
 *	this file cover an oracle that answered a canary check and an
 *	oracle that took no request (ORC-QUORUM-6).
 */
static const char *
state_text(int state)
{
	if (state == STATE_UNTRIED)
		return "the session sent no request";
	if (state == STATE_PASS)
		return "the canary check passes";
	return oracle_state_text(state);
}

/*
 * ctx_of(ctx, s, oracle):
 *	The record context of the oracle index oracle, from the
 *	session s. oracle.c gates each field of it.
 */
static void
ctx_of(struct oracle_ctx *ctx, const struct session *s, unsigned int oracle)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->vault = s->vault;
	ctx->config = &s->config;
	ctx->factor = s->factor;
	ctx->factorlen = sizeof(s->factor);
	ctx->pass = s->pass;
	ctx->passlen = s->passlen;
	ctx->oracle = oracle;
}

/*
 * config_read(s):
 *	The config file of the vault, to the session (VAULT-CONFIG-1,
 *	VAULT-CONFIG-2). The reader holds the position rule of the
 *	file, so this step adds no gate (VAULT-CONFIG-6).
 */
static int
config_read(struct session *s)
{
	char	 path[PATH_MAX];
	size_t	 len = 0;

	if (vault_path(path, sizeof(path), s->vault, VAULT_FILE_CONFIG,
	    NULL) != 0)
		return -1;
	if (vault_read(path, s->raw, RAW_MAX, &len) != 0) {
		warn("%s", path);
		return -1;
	}
	if (len == 0 || len == RAW_MAX) {
		warnx("%s: the config file is absent or too long", path);
		return -1;
	}
	if (vault_config_read((const char *)s->raw, len, &s->config) != 0) {
		warnx("%s: an oracle position or the threshold is wrong",
		    path);
		return -1;
	}
	return 0;
}

/*
 * factor_read(s):
 *	The device factor X of this machine, to the session
 *	(KEY-DEVICE-1, KEY-DEVICE-2). The factor is a secret, and it
 *	leaves memory in session_close().
 */
static int
factor_read(struct session *s)
{
	char	 path[PATH_MAX];
	size_t	 len = 0;

	if (vault_path(path, sizeof(path), s->vault, VAULT_FILE_FACTOR,
	    NULL) != 0)
		return -1;
	if (vault_read(path, s->raw, DERIVE_KEYLEN + 1, &len) != 0) {
		warn("%s", path);
		return -1;
	}
	if (len != DERIVE_KEYLEN) {
		warnx("%s: the device factor of this machine is absent",
		    path);
		return -1;
	}
	memcpy(s->factor, s->raw, sizeof(s->factor));
	explicit_bzero(s->raw, DERIVE_KEYLEN);
	return 0;
}

/*
 * wrap_live(s, oracle):
 *	1 when this machine holds an index wrap of the oracle index
 *	oracle, and 0 when that file is absent. An absent file is the
 *	dead state of a canary re-enrollment without the index key
 *	(ORC-CANARY-8).
 */
static int
wrap_live(const struct session *s, unsigned int oracle)
{
	struct vault_at	 at;
	char		 path[PATH_MAX];

	memset(&at, 0, sizeof(at));
	at.oracle = oracle;
	if (vault_path(path, sizeof(path), s->vault, VAULT_FILE_WRAP_INDEX,
	    &at) != 0)
		return 0;
	return access(path, R_OK) == 0;
}

/*
 * candidates(s):
 *	The candidates of the session quorum, in preference order
 *	(ORC-QUORUM-2). The first pass takes each live position that
 *	holds a live index wrap of this machine, and the second pass
 *	takes each other live position. Both passes keep the order of
 *	the list, so a position keeps its index (ORC-PROVISION-5).
 *
 *	A reachable oracle is a live oracle that answers, and no file
 *	states that (ORC-PROVISION-9). The walk of quorum_take()
 *	therefore learns it from the canary check of each candidate.
 */
static void
candidates(struct session *s)
{
	unsigned int	 i, pass;

	s->candlen = 0;
	s->next = 0;
	for (pass = 0; pass < 2; pass++) {
		for (i = 1; i <= s->config.count; i++) {
			if (s->config.oracle[i - 1].retired)
				continue;
			if (wrap_live(s, i) != (pass == 0))
				continue;
			s->cand[s->candlen++] = i;
		}
	}
}

/*
 * canary_report(s, oracle):
 *	The report of one canary check failure (ORC-CANARY-4,
 *	ORC-CANARY-9). A junk answer names no cause, so the report
 *	names the cause set.
 *
 *	A failure at the first canary of the session holds the typo
 *	case. A failure after a pass at another oracle excludes the
 *	typo, because the passphrase opened the canary check seal of
 *	that other oracle.
 */
static void
canary_report(const struct session *s, unsigned int oracle)
{
	const char	*url = s->config.oracle[oracle - 1].url;

	warnx("the canary of oracle %u (%s): the check fails", oracle, url);
	if (s->passed == 0)
		warnx("the cause is the passphrase, or, at oracle %u, a wiped "
		    "canary record, a counter behind the record, or a stale "
		    "canary check seal of this machine", oracle);
	else
		warnx("the passphrase passed at oracle %u, so the cause sits "
		    "at oracle %u: a wiped canary record, a counter behind "
		    "the record, or a stale canary check seal of this "
		    "machine", s->first, oracle);
	warnx("the session sends no entry request to oracle %u", oracle);
}

/*
 * canary_take(s, oracle, idxkey, share, live):
 *	The canary check of the oracle index oracle, and this
 *	machine's index share of it to share (ORC-CANARY-1,
 *	ORC-CANARY-3). idxkey heals a dead index wrap of that oracle,
 *	and a NULL idxkey heals none (ORC-CANARY-8).
 *
 *	The call gives the state of oracle.h, and it keeps that state
 *	for the reports. A junk answer takes its report here, because
 *	the cause set of it is the same at each caller
 *	(ORC-CANARY-9).
 */
static int
canary_take(struct session *s, unsigned int oracle,
    const unsigned char *idxkey, unsigned char *share, int *live)
{
	struct oracle_ctx	 ctx;
	int			 rv;

	ctx_of(&ctx, s, oracle);
	rv = oracle_canary_check(&ctx, idxkey,
	    idxkey == NULL ? 0 : DERIVE_KEYLEN, share, DERIVE_KEYLEN, live);
	s->state[oracle] = rv;
	if (rv == ORACLE_EJUNK)
		canary_report(s, oracle);
	else if (rv == 0) {
		if (s->passed == 0)
			s->first = oracle;
		s->passed++;
	}
	return rv;
}

/*
 * quorum_report(s):
 *	The report of a session with fewer than k reachable oracles
 *	(ORC-QUORUM-6). The report names the state of each live
 *	position, and the states of a request stay apart
 *	(ORC-REVEAL-6, ORC-REVEAL-8).
 */
static void
quorum_report(const struct session *s)
{
	unsigned int	 i;

	warnx("the quorum takes %u reachable oracles, and %u answered",
	    s->config.threshold, s->quorumlen);
	for (i = 1; i <= s->config.count; i++) {
		if (s->config.oracle[i - 1].retired)
			continue;
		warnx("oracle %u (%s): %s", i, s->config.oracle[i - 1].url,
		    state_text(s->state[i]));
	}
	warnx("the session performs no reveal");
}

/*
 * quorum_take(s, shares, live):
 *	The session quorum, from the candidates of candidates(). The
 *	walk takes the first k candidates that pass a canary check,
 *	one oracle at a time (ORC-CANARY-4). shares takes the index
 *	share of each quorum oracle, in quorum order, of
 *	DERIVE_KEYLEN bytes each. live takes 1 of each oracle that
 *	holds a live index wrap of this machine.
 *
 *	A canary check that fails with a junk answer stops the walk,
 *	and every other failure steps to the next candidate. A walk
 *	that ends below k oracles reports the state of each one
 *	(ORC-QUORUM-6).
 */
static int
quorum_take(struct session *s, unsigned char *shares, int *live)
{
	unsigned int	 i;
	int		 rv;

	while (s->quorumlen < s->config.threshold && s->next < s->candlen) {
		i = s->cand[s->next++];
		rv = canary_take(s, i, NULL,
		    &shares[s->quorumlen * DERIVE_KEYLEN], &live[s->quorumlen]);
		if (rv == ORACLE_EJUNK)
			return -1;
		if (rv != 0)
			continue;
		s->quorum[s->quorumlen++] = i;
	}
	if (s->quorumlen < s->config.threshold) {
		quorum_report(s);
		return -1;
	}
	return 0;
}

/*
 * quorum_name(s):
 *	The oracles of the session quorum, for a failure report.
 *	Every quorum failure names the oracles of the attempt
 *	(ORC-QUORUM-5).
 */
static void
quorum_name(const struct session *s)
{
	unsigned int	 i;

	for (i = 0; i < s->quorumlen; i++)
		warnx("the attempt holds oracle %u (%s) in the quorum",
		    s->quorum[i], s->config.oracle[s->quorum[i] - 1].url);
}

/*
 * last_slot(slots, out):
 *	The current slot of the slot list at slots, to out: the last
 *	index of the list (ENTRY-ROTATION-2). The scanner holds the
 *	form of the list, and vault_number() holds the form of one
 *	index (VAULT-FORMAT-7).
 */
static int
last_slot(const char *slots, uint32_t *out)
{
	const char	*at;

	if ((at = strrchr(slots, ',')) != NULL)
		at = &at[1];
	else
		at = slots;
	return vault_number(at, strlen(at), VAULT_SLOT_MAX, out);
}

/*
 * index_line(line, arg):
 *	Take one line of the index to the session at arg. An entry
 *	line becomes one row of the list, and every other line stays
 *	in the text of session_index() (VAULT-INDEX-2).
 *
 *	The scanner holds the form of the value: the file name of
 *	2 * DERIVE_KEYLEN hex bytes, the type name, the slot list,
 *	and the entry name, with one space between two parts. The
 *	copy of the value takes the three spaces as terminators, so
 *	the four parts are four strings. The entry name comes last,
 *	so it can hold a space.
 */
static int
index_line(const struct vault_line *line, void *arg)
{
	struct session		*s = arg;
	struct session_entry	*e;
	char			*at, *type, *slots, *space;

	if (strcmp(line->field->name, "entry") != 0)
		return 0;
	if (s->listlen == s->listmax ||
	    s->arenalen + line->valuelen + 1 > SESSION_INDEX_MAX)
		return -1;

	at = &s->arena[s->arenalen];
	memcpy(at, line->value, line->valuelen);
	at[line->valuelen] = '\0';
	s->arenalen += line->valuelen + 1;

	at[2 * DERIVE_KEYLEN] = '\0';
	type = &at[2 * DERIVE_KEYLEN + 1];
	if ((space = strchr(type, ' ')) == NULL)
		return -1;
	*space = '\0';
	slots = &space[1];
	if ((space = strchr(slots, ' ')) == NULL)
		return -1;
	*space = '\0';

	e = &s->list[s->listlen];
	memset(e, 0, sizeof(*e));
	e->file = at;
	e->type = type;
	e->slots = slots;
	e->name = &space[1];
	if (last_slot(slots, &e->slot) != 0)
		return -1;
	s->listlen++;
	return 0;
}

/*
 * index_gate(line, arg):
 *	Take one line of an index text, and keep nothing. The
 *	scanner gates the text of session_index_write() with this
 *	callback, before the write (VAULT-FORMAT-6).
 */
static int
index_gate(const struct vault_line *line, void *arg)
{
	(void)line;
	(void)arg;
	return 0;
}

/*
 * index_parse(s):
 *	The entries of the index text of the session, to the list of
 *	it. The list takes one row of each entry line, and the text
 *	bounds the count of them: an entry line holds
 *	ENTRY_LINE_MIN bytes or more.
 */
static int
index_parse(struct session *s)
{
	free(s->list);
	s->list = NULL;
	s->listlen = 0;
	s->arenalen = 0;
	s->listmax = s->textlen / ENTRY_LINE_MIN + 1;
	if ((s->list = calloc(s->listmax, sizeof(*s->list))) == NULL)
		return -1;
	return vault_scan(s->text, s->textlen, vault_index_fields, index_line,
	    s);
}

/*
 * index_report(s, path):
 *	The report of an index that does not open after a canary
 *	check that passed (VAULT-INDEX-6). The cause is the index
 *	file, or this machine's index wrap of one quorum oracle. The
 *	report names both, and it names no junk answer, because the
 *	canary checks of the quorum passed.
 */
static void
index_report(const struct session *s, const char *path)
{
	struct vault_at	 at;
	char		 wrap[PATH_MAX];
	unsigned int	 i;

	warnx("%s: the index does not open, and the canary of each quorum "
	    "oracle passed", path);
	warnx("the cause is that file, or one index wrap of this machine "
	    "below");
	for (i = 0; i < s->quorumlen; i++) {
		memset(&at, 0, sizeof(at));
		at.oracle = s->quorum[i];
		if (vault_path(wrap, sizeof(wrap), s->vault,
		    VAULT_FILE_WRAP_INDEX, &at) != 0)
			continue;
		warnx("the quorum holds oracle %u (%s), with the index wrap "
		    "%s", s->quorum[i],
		    s->config.oracle[s->quorum[i] - 1].url, wrap);
	}
}

/*
 * index_open(s):
 *	The index of the vault, under the index key of the session
 *	(VAULT-INDEX-1, VAULT-INDEX-3). The call keeps the plaintext
 *	of the file for session_index(), and it parses the entries of
 *	it.
 */
static int
index_open(struct session *s)
{
	char	 path[PATH_MAX];
	size_t	 len = 0;

	if (vault_path(path, sizeof(path), s->vault, VAULT_FILE_INDEX,
	    NULL) != 0)
		return -1;
	if (vault_read(path, s->raw, RAW_MAX, &len) != 0) {
		warn("%s", path);
		return -1;
	}
	if (len <= SEAL_OVERHEAD || len > SESSION_INDEX_MAX + SEAL_OVERHEAD) {
		warnx("%s: the index is absent, or it is not a sealed file of "
		    "this vault", path);
		return -1;
	}
	if (seal_open(s->idxkey, sizeof(s->idxkey), s->raw, len,
	    (unsigned char *)s->text, len - SEAL_OVERHEAD) != 0) {
		index_report(s, path);
		return -1;
	}
	s->textlen = len - SEAL_OVERHEAD;
	if (index_parse(s) != 0) {
		warnx("%s: the index holds a line that the reader rejects",
		    path);
		return -1;
	}
	return 0;
}

/*
 * index_dead(s):
 *	The report of a session quorum that covers fewer than k live
 *	index wraps of this machine (PROG-REPL-2, ORC-CANARY-8). The
 *	session opens, and it resolves no entry name.
 *
 *	The report names each dead index wrap of this machine, and
 *	each live one at an oracle that the session did not reach.
 */
static void
index_dead(const struct session *s)
{
	unsigned int	 i;
	int		 wrap;

	warnx("the index stays closed: the quorum covers fewer than %u live "
	    "index wraps of this machine", s->config.threshold);
	for (i = 1; i <= s->config.count; i++) {
		if (s->config.oracle[i - 1].retired)
			continue;
		wrap = wrap_live(s, i);
		if (wrap && s->state[i] == STATE_PASS)
			continue;
		warnx("the index wrap of oracle %u (%s) is %s, and %s", i,
		    s->config.oracle[i - 1].url,
		    wrap ? "out of reach" : "dead", state_text(s->state[i]));
	}
	warnx("the provisioning ceremony writes the index wraps of this "
	    "machine again");
}

/*
 * heal(s):
 *	The re-wrap of each dead index wrap of this machine
 *	(ORC-CANARY-8). The session holds the index key here, so one
 *	canary check per dead wrap gives the canary mask of that
 *	oracle, and the wrap follows it.
 *
 *	An oracle that already failed a request of this session takes
 *	no second one, and the report names the dead wrap. A wrap
 *	that stays dead costs the preference of ORC-QUORUM-2, and it
 *	costs no reveal.
 */
static void
heal(struct session *s)
{
	unsigned char	 share[DERIVE_KEYLEN];
	unsigned int	 i;
	int		 live, rv;

	for (i = 1; i <= s->config.count; i++) {
		if (s->config.oracle[i - 1].retired || wrap_live(s, i))
			continue;
		rv = s->state[i];
		if (rv == STATE_UNTRIED || rv == STATE_PASS) {
			rv = canary_take(s, i, s->idxkey, share, &live);
			if (rv == 0)
				continue;
		}
		warnx("the index wrap of oracle %u (%s) stays dead, and %s",
		    i, s->config.oracle[i - 1].url, state_text(rv));
		warnx("the provisioning ceremony writes it again");
	}
	explicit_bzero(share, sizeof(share));
}

/*
 * unlock(s):
 *	The unlock of the session, in the order of PROG-REPL-1. The
 *	passphrase enters once, through readpassphrase(3) of the core
 *	process (SEC-MEMORY-4, PROG-IFACE-3).
 *
 *	The k canary answers of the quorum carry the index shares of
 *	this machine, so the index opens with no request of its own
 *	(ORC-CANARY-3, VAULT-INDEX-3). A quorum that covers fewer
 *	than k live index wraps leaves the index closed, and the
 *	session opens (ORC-CANARY-8).
 */
static int
unlock(struct session *s)
{
	unsigned char	 shares[DERIVE_ORACLE_MAX * DERIVE_KEYLEN];
	int		 live[DERIVE_ORACLE_MAX];
	unsigned int	 i, count = 0;
	int		 rv = -1;

	memset(shares, 0, sizeof(shares));
	memset(live, 0, sizeof(live));
	if (config_read(s) != 0 || factor_read(s) != 0)
		goto out;
	for (i = 1; i <= s->config.count; i++)
		s->state[i] = STATE_UNTRIED;

	if (fugupass_passphrase("Passphrase: ", s->pass,
	    sizeof(s->pass)) != 0) {
		warnx("the passphrase: the read fails");
		goto out;
	}
	s->passlen = strlen(s->pass);

	candidates(s);
	if (quorum_take(s, shares, live) != 0)
		goto out;

	/*
	 * The index opens while the quorum covers k live index wraps
	 * of this machine, and k is the count of the quorum
	 * (ORC-QUORUM-2, ORC-CANARY-8).
	 */
	for (i = 0; i < s->quorumlen; i++)
		if (live[i])
			count++;
	if (count < s->quorumlen) {
		index_dead(s);
		rv = 0;
		goto out;
	}
	if (share_combine(s->quorum, shares, s->quorumlen, s->idxkey,
	    sizeof(s->idxkey)) != 0)
		goto out;
	if (index_open(s) != 0)
		goto out;
	s->opened = 1;

	/* The session holds K_idx here, so a dead wrap heals now. */
	heal(s);
	rv = 0;
out:
	explicit_bzero(shares, sizeof(shares));
	return rv;
}

/*
 * substitute(s, victim):
 *	The next untried candidate, in the place victim of the
 *	session quorum (ORC-QUORUM-5). The canary check of the
 *	candidate comes before the substitution, so no entry record
 *	of it takes a request first (ORC-CANARY-1).
 *
 *	A candidate that fails a request steps to the next one, and a
 *	junk answer of a canary stops the session (ORC-CANARY-4). A
 *	walk that runs out of candidates gives -1: no untried quorum
 *	remains.
 */
static int
substitute(struct session *s, unsigned int victim)
{
	unsigned char	 share[DERIVE_KEYLEN];
	unsigned int	 i;
	int		 live, rv, ok = -1;

	while (s->next < s->candlen) {
		i = s->cand[s->next++];
		rv = canary_take(s, i, s->opened ? s->idxkey : NULL, share,
		    &live);
		if (rv == ORACLE_EJUNK)
			goto out;
		if (rv != 0)
			continue;
		s->quorum[victim] = i;
		ok = 0;
		goto out;
	}
	warnx("no untried oracle remains for a substitution");
out:
	explicit_bzero(share, sizeof(share));
	return ok;
}

/*
 * entry_open(s, key):
 *	The entry file of the entry key key, to the plaintext buffer
 *	of the session. The file name is the lowercase hex of H(K_e)
 *	(VAULT-LAYOUT-5), so a key of a wrong reconstruction names
 *	another file.
 *
 *	The call gives EDECRYPT for an absent file and for a failed
 *	open, because both carry one cause: this quorum gives no
 *	entry key of that slot (ORC-QUORUM-4, VAULT-SEAL-4). It gives
 *	-1 for a failure of this machine, and 0 for the plaintext.
 */
static int
entry_open(struct session *s, const unsigned char *key)
{
	struct vault_at	 at;
	char		 path[PATH_MAX];
	size_t		 len = 0;

	if (vault_entry_name(key, DERIVE_KEYLEN, s->file,
	    sizeof(s->file)) != 0)
		return -1;
	memset(&at, 0, sizeof(at));
	at.name = s->file;
	if (vault_path(path, sizeof(path), s->vault, VAULT_FILE_ENTRY,
	    &at) != 0)
		return -1;
	if (vault_read(path, s->raw, RAW_MAX, &len) != 0) {
		warn("%s", path);
		return -1;
	}
	if (len == 0)
		return EDECRYPT;
	if (len <= SEAL_OVERHEAD || len > SESSION_PLAIN_MAX + SEAL_OVERHEAD) {
		warnx("%s: the file is not a sealed file of this vault", path);
		return -1;
	}
	if (seal_open(key, DERIVE_KEYLEN, s->raw, len,
	    (unsigned char *)s->plain, len - SEAL_OVERHEAD) != 0)
		return EDECRYPT;
	s->plainlen = len - SEAL_OVERHEAD;
	return 0;
}

/*
 * reveal(s, slot, keep):
 *	One quorum reveal of the slot index slot (ORC-QUORUM-3,
 *	ORC-QUORUM-4). Each attempt sends one get_pin per quorum
 *	oracle, reconstructs the entry key from the k shares, and
 *	opens the entry file of that key.
 *
 *	A request that fails names its oracle, and that oracle leaves
 *	the quorum. A decrypt failure names no oracle
 *	(ORC-QUORUM-4), so the attempts replace the places of the
 *	quorum in turn. Each attempt names its quorum oracles, and
 *	the substitutions end when no untried oracle remains
 *	(ORC-QUORUM-5).
 *
 *	keep holds the entry key in the session for session_seal(),
 *	and the key of every other reveal leaves memory directly
 *	after the decrypt (SEC-MEMORY-6).
 */
static int
reveal(struct session *s, uint32_t slot, int keep)
{
	unsigned char		 shares[DERIVE_ORACLE_MAX * DERIVE_KEYLEN];
	unsigned char		 key[DERIVE_KEYLEN];
	struct oracle_ctx	 ctx;
	unsigned int		 i, tries = 0, victim = 0;
	int			 n, fail, rv = -1;

	memset(shares, 0, sizeof(shares));
	memset(key, 0, sizeof(key));
	session_drop(s);
	if (s->plainlen != 0) {
		explicit_bzero(s->plain, s->plainlen);
		s->plainlen = 0;
	}

	for (;;) {
		fail = 0;
		for (i = 0; i < s->quorumlen; i++) {
			ctx_of(&ctx, s, s->quorum[i]);
			n = oracle_reveal(&ctx, slot,
			    &shares[i * DERIVE_KEYLEN], DERIVE_KEYLEN, NULL);
			if (n == 0)
				continue;
			s->state[s->quorum[i]] = n;
			warnx("slot %" PRIu32 " at oracle %u (%s): %s", slot,
			    s->quorum[i],
			    s->config.oracle[s->quorum[i] - 1].url,
			    oracle_state_text(n));
			victim = i;
			fail = 1;
			break;
		}

		if (!fail) {
			if (share_combine(s->quorum, shares, s->quorumlen, key,
			    sizeof(key)) != 0)
				goto out;
			n = entry_open(s, key);
			if (n == 0) {
				if (keep) {
					memcpy(s->key, key, sizeof(key));
					s->held = 1;
				}
				rv = 0;
				goto out;
			}
			if (n != EDECRYPT)
				goto out;
			warnx("slot %" PRIu32 ": the entry of this quorum "
			    "does not open", slot);
			victim = tries % s->quorumlen;
		}

		quorum_name(s);
		if (substitute(s, victim) != 0) {
			warnx("slot %" PRIu32 ": the session reveals it no "
			    "other way", slot);
			goto out;
		}
		tries++;
	}
out:
	explicit_bzero(shares, sizeof(shares));
	explicit_bzero(key, sizeof(key));
	if (rv != 0)
		memset(s->file, 0, sizeof(s->file));
	return rv;
}

int
session_open(const char *vault, struct session **out)
{
	struct session	*s;
	int		 n;

	if (vault == NULL || out == NULL)
		return -1;
	*out = NULL;
	if ((s = calloc(1, sizeof(*s))) == NULL)
		return -1;
	n = snprintf(s->vault, sizeof(s->vault), "%s", vault);
	if (n < 0 || (size_t)n >= sizeof(s->vault)) {
		free(s);
		return -1;
	}

	/*
	 * The three buffers hold one sealed file, one entry
	 * plaintext, and the index plaintext with the parts of each
	 * entry of it.
	 */
	s->raw = malloc(RAW_MAX);
	s->plain = malloc(SESSION_PLAIN_MAX);
	s->text = malloc(SESSION_INDEX_MAX);
	s->arena = malloc(SESSION_INDEX_MAX);
	if (s->raw == NULL || s->plain == NULL || s->text == NULL ||
	    s->arena == NULL) {
		session_close(s);
		return -1;
	}
	if (unlock(s) != 0) {
		session_close(s);
		return -1;
	}
	*out = s;
	return 0;
}

void
session_close(struct session *s)
{
	if (s == NULL)
		return;

	/*
	 * The plaintext of the index and of the last reveal each
	 * hold vault data, and the struct holds the passphrase, the
	 * device factor, the index key and the entry key
	 * (SEC-MEMORY-1).
	 */
	if (s->raw != NULL) {
		explicit_bzero(s->raw, RAW_MAX);
		free(s->raw);
	}
	if (s->plain != NULL) {
		explicit_bzero(s->plain, SESSION_PLAIN_MAX);
		free(s->plain);
	}
	if (s->text != NULL) {
		explicit_bzero(s->text, SESSION_INDEX_MAX);
		free(s->text);
	}
	if (s->arena != NULL) {
		explicit_bzero(s->arena, SESSION_INDEX_MAX);
		free(s->arena);
	}
	free(s->list);
	explicit_bzero(s, sizeof(*s));
	free(s);
}

const struct vault_config *
session_config(const struct session *s)
{
	return s == NULL ? NULL : &s->config;
}

const struct session_entry *
session_list(const struct session *s, size_t *count)
{
	if (count == NULL)
		return NULL;
	*count = 0;
	if (s == NULL || !s->opened)
		return NULL;
	*count = s->listlen;
	return s->list;
}

const char *
session_index(const struct session *s, size_t *len)
{
	if (len == NULL)
		return NULL;
	*len = 0;
	if (s == NULL || !s->opened)
		return NULL;
	*len = s->textlen;
	return s->text;
}

int
session_index_write(struct session *s, const char *text, size_t textlen)
{
	char	 path[PATH_MAX];

	if (s == NULL || !s->opened || text == NULL || textlen == 0 ||
	    textlen > SESSION_INDEX_MAX)
		return -1;

	/* The scanner gates the text, so a wrong text writes no file. */
	if (vault_scan(text, textlen, vault_index_fields, index_gate,
	    NULL) != 0) {
		warnx("the index text holds a line that the reader rejects");
		return -1;
	}
	if (vault_path(path, sizeof(path), s->vault, VAULT_FILE_INDEX,
	    NULL) != 0)
		return -1;
	if (vault_seal_write(path, s->idxkey, sizeof(s->idxkey),
	    (const unsigned char *)text, textlen, s->raw, RAW_MAX) != 0) {
		warn("%s", path);
		return -1;
	}
	/* A caller can give the text of session_index() again. */
	if (text != s->text)
		memcpy(s->text, text, textlen);
	s->textlen = textlen;
	return index_parse(s);
}

int
session_slot_ready(const struct session *s, uint32_t slot)
{
	struct vault_at	 at;
	char		 path[PATH_MAX];
	unsigned int	 i, count = 0;

	if (s == NULL || slot > VAULT_SLOT_MAX)
		return -1;
	for (i = 1; i <= s->config.count; i++) {
		if (s->config.oracle[i - 1].retired)
			continue;
		memset(&at, 0, sizeof(at));
		at.slot = slot;
		at.oracle = i;
		if (vault_path(path, sizeof(path), s->vault, VAULT_FILE_WRAP,
		    &at) != 0)
			continue;
		if (access(path, R_OK) == 0)
			count++;
	}
	return count >= s->config.threshold ? 0 : -1;
}

int
session_reveal(struct session *s, uint32_t slot, const char **plain,
    size_t *plainlen)
{
	if (s == NULL || plain == NULL || plainlen == NULL ||
	    slot > VAULT_SLOT_MAX)
		return -1;
	*plain = NULL;
	*plainlen = 0;
	if (reveal(s, slot, 0) != 0)
		return -1;
	*plain = s->plain;
	*plainlen = s->plainlen;
	return 0;
}

int
session_consume(struct session *s, uint32_t slot, const char **plain,
    size_t *plainlen)
{
	if (s == NULL || plain == NULL || plainlen == NULL ||
	    slot > VAULT_SLOT_MAX)
		return -1;
	*plain = NULL;
	*plainlen = 0;
	if (reveal(s, slot, 1) != 0)
		return -1;
	*plain = s->plain;
	*plainlen = s->plainlen;
	return 0;
}

const char *
session_file(const struct session *s)
{
	if (s == NULL || s->file[0] == '\0')
		return NULL;
	return s->file;
}

int
session_seal(struct session *s, const char *plain, size_t plainlen)
{
	struct vault_at	 at;
	char		 path[PATH_MAX];
	int		 rv = -1;

	if (s == NULL || !s->held || plain == NULL || plainlen == 0 ||
	    plainlen > SESSION_PLAIN_MAX)
		return -1;
	memset(&at, 0, sizeof(at));
	at.name = s->file;
	if (vault_path(path, sizeof(path), s->vault, VAULT_FILE_ENTRY,
	    &at) != 0)
		goto out;
	if (vault_seal_write(path, s->key, sizeof(s->key),
	    (const unsigned char *)plain, plainlen, s->raw, RAW_MAX) != 0) {
		warn("%s", path);
		goto out;
	}
	rv = 0;
out:
	/* The entry key leaves memory with the write (SEC-MEMORY-6). */
	session_drop(s);
	return rv;
}

void
session_drop(struct session *s)
{
	if (s == NULL)
		return;
	explicit_bzero(s->key, sizeof(s->key));
	s->held = 0;
}

int
session_canary(struct session *s, unsigned int oracle)
{
	struct oracle_ctx	 ctx;
	struct vault_at		 at;
	char			 again[FUGUPASS_PASS_MAX];
	char			 path[PATH_MAX];
	size_t			 len;
	int			 n, rv = -1;

	if (s == NULL || oracle == 0 || oracle > s->config.count ||
	    s->config.oracle[oracle - 1].retired)
		return -1;

	/*
	 * A canary enrollment takes two reads of the passphrase
	 * (ORC-CANARY-6). The unlock of the session read it once,
	 * and this step reads it again. The comparison runs in
	 * constant time (SEC-MEMORY-2).
	 */
	if (fugupass_passphrase("Passphrase again: ", again,
	    sizeof(again)) != 0) {
		warnx("the passphrase: the read fails");
		return -1;
	}
	len = strlen(again);
	if (len != s->passlen || timingsafe_bcmp(again, s->pass, len) != 0) {
		warnx("the passphrase: the two reads differ");
		goto out;
	}

	/*
	 * The canary mask of the fresh record wraps this machine's
	 * index share of the oracle, so a session that holds K_idx
	 * re-wraps with the enrollment (ORC-CANARY-3, ORC-CANARY-8).
	 */
	ctx_of(&ctx, s, oracle);
	if (s->opened)
		n = oracle_canary_index(&ctx, again, len, s->idxkey,
		    sizeof(s->idxkey));
	else
		n = oracle_canary_enroll(&ctx, again, len);
	if (n != 0) {
		warnx("the canary of oracle %u (%s): %s", oracle,
		    s->config.oracle[oracle - 1].url, oracle_state_text(n));
		goto out;
	}
	if (s->opened) {
		rv = 0;
		goto out;
	}

	/*
	 * The session holds no index key, so this machine's index
	 * wrap of the oracle is dead, and the file of it goes. The
	 * absent file is the detectable state (ORC-CANARY-8).
	 */
	memset(&at, 0, sizeof(at));
	at.oracle = oracle;
	if (vault_path(path, sizeof(path), s->vault, VAULT_FILE_WRAP_INDEX,
	    &at) != 0)
		goto out;
	if (unlink(path) == -1 && errno != ENOENT) {
		warn("%s", path);
		goto out;
	}
	warnx("the index wrap of oracle %u is gone: the provisioning "
	    "ceremony writes it again", oracle);
	rv = 0;
out:
	explicit_bzero(again, sizeof(again));
	return rv;
}
