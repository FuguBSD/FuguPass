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
 * Vault creation, the pool refill, and machine provisioning.
 * ceremony.h states the interface. CER-CREATE holds eight rules,
 * the rules are the steps, and ceremony_create() calls one function
 * of each step in rule order.
 *
 * step_master() is CER-CREATE-1, step_factor() is CER-CREATE-2,
 * step_config() is CER-CREATE-3, and step_passphrase() is
 * CER-CREATE-4. step_canaries() is CER-CREATE-5, step_slots() is
 * CER-CREATE-6, and step_index() is CER-CREATE-7. The erasure of
 * CER-CREATE-8 sits in ceremony_create().
 *
 * ceremony_refill() is the pool refill, the second ceremony of this
 * file (CER-REFILL). It reads the config of the vault and the device
 * factor of this machine. It scans a plate, and it opens the index
 * under K_idx. It then reserves the next sequential slot indexes,
 * and it runs step_slot() for each new slot (CER-REFILL-2). The two
 * ceremonies therefore hold one slot loop, and a new slot of a
 * refill takes the steps of CER-CREATE-6.
 *
 * refill_canaries() is the verification of CER-REFILL-7, before the
 * slot loop. index_write() records the new pool state, after the
 * slot loop. An interrupted refill therefore leaves the index as it
 * was, and the re-run reserves the same indexes again.
 *
 * ceremony_provision() is machine provisioning, the third ceremony
 * of this file (CER-PROVISION). It adds this machine to a vault
 * whose shared set a copy brought here (CER-PROVISION-2). It scans
 * a plate, it opens the index under K_idx, and it reads the machine
 * registry of it. provision_name() is the registry part of
 * CER-PROVISION-3, and step_factor() is the rest of it.
 * step_config() is CER-PROVISION-4, and step_passphrase() is
 * CER-PROVISION-5. provision_canaries() is CER-PROVISION-6, and
 * provision_slots() is CER-PROVISION-7: it runs slot_enroll() over
 * each existing slot, for the pairs with no wrap of this machine
 * (CER-PROVISION-12). provision_index_write() is CER-PROVISION-8,
 * and the erasure of CER-PROVISION-10 sits in ceremony_provision().
 * The three ceremonies therefore hold one enrollment loop of a
 * slot, and slot_enroll() is that loop.
 *
 * A provisioning re-run keeps each record that this machine holds
 * (CER-PROVISION-12). provision_canaries() verifies the passphrase
 * at each sealed canary, heals a dead index wrap under the answer,
 * and enrolls a canary again after a junk answer that follows a
 * pass at another oracle. A change of the oracle list or of the
 * threshold is a variant of this ceremony (CER-PROVISION-13 to
 * CER-PROVISION-17), and provision_old() refuses it: no variant
 * runs here.
 *
 * The steps come from the other files of the tree. helper.c runs
 * the scan helper, derive.c holds each label and the master gate,
 * bip85.c holds the two candidates, oracle.c holds each record and
 * each wrap, envelope.c holds the client public key, and vault.c
 * holds every path, the seal and the one writer. This file adds the
 * order of the steps, the text of the config and the index, and
 * the erasure.
 *
 * The secrets of the ceremony live in one struct state. The
 * allocation of it never moves, so one explicit_bzero(3) of it
 * clears each one (SEC-MEMORY-1). K_e lives in the slot loop, and
 * that loop clears it at each exit of a slot. Every share and every
 * mask lives in oracle.c, and that file clears each one
 * (ORC-ENROLL-3).
 *
 * The report of a failed step goes to the standard error, and a
 * failed enrollment names its oracle (CER-CREATE-6).
 * oracle_state_text() gives the text of each state of a request,
 * and the tool holds the four states apart (ORC-REVEAL-6,
 * ORC-REVEAL-8).
 */

#include <sys/stat.h>

#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bip85.h"
#include "ceremony.h"
#include "change.h"
#include "derive.h"
#include "entry.h"
#include "fugupass.h"
#include "helper.h"
#include "iface.h"
#include "oracle.h"
#include "seal.h"
#include "session.h"
#include "vault.h"

/*
 * One line of the config file: the longest field name of the
 * oracle rows, and the longest value that a position takes
 * (VAULT-CONFIG, ORC-PROVISION-1).
 */
#define CONFIG_LINE_MAX	(sizeof("oracle-255: ") + VAULT_OKEY_MAX + 1 + \
			    VAULT_URL_MAX + 1)

/* The config file: one line of each position, and the fixed rows. */
#define CONFIG_MAX	(DERIVE_ORACLE_MAX * CONFIG_LINE_MAX + 512)

/* The slot file: the two candidates, the slot row, and the names. */
#define SLOT_MAX	(BIP85_PWD_MAX + BIP85_MNEMONIC_MAX + 96)

/* The index of a new vault: the machine row and the pool rows. */
#define INDEX_MAX	(DERIVE_MACHINE_MAX + CEREMONY_POOL_MAX * 11 + 96)

/*
 * The bytes of the sealed index, and one more. A count of this
 * value names a file that is too long (vault.h). session.h states
 * the plaintext bound of the index.
 */
#define INDEX_RAW_MAX	(SESSION_INDEX_MAX + SEAL_OVERHEAD + 1)

/*
 * The state of one canary of a provisioning, by oracle index
 * (CER-PROVISION-6, CER-PROVISION-12). A retired position holds
 * none.
 */
enum canary_state {
	CANARY_NONE,	/* a retired position */
	CANARY_CHECK,	/* a seal exists, and the check runs */
	CANARY_KEEP,	/* the check passed */
	CANARY_ENROLL,	/* no seal exists, and the enrollment runs */
	CANARY_STALE	/* the check failed after a pass: the enrollment runs */
};

/*
 * The state of one ceremony. The master, root, the index key and
 * the passphrase are the secrets of CER-CREATE-8, of CER-REFILL-6
 * and of CER-PROVISION-10. The device factor persists on disk, so
 * the three rules hold no erasure of it (KEY-DEVICE-2).
 *
 * The three ceremonies share this state, and each one fills the
 * members that its steps read. arg is the command line of one
 * creation or of one provisioning, and a refill takes each tunable
 * of the config file.
 *
 * The three buffers and the four members below them belong to the
 * refill and to the provisioning. raw takes the sealed index, plain
 * takes the plaintext of it, and text takes the plaintext of the
 * write. free is the free slots of the pool, next is the lowest
 * unreserved slot index, and add is the slots of this refill
 * (VAULT-INDEX-2, ENTRY-POOL-1).
 *
 * The members below add belong to the provisioning. old is the
 * config of this machine before the ceremony, or NULL for a machine
 * with none. name is the machine name that index_line() looks up in
 * the registry, and NULL looks up none. registered and retired hold
 * the result of that lookup (VAULT-INDEX-2). verifier is 1 while a
 * canary check seal of a live oracle exists on this machine
 * (ORC-CANARY-6), and canary holds the state of each canary
 * (CER-PROVISION-12).
 */
struct state {
	const struct ceremony_create	*arg;
	const char			*vault;
	struct vault_config		 config;
	char				 master[DERIVE_MASTER_MAX + 1];
	unsigned char			 root[DERIVE_ROOTLEN];
	unsigned char			 factor[DERIVE_KEYLEN];
	unsigned char			 idxkey[DERIVE_KEYLEN];
	char				 pass[FUGUPASS_PASS_MAX];
	size_t				 passlen;
	unsigned char			*raw;
	char				*plain;
	char				*text;
	size_t				 textlen;
	char				 free[VAULT_VALUE_MAX + 1];
	uint32_t			 next;
	int				 havenext;
	unsigned int			 add;
	struct vault_config		*old;
	const char			*name;
	int				 registered;
	int				 retired;
	int				 verifier;
	unsigned char			 canary[DERIVE_ORACLE_MAX + 1];
};

static void		 hex(const unsigned char *, size_t, char *);
static void		 ctx_of(struct oracle_ctx *, const struct state *,
			    unsigned int);
static int		 machine_dir(const char *);
static int		 file_exists(const struct state *, enum vault_file,
			    const struct vault_at *);
static int		 step_master(struct state *);
static int		 step_factor(struct state *);
static int		 config_append(char *, size_t *, const char *, ...);
static int		 config_text(const struct state *, const char *,
			    char *, size_t *);
static int		 step_config(struct state *);
static int		 step_passphrase(struct state *);
static int		 step_canaries(struct state *);
static int		 slot_enroll(struct state *, uint32_t,
			    const unsigned char *, size_t, int);
static int		 step_slot(struct state *, uint32_t);
static int		 step_slots(struct state *);
static int		 step_index(const struct state *);
static int		 refill_config(struct state *);
static int		 refill_factor(struct state *);
static void		 registry_note(struct state *, const char *, size_t);
static int		 index_line(const struct vault_line *, void *);
static int		 index_read(struct state *);
static int		 refill_reserve(struct state *);
static int		 refill_pass(struct state *);
static int		 refill_canaries(struct state *);
static int		 refill_slots(struct state *);
static int		 index_write(struct state *);
static int		 provision_shared(const struct state *);
static int		 config_same(const struct vault_config *,
			    const struct vault_config *);
static int		 provision_old(struct state *);
static int		 provision_name(const struct state *);
static int		 provision_seals(struct state *);
static int		 provision_canaries(struct state *);
static int		 provision_slot(struct state *, uint32_t);
static int		 provision_slots(struct state *);
static int		 provision_index_write(struct state *);

/*
 * hex(in, inlen, out):
 *	The lowercase hex of the inlen bytes at in, to out. out
 *	takes 2 * inlen bytes and one terminator.
 */
static void
hex(const unsigned char *in, size_t inlen, char *out)
{
	size_t	 i;

	for (i = 0; i < inlen; i++)
		snprintf(&out[2 * i], 3, "%02x", in[i]);
}

/*
 * ctx_of(ctx, st, oracle):
 *	The record context of the oracle index oracle, from the
 *	state st. oracle.c gates each field of it.
 */
static void
ctx_of(struct oracle_ctx *ctx, const struct state *st, unsigned int oracle)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->vault = st->vault;
	ctx->config = &st->config;
	ctx->factor = st->factor;
	ctx->factorlen = sizeof(st->factor);
	ctx->pass = st->pass;
	ctx->passlen = st->passlen;
	ctx->oracle = oracle;
}

/*
 * machine_dir(vault):
 *	Make the machine-local directory of the vault directory
 *	vault (VAULT-LAYOUT-4). main() of fugupass.c makes the vault
 *	directory, and this call makes the one subdirectory of it.
 */
static int
machine_dir(const char *vault)
{
	char	 path[PATH_MAX];
	int	 n;

	n = snprintf(path, sizeof(path), "%s/%s", vault, VAULT_MACHINE_DIR);
	if (n < 0 || (size_t)n >= sizeof(path)) {
		warnx("%s: the path of the machine directory does not fit",
		    vault);
		return -1;
	}
	if (mkdir(path, S_IRWXU) == -1 && errno != EEXIST) {
		warn("%s", path);
		return -1;
	}
	return 0;
}

/*
 * file_exists(st, kind, at):
 *	1 when the file kind kind of the vault at at exists, 0 when
 *	it is absent, and -1 for a path that does not fit or a
 *	lookup that fails with another cause. The provisioning reads
 *	the presence of a file, and never its bytes, to select the
 *	pairs of the loop and the canaries of the check
 *	(CER-PROVISION-12).
 */
static int
file_exists(const struct state *st, enum vault_file kind,
    const struct vault_at *at)
{
	char	 path[PATH_MAX];

	if (vault_path(path, sizeof(path), st->vault, kind, at) != 0) {
		warnx("%s: a path of the vault does not fit", st->vault);
		return -1;
	}
	if (access(path, F_OK) == 0)
		return 1;
	if (errno == ENOENT)
		return 0;
	warn("%s", path);
	return -1;
}

/*
 * step_master(st):
 *	CER-CREATE-1. The master comes from a SeedQR scan of a
 *	plate, and the scan helper gives the words of it as one line
 *	of text (PROG-SCAN-5, PROG-SPLIT-2).
 *
 *	The gate of the master rejects a count other than 12 words,
 *	and a wrong BIP39 checksum. The message of the gate names
 *	the count or the checksum, and it holds no word
 *	(KEY-MASTER-6).
 */
static int
step_master(struct state *st)
{
	char	 err[DERIVE_ERRLEN];
	char	*feed;
	size_t	 len = 0;

	if (helper_run(HELPER_SCAN, NULL, 0, st->master, sizeof(st->master),
	    &len) != 0) {
		warnx("the plate scan fails");
		return -1;
	}

	/* The helper writes one line, and the master is that line. */
	if ((feed = memchr(st->master, '\n', len)) != NULL)
		len = (size_t)(feed - st->master);
	while (len > 0 && st->master[len - 1] == '\r')
		len--;
	st->master[len] = '\0';

	if (derive_master_check(st->master, len, err, sizeof(err)) != 0) {
		warnx("the master: %s", err);
		return -1;
	}
	if (derive_root(st->master, len, st->root, sizeof(st->root)) != 0) {
		warnx("the master: the seed of it fails");
		return -1;
	}
	return 0;
}

/*
 * step_factor(st):
 *	CER-CREATE-2. The device factor of this machine is
 *	X = f(root, "fugupass/v1/device-factor" || machine-name),
 *	and it persists in the machine-local set (KEY-DEVICE-1,
 *	KEY-DEVICE-2, VAULT-LAYOUT-4).
 */
static int
step_factor(struct state *st)
{
	char	 path[PATH_MAX];

	if (derive_device_factor(st->root, sizeof(st->root), st->arg->machine,
	    strlen(st->arg->machine), st->factor, sizeof(st->factor)) != 0) {
		warnx("the device factor: the machine name is wrong");
		return -1;
	}
	if (vault_path(path, sizeof(path), st->vault, VAULT_FILE_FACTOR,
	    NULL) != 0) {
		warnx("%s: the path of the factor file does not fit",
		    st->vault);
		return -1;
	}
	if (vault_write(path, st->factor, sizeof(st->factor)) != 0) {
		warn("%s", path);
		return -1;
	}
	return 0;
}

/*
 * config_append(text, len, fmt, ...):
 *	One or more lines of the config file, at the len bytes at
 *	text, and the new count to len. The room is CONFIG_MAX
 *	bytes, and a text that does not fit gives -1.
 */
static int
config_append(char *text, size_t *len, const char *fmt, ...)
{
	va_list	 ap;
	int	 n;

	va_start(ap, fmt);
	n = vsnprintf(&text[*len], CONFIG_MAX - *len, fmt, ap);
	va_end(ap);
	if (n < 0 || (size_t)n >= CONFIG_MAX - *len) {
		warnx("the config: the text does not fit");
		return -1;
	}
	*len += (size_t)n;
	return 0;
}

/*
 * config_text(st, plate, text, len):
 *	The text of the config file of the command line of st, to
 *	the CONFIG_MAX bytes at text, and the count of it to len
 *	(VAULT-CONFIG-1). plate is the plate check value as hex, and
 *	NULL leaves that line out: the gate of a provisioning reads
 *	the command line before the plate scan.
 *
 *	The four tunables come from the config that this machine
 *	holds, when old of st holds one, so a re-run keeps each
 *	value that the operator set (ENTRY-POOL-2, ENTRY-POOL-6,
 *	ENTRY-SHADOW-6, PROG-REPL-11). A value of 0 is an absent
 *	line, and it takes the default. A creation takes the pool
 *	size of the command line and the default of each other one.
 */
static int
config_text(const struct state *st, const char *plate, char *text,
    size_t *len)
{
	const struct vault_config	*old = st->old;
	unsigned int			 i;
	unsigned int			 pool = st->arg->pool;
	unsigned int			 mark = CEREMONY_POOL_WATERMARK;
	unsigned int			 age = ENTRY_AUDIT_AGE_DEFAULT;
	unsigned int			 lock = IFACE_LOCK_TIMEOUT_DEFAULT;

	if (old != NULL) {
		pool = old->pool_size != 0 ? old->pool_size : pool;
		mark = old->pool_watermark != 0 ? old->pool_watermark : mark;
		age = old->audit_age != 0 ? old->audit_age : age;
		lock = old->lock_timeout != 0 ? old->lock_timeout : lock;
	}

	*len = 0;
	for (i = 0; i < st->arg->count; i++) {
		if (config_append(text, len, "oracle-%u: %s\n", i + 1,
		    st->arg->oracle[i]) != 0)
			return -1;
	}
	if (config_append(text, len,
	    "threshold: %u\nmachine-name: %s\nkdf-rounds: %u\n",
	    st->arg->threshold, st->arg->machine, st->arg->rounds) != 0)
		return -1;
	if (plate != NULL &&
	    config_append(text, len, "plate-check: %s\n", plate) != 0)
		return -1;
	return config_append(text, len,
	    "pool-size: %u\npool-watermark: %u\naudit-age: %u\n"
	    "lock-timeout: %u\n", pool, mark, age, lock);
}

/*
 * step_config(st):
 *	CER-CREATE-3 and CER-PROVISION-4. The config file holds the
 *	ordered oracle set, the threshold, the machine name, the
 *	round count, the plate check value, the pool tunables, the
 *	audit age and the lock timeout (VAULT-CONFIG-1, KEY-MASTER-5,
 *	ENTRY-POOL-2, ENTRY-POOL-6, ENTRY-SHADOW-6, PROG-REPL-11).
 *	config_text() gives the text, and the operator edits the
 *	tunables of the file.
 *
 *	The reader of vault.c holds each rule of the file, so this
 *	step parses the text before it writes the file. A wrong
 *	oracle value, a gap in the positions, and a threshold above
 *	the live count therefore write no file (VAULT-CONFIG-6).
 *
 *	The parsed config also serves each record of the ceremony,
 *	and oracle.c reads the oracle of a position from it.
 */
static int
step_config(struct state *st)
{
	unsigned char	 check[DERIVE_KEYLEN];
	char		 plate[VAULT_NAMELEN];
	char		 path[PATH_MAX];
	char		*text = NULL;
	size_t		 len = 0;
	int		 rv = -1;

	if (derive_plate_check(st->root, sizeof(st->root), check,
	    sizeof(check)) != 0) {
		warnx("the config: the plate check value fails");
		goto out;
	}
	hex(check, sizeof(check), plate);
	if ((text = malloc(CONFIG_MAX)) == NULL) {
		warn("the config");
		goto out;
	}
	if (config_text(st, plate, text, &len) != 0)
		goto out;
	if (vault_config_read(text, len, &st->config) != 0) {
		warnx("the config: an oracle value or the threshold is wrong");
		goto out;
	}
	if (vault_path(path, sizeof(path), st->vault, VAULT_FILE_CONFIG,
	    NULL) != 0) {
		warnx("%s: the path of the config file does not fit",
		    st->vault);
		goto out;
	}
	if (vault_write(path, (const unsigned char *)text, len) != 0) {
		warn("%s", path);
		goto out;
	}
	rv = 0;
out:
	explicit_bzero(check, sizeof(check));
	free(text);
	return rv;
}

/*
 * step_passphrase(st):
 *	CER-CREATE-4 and CER-PROVISION-5. readpassphrase(3) reads the
 *	passphrase twice, and a mismatch stops the ceremony
 *	(SEC-MEMORY-4). A creation verifies this value against no
 *	canary record, so the warning of ORC-CANARY-6 comes first. A
 *	provisioning re-run verifies it at each sealed canary before
 *	any set_pin, and verifier of st then holds 1
 *	(CER-PROVISION-12).
 */
static int
step_passphrase(struct state *st)
{
	int	 rv;

	if (!st->verifier)
		warnx("no file verifies this passphrase: a mistyped "
		    "passphrase enrolls at every oracle");
	rv = fugupass_passphrase_new(st->pass, sizeof(st->pass));
	if (rv == FUGUPASS_EMISMATCH) {
		warnx("the passphrase: the two reads differ");
		return -1;
	}
	if (rv != 0) {
		warnx("the passphrase: the read fails");
		return -1;
	}
	st->passlen = strlen(st->pass);
	return 0;
}

/*
 * step_canaries(st):
 *	CER-CREATE-5. Each live oracle takes one canary enrollment,
 *	one immediate get_pin, and the seal of its canary check
 *	value (ORC-CANARY-7, ORC-CANARY-11). The index key splits,
 *	and this machine's index wrap of each oracle persists
 *	(KEY-MASK-6, KEY-MASK-7, KEY-SHARE-5).
 *
 *	K_idx derives before the loop, because the canary mask of an
 *	oracle wraps that oracle's index share. The wrap therefore
 *	rides on the enrollment of the oracle (ORC-CANARY-3).
 *
 *	The two reads of the passphrase happen in step_passphrase(),
 *	and this step gives the matched value to both arguments of
 *	the enrollment (ORC-CANARY-6).
 */
static int
step_canaries(struct state *st)
{
	struct oracle_ctx	 ctx;
	unsigned int		 i;
	int			 rv;

	if (derive_index_key(st->root, sizeof(st->root), st->idxkey,
	    sizeof(st->idxkey)) != 0) {
		warnx("the index key fails");
		return -1;
	}
	for (i = 1; i <= st->config.count; i++) {
		if (st->config.oracle[i - 1].retired)
			continue;
		ctx_of(&ctx, st, i);
		rv = oracle_canary_index(&ctx, st->pass, st->passlen,
		    st->idxkey, sizeof(st->idxkey));
		if (rv != 0) {
			warnx("the canary of oracle %u (%s): %s", i,
			    st->config.oracle[i - 1].url, oracle_state_text(rv));
			return -1;
		}
	}
	return 0;
}

/*
 * slot_enroll(st, slot, key, keylen, every):
 *	The enrollment of the slot index slot at each live oracle in
 *	list order, with the entry key K_e of keylen bytes at key
 *	(CER-CREATE-6, CER-PROVISION-7). oracle_enroll() verifies the
 *	HTTP success of each enrollment and persists the wrap of that
 *	oracle (ORC-ENROLL-2, ORC-ENROLL-3). A failure stops the
 *	ceremony with the oracle named.
 *
 *	every takes 1 for each pair of the slot, and 0 for the pairs
 *	with no wrap of this machine: a provisioning re-run passes
 *	over each wrap that exists (CER-PROVISION-12). A creation and
 *	a refill enroll every pair, and a re-run of a stopped one
 *	completes the pool: a fresh set_pin replaces the record, and
 *	the wrap comes from the re-derived share.
 */
static int
slot_enroll(struct state *st, uint32_t slot, const unsigned char *key,
    size_t keylen, int every)
{
	struct oracle_ctx	 ctx;
	struct vault_at		 at;
	unsigned int		 i;
	int			 n;

	for (i = 1; i <= st->config.count; i++) {
		if (st->config.oracle[i - 1].retired)
			continue;
		if (!every) {
			memset(&at, 0, sizeof(at));
			at.slot = slot;
			at.oracle = i;
			if ((n = file_exists(st, VAULT_FILE_WRAP, &at)) < 0)
				return -1;
			if (n == 1)
				continue;
		}
		ctx_of(&ctx, st, i);
		n = oracle_enroll(&ctx, slot, key, keylen);
		if (n != 0) {
			warnx("slot %" PRIu32 " at oracle %u (%s): %s", slot,
			    i, st->config.oracle[i - 1].url, oracle_state_text(n));
			return -1;
		}
	}
	return 0;
}

/*
 * step_slot(st, slot):
 *	One slot of the pool, in the order of CER-CREATE-6. The step
 *	derives K_e, materializes the two BIP85 candidates, enrolls
 *	the record at each live oracle with slot_enroll(), and seals
 *	the slot file last (KEY-ENTRY-2, KEY-BIP85-5, ENTRY-POOL-1).
 *
 *	The slot file name is the lowercase hex of H(K_e), and the
 *	file seals under K_e (VAULT-LAYOUT-5, KEY-ENTRY-3). The
 *	secret fields lead the plaintext (VAULT-FORMAT-4).
 */
static int
step_slot(struct state *st, uint32_t slot)
{
	struct vault_at		 at;
	unsigned char		 key[DERIVE_KEYLEN];
	unsigned char		 sealed[SLOT_MAX + SEAL_OVERHEAD];
	char			 password[BIP85_PWD_MAX];
	char			 mnemonic[BIP85_MNEMONIC_MAX];
	char			 plain[SLOT_MAX];
	char			 name[VAULT_NAMELEN];
	char			 path[PATH_MAX];
	size_t			 len;
	int			 n, rv = -1;

	if (derive_entry_key(st->root, sizeof(st->root), slot, key,
	    sizeof(key)) != 0) {
		warnx("slot %" PRIu32 ": the entry key fails", slot);
		goto out;
	}
	if (bip85_pwd_base64(st->root, sizeof(st->root), slot, password,
	    sizeof(password)) != 0 ||
	    bip85_bip39(st->root, sizeof(st->root), slot, mnemonic,
	    sizeof(mnemonic)) != 0) {
		warnx("slot %" PRIu32 ": a candidate fails", slot);
		goto out;
	}
	if (slot_enroll(st, slot, key, sizeof(key), 1) != 0)
		goto out;

	n = snprintf(plain, sizeof(plain),
	    "candidate-password: %s\n"
	    "candidate-mnemonic: %s\n"
	    "slot: %" PRIu32 "\n", password, mnemonic, slot);
	if (n < 0 || (size_t)n >= sizeof(plain)) {
		warnx("slot %" PRIu32 ": the text does not fit", slot);
		goto out;
	}
	len = (size_t)n;

	if (vault_entry_name(key, sizeof(key), name, sizeof(name)) != 0) {
		warnx("slot %" PRIu32 ": the name of the entry file fails",
		    slot);
		goto out;
	}
	memset(&at, 0, sizeof(at));
	at.name = name;
	if (vault_path(path, sizeof(path), st->vault, VAULT_FILE_ENTRY,
	    &at) != 0) {
		warnx("%s: the path of the entry file does not fit",
		    st->vault);
		goto out;
	}
	if (vault_seal_write(path, key, sizeof(key),
	    (const unsigned char *)plain, len, sealed, sizeof(sealed)) != 0) {
		warn("%s", path);
		goto out;
	}
	rv = 0;
out:
	/*
	 * K_e, the two candidates and the plaintext leave memory at
	 * each exit of the slot (CER-CREATE-8, SEC-MEMORY-5).
	 */
	explicit_bzero(key, sizeof(key));
	explicit_bzero(password, sizeof(password));
	explicit_bzero(mnemonic, sizeof(mnemonic));
	explicit_bzero(plain, sizeof(plain));
	explicit_bzero(sealed, sizeof(sealed));
	return rv;
}

/*
 * step_slots(st):
 *	CER-CREATE-6. The slot loop runs over each slot of the pool.
 *	The pool of a new vault holds the slots of the command line,
 *	and the slot indexes of it start at 0 (ENTRY-POOL-2,
 *	KEY-ENTRY-1).
 */
static int
step_slots(struct state *st)
{
	uint32_t	 slot;

	for (slot = 0; slot < st->arg->pool; slot++) {
		if (step_slot(st, slot) != 0)
			return -1;
	}
	return 0;
}

/*
 * step_index(st):
 *	CER-CREATE-7. The index seals under K_idx, and it holds this
 *	machine's name in the registry (VAULT-INDEX-1,
 *	VAULT-INDEX-2). A new vault holds no entry, and each slot of
 *	the pool is free.
 */
static int
step_index(const struct state *st)
{
	unsigned char	 sealed[INDEX_MAX + SEAL_OVERHEAD];
	char		 plain[INDEX_MAX];
	char		 path[PATH_MAX];
	uint32_t	 slot;
	size_t		 len = 0;
	int		 n;

	n = snprintf(plain, sizeof(plain), "machine: %s\npool-free: ",
	    st->arg->machine);
	if (n < 0 || (size_t)n >= sizeof(plain)) {
		warnx("the index: the text does not fit");
		return -1;
	}
	len = (size_t)n;
	for (slot = 0; slot < st->arg->pool; slot++) {
		n = snprintf(&plain[len], sizeof(plain) - len, "%s%" PRIu32,
		    slot == 0 ? "" : ",", slot);
		if (n < 0 || (size_t)n >= sizeof(plain) - len) {
			warnx("the index: the text does not fit");
			return -1;
		}
		len += (size_t)n;
	}
	n = snprintf(&plain[len], sizeof(plain) - len, "\npool-next: %u\n",
	    st->arg->pool);
	if (n < 0 || (size_t)n >= sizeof(plain) - len) {
		warnx("the index: the text does not fit");
		return -1;
	}
	len += (size_t)n;

	if (vault_path(path, sizeof(path), st->vault, VAULT_FILE_INDEX,
	    NULL) != 0) {
		warnx("%s: the path of the index file does not fit",
		    st->vault);
		return -1;
	}
	if (vault_seal_write(path, st->idxkey, sizeof(st->idxkey),
	    (const unsigned char *)plain, len, sealed, sizeof(sealed)) != 0) {
		warn("%s", path);
		return -1;
	}
	return 0;
}

int
ceremony_create(const struct ceremony_create *arg)
{
	struct state	*st;
	int		 rv = -1;

	if (arg == NULL || arg->vault == NULL || arg->machine == NULL ||
	    arg->oracle == NULL || arg->count == 0 || arg->threshold == 0 ||
	    arg->rounds == 0 || arg->pool == 0) {
		warnx("the ceremony takes an incomplete argument set");
		return -1;
	}
	if (arg->count > DERIVE_ORACLE_MAX) {
		warnx("the oracle set takes %d positions at the most",
		    DERIVE_ORACLE_MAX);
		return -1;
	}
	if (arg->pool > CEREMONY_POOL_MAX) {
		warnx("the pool takes %d slots at the most",
		    CEREMONY_POOL_MAX);
		return -1;
	}
	if (machine_dir(arg->vault) != 0)
		return -1;
	if ((st = calloc(1, sizeof(*st))) == NULL) {
		warn("the ceremony");
		return -1;
	}
	st->arg = arg;
	st->vault = arg->vault;

	if (step_master(st) != 0)
		goto out;
	if (step_factor(st) != 0)
		goto out;
	if (step_config(st) != 0)
		goto out;
	if (step_passphrase(st) != 0)
		goto out;
	if (step_canaries(st) != 0)
		goto out;
	if (step_slots(st) != 0)
		goto out;
	if (step_index(st) != 0)
		goto out;
	rv = 0;
out:
	/*
	 * CER-CREATE-8. M, root and K_idx leave memory here, on the
	 * pass and on every failure path. The passphrase leaves as
	 * well (SEC-MEMORY-4, SEC-MEMORY-5). Every K_e, every share
	 * and every mask left memory in the step that held it.
	 */
	explicit_bzero(st->master, sizeof(st->master));
	explicit_bzero(st->root, sizeof(st->root));
	explicit_bzero(st->idxkey, sizeof(st->idxkey));
	explicit_bzero(st->pass, sizeof(st->pass));
	st->passlen = 0;

	explicit_bzero(st, sizeof(*st));
	free(st);
	return rv;
}

/*
 * refill_config(st):
 *	The config file of the vault, to the state (VAULT-CONFIG-1,
 *	VAULT-CONFIG-2). The reader holds the position rule of the
 *	file, so this step adds no gate (VAULT-CONFIG-6).
 *
 *	The refill takes the oracle set, the threshold and the pool
 *	size of the vault from this file. The creation writes the
 *	file, and the operator edits the two tunables of it
 *	(ENTRY-POOL-2).
 */
static int
refill_config(struct state *st)
{
	char	 path[PATH_MAX];
	char	*text;
	size_t	 len = 0;
	int	 rv = -1;

	if (vault_path(path, sizeof(path), st->vault, VAULT_FILE_CONFIG,
	    NULL) != 0) {
		warnx("%s: the path of the config file does not fit",
		    st->vault);
		return -1;
	}
	if ((text = malloc(CONFIG_MAX)) == NULL) {
		warn("the config");
		return -1;
	}
	if (vault_read(path, (unsigned char *)text, CONFIG_MAX, &len) != 0) {
		warn("%s", path);
		goto out;
	}
	if (len == 0 || len == CONFIG_MAX) {
		warnx("%s: the config file is absent or too long", path);
		goto out;
	}
	if (vault_config_read(text, len, &st->config) != 0) {
		warnx("%s: an oracle position or the threshold is wrong",
		    path);
		goto out;
	}
	rv = 0;
out:
	free(text);
	return rv;
}

/*
 * refill_factor(st):
 *	The device factor X of this machine, to the state
 *	(KEY-DEVICE-1, KEY-DEVICE-2). The creation of the vault wrote
 *	the file, and each record of this machine takes the value of
 *	it (CER-CREATE-2).
 *
 *	A machine with no machine-local set holds no such file, and
 *	the refill stops there. The provisioning ceremony adds a
 *	machine to a vault (CER-PROVISION-3).
 */
static int
refill_factor(struct state *st)
{
	unsigned char	 buf[DERIVE_KEYLEN + 1];
	char		 path[PATH_MAX];
	size_t		 len = 0;
	int		 rv = -1;

	if (vault_path(path, sizeof(path), st->vault, VAULT_FILE_FACTOR,
	    NULL) != 0) {
		warnx("%s: the path of the factor file does not fit",
		    st->vault);
		return -1;
	}
	if (vault_read(path, buf, sizeof(buf), &len) != 0) {
		warn("%s", path);
		goto out;
	}
	if (len != DERIVE_KEYLEN) {
		warnx("%s: the device factor of this machine is absent", path);
		goto out;
	}
	memcpy(st->factor, buf, sizeof(st->factor));
	rv = 0;
out:
	explicit_bzero(buf, sizeof(buf));
	return rv;
}

/*
 * registry_note(st, value, valuelen):
 *	One machine line of the index, against the name of st. The
 *	value is one machine name, or one machine name, one space
 *	and the word retired (VAULT-INDEX-2, VAULT-FORMAT). A match
 *	sets registered, and a match with the mark sets retired as
 *	well (VAULT-INDEX-7).
 */
static void
registry_note(struct state *st, const char *value, size_t valuelen)
{
	static const char	 mark[] = " retired";
	size_t			 namelen = strlen(st->name);

	if (valuelen < namelen || memcmp(value, st->name, namelen) != 0)
		return;
	if (valuelen == namelen)
		st->registered = 1;
	else if (valuelen == namelen + sizeof(mark) - 1 &&
	    memcmp(&value[namelen], mark, sizeof(mark) - 1) == 0)
		st->registered = st->retired = 1;
}

/*
 * index_line(line, arg):
 *	Take one line of the index to the state at arg. The two pool
 *	lines give the pool state of it, and they stay out of the
 *	text of the write. index_write() writes the new state of the
 *	two (VAULT-INDEX-2). A machine line of the name of the state
 *	sets the registry members (CER-PROVISION-3).
 *
 *	Every other line reaches that text again, so the refill and
 *	the provisioning change no entry and no other machine of the
 *	registry (CER-REFILL-4, CER-PROVISION-8).
 */
static int
index_line(const struct vault_line *line, void *arg)
{
	struct state	*st = arg;
	const char	*name = line->field->name;
	int		 n;

	if (strcmp(name, "machine") == 0 && st->name != NULL)
		registry_note(st, line->value, line->valuelen);
	if (strcmp(name, "pool-free") == 0) {
		if (line->valuelen >= sizeof(st->free))
			return -1;
		memcpy(st->free, line->value, line->valuelen + 1);
		return 0;
	}
	if (strcmp(name, "pool-next") == 0) {
		if (vault_number(line->value, line->valuelen, VAULT_SLOT_MAX,
		    &st->next) != 0)
			return -1;
		st->havenext = 1;
		return 0;
	}
	n = snprintf(&st->text[st->textlen], SESSION_INDEX_MAX - st->textlen,
	    "%s: %s\n", name, line->value);
	if (n < 0 || (size_t)n >= SESSION_INDEX_MAX - st->textlen)
		return -1;
	st->textlen += (size_t)n;
	return 0;
}

/*
 * index_read(st):
 *	The index of the vault, under K_idx (VAULT-INDEX-1,
 *	VAULT-INDEX-4). The scan keeps each line of the file for the
 *	write, it takes the pool state of the two pool lines, and it
 *	takes the registry state of the name of st.
 *
 *	The plate gives root, so K_idx derives here and no oracle
 *	request carries a share of it (KEY-MASK-6). An index that
 *	does not open names another master, so this step holds the
 *	plate of this vault (KEY-MASTER-5).
 *
 *	An index with no pool-next line names no slot index. A
 *	reservation from 0 would replace the records of the first
 *	entries, and a provisioning would know no existing slot, so
 *	the ceremony stops there (CER-REFILL-4, CER-PROVISION-7,
 *	KEY-ENTRY-1).
 *
 *	The plaintext of the index is a secret of the vault, and it
 *	leaves memory with the state of the ceremony (SEC-MEMORY-1).
 */
static int
index_read(struct state *st)
{
	char	 path[PATH_MAX];
	size_t	 len = 0;

	if (derive_index_key(st->root, sizeof(st->root), st->idxkey,
	    sizeof(st->idxkey)) != 0) {
		warnx("the index key fails");
		return -1;
	}
	if (vault_path(path, sizeof(path), st->vault, VAULT_FILE_INDEX,
	    NULL) != 0) {
		warnx("%s: the path of the index file does not fit",
		    st->vault);
		return -1;
	}
	if (vault_read(path, st->raw, INDEX_RAW_MAX, &len) != 0) {
		warn("%s", path);
		return -1;
	}
	if (len <= SEAL_OVERHEAD || len == INDEX_RAW_MAX) {
		warnx("%s: the index is absent, or it is not a sealed file "
		    "of this vault", path);
		return -1;
	}
	if (seal_open(st->idxkey, sizeof(st->idxkey), st->raw, len,
	    (unsigned char *)st->plain, len - SEAL_OVERHEAD) != 0) {
		warnx("%s: the index does not open under the index key of "
		    "this plate", path);
		return -1;
	}
	if (vault_scan(st->plain, len - SEAL_OVERHEAD, vault_index_fields,
	    index_line, st) != 0) {
		warnx("%s: the index holds a line that the reader rejects, "
		    "or the text of the write does not fit", path);
		return -1;
	}
	if (!st->havenext) {
		warnx("%s: the index holds no pool-next line, and the "
		    "ceremony takes no slot index from it", path);
		return -1;
	}
	return 0;
}

/*
 * refill_reserve(st):
 *	CER-REFILL-2. The refill reserves the next sequential slot
 *	indexes, from the pool-next line of the index
 *	(VAULT-INDEX-2). The count is the pool size of the config,
 *	and a config with no such line takes CEREMONY_POOL_SIZE
 *	(ENTRY-POOL-2).
 *
 *	Each reserved index stands above every index of every earlier
 *	ceremony, so the slot loop writes the file of no existing
 *	entry (CER-REFILL-4, VAULT-LAYOUT-5).
 *
 *	The new pool-next is the index after the last new slot, and
 *	that value stays inside the form of a number
 *	(VAULT-FORMAT-7, KEY-ENTRY-1).
 */
static int
refill_reserve(struct state *st)
{
	st->add = st->config.pool_size != 0 ? st->config.pool_size :
	    CEREMONY_POOL_SIZE;
	if (st->add > CEREMONY_POOL_MAX) {
		warnx("the pool size takes %d slots at the most",
		    CEREMONY_POOL_MAX);
		return -1;
	}
	if (st->add > (uint32_t)VAULT_SLOT_MAX - st->next) {
		warnx("the pool reaches the highest slot index, and this "
		    "vault takes no refill");
		return -1;
	}
	return 0;
}

/*
 * refill_pass(st):
 *	CER-REFILL-7. readpassphrase(3) reads the passphrase once,
 *	and the canary check of each live oracle verifies it
 *	(SEC-MEMORY-4). A creation reads twice, because no file
 *	verifies the passphrase of a new vault (ORC-CANARY-6).
 */
static int
refill_pass(struct state *st)
{
	if (fugupass_passphrase("Passphrase: ", st->pass,
	    sizeof(st->pass)) != 0) {
		warnx("the passphrase: the read fails");
		return -1;
	}
	st->passlen = strlen(st->pass);
	return 0;
}

/*
 * refill_canaries(st):
 *	CER-REFILL-7. The canary record of each live oracle verifies
 *	the passphrase, before the slot loop (ORC-CANARY-1). The walk
 *	stops at the first failure, so a mistyped passphrase enrolls
 *	no record (ORC-CANARY-4).
 *
 *	The slot loop needs every live oracle, so a failure of one
 *	oracle stops the ceremony here (CER-CREATE-6). A junk answer
 *	names no cause, so the report names the cause set
 *	(ORC-CANARY-9).
 *
 *	The refill takes K_idx from the plate, so it needs no index
 *	share of an answer (ORC-CANARY-3). The share of the check
 *	therefore leaves memory here (KEY-SHARE-8).
 */
static int
refill_canaries(struct state *st)
{
	struct oracle_ctx	 ctx;
	unsigned char		 share[DERIVE_KEYLEN];
	unsigned int		 i;
	int			 live = 0, rv, ok = 0;

	for (i = 1; i <= st->config.count; i++) {
		if (st->config.oracle[i - 1].retired)
			continue;
		ctx_of(&ctx, st, i);
		rv = oracle_canary_check(&ctx, NULL, 0, share, sizeof(share),
		    &live);
		if (rv == 0)
			continue;
		warnx("the canary of oracle %u (%s): %s", i,
		    st->config.oracle[i - 1].url, oracle_state_text(rv));
		if (rv == ORACLE_EJUNK)
			warnx("the cause is the passphrase, or, at oracle %u, "
			    "a wiped canary record, a counter behind the "
			    "record, or a stale canary check seal of this "
			    "machine", i);
		warnx("the refill sends no set_pin");
		ok = -1;
		break;
	}
	explicit_bzero(share, sizeof(share));
	return ok;
}

/*
 * refill_slots(st):
 *	CER-REFILL-2. The slot loop of CER-CREATE-6 runs for each new
 *	slot, and step_slot() is that loop. Each new slot therefore
 *	takes one record at each live oracle, this machine's wrap of
 *	each one, and one sealed slot file (ENTRY-POOL-1).
 */
static int
refill_slots(struct state *st)
{
	unsigned int	 i;

	for (i = 0; i < st->add; i++) {
		if (step_slot(st, st->next + i) != 0)
			return -1;
	}
	return 0;
}

/*
 * index_write(st):
 *	CER-REFILL-2. The new pool state reaches the index. Each new
 *	slot joins the free list, and pool-next takes the index after
 *	the last new slot (VAULT-INDEX-2, ENTRY-POOL-1). A
 *	provisioning adds no slot, so it writes the pool state of the
 *	read as it was (CER-PROVISION-8).
 *
 *	The step follows the slot loop, so an interrupted refill
 *	leaves the index as it was. A re-run reserves the same
 *	indexes again, and a fresh set_pin replaces each record of
 *	them (CER-CREATE-6).
 *
 *	Every other line comes from the read, so the write changes no
 *	entry of the vault (CER-REFILL-4).
 */
static int
index_write(struct state *st)
{
	char		 path[PATH_MAX];
	size_t		 len;
	unsigned int	 i;
	int		 n;

	len = strlen(st->free);
	for (i = 0; i < st->add; i++) {
		n = snprintf(&st->free[len], sizeof(st->free) - len,
		    "%s%" PRIu32, len == 0 ? "" : ",", st->next + i);
		if (n < 0 || (size_t)n >= sizeof(st->free) - len) {
			warnx("the index: the free slots of the pool do not "
			    "fit one line");
			return -1;
		}
		len += (size_t)n;
	}
	n = snprintf(&st->text[st->textlen], SESSION_INDEX_MAX - st->textlen,
	    "pool-free: %s\npool-next: %" PRIu32 "\n", st->free,
	    st->next + st->add);
	if (n < 0 || (size_t)n >= SESSION_INDEX_MAX - st->textlen) {
		warnx("the index: the text does not fit");
		return -1;
	}
	st->textlen += (size_t)n;

	if (vault_path(path, sizeof(path), st->vault, VAULT_FILE_INDEX,
	    NULL) != 0) {
		warnx("%s: the path of the index file does not fit",
		    st->vault);
		return -1;
	}
	if (vault_seal_write(path, st->idxkey, sizeof(st->idxkey),
	    (const unsigned char *)st->text, st->textlen, st->raw,
	    INDEX_RAW_MAX) != 0) {
		warn("%s", path);
		return -1;
	}
	return 0;
}

int
ceremony_refill(const char *vault)
{
	struct state	*st;
	int		 n, rv = -1;

	if (vault == NULL) {
		warnx("the refill takes no vault directory");
		return -1;
	}

	/*
	 * CER-REFILL-8. A marker names an incomplete change, and this
	 * ceremony enrolls a record, so it refuses to start
	 * (CER-PROVISION-18, ORC-ENROLL-10).
	 */
	if ((n = change_pending(vault)) != 0) {
		if (n == 1)
			warnx("this vault holds an incomplete passphrase "
			    "change, and \"%s\" completes it",
			    CHANGE_RESUME_CMD);
		return -1;
	}

	if ((st = calloc(1, sizeof(*st))) == NULL) {
		warn("the refill");
		return -1;
	}
	st->vault = vault;

	/* The three buffers of the index (struct state). */
	st->raw = malloc(INDEX_RAW_MAX);
	st->plain = malloc(SESSION_INDEX_MAX);
	st->text = malloc(SESSION_INDEX_MAX);
	if (st->raw == NULL || st->plain == NULL || st->text == NULL) {
		warn("the refill");
		goto out;
	}

	/*
	 * The two reads of the disk come first, so a vault that this
	 * machine cannot refill takes no plate.
	 */
	if (refill_config(st) != 0)
		goto out;
	if (refill_factor(st) != 0)
		goto out;
	if (step_master(st) != 0)
		goto out;
	if (index_read(st) != 0)
		goto out;
	if (refill_reserve(st) != 0)
		goto out;
	if (refill_pass(st) != 0)
		goto out;
	if (refill_canaries(st) != 0)
		goto out;
	if (refill_slots(st) != 0)
		goto out;
	if (index_write(st) != 0)
		goto out;
	rv = 0;
out:
	/*
	 * CER-REFILL-6. M, root, K_idx and the passphrase leave
	 * memory here, on the pass and on every failure path
	 * (SEC-MEMORY-4, SEC-MEMORY-5). Every new K_e, every share
	 * and every mask left memory in the step that held it. The
	 * three buffers hold vault data, and they leave with it.
	 */
	if (st->raw != NULL) {
		explicit_bzero(st->raw, INDEX_RAW_MAX);
		free(st->raw);
	}
	if (st->plain != NULL) {
		explicit_bzero(st->plain, SESSION_INDEX_MAX);
		free(st->plain);
	}
	if (st->text != NULL) {
		explicit_bzero(st->text, SESSION_INDEX_MAX);
		free(st->text);
	}
	explicit_bzero(st, sizeof(*st));
	free(st);
	return rv;
}

/*
 * provision_shared(st):
 *	CER-PROVISION-2. A copy brought the shared set onto this
 *	machine, by any transport (VAULT-BACKUP-1). The index is the
 *	file of that set that the ceremony reads, so an absent index
 *	stops the ceremony here, before the plate scan.
 */
static int
provision_shared(const struct state *st)
{
	int	 n;

	if ((n = file_exists(st, VAULT_FILE_INDEX, NULL)) < 0)
		return -1;
	if (n == 0) {
		warnx("%s: the index is absent: copy the shared set of the "
		    "vault onto this machine first", st->vault);
		return -1;
	}
	return 0;
}

/*
 * config_same(a, b):
 *	1 when the two configs hold one oracle list, one threshold
 *	and one round count, and 0 when one of them differs. The
 *	value of a position is the static public key and the URL, or
 *	the retired state (VAULT-CONFIG-6).
 */
static int
config_same(const struct vault_config *a, const struct vault_config *b)
{
	unsigned int	 i;

	if (a->count != b->count || a->threshold != b->threshold ||
	    a->rounds != b->rounds)
		return 0;
	for (i = 0; i < a->count; i++) {
		if (a->oracle[i].retired != b->oracle[i].retired)
			return 0;
		if (!a->oracle[i].retired &&
		    (strcmp(a->oracle[i].key, b->oracle[i].key) != 0 ||
		    strcmp(a->oracle[i].url, b->oracle[i].url) != 0))
			return 0;
	}
	return 1;
}

/*
 * provision_old(st):
 *	The config that this machine holds, to the old member of st,
 *	and the gate of the command line against it. A machine with
 *	no config file is a new machine of the vault, and old stays
 *	NULL.
 *
 *	A config of another machine name refuses the ceremony: two
 *	machines must not run from one machine-local set, and a
 *	clone under a new name takes an empty machine directory
 *	(CER-PROVISION-19). A config of the same name is the re-run
 *	of CER-PROVISION-12, and the re-run takes the oracle list,
 *	the threshold and the round count of that file. A command
 *	line that differs in one of them is a change of the list or
 *	of the threshold, or a change of every pin of this machine,
 *	and this ceremony refuses it (CER-PROVISION-13).
 *
 *	The gate parses the command line without the plate check
 *	value, so it runs before the plate scan.
 */
static int
provision_old(struct state *st)
{
	struct vault_config	*new = NULL;
	char			 path[PATH_MAX];
	char			*text = NULL;
	size_t			 len = 0;
	int			 rv = -1;

	if (vault_path(path, sizeof(path), st->vault, VAULT_FILE_CONFIG,
	    NULL) != 0) {
		warnx("%s: the path of the config file does not fit",
		    st->vault);
		return -1;
	}
	if ((text = malloc(CONFIG_MAX)) == NULL) {
		warn("the config");
		return -1;
	}
	if (vault_read(path, (unsigned char *)text, CONFIG_MAX, &len) != 0) {
		warn("%s", path);
		goto out;
	}
	if (len == 0) {
		rv = 0;
		goto out;
	}
	if (len == CONFIG_MAX) {
		warnx("%s: the config file is too long", path);
		goto out;
	}
	if ((st->old = calloc(1, sizeof(*st->old))) == NULL ||
	    (new = calloc(1, sizeof(*new))) == NULL) {
		warn("the config");
		goto out;
	}
	if (vault_config_read(text, len, st->old) != 0) {
		warnx("%s: an oracle position or the threshold is wrong",
		    path);
		goto out;
	}
	if (strcmp(st->old->machine, st->arg->machine) != 0) {
		warnx("%s: the machine-local set of this vault directory "
		    "belongs to the machine %s, and this ceremony takes "
		    "that name or an empty machine directory", path,
		    st->old->machine);
		goto out;
	}
	if (config_text(st, NULL, text, &len) != 0 ||
	    vault_config_read(text, len, new) != 0) {
		warnx("the config: an oracle value or the threshold is wrong");
		goto out;
	}
	if (!config_same(st->old, new)) {
		warnx("%s: the oracle list, the threshold or the round count "
		    "of this machine differs from the command line, and this "
		    "ceremony changes none of them", path);
		goto out;
	}
	rv = 0;
out:
	free(new);
	free(text);
	return rv;
}

/*
 * provision_name(st):
 *	CER-PROVISION-3, the machine registry. index_read() set
 *	registered and retired for the machine name of the command
 *	line. A retired name never runs this ceremony, and the
 *	refusal names a new machine name as the path (ORC-REVOKE-11,
 *	KEY-DEVICE-3).
 *
 *	A name of the registry with no config of that name on this
 *	machine names another machine, and the ceremony replaces the
 *	records of it: each set_pin of the loops enrolls the records
 *	that the device factor of that name addresses (KEY-DEVICE-4).
 *	The step warns, and it takes an explicit confirmation from
 *	the terminal. A config of that name on this machine is the
 *	re-run of CER-PROVISION-12, and the re-run takes no
 *	confirmation.
 */
static int
provision_name(const struct state *st)
{
	if (st->retired) {
		warnx("the registry of the index marks the machine %s "
		    "retired, and a retired name never runs this ceremony: "
		    "give a new machine name", st->arg->machine);
		return -1;
	}
	if (!st->registered || st->old != NULL)
		return 0;
	warnx("the registry of the index holds the machine %s, and this "
	    "machine holds no machine-local set of that name",
	    st->arg->machine);
	warnx("the ceremony replaces the records of the machine that holds "
	    "that name, at every live oracle");
	if (fugupass_confirm("Replace the records of that machine? Type "
	    "yes: ") != 0) {
		warnx("the ceremony stops, and it writes no file");
		return -1;
	}
	return 0;
}

/*
 * provision_seals(st):
 *	The canary check seal of each live oracle on this machine, to
 *	the canary state of that position. A seal takes the check of
 *	provision_canaries(), and no seal takes the enrollment. A
 *	seal is a verifier of the passphrase, so a machine with one
 *	takes no warning at the read (ORC-CANARY-6).
 */
static int
provision_seals(struct state *st)
{
	struct vault_at	 at;
	unsigned int	 i;
	int		 n;

	for (i = 1; i <= st->config.count; i++) {
		if (st->config.oracle[i - 1].retired)
			continue;
		memset(&at, 0, sizeof(at));
		at.oracle = i;
		if ((n = file_exists(st, VAULT_FILE_CANARY, &at)) < 0)
			return -1;
		st->canary[i] = n ? CANARY_CHECK : CANARY_ENROLL;
		if (n)
			st->verifier = 1;
	}
	return 0;
}

/*
 * provision_canaries(st):
 *	CER-PROVISION-6, and the canary part of CER-PROVISION-12. A
 *	live oracle with no canary check seal on this machine takes
 *	the enrollment of step_canaries(): one set_pin, one immediate
 *	get_pin, the seal, and this machine's index wrap
 *	(ORC-CANARY-7, ORC-CANARY-11, KEY-MASK-7).
 *
 *	A live oracle with a seal takes the canary check first, and
 *	that check heals a dead index wrap under the canary mask of
 *	the answer (ORC-CANARY-1, ORC-CANARY-8). A pass keeps the
 *	record, the seal and the wrap. A junk answer after a pass at
 *	another oracle names a record-side cause: a wiped record, a
 *	counter behind the record, or a stale seal of this machine
 *	(ORC-CANARY-4). That oracle then takes the enrollment above,
 *	and the fresh mask seals the check value and wraps the index
 *	share again. A junk answer at every sealed canary keeps the
 *	typo case, and the ceremony stops before any set_pin
 *	(ORC-CANARY-9). Every other state of a request stops the
 *	ceremony, because the loops need every live oracle
 *	(ORC-REVEAL-6, ORC-REVEAL-8).
 *
 *	K_idx came from the plate at the index read, so the check
 *	takes no share of an answer, and the share leaves memory
 *	here (KEY-SHARE-8).
 */
static int
provision_canaries(struct state *st)
{
	struct oracle_ctx	 ctx;
	unsigned char		 share[DERIVE_KEYLEN];
	const char		*url;
	unsigned int		 i, checked = 0, passed = 0;
	int			 live, rv, ok = -1;

	for (i = 1; i <= st->config.count; i++) {
		if (st->canary[i] != CANARY_CHECK)
			continue;
		checked++;
		url = st->config.oracle[i - 1].url;
		ctx_of(&ctx, st, i);
		rv = oracle_canary_check(&ctx, st->idxkey, sizeof(st->idxkey),
		    share, sizeof(share), &live);
		if (rv == 0) {
			st->canary[i] = CANARY_KEEP;
			passed++;
			continue;
		}
		warnx("the canary of oracle %u (%s): %s", i, url,
		    oracle_state_text(rv));
		if (rv != ORACLE_EJUNK)
			goto out;
		st->canary[i] = CANARY_STALE;
	}
	if (checked > 0 && passed == 0) {
		warnx("the cause is the passphrase, or, at each oracle, a "
		    "wiped canary record, a counter behind the record, or a "
		    "stale canary check seal of this machine");
		warnx("the ceremony sends no set_pin");
		goto out;
	}

	for (i = 1; i <= st->config.count; i++) {
		if (st->canary[i] != CANARY_ENROLL &&
		    st->canary[i] != CANARY_STALE)
			continue;
		url = st->config.oracle[i - 1].url;
		ctx_of(&ctx, st, i);
		rv = oracle_canary_index(&ctx, st->pass, st->passlen,
		    st->idxkey, sizeof(st->idxkey));
		if (rv != 0) {
			warnx("the canary of oracle %u (%s): %s", i, url,
			    oracle_state_text(rv));
			goto out;
		}
		if (st->canary[i] == CANARY_STALE)
			warnx("the canary of oracle %u (%s) is enrolled again, "
			    "with a fresh seal and a fresh index wrap of it",
			    i, url);
		st->canary[i] = CANARY_KEEP;
	}
	ok = 0;
out:
	explicit_bzero(share, sizeof(share));
	return ok;
}

/*
 * provision_slot(st, slot):
 *	One existing slot of the vault (CER-PROVISION-7). K_e derives
 *	from root, slot_enroll() enrolls the pairs with no wrap of
 *	this machine, and K_e leaves memory at each exit
 *	(KEY-ENTRY-2, CER-PROVISION-12, CER-PROVISION-10). The slot
 *	file of the shared set stays as it is: it holds the slot or
 *	the entry of that slot under K_e, and the ceremony writes no
 *	file of the shared set but the index.
 */
static int
provision_slot(struct state *st, uint32_t slot)
{
	unsigned char	 key[DERIVE_KEYLEN];
	int		 rv = -1;

	if (derive_entry_key(st->root, sizeof(st->root), slot, key,
	    sizeof(key)) != 0) {
		warnx("slot %" PRIu32 ": the entry key fails", slot);
		goto out;
	}
	rv = slot_enroll(st, slot, key, sizeof(key), 0);
out:
	explicit_bzero(key, sizeof(key));
	return rv;
}

/*
 * provision_slots(st):
 *	CER-PROVISION-7. The existing slots are the slot indexes
 *	below the pool-next line of the index: each ceremony reserved
 *	its slots below that line, and a slot below it is free or
 *	consumed (VAULT-INDEX-2, ENTRY-POOL-1).
 */
static int
provision_slots(struct state *st)
{
	uint32_t	 slot;

	for (slot = 0; slot < st->next; slot++) {
		if (provision_slot(st, slot) != 0)
			return -1;
	}
	return 0;
}

/*
 * provision_index_write(st):
 *	CER-PROVISION-8. This machine's name joins the machine
 *	registry of the index, once: a re-run of a registered machine
 *	adds no second line (VAULT-INDEX-2, VAULT-FORMAT-8). Every
 *	other line comes from the read, and index_write() writes the
 *	pool state of the read as it was, so the write changes no
 *	entry and no other machine of the registry.
 */
static int
provision_index_write(struct state *st)
{
	int	 n;

	if (!st->registered) {
		n = snprintf(&st->text[st->textlen],
		    SESSION_INDEX_MAX - st->textlen, "machine: %s\n",
		    st->arg->machine);
		if (n < 0 || (size_t)n >= SESSION_INDEX_MAX - st->textlen) {
			warnx("the index: the text does not fit");
			return -1;
		}
		st->textlen += (size_t)n;
	}
	return index_write(st);
}

int
ceremony_provision(const struct ceremony_create *arg)
{
	struct state	*st;
	int		 n, rv = -1;

	if (arg == NULL || arg->vault == NULL || arg->machine == NULL ||
	    arg->oracle == NULL || arg->count == 0 || arg->threshold == 0 ||
	    arg->rounds == 0 || arg->pool == 0) {
		warnx("the ceremony takes an incomplete argument set");
		return -1;
	}
	if (arg->count > DERIVE_ORACLE_MAX) {
		warnx("the oracle set takes %d positions at the most",
		    DERIVE_ORACLE_MAX);
		return -1;
	}

	/*
	 * CER-PROVISION-18. A marker names an incomplete change, and
	 * this ceremony enrolls a record, so it refuses to start
	 * (ORC-ENROLL-10).
	 */
	if ((n = change_pending(arg->vault)) != 0) {
		if (n == 1)
			warnx("this vault holds an incomplete passphrase "
			    "change, and \"%s\" completes it",
			    CHANGE_RESUME_CMD);
		return -1;
	}

	if ((st = calloc(1, sizeof(*st))) == NULL) {
		warn("the provisioning");
		return -1;
	}
	st->arg = arg;
	st->vault = arg->vault;
	st->name = arg->machine;

	/* The three buffers of the index (struct state). */
	st->raw = malloc(INDEX_RAW_MAX);
	st->plain = malloc(SESSION_INDEX_MAX);
	st->text = malloc(SESSION_INDEX_MAX);
	if (st->raw == NULL || st->plain == NULL || st->text == NULL) {
		warn("the provisioning");
		goto out;
	}

	/*
	 * The gates of the disk come before the plate scan, so a
	 * vault that this machine cannot join takes no plate.
	 */
	if (provision_shared(st) != 0)
		goto out;
	if (provision_old(st) != 0)
		goto out;
	if (machine_dir(st->vault) != 0)
		goto out;

	if (step_master(st) != 0)
		goto out;
	if (index_read(st) != 0)
		goto out;
	if (provision_name(st) != 0)
		goto out;
	if (step_factor(st) != 0)
		goto out;
	if (step_config(st) != 0)
		goto out;
	if (provision_seals(st) != 0)
		goto out;
	if (step_passphrase(st) != 0)
		goto out;
	if (provision_canaries(st) != 0)
		goto out;
	if (provision_slots(st) != 0)
		goto out;
	if (provision_index_write(st) != 0)
		goto out;
	rv = 0;
out:
	/*
	 * CER-PROVISION-10. M, root, K_idx and the passphrase leave
	 * memory here, on the pass and on every failure path
	 * (SEC-MEMORY-4, SEC-MEMORY-5). Every K_e, every share and
	 * every mask left memory in the step that held it. The three
	 * buffers hold vault data, and they leave with it. The old
	 * config holds no secret (VAULT-CONFIG-3).
	 */
	if (st->raw != NULL) {
		explicit_bzero(st->raw, INDEX_RAW_MAX);
		free(st->raw);
	}
	if (st->plain != NULL) {
		explicit_bzero(st->plain, SESSION_INDEX_MAX);
		free(st->plain);
	}
	if (st->text != NULL) {
		explicit_bzero(st->text, SESSION_INDEX_MAX);
		free(st->text);
	}
	free(st->old);
	explicit_bzero(st, sizeof(*st));
	free(st);
	return rv;
}
