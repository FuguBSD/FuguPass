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
 * Vault creation and the pool refill. ceremony.h states the
 * interface. CER-CREATE holds nine rules, the rules are the steps,
 * and ceremony_create() calls one function of each step in rule
 * order.
 *
 * step_master() is CER-CREATE-1, step_factor() is CER-CREATE-2,
 * step_config() is CER-CREATE-3, and step_passphrase() is
 * CER-CREATE-4. step_canaries() is CER-CREATE-5, step_slots() is
 * CER-CREATE-6, and step_index() is CER-CREATE-7. The erasure of
 * CER-CREATE-8 sits in ceremony_create(), and step_kit() is
 * CER-CREATE-9.
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
 * slot loop. refill_index_write() records the new pool state, after
 * the slot loop. An interrupted refill therefore leaves the index as
 * it was, and the re-run reserves the same indexes again.
 *
 * The steps come from the other files of the tree. helper.c runs
 * the scan helper, derive.c holds each label and the master gate,
 * bip85.c holds the two candidates, oracle.c holds each record and
 * each wrap, envelope.c holds the client public key, and vault.c
 * holds every path, the seal and the one writer. This file adds the
 * order of the steps, the text of the config, the index and the
 * kit, and the erasure.
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
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>

#include "bip85.h"
#include "ceremony.h"
#include "change.h"
#include "derive.h"
#include "entry.h"
#include "envelope.h"
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

/* One record row of the kit: the oracle index and the file name. */
#define KIT_LINE_MAX	(sizeof("record 255 ") + 2 * DERIVE_KEYLEN + \
			    sizeof(".pin"))

/* One oracle of the kit: the URL row, each slot, and the canary. */
#define KIT_ORACLE_MAX	(sizeof("oracle 255 ") + VAULT_URL_MAX + 1 + \
			    (CEREMONY_POOL_MAX + 1) * KIT_LINE_MAX)

/* The kit: the machine row, and one block of each position. */
#define KIT_MAX		(DERIVE_ORACLE_MAX * KIT_ORACLE_MAX + \
			    DERIVE_MACHINE_MAX + 96)

/* The record file name of one record: the hex, and the suffix. */
#define KIT_NAME_MAX	(2 * DERIVE_KEYLEN + sizeof(".pin"))

/*
 * The bytes of the sealed index, and one more. A count of this
 * value names a file that is too long (vault.h). session.h states
 * the plaintext bound of the index.
 */
#define INDEX_RAW_MAX	(SESSION_INDEX_MAX + SEAL_OVERHEAD + 1)

/*
 * The state of one ceremony. The master, root, the index key and
 * the passphrase are the secrets of CER-CREATE-8 and of
 * CER-REFILL-6. The device factor persists on disk, so the two rules
 * hold no erasure of it (KEY-DEVICE-2).
 *
 * The two ceremonies share this state, and each one fills the
 * members that its steps read. arg is the command line of one
 * creation, and a refill takes each tunable of the config file.
 *
 * The three buffers and the four members below them belong to the
 * refill. raw takes the sealed index, plain takes the plaintext of
 * it, and text takes the plaintext of the write. free is the free
 * slots of the pool, next is the lowest unreserved slot index, and
 * add is the slots of this refill (VAULT-INDEX-2, ENTRY-POOL-1).
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
};

static void		 hex(const unsigned char *, size_t, char *);
static void		 ctx_of(struct oracle_ctx *, const struct state *,
			    unsigned int);
static int		 machine_dir(const char *);
static int		 step_master(struct state *);
static int		 step_factor(struct state *);
static int		 step_config(struct state *);
static int		 step_passphrase(struct state *);
static int		 step_canaries(struct state *);
static int		 step_slot(struct state *, uint32_t);
static int		 step_slots(struct state *);
static int		 step_index(const struct state *);
static int		 kit_name(const struct state *, unsigned int, uint32_t,
			    int, char *, size_t);
static int		 step_kit(const struct state *);
static int		 refill_config(struct state *);
static int		 refill_factor(struct state *);
static int		 index_line(const struct vault_line *, void *);
static int		 refill_index_read(struct state *);
static int		 refill_reserve(struct state *);
static int		 refill_pass(struct state *);
static int		 refill_canaries(struct state *);
static int		 refill_slots(struct state *);
static int		 refill_index_write(struct state *);

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
 * step_config(st):
 *	CER-CREATE-3. The config file holds the ordered oracle set,
 *	the threshold, the machine name, the round count, the plate
 *	check value, the pool tunables, the audit age and the lock
 *	timeout (VAULT-CONFIG-1, KEY-MASTER-5, ENTRY-POOL-2,
 *	ENTRY-POOL-6, ENTRY-SHADOW-6, PROG-REPL-11). The two tunables
 *	take their default value, and the operator edits the file.
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
	unsigned int	 i;
	int		 n, rv = -1;

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

	for (i = 0; i < st->arg->count; i++) {
		n = snprintf(&text[len], CONFIG_MAX - len, "oracle-%u: %s\n",
		    i + 1, st->arg->oracle[i]);
		if (n < 0 || (size_t)n >= CONFIG_MAX - len) {
			warnx("the config: the oracle set does not fit");
			goto out;
		}
		len += (size_t)n;
	}
	n = snprintf(&text[len], CONFIG_MAX - len,
	    "threshold: %u\n"
	    "machine-name: %s\n"
	    "kdf-rounds: %u\n"
	    "plate-check: %s\n"
	    "pool-size: %u\n"
	    "pool-watermark: %u\n"
	    "audit-age: %u\n"
	    "lock-timeout: %u\n",
	    st->arg->threshold, st->arg->machine, st->arg->rounds, plate,
	    st->arg->pool, CEREMONY_POOL_WATERMARK,
	    ENTRY_AUDIT_AGE_DEFAULT, IFACE_LOCK_TIMEOUT_DEFAULT);
	if (n < 0 || (size_t)n >= CONFIG_MAX - len) {
		warnx("the config: the text does not fit");
		goto out;
	}
	len += (size_t)n;

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
 *	CER-CREATE-4. readpassphrase(3) reads the passphrase twice,
 *	and a mismatch stops the ceremony (SEC-MEMORY-4). The
 *	ceremony verifies this value against no canary record, so
 *	the warning of ORC-CANARY-6 comes first.
 */
static int
step_passphrase(struct state *st)
{
	int	 rv;

	warnx("no file verifies this passphrase: a mistyped passphrase "
	    "enrolls at every oracle");
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
 * step_slot(st, slot):
 *	One slot of the pool, in the order of CER-CREATE-6. The step
 *	derives K_e, materializes the two BIP85 candidates, enrolls
 *	the record at each live oracle in list order, and seals the
 *	slot file last (KEY-ENTRY-2, KEY-BIP85-5, ENTRY-POOL-1).
 *
 *	oracle_enroll() verifies the HTTP success of the enrollment
 *	and persists the wrap of that oracle (ORC-ENROLL-2,
 *	ORC-ENROLL-3). A failure stops the ceremony with the oracle
 *	named, and a re-run completes the pool: a fresh set_pin
 *	replaces the record, and the wrap comes from the re-derived
 *	share.
 *
 *	The slot file name is the lowercase hex of H(K_e), and the
 *	file seals under K_e (VAULT-LAYOUT-5, KEY-ENTRY-3). The
 *	secret fields lead the plaintext (VAULT-FORMAT-4).
 */
static int
step_slot(struct state *st, uint32_t slot)
{
	struct oracle_ctx	 ctx;
	struct vault_at		 at;
	unsigned char		 key[DERIVE_KEYLEN];
	unsigned char		 sealed[SLOT_MAX + SEAL_OVERHEAD];
	char			 password[BIP85_PWD_MAX];
	char			 mnemonic[BIP85_MNEMONIC_MAX];
	char			 plain[SLOT_MAX];
	char			 name[VAULT_NAMELEN];
	char			 path[PATH_MAX];
	unsigned int		 i;
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

	for (i = 1; i <= st->config.count; i++) {
		if (st->config.oracle[i - 1].retired)
			continue;
		ctx_of(&ctx, st, i);
		n = oracle_enroll(&ctx, slot, key, sizeof(key));
		if (n != 0) {
			warnx("slot %" PRIu32 " at oracle %u (%s): %s", slot,
			    i, st->config.oracle[i - 1].url, oracle_state_text(n));
			goto out;
		}
	}

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

/*
 * kit_name(st, oracle, slot, canary, out, outlen):
 *	The record file name of one record of this machine at the
 *	oracle index oracle, to the outlen bytes at out. canary
 *	takes the canary record of the oracle in place of the record
 *	of the slot index slot (ORC-RECORDS-1, ORC-RECORDS-2).
 *
 *	The name is the lowercase hex of the hash of the record's
 *	compressed client public key, with the suffix .pin
 *	(ORC-REVOKE-6, FuguOracle STORE-KEYS-3). The client key
 *	takes the device factor alone, so this call needs no
 *	passphrase and no master (KEY-CLIENT-1, KEY-CLIENT-4).
 *
 *	The call gives 0, and -1 with the report of the failure on
 *	the standard error. The caller of it adds no report.
 */
static int
kit_name(const struct state *st, unsigned int oracle, uint32_t slot,
    int canary, char *out, size_t outlen)
{
	unsigned char	 client[DERIVE_KEYLEN];
	unsigned char	 pub[ENVELOPE_PUBKEYLEN];
	unsigned char	 digest[SHA256_DIGEST_LENGTH];
	char		 text[2 * SHA256_DIGEST_LENGTH + 1];
	int		 n, rv = -1;

	if (outlen < KIT_NAME_MAX) {
		warnx("the kit: the record name of oracle %u does not fit",
		    oracle);
		goto out;
	}
	if (canary)
		n = derive_client_key_canary(st->factor, sizeof(st->factor),
		    oracle, client, sizeof(client));
	else
		n = derive_client_key(st->factor, sizeof(st->factor), oracle,
		    slot, client, sizeof(client));
	if (n != 0) {
		warnx("the kit: the client key of oracle %u fails", oracle);
		goto out;
	}
	if (envelope_pubkey(client, pub) != 0) {
		warnx("the kit: the client public key of oracle %u fails",
		    oracle);
		goto out;
	}
	if (SHA256(pub, sizeof(pub), digest) == NULL) {
		warnx("the kit: the hash of a client public key fails");
		goto out;
	}
	hex(digest, sizeof(digest), text);
	n = snprintf(out, outlen, "%s.pin", text);
	if (n < 0 || (size_t)n >= outlen) {
		warnx("the kit: the record name of oracle %u does not fit",
		    oracle);
		goto out;
	}
	rv = 0;
out:
	/*
	 * The client key is a secret of this machine, and the public
	 * key and the name of it are not (ORC-REVOKE-6).
	 */
	explicit_bzero(client, sizeof(client));
	return rv;
}

/*
 * step_kit(st):
 *	CER-CREATE-9. The revocation kit of this machine names the
 *	machine, and, for each oracle, the record file names of this
 *	machine at that oracle (ORC-REVOKE-6). The count is one name
 *	of each slot of the pool, and one canary name.
 *
 *	The kit holds no secret, so this step follows the erasure of
 *	CER-CREATE-8. It takes the device factor from the state,
 *	because that rule names no erasure of the device factor. The
 *	factor persists on disk as well (KEY-DEVICE-2).
 *
 *	The kit is plaintext, and it names the records of one
 *	machine, so it sits at the machine-local path of
 *	VAULT-LAYOUT-4 and VAULT-LAYOUT-6. This step prints that
 *	path (PROG-ONESHOT-7).
 */
static int
step_kit(const struct state *st)
{
	char		 name[KIT_NAME_MAX];
	char		 path[PATH_MAX];
	char		*text = NULL;
	uint32_t	 slot;
	size_t		 len = 0;
	unsigned int	 i;
	int		 n, rv = -1;

	if (vault_path(path, sizeof(path), st->vault, VAULT_FILE_KIT,
	    NULL) != 0) {
		warnx("%s: the path of the kit does not fit",
		    st->vault);
		goto out;
	}
	if ((text = malloc(KIT_MAX)) == NULL) {
		warn("the kit");
		goto out;
	}

	n = snprintf(text, KIT_MAX, "machine %s\n", st->arg->machine);
	if (n < 0 || (size_t)n >= KIT_MAX) {
		warnx("the kit: the text does not fit");
		goto out;
	}
	len = (size_t)n;

	for (i = 1; i <= st->config.count; i++) {
		if (st->config.oracle[i - 1].retired)
			continue;
		n = snprintf(&text[len], KIT_MAX - len, "oracle %u %s\n", i,
		    st->config.oracle[i - 1].url);
		if (n < 0 || (size_t)n >= KIT_MAX - len) {
			warnx("the kit: the text does not fit");
			goto out;
		}
		len += (size_t)n;

		/* One name of each slot, and one of the canary. */
		for (slot = 0; slot <= st->arg->pool; slot++) {
			if (kit_name(st, i, slot, slot == st->arg->pool,
			    name, sizeof(name)) != 0)
				goto out;
			n = snprintf(&text[len], KIT_MAX - len,
			    "record %u %s\n", i, name);
			if (n < 0 || (size_t)n >= KIT_MAX - len) {
				warnx("the kit: the text does not fit");
				goto out;
			}
			len += (size_t)n;
		}
	}

	if (vault_write(path, (const unsigned char *)text, len) != 0) {
		warn("%s", path);
		goto out;
	}
	printf("%s\n", path);
	rv = 0;
out:
	free(text);
	return rv;
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

	/* CER-CREATE-9, after the erasure: the kit holds no secret. */
	if (rv == 0)
		rv = step_kit(st);

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
 * index_line(line, arg):
 *	Take one line of the index to the state at arg. The two pool
 *	lines give the pool state of it, and they stay out of the
 *	text of the write. refill_index_write() writes the new state
 *	of the two (VAULT-INDEX-2).
 *
 *	Every other line reaches that text again, so the refill
 *	changes no entry and no machine of the registry
 *	(CER-REFILL-4).
 */
static int
index_line(const struct vault_line *line, void *arg)
{
	struct state	*st = arg;
	const char	*name = line->field->name;
	int		 n;

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
 * refill_index_read(st):
 *	The index of the vault, under K_idx (VAULT-INDEX-1,
 *	VAULT-INDEX-3). The scan keeps each line of the file for the
 *	write, and it takes the pool state of the two pool lines.
 *
 *	The plate gives root, so K_idx derives here and no oracle
 *	request carries a share of it (KEY-MASK-6). An index that
 *	does not open names another master, so this step holds the
 *	plate of this vault (KEY-MASTER-5).
 *
 *	An index with no pool-next line names no free slot index. A
 *	reservation from 0 would replace the records of the first
 *	entries, so the refill stops there (CER-REFILL-4,
 *	KEY-ENTRY-1).
 *
 *	The plaintext of the index is a secret of the vault, and it
 *	leaves memory in ceremony_refill() (SEC-MEMORY-1).
 */
static int
refill_index_read(struct state *st)
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
		warnx("%s: the index holds no pool-next line, and the refill "
		    "reserves no slot index", path);
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
 * refill_index_write(st):
 *	CER-REFILL-2. The new pool state reaches the index. Each new
 *	slot joins the free list, and pool-next takes the index after
 *	the last new slot (VAULT-INDEX-2, ENTRY-POOL-1).
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
refill_index_write(struct state *st)
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
	if (refill_index_read(st) != 0)
		goto out;
	if (refill_reserve(st) != 0)
		goto out;
	if (refill_pass(st) != 0)
		goto out;
	if (refill_canaries(st) != 0)
		goto out;
	if (refill_slots(st) != 0)
		goto out;
	if (refill_index_write(st) != 0)
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
