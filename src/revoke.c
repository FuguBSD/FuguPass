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
 * The revocation kit (ORC-REVOKE-6). revoke.h states the interface,
 * and the two sources of a kit.
 *
 * revoke_kit() derives the kit and prints it, and no file of the
 * vault holds one (PROG-ONESHOT-7). A stored kit is a copy of
 * derived data, and each refill enrolls records that such a copy
 * does not name (CER-REFILL). A revocation from a stale copy misses
 * those records, so the tool derives the kit at each call.
 *
 * kit_name() gives the record file name of one record: the
 * lowercase hex of the hash of the compressed client public key,
 * with the suffix .pin (FuguOracle STORE-KEYS-3). The client key
 * takes the device factor and the oracle index alone, so a name
 * needs no passphrase and no master (KEY-CLIENT-1, KEY-CLIENT-4).
 *
 * kit_config() reads the config file of this machine: the oracle
 * set, and the name of this machine. kit_factor() reads the factor
 * file, and kit_wraps() reads the wrap files. One wrap file names
 * one record of this machine at one oracle (KEY-MASK-4), so the
 * wraps give the slot set of this machine, and every slot of
 * every refill stands in it. A retirement deletes the wraps of
 * its position, and the records of this machine stay at the
 * departing oracle (CER-PROVISION-16), so the kit lists that set
 * under each position, live or retired. kit_plate() takes a
 * plate scan in place of the two files, and it derives the factor
 * of a named machine from the master (KEY-DEVICE-4,
 * ORC-REVOKE-4). kit_index() then opens the index of the shared
 * set under K_idx, from root (VAULT-INDEX-4), and the next free
 * slot index of it bounds the kit. Every refill of every machine
 * raises that index, so the kit names each slot of the vault, and
 * no constant bounds it (CER-REFILL-2).
 *
 * The device factor of a named machine belongs to that machine, so
 * this file writes it to no file (KEY-DEVICE-2). The master, root,
 * K_idx, the plaintext of the index, each client key and each
 * factor leave memory on every path (SEC-MEMORY-5).
 */

#include <sys/types.h>

#include <dirent.h>
#include <err.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>

#include "derive.h"
#include "envelope.h"
#include "helper.h"
#include "revoke.h"
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

/* The record file name of one record: the hex, and the suffix. */
#define KIT_NAME_MAX	(2 * SHA256_DIGEST_LENGTH + sizeof(".pin"))

/* The first allocation of the slot list, in slots. */
#define SLOT_MIN	64

/*
 * The bytes of the sealed index, and one more. A count of this
 * value names a file that is too long (vault.h). session.h states
 * the plaintext bound of the index.
 */
#define INDEX_RAW_MAX	(SESSION_INDEX_MAX + SEAL_OVERHEAD + 1)

/*
 * The state of one kit. machine is NULL for this machine, and the
 * name of a machine that is lost otherwise. slot holds the slot
 * index of each wrap file of this machine, in the order of the
 * print and with no repeat. slots is the next free slot index of
 * the vault, from the pool-next line of the index, and haveslots
 * marks the read of that line (VAULT-INDEX-2).
 */
struct kit {
	const char		*vault;
	const char		*machine;
	struct vault_config	*config;
	unsigned char		 factor[DERIVE_KEYLEN];
	uint32_t		*slot;
	size_t			 slotlen;
	size_t			 slotmax;
	uint32_t		 slots;
	int			 haveslots;
};

static void	 hex(const unsigned char *, size_t, char *);
static int	 kit_config(struct kit *);
static int	 kit_factor(struct kit *);
static int	 slot_add(struct kit *, uint32_t);
static int	 slot_cmp(const void *, const void *);
static int	 kit_wraps(struct kit *);
static int	 kit_index_line(const struct vault_line *, void *);
static int	 kit_index(struct kit *, const unsigned char *);
static int	 kit_plate(struct kit *);
static int	 kit_name(const unsigned char *, unsigned int, uint32_t, int,
		    char *, size_t);
static int	 kit_line(const struct kit *, unsigned int, uint32_t, int);
static int	 kit_print(const struct kit *);

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
 * kit_config(k):
 *	The config file of the vault, to the state (VAULT-CONFIG-1).
 *	The kit takes the oracle set from it, and the kit of this
 *	machine takes the machine name from it (KEY-DEVICE-3). The
 *	reader holds the position rule of the file (VAULT-CONFIG-6).
 */
static int
kit_config(struct kit *k)
{
	char	 path[PATH_MAX];
	char	*text;
	size_t	 len = 0;
	int	 rv = -1;

	if (vault_path(path, sizeof(path), k->vault, VAULT_FILE_CONFIG,
	    NULL) != 0) {
		warnx("%s: the path of the config file does not fit",
		    k->vault);
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
	if (vault_config_read(text, len, k->config) != 0) {
		warnx("%s: an oracle position or the threshold is wrong",
		    path);
		goto out;
	}
	if (k->machine == NULL && k->config->machine[0] == '\0') {
		warnx("%s: the config file names no machine", path);
		goto out;
	}
	rv = 0;
out:
	free(text);
	return rv;
}

/*
 * kit_factor(k):
 *	The device factor X of this machine, to the state
 *	(KEY-DEVICE-2). A machine with no machine-local set holds no
 *	factor file, and the kit of that machine takes the plate.
 */
static int
kit_factor(struct kit *k)
{
	unsigned char	 buf[DERIVE_KEYLEN + 1];
	char		 path[PATH_MAX];
	size_t		 len = 0;
	int		 rv = -1;

	if (vault_path(path, sizeof(path), k->vault, VAULT_FILE_FACTOR,
	    NULL) != 0) {
		warnx("%s: the path of the factor file does not fit",
		    k->vault);
		return -1;
	}
	if (vault_read(path, buf, sizeof(buf), &len) != 0) {
		warn("%s", path);
		goto out;
	}
	if (len != DERIVE_KEYLEN) {
		warnx("%s: the device factor of this machine is absent, "
		    "and the -m option takes the plate", path);
		goto out;
	}
	memcpy(k->factor, buf, sizeof(k->factor));
	rv = 0;
out:
	explicit_bzero(buf, sizeof(buf));
	return rv;
}

/*
 * slot_add(k, slot):
 *	Add one slot index to the list of the state.
 */
static int
slot_add(struct kit *k, uint32_t slot)
{
	uint32_t	*at;
	size_t		 max;

	if (k->slotlen == k->slotmax) {
		max = k->slotmax == 0 ? SLOT_MIN : 2 * k->slotmax;
		if ((at = reallocarray(k->slot, max, sizeof(*at))) == NULL) {
			warn("the kit");
			return -1;
		}
		k->slot = at;
		k->slotmax = max;
	}
	k->slot[k->slotlen++] = slot;
	return 0;
}

/*
 * slot_cmp(a, b):
 *	The order of the print: the slot index.
 */
static int
slot_cmp(const void *a, const void *b)
{
	const uint32_t	*x = a, *y = b;

	if (*x != *y)
		return *x < *y ? -1 : 1;
	return 0;
}

/*
 * kit_wraps(k):
 *	The slot set of this machine, from the wrap files of the
 *	machine-local set (KEY-MASK-4, VAULT-LAYOUT-4). One wrap
 *	names one record of one slot at one oracle, and a ceremony
 *	writes the wrap of each record that it enrolls
 *	(CER-CREATE-6, CER-REFILL-2). The wraps therefore name every
 *	slot of every ceremony of this machine. A retirement deletes
 *	the wraps of its position (CER-PROVISION-16), so the set
 *	takes the wraps of every position, and the print lists it
 *	under each position.
 *
 *	The walk reads the directory, and it takes the two indexes
 *	of a name. It asks vault_path() for the path of that pair,
 *	and a name that differs from the path names another file.
 *	The layout therefore stays in vault.c. The sort gives the
 *	order of the print, and one slot of many wraps stands once.
 */
static int
kit_wraps(struct kit *k)
{
	struct vault_at	 at;
	char		 dir[PATH_MAX];
	char		 name[PATH_MAX];
	char		 path[PATH_MAX];
	struct dirent	*ent;
	const char	*head, *tail;
	DIR		*dp;
	size_t		 i, keep;
	uint32_t	 slot, oracle;
	int		 n, rv = -1;

	n = snprintf(dir, sizeof(dir), "%s/%s", k->vault, VAULT_MACHINE_DIR);
	if (n < 0 || (size_t)n >= sizeof(dir)) {
		warnx("%s: the path of the machine directory does not fit",
		    k->vault);
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
		if (vault_path(path, sizeof(path), k->vault, VAULT_FILE_WRAP,
		    &at) != 0)
			continue;
		n = snprintf(name, sizeof(name), "%s/%s", dir, ent->d_name);
		if (n < 0 || (size_t)n >= sizeof(name) ||
		    strcmp(name, path) != 0)
			continue;
		if (slot_add(k, slot) != 0)
			goto out;
	}
	if (k->slotlen > 0) {
		qsort(k->slot, k->slotlen, sizeof(*k->slot), slot_cmp);
		for (i = 1, keep = 1; i < k->slotlen; i++) {
			if (k->slot[i] != k->slot[keep - 1])
				k->slot[keep++] = k->slot[i];
		}
		k->slotlen = keep;
	}
	rv = 0;
out:
	closedir(dp);
	return rv;
}

/*
 * kit_index_line(line, arg):
 *	Take one line of the index to the state at arg. The
 *	pool-next line gives the next free slot index of the vault,
 *	and every other line stays out of the kit (VAULT-INDEX-2).
 */
static int
kit_index_line(const struct vault_line *line, void *arg)
{
	struct kit	*k = arg;

	if (strcmp(line->field->name, "pool-next") != 0)
		return 0;
	if (vault_number(line->value, line->valuelen, VAULT_SLOT_MAX,
	    &k->slots) != 0)
		return -1;
	k->haveslots = 1;
	return 0;
}

/*
 * kit_index(k, root):
 *	The slot bound of a named machine, from the index of the
 *	vault under K_idx (VAULT-INDEX-1, VAULT-INDEX-3). A plate
 *	ceremony derives K_idx from root (VAULT-INDEX-4), so the
 *	read takes no index wrap and no oracle request (KEY-MASK-6).
 *
 *	The pool-next line holds the next free slot index, and each
 *	refill of each machine of the vault raises it (CER-REFILL-2).
 *	Every slot of every ceremony of the vault therefore stands
 *	below it, and no constant bounds the kit. An index that does
 *	not open names another master, so a wrong plate stops here
 *	(KEY-MASTER-5). An index with no pool-next line names no
 *	slot, and the kit stops there as well.
 *
 *	K_idx and the plaintext of the index leave memory here
 *	(SEC-MEMORY-1, SEC-MEMORY-5).
 */
static int
kit_index(struct kit *k, const unsigned char *root)
{
	unsigned char	 idxkey[DERIVE_KEYLEN];
	unsigned char	*raw = NULL;
	char		*plain = NULL;
	char		 path[PATH_MAX];
	size_t		 len = 0;
	int		 rv = -1;

	if (derive_index_key(root, DERIVE_ROOTLEN, idxkey,
	    sizeof(idxkey)) != 0) {
		warnx("the index key fails");
		goto out;
	}
	if (vault_path(path, sizeof(path), k->vault, VAULT_FILE_INDEX,
	    NULL) != 0) {
		warnx("%s: the path of the index file does not fit",
		    k->vault);
		goto out;
	}
	raw = malloc(INDEX_RAW_MAX);
	plain = malloc(SESSION_INDEX_MAX);
	if (raw == NULL || plain == NULL) {
		warn("the kit");
		goto out;
	}
	if (vault_read(path, raw, INDEX_RAW_MAX, &len) != 0) {
		warn("%s", path);
		goto out;
	}
	if (len <= SEAL_OVERHEAD || len == INDEX_RAW_MAX) {
		warnx("%s: the index is absent, or it is not a sealed file "
		    "of this vault", path);
		goto out;
	}
	if (seal_open(idxkey, sizeof(idxkey), raw, len,
	    (unsigned char *)plain, len - SEAL_OVERHEAD) != 0) {
		warnx("%s: the plate does not open the index of this vault",
		    path);
		goto out;
	}
	if (vault_scan(plain, len - SEAL_OVERHEAD, vault_index_fields,
	    kit_index_line, k) != 0) {
		warnx("%s: the index holds a line that the reader rejects",
		    path);
		goto out;
	}
	if (!k->haveslots) {
		warnx("%s: the index holds no pool-next line, and the kit "
		    "names no slot", path);
		goto out;
	}
	rv = 0;
out:
	explicit_bzero(idxkey, sizeof(idxkey));
	if (raw != NULL) {
		explicit_bzero(raw, INDEX_RAW_MAX);
		free(raw);
	}
	if (plain != NULL) {
		explicit_bzero(plain, SESSION_INDEX_MAX);
		free(plain);
	}
	return rv;
}

/*
 * kit_plate(k):
 *	The device factor of the named machine, from a plate scan
 *	(KEY-DEVICE-4, ORC-REVOKE-4). The scan helper gives the words
 *	of the master as one line of text (PROG-SCAN-5). The gate of
 *	the master rejects a count other than 12 words and a wrong
 *	checksum, and the message of it holds no word (KEY-MASTER-6).
 *	root then gives the factor of the name (KEY-DEVICE-1), and
 *	the slot bound of the kit comes from the index (kit_index).
 *
 *	The master and root leave memory here, and the factor leaves
 *	memory in revoke_kit() (SEC-MEMORY-5).
 */
static int
kit_plate(struct kit *k)
{
	char		 master[DERIVE_MASTER_MAX + 1];
	unsigned char	 root[DERIVE_ROOTLEN];
	char		 err[DERIVE_ERRLEN];
	char		*feed;
	size_t		 len = 0;
	int		 rv = -1;

	if (helper_run(HELPER_SCAN, NULL, 0, master, sizeof(master),
	    &len) != 0) {
		warnx("the plate scan fails");
		goto out;
	}

	/* The helper writes one line, and the master is that line. */
	if ((feed = memchr(master, '\n', len)) != NULL)
		len = (size_t)(feed - master);
	while (len > 0 && master[len - 1] == '\r')
		len--;
	master[len] = '\0';

	if (derive_master_check(master, len, err, sizeof(err)) != 0) {
		warnx("the master: %s", err);
		goto out;
	}
	if (derive_root(master, len, root, sizeof(root)) != 0) {
		warnx("the master: the seed of it fails");
		goto out;
	}
	if (derive_device_factor(root, sizeof(root), k->machine,
	    strlen(k->machine), k->factor, sizeof(k->factor)) != 0) {
		warnx("the device factor: the machine name is wrong");
		goto out;
	}
	if (kit_index(k, root) != 0)
		goto out;
	rv = 0;
out:
	explicit_bzero(master, sizeof(master));
	explicit_bzero(root, sizeof(root));
	return rv;
}

/*
 * kit_name(factor, oracle, slot, canary, out, outlen):
 *	The record file name of one record of the machine of the
 *	device factor at factor, at the oracle index oracle, to the
 *	outlen bytes at out. canary takes the canary record of the
 *	oracle in place of the record of the slot index slot
 *	(ORC-RECORDS-1, ORC-RECORDS-2).
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
kit_name(const unsigned char *factor, unsigned int oracle, uint32_t slot,
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
		n = derive_client_key_canary(factor, DERIVE_KEYLEN, oracle,
		    client, sizeof(client));
	else
		n = derive_client_key(factor, DERIVE_KEYLEN, oracle, slot,
		    client, sizeof(client));
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
	 * The client key is a secret of the machine, and the public
	 * key and the name of it are not (ORC-REVOKE-6).
	 */
	explicit_bzero(client, sizeof(client));
	return rv;
}

/*
 * kit_line(k, oracle, slot, canary):
 *	One record line of the kit: the word record, the oracle
 *	index, and the record file name of kit_name().
 */
static int
kit_line(const struct kit *k, unsigned int oracle, uint32_t slot, int canary)
{
	char	 name[KIT_NAME_MAX];

	if (kit_name(k->factor, oracle, slot, canary, name,
	    sizeof(name)) != 0)
		return -1;
	printf("record %u %s\n", oracle, name);
	return 0;
}

/*
 * kit_print(k):
 *	The lines of the kit, on the standard output (ORC-REVOKE-6,
 *	PROG-ONESHOT-3). The first line names the machine. Each
 *	position then takes one line of its index and its URL, one
 *	line of each record of the machine there in slot order, and
 *	the canary line last (ORC-RECORDS-1, ORC-RECORDS-2). A
 *	retired position takes the word retired in place of its URL.
 *	The records of the machine stay at the departing oracle, and
 *	the owner destroys them with the kit (ORC-PROVISION-6,
 *	CER-PROVISION-16).
 *
 *	The kit of this machine takes the slot set of the wrap
 *	files, and the kit of a named machine takes each slot index
 *	below the next free slot index of the vault (kit_index).
 */
static int
kit_print(const struct kit *k)
{
	const char	*machine;
	size_t		 at;
	uint32_t	 slot;
	unsigned int	 i;

	machine = k->machine != NULL ? k->machine : k->config->machine;
	printf("machine %s\n", machine);
	for (i = 1; i <= k->config->count; i++) {
		if (k->config->oracle[i - 1].retired)
			printf("oracle %u retired\n", i);
		else
			printf("oracle %u %s\n", i,
			    k->config->oracle[i - 1].url);
		if (k->machine != NULL) {
			for (slot = 0; slot < k->slots; slot++) {
				if (kit_line(k, i, slot, 0) != 0)
					return -1;
			}
		} else {
			for (at = 0; at < k->slotlen; at++) {
				if (kit_line(k, i, k->slot[at], 0) != 0)
					return -1;
			}
		}
		if (kit_line(k, i, 0, 1) != 0)
			return -1;
	}
	if (fflush(stdout) != 0 || ferror(stdout)) {
		warn("the kit: the standard output");
		return -1;
	}
	return 0;
}

int
revoke_kit(const char *vault, const char *machine)
{
	struct kit	*k;
	int		 rv = -1;

	if (vault == NULL) {
		warnx("the kit takes an incomplete argument set");
		return -1;
	}
	if ((k = calloc(1, sizeof(*k))) == NULL) {
		warn("the kit");
		return -1;
	}
	if ((k->config = calloc(1, sizeof(*k->config))) == NULL) {
		warn("the kit");
		free(k);
		return -1;
	}
	k->vault = vault;
	k->machine = machine;

	if (kit_config(k) != 0)
		goto out;
	if (machine == NULL) {
		if (kit_factor(k) != 0 || kit_wraps(k) != 0)
			goto out;
	} else if (kit_plate(k) != 0)
		goto out;
	rv = kit_print(k);
out:
	/*
	 * The factor of a named machine belongs to that machine, and
	 * the factor of this machine persists on disk. Neither one
	 * stays in memory (KEY-DEVICE-2, SEC-MEMORY-5).
	 */
	explicit_bzero(k->factor, sizeof(k->factor));
	free(k->slot);
	free(k->config);
	free(k);
	return rv;
}
