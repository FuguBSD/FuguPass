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
 * The two recovery paths (REC-PLATE, REC-VAULT). recover.h states
 * the one entry point and the two sources of a recovery.
 *
 * scan_plate() reads the master from the plate and derives root. It
 * is the one input of a recovery, and the oracle gates no path here
 * (REC-PRINCIPLE-4, D-04). has_shared_set() then reads the vault
 * directory: an index file or one entry file marks the shared set.
 *
 * recover_vault() is the plate-plus-files path (REC-VAULT). For each
 * slot from 0 to the ceiling, it re-derives K_e, names the file with
 * H(K_e), and opens the file of that name under K_e (REC-VAULT-1,
 * REC-VAULT-2). index_open() opens the index under K_idx from root,
 * and emit_entry() names each recovered entry from that index. An
 * index that does not open leaves the names as file names, and it
 * loses no secret (REC-RESTORE-5, VAULT-INDEX-5). A free pool slot
 * file maps to no entry, and the path skips it.
 *
 * recover_plate() is the plate-alone path (REC-PLATE). It re-derives
 * the entry key of every slot from 0 to the ceiling, and it
 * re-materializes the two BIP85 candidates of each slot
 * (REC-PLATE-1, KEY-BIP85). A scan past the last used slot is safe,
 * because the derivation is deterministic (REC-PLATE-3). The report
 * names the scanned range (REC-PLATE-2).
 *
 * A recovered secret prints to the terminal through tty_secret(),
 * one entry at a time, and no secret reaches a file (PROG-OUTPUT-1,
 * PROG-OUTPUT-4). The master, root, each entry key, each candidate,
 * and the plaintext of the index leave memory on every path
 * (SEC-MEMORY-1, SEC-MEMORY-5).
 */

#include <sys/types.h>

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bip85.h"
#include "derive.h"
#include "entry.h"
#include "helper.h"
#include "recover.h"
#include "seal.h"
#include "session.h"
#include "vault.h"

/*
 * The bytes of the sealed index, and one more. session.h states the
 * plaintext bound of the index, and a count of this value names a
 * file that is too long (vault.h).
 */
#define INDEX_RAW_MAX	(SESSION_INDEX_MAX + SEAL_OVERHEAD + 1)

/* The bytes of a sealed entry file, and one more. */
#define ENTRY_RAW_MAX	(SESSION_PLAIN_MAX + SEAL_OVERHEAD + 1)

/* One lookup of an entry line of the index, by file name. */
struct idx_find {
	const char	*file;			/* the file name to match */
	char		 name[VAULT_VALUE_MAX + 1];
	char		 type[VAULT_FIELDNAME_MAX + 1];
	int		 found;
};

/* The state of one secret print of an entry file. */
struct print_state {
	int	 fail;
};

static int	 write_all(int, const char *, size_t);
static int	 tty_secret(const char *);
static int	 scan_plate(unsigned char *);
static int	 is_entry_name(const char *);
static int	 has_shared_set(const char *);
static int	 gate(const struct vault_line *, void *);
static int	 type_capture(const struct vault_line *, void *);
static int	 detect_type(const char *, size_t, enum entry_type *);
static int	 idx_find_line(const struct vault_line *, void *);
static int	 print_secret(const struct vault_line *, void *);
static char	*index_open(const char *, const unsigned char *, size_t *);
static int	 emit_entry(const char *, size_t, const char *, const char *,
		     size_t);
static int	 recover_vault(const char *, const unsigned char *,
		     unsigned int);
static int	 recover_plate(const unsigned char *, unsigned int);

/*
 * write_all(fd, data, len):
 *	The len bytes at data to the file descriptor fd. The call
 *	gives -1 for a write that fails, and 0 for the bytes.
 */
static int
write_all(int fd, const char *data, size_t len)
{
	ssize_t	 n;
	size_t	 at = 0;

	while (at < len) {
		n = write(fd, &data[at], len - at);
		if (n == -1 && errno == EINTR)
			continue;
		if (n <= 0)
			return -1;
		at += (size_t)n;
	}
	return 0;
}

/*
 * tty_secret(value):
 *	One recovered secret to the terminal, on one line
 *	(PROG-OUTPUT-1). The standard output carries no secret, so a
 *	pipe of it takes none (PROG-OUTPUT-4). The call gives -1 for a
 *	process with no terminal, and the terminal takes no secret
 *	then. stdio holds no copy of the bytes (SEC-MEMORY-1).
 */
static int
tty_secret(const char *value)
{
	int	 fd, rv = -1;

	if ((fd = open("/dev/tty", O_WRONLY | O_CLOEXEC)) == -1) {
		warn("/dev/tty");
		return -1;
	}
	if (write_all(fd, value, strlen(value)) == 0 &&
	    write_all(fd, "\n", 1) == 0)
		rv = 0;
	else
		warn("/dev/tty");
	close(fd);
	return rv;
}

/*
 * scan_plate(root):
 *	The master of the plate, to root (CER-CREATE-1, KEY-MASTER-3).
 *	The scan helper gives the words of the master as one line of
 *	text (PROG-SCAN-5). The gate of the master rejects a count
 *	other than 12 words and a wrong checksum, and the message of
 *	it holds no word (KEY-MASTER-6).
 *
 *	The master leaves memory here, and root leaves memory in the
 *	caller (SEC-MEMORY-5).
 */
static int
scan_plate(unsigned char *root)
{
	char	 master[DERIVE_MASTER_MAX + 1];
	char	 err[DERIVE_ERRLEN];
	char	*feed;
	size_t	 len = 0;
	int	 rv = -1;

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
	if (derive_root(master, len, root, DERIVE_ROOTLEN) != 0) {
		warnx("the master: the seed of it fails");
		goto out;
	}
	rv = 0;
out:
	explicit_bzero(master, sizeof(master));
	return rv;
}

/*
 * is_entry_name(name):
 *	1 when name is the lowercase hex of a 32-byte value, and 0 for
 *	every other name (VAULT-LAYOUT-5). An entry file and a free
 *	pool slot file take this name.
 */
static int
is_entry_name(const char *name)
{
	size_t	 i;

	for (i = 0; i < 2 * DERIVE_KEYLEN; i++) {
		if (!((name[i] >= '0' && name[i] <= '9') ||
		    (name[i] >= 'a' && name[i] <= 'f')))
			return 0;
	}
	return name[2 * DERIVE_KEYLEN] == '\0';
}

/*
 * has_shared_set(vault):
 *	1 when the vault directory vault holds a shared set, and 0
 *	otherwise (VAULT-LAYOUT-3). The index file or one entry file
 *	marks the set. The plate-plus-files path takes a directory
 *	with a set, and the plate-alone path takes a directory with
 *	none (REC-PLATE, REC-VAULT). An absent directory holds no set.
 */
static int
has_shared_set(const char *vault)
{
	DIR		*dp;
	struct dirent	*ent;
	int		 found = 0;

	if ((dp = opendir(vault)) == NULL)
		return 0;
	while ((ent = readdir(dp)) != NULL) {
		if (strcmp(ent->d_name, "index") == 0 ||
		    is_entry_name(ent->d_name)) {
			found = 1;
			break;
		}
	}
	closedir(dp);
	return found;
}

/*
 * gate(line, arg):
 *	Take one line and keep nothing. The detection of a free pool
 *	slot file scans the plaintext with this callback (ENTRY-POOL).
 */
static int
gate(const struct vault_line *line, void *arg)
{
	(void)line;
	(void)arg;
	return 0;
}

/*
 * type_capture(line, arg):
 *	Take the type line of an entry file to the entry type at arg
 *	(ENTRY-TYPES-1). A type line that no row resolves stops the
 *	scan, so a table that names another type gives no match.
 */
static int
type_capture(const struct vault_line *line, void *arg)
{
	enum entry_type	*out = arg;

	if (strcmp(line->field->name, "type") != 0)
		return 0;
	return entry_type_find(line->value, line->valuelen, out);
}

/*
 * detect_type(plain, len, out):
 *	The entry type of the plaintext of len bytes at plain, to out
 *	(ENTRY-TYPES-5). The call scans the plaintext with each type
 *	table, and the type of a match is the table whose fields the
 *	file holds and whose type line names that table. Each type
 *	holds a secret field of its own name, so one table alone
 *	matches an entry file.
 *
 *	The call gives 0 for an entry file, and -1 for a free pool
 *	slot file and for a malformed file. The caller then tests the
 *	slot table (ENTRY-POOL-9).
 */
static int
detect_type(const char *plain, size_t len, enum entry_type *out)
{
	enum entry_type	 t, named;

	for (t = 0; t < ENTRY_TYPE_MAX; t++) {
		named = ENTRY_TYPE_MAX;
		if (vault_scan(plain, len, entry_types[t].fields, type_capture,
		    &named) == 0 && named == t) {
			*out = t;
			return 0;
		}
	}
	return -1;
}

/*
 * idx_find_line(line, arg):
 *	Take one entry line of the index, and keep the name and the
 *	type of the line whose file name is the file of arg
 *	(VAULT-INDEX-2). The value holds the file name, the type name,
 *	the slot list, and the entry name, with one space between two
 *	parts. The entry name comes last, so it can hold a space.
 */
static int
idx_find_line(const struct vault_line *line, void *arg)
{
	struct idx_find	*f = arg;
	char		 buf[VAULT_VALUE_MAX + 1];
	char		*type, *slots, *name, *space;

	if (f->found || strcmp(line->field->name, "entry") != 0)
		return 0;
	if (line->valuelen >= sizeof(buf))
		return 0;
	memcpy(buf, line->value, line->valuelen);
	buf[line->valuelen] = '\0';

	if ((space = strchr(buf, ' ')) == NULL)
		return 0;
	*space = '\0';
	if (strcmp(buf, f->file) != 0)
		return 0;
	type = &space[1];
	if ((space = strchr(type, ' ')) == NULL)
		return 0;
	*space = '\0';
	slots = &space[1];
	if ((space = strchr(slots, ' ')) == NULL)
		return 0;
	name = &space[1];
	if (strlen(type) >= sizeof(f->type) || strlen(name) >= sizeof(f->name))
		return 0;
	strlcpy(f->type, type, sizeof(f->type));
	strlcpy(f->name, name, sizeof(f->name));
	f->found = 1;
	return 0;
}

/*
 * print_secret(line, arg):
 *	Print each secret field of an entry file to the terminal
 *	(VAULT-FORMAT-4, PROG-OUTPUT-1). A metadata field takes no
 *	print, and a shadow entry holds no secret field. A failed
 *	write sets the fail of arg and stops the scan.
 */
static int
print_secret(const struct vault_line *line, void *arg)
{
	struct print_state	*p = arg;

	if ((line->field->flags & VAULT_FIELD_SECRET) != 0 &&
	    tty_secret(line->value) != 0) {
		p->fail = 1;
		return -1;
	}
	return 0;
}

/*
 * index_open(vault, root, outlen):
 *	The plaintext of the index of the vault, under K_idx from root
 *	(VAULT-INDEX-1, VAULT-INDEX-4). The call derives K_idx and
 *	opens the index of the shared set, with no oracle request
 *	(KEY-MASK-6). The plaintext bytes go to outlen, and the caller
 *	frees and clears the buffer.
 *
 *	The call gives NULL for an absent index, for a file that is no
 *	sealed file of this vault, and for an index that the plate
 *	does not open (REC-RESTORE-5). A stale index still opens, and
 *	it degrades the names alone. The caller then names each entry
 *	by its file name.
 */
static char *
index_open(const char *vault, const unsigned char *root, size_t *outlen)
{
	unsigned char	 idxkey[DERIVE_KEYLEN];
	unsigned char	*raw = NULL;
	char		*plain = NULL;
	char		 path[PATH_MAX];
	size_t		 len = 0;

	*outlen = 0;
	if (derive_index_key(root, DERIVE_ROOTLEN, idxkey, sizeof(idxkey)) != 0)
		goto out;
	if (vault_path(path, sizeof(path), vault, VAULT_FILE_INDEX, NULL) != 0)
		goto out;
	if ((raw = malloc(INDEX_RAW_MAX)) == NULL ||
	    (plain = malloc(SESSION_INDEX_MAX)) == NULL) {
		warn("the recovery");
		goto out;
	}
	if (vault_read(path, raw, INDEX_RAW_MAX, &len) != 0)
		goto out;
	if (len <= SEAL_OVERHEAD || len == INDEX_RAW_MAX)
		goto out;
	if (seal_open(idxkey, sizeof(idxkey), raw, len,
	    (unsigned char *)plain, len - SEAL_OVERHEAD) != 0)
		goto out;

	*outlen = len - SEAL_OVERHEAD;
	explicit_bzero(idxkey, sizeof(idxkey));
	explicit_bzero(raw, INDEX_RAW_MAX);
	free(raw);
	return plain;
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
	return NULL;
}

/*
 * emit_entry(idx, idxlen, name, plain, plainlen):
 *	One recovered entry file, on the standard output and the
 *	terminal (REC-VAULT-2, PROG-OUTPUT-1). name is the file name
 *	H(K_e), and plain is the plaintext of the file. The index of
 *	idxlen bytes at idx gives the entry name and the type, and a
 *	NULL idx names the entry by its file name (REC-RESTORE-5).
 *
 *	The call prints the entry name on the standard output, and
 *	each secret field on the terminal. A free pool slot file maps
 *	to no entry, so the call skips it and gives 0 (ENTRY-POOL-9).
 *	The call gives -1 for a malformed file and for a failed write.
 */
static int
emit_entry(const char *idx, size_t idxlen, const char *name,
    const char *plain, size_t plainlen)
{
	struct idx_find		 find;
	struct print_state	 ps;
	enum entry_type		 type;
	const char		*disp;

	memset(&find, 0, sizeof(find));
	find.file = name;
	if (idx != NULL)
		(void)vault_scan(idx, idxlen, vault_index_fields, idx_find_line,
		    &find);

	if (find.found &&
	    entry_type_find(find.type, strlen(find.type), &type) == 0)
		disp = find.name;
	else if (detect_type(plain, plainlen, &type) == 0)
		disp = name;
	else {
		if (vault_scan(plain, plainlen, vault_slot_fields, gate,
		    NULL) == 0)
			return 0;
		warnx("%s: the file holds no entry of a known type", name);
		return -1;
	}

	if (printf("%s\n", disp) < 0) {
		warn("the recovery: the standard output");
		return -1;
	}
	memset(&ps, 0, sizeof(ps));
	if (vault_scan(plain, plainlen, entry_types[type].fields, print_secret,
	    &ps) != 0 || ps.fail != 0) {
		if (ps.fail == 0)
			warnx("%s: the file disagrees with its type", name);
		return -1;
	}
	return 0;
}

/*
 * recover_vault(vault, root, ceiling):
 *	The plate-plus-files path (REC-VAULT). For each slot from 0 to
 *	the ceiling, the call re-derives K_e, names the file with
 *	H(K_e), and opens the file of that name under K_e (REC-VAULT-1,
 *	REC-VAULT-2). It opens the index once for the entry names, and
 *	a stale or absent index degrades the names alone (REC-VAULT-3,
 *	REC-RESTORE-5).
 *
 *	The call gives 0 when each present file recovers, and -1 when
 *	one file does not open or one write fails. A slot with no file
 *	takes no action, because the pool of a vault holds fewer slots
 *	than the ceiling (REC-PLATE-3). Each entry key and the
 *	plaintext of a file leave memory before the return
 *	(SEC-MEMORY-6).
 */
static int
recover_vault(const char *vault, const unsigned char *root, unsigned int ceiling)
{
	unsigned char	 key[DERIVE_KEYLEN];
	char		 name[VAULT_NAMELEN];
	char		 path[PATH_MAX];
	struct vault_at	 at;
	unsigned char	*raw = NULL;
	char		*plain = NULL;
	char		*idx = NULL;
	size_t		 idxlen = 0;
	uint32_t	 e;
	int		 rv = -1;

	idx = index_open(vault, root, &idxlen);
	if ((raw = malloc(ENTRY_RAW_MAX)) == NULL ||
	    (plain = malloc(SESSION_PLAIN_MAX)) == NULL) {
		warn("the recovery");
		goto out;
	}

	rv = 0;
	for (e = 0; e < ceiling; e++) {
		size_t	 len = 0;

		if (derive_entry_key(root, DERIVE_ROOTLEN, e, key,
		    sizeof(key)) != 0) {
			warnx("slot %" PRIu32 ": the entry key fails", e);
			rv = -1;
			continue;
		}
		if (vault_entry_name(key, sizeof(key), name, sizeof(name)) != 0)
			continue;
		memset(&at, 0, sizeof(at));
		at.name = name;
		if (vault_path(path, sizeof(path), vault, VAULT_FILE_ENTRY,
		    &at) != 0)
			continue;
		if (vault_read(path, raw, ENTRY_RAW_MAX, &len) != 0) {
			warn("%s", path);
			rv = -1;
			continue;
		}
		if (len == 0)
			continue;
		if (len <= SEAL_OVERHEAD || len == ENTRY_RAW_MAX) {
			warnx("%s: the file is no sealed file of this vault",
			    name);
			rv = -1;
			continue;
		}
		if (seal_open(key, sizeof(key), raw, len,
		    (unsigned char *)plain, len - SEAL_OVERHEAD) != 0) {
			warnx("%s: the file does not open under the entry key",
			    name);
			rv = -1;
			continue;
		}
		if (emit_entry(idx, idxlen, name, plain, len - SEAL_OVERHEAD)
		    != 0)
			rv = -1;
	}
	if (fflush(stdout) != 0 || ferror(stdout)) {
		warn("the recovery: the standard output");
		rv = -1;
	}
out:
	explicit_bzero(key, sizeof(key));
	if (raw != NULL) {
		explicit_bzero(raw, ENTRY_RAW_MAX);
		free(raw);
	}
	if (plain != NULL) {
		explicit_bzero(plain, SESSION_PLAIN_MAX);
		free(plain);
	}
	if (idx != NULL) {
		explicit_bzero(idx, SESSION_INDEX_MAX);
		free(idx);
	}
	return rv;
}

/*
 * recover_plate(root, ceiling):
 *	The plate-alone path (REC-PLATE). The call re-materializes the
 *	two BIP85 candidates of every slot from 0 to the ceiling, and
 *	it prints each candidate on the terminal (REC-PLATE-1,
 *	KEY-BIP85). It reports the scanned range on the standard
 *	output (REC-PLATE-2). A scan past the last used slot is safe,
 *	because the derivation is deterministic (REC-PLATE-3).
 *
 *	The call gives 0 when each candidate materializes and each
 *	write passes, and -1 otherwise. Each candidate leaves memory
 *	before the return (SEC-MEMORY-5).
 */
static int
recover_plate(const unsigned char *root, unsigned int ceiling)
{
	char		 pwd[BIP85_PWD_MAX];
	char		 mnemonic[BIP85_MNEMONIC_MAX];
	uint32_t	 e;
	int		 rv = -1;

	if (printf("plate slots 0 to %u\n", ceiling - 1) < 0) {
		warn("the recovery: the standard output");
		goto out;
	}
	for (e = 0; e < ceiling; e++) {
		if (bip85_pwd_base64(root, DERIVE_ROOTLEN, e, pwd,
		    sizeof(pwd)) != 0 ||
		    bip85_bip39(root, DERIVE_ROOTLEN, e, mnemonic,
		    sizeof(mnemonic)) != 0) {
			warnx("slot %" PRIu32 ": a candidate fails", e);
			goto out;
		}
		if (printf("slot %" PRIu32 "\n", e) < 0) {
			warn("the recovery: the standard output");
			goto out;
		}
		if (tty_secret(pwd) != 0 || tty_secret(mnemonic) != 0)
			goto out;
	}
	if (fflush(stdout) != 0 || ferror(stdout)) {
		warn("the recovery: the standard output");
		goto out;
	}
	rv = 0;
out:
	explicit_bzero(pwd, sizeof(pwd));
	explicit_bzero(mnemonic, sizeof(mnemonic));
	return rv;
}

int
recover_run(const char *vault, unsigned int ceiling)
{
	unsigned char	 root[DERIVE_ROOTLEN];
	int		 rv;

	if (vault == NULL || ceiling == 0) {
		warnx("the recovery takes an incomplete argument set");
		return -1;
	}
	if (scan_plate(root) != 0)
		return -1;
	if (has_shared_set(vault))
		rv = recover_vault(vault, root, ceiling);
	else
		rv = recover_plate(root, ceiling);
	explicit_bzero(root, sizeof(root));
	return rv;
}
