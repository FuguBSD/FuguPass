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
 * The vault on disk: the paths, the scanner, the writer, the
 * sealed pair, and the config. vault.h states the interface and
 * the table contract.
 *
 * The scanner holds one rule set, and the tables hold the fields.
 * A new file kind adds a table, and it adds no branch here. The
 * scanner reads no library: it walks the bytes of the text, and it
 * takes a line of VAULT_LINE_MAX bytes or fewer (VAULT-FORMAT-5,
 * VAULT-FORMAT-6).
 *
 * The layout table holds the paths of VAULT-LAYOUT. The want
 * member of a row names the indexes that the name of that file
 * takes, so one function builds every path.
 *
 * The sealed pair holds no rule of its own. It calls the seal of
 * seal.c, the writer above and the scanner above, and it holds
 * the bounds of the buffer between them.
 *
 * SHA-256 comes from libcrypto, for the entry file name alone
 * (VAULT-LAYOUT-5). No other library enters this file.
 */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/sha.h>

#include "derive.h"
#include "seal.h"
#include "vault.h"

/* The indexes that the name of one file kind takes. */
#define WANT_NAME	0x01
#define WANT_SLOT	0x02
#define WANT_ORACLE	0x04

/* The file name of the last row of a leaf, and of a temporary file. */
#define LEAF_MAX	(VAULT_NAMELEN + 24)
#define TMP_NAME	".tmp.XXXXXXXXXX"

/*
 * The slot file (VAULT-FORMAT). The two candidates are the secret
 * block, and they come first (VAULT-FORMAT-4, KEY-BIP85).
 */
const struct vault_field vault_slot_fields[] = {
	{ "candidate-password", VAULT_NAME_FIXED, VAULT_VALUE_TEXT,
	    VAULT_FIELD_SECRET },
	{ "candidate-mnemonic", VAULT_NAME_FIXED, VAULT_VALUE_TEXT,
	    VAULT_FIELD_SECRET },
	{ "slot", VAULT_NAME_FIXED, VAULT_VALUE_NUMBER, 0 },
	{ NULL, VAULT_NAME_FIXED, VAULT_VALUE_TEXT, 0 }
};

/*
 * The index (VAULT-FORMAT, VAULT-INDEX-2). One entry line holds one
 * entry, and one machine line holds one machine of the registry.
 * The value of a machine line carries the retired mark, and no
 * function of this file clears that mark (VAULT-INDEX-7).
 */
const struct vault_field vault_index_fields[] = {
	{ "entry", VAULT_NAME_FIXED, VAULT_VALUE_ENTRY, VAULT_FIELD_REPEAT },
	{ "machine", VAULT_NAME_FIXED, VAULT_VALUE_MACHINE,
	    VAULT_FIELD_REPEAT },
	{ "pool-free", VAULT_NAME_FIXED, VAULT_VALUE_SLOTS, 0 },
	{ "pool-next", VAULT_NAME_FIXED, VAULT_VALUE_NUMBER, 0 },
	{ "verified", VAULT_NAME_FIXED, VAULT_VALUE_DATE, 0 },
	{ NULL, VAULT_NAME_FIXED, VAULT_VALUE_TEXT, 0 }
};

/*
 * The counters file (VAULT-FORMAT, ORC-COUNTER). The field name is
 * the record name, so the file holds one line per record. The
 * scanner holds the form of a name, and the caller holds the rule
 * that one record takes one line.
 */
const struct vault_field vault_counters_fields[] = {
	{ "canary-", VAULT_NAME_ORACLE, VAULT_VALUE_NUMBER,
	    VAULT_FIELD_REPEAT },
	{ "", VAULT_NAME_RECORD, VAULT_VALUE_NUMBER, VAULT_FIELD_REPEAT },
	{ NULL, VAULT_NAME_FIXED, VAULT_VALUE_TEXT, 0 }
};

/* The change marker (VAULT-FORMAT). One done line holds one record. */
const struct vault_field vault_change_fields[] = {
	{ "kind", VAULT_NAME_FIXED, VAULT_VALUE_WORD, 0 },
	{ "done", VAULT_NAME_FIXED, VAULT_VALUE_RECORD, VAULT_FIELD_REPEAT },
	{ NULL, VAULT_NAME_FIXED, VAULT_VALUE_TEXT, 0 }
};

/*
 * The config file (VAULT-CONFIG-1). This table is the complete
 * field list, and it holds no secret (VAULT-CONFIG-3,
 * VAULT-CONFIG-4). vault_config_read() reads the two provisioned
 * values of a position from the value of an oracle line.
 */
const struct vault_field vault_config_fields[] = {
	{ "oracle-", VAULT_NAME_ORACLE, VAULT_VALUE_TEXT,
	    VAULT_FIELD_REPEAT },
	{ "threshold", VAULT_NAME_FIXED, VAULT_VALUE_NUMBER, 0 },
	{ "machine-name", VAULT_NAME_FIXED, VAULT_VALUE_WORD, 0 },
	{ "kdf-rounds", VAULT_NAME_FIXED, VAULT_VALUE_NUMBER, 0 },
	{ "plate-check", VAULT_NAME_FIXED, VAULT_VALUE_HEX, 0 },
	{ "pool-size", VAULT_NAME_FIXED, VAULT_VALUE_NUMBER, 0 },
	{ "pool-watermark", VAULT_NAME_FIXED, VAULT_VALUE_NUMBER, 0 },
	{ "audit-age", VAULT_NAME_FIXED, VAULT_VALUE_NUMBER, 0 },
	{ "lock-timeout", VAULT_NAME_FIXED, VAULT_VALUE_NUMBER, 0 },
	{ NULL, VAULT_NAME_FIXED, VAULT_VALUE_TEXT, 0 }
};

/*
 * The paths of the layout (VAULT-LAYOUT). base is the fixed name,
 * or the first part of a name that an index completes. want names
 * the indexes of that name, and machine puts the file in the
 * machine-local subdirectory (VAULT-LAYOUT-4, VAULT-LAYOUT-6).
 */
static const struct {
	const char	*base;
	int		 want;
	int		 machine;
} layout[VAULT_FILE_MAX] = {
	[VAULT_FILE_ENTRY]	= { NULL, WANT_NAME, 0 },
	[VAULT_FILE_INDEX]	= { "index", 0, 0 },
	[VAULT_FILE_FACTOR]	= { "factor", 0, 1 },
	[VAULT_FILE_WRAP]	= { "wrap", WANT_SLOT | WANT_ORACLE, 1 },
	[VAULT_FILE_WRAP_INDEX]	= { "wrap.index", WANT_ORACLE, 1 },
	[VAULT_FILE_CANARY]	= { "canary", WANT_ORACLE, 1 },
	[VAULT_FILE_COUNTERS]	= { "counters", 0, 1 },
	[VAULT_FILE_CONFIG]	= { "config", 0, 1 },
	[VAULT_FILE_CHANGE]	= { "change", 0, 1 }
};

/*
 * digits(text, len, out):
 *	The value of the len digits at text, to out. The text takes
 *	a leading zero, because a date pads each part
 *	(VAULT-FORMAT-7). A character that is not a digit gives -1.
 */
static int
digits(const char *text, size_t len, uint32_t *out)
{
	uint32_t	 value = 0;
	size_t		 i;

	if (len == 0 || len > 9)
		return -1;
	for (i = 0; i < len; i++) {
		if (text[i] < '0' || text[i] > '9')
			return -1;
		value = value * 10 + (uint32_t)(text[i] - '0');
	}
	*out = value;
	return 0;
}

int
vault_number(const char *text, size_t len, uint32_t max, uint32_t *out)
{
	uint64_t	 value = 0;
	size_t		 i;

	/* 10 digits hold every value below 2^32. */
	if (len == 0 || len > 10 || (len > 1 && text[0] == '0'))
		return -1;
	for (i = 0; i < len; i++) {
		if (text[i] < '0' || text[i] > '9')
			return -1;
		value = value * 10 + (uint64_t)(text[i] - '0');
	}
	if (value > max)
		return -1;
	*out = (uint32_t)value;
	return 0;
}

/*
 * word_ok(text, len):
 *	0 when the len bytes at text hold lowercase ASCII letters,
 *	digits and hyphens alone, and 1 byte or more. The field
 *	names take this character set (VAULT-FORMAT-3), and the
 *	machine name takes it too (KEY-DEVICE-3).
 */
static int
word_ok(const char *text, size_t len)
{
	size_t	 i;

	if (len == 0)
		return -1;
	for (i = 0; i < len; i++) {
		if ((text[i] >= 'a' && text[i] <= 'z') ||
		    (text[i] >= '0' && text[i] <= '9') || text[i] == '-')
			continue;
		return -1;
	}
	return 0;
}

/*
 * hex_ok(text, len):
 *	0 when the len bytes at text hold lowercase hex of an even
 *	count, and 1 byte or more.
 */
static int
hex_ok(const char *text, size_t len)
{
	size_t	 i;

	if (len == 0 || len % 2 != 0)
		return -1;
	for (i = 0; i < len; i++) {
		if ((text[i] >= '0' && text[i] <= '9') ||
		    (text[i] >= 'a' && text[i] <= 'f'))
			continue;
		return -1;
	}
	return 0;
}

/*
 * slots_ok(text, len):
 *	0 when the len bytes at text hold a slot list: slot indexes
 *	with one comma between two indexes, and no space
 *	(VAULT-FORMAT-7). A list holds 1 index or more, and a file
 *	omits the line of an empty list.
 */
static int
slots_ok(const char *text, size_t len)
{
	const char	*comma;
	uint32_t	 slot;
	size_t		 at = 0, part;

	for (;;) {
		comma = memchr(text + at, ',', len - at);
		part = (comma == NULL) ? len - at : (size_t)(comma - text) - at;
		if (vault_number(text + at, part, VAULT_SLOT_MAX, &slot) != 0)
			return -1;
		if (comma == NULL)
			return 0;
		at += part + 1;
	}
}

/*
 * date_ok(text, len):
 *	0 when the len bytes at text hold a date: YYYY-MM-DD
 *	(VAULT-FORMAT-7).
 */
static int
date_ok(const char *text, size_t len)
{
	uint32_t	 year, month, day;

	if (len != 10 || text[4] != '-' || text[7] != '-')
		return -1;
	if (digits(text, 4, &year) != 0 || digits(&text[5], 2, &month) != 0 ||
	    digits(&text[8], 2, &day) != 0)
		return -1;
	if (month < 1 || month > 12 || day < 1 || day > 31)
		return -1;
	return 0;
}

/*
 * record_ok(text, len):
 *	0 when the len bytes at text hold a record name: the slot
 *	index, a hyphen and the oracle index, or the literal canary,
 *	a hyphen and the oracle index (ORC-COUNTER).
 */
static int
record_ok(const char *text, size_t len)
{
	static const char	 canary[] = "canary";
	const char		*hyphen;
	uint32_t		 value;
	size_t			 head;

	if ((hyphen = memchr(text, '-', len)) == NULL)
		return -1;
	head = (size_t)(hyphen - text);
	if (vault_number(&hyphen[1], len - head - 1, DERIVE_ORACLE_MAX,
	    &value) != 0 || value == 0)
		return -1;
	if (head == sizeof(canary) - 1 && memcmp(text, canary, head) == 0)
		return 0;
	return vault_number(text, head, VAULT_SLOT_MAX, &value);
}

/*
 * machine_ok(text, len):
 *	0 when the len bytes at text hold one machine name, or one
 *	machine name, one space and the word retired (VAULT-INDEX-2,
 *	VAULT-INDEX-7). A machine name holds no space, so the
 *	suffix is plain. derive_machine_check() holds the name rule
 *	(KEY-DEVICE-3).
 */
static int
machine_ok(const char *text, size_t len)
{
	static const char	 retired[] = " retired";
	size_t			 mark = sizeof(retired) - 1;

	if (len > mark && memcmp(&text[len - mark], retired, mark) == 0)
		len -= mark;
	return derive_machine_check(text, len);
}

/*
 * entry_ok(text, len):
 *	0 when the len bytes at text hold one entry of the index:
 *	the entry file name, one space, the slot list, one space,
 *	and the entry name (VAULT-INDEX-2). The entry name comes
 *	last, so it can hold a space.
 */
static int
entry_ok(const char *text, size_t len)
{
	const char	*first, *second;
	size_t		 head, list;

	if ((first = memchr(text, ' ', len)) == NULL)
		return -1;
	head = (size_t)(first - text);
	if (head != 2 * DERIVE_KEYLEN || hex_ok(text, head) != 0)
		return -1;
	if ((second = memchr(&first[1], ' ', len - head - 1)) == NULL)
		return -1;
	list = (size_t)(second - first) - 1;
	if (slots_ok(&first[1], list) != 0)
		return -1;

	/* The entry name is the rest, and it holds 1 byte or more. */
	if ((size_t)(second - text) + 1 >= len)
		return -1;
	return 0;
}

/*
 * value_ok(form, text, len):
 *	0 when the len bytes at text hold the form form
 *	(VAULT-FORMAT-7). The caller holds the gates that every form
 *	shares: 1 byte or more, no NUL byte, and the line length.
 */
static int
value_ok(enum vault_value form, const char *text, size_t len)
{
	uint32_t	 value;

	switch (form) {
	case VAULT_VALUE_TEXT:
		return 0;
	case VAULT_VALUE_WORD:
		return word_ok(text, len);
	case VAULT_VALUE_NUMBER:
		return vault_number(text, len, VAULT_SLOT_MAX, &value);
	case VAULT_VALUE_SLOTS:
		return slots_ok(text, len);
	case VAULT_VALUE_DATE:
		return date_ok(text, len);
	case VAULT_VALUE_HEX:
		return hex_ok(text, len);
	case VAULT_VALUE_ENTRY:
		return entry_ok(text, len);
	case VAULT_VALUE_MACHINE:
		return machine_ok(text, len);
	case VAULT_VALUE_RECORD:
		return record_ok(text, len);
	}
	return -1;
}

/*
 * match_name(field, name, namelen, line):
 *	Match the field name of namelen bytes at name against the
 *	row field. A match writes the indexes of the name to line,
 *	and gives 0. Another name gives -1.
 */
static int
match_name(const struct vault_field *field, const char *name, size_t namelen,
    struct vault_line *line)
{
	const char	*hyphen;
	uint32_t	 value;
	size_t		 head;

	line->slot = 0;
	line->oracle = 0;
	head = strlen(field->name);
	switch (field->form) {
	case VAULT_NAME_FIXED:
		if (namelen != head || memcmp(name, field->name, head) != 0)
			return -1;
		return 0;
	case VAULT_NAME_ORACLE:
		if (namelen <= head || memcmp(name, field->name, head) != 0)
			return -1;
		if (vault_number(&name[head], namelen - head, DERIVE_ORACLE_MAX,
		    &value) != 0 || value == 0)
			return -1;
		line->oracle = (unsigned int)value;
		return 0;
	case VAULT_NAME_RECORD:
		if ((hyphen = memchr(name, '-', namelen)) == NULL)
			return -1;
		head = (size_t)(hyphen - name);
		if (vault_number(name, head, VAULT_SLOT_MAX, &value) != 0)
			return -1;
		line->slot = value;
		if (vault_number(&hyphen[1], namelen - head - 1,
		    DERIVE_ORACLE_MAX, &value) != 0 || value == 0)
			return -1;
		line->oracle = (unsigned int)value;
		return 0;
	}
	return -1;
}

int
vault_scan(const char *text, size_t textlen, const struct vault_field *table,
    vault_scan_cb cb, void *arg)
{
	struct vault_line	 line;
	char			 value[VAULT_VALUE_MAX + 1];
	const char		*at, *colon, *end, *feed;
	uint64_t		 seen = 0;
	size_t			 namelen, rows, row, valuelen;
	int			 metadata = 0, rv = -1;

	memset(&line, 0, sizeof(line));
	if (text == NULL || table == NULL || cb == NULL)
		return -1;
	for (rows = 0; table[rows].name != NULL; rows++)
		;
	if (rows == 0 || rows > VAULT_TABLE_MAX)
		return -1;

	/* A file of the line format holds one line or more. */
	if (textlen == 0)
		return -1;

	end = text + textlen;
	for (at = text; at < end; at = &feed[1]) {
		/*
		 * One line feed ends each line, so a text that does
		 * not end with one gives a failure (VAULT-FORMAT-2).
		 */
		if ((feed = memchr(at, '\n', (size_t)(end - at))) == NULL)
			goto out;
		line.number++;
		if ((size_t)(feed - at) + 1 > VAULT_LINE_MAX)
			goto out;

		/* The line is the name, one colon, one space, the value. */
		colon = memchr(at, ':', (size_t)(feed - at));
		if (colon == NULL || (size_t)(feed - colon) < 3 ||
		    colon[1] != ' ')
			goto out;
		namelen = (size_t)(colon - at);
		valuelen = (size_t)(feed - colon) - 2;
		if (namelen > VAULT_FIELDNAME_MAX ||
		    valuelen > VAULT_VALUE_MAX)
			goto out;
		if (word_ok(at, namelen) != 0)
			goto out;

		/* The value reaches the callback with a terminator. */
		if (memchr(&colon[2], '\0', valuelen) != NULL)
			goto out;

		for (row = 0; row < rows; row++)
			if (match_name(&table[row], at, namelen, &line) == 0)
				break;
		if (row == rows)
			goto out;	/* an unknown field */

		/* One line of a field, unless the row takes many. */
		if ((table[row].flags & VAULT_FIELD_REPEAT) == 0) {
			if ((seen & ((uint64_t)1 << row)) != 0)
				goto out;
			seen |= (uint64_t)1 << row;
		}

		/* The secret block comes first (VAULT-FORMAT-4). */
		if ((table[row].flags & VAULT_FIELD_SECRET) != 0) {
			if (metadata)
				goto out;
		} else
			metadata = 1;

		if (value_ok(table[row].value, &colon[2], valuelen) != 0)
			goto out;

		memcpy(value, &colon[2], valuelen);
		value[valuelen] = '\0';
		line.field = &table[row];
		line.value = value;
		line.valuelen = valuelen;
		if (cb(&line, arg) != 0)
			goto out;
	}
	rv = 0;
out:
	explicit_bzero(value, sizeof(value));
	return rv;
}

int
vault_entry_name(const unsigned char *key, size_t keylen, char *out,
    size_t outlen)
{
	unsigned char	 digest[SHA256_DIGEST_LENGTH];
	size_t		 i;

	if (key == NULL || out == NULL || keylen != DERIVE_KEYLEN ||
	    outlen != VAULT_NAMELEN)
		return -1;

	/*
	 * The digest is the file name on disk, so it is public. The
	 * entry key is the secret, and this call keeps no copy of
	 * it.
	 */
	SHA256(key, keylen, digest);
	for (i = 0; i < sizeof(digest); i++)
		snprintf(&out[2 * i], 3, "%02x", digest[i]);
	return 0;
}

int
vault_path(char *out, size_t outlen, const char *vault, enum vault_file kind,
    const struct vault_at *at)
{
	char	 leaf[LEAF_MAX];
	int	 n, want;

	if (out == NULL || vault == NULL || vault[0] == '\0' ||
	    (unsigned int)kind >= VAULT_FILE_MAX)
		return -1;
	want = layout[kind].want;
	if (want != 0 && at == NULL)
		return -1;
	if ((want & WANT_ORACLE) != 0 &&
	    (at->oracle == 0 || at->oracle > DERIVE_ORACLE_MAX))
		return -1;
	if ((want & WANT_SLOT) != 0 && at->slot > VAULT_SLOT_MAX)
		return -1;

	if ((want & WANT_NAME) != 0) {
		if (at->name == NULL ||
		    strlen(at->name) != VAULT_NAMELEN - 1 ||
		    hex_ok(at->name, VAULT_NAMELEN - 1) != 0)
			return -1;
		n = snprintf(leaf, sizeof(leaf), "%s", at->name);
	} else if (want == (WANT_SLOT | WANT_ORACLE))
		n = snprintf(leaf, sizeof(leaf), "%s.%" PRIu32 ".%u",
		    layout[kind].base, at->slot, at->oracle);
	else if ((want & WANT_ORACLE) != 0)
		n = snprintf(leaf, sizeof(leaf), "%s.%u", layout[kind].base,
		    at->oracle);
	else
		n = snprintf(leaf, sizeof(leaf), "%s", layout[kind].base);
	if (n < 0 || (size_t)n >= sizeof(leaf))
		return -1;

	n = snprintf(out, outlen, "%s/%s%s", vault,
	    layout[kind].machine ? VAULT_MACHINE_DIR "/" : "", leaf);
	if (n < 0 || (size_t)n >= outlen)
		return -1;
	return 0;
}

int
vault_write(const char *path, const unsigned char *data, size_t datalen)
{
	char		 dir[PATH_MAX], tmp[PATH_MAX];
	const char	*slash;
	ssize_t		 wrote;
	size_t		 at = 0;
	int		 fd = -1, dirfd = -1, moved = 0, n, rv = -1;

	if (path == NULL || data == NULL || datalen == 0)
		return -1;

	/* The temporary file sits in the directory of the target. */
	slash = strrchr(path, '/');
	if (slash == NULL)
		n = snprintf(dir, sizeof(dir), ".");
	else if (slash == path)
		n = snprintf(dir, sizeof(dir), "/");
	else if ((size_t)(slash - path) >= sizeof(dir))
		return -1;
	else
		n = snprintf(dir, sizeof(dir), "%.*s", (int)(slash - path),
		    path);
	if (n < 0 || (size_t)n >= sizeof(dir))
		return -1;
	n = snprintf(tmp, sizeof(tmp), "%s%s%s", dir,
	    slash == path ? "" : "/", TMP_NAME);
	if (n < 0 || (size_t)n >= sizeof(tmp))
		return -1;

	/* mkstemp(3) makes the file with the mode 0600. */
	if ((fd = mkstemp(tmp)) == -1)
		return -1;
	while (at < datalen) {
		wrote = write(fd, &data[at], datalen - at);
		if (wrote == -1) {
			if (errno == EINTR)
				continue;
			goto out;
		}
		if (wrote == 0)
			goto out;
		at += (size_t)wrote;
	}
	if (fsync(fd) == -1)
		goto out;
	n = close(fd);
	fd = -1;
	if (n == -1)
		goto out;

	/*
	 * The rename(2) is the one step that changes the target. A
	 * stop before it leaves the target as it was
	 * (VAULT-ATOMIC-2).
	 */
	if (rename(tmp, path) == -1)
		goto out;
	moved = 1;

	/* The fsync(2) of the directory holds the new name. */
	if ((dirfd = open(dir, O_RDONLY)) == -1)
		goto out;
	if (fsync(dirfd) == -1)
		goto out;
	rv = 0;
out:
	if (fd != -1)
		close(fd);
	if (dirfd != -1)
		close(dirfd);

	/*
	 * The unlink(2) takes the temporary file alone. After the
	 * rename(2), that name holds no file, and the target must
	 * stay.
	 */
	if (rv != 0 && !moved)
		unlink(tmp);
	return rv;
}

int
vault_seal_write(const char *path, const unsigned char *key, size_t keylen,
    const unsigned char *plain, size_t plainlen, unsigned char *buf,
    size_t buflen)
{
	size_t	 sealedlen;

	/*
	 * A plaintext of 0 bytes is no vault file, and the gate of
	 * it stops the overflow of the sum below.
	 */
	if (plain == NULL || buf == NULL || plainlen == 0 ||
	    plainlen > SIZE_MAX - SEAL_OVERHEAD)
		return -1;
	sealedlen = plainlen + SEAL_OVERHEAD;
	if (buflen < sealedlen)
		return -1;

	/* A failed seal leaves no plaintext at buf (seal.h). */
	if (seal_seal(key, keylen, plain, plainlen, buf, sealedlen) != 0)
		return -1;
	return vault_write(path, buf, sealedlen);
}

int
vault_seal_read(const char *path, const unsigned char *key, size_t keylen,
    unsigned char *buf, size_t buflen, const struct vault_field *table,
    vault_scan_cb cb, void *arg)
{
	ssize_t	 got;
	size_t	 plainlen, sealedlen = 0;
	int	 fd, rv = -1;

	if (path == NULL || buf == NULL)
		return -1;
	if ((fd = open(path, O_RDONLY)) == -1)
		return -1;

	/*
	 * The read stops at buflen bytes. A file of that many bytes
	 * leaves no room for the plaintext of it, so the fit gate
	 * below holds a longer file too.
	 */
	while (sealedlen < buflen) {
		got = read(fd, &buf[sealedlen], buflen - sealedlen);
		if (got == -1) {
			if (errno == EINTR)
				continue;
			goto out;
		}
		if (got == 0)
			break;
		sealedlen += (size_t)got;
	}

	/* The gate of the short file holds the subtraction below. */
	if (sealedlen <= SEAL_OVERHEAD)
		goto out;
	plainlen = sealedlen - SEAL_OVERHEAD;

	/* The plaintext takes the bytes of buf after the file. */
	if (plainlen > buflen - sealedlen)
		goto out;
	if (seal_open(key, keylen, buf, sealedlen, &buf[sealedlen],
	    plainlen) != 0)
		goto out;
	rv = vault_scan((const char *)&buf[sealedlen], plainlen, table, cb,
	    arg);
out:
	close(fd);

	/*
	 * buf holds the plaintext of the file, so each exit path
	 * clears it (SEC-MEMORY-1). Every failure above gives this
	 * one -1, with no message and no cause, so a caller learns
	 * nothing of the key (VAULT-SEAL-4).
	 */
	explicit_bzero(buf, buflen);
	return rv;
}

/* The state of one config read. */
struct config_state {
	struct vault_config	*cfg;
	uint64_t		 seen[(DERIVE_ORACLE_MAX + 63) / 64];
	unsigned int		 high;		/* the highest position */
	int			 threshold;	/* the file holds the line */
};

/*
 * oracle_value(value, valuelen, out):
 *	The two provisioned values of one position, from the valuelen
 *	bytes at value, to out (ORC-PROVISION-1). The value is the
 *	static public key hex, one space and the URL, or the single
 *	word retired (VAULT-CONFIG-6). Another value gives -1.
 */
static int
oracle_value(const char *value, size_t valuelen, struct vault_oracle *out)
{
	const char	*space;
	size_t		 keylen, urllen;

	if (valuelen == strlen("retired") &&
	    memcmp(value, "retired", valuelen) == 0) {
		out->retired = 1;
		return 0;
	}
	if ((space = memchr(value, ' ', valuelen)) == NULL)
		return -1;
	keylen = (size_t)(space - value);
	urllen = valuelen - keylen - 1;
	if (keylen > VAULT_OKEY_MAX || hex_ok(value, keylen) != 0)
		return -1;
	if (urllen == 0 || urllen > VAULT_URL_MAX ||
	    memchr(&space[1], ' ', urllen) != NULL)
		return -1;
	memcpy(out->key, value, keylen);
	out->key[keylen] = '\0';
	memcpy(out->url, &space[1], urllen);
	out->url[urllen] = '\0';
	out->retired = 0;
	return 0;
}

/*
 * config_line(line, arg):
 *	Take one line of the config file to the state at arg. The
 *	scanner holds the name and the form of each value, and this
 *	function holds the values of a position and the count of the
 *	positions (VAULT-CONFIG-6).
 */
static int
config_line(const struct vault_line *line, void *arg)
{
	struct config_state	*st = arg;
	struct vault_config	*cfg = st->cfg;
	const char		*name = line->field->name;
	uint64_t		 bit;
	uint32_t		 value;
	unsigned int		 at;

	if (line->field->form == VAULT_NAME_ORACLE) {
		at = line->oracle - 1;
		bit = (uint64_t)1 << (at % 64);
		if ((st->seen[at / 64] & bit) != 0)
			return -1;	/* the position holds two lines */
		st->seen[at / 64] |= bit;
		if (line->oracle > st->high)
			st->high = line->oracle;
		return oracle_value(line->value, line->valuelen,
		    &cfg->oracle[at]);
	}
	if (strcmp(name, "machine-name") == 0) {
		/*
		 * The word form of the row holds the character set
		 * of the name, and this gate holds the byte count
		 * of it (KEY-DEVICE-3).
		 */
		if (line->valuelen >= sizeof(cfg->machine))
			return -1;
		memcpy(cfg->machine, line->value, line->valuelen);
		cfg->machine[line->valuelen] = '\0';
		return 0;
	}
	if (strcmp(name, "plate-check") == 0) {
		/* The plate check value holds 32 bytes (KEY-MASTER-5). */
		if (line->valuelen != 2 * DERIVE_KEYLEN)
			return -1;
		memcpy(cfg->plate_check, line->value, line->valuelen);
		cfg->plate_check[line->valuelen] = '\0';
		return 0;
	}

	/* The table holds every other field to a number. */
	if (vault_number(line->value, line->valuelen, VAULT_SLOT_MAX,
	    &value) != 0)
		return -1;
	if (strcmp(name, "threshold") == 0) {
		cfg->threshold = value;
		st->threshold = 1;
	} else if (strcmp(name, "kdf-rounds") == 0)
		cfg->rounds = value;
	else if (strcmp(name, "pool-size") == 0)
		cfg->pool_size = value;
	else if (strcmp(name, "pool-watermark") == 0)
		cfg->pool_watermark = value;
	else if (strcmp(name, "audit-age") == 0)
		cfg->audit_age = value;
	else if (strcmp(name, "lock-timeout") == 0)
		cfg->lock_timeout = value;
	else
		return -1;	/* the table and this function must agree */
	return 0;
}

int
vault_config_read(const char *text, size_t textlen, struct vault_config *cfg)
{
	struct config_state	 st;
	unsigned int		 i, live = 0;

	if (cfg == NULL)
		return -1;
	memset(cfg, 0, sizeof(*cfg));
	memset(&st, 0, sizeof(st));
	st.cfg = cfg;
	if (vault_scan(text, textlen, vault_config_fields, config_line,
	    &st) != 0)
		goto bad;

	/* VAULT-CONFIG-6 binds the positions and the threshold. */
	if (st.high == 0 || !st.threshold)
		goto bad;

	/* The positions run from 1 to n with no gap (VAULT-CONFIG-6). */
	for (i = 1; i <= st.high; i++) {
		if ((st.seen[(i - 1) / 64] &
		    ((uint64_t)1 << ((i - 1) % 64))) == 0)
			goto bad;
		if (!cfg->oracle[i - 1].retired)
			live++;
	}
	cfg->count = st.high;

	/* k takes the count of the live positions or less. */
	if (cfg->threshold == 0 || cfg->threshold > live)
		goto bad;
	return 0;
bad:
	memset(cfg, 0, sizeof(*cfg));
	return -1;
}

/*
 * same_oracle(a, b):
 *	1 when the two positions hold one value.
 */
static int
same_oracle(const struct vault_oracle *a, const struct vault_oracle *b)
{
	if (a->retired != b->retired)
		return 0;
	return strcmp(a->key, b->key) == 0 && strcmp(a->url, b->url) == 0;
}

int
vault_config_change(const struct vault_config *from,
    const struct vault_config *to)
{
	unsigned int	 i, j;

	if (from == NULL || to == NULL || from->count == 0 || to->count == 0)
		return -1;

	/* A position must not disappear (VAULT-CONFIG-6). */
	if (to->count < from->count)
		return -1;

	/*
	 * Two positions must not exchange values (VAULT-CONFIG-6). A
	 * position that takes the live value of another position is
	 * that exchange, and the move of one value is the same
	 * failure. A replacement oracle and the retired state each
	 * pass, because no other position held that value.
	 */
	for (i = 1; i <= to->count; i++) {
		if (i <= from->count &&
		    same_oracle(&from->oracle[i - 1], &to->oracle[i - 1]))
			continue;
		if (to->oracle[i - 1].retired)
			continue;
		for (j = 1; j <= from->count; j++) {
			if (j == i || from->oracle[j - 1].retired)
				continue;
			if (same_oracle(&from->oracle[j - 1],
			    &to->oracle[i - 1]))
				return -1;
		}
	}
	return 0;
}
