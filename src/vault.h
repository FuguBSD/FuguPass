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
 * The vault on disk. One vault is one directory of flat files, and
 * one sealed file holds one entry (VAULT-LAYOUT-1). This file gives
 * the paths of that directory, the reader of the line format, the
 * atomic write, and the config file.
 *
 * vault_path() maps one file kind and its indexes to one path
 * (VAULT-LAYOUT). The shared set sits at the vault root, and the
 * machine-local set sits under VAULT_MACHINE_DIR (VAULT-LAYOUT-3,
 * VAULT-LAYOUT-4, VAULT-LAYOUT-6). The entry file of a slot takes
 * the name of vault_entry_name(): the lowercase hex of H(K_e)
 * (VAULT-LAYOUT-5, KEY-ENTRY-3). No name of the layout holds an
 * entry name or a site, so a listing of the directory holds neither
 * (VAULT-LAYOUT-7).
 *
 * vault_write() is the one writer of the tree, and every file kind
 * takes it (VAULT-ATOMIC-1).
 *
 * vault_scan() is the strict scanner of the line format
 * (VAULT-FORMAT-6). It reads field: value lines, and it takes the
 * field table of one file kind as data. A file kind adds a table,
 * and no file kind adds a rule to the scanner. This file holds the
 * table of the slot file, the index, the counters file, the change
 * marker, and the config file. entry.c holds the table of each of
 * the six entry types (ENTRY-TYPES-5).
 *
 * The table contract: a table is an array of rows, and the last row
 * holds a NULL name. A table holds 1 to VAULT_TABLE_MAX rows before
 * that last one. Each row states the name form, the value form, and
 * the flags of one field. A row without VAULT_FIELD_REPEAT takes
 * one line of that field in one file (VAULT-FORMAT-8). A row with
 * VAULT_FIELD_SECRET belongs to the secret block, and the scanner
 * rejects a secret field after a metadata field (VAULT-FORMAT-4).
 * The scanner walks the rows in order, and it takes the first row
 * that the field name matches. A row of a name form that holds an
 * index matches many names, so that row takes VAULT_FIELD_REPEAT.
 * A row with VAULT_FIELD_REPEAT takes one line of each object, and
 * the scanner rejects a second line of one object
 * (VAULT-FORMAT-8). The object of an indexed name is the name of
 * the line, and the object of a fixed name is the value before the
 * first space: the entry file name, the machine name, or the
 * record name.
 *
 * vault_seal_write() and vault_seal_read() are the pair that
 * takes a sealed file of the tree. The first one seals a
 * plaintext with seal.h and writes it with vault_write(). The
 * second one reads the file, opens it, and gives the plaintext to
 * vault_scan(). The caller holds the key and the field table, so
 * the pair adds no file kind: the entry file goes under K_e, and
 * the index goes under K_idx (KEY-ENTRY-3, VAULT-INDEX-1).
 *
 * vault_config_read() reads the config file, and it holds the
 * position rule of the oracle list (VAULT-CONFIG-6).
 * vault_config_change() holds the half of that rule that one file
 * cannot show.
 *
 * A value of a sealed file can be a secret, so vault_scan() clears
 * its own buffer on each exit path (SEC-MEMORY-1). Each caller
 * clears the buffers that it owns.
 */

#ifndef VAULT_H
#define VAULT_H

#include <stddef.h>
#include <stdint.h>

#include "derive.h"
#include "seal.h"

/*
 * The bytes of one line, with the line feed of it
 * (VAULT-FORMAT-5). A field name takes 1 byte or more, and the
 * colon and the space take 2, so a value takes 4 bytes less than a
 * line.
 */
#define VAULT_LINE_MAX		4096
#define VAULT_FIELDNAME_MAX	64
#define VAULT_VALUE_MAX		(VAULT_LINE_MAX - 4)

/* The rows of one field table, without the last row. */
#define VAULT_TABLE_MAX		64

/* The highest slot index: a slot index stays below 2^31 (KEY-ENTRY-1). */
#define VAULT_SLOT_MAX		INT32_MAX

/* The highest replay counter: a counter is a uint32 (ORC-COUNTER-1). */
#define VAULT_COUNTER_MAX	UINT32_MAX

/* An entry file name: the hex of H(K_e), and the terminator. */
#define VAULT_NAMELEN		(2 * DERIVE_KEYLEN + 1)

/* The subdirectory of the machine-local set (VAULT-LAYOUT-4). */
#define VAULT_MACHINE_DIR	"machine"

/*
 * The bytes of the two provisioned values of one oracle position:
 * the static public key as hex, and the URL (ORC-PROVISION-1).
 */
#define VAULT_OKEY_MAX		128
#define VAULT_URL_MAX		255

/* The form of the field name of one row. */
enum vault_name {
	VAULT_NAME_FIXED,	/* the name of the row, and no index */
	VAULT_NAME_ORACLE,	/* the name of the row, then an oracle index */
	VAULT_NAME_RECORD	/* a slot index, a hyphen, an oracle index */
};

/*
 * The form of the value of one row (VAULT-FORMAT-7). Every value
 * takes 1 byte or more. A file omits the line of an empty list.
 */
enum vault_value {
	VAULT_VALUE_TEXT,	/* UTF-8 text, with no line feed */
	VAULT_VALUE_WORD,	/* lowercase letters, digits and hyphens */
	VAULT_VALUE_NUMBER,	/* unpadded decimal ASCII, 0 to 2^31 - 1 */
	VAULT_VALUE_COUNTER,	/* a replay counter: 0 to 2^32 - 1 */
	VAULT_VALUE_SLOTS,	/* a slot list: indexes, one comma between */
	VAULT_VALUE_DATE,	/* YYYY-MM-DD */
	VAULT_VALUE_HEX,	/* lowercase hex, of an even count */
	VAULT_VALUE_ENTRY,	/* the entry line of the index */
	VAULT_VALUE_MACHINE,	/* a machine name, and the word retired */
	VAULT_VALUE_RECORD	/* a record name: <e>-<i>, or canary-<i> */
};

#define VAULT_FIELD_REPEAT	0x01	/* the field takes many lines */
#define VAULT_FIELD_SECRET	0x02	/* the field is of the secret block */

/* One row of a field table. */
struct vault_field {
	const char		*name;
	enum vault_name		 form;
	enum vault_value	 value;
	int			 flags;
};

/* One line that the scanner takes, for the callback of it. */
struct vault_line {
	const struct vault_field	*field;	  /* the row of the table */
	const char			*value;	  /* with a terminator */
	size_t				 valuelen;
	size_t				 number;  /* the 1-based line */
	uint32_t			 slot;	  /* of the name, or 0 */
	unsigned int			 oracle;  /* of the name, or 0 */
};

/*
 * The callback of vault_scan(). It gives 0 to take the line, and
 * -1 to stop the scan. The value of the line lives until the
 * callback returns, so a callback that keeps a value copies it.
 */
typedef int	(*vault_scan_cb)(const struct vault_line *, void *);

/* The file kinds of the layout (VAULT-LAYOUT). */
enum vault_file {
	VAULT_FILE_ENTRY,	/* <hex of H(K_e)>, the entry of a slot */
	VAULT_FILE_INDEX,	/* index */
	VAULT_FILE_FACTOR,	/* machine/factor */
	VAULT_FILE_WRAP,	/* machine/wrap.<e>.<i> */
	VAULT_FILE_WRAP_INDEX,	/* machine/wrap.index.<i> */
	VAULT_FILE_CANARY,	/* machine/canary.<i> */
	VAULT_FILE_COUNTERS,	/* machine/counters */
	VAULT_FILE_CONFIG,	/* machine/config */
	VAULT_FILE_CHANGE,	/* machine/change */
	VAULT_FILE_MAX
};

/*
 * The indexes of one path. A file kind reads the members that the
 * name of it holds, and it reads no other member.
 */
struct vault_at {
	const char	*name;		/* the entry file name */
	uint32_t	 slot;		/* the slot index e */
	unsigned int	 oracle;	/* the oracle index i, 1-based */
};

/* One oracle position of the config file (ORC-PROVISION-1). */
struct vault_oracle {
	char	key[VAULT_OKEY_MAX + 1];	/* the static public key */
	char	url[VAULT_URL_MAX + 1];
	int	retired;			/* the position holds no oracle */
};

/*
 * The config file, after the read. oracle[i - 1] holds position i,
 * and count is n, the highest position (VAULT-CONFIG-6). The struct
 * takes about 100 kilobytes, because a vault takes up to
 * DERIVE_ORACLE_MAX positions (KEY-SHARE-1). A program allocates
 * one of these, and it does not place one on a small stack.
 *
 * The reader takes the oracle positions and the threshold, and it
 * leaves each other member empty or 0 for a file that holds no line
 * of that field. The unit that owns the field states the default.
 */
struct vault_config {
	struct vault_oracle	 oracle[DERIVE_ORACLE_MAX];
	unsigned int		 count;		/* n */
	unsigned int		 threshold;	/* k (ORC-PROVISION-2) */
	unsigned int		 rounds;	/* kdf-rounds (KEY-PIN-5) */
	unsigned int		 pool_size;
	unsigned int		 pool_watermark;
	unsigned int		 audit_age;
	unsigned int		 lock_timeout;
	char			 machine[DERIVE_MACHINE_MAX + 1];
	char			 plate_check[VAULT_NAMELEN];
};

/*
 * The field table of each file kind of this unit. The tables of
 * VAULT-FORMAT cover the slot file, the index, the counters file,
 * and the change marker. VAULT-CONFIG holds the config table, and
 * that table is the complete field list of the config file
 * (VAULT-CONFIG-1). The config table holds no secret field, and the
 * scanner rejects every field that no table holds, so no secret
 * reaches the config file (VAULT-CONFIG-3, VAULT-CONFIG-4).
 */
extern const struct vault_field	vault_slot_fields[];
extern const struct vault_field	vault_index_fields[];
extern const struct vault_field	vault_counters_fields[];
extern const struct vault_field	vault_change_fields[];
extern const struct vault_field	vault_config_fields[];

/*
 * vault_entry_name(key, keylen, out, outlen):
 *	The entry file name of the entry key of keylen bytes at key,
 *	to the outlen bytes at out: the lowercase hex of H(K_e),
 *	with a terminator (VAULT-LAYOUT-5, KEY-ENTRY-3). keylen must
 *	be DERIVE_KEYLEN, and outlen must be VAULT_NAMELEN.
 *
 *	The name is public, and the entry key is a secret. The call
 *	keeps no copy of the key.
 */
int	vault_entry_name(const unsigned char *, size_t, char *, size_t);

/*
 * vault_path(out, outlen, vault, kind, at):
 *	The path of the file kind kind of the vault directory vault,
 *	to the outlen bytes at out (VAULT-LAYOUT). at holds the
 *	indexes of the file, and it can be NULL for a kind that
 *	takes no index.
 *
 *	The call gives -1 for an index that the layout rejects: an
 *	oracle index outside 1 to DERIVE_ORACLE_MAX, a slot index of
 *	2^31 or more (KEY-ENTRY-1), and a name that is not the hex
 *	of a 32-byte value. It gives -1 for a path that outlen does
 *	not take.
 */
int	vault_path(char *, size_t, const char *, enum vault_file,
	    const struct vault_at *);

/*
 * vault_scan(text, textlen, table, cb, arg):
 *	Read the textlen bytes at text as field: value lines, with
 *	the field table at table (VAULT-FORMAT-1, VAULT-FORMAT-6).
 *	Each line reaches cb with arg, in the order of the file.
 *
 *	The text ends with one line feed, and each line is the field
 *	name, one colon, one space, the value, and one line feed
 *	(VAULT-FORMAT-2). The call gives -1 for an unknown field, a
 *	line of more than VAULT_LINE_MAX bytes, a field name that
 *	holds another character than a lowercase letter, a digit or
 *	a hyphen, a value of no byte, a value that the form of the
 *	row rejects, a repeat that the table forbids, a secret field
 *	after a metadata field, and a callback that gives -1
 *	(VAULT-FORMAT-3 to VAULT-FORMAT-8).
 *
 *	A value holds no line feed, because the line feed ends the
 *	line (VAULT-FORMAT-7). A value holds no NUL byte, because
 *	the callback takes the value with a terminator.
 */
int	vault_scan(const char *, size_t, const struct vault_field *,
	    vault_scan_cb, void *);

/*
 * vault_number(text, len, max, out):
 *	The value of the unpadded decimal ASCII of len bytes at text,
 *	to out (VAULT-FORMAT-7). A leading zero, a character that is
 *	not a digit, and a value above max each give -1.
 *
 *	vault_scan() takes this rule for each number of a file, and a
 *	caller that reads a number out of a scanned value takes this
 *	same call with the bound of that number.
 */
int	vault_number(const char *, size_t, uint32_t, uint32_t *);

/*
 * vault_write(path, data, datalen):
 *	Write the datalen bytes at data to path, atomically
 *	(VAULT-ATOMIC-1). The sequence is mkstemp(3) in the
 *	directory of path, the write, fsync(2), rename(2) over
 *	path, and then fsync(2) of the directory.
 *
 *	datalen must be 1 or more. A failure before the rename(2)
 *	removes the temporary file and leaves path as it was
 *	(VAULT-ATOMIC-2). The call gives -1 on every failure.
 *
 *	The call creates no directory. A ceremony makes the vault
 *	directory and the machine-local subdirectory.
 */
int	vault_write(const char *, const unsigned char *, size_t);

/*
 * vault_seal_write(path, key, keylen, plain, plainlen, buf, buflen):
 *	Seal the plainlen bytes at plain under the key of keylen
 *	bytes at key, and write the sealed bytes to path
 *	(VAULT-SEAL-1, VAULT-ATOMIC-1). plainlen must be 1 or more,
 *	and keylen must be SEAL_KEYLEN. The seal holds the key gate.
 *
 *	buf takes the sealed bytes, so buflen must be plainlen plus
 *	SEAL_OVERHEAD, or more. Those bytes are public
 *	(VAULT-BACKUP-1), so the call leaves them at buf. The
 *	plaintext at plain belongs to the caller, and the caller
 *	clears it (SEC-MEMORY-1).
 *
 *	The call gives -1 on every failure. A failed seal writes no
 *	file.
 */
int	vault_seal_write(const char *, const unsigned char *, size_t,
	    const unsigned char *, size_t, unsigned char *, size_t);

/*
 * vault_seal_read(path, key, keylen, buf, buflen, table, cb, arg):
 *	Read the sealed file at path, open it under the key of
 *	keylen bytes at key, and read the plaintext of it with the
 *	field table at table (VAULT-SEAL-1, VAULT-FORMAT-6). Each
 *	line reaches cb with arg, as vault_scan() states. keylen
 *	must be SEAL_KEYLEN, and the open holds that gate.
 *
 *	buf takes the bytes of the file, and then the plaintext of
 *	them, so buflen must take the two. A file of SEAL_OVERHEAD
 *	bytes or fewer gives -1, and a file that buflen does not
 *	take gives -1.
 *
 *	The call gives -1 on every failure, and it names no cause
 *	(VAULT-SEAL-4). It clears buf on each exit path, because buf
 *	holds the plaintext (SEC-MEMORY-1).
 */
int	vault_seal_read(const char *, const unsigned char *, size_t,
	    unsigned char *, size_t, const struct vault_field *,
	    vault_scan_cb, void *);

/*
 * vault_config_read(text, textlen, cfg):
 *	Read the config file of textlen bytes at text, to cfg
 *	(VAULT-CONFIG-1). The text is the plaintext of the file,
 *	because the config carries no seal (VAULT-CONFIG-2).
 *
 *	The call gives -1 for a file that breaks the position rule:
 *	a file with no oracle position, a gap in the positions, a
 *	position twice, a file with no threshold, and a threshold
 *	outside 1 to the count of the live positions
 *	(VAULT-CONFIG-6). It gives -1 for an oracle value that is
 *	not the static public key hex, one space and the URL, and
 *	not the single word retired. A failure leaves cfg empty.
 */
int	vault_config_read(const char *, size_t, struct vault_config *);

/*
 * vault_config_change(from, to):
 *	0 when the change from the config from to the config to
 *	holds the position rule, and -1 when it breaks the rule
 *	(VAULT-CONFIG-6). A position must not disappear, and two
 *	positions must not exchange values. A position takes a
 *	replacement oracle or the retired state, and a change adds
 *	a position at the end of the list.
 *
 *	One file cannot show this half of the rule, so the caller of
 *	a config change reads both files and calls this function.
 */
int	vault_config_change(const struct vault_config *,
	    const struct vault_config *);

#endif /* VAULT_H */
