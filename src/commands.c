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
 * The six commands. commands.h states the interface, and each
 * command reads the open session of session.h (PROG-ONESHOT-2).
 *
 * ls reads the entry list of the open index, and it sends no
 * request (PROG-REPL-3). show and totp each reveal one entry, and
 * audit reveals the entries of the index in order (PROG-REPL-4).
 *
 * create() holds add and gen, because the two commands differ in
 * two points: the origin class of the entry, and the origin of the
 * secret (ENTRY-MODEL-1, ENTRY-POOL-4). gen takes the candidate of
 * the consumed slot, and add takes the secret from the terminal
 * (ENTRY-TYPES-4, SEC-MEMORY-4).
 *
 * A name that the index already holds takes a rotation
 * (ENTRY-ROTATION-5). gen consumes a new slot, and it extends the
 * slot list of the entry (ENTRY-ROTATION-1, ENTRY-ROTATION-2). add
 * seals the new secret in the slot of the entry, and it writes no
 * index (ENTRY-ROTATION-4). Both rotations read the current entry
 * first, and they carry the metadata of it to the new file. That
 * read is one quorum event, and the consumption of gen is another.
 *
 * A consumption runs in one order: the lowest free slot of the pool
 * with the wraps of this machine, the reveal of the slot file with
 * the two candidates, the index with the slot consumed, and then
 * the entry file (ENTRY-POOL-3, ENTRY-POOL-8, ENTRY-POOL-9). The
 * records and the wraps of the slot stay as they are, because no
 * step of this file writes one (ENTRY-POOL-5).
 *
 * The index names the type of each entry, and the type carries the
 * field table of an entry file (VAULT-INDEX-2, ENTRY-TYPES-5).
 * index_type() therefore takes the type of one entry from the open
 * index, and it sends no request. A command that refuses an entry
 * of the wrong type refuses it there, before the reveal.
 *
 * The entry file owns the type, and the index holds a copy of it.
 * file_type() proves that the file of a reveal agrees with the
 * index. The audit takes the type of each entry from the index, it
 * reveals the shadow entries alone, and it sends no request for an
 * entry of another type (ENTRY-SHADOW-4, ENTRY-SHADOW-5,
 * PROG-REPL-4).
 *
 * A mnemonic entry takes the QR code of the render helper, and the
 * -w option of show takes the words as text (PROG-OUTPUT-2). The
 * helper runs as a child of helper.h, so this file renders no code
 * of its own (PROG-SPLIT-2).
 *
 * Every record goes through record(), and every report goes to the
 * standard error (PROG-ONESHOT-3). A one-shot subcommand takes its
 * records from the standard output, and the session of iface.c takes
 * them from the sink of commands_sink() (PROG-IFACE-13). A secret
 * goes to /dev/tty, so a pipe of the standard output carries none
 * (PROG-OUTPUT-1, PROG-OUTPUT-4).
 *
 * The secret of an entry lives in the plaintext of the session, and
 * the session clears it (SEC-MEMORY-1). This file clears each
 * buffer of its own on each exit path: the secret of a terminal
 * read, the candidate of a slot, the TOTP key, the TOTP code, and
 * the composed plaintext of an entry file.
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "ceremony.h"
#include "commands.h"
#include "derive.h"
#include "entry.h"
#include "fugupass.h"
#include "helper.h"
#include "qr.h"
#include "session.h"
#include "vault.h"

/* The -f options of one command: the rows of one field table. */
#define FIELD_MAX	VAULT_TABLE_MAX

/* The bytes of one value of the line format, with the terminator. */
#define VALUE_MAX	(VAULT_VALUE_MAX + 1)

/*
 * The bytes of the rendered QR code of a mnemonic (PROG-QR-6,
 * PROG-QR-9). The code holds QR_MNEMONIC_WIDTH modules on each
 * side, and a quiet zone of QR_QUIET light modules stands on each
 * side of it. One character carries two module rows, one half block
 * takes three bytes of UTF-8, and one line feed ends each line. The
 * terminator of helper_run() takes the last byte.
 */
#define CODE_SIDE	(QR_MNEMONIC_WIDTH + 2 * QR_QUIET)
#define CODE_MAX	(((CODE_SIDE + 1) / 2) * (CODE_SIDE * 3 + 1) + 1)

/* One text buffer of the line format, and the length of it. */
struct text {
	char	*at;
	size_t	 len;
	size_t	 size;
	int	 fail;
};

/* The command line of add and of gen. */
struct newentry {
	const char		*name;		/* the entry name */
	const char		*field[FIELD_MAX];
	const char		*value[FIELD_MAX];
	size_t			 count;		/* the -f options */
	enum entry_type		 type;
	enum entry_class	 class;
	int			 typeset;	/* the -T option came */
	int			 derived;	/* the command is gen */
};

/* The lines of the index that one write of this file replaces. */
struct rewrite {
	struct text	*text;
	const char	*drop;		/* the entry file name of a line */
	int		 pool;		/* the pool-free line goes */
};

/* One slot file field of a totp entry (ENTRY-TYPES-3). */
struct totp_state {
	char			 key[VALUE_MAX];
	enum entry_totp_alg	 alg;
	unsigned int		 digits;
	unsigned int		 period;
	int			 have;
};

/* The verification date of one shadow entry, or of the index. */
struct date_state {
	char	date[ENTRY_DATE_MAX];
	int	have;
};

/* The metadata of the current version, for a rotation. */
struct meta_state {
	struct text		*text;
	const struct newentry	*entry;
};

static void	 text_init(struct text *, char *, size_t);
static void	 text_add(struct text *, const char *, const char *);
static void	 text_cat(struct text *, const struct text *);
static int	 gate(const struct vault_line *, void *);
static int	 write_all(int, const char *, size_t);
static int	 tty_write(const char *, size_t, int);
static int	 secret_print(const char *);
static int	 secret_qr(const char *);
static void	 record(const char *, ...);
static const struct commands_cmd *find(const char *);
static int	 usage_cmd(const char *);
static int	 index_ready(const struct session *);
static int	 entry_find(const struct session *, const char *,
		     const struct session_entry **);
static int	 type_line(const struct vault_line *, void *);
static int	 index_type(const struct session_entry *, enum entry_type *);
static int	 file_type(const struct session_entry *, enum entry_type,
		     const char *, size_t);
static const struct vault_field *field_of(enum entry_type, const char *);
static int	 own_field(const char *);
static int	 meta_line(const struct vault_line *, void *);
static int	 copy_line(const struct vault_line *, void *);
static int	 pool_line(const struct vault_line *, void *);
static int	 ready(void *, uint32_t);
static int	 pool_read(const struct session *, struct entry_pool *);
static int	 index_write(struct session *, const char *, const char *,
		     const struct entry_pool *);
static int	 parse_new(struct newentry *, int, char *[], int);
static int	 fields_check(const struct newentry *, enum entry_type);
static int	 create(struct session *, struct newentry *);
static int	 show_line(const struct vault_line *, void *);
static int	 date_line(const struct vault_line *, void *);
static int	 totp_line(const struct vault_line *, void *);
static int	 hex_digit(char);
static int	 hex_bytes(const char *, unsigned char *, size_t, size_t *);
static int	 cmd_ls(struct session *, int, char *[]);
static int	 cmd_show(struct session *, int, char *[]);
static int	 cmd_add(struct session *, int, char *[]);
static int	 cmd_gen(struct session *, int, char *[]);
static int	 cmd_totp(struct session *, int, char *[]);
static int	 cmd_audit(struct session *, int, char *[]);

/*
 * The sink of the output records (PROG-IFACE-13). The standard
 * output takes each record of a one-shot subcommand, and iface.c
 * gives the reply pipe of a session in place of it.
 */
static void	(*sink)(const char *);

/*
 * A record that one line does not take (PROG-IFACE-13).
 * commands_run() clears the flag before each command, and it fails
 * a command that left the flag.
 */
static int	 record_fail;

/*
 * The six commands of the session (PROG-REPL-3). The interface
 * process adds help and quit, and neither one reaches this table
 * (PROG-IFACE-1).
 */
const struct commands_cmd commands_table[] = {
	{ "ls",		"", cmd_ls },
	{ "show",	"[-w] name", cmd_show },
	{ "add",	"[-T type] [-c class] [-f name=value ...] name",
	    cmd_add },
	{ "gen",	"[-T type] [-f name=value ...] name", cmd_gen },
	{ "totp",	"name", cmd_totp },
	{ "audit",	"", cmd_audit },
	{ NULL,		NULL, NULL }
};

/*
 * text_init(t, at, size):
 *	The empty text of the size bytes at at.
 */
static void
text_init(struct text *t, char *at, size_t size)
{
	t->at = at;
	t->len = 0;
	t->size = size;
	t->fail = 0;
	if (size != 0)
		at[0] = '\0';
}

/*
 * text_add(t, name, value):
 *	One line of the field name with the value value, at the end
 *	of t (VAULT-FORMAT-2). A text that the size does not take
 *	sets the failure of t, and each later call gives no line.
 */
static void
text_add(struct text *t, const char *name, const char *value)
{
	int	 n;

	if (t->fail)
		return;
	n = snprintf(&t->at[t->len], t->size - t->len, "%s: %s\n", name,
	    value);
	if (n < 0 || (size_t)n >= t->size - t->len) {
		t->fail = 1;
		return;
	}
	t->len += (size_t)n;
}

/*
 * text_cat(t, from):
 *	The lines of from, at the end of t.
 */
static void
text_cat(struct text *t, const struct text *from)
{
	if (t->fail || from->fail)
		t->fail = 1;
	if (t->fail || from->len == 0)
		return;
	if (from->len >= t->size - t->len) {
		t->fail = 1;
		return;
	}
	memcpy(&t->at[t->len], from->at, from->len);
	t->len += from->len;
	t->at[t->len] = '\0';
}

/*
 * gate(line, arg):
 *	Take one line, and keep nothing. The scanner reads a composed
 *	text with this callback, so a text that the reader rejects
 *	writes no file (VAULT-FORMAT-6).
 */
static int
gate(const struct vault_line *line, void *arg)
{
	(void)line;
	(void)arg;
	return 0;
}

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
 * tty_write(data, len, feed):
 *	The len bytes at data to the terminal, and one line feed
 *	after them when feed holds one (PROG-OUTPUT-1). The standard
 *	output carries no secret, so a pipe of it takes none
 *	(PROG-OUTPUT-4).
 *
 *	The call writes the bytes of the caller, and stdio holds no
 *	copy of them (SEC-MEMORY-1). It gives -1 for a process with
 *	no terminal, and the terminal takes no secret then.
 */
static int
tty_write(const char *data, size_t len, int feed)
{
	int	 fd, rv = -1;

	if ((fd = open("/dev/tty", O_WRONLY | O_CLOEXEC)) == -1) {
		warn("/dev/tty");
		return -1;
	}
	if (write_all(fd, data, len) == 0 &&
	    (feed == 0 || write_all(fd, "\n", 1) == 0))
		rv = 0;
	else
		warn("/dev/tty");
	close(fd);
	return rv;
}

/*
 * secret_print(value):
 *	One secret to the terminal, on one line (PROG-OUTPUT-1).
 */
static int
secret_print(const char *value)
{
	return tty_write(value, strlen(value), 1);
}

/*
 * secret_qr(value):
 *	The QR code of one secret to the terminal, in UTF-8 half
 *	blocks (PROG-OUTPUT-2). The render helper reads the bytes of
 *	the secret on its standard input, and it writes the code back
 *	(PROG-QR-1). This process renders no code of its own
 *	(PROG-SPLIT-2).
 *
 *	The value of a mnemonic entry is 12 words with one space
 *	between two words, and the helper reads that form as a
 *	Standard SeedQR (PROG-QR-7). One line feed ends each line of
 *	the answer, so the terminal takes the bytes of the helper and
 *	no other byte (PROG-QR-9).
 *
 *	The call gives 0, and -1 for a failed run of the helper and
 *	for a failed write. A failed run leaves the terminal without
 *	a code, because the helper writes the whole code or no code
 *	(PROG-QR-3). The buffer takes the code of a mnemonic, and a
 *	value of another form takes the code of a vault file: such a
 *	code is longer, and the run of it fails here. The report
 *	therefore names the -w option. The call clears the code of
 *	the buffer (SEC-MEMORY-1).
 */
static int
secret_qr(const char *value)
{
	char	 code[CODE_MAX];
	size_t	 len = 0;
	int	 rv;

	if (helper_run(HELPER_QR, value, strlen(value), code, sizeof(code),
	    &len) != 0) {
		warnx("the mnemonic: the render of the QR code fails, and "
		    "the -w option prints the words of the entry");
		rv = -1;
	} else
		rv = tty_write(code, len, 0);
	explicit_bzero(code, sizeof(code));
	return rv;
}

/*
 * record(fmt, ...):
 *	One output record of a command, on one line of its own
 *	(PROG-ONESHOT-3). The caller gives the record without the
 *	line feed, and the sink of the session takes the record in
 *	place of the standard output (PROG-IFACE-13).
 *
 *	Each record carries one value of a vault line, behind a name
 *	that is no longer than the name of that line: show writes the
 *	name of the line back, audit writes a date and one space
 *	before an entry name of the index, and ls writes that name
 *	alone. One record therefore takes the line of VAULT-FORMAT-5
 *	without the line feed of it, and the buffer below holds that
 *	record (PROG-IFACE-13).
 *
 *	The metadata line of show reaches that bound exactly. The
 *	stale line of audit stays below it, because the index line
 *	carries the entry file name, the type name and the slot list
 *	before the entry name. The reply line of iface.c takes the
 *	same record inside the frame of the reply pipe.
 *
 *	A record above that bound reaches no sink, because a
 *	truncated record is a wrong record. The report of it goes to
 *	the standard error, and the flag fails the command. A dropped
 *	record is a missing output line, so the command must not
 *	report success (PROG-IFACE-13).
 */
static void
record(const char *fmt, ...)
{
	char	 line[VAULT_LINE_MAX];
	va_list	 ap;
	int	 n;

	va_start(ap, fmt);
	n = vsnprintf(line, sizeof(line), fmt, ap);
	va_end(ap);

	if (n < 0 || (size_t)n >= sizeof(line)) {
		warnx("the record of the command does not fit one line");
		record_fail = 1;
		return;
	}
	if (sink == NULL)
		printf("%s\n", line);
	else
		sink(line);
}

/*
 * find(name):
 *	The row of the command name, and NULL for a name that the
 *	table does not hold.
 */
static const struct commands_cmd *
find(const char *name)
{
	const struct commands_cmd	*c;

	for (c = commands_table; c->name != NULL; c++) {
		if (strcmp(c->name, name) == 0)
			return c;
	}
	return NULL;
}

/*
 * usage_cmd(name):
 *	The usage line of the command name, to the standard error,
 *	and -1 for the caller.
 */
static int
usage_cmd(const char *name)
{
	const struct commands_cmd	*c;

	if ((c = find(name)) != NULL)
		fprintf(stderr, "usage: %s %s\n", c->name, c->args);
	return -1;
}

/*
 * index_ready(s):
 *	0 for a session that holds an open index, and -1 with a
 *	report for a session without one (ORC-CANARY-8). Each command
 *	resolves an entry name through the index, so each one takes
 *	this gate.
 */
static int
index_ready(const struct session *s)
{
	size_t	 len = 0;

	if (session_index(s, &len) != NULL)
		return 0;
	warnx("the index of this session stays closed, so the command "
	    "resolves no entry name");
	return -1;
}

/*
 * entry_find(s, name, out):
 *	The entry of the name name in the open index, to out
 *	(VAULT-INDEX-2). A name that the index does not hold gives 0
 *	with NULL at out, and that state is a new entry.
 *
 *	A name at two entries gives -1: the command names one entry,
 *	and the index gives two.
 */
static int
entry_find(const struct session *s, const char *name,
    const struct session_entry **out)
{
	const struct session_entry	*list;
	size_t				 i, count = 0;

	*out = NULL;
	if ((list = session_list(s, &count)) == NULL)
		return -1;
	for (i = 0; i < count; i++) {
		if (strcmp(list[i].name, name) != 0)
			continue;
		if (*out != NULL) {
			warnx("the index holds two entries of the name %s",
			    name);
			return -1;
		}
		*out = &list[i];
	}
	return 0;
}

/*
 * type_line(line, arg):
 *	Take the type line of an entry file to the entry type at arg
 *	(ENTRY-TYPES-1). A type name that no row holds stops the
 *	scan.
 */
static int
type_line(const struct vault_line *line, void *arg)
{
	enum entry_type	*out = arg;

	if (strcmp(line->field->name, "type") != 0)
		return 0;
	return entry_type_find(line->value, line->valuelen, out);
}

/*
 * index_type(e, out):
 *	The entry type of the index entry e, to out (VAULT-INDEX-2,
 *	ENTRY-TYPES-1). The call reads the open index alone, so it
 *	sends no oracle request.
 *
 *	A type name that this tool does not hold gives -1 with a
 *	report.
 */
static int
index_type(const struct session_entry *e, enum entry_type *out)
{
	if (entry_type_find(e->type, strlen(e->type), out) != 0) {
		warnx("the entry %s: the index names the type %s, and this "
		    "tool holds no type of that name", e->name, e->type);
		return -1;
	}
	return 0;
}

/*
 * file_type(e, type, plain, plainlen):
 *	0 when the entry file of plainlen bytes at plain holds one
 *	entry of the type type (ENTRY-TYPES-5). The file owns the
 *	type, and the index holds a copy of it, so each reveal takes
 *	this gate (VAULT-INDEX-2).
 *
 *	The file agrees when the field table of the type takes it,
 *	and when the type line of it names that type. A file of
 *	another shape gives -1 with a report.
 */
static int
file_type(const struct session_entry *e, enum entry_type type,
    const char *plain, size_t plainlen)
{
	enum entry_type	 named = ENTRY_TYPE_MAX;

	if (vault_scan(plain, plainlen, entry_types[type].fields, type_line,
	    &named) == 0 && named == type)
		return 0;
	warnx("the entry %s: the index names the type %s, and the file of it "
	    "holds no entry of that type", e->name, entry_types[type].name);
	return -1;
}

/*
 * field_of(type, name):
 *	The row of the field name name of the entry type type, and
 *	NULL for a name that the table of the type does not hold
 *	(ENTRY-TYPES-5).
 */
static const struct vault_field *
field_of(enum entry_type type, const char *name)
{
	const struct vault_field	*f;

	for (f = entry_types[type].fields; f->name != NULL; f++) {
		if (strcmp(f->name, name) == 0)
			return f;
	}
	return NULL;
}

/*
 * own_field(name):
 *	1 for a field that this file writes, and 0 for every other
 *	field. The type and the slot list come from the entry
 *	(ENTRY-TYPES-5, ENTRY-ROTATION-2), and the version is the
 *	position of the slot in that list (ENTRY-ROTATION-1).
 */
static int
own_field(const char *name)
{
	return strcmp(name, "type") == 0 || strcmp(name, "slots") == 0 ||
	    strcmp(name, "version") == 0;
}

/*
 * meta_line(line, arg):
 *	Take one metadata line of the current entry file to the text
 *	of the state at arg. The secret of the file, the fields of
 *	this file, and each field of a -f option stay out: the
 *	composition writes those.
 */
static int
meta_line(const struct vault_line *line, void *arg)
{
	struct meta_state	*m = arg;
	const char		*name = line->field->name;
	size_t			 i;

	if ((line->field->flags & VAULT_FIELD_SECRET) != 0 ||
	    own_field(name))
		return 0;
	for (i = 0; i < m->entry->count; i++) {
		if (strcmp(m->entry->field[i], name) == 0)
			return 0;
	}
	text_add(m->text, name, line->value);
	return m->text->fail ? -1 : 0;
}

/*
 * copy_line(line, arg):
 *	Take one line of the open index to the text of the state at
 *	arg. The entry line of the file name at drop, and the
 *	pool-free line of a write of the pool, each stay out: the
 *	caller writes those again.
 */
static int
copy_line(const struct vault_line *line, void *arg)
{
	struct rewrite	*r = arg;
	const char	*name = line->field->name;

	if (r->pool && strcmp(name, "pool-free") == 0)
		return 0;
	if (r->drop != NULL && strcmp(name, "entry") == 0 &&
	    strncmp(line->value, r->drop, 2 * DERIVE_KEYLEN) == 0)
		return 0;
	text_add(r->text, name, line->value);
	return r->text->fail ? -1 : 0;
}

/*
 * pool_line(line, arg):
 *	Take the pool-free line of the index to the pool at arg
 *	(VAULT-INDEX-2). An index with no such line leaves the empty
 *	pool of the caller (ENTRY-POOL-7).
 */
static int
pool_line(const struct vault_line *line, void *arg)
{
	if (strcmp(line->field->name, "pool-free") != 0)
		return 0;
	return entry_pool_set(arg, line->value, line->valuelen);
}

/*
 * ready(arg, slot):
 *	The test of entry_pool_take(): 0 when this machine holds
 *	wraps of the slot index slot at k or more live oracles
 *	(ENTRY-POOL-3, KEY-MASK-4). arg is the session.
 */
static int
ready(void *arg, uint32_t slot)
{
	return session_slot_ready(arg, slot);
}

/*
 * pool_read(s, pool):
 *	The free slots of the open index of the session s, to pool
 *	(ENTRY-POOL-1, VAULT-INDEX-2).
 */
static int
pool_read(const struct session *s, struct entry_pool *pool)
{
	const char	*text;
	size_t		 len = 0;

	memset(pool, 0, sizeof(*pool));
	if ((text = session_index(s, &len)) == NULL)
		return -1;
	return vault_scan(text, len, vault_index_fields, pool_line, pool);
}

/*
 * index_write(s, drop, entry, pool):
 *	The index of the session, with the entry line entry, without
 *	the entry line of the file name drop, and with the free slots
 *	of pool (VAULT-INDEX-2). A NULL drop drops no line, a NULL
 *	entry adds none, and a NULL pool keeps the free slots of the
 *	file.
 *
 *	A pool of no free slot writes no pool-free line, because a
 *	value of the line format holds one byte or more
 *	(VAULT-FORMAT-7).
 */
static int
index_write(struct session *s, const char *drop, const char *entry,
    const struct entry_pool *pool)
{
	struct rewrite	 r;
	struct text	 t;
	const char	*text;
	char		*buf;
	size_t		 len = 0;
	int		 rv = -1;

	if ((text = session_index(s, &len)) == NULL)
		return -1;
	if ((buf = malloc(SESSION_INDEX_MAX)) == NULL)
		return -1;
	text_init(&t, buf, SESSION_INDEX_MAX);
	r.text = &t;
	r.drop = drop;
	r.pool = pool != NULL;
	if (vault_scan(text, len, vault_index_fields, copy_line, &r) != 0)
		goto out;
	if (entry != NULL)
		text_add(&t, "entry", entry);
	if (pool != NULL && pool->free[0] != '\0')
		text_add(&t, "pool-free", pool->free);
	if (t.fail)
		goto out;
	rv = session_index_write(s, t.at, t.len);
out:
	if (rv != 0)
		warnx("the index takes no write of this command");
	explicit_bzero(buf, SESSION_INDEX_MAX);
	free(buf);
	return rv;
}

/*
 * parse_new(ne, argc, argv, derived):
 *	The command line of add or of gen, to ne (PROG-ONESHOT-8).
 *	derived states gen: the entry takes the derived class, and
 *	the command takes no class option (ENTRY-MODEL-1).
 *
 *	The call gives -1 with the usage line for a command line that
 *	the rules above reject.
 */
static int
parse_new(struct newentry *ne, int argc, char *argv[], int derived)
{
	const char	*name;
	char		*value;
	size_t		 i;
	int		 ch;

	memset(ne, 0, sizeof(*ne));
	ne->derived = derived;
	ne->class = derived ? ENTRY_CLASS_DERIVED : ENTRY_CLASS_STORED;
	name = derived ? "gen" : "add";

	optreset = 1;
	optind = 1;
	while ((ch = getopt(argc, argv, derived ? "T:f:" : "T:c:f:")) != -1) {
		switch (ch) {
		case 'T':
			if (entry_type_find(optarg, strlen(optarg),
			    &ne->type) != 0) {
				warnx("the entry type %s: no type of that "
				    "name", optarg);
				return -1;
			}
			ne->typeset = 1;
			break;
		case 'c':
			if (entry_class_find(optarg, strlen(optarg),
			    &ne->class) != 0) {
				warnx("the origin class %s: no class of that "
				    "name", optarg);
				return -1;
			}
			break;
		case 'f':
			if (ne->count == FIELD_MAX) {
				warnx("the command takes %d fields at most",
				    FIELD_MAX);
				return -1;
			}
			if ((value = strchr(optarg, '=')) == NULL) {
				warnx("the field %s: the form is name=value",
				    optarg);
				return -1;
			}
			*value = '\0';
			for (i = 0; i < ne->count; i++) {
				if (strcmp(ne->field[i], optarg) != 0)
					continue;
				warnx("the field %s comes twice", optarg);
				return -1;
			}
			ne->field[ne->count] = optarg;
			ne->value[ne->count] = &value[1];
			ne->count++;
			break;
		default:
			return usage_cmd(name);
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 1)
		return usage_cmd(name);
	ne->name = argv[0];
	return 0;
}

/*
 * fields_check(ne, type):
 *	0 when each -f option of ne names a metadata field of the
 *	entry type type, and -1 with a report for every other option
 *	(ENTRY-TYPES-5).
 *
 *	A secret takes no option, because the process list holds each
 *	argument (SEC-MEMORY-4, PROG-OUTPUT-4). The type, the slot
 *	list and the version take none either, because this file
 *	writes them.
 */
static int
fields_check(const struct newentry *ne, enum entry_type type)
{
	const struct vault_field	*f;
	size_t				 i;

	for (i = 0; i < ne->count; i++) {
		if (own_field(ne->field[i])) {
			warnx("the field %s: the tool writes it",
			    ne->field[i]);
			return -1;
		}
		if ((f = field_of(type, ne->field[i])) == NULL) {
			warnx("the field %s: the type %s holds no field of "
			    "that name", ne->field[i],
			    entry_types[type].name);
			return -1;
		}
		if ((f->flags & VAULT_FIELD_SECRET) != 0) {
			warnx("the field %s: a secret enters from the "
			    "terminal", ne->field[i]);
			return -1;
		}
	}
	return 0;
}

/*
 * create(s, ne):
 *	add and gen: one new entry of the name of ne, or one rotation
 *	of the entry of that name (ENTRY-POOL-4, ENTRY-ROTATION-5).
 *
 *	A new entry and a rotation of gen each consume the lowest
 *	free slot of the pool, and the write order is the index, then
 *	the entry file (ENTRY-POOL-3, ENTRY-POOL-8). A rotation of
 *	add consumes no slot, and it seals the new secret in the slot
 *	of the entry (ENTRY-ROTATION-4).
 */
static int
create(struct session *s, struct newentry *ne)
{
	const struct session_entry	*old = NULL;
	const struct vault_config	*cfg;
	struct entry_pool		 pool;
	struct meta_state		 m;
	struct text			 meta, body;
	const char			*plain, *secret;
	char				 pass[FUGUPASS_PASS_MAX];
	char				 candidate[ENTRY_CANDIDATE_MAX];
	char				 slots[VALUE_MAX];
	char				 list[VALUE_MAX];
	char				 line[VALUE_MAX];
	char				 drop[VAULT_NAMELEN];
	char				 number[16];
	enum entry_type			 type;
	size_t				 i, plainlen = 0;
	uint32_t			 slot;
	unsigned int			 version, watermark;
	int				 consumes, n, rv = -1;

	memset(&pool, 0, sizeof(pool));
	memset(pass, 0, sizeof(pass));
	memset(candidate, 0, sizeof(candidate));
	slots[0] = '\0';
	drop[0] = '\0';
	meta.at = NULL;
	body.at = NULL;
	cfg = session_config(s);

	if (index_ready(s) != 0 || entry_find(s, ne->name, &old) != 0)
		return -1;
	if ((meta.at = malloc(SESSION_PLAIN_MAX)) == NULL ||
	    (body.at = malloc(SESSION_PLAIN_MAX)) == NULL)
		goto out;
	text_init(&meta, meta.at, SESSION_PLAIN_MAX);
	text_init(&body, body.at, SESSION_PLAIN_MAX);

	/*
	 * A rotation takes the type of the entry from the index, so
	 * a command line of the wrong type refuses before the quorum
	 * event (VAULT-INDEX-2).
	 */
	if (old != NULL) {
		if (index_type(old, &type) != 0)
			goto out;
		if (ne->typeset && ne->type != type) {
			warnx("the entry %s holds the type %s", ne->name,
			    entry_types[type].name);
			goto out;
		}
	} else {
		if (!ne->typeset) {
			warnx("the -T option names the entry type of the new "
			    "entry %s", ne->name);
			goto out;
		}
		type = ne->type;
	}

	if (entry_class_check(type, ne->class) != 0) {
		warnx("the type %s takes no %s entry", entry_types[type].name,
		    entry_classes[ne->class].name);
		goto out;
	}
	if (ne->derived &&
	    entry_types[type].candidate == ENTRY_CANDIDATE_NONE) {
		warnx("the type %s takes no candidate of a slot",
		    entry_types[type].name);
		goto out;
	}
	if (fields_check(ne, type) != 0)
		goto out;

	/*
	 * The secret of add enters from the terminal, before the
	 * quorum event of each path, so a read that fails consumes
	 * no slot, and no entry key waits in memory for the read
	 * (SEC-MEMORY-4, SEC-MEMORY-6). A shadow entry holds no
	 * secret, and it takes no read (ENTRY-SHADOW-1).
	 */
	secret = NULL;
	if (entry_types[type].secret != NULL && !ne->derived) {
		if (fugupass_passphrase("Secret: ", pass, sizeof(pass)) != 0) {
			warnx("the secret: the read fails");
			goto out;
		}
		secret = pass;
	}

	/*
	 * A rotation reads the current entry: the metadata that the
	 * new file carries, and the proof that the file holds the
	 * type of the index (ENTRY-ROTATION-5). The read of add
	 * holds the entry key of the slot, because the seal of add
	 * takes that same key (ENTRY-ROTATION-4).
	 */
	if (old != NULL) {
		if (ne->derived) {
			if (session_reveal(s, old->slot, &plain,
			    &plainlen) != 0)
				goto out;
		} else if (session_consume(s, old->slot, &plain,
		    &plainlen) != 0)
			goto out;
		if (file_type(old, type, plain, plainlen) != 0)
			goto out;
		m.text = &meta;
		m.entry = ne;
		if (vault_scan(plain, plainlen, entry_types[type].fields,
		    meta_line, &m) != 0) {
			warnx("the entry %s: the metadata of it does not fit",
			    ne->name);
			goto out;
		}
		n = snprintf(slots, sizeof(slots), "%s", old->slots);
		if (n < 0 || (size_t)n >= sizeof(slots))
			goto out;
		n = snprintf(drop, sizeof(drop), "%s", old->file);
		if (n < 0 || (size_t)n >= sizeof(drop))
			goto out;
	}

	consumes = old == NULL || ne->derived;
	if (consumes) {
		if (pool_read(s, &pool) != 0) {
			warnx("the index: the pool state of it is wrong");
			goto out;
		}
		if (entry_pool_take(&pool, ready, s, &slot) != 0) {
			if (pool.count == 0)
				warnx("the pool of this vault holds no free "
				    "slot");
			else
				warnx("no free slot of the pool holds the "
				    "wraps of this machine at %u live "
				    "oracles", cfg->threshold);
			warnx("the provisioning ceremony writes the wraps of "
			    "this machine, and the refill ceremony adds "
			    "slots to the pool");
			goto out;
		}
		if (session_consume(s, slot, &plain, &plainlen) != 0)
			goto out;
		if (entry_slot_read(plain, plainlen, slot,
		    ne->derived ? entry_types[type].candidate :
		    ENTRY_CANDIDATE_NONE, candidate,
		    sizeof(candidate)) != 0) {
			warnx("slot %" PRIu32 ": the slot file holds no two "
			    "candidates of this slot", slot);
			goto out;
		}
		if (ne->derived)
			secret = candidate;
		if (entry_slots_add(slots, slot, list, sizeof(list)) != 0)
			goto out;
	} else {
		slot = old->slot;
		n = snprintf(list, sizeof(list), "%s", slots);
		if (n < 0 || (size_t)n >= sizeof(list))
			goto out;
	}

	/*
	 * The secret of the type comes first, then the two fields of
	 * each entry file, then the fields of the command line, then
	 * the metadata of the current version (VAULT-FORMAT-4,
	 * ENTRY-TYPES-5).
	 */
	if (entry_types[type].secret != NULL) {
		if (secret == NULL) {
			warnx("the entry %s: the secret of it is absent",
			    ne->name);
			goto out;
		}
		text_add(&body, entry_types[type].secret, secret);
	}
	text_add(&body, "type", entry_types[type].name);
	text_add(&body, "slots", list);
	if (field_of(type, "version") != NULL) {
		if (entry_version(list, strlen(list), slot, &version) != 0)
			goto out;
		n = snprintf(number, sizeof(number), "%u", version);
		if (n < 0 || (size_t)n >= sizeof(number))
			goto out;
		text_add(&body, "version", number);
	}
	for (i = 0; i < ne->count; i++)
		text_add(&body, ne->field[i], ne->value[i]);
	text_cat(&body, &meta);
	if (body.fail) {
		warnx("the entry %s: the file of it does not fit", ne->name);
		goto out;
	}
	if (vault_scan(body.at, body.len, entry_types[type].fields, gate,
	    NULL) != 0) {
		warnx("the entry %s: the file of it holds a field or a value "
		    "that the reader rejects", ne->name);
		goto out;
	}

	/*
	 * The index holds the consumed slot before the entry file
	 * exists (ENTRY-POOL-8). A rotation of add writes no index:
	 * the entry keeps the slot, the file name, the type and the
	 * slot list of it (ENTRY-ROTATION-4).
	 */
	if (consumes) {
		n = snprintf(line, sizeof(line), "%s %s %s %s",
		    session_file(s), entry_types[type].name, list, ne->name);
		if (n < 0 || (size_t)n >= sizeof(line))
			goto out;
		if (index_write(s, drop[0] == '\0' ? NULL : drop, line,
		    &pool) != 0)
			goto out;
	}
	if (session_seal(s, body.at, body.len) != 0)
		goto out;
	rv = 0;

	watermark = cfg->pool_watermark != 0 ? cfg->pool_watermark :
	    CEREMONY_POOL_WATERMARK;
	if (consumes && pool.count <= watermark) {
		warnx("the pool holds %u free slots, at the low watermark of "
		    "%u", pool.count, watermark);
		warnx("the refill ceremony adds slots to the pool");
	}
out:
	/*
	 * The entry key of a consumption that writes no entry file
	 * leaves memory here, and the seal above clears the key of
	 * each other path (SEC-MEMORY-6).
	 */
	session_drop(s);
	explicit_bzero(pass, sizeof(pass));
	explicit_bzero(candidate, sizeof(candidate));
	if (meta.at != NULL)
		explicit_bzero(meta.at, SESSION_PLAIN_MAX);
	if (body.at != NULL)
		explicit_bzero(body.at, SESSION_PLAIN_MAX);
	free(meta.at);
	free(body.at);
	return rv;
}

/*
 * show_line(line, arg):
 *	Print one line of an entry file. The secret of the file goes
 *	to the terminal, and each other field goes to the sink of the
 *	records (PROG-OUTPUT-1, PROG-ONESHOT-9).
 *
 *	arg names one int: the QR code of the secret, in place of the
 *	text of it (PROG-OUTPUT-2). cmd_show() sets that flag for a
 *	mnemonic entry without the -w option.
 */
static int
show_line(const struct vault_line *line, void *arg)
{
	const int	*code = arg;

	if ((line->field->flags & VAULT_FIELD_SECRET) != 0)
		return *code != 0 ? secret_qr(line->value) :
		    secret_print(line->value);
	record("%s: %s", line->field->name, line->value);
	return 0;
}

/*
 * date_line(line, arg):
 *	Take the verified line of a file to the state at arg. The
 *	shadow entry and the index each hold one (ENTRY-TYPES-5,
 *	VAULT-INDEX-2).
 */
static int
date_line(const struct vault_line *line, void *arg)
{
	struct date_state	*d = arg;

	if (strcmp(line->field->name, "verified") != 0)
		return 0;
	if (line->valuelen >= sizeof(d->date))
		return -1;
	memcpy(d->date, line->value, line->valuelen);
	d->date[line->valuelen] = '\0';
	d->have = 1;
	return 0;
}

/*
 * totp_line(line, arg):
 *	Take one line of a totp entry to the state at arg. The three
 *	parameters take the values of RFC 6238 without a line of
 *	their own (ENTRY-TYPES-3).
 */
static int
totp_line(const struct vault_line *line, void *arg)
{
	struct totp_state	*t = arg;
	const char		*name = line->field->name;
	uint32_t		 value;

	if (strcmp(name, "totp-key") == 0) {
		if (line->valuelen >= sizeof(t->key))
			return -1;
		memcpy(t->key, line->value, line->valuelen);
		t->key[line->valuelen] = '\0';
		t->have = 1;
		return 0;
	}
	if (strcmp(name, "totp-algorithm") == 0)
		return entry_totp_alg_find(line->value, line->valuelen,
		    &t->alg);
	if (strcmp(name, "totp-digits") == 0) {
		if (vault_number(line->value, line->valuelen,
		    ENTRY_TOTP_DIGITS_MAX, &value) != 0 ||
		    value < ENTRY_TOTP_DIGITS_MIN)
			return -1;
		t->digits = (unsigned int)value;
		return 0;
	}
	if (strcmp(name, "totp-period") == 0) {
		if (vault_number(line->value, line->valuelen, VAULT_SLOT_MAX,
		    &value) != 0 || value == 0)
			return -1;
		t->period = (unsigned int)value;
	}
	return 0;
}

/*
 * hex_digit(c):
 *	The value of the lowercase hex digit c, and -1 for every
 *	other character.
 */
static int
hex_digit(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	return -1;
}

/*
 * hex_bytes(text, out, outlen, len):
 *	The bytes of the lowercase hex string at text, to the outlen
 *	bytes at out, and the count of them to len. The scanner holds
 *	the form of the value, and this call reads it
 *	(VAULT-FORMAT-7).
 */
static int
hex_bytes(const char *text, unsigned char *out, size_t outlen, size_t *len)
{
	size_t	 i, count;
	int	 hi, lo;

	count = strlen(text);
	if (count == 0 || (count % 2) != 0 || count / 2 > outlen)
		return -1;
	for (i = 0; i < count; i += 2) {
		if ((hi = hex_digit(text[i])) < 0 ||
		    (lo = hex_digit(text[i + 1])) < 0)
			return -1;
		out[i / 2] = (unsigned char)((hi << 4) | lo);
	}
	*len = count / 2;
	return 0;
}

/*
 * cmd_ls(s, argc, argv):
 *	The entries of the open index, one name per line
 *	(PROG-REPL-3, PROG-ONESHOT-9). The command sends no request,
 *	because the index carries each name (VAULT-INDEX-2).
 */
static int
cmd_ls(struct session *s, int argc, char *argv[])
{
	const struct session_entry	*list;
	size_t				 i, count = 0;

	(void)argv;
	if (argc != 1)
		return usage_cmd("ls");
	if (index_ready(s) != 0)
		return -1;
	if ((list = session_list(s, &count)) == NULL)
		return -1;
	for (i = 0; i < count; i++)
		record("%s", list[i].name);
	return 0;
}

/*
 * cmd_show(s, argc, argv):
 *	One entry of the index: the secret of it to the terminal, and
 *	each metadata field to the sink of the records (PROG-REPL-3,
 *	PROG-OUTPUT-1). The reveal is one quorum event (PROG-REPL-4).
 *
 *	A mnemonic takes the QR code of the render helper, and the -w
 *	option takes the words as text (PROG-OUTPUT-2,
 *	PROG-ONESHOT-9). The index names the type of the entry, so
 *	the shape of the secret stands before the reveal
 *	(VAULT-INDEX-2).
 */
static int
cmd_show(struct session *s, int argc, char *argv[])
{
	const struct session_entry	*e;
	const char			*plain;
	enum entry_type			 type;
	size_t				 plainlen = 0;
	int				 ch, code, words = 0;

	optreset = 1;
	optind = 1;
	while ((ch = getopt(argc, argv, "w")) != -1) {
		switch (ch) {
		case 'w':
			words = 1;
			break;
		default:
			return usage_cmd("show");
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 1)
		return usage_cmd("show");
	if (index_ready(s) != 0 || entry_find(s, argv[0], &e) != 0)
		return -1;
	if (e == NULL) {
		warnx("the index holds no entry of the name %s", argv[0]);
		return -1;
	}
	if (index_type(e, &type) != 0)
		return -1;
	code = type == ENTRY_TYPE_MNEMONIC && words == 0;
	if (session_reveal(s, e->slot, &plain, &plainlen) != 0)
		return -1;
	if (file_type(e, type, plain, plainlen) != 0)
		return -1;
	return vault_scan(plain, plainlen, entry_types[type].fields,
	    show_line, &code);
}

static int
cmd_add(struct session *s, int argc, char *argv[])
{
	struct newentry	 ne;

	if (parse_new(&ne, argc, argv, 0) != 0)
		return -1;
	return create(s, &ne);
}

static int
cmd_gen(struct session *s, int argc, char *argv[])
{
	struct newentry	 ne;

	if (parse_new(&ne, argc, argv, 1) != 0)
		return -1;
	return create(s, &ne);
}

/*
 * cmd_totp(s, argc, argv):
 *	The TOTP code of one totp entry, to the terminal
 *	(PROG-REPL-3, ENTRY-TYPES-3). The reveal is one quorum event,
 *	and the code takes no request of its own (PROG-REPL-4).
 */
static int
cmd_totp(struct session *s, int argc, char *argv[])
{
	const struct session_entry	*e;
	struct totp_state		 t;
	const char			*plain;
	unsigned char			 key[VALUE_MAX / 2];
	char				 code[ENTRY_TOTP_MAX];
	enum entry_type			 type;
	size_t				 keylen = 0, plainlen = 0;
	int				 rv = -1;

	if (argc != 2)
		return usage_cmd("totp");
	if (index_ready(s) != 0 || entry_find(s, argv[1], &e) != 0)
		return -1;
	if (e == NULL) {
		warnx("the index holds no entry of the name %s", argv[1]);
		return -1;
	}
	if (index_type(e, &type) != 0)
		return -1;
	if (type != ENTRY_TYPE_TOTP) {
		warnx("the entry %s holds no totp entry", argv[1]);
		return -1;
	}
	if (session_reveal(s, e->slot, &plain, &plainlen) != 0)
		return -1;
	if (file_type(e, type, plain, plainlen) != 0)
		return -1;

	memset(&t, 0, sizeof(t));
	memset(key, 0, sizeof(key));
	memset(code, 0, sizeof(code));
	t.alg = ENTRY_TOTP_ALG_DEFAULT;
	t.digits = ENTRY_TOTP_DIGITS_DEFAULT;
	t.period = ENTRY_TOTP_PERIOD_DEFAULT;
	if (vault_scan(plain, plainlen, entry_types[type].fields, totp_line,
	    &t) != 0 || t.have == 0) {
		warnx("the entry %s: the key or a parameter of it is wrong",
		    argv[1]);
		goto out;
	}
	if (hex_bytes(t.key, key, sizeof(key), &keylen) != 0) {
		warnx("the entry %s: the key of it is wrong", argv[1]);
		goto out;
	}
	if (entry_totp(key, keylen, t.alg, t.digits, t.period,
	    (uint64_t)time(NULL), code, sizeof(code)) != 0) {
		warnx("the entry %s: the code does not compute", argv[1]);
		goto out;
	}
	rv = secret_print(code);
out:
	explicit_bzero(&t, sizeof(t));
	explicit_bzero(key, sizeof(key));
	explicit_bzero(code, sizeof(code));
	return rv;
}

/*
 * cmd_audit(s, argc, argv):
 *	The stale shadow entries of the index, and the date of the
 *	last plate verification (PROG-REPL-3, ENTRY-SHADOW-4). A
 *	shadow entry of a verification date below the audit age is
 *	stale, and this command prints one line of each one
 *	(PROG-ONESHOT-9).
 *
 *	The index names the type of each entry, so the audit reveals
 *	the shadow entries alone (ENTRY-SHADOW-5, VAULT-INDEX-2). An
 *	entry of another type takes no oracle request, and each
 *	reveal of a shadow entry is one quorum event (PROG-REPL-4).
 */
static int
cmd_audit(struct session *s, int argc, char *argv[])
{
	const struct session_entry	*list;
	const struct vault_config	*cfg;
	struct date_state		 plate, entry;
	const char			*plain, *text;
	char				 cutoff[ENTRY_DATE_MAX];
	enum entry_type			 type;
	size_t				 i, count = 0, len = 0, plainlen = 0;
	unsigned int			 age;

	(void)argv;
	if (argc != 1)
		return usage_cmd("audit");
	if (index_ready(s) != 0)
		return -1;
	cfg = session_config(s);
	age = cfg->audit_age != 0 ? cfg->audit_age : ENTRY_AUDIT_AGE_DEFAULT;
	if (entry_audit_cutoff(age, time(NULL), cutoff, sizeof(cutoff)) != 0)
		return -1;

	memset(&plate, 0, sizeof(plate));
	if ((text = session_index(s, &len)) == NULL ||
	    vault_scan(text, len, vault_index_fields, date_line, &plate) != 0)
		return -1;
	if (plate.have)
		record("verified: %s", plate.date);
	else
		warnx("the index holds no date of a plate verification");

	if ((list = session_list(s, &count)) == NULL)
		return -1;
	for (i = 0; i < count; i++) {
		if (index_type(&list[i], &type) != 0)
			return -1;
		if (type != ENTRY_TYPE_SHADOW)
			continue;
		if (session_reveal(s, list[i].slot, &plain, &plainlen) != 0)
			return -1;
		if (file_type(&list[i], type, plain, plainlen) != 0)
			return -1;
		memset(&entry, 0, sizeof(entry));
		if (vault_scan(plain, plainlen, entry_types[type].fields,
		    date_line, &entry) != 0)
			return -1;
		if (!entry.have) {
			warnx("the shadow entry %s holds no verification "
			    "date", list[i].name);
			continue;
		}
		if (strcmp(entry.date, cutoff) < 0)
			record("%s %s", entry.date, list[i].name);
	}
	return 0;
}

void
commands_sink(void (*fn)(const char *))
{
	sink = fn;
}

int
commands_run(struct session *s, int argc, char *argv[])
{
	const struct commands_cmd	*c;
	int				 rv;

	if (s == NULL || argc < 1 || argv == NULL || argv[0] == NULL)
		return -1;
	if ((c = find(argv[0])) == NULL) {
		warnx("%s: no command of that name", argv[0]);
		return -1;
	}
	record_fail = 0;
	rv = c->run(s, argc, argv);
	return record_fail != 0 ? -1 : rv;
}

int
commands_oneshot(const char *vault, int argc, char *argv[])
{
	struct session	*s = NULL;
	int		 rv;

	if (vault == NULL || argc < 1 || argv == NULL || argv[0] == NULL)
		return 1;

	/* A name that the table does not hold reads no passphrase. */
	if (find(argv[0]) == NULL) {
		warnx("%s: no command of that name", argv[0]);
		return 1;
	}
	if (session_open(vault, &s) != 0)
		return 1;
	rv = commands_run(s, argc, argv);
	session_close(s);
	return rv == 0 ? 0 : 1;
}
