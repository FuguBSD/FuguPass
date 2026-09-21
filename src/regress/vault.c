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
 * The tests of the vault on disk. The parts here are the seal and
 * the open of it (TEST-KAT-2), the strict scanner with the field
 * table of each file kind, the config file, the atomic write, and
 * the directory layout. tests/vectors/seal.h holds the seal
 * vectors, and every seal test reads them from there. A test needs
 * no network and no oracle (TEST-KAT-5).
 *
 * A test of the write makes a directory with mkdtemp(3) in the
 * working directory, and it removes that directory at the end of
 * it.
 *
 * The program prints nothing on a pass, and it exits 0. A wrong
 * value prints the test, the value and the vector to the standard
 * error, and the program exits 1. Every test runs on each run, so
 * one run reports every wrong value.
 *
 * The values of the tests are public constants of the tests, so
 * this file holds no secret and clears nothing.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <dirent.h>
#include <err.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "derive.h"
#include "seal.h"
#include "vault.h"

/*
 * The vectors, one directory below tests. Two files carry the name
 * seal.h: the interface of the source, and the vectors of it. The
 * include above takes the interface, and the include below carries
 * the directory name, which the source directory does not hold. No
 * order of the search path can exchange the two files.
 */
#include "vectors/seal.h"

/*
 * Each of the two files sets a guard of its own, and both of them
 * must enter this file. A build that reaches a wrong file stops
 * here.
 */
#if !defined(SEAL_H) || !defined(VECTORS_SEAL_H)
#error an include of vault.c reached the wrong seal.h
#endif

/* The vectors and the seal must name one version (VAULT-SEAL-1). */
#if KAT_SEAL_VERSION != SEAL_VERSION
#error the vectors and the seal name two versions
#endif

/* The longest plaintext of a vector, and the sealed form of it. */
#define PLAIN_MAX	128
#define SEALED_MAX	(PLAIN_MAX + SEAL_OVERHEAD)

/* The name of one test in a message, with the terminator. */
#define NAMELEN		80

/*
 * The plaintext of the round trip: one secret field, and then one
 * metadata field (VAULT-FORMAT-1, VAULT-FORMAT-4). The round trip
 * takes no vector, because a seal draws its own nonce. The value
 * of the secret field is a public test constant.
 */
static const unsigned char	roundtrip[] =
    "candidate-password: the-test-value-of-the-seal-vectors\n"
    "slot: 17\n";

/* The bytes of that plaintext, with no terminator, and sealed. */
#define ROUNDTRIP_LEN	(sizeof(roundtrip) - 1)
#define SEALED_LEN	(ROUNDTRIP_LEN + SEAL_OVERHEAD)

/* The rows of the vectors: the nonce, the plaintext, and the body. */
static const struct {
	const char	*nonce;
	const char	*plain;
	const char	*body;
} vectors[KAT_SEAL_COUNT] = KAT_SEAL_VECTORS;

/*
 * hexdigit(c):
 *	The value of the lower-case hex digit c, or -1 for another
 *	character.
 */
static int
hexdigit(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	return -1;
}

/*
 * hexsize(name, text, out):
 *	The byte count of the hex text at text, to out. A count of
 *	characters that no byte count gives prints the failure and
 *	gives -1.
 */
static int
hexsize(const char *name, const char *text, size_t *out)
{
	size_t	 len;

	len = strlen(text);
	if (len == 0 || len % 2 != 0) {
		warnx("%s: the vector holds %zu characters, and one byte "
		    "takes two of them", name, len);
		return -1;
	}
	*out = len / 2;
	return 0;
}

/*
 * hexbytes(name, text, out, outlen):
 *	The outlen bytes of the hex text at text, to out. A text of
 *	another length, or a character that is not lower-case hex,
 *	prints the failure and gives -1.
 */
static int
hexbytes(const char *name, const char *text, unsigned char *out, size_t outlen)
{
	size_t	 i, len;
	int	 hi, lo;

	len = strlen(text);
	if (len != 2 * outlen) {
		warnx("%s: the vector holds %zu characters, and the test "
		    "takes %zu bytes", name, len, outlen);
		return -1;
	}
	for (i = 0; i < outlen; i++) {
		hi = hexdigit(text[2 * i]);
		lo = hexdigit(text[2 * i + 1]);
		if (hi < 0 || lo < 0) {
			warnx("%s: the vector holds a character that is not "
			    "lower-case hex", name);
			return -1;
		}
		out[i] = (unsigned char)((hi << 4) | lo);
	}
	return 0;
}

/*
 * hexcheck(name, value, len, want):
 *	Compare the len bytes at value with the hex text at want. A
 *	difference prints the two values, and gives -1.
 */
static int
hexcheck(const char *name, const unsigned char *value, size_t len,
    const char *want)
{
	char	 got[2 * PLAIN_MAX + 1];
	size_t	 i;

	if (len > PLAIN_MAX) {
		warnx("%s: %zu bytes are too many for a vector", name, len);
		return -1;
	}
	for (i = 0; i < len; i++)
		snprintf(&got[2 * i], 3, "%02x", value[i]);
	got[2 * len] = '\0';
	if (strcmp(got, want) != 0) {
		warnx("%s: the value is %s, and the vector is %s", name, got,
		    want);
		return -1;
	}
	return 0;
}

/*
 * vectorseal(name, at, sealed, sealedlen, plainlen):
 *	The sealed value of the row at, to sealed, with the byte
 *	count of it to sealedlen and the byte count of the plaintext
 *	to plainlen. The value is the version byte, the nonce of the
 *	row, and then the body of the row (VAULT-SEAL-1).
 *
 *	A row that does not fit the buffer prints the failure and
 *	gives -1. That one gate holds the plaintext of the row to
 *	PLAIN_MAX bytes too, because a seal adds SEAL_OVERHEAD bytes
 *	to a plaintext.
 */
static int
vectorseal(const char *name, size_t at, unsigned char *sealed,
    size_t *sealedlen, size_t *plainlen)
{
	size_t	 bodylen;

	if (hexsize(name, vectors[at].plain, plainlen) != 0)
		return -1;
	if (hexsize(name, vectors[at].body, &bodylen) != 0)
		return -1;
	if (bodylen != *plainlen + SEAL_TAGLEN) {
		warnx("%s: the body holds %zu bytes, and the plaintext and "
		    "the tag take %zu", name, bodylen,
		    *plainlen + SEAL_TAGLEN);
		return -1;
	}
	*sealedlen = SEAL_OFF_BODY + bodylen;
	if (*sealedlen > SEALED_MAX) {
		warnx("%s: the sealed value holds %zu bytes, and the buffer "
		    "takes %d", name, *sealedlen, SEALED_MAX);
		return -1;
	}
	sealed[SEAL_OFF_VERSION] = KAT_SEAL_VERSION;
	if (hexbytes(name, vectors[at].nonce, &sealed[SEAL_OFF_NONCE],
	    SEAL_NONCELEN) != 0)
		return -1;
	return hexbytes(name, vectors[at].body, &sealed[SEAL_OFF_BODY],
	    bodylen);
}

/*
 * changed(key, sealed, at):
 *	Change the byte at the index at of a copy of the sealed
 *	value at sealed, and open the copy. It gives the result of
 *	the open, so 0 reports that the open takes the changed
 *	value.
 */
static int
changed(const unsigned char *key, const unsigned char *sealed, size_t at)
{
	unsigned char	 bad[SEALED_LEN];
	unsigned char	 got[ROUNDTRIP_LEN];

	memcpy(bad, sealed, sizeof(bad));
	bad[at] ^= 0x01;
	return seal_open(key, SEAL_KEYLEN, bad, sizeof(bad), got,
	    sizeof(got));
}

/*
 * test_vector():
 *	Each vector opens to the plaintext of it (TEST-KAT-2). The
 *	bodies come from the cryptography module of PyPI, and not
 *	from seal_seal(), so a matched pair of defects in the seal
 *	and the open cannot hide here. A wrong offset, wrong
 *	additional data, and a wrong nonce each fail this test
 *	(VAULT-SEAL-1, VAULT-SEAL-5).
 */
static int
test_vector(void)
{
	unsigned char	 key[SEAL_KEYLEN];
	unsigned char	 sealed[SEALED_MAX];
	unsigned char	 got[PLAIN_MAX];
	char		 name[NAMELEN];
	size_t		 at, sealedlen, plainlen;
	int		 rv = 0;

	if (hexbytes("the seal key", KAT_SEAL_KEY, key, sizeof(key)) != 0)
		return -1;
	for (at = 0; at < nitems(vectors); at++) {
		snprintf(name, sizeof(name), "the seal vector %zu", at + 1);
		if (vectorseal(name, at, sealed, &sealedlen,
		    &plainlen) != 0) {
			rv = -1;
			continue;
		}
		if (seal_open(key, sizeof(key), sealed, sealedlen, got,
		    plainlen) != 0) {
			warnx("%s: the open fails", name);
			rv = -1;
			continue;
		}
		if (hexcheck(name, got, plainlen, vectors[at].plain) != 0)
			rv = -1;
	}

	/*
	 * The tool reads one version (VAULT-SEAL-1). The body below
	 * carries the plaintext and the nonce of the first row under
	 * another version byte, and the tag of it is right. The open
	 * must fail on the version byte alone.
	 */
	if (vectorseal("the seal vector 1", 0, sealed, &sealedlen,
	    &plainlen) != 0)
		return -1;
	sealed[SEAL_OFF_VERSION] = KAT_SEAL_OTHER;
	if (hexbytes("the body of the other version", KAT_SEAL_OTHER_BODY,
	    &sealed[SEAL_OFF_BODY], plainlen + SEAL_TAGLEN) != 0)
		return -1;
	if (seal_open(key, sizeof(key), sealed, sealedlen, got,
	    plainlen) == 0) {
		warnx("a seal of another version: the open takes it");
		rv = -1;
	}
	return rv;
}

/*
 * test_roundtrip():
 *	A seal and then an open give the plaintext back
 *	(TEST-KAT-2). A changed byte of the version, of the nonce,
 *	of the body and of the tag fails the open, and a wrong key
 *	fails it too (VAULT-SEAL-4, VAULT-SEAL-5).
 */
static int
test_roundtrip(void)
{
	static const struct {
		size_t		 at;
		const char	*part;
	} spot[] = {
		{ SEAL_OFF_VERSION, "version byte" },
		{ SEAL_OFF_NONCE, "first byte of the nonce" },
		{ SEAL_OFF_NONCE + SEAL_NONCELEN - 1,
		    "last byte of the nonce" },
		{ SEAL_OFF_BODY, "first byte of the body" },
		{ SEALED_LEN - 1, "last byte of the tag" },
	};
	unsigned char	 key[SEAL_KEYLEN];
	unsigned char	 sealed[SEALED_LEN];
	unsigned char	 got[ROUNDTRIP_LEN];
	size_t		 i;
	int		 rv = 0;

	if (hexbytes("the seal key", KAT_SEAL_KEY, key, sizeof(key)) != 0)
		return -1;
	if (seal_seal(key, sizeof(key), roundtrip, ROUNDTRIP_LEN, sealed,
	    sizeof(sealed)) != 0) {
		warnx("the seal: the call fails");
		return -1;
	}
	if (sealed[SEAL_OFF_VERSION] != SEAL_VERSION) {
		warnx("the seal: the version byte is %02x, and the layout "
		    "takes %02x", sealed[SEAL_OFF_VERSION], SEAL_VERSION);
		rv = -1;
	}
	if (seal_open(key, sizeof(key), sealed, sizeof(sealed), got,
	    sizeof(got)) != 0) {
		warnx("the open of a seal: the call fails");
		return -1;
	}
	if (memcmp(got, roundtrip, sizeof(got)) != 0) {
		warnx("the open of a seal: the plaintext differs from the "
		    "input");
		rv = -1;
	}

	/*
	 * Every changed byte must fail the open. The version byte
	 * is the additional data, so the tag covers it too
	 * (VAULT-SEAL-5).
	 */
	for (i = 0; i < nitems(spot); i++)
		if (changed(key, sealed, spot[i].at) == 0) {
			warnx("a changed %s: the open takes it",
			    spot[i].part);
			rv = -1;
		}

	/*
	 * A wrong key gives the one failure of the seal
	 * (VAULT-SEAL-4). A junk oracle answer, a wrong passphrase,
	 * a wiped record and a stale wrap each reach the open with
	 * a wrong key.
	 */
	key[0] ^= 0x01;
	if (seal_open(key, sizeof(key), sealed, sizeof(sealed), got,
	    sizeof(got)) == 0) {
		warnx("a wrong key: the open takes it");
		rv = -1;
	}
	return rv;
}

/*
 * test_reject():
 *	The gates of seal_seal() give a failure (seal.h). Each case
 *	below names the mutation that it catches, and each of those
 *	mutations turns a caller error into a wrong file.
 *
 *	The other halves of the gates carry no case, because
 *	another path gives -1 for the same call. EVP_AEAD_CTX_init()
 *	rejects a keylen other than SEAL_KEYLEN. The AEAD rejects an
 *	outlen below the sum, because that sum is the output of it.
 *	The two halves of the gate of seal_open() hold each other:
 *	a sealedlen of SEAL_OVERHEAD or less makes the difference
 *	wrap, and no outlen matches the wrapped value.
 */
static int
test_reject(void)
{
	unsigned char	 key[SEAL_KEYLEN];
	unsigned char	 sealed[SEALED_LEN + 1];
	int		 rv = 0;

	if (hexbytes("the seal key", KAT_SEAL_KEY, key, sizeof(key)) != 0)
		return -1;

	/*
	 * A plaintext of 0 bytes gives -1 (seal.h). A removal of
	 * that half of the gate seals the empty plaintext, and the
	 * caller writes a vault file that holds no field.
	 */
	if (seal_seal(key, sizeof(key), roundtrip, 0, sealed,
	    SEAL_OVERHEAD) == 0) {
		warnx("a plaintext of no byte: the seal takes it");
		rv = -1;
	}

	/*
	 * An outlen other than the sum gives -1 (seal.h). A removal
	 * of that half of the gate seals the plaintext into the head
	 * of the buffer, and it leaves the last byte untouched. The
	 * caller then writes a file with one stale byte at the end
	 * of it.
	 */
	if (seal_seal(key, sizeof(key), roundtrip, ROUNDTRIP_LEN, sealed,
	    sizeof(sealed)) == 0) {
		warnx("a long output: the seal takes it");
		rv = -1;
	}
	return rv;
}

/*
 * test_nonce():
 *	Two seals of one plaintext write two nonces (VAULT-SEAL-3).
 *	One nonce under one key twice breaks the AEAD, so a fixed
 *	nonce or a missed draw must fail here.
 */
static int
test_nonce(void)
{
	unsigned char	 key[SEAL_KEYLEN];
	unsigned char	 first[SEALED_LEN];
	unsigned char	 second[SEALED_LEN];

	if (hexbytes("the seal key", KAT_SEAL_KEY, key, sizeof(key)) != 0)
		return -1;
	if (seal_seal(key, sizeof(key), roundtrip, ROUNDTRIP_LEN, first,
	    sizeof(first)) != 0 ||
	    seal_seal(key, sizeof(key), roundtrip, ROUNDTRIP_LEN, second,
	    sizeof(second)) != 0) {
		warnx("two seals: a call fails");
		return -1;
	}
	if (memcmp(&first[SEAL_OFF_NONCE], &second[SEAL_OFF_NONCE],
	    SEAL_NONCELEN) == 0) {
		warnx("two seals of one plaintext: the two nonces are equal");
		return -1;
	}
	if (memcmp(&first[SEAL_OFF_BODY], &second[SEAL_OFF_BODY],
	    ROUNDTRIP_LEN + SEAL_TAGLEN) == 0) {
		warnx("two seals of one plaintext: the two bodies are equal");
		return -1;
	}
	return 0;
}

/*
 * The entry file name of the entry key of 32 zero bytes: the
 * lowercase hex of H(K_e) (VAULT-LAYOUT-5, KEY-ENTRY-3). The value
 * is the SHA-256 of 32 zero bytes, and it is a public constant.
 */
#define TEST_HEX64	"66687aadf862bd776c8fc18b8e9f8e20" \
			"089714856ee233b3902a591d0d5f2925"

/*
 * The two provisioned values of one oracle position: the static
 * public key as hex, one space, and the URL (ORC-PROVISION-1). The
 * three positions below hold three values, so a test can move one
 * of them to another position.
 */
#define ORACLE_A	"aa00aa00aa00aa00aa00aa00aa00aa00 " \
			"https://one.example.test"
#define ORACLE_B	"bb11bb11bb11bb11bb11bb11bb11bb11 " \
			"https://two.example.test"
#define ORACLE_C	"cc22cc22cc22cc22cc22cc22cc22cc22 " \
			"https://three.example.test"

/* The fields that every config file of a change test holds. */
#define CONFIG_TAIL	"threshold: 1\nmachine-name: laptop\n"

/* The text of each file kind of this unit (VAULT-FORMAT). */
static const char	 text_slot[] =
    "candidate-password: the-test-value-of-the-slot-file\n"
    "candidate-mnemonic: the-bip39-child-of-the-test\n"
    "slot: 17\n";

static const char	 text_index[] =
    "entry: " TEST_HEX64 " 17,40 the test entry of a site\n"
    "machine: laptop\n"
    "machine: old-desktop retired\n"
    "pool-free: 41,42\n"
    "pool-next: 43\n"
    "verified: 2026-09-21\n";

static const char	 text_counters[] =
    "canary-1: 7\n"
    "canary-2: 9\n"
    "17-1: 3\n"
    "17-2: 4\n";

static const char	 text_change[] =
    "kind: passphrase\n"
    "done: 17-1\n"
    "done: canary-2\n";

static const char	 text_config[] =
    "oracle-1: " ORACLE_A "\n"
    "oracle-2: retired\n"
    "threshold: 1\n"
    "machine-name: laptop\n"
    "kdf-rounds: 16\n"
    "plate-check: " TEST_HEX64 "\n"
    "pool-size: 8\n"
    "pool-watermark: 2\n"
    "audit-age: 180\n"
    "lock-timeout: 300\n";

/* The config files of the change rule (VAULT-CONFIG-6). */
static const char	 change_ab[] =
    "oracle-1: " ORACLE_A "\noracle-2: " ORACLE_B "\n" CONFIG_TAIL;
static const char	 change_ba[] =
    "oracle-1: " ORACLE_B "\noracle-2: " ORACLE_A "\n" CONFIG_TAIL;
static const char	 change_a[] =
    "oracle-1: " ORACLE_A "\n" CONFIG_TAIL;
static const char	 change_ar[] =
    "oracle-1: " ORACLE_A "\noracle-2: retired\n" CONFIG_TAIL;
static const char	 change_abc[] =
    "oracle-1: " ORACLE_A "\noracle-2: " ORACLE_B "\noracle-3: " ORACLE_C
    "\n" CONFIG_TAIL;
static const char	 change_cb[] =
    "oracle-1: " ORACLE_C "\noracle-2: " ORACLE_B "\n" CONFIG_TAIL;

/*
 * A table that breaks the field name rule: a name holds lowercase
 * letters, digits and hyphens alone (VAULT-FORMAT-3). The scanner
 * holds the table to that rule, and it takes no line of this table.
 */
static const struct vault_field	 table_bad[] = {
	{ "Slot", VAULT_NAME_FIXED, VAULT_VALUE_NUMBER, 0 },
	{ NULL, VAULT_NAME_FIXED, VAULT_VALUE_TEXT, 0 }
};

/* The text that one scan writes back, for the round trip. */
struct build {
	char	 text[2048];
	size_t	 at;
};

/*
 * count_lines(line, arg):
 *	A callback that counts the lines of a scan. It gives -1 for
 *	a line number that does not follow the one before it.
 */
static int
count_lines(const struct vault_line *line, void *arg)
{
	size_t	*count = arg;

	(*count)++;
	return (line->number == *count) ? 0 : -1;
}

/*
 * rebuild(line, arg):
 *	A callback that writes one line back to the buffer at arg.
 *	It builds the field name from the form of the row and the
 *	indexes of the line, so the round trip proves the name
 *	scan too.
 */
static int
rebuild(const struct vault_line *line, void *arg)
{
	struct build	*built = arg;
	size_t		 left = sizeof(built->text) - built->at;
	int		 n;

	switch (line->field->form) {
	case VAULT_NAME_FIXED:
		n = snprintf(&built->text[built->at], left, "%s: %s\n",
		    line->field->name, line->value);
		break;
	case VAULT_NAME_ORACLE:
		n = snprintf(&built->text[built->at], left, "%s%u: %s\n",
		    line->field->name, line->oracle, line->value);
		break;
	case VAULT_NAME_RECORD:
		n = snprintf(&built->text[built->at], left,
		    "%" PRIu32 "-%u: %s\n", line->slot, line->oracle,
		    line->value);
		break;
	default:
		return -1;
	}
	if (n < 0 || (size_t)n >= left)
		return -1;
	built->at += (size_t)n;
	return 0;
}

/*
 * slurp(path, out, outlen, len):
 *	The bytes of the file at path, to the outlen bytes at out,
 *	with the count of them to len.
 */
static int
slurp(const char *path, unsigned char *out, size_t outlen, size_t *len)
{
	ssize_t	 got;
	int	 fd;

	if ((fd = open(path, O_RDONLY)) == -1) {
		warn("open %s", path);
		return -1;
	}
	got = read(fd, out, outlen);
	close(fd);
	if (got < 0) {
		warn("read %s", path);
		return -1;
	}
	*len = (size_t)got;
	return 0;
}

/*
 * entries(path, strict):
 *	The count of the names of the directory at path, without
 *	the two names of the tree. With strict, a name that is not
 *	a hex name, index or the machine-local subdirectory prints
 *	the failure and gives -1 (VAULT-LAYOUT-7).
 */
static int
entries(const char *path, int strict)
{
	DIR		*dir;
	struct dirent	*item;
	int		 count = 0;

	if ((dir = opendir(path)) == NULL) {
		warn("opendir %s", path);
		return -1;
	}
	while ((item = readdir(dir)) != NULL) {
		if (strcmp(item->d_name, ".") == 0 ||
		    strcmp(item->d_name, "..") == 0)
			continue;
		count++;
		if (!strict)
			continue;
		if (strcmp(item->d_name, "index") == 0 ||
		    strcmp(item->d_name, VAULT_MACHINE_DIR) == 0)
			continue;
		if (strlen(item->d_name) == VAULT_NAMELEN - 1 &&
		    strspn(item->d_name, "0123456789abcdef") ==
		    VAULT_NAMELEN - 1)
			continue;
		warnx("the listing holds %s, and the layout holds a hex "
		    "name, index and %s alone", item->d_name,
		    VAULT_MACHINE_DIR);
		count = -1;
		break;
	}
	closedir(dir);
	return count;
}

/*
 * rmtree(path):
 *	Remove the directory at path and every file under it. The
 *	call reports nothing, because it runs at the end of a test.
 */
static void
rmtree(const char *path)
{
	char		 sub[PATH_MAX];
	DIR		*dir;
	struct dirent	*item;
	int		 n;

	if ((dir = opendir(path)) != NULL) {
		while ((item = readdir(dir)) != NULL) {
			if (strcmp(item->d_name, ".") == 0 ||
			    strcmp(item->d_name, "..") == 0)
				continue;
			n = snprintf(sub, sizeof(sub), "%s/%s", path,
			    item->d_name);
			if (n < 0 || (size_t)n >= sizeof(sub))
				continue;
			if (item->d_type == DT_DIR)
				rmtree(sub);
			else
				unlink(sub);
		}
		closedir(dir);
	}
	rmdir(path);
}

/*
 * readconfig(name, text, cfg):
 *	Read the config text to cfg. A failure prints the name and
 *	gives -1.
 */
static int
readconfig(const char *name, const char *text, struct vault_config *cfg)
{
	if (vault_config_read(text, strlen(text), cfg) != 0) {
		warnx("%s: the config read fails", name);
		return -1;
	}
	return 0;
}

/*
 * test_scan():
 *	The strict scanner takes the line format, and it rejects
 *	every other text (VAULT-FORMAT-5 to VAULT-FORMAT-8). Each
 *	case below names the rule that it holds.
 */
static int
test_scan(void)
{
	static const struct {
		const char			*name;
		const struct vault_field	*table;
		const char			*text;
		int				 take;
	} cases[] = {
		{ "an unknown field", vault_slot_fields, "unknown: 1\n", 0 },
		{ "a name with an upper-case letter", vault_slot_fields,
		    "Slot: 17\n", 0 },
		{ "no space after the colon", vault_slot_fields,
		    "slot:17\n", 0 },
		{ "no colon", vault_slot_fields, "slot 17\n", 0 },
		{ "a value of no byte", vault_slot_fields,
		    "candidate-password: \n", 0 },
		{ "no line feed at the end", vault_slot_fields, "slot: 17",
		    0 },
		{ "an empty line", vault_slot_fields, "slot: 17\n\n", 0 },
		{ "a line feed in a value", vault_change_fields,
		    "kind: pass\nphrase\n", 0 },
		{ "a field that repeats", vault_slot_fields,
		    "slot: 17\nslot: 18\n", 0 },
		{ "a secret field after a metadata field", vault_slot_fields,
		    "slot: 17\ncandidate-password: x\n", 0 },
		{ "a padded slot index", vault_slot_fields, "slot: 017\n", 0 },
		{ "a wrong month", vault_index_fields,
		    "verified: 2026-13-01\n", 0 },
		{ "an oracle index of 0", vault_counters_fields,
		    "canary-0: 1\n", 0 },
		{ "a slot list with a space", vault_index_fields,
		    "pool-free: 41, 42\n", 0 },
		{ "an entry with no slot list", vault_index_fields,
		    "entry: " TEST_HEX64 " the test entry\n", 0 },
		{ "an entry with no name", vault_index_fields,
		    "entry: " TEST_HEX64 " 17\n", 0 },
		{ "an entry with a name that is not hex", vault_index_fields,
		    "entry: not-a-hex-name 17 the test entry\n", 0 },
		{ "a text of no byte", vault_slot_fields, "", 0 },
		{ "a machine name with an upper-case letter",
		    vault_index_fields, "machine: LAPTOP\n", 0 },
		{ "a row with an upper-case letter", table_bad,
		    "Slot: 17\n", 0 },
		{ "the secret block first", vault_slot_fields, text_slot, 1 },
		{ "a field that the table repeats", vault_change_fields,
		    "done: 17-1\ndone: canary-2\n", 1 },
	};
	char	 line[VAULT_LINE_MAX + 2];
	size_t	 count, head, i;
	int	 rv = 0;

	for (i = 0; i < nitems(cases); i++) {
		count = 0;
		if ((vault_scan(cases[i].text, strlen(cases[i].text),
		    cases[i].table, count_lines, &count) == 0) !=
		    cases[i].take) {
			warnx("%s: the scanner differs from the "
			    "specification", cases[i].name);
			rv = -1;
		}
	}

	/*
	 * A line of VAULT_LINE_MAX bytes passes, and one byte more
	 * fails (VAULT-FORMAT-5). A line holds the name, the colon,
	 * the space, the value, and the line feed of it.
	 */
	head = strlen("kind: ");
	memcpy(line, "kind: ", head);
	memset(&line[head], 'a', sizeof(line) - head);
	count = 0;
	line[VAULT_LINE_MAX - 1] = '\n';
	if (vault_scan(line, VAULT_LINE_MAX, vault_change_fields, count_lines,
	    &count) != 0) {
		warnx("a line of %d bytes: the scanner rejects it",
		    VAULT_LINE_MAX);
		rv = -1;
	}
	count = 0;
	line[VAULT_LINE_MAX - 1] = 'a';
	line[VAULT_LINE_MAX] = '\n';
	if (vault_scan(line, VAULT_LINE_MAX + 1, vault_change_fields,
	    count_lines, &count) == 0) {
		warnx("a line of %d bytes: the scanner takes it",
		    VAULT_LINE_MAX + 1);
		rv = -1;
	}
	return rv;
}

/*
 * test_kinds():
 *	Each file kind of this unit passes through the field table
 *	of it, and the scan writes the file back byte for byte
 *	(VAULT-FORMAT-3, VAULT-FORMAT-8). entry.c holds the six
 *	entry types (ENTRY-TYPES-5).
 */
static int
test_kinds(void)
{
	static const struct {
		const char			*name;
		const struct vault_field	*table;
		const char			*text;
	} kinds[] = {
		{ "the slot file", vault_slot_fields, text_slot },
		{ "the index", vault_index_fields, text_index },
		{ "the counters file", vault_counters_fields, text_counters },
		{ "the change marker", vault_change_fields, text_change },
		{ "the config file", vault_config_fields, text_config }
	};
	struct build	 built;
	size_t		 i;
	int		 rv = 0;

	for (i = 0; i < nitems(kinds); i++) {
		memset(&built, 0, sizeof(built));
		if (vault_scan(kinds[i].text, strlen(kinds[i].text),
		    kinds[i].table, rebuild, &built) != 0) {
			warnx("%s: the scan of the file fails",
			    kinds[i].name);
			rv = -1;
			continue;
		}
		if (strcmp(built.text, kinds[i].text) != 0) {
			warnx("%s: the round trip gives %s", kinds[i].name,
			    built.text);
			rv = -1;
		}
	}
	return rv;
}

/*
 * test_config():
 *	The config reader takes the values of the file, and it
 *	holds the position rule (VAULT-CONFIG-6). The reader also
 *	rejects a value that holds no oracle and no retired state
 *	(ORC-PROVISION-1).
 */
static int
test_config(void)
{
	static const struct {
		const char	*name;
		const char	*text;
	} bad[] = {
		{ "a gap in the positions",
		    "oracle-1: " ORACLE_A "\noracle-3: " ORACLE_B "\n"
		    CONFIG_TAIL },
		{ "a threshold above the live count",
		    "oracle-1: " ORACLE_A "\noracle-2: retired\n"
		    "threshold: 2\nmachine-name: laptop\n" },
		{ "a position twice",
		    "oracle-1: " ORACLE_A "\noracle-1: " ORACLE_B "\n"
		    CONFIG_TAIL },
		{ "a file with no threshold",
		    "oracle-1: " ORACLE_A "\nmachine-name: laptop\n" },
		{ "a file with no position", CONFIG_TAIL },
		{ "a threshold of 0",
		    "oracle-1: " ORACLE_A "\nthreshold: 0\n" },
		{ "a position of 0", "oracle-0: " ORACLE_A "\n"
		    CONFIG_TAIL },
		{ "an oracle value with no URL",
		    "oracle-1: aa00aa00\n" CONFIG_TAIL },
		{ "an oracle value with two spaces",
		    "oracle-1: aa00aa00 one two\n" CONFIG_TAIL },
		{ "an oracle key that is not hex",
		    "oracle-1: zz00zz00 https://one.example.test\n"
		    CONFIG_TAIL },
		{ "a plate check value of another length",
		    "oracle-1: " ORACLE_A "\nplate-check: aa00\n"
		    CONFIG_TAIL },
		{ "a machine name with an upper-case letter",
		    "oracle-1: " ORACLE_A "\nthreshold: 1\n"
		    "machine-name: LAPTOP\n" },
		{ "a machine name of 65 bytes",
		    "oracle-1: " ORACLE_A "\nthreshold: 1\nmachine-name: "
		    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		    "aaaaaaaaaaaaaaa\n" }
	};
	static const struct {
		const char	*name;
		const char	*from;
		const char	*to;
		int		 take;
	} changes[] = {
		{ "an exchange of two positions", change_ab, change_ba, 0 },
		{ "a position that disappears", change_ab, change_a, 0 },
		{ "a position that retires", change_ab, change_ar, 1 },
		{ "a position at the end", change_ab, change_abc, 1 },
		{ "a replacement oracle", change_ab, change_cb, 1 }
	};
	static struct vault_config	 cfg, from, to;
	size_t				 i;
	int				 rv = 0;

	if (readconfig("the config file", text_config, &cfg) != 0)
		return -1;
	if (cfg.count != 2 || cfg.threshold != 1 || cfg.rounds != 16 ||
	    cfg.pool_size != 8 || cfg.pool_watermark != 2 ||
	    cfg.audit_age != 180 || cfg.lock_timeout != 300) {
		warnx("the config file: a value differs from the file");
		rv = -1;
	}
	if (strcmp(cfg.machine, "laptop") != 0 ||
	    strcmp(cfg.plate_check, TEST_HEX64) != 0 ||
	    strcmp(cfg.oracle[0].url, "https://one.example.test") != 0 ||
	    cfg.oracle[0].retired || !cfg.oracle[1].retired) {
		warnx("the config file: a value of a position differs from "
		    "the file");
		rv = -1;
	}

	for (i = 0; i < nitems(bad); i++)
		if (vault_config_read(bad[i].text, strlen(bad[i].text),
		    &cfg) == 0) {
			warnx("%s: the config reader takes it", bad[i].name);
			rv = -1;
		}

	/*
	 * A position must not disappear, and two positions must not
	 * exchange values (VAULT-CONFIG-6). One file cannot show
	 * this half of the rule, so the two configs of a change
	 * reach the rule together.
	 */
	for (i = 0; i < nitems(changes); i++) {
		if (readconfig(changes[i].name, changes[i].from, &from) != 0 ||
		    readconfig(changes[i].name, changes[i].to, &to) != 0) {
			rv = -1;
			continue;
		}
		if ((vault_config_change(&from, &to) == 0) !=
		    changes[i].take) {
			warnx("%s: the change rule differs from the "
			    "specification", changes[i].name);
			rv = -1;
		}
	}
	return rv;
}

/*
 * test_atomic():
 *	The write takes the bytes to the target, and a write that
 *	stops before the rename(2) leaves the target as it was
 *	(VAULT-ATOMIC-1, VAULT-ATOMIC-2).
 */
static int
test_atomic(void)
{
	static const unsigned char	 first[] = "canary-1: 1\n";
	static const unsigned char	 second[] = "canary-1: 2\n";
	char		 root[] = "vault-atomic.XXXXXXXX";
	char		 path[PATH_MAX], target[PATH_MAX], keep[PATH_MAX];
	unsigned char	 got[64];
	size_t		 gotlen;
	int		 count, rv = 0;

	if (mkdtemp(root) == NULL) {
		warn("mkdtemp");
		return -1;
	}
	snprintf(path, sizeof(path), "%s/counters", root);
	if (vault_write(path, first, sizeof(first) - 1) != 0) {
		warnx("the atomic write: the call fails");
		rv = -1;
		goto out;
	}
	if (slurp(path, got, sizeof(got), &gotlen) != 0) {
		rv = -1;
		goto out;
	}
	if (gotlen != sizeof(first) - 1 || memcmp(got, first, gotlen) != 0) {
		warnx("the atomic write: the file differs from the input");
		rv = -1;
	}

	/* A second write takes the place of the first one. */
	if (vault_write(path, second, sizeof(second) - 1) != 0) {
		warnx("the second write: the call fails");
		rv = -1;
		goto out;
	}
	if (slurp(path, got, sizeof(got), &gotlen) != 0) {
		rv = -1;
		goto out;
	}
	if (gotlen != sizeof(second) - 1 || memcmp(got, second, gotlen) != 0) {
		warnx("the second write: the file differs from the input");
		rv = -1;
	}

	/*
	 * A directory at the target stops the sequence at the
	 * rename(2), and the steps before it hold. The file of the
	 * target must stay, and the directory of the target must
	 * hold no temporary file (VAULT-ATOMIC-2).
	 */
	snprintf(target, sizeof(target), "%s/target", root);
	if (mkdir(target, 0700) == -1) {
		warn("mkdir %s", target);
		rv = -1;
		goto out;
	}
	snprintf(keep, sizeof(keep), "%s/keep", target);
	if (vault_write(keep, first, sizeof(first) - 1) != 0) {
		warnx("the write of the target file: the call fails");
		rv = -1;
		goto out;
	}
	if (vault_write(target, second, sizeof(second) - 1) == 0) {
		warnx("a write over a directory: the call takes it");
		rv = -1;
	}
	if (access(keep, F_OK) != 0) {
		warnx("a stopped write: the target loses the file of it");
		rv = -1;
	}
	count = entries(root, 0);
	if (count != 2) {
		warnx("a stopped write: the directory holds %d names, and "
		    "the counters file and the target take 2", count);
		rv = -1;
	}
out:
	rmtree(root);
	return rv;
}

/*
 * test_layout():
 *	The entry file of a slot sits at the lowercase hex of
 *	H(K_e), each other file takes the fixed path of the layout,
 *	and a listing of the vault holds a hex name, index and the
 *	machine-local subdirectory alone (VAULT-LAYOUT-5 to
 *	VAULT-LAYOUT-7).
 */
static int
test_layout(void)
{
	static const struct {
		enum vault_file	 kind;
		const char	*tail;
	} want[] = {
		{ VAULT_FILE_INDEX, "index" },
		{ VAULT_FILE_FACTOR, "machine/factor" },
		{ VAULT_FILE_WRAP, "machine/wrap.17.2" },
		{ VAULT_FILE_WRAP_INDEX, "machine/wrap.index.2" },
		{ VAULT_FILE_CANARY, "machine/canary.2" },
		{ VAULT_FILE_COUNTERS, "machine/counters" },
		{ VAULT_FILE_CONFIG, "machine/config" },
		{ VAULT_FILE_CHANGE, "machine/change" }
	};
	static const unsigned char	 key[DERIVE_KEYLEN] = { 0 };
	static const unsigned char	 body[] = "slot: 17\n";
	struct vault_at	 at;
	char		 root[] = "vault-layout.XXXXXXXX";
	char		 name[VAULT_NAMELEN], path[PATH_MAX];
	char		 expect[PATH_MAX];
	size_t		 i;
	int		 count, rv = 0;

	if (vault_entry_name(key, sizeof(key), name, sizeof(name)) != 0) {
		warnx("the entry file name: the call fails");
		return -1;
	}
	if (strcmp(name, TEST_HEX64) != 0) {
		warnx("the entry file name is %s, and the vector is %s", name,
		    TEST_HEX64);
		return -1;
	}

	memset(&at, 0, sizeof(at));
	at.name = name;
	at.slot = 17;
	at.oracle = 2;

	/* An index that the layout rejects gives a failure. */
	at.oracle = 0;
	if (vault_path(path, sizeof(path), "v", VAULT_FILE_CANARY, &at) == 0) {
		warnx("an oracle index of 0: the path takes it");
		rv = -1;
	}
	at.oracle = DERIVE_ORACLE_MAX + 1;
	if (vault_path(path, sizeof(path), "v", VAULT_FILE_CANARY, &at) == 0) {
		warnx("an oracle index above %d: the path takes it",
		    DERIVE_ORACLE_MAX);
		rv = -1;
	}
	at.oracle = 2;
	at.slot = (uint32_t)INT32_MAX + 1;
	if (vault_path(path, sizeof(path), "v", VAULT_FILE_WRAP, &at) == 0) {
		warnx("a slot index of 2^31: the path takes it");
		rv = -1;
	}
	at.slot = 17;
	at.name = "not-a-hex-name";
	if (vault_path(path, sizeof(path), "v", VAULT_FILE_ENTRY, &at) == 0) {
		warnx("a name of another length: the path takes it");
		rv = -1;
	}
	strlcpy(expect, TEST_HEX64, sizeof(expect));
	expect[0] = 'z';
	at.name = expect;
	if (vault_path(path, sizeof(path), "v", VAULT_FILE_ENTRY, &at) == 0) {
		warnx("a name that is not hex: the path takes it");
		rv = -1;
	}
	at.name = name;

	if (mkdtemp(root) == NULL) {
		warn("mkdtemp");
		return -1;
	}
	snprintf(path, sizeof(path), "%s/%s", root, VAULT_MACHINE_DIR);
	if (mkdir(path, 0700) == -1) {
		warn("mkdir %s", path);
		rv = -1;
		goto out;
	}
	for (i = 0; i < nitems(want); i++) {
		snprintf(expect, sizeof(expect), "%s/%s", root, want[i].tail);
		if (vault_path(path, sizeof(path), root, want[i].kind,
		    &at) != 0) {
			warnx("%s: the path fails", want[i].tail);
			rv = -1;
			continue;
		}
		if (strcmp(path, expect) != 0) {
			warnx("the path is %s, and the layout takes %s", path,
			    expect);
			rv = -1;
			continue;
		}
		if (vault_write(path, body, sizeof(body) - 1) != 0) {
			warnx("%s: the write fails", want[i].tail);
			rv = -1;
		}
	}

	/* The entry file of the slot sits at the hex name. */
	snprintf(expect, sizeof(expect), "%s/%s", root, name);
	if (vault_path(path, sizeof(path), root, VAULT_FILE_ENTRY, &at) != 0) {
		warnx("the entry path: the call fails");
		rv = -1;
		goto out;
	}
	if (strcmp(path, expect) != 0) {
		warnx("the entry path is %s, and the layout takes %s", path,
		    expect);
		rv = -1;
	}
	if (vault_write(path, body, sizeof(body) - 1) != 0) {
		warnx("the entry file: the write fails");
		rv = -1;
	}

	/*
	 * The listing of the vault root holds the entry file, index
	 * and the machine-local subdirectory (VAULT-LAYOUT-7).
	 */
	count = entries(root, 1);
	if (count != 3) {
		warnx("the listing holds %d names, and the vault holds the "
		    "entry file, index and %s", count, VAULT_MACHINE_DIR);
		rv = -1;
	}
out:
	rmtree(root);
	return rv;
}

int
main(void)
{
	int	 rv = 0;

	rv |= test_vector();
	rv |= test_roundtrip();
	rv |= test_reject();
	rv |= test_nonce();
	rv |= test_scan();
	rv |= test_kinds();
	rv |= test_config();
	rv |= test_atomic();
	rv |= test_layout();
	return rv != 0;
}
