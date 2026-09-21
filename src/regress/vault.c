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
 * table of each file kind, the config file, the atomic write, the
 * directory layout, the entry model, the TOTP code, and the
 * sealed file of a vault.
 * tests/vectors/seal.h holds the seal vectors, and every seal test
 * reads them from there. The TOTP vectors of RFC 6238 sit with the
 * test of them. A test needs no network and no oracle
 * (TEST-KAT-5).
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
#include "entry.h"
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
 *	(VAULT-FORMAT-3, VAULT-FORMAT-8). test_entries() holds the
 *	six entry types of entry.c (ENTRY-TYPES-5).
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

/*
 * The keys of the test vectors of RFC 6238, as lowercase hex. The
 * document gives them as ASCII digits, of 20, 32 and 64 bytes.
 */
#define TOTP_KEY_SHA1	"3132333435363738393031323334353637383930"
#define TOTP_KEY_SHA256	TOTP_KEY_SHA1 "313233343536373839303132"
#define TOTP_KEY_SHA512	TOTP_KEY_SHA1 TOTP_KEY_SHA1 TOTP_KEY_SHA1 "31323334"

/* The seconds of one step of the vectors (RFC 6238). */
#define TOTP_PERIOD	30

/*
 * The entry file of each of the six types (ENTRY-TYPES-5). The
 * secret field comes first (VAULT-FORMAT-4), and each value is a
 * public test constant.
 */
static const char	 text_password[] =
    "password: the-test-value-of-a-password-entry\n"
    "type: password\n"
    "slots: 17,40\n"
    "username: the-test-user\n"
    "url: https://one.example.test/login\n"
    "transform: the test transform of a site\n"
    "version: 2\n";

static const char	 text_mnemonic[] =
    "mnemonic: the-twelve-words-of-the-test\n"
    "type: mnemonic\n"
    "slots: 18\n";

static const char	 text_passphrase[] =
    "passphrase: the-test-value-of-a-passphrase-entry\n"
    "type: passphrase\n"
    "slots: 19\n"
    "seed-fingerprint: aa00aa00\n";

static const char	 text_totp[] =
    "totp-key: " TOTP_KEY_SHA1 "\n"
    "type: totp\n"
    "slots: 20\n"
    "totp-algorithm: sha1\n"
    "totp-digits: 6\n"
    "totp-period: 30\n";

static const char	 text_note[] =
    "note: the test descriptor of a note entry\n"
    "type: note\n"
    "slots: 21\n";

static const char	 text_shadow[] =
    "type: shadow\n"
    "slots: 22\n"
    "location: the test location of a plate\n"
    "custodian: the test custodian\n"
    "verified: 2026-09-21\n";

/*
 * The six entry types, with the file, the secret field and the
 * candidate of each one (ENTRY-TYPES-1, ENTRY-TYPES-4,
 * ENTRY-TYPES-5). This table is the list of the specification, and
 * the test reads none of it from entry.c. A type with no secret
 * field holds NULL, and the value of a secret field takes the form
 * of the row of it.
 */
static const struct {
	const char		*name;
	enum entry_type		 type;
	const char		*text;
	const char		*secret;
	const char		*value;
	enum entry_candidate	 candidate;
} types[] = {
	{ "password", ENTRY_TYPE_PASSWORD, text_password, "password", "x",
	    ENTRY_CANDIDATE_PWD },
	{ "mnemonic", ENTRY_TYPE_MNEMONIC, text_mnemonic, "mnemonic", "x",
	    ENTRY_CANDIDATE_BIP39 },
	{ "passphrase", ENTRY_TYPE_PASSPHRASE, text_passphrase, "passphrase",
	    "x", ENTRY_CANDIDATE_PWD },
	{ "totp", ENTRY_TYPE_TOTP, text_totp, "totp-key", "3132",
	    ENTRY_CANDIDATE_NONE },
	{ "note", ENTRY_TYPE_NOTE, text_note, "note", "x",
	    ENTRY_CANDIDATE_NONE },
	{ "shadow", ENTRY_TYPE_SHADOW, text_shadow, NULL, NULL,
	    ENTRY_CANDIDATE_NONE }
};

/*
 * table_rows(name, table, secret):
 *	Prove the rows of the field table at table. Every row takes
 *	a fixed name and one line, the type and the slots rows take
 *	the form of the specification, and the row of the secret
 *	field at secret is the one row of the secret block
 *	(ENTRY-TYPES-5, VAULT-FORMAT-4). A wrong row prints the
 *	failure and gives -1.
 */
static int
table_rows(const char *name, const struct vault_field *table,
    const char *secret)
{
	size_t	 row;
	int	 rv = 0, secrets = 0, slots = 0, type = 0;

	for (row = 0; table[row].name != NULL; row++) {
		if (table[row].form != VAULT_NAME_FIXED ||
		    (table[row].flags & VAULT_FIELD_REPEAT) != 0) {
			warnx("%s: the row %s takes an index or a repeat",
			    name, table[row].name);
			rv = -1;
		}
		if ((table[row].flags & VAULT_FIELD_SECRET) != 0) {
			secrets++;
			if (secret == NULL ||
			    strcmp(table[row].name, secret) != 0) {
				warnx("%s: %s is a secret field", name,
				    table[row].name);
				rv = -1;
			}
		}
		if (strcmp(table[row].name, "type") == 0) {
			type = 1;
			if (table[row].value != VAULT_VALUE_WORD) {
				warnx("%s: the type field takes another "
				    "value form", name);
				rv = -1;
			}
		}
		if (strcmp(table[row].name, "slots") == 0) {
			slots = 1;
			if (table[row].value != VAULT_VALUE_SLOTS) {
				warnx("%s: the slots field takes another "
				    "value form", name);
				rv = -1;
			}
		}
	}
	if (secrets != (secret == NULL ? 0 : 1)) {
		warnx("%s: the table holds %d secret fields", name, secrets);
		rv = -1;
	}
	if (!type || !slots) {
		warnx("%s: the table holds no type field or no slots field",
		    name);
		rv = -1;
	}
	return rv;
}

/*
 * test_entries():
 *	Each of the six entry types passes through the field table
 *	of it, and the scan writes the file back byte for byte
 *	(ENTRY-TYPES-5). The table of a type holds the fields of the
 *	specification, and the scanner rejects every other file.
 */
static int
test_entries(void)
{
	static const struct {
		const char	*name;
		enum entry_type	 type;
		const char	*text;
	} bad[] = {
		{ "a password entry with an unknown field",
		    ENTRY_TYPE_PASSWORD,
		    "password: x\ntype: password\nslots: 17\nnote: x\n" },
		{ "a password entry with a padded version",
		    ENTRY_TYPE_PASSWORD,
		    "password: x\ntype: password\nslots: 17\nversion: 02\n" },
		{ "a mnemonic entry with a space in the slot list",
		    ENTRY_TYPE_MNEMONIC, "mnemonic: x\ntype: mnemonic\n"
		    "slots: 17, 18\n" },
		{ "a passphrase entry with a fingerprint that is not hex",
		    ENTRY_TYPE_PASSPHRASE, "passphrase: x\n"
		    "type: passphrase\nslots: 17\nseed-fingerprint: zz\n" },
		{ "a totp entry with a key of an odd hex count",
		    ENTRY_TYPE_TOTP, "totp-key: 313\ntype: totp\n"
		    "slots: 17\n" },
		{ "a totp entry with a period that is not a number",
		    ENTRY_TYPE_TOTP, "totp-key: 3132\ntype: totp\n"
		    "slots: 17\ntotp-period: half\n" },
		{ "a note entry with a type field twice", ENTRY_TYPE_NOTE,
		    "note: x\ntype: note\ntype: note\nslots: 17\n" },
		{ "a shadow entry with a wrong month", ENTRY_TYPE_SHADOW,
		    "type: shadow\nslots: 17\nverified: 2026-13-01\n" },
		{ "a shadow entry with a secret field", ENTRY_TYPE_SHADOW,
		    "note: x\ntype: shadow\nslots: 17\n" }
	};
	struct build	 built;
	char		 text[128];
	enum entry_type	 type;
	size_t		 count, i;
	int		 n, rv = 0;

	for (i = 0; i < nitems(types); i++) {
		/* The name of the row is the value of the type field. */
		if (entry_type_find(types[i].name, strlen(types[i].name),
		    &type) != 0 || type != types[i].type ||
		    strcmp(entry_types[types[i].type].name,
		    types[i].name) != 0) {
			warnx("%s: the type of that name is another one",
			    types[i].name);
			rv = -1;
		}
		if (table_rows(types[i].name,
		    entry_types[types[i].type].fields, types[i].secret) != 0)
			rv = -1;

		memset(&built, 0, sizeof(built));
		if (vault_scan(types[i].text, strlen(types[i].text),
		    entry_types[types[i].type].fields, rebuild, &built) != 0) {
			warnx("%s: the scan of the entry file fails",
			    types[i].name);
			rv = -1;
		} else if (strcmp(built.text, types[i].text) != 0) {
			warnx("%s: the round trip gives %s", types[i].name,
			    built.text);
			rv = -1;
		}

		/*
		 * The secret block comes first, so a file with the
		 * secret field after the type field fails
		 * (VAULT-FORMAT-4).
		 */
		if (types[i].secret == NULL)
			continue;
		n = snprintf(text, sizeof(text), "type: %s\n%s: %s\n",
		    types[i].name, types[i].secret, types[i].value);
		count = 0;
		if (n < 0 || (size_t)n >= sizeof(text)) {
			warnx("%s: the test file does not fit",
			    types[i].name);
			rv = -1;
		} else if (vault_scan(text, strlen(text),
		    entry_types[types[i].type].fields, count_lines,
		    &count) == 0) {
			warnx("%s: the scanner takes the secret field after "
			    "the metadata", types[i].name);
			rv = -1;
		}
	}

	for (i = 0; i < nitems(bad); i++) {
		count = 0;
		if (vault_scan(bad[i].text, strlen(bad[i].text),
		    entry_types[bad[i].type].fields, count_lines,
		    &count) == 0) {
			warnx("%s: the scanner takes it", bad[i].name);
			rv = -1;
		}
	}

	/* A name that no row holds is no type (ENTRY-TYPES-1). */
	if (entry_type_find("passwords", strlen("passwords"), &type) == 0 ||
	    entry_type_find("", 0, &type) == 0) {
		warnx("the type lookup takes a name that no row holds");
		rv = -1;
	}
	return rv;
}

/*
 * test_model():
 *	The origin class table, the classes of each type, the
 *	candidate of each type, and the version of a slot
 *	(ENTRY-MODEL-1, ENTRY-MODEL-2, ENTRY-TYPES-4,
 *	ENTRY-ROTATION-2).
 */
static int
test_model(void)
{
	/*
	 * The origin classes of the specification. in_place states
	 * the rotation of the class: a derived entry takes a new
	 * slot, and every other class holds the slot of the entry
	 * (ENTRY-ROTATION-4).
	 */
	static const struct {
		enum entry_class	 class;
		const char		*name;
		int			 in_place;
	} classes[] = {
		{ ENTRY_CLASS_DERIVED, "derived", 0 },
		{ ENTRY_CLASS_STORED, "stored", 1 },
		{ ENTRY_CLASS_SOVEREIGN, "sovereign", 1 },
		{ ENTRY_CLASS_SHADOW, "shadow", 1 }
	};

	/*
	 * The classes of each type (ENTRY-TYPES-5). One character
	 * per class, in the order of the class table: y for a class
	 * that the type takes, and n for every other one.
	 */
	static const struct {
		enum entry_type	 type;
		const char	*allow;
	} allow[] = {
		{ ENTRY_TYPE_PASSWORD, "yynn" },
		{ ENTRY_TYPE_MNEMONIC, "yyyn" },
		{ ENTRY_TYPE_PASSPHRASE, "yyyn" },
		{ ENTRY_TYPE_TOTP, "nynn" },
		{ ENTRY_TYPE_NOTE, "nynn" },
		{ ENTRY_TYPE_SHADOW, "nnny" }
	};

	/* The version of one slot of a slot list (ENTRY-ROTATION-2). */
	static const struct {
		const char	*name;
		const char	*slots;
		uint32_t	 slot;
		unsigned int	 version;	/* 0 for a failure */
	} versions[] = {
		{ "the first slot of two", "17,40", 17, 1 },
		{ "the second slot of two", "17,40", 40, 2 },
		{ "the one slot of a new entry", "17", 17, 1 },
		{ "the third slot of three", "17,40,41", 41, 3 },
		{ "a slot that the list does not hold", "17,40", 41, 0 },
		{ "a slot that the list holds twice", "17,17", 17, 0 },
		{ "a list with a space", "17, 40", 40, 0 },
		{ "a padded index", "017,40", 17, 0 },
		{ "a list of no byte", "", 17, 0 }
	};
	size_t		 i, j;
	unsigned int	 version;
	int		 rv = 0, take;

	for (i = 0; i < nitems(classes); i++) {
		if (strcmp(entry_classes[classes[i].class].name,
		    classes[i].name) != 0 ||
		    entry_classes[classes[i].class].in_place !=
		    classes[i].in_place) {
			warnx("%s: the class row differs from the "
			    "specification", classes[i].name);
			rv = -1;
		}
		if (entry_classes[classes[i].class].origin[0] == '\0' ||
		    entry_classes[classes[i].class].backup[0] == '\0' ||
		    entry_classes[classes[i].class].restore[0] == '\0') {
			warnx("%s: the class row holds an empty column",
			    classes[i].name);
			rv = -1;
		}
	}

	/* The default class of a new entry is derived (ENTRY-MODEL-1). */
	if (strcmp(entry_classes[ENTRY_CLASS_DEFAULT].name, "derived") != 0) {
		warnx("the default class of a new entry is %s",
		    entry_classes[ENTRY_CLASS_DEFAULT].name);
		rv = -1;
	}

	for (i = 0; i < nitems(allow); i++) {
		if (strlen(allow[i].allow) != nitems(classes)) {
			warnx("the class list of a type holds %zu classes",
			    strlen(allow[i].allow));
			rv = -1;
			continue;
		}
		for (j = 0; j < nitems(classes); j++) {
			take = allow[i].allow[j] == 'y';
			if ((entry_class_check(allow[i].type,
			    classes[j].class) == 0) != take) {
				warnx("%s: the class %s differs from the "
				    "specification",
				    entry_types[allow[i].type].name,
				    classes[j].name);
				rv = -1;
			}
		}
	}

	/* The candidate of each type (ENTRY-TYPES-4). */
	for (i = 0; i < nitems(types); i++) {
		if (entry_types[types[i].type].candidate !=
		    types[i].candidate) {
			warnx("%s: the candidate differs from the "
			    "specification", types[i].name);
			rv = -1;
		}
	}
	if (entry_class_check(ENTRY_TYPE_MAX, ENTRY_CLASS_DERIVED) == 0 ||
	    entry_class_check(ENTRY_TYPE_PASSWORD, ENTRY_CLASS_MAX) == 0) {
		warnx("the class check takes a type or a class of the "
		    "count");
		rv = -1;
	}

	for (i = 0; i < nitems(versions); i++) {
		version = 0;
		if (entry_version(versions[i].slots,
		    strlen(versions[i].slots), versions[i].slot,
		    &version) != 0) {
			if (versions[i].version != 0) {
				warnx("%s: the version call fails",
				    versions[i].name);
				rv = -1;
			}
			continue;
		}
		if (version != versions[i].version) {
			warnx("%s: the version is %u, and the list gives "
			    "%u", versions[i].name, version,
			    versions[i].version);
			rv = -1;
		}
	}
	return rv;
}

/*
 * test_totp():
 *	The TOTP code of the test vectors of RFC 6238 is correct for
 *	SHA-1, SHA-256 and SHA-512 (ENTRY-TYPES-3). The last three
 *	rows take 6 digits, and the code of them is the low part of
 *	the 8-digit code of the same second.
 */
static int
test_totp(void)
{
	static const struct {
		enum entry_totp_alg	 alg;
		const char		*key;
		uint64_t		 at;
		unsigned int		 digits;
		const char		*code;
	} codes[] = {
		{ ENTRY_TOTP_SHA1, TOTP_KEY_SHA1, 59, 8, "94287082" },
		{ ENTRY_TOTP_SHA256, TOTP_KEY_SHA256, 59, 8, "46119246" },
		{ ENTRY_TOTP_SHA512, TOTP_KEY_SHA512, 59, 8, "90693936" },
		{ ENTRY_TOTP_SHA1, TOTP_KEY_SHA1, 1111111109, 8, "07081804" },
		{ ENTRY_TOTP_SHA256, TOTP_KEY_SHA256, 1111111109, 8,
		    "68084774" },
		{ ENTRY_TOTP_SHA512, TOTP_KEY_SHA512, 1111111109, 8,
		    "25091201" },
		{ ENTRY_TOTP_SHA1, TOTP_KEY_SHA1, 1111111111, 8, "14050471" },
		{ ENTRY_TOTP_SHA256, TOTP_KEY_SHA256, 1111111111, 8,
		    "67062674" },
		{ ENTRY_TOTP_SHA512, TOTP_KEY_SHA512, 1111111111, 8,
		    "99943326" },
		{ ENTRY_TOTP_SHA1, TOTP_KEY_SHA1, 1234567890, 8, "89005924" },
		{ ENTRY_TOTP_SHA256, TOTP_KEY_SHA256, 1234567890, 8,
		    "91819424" },
		{ ENTRY_TOTP_SHA512, TOTP_KEY_SHA512, 1234567890, 8,
		    "93441116" },
		{ ENTRY_TOTP_SHA1, TOTP_KEY_SHA1, 2000000000, 8, "69279037" },
		{ ENTRY_TOTP_SHA256, TOTP_KEY_SHA256, 2000000000, 8,
		    "90698825" },
		{ ENTRY_TOTP_SHA512, TOTP_KEY_SHA512, 2000000000, 8,
		    "38618901" },
		{ ENTRY_TOTP_SHA1, TOTP_KEY_SHA1, 20000000000, 8,
		    "65353130" },
		{ ENTRY_TOTP_SHA256, TOTP_KEY_SHA256, 20000000000, 8,
		    "77737706" },
		{ ENTRY_TOTP_SHA512, TOTP_KEY_SHA512, 20000000000, 8,
		    "47863826" },
		{ ENTRY_TOTP_SHA1, TOTP_KEY_SHA1, 59, 6, "287082" },
		{ ENTRY_TOTP_SHA256, TOTP_KEY_SHA256, 1111111109, 6,
		    "084774" },
		{ ENTRY_TOTP_SHA512, TOTP_KEY_SHA512, 20000000000, 6,
		    "863826" }
	};

	/* The values that the call rejects. */
	static const struct {
		const char	*name;
		unsigned int	 digits;
		unsigned int	 period;
		size_t		 keylen;
		size_t		 outlen;
	} bad[] = {
		{ "a code of 5 digits", 5, TOTP_PERIOD, 20, ENTRY_TOTP_MAX },
		{ "a code of 9 digits", 9, TOTP_PERIOD, 20, ENTRY_TOTP_MAX },
		{ "a period of 0 seconds", 6, 0, 20, ENTRY_TOTP_MAX },
		{ "a key of no byte", 6, TOTP_PERIOD, 0, ENTRY_TOTP_MAX },
		{ "an output buffer of one byte less", 6, TOTP_PERIOD, 20,
		    ENTRY_TOTP_MAX - 1 }
	};

	/* The algorithm names of the totp-algorithm field. */
	static const struct {
		const char		*name;
		enum entry_totp_alg	 alg;
		int			 take;
	} algs[] = {
		{ "sha1", ENTRY_TOTP_SHA1, 1 },
		{ "sha256", ENTRY_TOTP_SHA256, 1 },
		{ "sha512", ENTRY_TOTP_SHA512, 1 },
		{ "sha", ENTRY_TOTP_SHA1, 0 },
		{ "sha3", ENTRY_TOTP_SHA1, 0 },
		{ "SHA1", ENTRY_TOTP_SHA1, 0 }
	};
	char			 code[ENTRY_TOTP_MAX], name[NAMELEN];
	unsigned char		 key[64];
	enum entry_totp_alg	 alg;
	size_t			 i, keylen;
	int			 rv = 0;

	for (i = 0; i < nitems(codes); i++) {
		snprintf(name, sizeof(name), "the TOTP vector %zu", i);
		if (hexsize(name, codes[i].key, &keylen) != 0 ||
		    keylen > sizeof(key)) {
			warnx("%s: the key does not fit", name);
			rv = -1;
			continue;
		}
		if (hexbytes(name, codes[i].key, key, keylen) != 0) {
			rv = -1;
			continue;
		}
		if (entry_totp(key, keylen, codes[i].alg, codes[i].digits,
		    TOTP_PERIOD, codes[i].at, code, sizeof(code)) != 0) {
			warnx("%s: the call fails", name);
			rv = -1;
			continue;
		}
		if (strcmp(code, codes[i].code) != 0) {
			warnx("%s: the code is %s, and the vector gives %s",
			    name, code, codes[i].code);
			rv = -1;
		}
	}

	if (hexbytes("the TOTP key", TOTP_KEY_SHA1, key, 20) != 0)
		return -1;
	for (i = 0; i < nitems(bad); i++) {
		if (entry_totp(key, bad[i].keylen, ENTRY_TOTP_SHA1,
		    bad[i].digits, bad[i].period, 59, code,
		    bad[i].outlen) == 0) {
			warnx("%s: the call takes it", bad[i].name);
			rv = -1;
		}
	}

	for (i = 0; i < nitems(algs); i++) {
		alg = ENTRY_TOTP_SHA512;
		if ((entry_totp_alg_find(algs[i].name, strlen(algs[i].name),
		    &alg) == 0) != algs[i].take) {
			warnx("%s: the algorithm lookup differs from the "
			    "specification", algs[i].name);
			rv = -1;
		} else if (algs[i].take && alg != algs[i].alg) {
			warnx("%s: the algorithm lookup gives another hash",
			    algs[i].name);
			rv = -1;
		}
	}
	return rv;
}

/*
 * The buffer of a sealed file below. It takes the bytes of the
 * file, and then the plaintext of them (vault.h). The longest file
 * of a test here holds about 200 bytes.
 */
#define SEALBUF		1024

/*
 * sealread(name, path, key, table, want):
 *	Read the sealed file at path under key, with the field
 *	table at table, and compare the plaintext of it with want.
 *	A wrong value prints the name and gives -1.
 */
static int
sealread(const char *name, const char *path, const unsigned char *key,
    const struct vault_field *table, const char *want)
{
	struct build	 built;
	unsigned char	 buf[SEALBUF];

	memset(&built, 0, sizeof(built));
	if (vault_seal_read(path, key, SEAL_KEYLEN, buf, sizeof(buf), table,
	    rebuild, &built) != 0) {
		warnx("%s: the read of the sealed file fails", name);
		return -1;
	}
	if (strcmp(built.text, want) != 0) {
		warnx("%s: the round trip gives %s", name, built.text);
		return -1;
	}
	return 0;
}

/*
 * badread(name, path, key, sealed, sealedlen):
 *	Write the sealedlen bytes at sealed to path, and read the
 *	file back under key, with the field table of a password
 *	entry. The read must give -1, and no byte of a plaintext
 *	must reach the callback. Each case of the caller takes this
 *	one value, so the read names no cause (VAULT-SEAL-4).
 */
static int
badread(const char *name, const char *path, const unsigned char *key,
    const unsigned char *sealed, size_t sealedlen)
{
	struct build	 built;
	unsigned char	 buf[SEALBUF];
	int		 got, rv = 0;

	memset(&built, 0, sizeof(built));
	if (vault_write(path, sealed, sealedlen) != 0) {
		warnx("%s: the write of the file fails", name);
		return -1;
	}
	got = vault_seal_read(path, key, SEAL_KEYLEN, buf, sizeof(buf),
	    entry_types[ENTRY_TYPE_PASSWORD].fields, rebuild, &built);
	if (got != -1) {
		warnx("%s: the sealed read gives %d, and each failure gives "
		    "-1", name, got);
		rv = -1;
	}
	if (built.at != 0) {
		warnx("%s: %zu bytes of a plaintext reach the callback", name,
		    built.at);
		rv = -1;
	}
	return rv;
}

/*
 * test_sealfile():
 *	A vault file goes to disk under one key, and it comes back
 *	through that key. The entry file of a slot seals under K_e
 *	at the name of vault_entry_name(), and the index seals
 *	under K_idx at the name of the layout (KEY-ENTRY-3,
 *	VAULT-INDEX-1). The two keys come from the root of the
 *	test, so each file takes the key of the specification
 *	(KEY-ENTRY-2, KEY-MASK-6). No oracle touches this vault
 *	(TEST-KAT-5).
 *
 *	A wrong key, a short file, a truncated file, a changed byte
 *	and a plaintext that the field table rejects each give the
 *	one failure of the seal (VAULT-SEAL-4). A buffer that the
 *	file does not fit gives that failure too, and a buffer that
 *	the sealed bytes do not fit writes no file.
 */
static int
test_sealfile(void)
{
	static const unsigned char	 root[DERIVE_ROOTLEN] = { 0 };
	struct vault_at	 at;
	unsigned char	 entrykey[DERIVE_KEYLEN];
	unsigned char	 indexkey[DERIVE_KEYLEN];
	unsigned char	 wrong[DERIVE_KEYLEN];
	unsigned char	 buf[SEALBUF], sealed[SEALBUF], got[SEALBUF];
	char		 vault[] = "vault-seal.XXXXXXXX";
	char		 name[VAULT_NAMELEN];
	char		 path[PATH_MAX], expect[PATH_MAX];
	size_t		 gotlen, indexlen, lines = 0, plainlen, sealedlen;
	int		 rv = 0;

	/*
	 * The root of the test is 64 zero bytes, a public constant.
	 * Slot 17 is the slot of the entry file below.
	 */
	if (derive_entry_key(root, sizeof(root), 17, entrykey,
	    sizeof(entrykey)) != 0 ||
	    derive_index_key(root, sizeof(root), indexkey,
	    sizeof(indexkey)) != 0) {
		warnx("the keys of the sealed files: a derivation fails");
		return -1;
	}
	if (vault_entry_name(entrykey, sizeof(entrykey), name,
	    sizeof(name)) != 0) {
		warnx("the entry file name: the call fails");
		return -1;
	}
	if (mkdtemp(vault) == NULL) {
		warn("mkdtemp");
		return -1;
	}
	memset(&at, 0, sizeof(at));
	at.name = name;
	if (vault_path(path, sizeof(path), vault, VAULT_FILE_ENTRY,
	    &at) != 0) {
		warnx("the entry path: the call fails");
		rv = -1;
		goto out;
	}
	snprintf(expect, sizeof(expect), "%s/%s", vault, name);
	if (strcmp(path, expect) != 0) {
		warnx("the entry path is %s, and the layout takes %s", path,
		    expect);
		rv = -1;
		goto out;
	}
	plainlen = strlen(text_password);
	sealedlen = plainlen + SEAL_OVERHEAD;

	/* A buffer that the sealed bytes do not fit writes no file. */
	if (vault_seal_write(path, entrykey, sizeof(entrykey),
	    (const unsigned char *)text_password, plainlen, buf,
	    sealedlen - 1) == 0) {
		warnx("a buffer of one byte too few: the sealed write takes "
		    "it");
		rv = -1;
	}
	if (access(path, F_OK) == 0) {
		warnx("a failed sealed write: the file of it exists");
		rv = -1;
	}

	/* The entry file of the slot seals under K_e (KEY-ENTRY-3). */
	if (vault_seal_write(path, entrykey, sizeof(entrykey),
	    (const unsigned char *)text_password, plainlen, buf,
	    sizeof(buf)) != 0) {
		warnx("the entry file: the sealed write fails");
		rv = -1;
		goto out;
	}
	if (slurp(path, got, sizeof(got), &gotlen) != 0) {
		rv = -1;
		goto out;
	}
	if (gotlen != sealedlen) {
		warnx("the entry file holds %zu bytes, and a seal of that "
		    "plaintext takes %zu", gotlen, sealedlen);
		rv = -1;
		goto out;
	}
	if (got[SEAL_OFF_VERSION] != SEAL_VERSION) {
		warnx("the entry file holds the version %02x, and the layout "
		    "takes %02x", got[SEAL_OFF_VERSION], SEAL_VERSION);
		rv = -1;
	}
	if (sealread("the entry file", path, entrykey,
	    entry_types[ENTRY_TYPE_PASSWORD].fields, text_password) != 0)
		rv = -1;

	/* A buffer that the file fills leaves no room for the plaintext. */
	if (vault_seal_read(path, entrykey, sizeof(entrykey), buf, sealedlen,
	    entry_types[ENTRY_TYPE_PASSWORD].fields, count_lines,
	    &lines) == 0) {
		warnx("a buffer that the file fills: the sealed read takes "
		    "it");
		rv = -1;
	}

	/* The index seals under K_idx (VAULT-INDEX-1). */
	indexlen = strlen(text_index);
	if (vault_path(path, sizeof(path), vault, VAULT_FILE_INDEX,
	    NULL) != 0) {
		warnx("the index path: the call fails");
		rv = -1;
		goto out;
	}
	if (vault_seal_write(path, indexkey, sizeof(indexkey),
	    (const unsigned char *)text_index, indexlen, buf,
	    sizeof(buf)) != 0) {
		warnx("the index: the sealed write fails");
		rv = -1;
		goto out;
	}
	if (sealread("the index", path, indexkey, vault_index_fields,
	    text_index) != 0)
		rv = -1;

	/*
	 * Each case below takes the entry path, and vault_write()
	 * puts the exact bytes of the case there.
	 */
	if (vault_path(path, sizeof(path), vault, VAULT_FILE_ENTRY,
	    &at) != 0) {
		warnx("the entry path: the call fails");
		rv = -1;
		goto out;
	}
	if (seal_seal(entrykey, sizeof(entrykey),
	    (const unsigned char *)text_password, plainlen, sealed,
	    sealedlen) != 0) {
		warnx("the seal of the entry file: the call fails");
		rv = -1;
		goto out;
	}
	memcpy(wrong, entrykey, sizeof(wrong));
	wrong[0] ^= 0x01;
	if (badread("a wrong key", path, wrong, sealed, sealedlen) != 0)
		rv = -1;
	if (badread("a file of the seal overhead alone", path, entrykey,
	    sealed, SEAL_OVERHEAD) != 0)
		rv = -1;
	if (badread("a truncated file", path, entrykey, sealed,
	    sealedlen - 1) != 0)
		rv = -1;
	sealed[SEAL_OFF_BODY] ^= 0x01;
	if (badread("a changed byte of the body", path, entrykey, sealed,
	    sealedlen) != 0)
		rv = -1;

	/*
	 * The file below holds the index text under the entry key.
	 * The field table of a password entry holds no field of
	 * that text, so the scan of it fails (VAULT-FORMAT-6).
	 */
	if (seal_seal(entrykey, sizeof(entrykey),
	    (const unsigned char *)text_index, indexlen, sealed,
	    indexlen + SEAL_OVERHEAD) != 0) {
		warnx("the seal of the index text: the call fails");
		rv = -1;
		goto out;
	}
	if (badread("a plaintext that the field table rejects", path,
	    entrykey, sealed, indexlen + SEAL_OVERHEAD) != 0)
		rv = -1;
out:
	rmtree(vault);
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
	rv |= test_entries();
	rv |= test_model();
	rv |= test_totp();
	rv |= test_sealfile();
	return rv != 0;
}
