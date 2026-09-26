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
 * The known-answer tests of the derivation tree (TEST-KAT-1,
 * TEST-KAT-4, TEST-KAT-6). tests/vectors/derive.h holds the vectors,
 * and every test reads them from there. A test needs no network and
 * no oracle (TEST-KAT-5).
 *
 * The program prints nothing on a pass, and it exits 0. A wrong
 * value prints the test, the value and the vector to the standard
 * error, and the program exits 1. Every test runs on each run, so
 * one run reports every wrong value.
 *
 * The values of the tests are public constants of the tests, so this
 * file holds no secret and clears nothing.
 */

#include <ctype.h>
#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/sha.h>

#include "bip85.h"
#include "derive.h"
#include "wordlist.h"

/*
 * The vectors, one directory below tests. Two files carry the name
 * derive.h: the interface of the derivation core, and this one. The
 * include above takes the interface, and the include below carries
 * the directory name, which the source directory does not hold. No
 * order of the search path can exchange the two files.
 */
#include "vectors/derive.h"

/*
 * Each of the two files sets a guard of its own, and both files must
 * enter this one. A build that reaches one file only stops here.
 */
#if !defined(DERIVE_H) || !defined(VECTORS_DERIVE_H)
#error an include of kat.c reached the wrong derive.h
#endif

/*
 * The first 11 words of the test master. The 12th word makes the
 * negative cases: the line alone is 11 words, one more abandon gives
 * a wrong checksum, and fugu is not a word of the list.
 */
#define WORDS_11 \
	"abandon abandon abandon abandon abandon abandon " \
	"abandon abandon abandon abandon abandon"

/*
 * A 24-word master with a correct BIP39 checksum. Its entropy is 32
 * zero bytes, and its words are the published BIP39 vector of that
 * entropy. A master has 12 words, so the gate must reject this line
 * on the count alone (D-22, KEY-MASTER-6).
 */
#define WORDS_24 \
	"abandon abandon abandon abandon abandon abandon " \
	"abandon abandon abandon abandon abandon abandon " \
	"abandon abandon abandon abandon abandon abandon " \
	"abandon abandon abandon abandon abandon art"

/*
 * A caller word that is longer than every word of the list. Its
 * first WORDLIST_MAX bytes are the word accident of the list, so a
 * lookup of those bytes alone gives a wrong index.
 */
#define WORD_LONG	"accidental"

/*
 * hexcheck(name, value, len, want):
 *	Compare the len bytes at value with the hex text at want. A
 *	difference prints the two values, and gives -1.
 */
static int
hexcheck(const char *name, const unsigned char *value, size_t len,
    const char *want)
{
	char	 got[2 * DERIVE_ROOTLEN + 1];
	size_t	 i;

	if (len > DERIVE_ROOTLEN) {
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
 * textcheck(name, got, want):
 *	Compare the text at got with the text at want. A difference
 *	prints the two values, and gives -1.
 */
static int
textcheck(const char *name, const char *got, const char *want)
{
	if (strcmp(got, want) != 0) {
		warnx("%s: the value is %s, and the vector is %s", name, got,
		    want);
		return -1;
	}
	return 0;
}

/*
 * test_wordlist():
 *	The table holds the 2048 words of the pinned digest, and each
 *	word maps to its index and back. A word that is longer than
 *	every word of the list gives a failure, and a buffer that is
 *	too small for a word takes no byte of it. The digest covers the
 *	words, with one line feed after each word. FuguSeed pins the
 *	same number for the same list, so the two projects agree on
 *	the list by one number.
 */
static int
test_wordlist(void)
{
	SHA256_CTX	 ctx;
	unsigned char	 digest[SHA256_DIGEST_LENGTH];
	char		 word[WORDLIST_MAX + 1];
	size_t		 i, index, len;
	int		 rv = 0;

	SHA256_Init(&ctx);
	for (i = 0; i < WORDLIST_COUNT; i++) {
		if (wordlist_word(i, word, sizeof(word)) != 0) {
			warnx("the word list: the word of %zu is absent", i);
			return -1;
		}
		len = strlen(word);
		SHA256_Update(&ctx, word, len);
		SHA256_Update(&ctx, "\n", 1);
		if (wordlist_index(word, len, &index) != 0) {
			warnx("the word list: the index of the word of %zu "
			    "is absent", i);
			rv = -1;
		} else if (index != i) {
			warnx("the word list: the word of %zu maps to %zu",
			    i, index);
			rv = -1;
		}
	}
	SHA256_Final(digest, &ctx);
	if (hexcheck("the word digest", digest, sizeof(digest),
	    WORDLIST_DIGEST) != 0)
		rv = -1;

	/*
	 * A line of the operator can hold a long word. The guard of
	 * the lookup stops that word before the buffer of the scan.
	 */
	if (wordlist_index(WORD_LONG, strlen(WORD_LONG), &index) == 0) {
		warnx("the word list: the long word %s maps to %zu",
		    WORD_LONG, index);
		rv = -1;
	}

	/*
	 * A buffer that is too small for a word takes no byte of it: a
	 * failed call writes nothing to an output (wordlist.h). The
	 * first word of the list holds seven letters.
	 */
	memset(word, 'x', sizeof(word));
	if (wordlist_word(0, word, 3) == 0 || word[0] != 'x') {
		warnx("the word list: a small buffer takes a part of a word");
		rv = -1;
	}
	return rv;
}

/*
 * nowords(name, err):
 *	Prove that the message at err holds no word of the list
 *	(KEY-MASTER-6). The rule bans a word of the scanned master,
 *	and a message of no list word at all holds to the rule for
 *	every master.
 *
 *	One run of letters is one word of the message, and the list
 *	holds a whole run or none of it. The rule bans a word, and
 *	not a part of one: the word checksum starts with the letters
 *	of a word of the list, and KEY-MASTER-6 asks the gate to name
 *	the checksum.
 */
static int
nowords(const char *name, const char *err)
{
	size_t	 i, len, index;

	if (err[0] == '\0') {
		warnx("%s: the gate gives no message", name);
		return -1;
	}
	for (i = 0; err[i] != '\0'; i++) {
		if (!isalpha((unsigned char)err[i]))
			continue;
		for (len = 0; isalpha((unsigned char)err[i + len]); len++)
			continue;
		if (wordlist_index(&err[i], len, &index) == 0) {
			warnx("%s: the message holds a word of the list: %s",
			    name, err);
			return -1;
		}
		i += len - 1;
	}
	return 0;
}

/*
 * reject(name, line):
 *	Prove that the gate rejects the master at line, and that the
 *	message of the gate holds no word.
 */
static int
reject(const char *name, const char *line)
{
	char	 err[DERIVE_ERRLEN];

	err[0] = '\0';
	if (derive_master_check(line, strlen(line), err, sizeof(err)) == 0) {
		warnx("%s: the gate takes the line", name);
		return -1;
	}
	return nowords(name, err);
}

/*
 * test_gate():
 *	The gate takes the test master. It rejects 11 words, 13
 *	words, 24 words, an unknown word, and a wrong checksum.
 */
static int
test_gate(void)
{
	char	 err[DERIVE_ERRLEN];
	int	 rv = 0;

	err[0] = '\0';
	if (derive_master_check(KAT_TEST_MASTER, strlen(KAT_TEST_MASTER), err,
	    sizeof(err)) != 0) {
		warnx("the test master: the gate rejects it: %s", err);
		rv = -1;
	}
	if (reject("11 words", WORDS_11) != 0)
		rv = -1;
	if (reject("13 words", KAT_TEST_MASTER " abandon") != 0)
		rv = -1;
	if (reject("24 words", WORDS_24) != 0)
		rv = -1;
	if (reject("an unknown word", WORDS_11 " fugu") != 0)
		rv = -1;
	if (reject("a wrong checksum", WORDS_11 " abandon") != 0)
		rv = -1;
	return rv;
}

/*
 * test_root():
 *	The BIP39 seed of the test master equals the vector.
 */
static int
test_root(void)
{
	unsigned char	 root[DERIVE_ROOTLEN];

	if (derive_root(KAT_TEST_MASTER, strlen(KAT_TEST_MASTER), root,
	    sizeof(root)) != 0) {
		warnx("root of the test master: the call fails");
		return -1;
	}
	return hexcheck("root of the test master", root, sizeof(root),
	    KAT_TEST_ROOT);
}

/*
 * test_labels():
 *	The entry key of the slot of the vectors and the plate check
 *	value equal the vectors (TEST-KAT-4).
 */
static int
test_labels(void)
{
	unsigned char	 root[DERIVE_ROOTLEN];
	unsigned char	 key[DERIVE_KEYLEN];
	int		 rv = 0;

	if (derive_root(KAT_TEST_MASTER, strlen(KAT_TEST_MASTER), root,
	    sizeof(root)) != 0) {
		warnx("root of the test master: the call fails");
		return -1;
	}
	if (derive_entry_key(root, sizeof(root), KAT_TEST_SLOT, key,
	    sizeof(key)) != 0) {
		warnx("the entry key: the call fails");
		rv = -1;
	} else if (hexcheck("the entry key", key, sizeof(key),
	    KAT_TEST_ENTRY_KEY) != 0)
		rv = -1;
	if (derive_plate_check(root, sizeof(root), key, sizeof(key)) != 0) {
		warnx("the plate check value: the call fails");
		rv = -1;
	} else if (hexcheck("the plate check value", key, sizeof(key),
	    KAT_TEST_PLATE_CHECK) != 0)
		rv = -1;
	return rv;
}

/*
 * test_bip85():
 *	The two applications give the values of the BIP85 document,
 *	from the master of that document (TEST-KAT-1).
 */
static int
test_bip85(void)
{
	unsigned char	 root[DERIVE_ROOTLEN];
	char		 pwd[BIP85_PWD_MAX];
	char		 child[BIP85_MNEMONIC_MAX];
	int		 rv = 0;

	if (derive_root(KAT_BIP85_MASTER, strlen(KAT_BIP85_MASTER), root,
	    sizeof(root)) != 0) {
		warnx("root of the BIP85 master: the call fails");
		return -1;
	}
	if (hexcheck("root of the BIP85 master", root, sizeof(root),
	    KAT_BIP85_ROOT) != 0)
		rv = -1;
	if (bip85_pwd_base64(root, sizeof(root), KAT_BIP85_SLOT, pwd,
	    sizeof(pwd)) != 0) {
		warnx("the password: the call fails");
		rv = -1;
	} else if (textcheck("the password", pwd, KAT_BIP85_PWD) != 0)
		rv = -1;
	if (bip85_bip39(root, sizeof(root), KAT_BIP85_SLOT, child,
	    sizeof(child)) != 0) {
		warnx("the child mnemonic: the call fails");
		rv = -1;
	} else if (textcheck("the child mnemonic", child,
	    KAT_BIP85_MNEMONIC) != 0)
		rv = -1;
	return rv;
}

/*
 * test_shape():
 *	The password has 21 characters, and the child mnemonic has 12
 *	words with a valid checksum (KEY-BIP85-8). The gate proves
 *	the count of the words and the checksum of the mnemonic.
 */
static int
test_shape(void)
{
	unsigned char	 root[DERIVE_ROOTLEN];
	char		 pwd[BIP85_PWD_MAX];
	char		 child[BIP85_MNEMONIC_MAX];
	char		 err[DERIVE_ERRLEN];
	size_t		 len;
	int		 rv = 0;

	if (derive_root(KAT_BIP85_MASTER, strlen(KAT_BIP85_MASTER), root,
	    sizeof(root)) != 0) {
		warnx("root of the BIP85 master: the call fails");
		return -1;
	}
	if (bip85_pwd_base64(root, sizeof(root), KAT_BIP85_SLOT, pwd,
	    sizeof(pwd)) != 0) {
		warnx("the password: the call fails");
		rv = -1;
	} else if ((len = strlen(pwd)) != BIP85_PWDLEN) {
		warnx("the password: %zu characters, and the rule is %d", len,
		    BIP85_PWDLEN);
		rv = -1;
	}
	if (bip85_bip39(root, sizeof(root), KAT_BIP85_SLOT, child,
	    sizeof(child)) != 0) {
		warnx("the child mnemonic: the call fails");
		rv = -1;
	} else {
		err[0] = '\0';
		if (derive_master_check(child, strlen(child), err,
		    sizeof(err)) != 0) {
			warnx("the child mnemonic: the gate rejects it: %s",
			    err);
			rv = -1;
		}
	}
	return rv;
}

int
main(void)
{
	int	 rv = 0;

	rv |= test_wordlist();
	rv |= test_gate();
	rv |= test_root();
	rv |= test_labels();
	rv |= test_bip85();
	rv |= test_shape();
	return rv != 0;
}
