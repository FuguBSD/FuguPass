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
 * The known-answer vectors of the derivation tree (TEST-KAT-1,
 * TEST-KAT-4). tests/vectors/generate.py made this file, and no
 * person edits it by hand:
 *
 *	python3 tests/vectors/generate.py > tests/vectors/derive.h
 *
 * The generator is a second implementation of the tree, and it takes
 * the Python standard library only. Two masters give the values.
 *
 * KAT_TEST_* comes from the fixed test master, a public constant of
 * the tests. BIP39 fixes root, and it publishes the seed of this
 * master as a test vector. The label table of spec/keys.md fixes the
 * two labels, and KEY-DERIVE-1 fixes f.
 *
 * KAT_BIP85_* comes from the master of the test vectors of BIP85.
 * That document prints the password and the child mnemonic beside
 * the path of each one, so a reader compares the two values below
 * with the document by eye. The document names the master as this
 * extended private key:
 *
 *	xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2u
 *	Yo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb
 *
 * The 12 words of KAT_BIP85_MASTER give that key, and the generator
 * proves them against it at each run.
 *
 * A derived key stands as lower-case hex, with no separator and no
 * prefix. A master, a password and a mnemonic stand as text.
 */

#ifndef VECTORS_DERIVE_H
#define VECTORS_DERIVE_H

/* The fixed test master: 12 words of the BIP39 English list. */
#define KAT_TEST_MASTER \
	"abandon abandon abandon abandon abandon abandon " \
	"abandon abandon abandon abandon abandon about"

/* root of the test master: its BIP39 seed, with no passphrase. */
#define KAT_TEST_ROOT \
	"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1" \
	"9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"

/* The slot index of the entry key below. */
#define KAT_TEST_SLOT	17

/* The entry key of that slot: f(root, "fugupass/v1/entry-key17"). */
#define KAT_TEST_ENTRY_KEY \
	"ae0d5c3e7ed8def43f4d6d588236e9cc794562d13b321bcaeb64fe27912fd221"

/* The plate check value: f(root, "fugupass/v1/plate-check"). */
#define KAT_TEST_PLATE_CHECK \
	"5ff12178fc2f249204cb9971f351fce503899de06d02722eaa99b92fca9860be"

/* The 12 words of the master of the BIP85 test vectors. */
#define KAT_BIP85_MASTER \
	"install scatter logic circle pencil average fall " \
	"shoe quantum disease suspect usage"

/* root of the BIP85 master: its BIP39 seed, with no passphrase. */
#define KAT_BIP85_ROOT \
	"37483472a6af7fd107fb5f5aaaa7bddc89690353369229771c32812f711207c8" \
	"7398a8d44cfc763a8185ff346272e8f1455170decae712598f5990c1207d2f88"

/* The BIP85 index of the two vectors below. */
#define KAT_BIP85_SLOT	0

/* PWD BASE64, at m/83696968'/707764'/21'/0'. */
#define KAT_BIP85_PWD \
	"dKLoepugzdVJvdL56ogNV"

/* BIP39, at m/83696968'/39'/0'/12'/0'. */
#define KAT_BIP85_MNEMONIC \
	"girl mad pet galaxy egg matter matrix prison " \
	"refuse sense ordinary nose"

#endif /* VECTORS_DERIVE_H */
