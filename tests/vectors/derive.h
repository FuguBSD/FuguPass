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
 * master as a test vector. The label table of spec/keys.md fixes
 * every label, and KEY-DERIVE-1 fixes f. These vectors cover each of
 * the ten labels of that table.
 *
 * KAT_TEST_MASK and KAT_TEST_CANARY_MASK are public test constants,
 * and they are not secrets. A real mask is the 32-byte answer of an
 * oracle, and the client stores no mask (KEY-MASK-1, KEY-MASK-2). A
 * test needs a fixed input, so these bytes stand in place of an
 * answer.
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

/* The machine name of the device factor below (KEY-DEVICE-3). */
#define KAT_TEST_MACHINE \
	"laptop-1"

/* The device factor: f(root, "fugupass/v1/device-factorlaptop-1"). */
#define KAT_TEST_DEVICE_FACTOR \
	"0322c00e1c113467fd854c1daa9ee410005af9212a95e9de7fbdbf0fec294d90"

/* The oracle index of the record vectors below. */
#define KAT_TEST_ORACLE	2

/* The client key material: f(X, "fugupass/v1/client-key2/17"). */
#define KAT_TEST_CLIENT_MATERIAL \
	"55a5f54fcb0601088a70f40cc468e49cf678ae67e51d64d658cc91598270030e"

/* The client key of that material: (t mod (q - 1)) + 1. */
#define KAT_TEST_CLIENT_KEY \
	"55a5f54fcb0601088a70f40cc468e49cf678ae67e51d64d658cc91598270030f"

/*
 * The canary client key: the same reduction of
 * f(X, "fugupass/v1/client-key2/canary").
 */
#define KAT_TEST_CANARY_CLIENT_KEY \
	"cd972b1facf2791fb937f51fd92c1520d6e1022d3e01c423147c97dc9b43a308"

/* A public test material of 32 bytes 0xff, above q - 1. */
#define KAT_TEST_EDGE_MATERIAL \
	"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

/* The client key of that material, through the modulus. */
#define KAT_TEST_EDGE_CLIENT_KEY \
	"000000000000000000000000000000014551231950b75fc4402da1732fc9bec0"

/* The pin salt: f(X, "fugupass/v1/pin-salt2/17"). */
#define KAT_TEST_PIN_SALT \
	"e9f96c9c62856e3981a3b66d46f1bf315118f7bec729a9ea518216c2fa92b5b4"

/* The canary pin salt: f(X, "fugupass/v1/pin-salt2/canary"). */
#define KAT_TEST_CANARY_PIN_SALT \
	"6d7212dbaadb1e1b32e648c462585da4aead815ce6999d5d738f2a5f23c47e57"

/* A public test mask of the record, in place of an answer. */
#define KAT_TEST_MASK \
	"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

/* A public test mask of the canary record. */
#define KAT_TEST_CANARY_MASK \
	"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"

/* The wrap key: f(mask, "fugupass/v1/wrap2/17"). */
#define KAT_TEST_WRAP_KEY \
	"05b24241ad0e455eba706e6abdbc60cc8adc7ac65d7b02c8faf48628732fa133"

/* The index key: f(root, "fugupass/v1/index-key"). */
#define KAT_TEST_INDEX_KEY \
	"f18f73d84543cfea0c75a8f53cb4acee251fec42aaa4fcd6dd1e17aac4efbfea"

/* The index wrap key: f(canary mask, "fugupass/v1/wrap-index2"). */
#define KAT_TEST_INDEX_WRAP_KEY \
	"d59f0b86ec2e4d158fd74c1bb9327085b230145efe7d793d8dba3e18e26a20ff"

/*
 * The canary check seal key:
 * f(canary mask, "fugupass/v1/canary-check2").
 */
#define KAT_TEST_CANARY_CHECK_KEY \
	"8607f28ef13aa9cc35a21fae39584fe9161d4ca3e26b4ab55030114db7a56604"

/*
 * The coefficients of the split of KAT_TEST_ENTRY_KEY
 * (KEY-SHARE-3). A name carries the threshold and the
 * coefficient index, as the label does:
 * KAT_TEST_COEFF_K3_1 comes from
 * f(K_e, "fugupass/v1/shamir/3/1").
 */
#define KAT_TEST_COEFF_K2_1 \
	"f61351bf9ccc3b397d96842525d04dbacc6380cb58e140808dbdc3fac4a9b712"

#define KAT_TEST_COEFF_K3_1 \
	"27e711aa98fae8bd754b7ee2cca758ed3f76068df42ee4e641ed8a3606c5eb10"

#define KAT_TEST_COEFF_K3_2 \
	"1b985305180c53e64cfc34877181aef1fc96b840e13021fe5903f83865751548"

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
