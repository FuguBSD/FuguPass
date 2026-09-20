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
 * The known-answer vectors of the share split and of the pin secret
 * (TEST-SPLIT-4, TEST-KAT-4). Two generators made this file, and no
 * person edits it by hand. The first one writes the head of the
 * file and the share vectors:
 *
 *	python3 tests/vectors/generate-share.py > tests/vectors/share.h
 *
 * The second one appends the pin vectors and the last line:
 *
 *	scratch/venv/bin/python tests/vectors/generate-pin.py \
 *	    >> tests/vectors/share.h
 *
 * Each generator is an independent reference of its part, outside
 * the dependency set of this repository (D-15). Neither one reads a
 * file of the C build, and neither one copies C code. A difference
 * between a generator and the C is a defect of one of them, and the
 * known-answer test shows that difference.
 *
 * tests/vectors/generate-share.py holds its own field, its own
 * split, and its own reconstruction. It derives each coefficient
 * with the hmac module of the Python standard library
 * (KEY-SHARE-3). The label strings come from spec/keys.md, which is
 * specification and not an implementation.
 *
 * KAT_SHARE_SECRET is a public test constant, and it is not a
 * secret. A secret and a share stand as lower-case hex, with no
 * separator and no prefix. A field element stands as one byte.
 */

#ifndef VECTORS_SHARE_H
#define VECTORS_SHARE_H

/* The field polynomial of GF(256) (KEY-SHARE-2). */
#define KAT_SHARE_POLY	0x11b

/* The split secret of every vector below. */
#define KAT_SHARE_SECRET \
	"00ff00ff0f1e2d3c4b5a69788796a5b4c3d2e1f00123456789abcdef0fedcba9"

/* The oracle count: the indexes 1 to 5. */
#define KAT_SHARE_ORACLES	5

/* Products of the field: a, b, and the product of them. */
#define KAT_SHARE_MUL_COUNT	9
#define KAT_SHARE_MUL { \
	{ 0x00, 0x57, 0x00 }, \
	{ 0x57, 0x00, 0x00 }, \
	{ 0x01, 0x57, 0x57 }, \
	{ 0x57, 0x01, 0x57 }, \
	{ 0x80, 0x02, 0x1b }, \
	{ 0x57, 0x83, 0xc1 }, \
	{ 0x57, 0x13, 0xfe }, \
	{ 0x53, 0xca, 0x01 }, \
	{ 0xff, 0xff, 0x13 }, \
}

/* Inverses of the field: a, and the inverse of a. */
#define KAT_SHARE_INV_COUNT	7
#define KAT_SHARE_INV { \
	{ 0x01, 0x01 }, \
	{ 0x02, 0x8d }, \
	{ 0x53, 0xca }, \
	{ 0x57, 0xbf }, \
	{ 0x80, 0x83 }, \
	{ 0x1b, 0xcc }, \
	{ 0xff, 0x1c }, \
}

/*
 * The shares of threshold 1, for the oracle indexes
 * 1 to 5. Every share equals the secret
 * (KEY-SHARE-7).
 */
#define KAT_SHARE_K1 { \
	"00ff00ff0f1e2d3c4b5a69788796a5b4c3d2e1f00123456789abcdef0fedcba9", \
	"00ff00ff0f1e2d3c4b5a69788796a5b4c3d2e1f00123456789abcdef0fedcba9", \
	"00ff00ff0f1e2d3c4b5a69788796a5b4c3d2e1f00123456789abcdef0fedcba9", \
	"00ff00ff0f1e2d3c4b5a69788796a5b4c3d2e1f00123456789abcdef0fedcba9", \
	"00ff00ff0f1e2d3c4b5a69788796a5b4c3d2e1f00123456789abcdef0fedcba9", \
}

/* The index set that reconstructs the secret (KEY-SHARE-6). */
#define KAT_SHARE_SET_K1	{ 3 }

/* The shares of threshold 2, for the oracle indexes 1 to 5. */
#define KAT_SHARE_K2 { \
	"2beb14114a5d364a0a50293e25838e1b6d9520fefc1491b87ebfaf1ad66583b7", \
	"56d7283885981bd0c94ee9f4d8bcf3f1845c78ece04df6c27c83091ea6e65b95", \
	"7dc33cd6c0db00a68844a9b27aa9d85e2a1bb9e21d7a221d8b976beb7f6e138b", \
	"acaf506a000941ff5472727b39c2093e4dd5c8c8d8ff383678fb5e1646fbf0d1", \
	"87bb4484454a5a891578323d9bd72291e39209c625c8ece98fef3ce39f73b8cf", \
}

/* The index set that reconstructs the secret (KEY-SHARE-6). */
#define KAT_SHARE_SET_K2	{ 2, 5 }

/* The shares of threshold 3, for the oracle indexes 1 to 5. */
#define KAT_SHARE_K3 { \
	"de4b64d4e7c0817cb71905bbfb7b2fe373a38046564e5470be5b0cfe4df30457", \
	"044834d4058c5bdd735d4b1a8ae992baa575e9d5409571da1441d2d76b1d76e8", \
	"dafc50ffed52f79d8f1e27d9f60418ed1504886317f860cd23b113c62903b916", \
	"b2b7b54632f5157a7a66e86d64a62b1e7b88f4e912ff757c4920ddf76a0b4a85", \
	"6c03d16dda2bb93a862584ae184ba149cbf9955f4592646b7ed01ce62815857b", \
}

/* The index set that reconstructs the secret (KEY-SHARE-6). */
#define KAT_SHARE_SET_K3	{ 1, 3, 4 }

/*
 * The pin vectors (KEY-PIN-3). tests/vectors/generate-pin.py
 * made this part of the file, and no person edits it by
 * hand:
 *
 *	python3 -m venv scratch/venv
 *	scratch/venv/bin/pip install bcrypt
 *	scratch/venv/bin/python tests/vectors/generate-pin.py \
 *	    >> tests/vectors/share.h
 *
 * The Python standard library holds no bcrypt_pbkdf(3), so
 * the generator takes the bcrypt module 5.0.0 of PyPI.
 * That module stays outside the dependency set of this
 * repository, and the repository ignores scratch/, so no
 * part of it enters the checkout (D-15).
 *
 * The two salts come from the chain of KAT_TEST_PIN_SALT
 * and KAT_TEST_CANARY_PIN_SALT of tests/vectors/derive.h:
 * root, then the device factor of the machine name, then
 * the pin salt of the record. The regress test derives each
 * salt from root, so a difference between the two headers
 * fails the test.
 */

/* The passphrase of the vectors: a public test constant. */
#define KAT_PIN_PASSPHRASE \
	"fugupass test passphrase"

/*
 * The round count of the vectors. It is small, so the test
 * stays fast.
 */
#define KAT_PIN_ROUNDS	8

/* pin_ei over KAT_TEST_PIN_SALT, with 32 bytes out. */
#define KAT_PIN_ENTRY \
	"c4b46e2904681713043ff3de03508413d5b4d4cc68d8b29139396a7f2bb8f4cf"

/*
 * pin_ei over KAT_TEST_CANARY_PIN_SALT. Two salts give two
 * values.
 */
#define KAT_PIN_CANARY \
	"09b90c2981f3ba8ac207189cd4c4c35d4451b6b7bafac03c7dc050025e70705c"

#endif /* VECTORS_SHARE_H */
