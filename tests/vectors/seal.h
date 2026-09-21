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
 * The known-answer vectors of the seal (TEST-KAT-2). One generator
 * made this file, and no person edits it by hand:
 *
 *	python3 -m venv scratch/venv
 *	scratch/venv/bin/pip install cryptography
 *	scratch/venv/bin/python tests/vectors/generate-seal.py \
 *	    > tests/vectors/seal.h
 *
 * The generator rests on a third-party reference of the AEAD,
 * outside the dependency set of this repository (D-15). The
 * reference is the cryptography module of PyPI, and the rows here
 * come from version 50.0.1. That module calls
 * OpenSSL, and the C calls the AEAD of LibreSSL libcrypto.
 * LibreSSL is a fork of OpenSSL, so these rows pin no independent
 * ChaCha20-Poly1305. They pin the layout, the additional data, the
 * key length and the nonce length of VAULT-SEAL, which
 * spec/vault.md states. The generator proves the module against
 * the AEAD vector of RFC 8439, section 2.8.2, before it prints, so
 * that vector pins the primitive itself. The additional data of
 * that vector is 12 bytes, and the seal fixes the additional data
 * at the one version byte (VAULT-SEAL-5), so no row below holds
 * it.
 *
 * A seal draws a fresh nonce for each write (VAULT-SEAL-3), so no
 * row pins the output of seal_seal(). Each row pins the nonce as
 * an input. The test builds the sealed value from the row, and it
 * opens that value.
 *
 * The generator reads no file of the C build, and it copies no C
 * code. A difference between the generator and the C is a defect
 * of one of them, and the known-answer test shows that difference.
 *
 * KAT_SEAL_KEY is a public test constant, and it is not a secret.
 * Every value stands as lower-case hex, with no separator and no
 * prefix.
 */

#ifndef VECTORS_SEAL_H
#define VECTORS_SEAL_H

/* The version byte of every row (VAULT-SEAL-1). */
#define KAT_SEAL_VERSION	0x01

/* The seal key of every row: a public test constant. */
#define KAT_SEAL_KEY \
	"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

/*
 * The rows: the nonce, the plaintext, and the body. The body
 * is the ciphertext and the 16-byte tag. One plaintext is the
 * raw check value of a canary check seal, and the others are
 * line format (VAULT-FORMAT-1). The plaintexts hold 9, 32, 64 and 65
 * bytes, so two rows stand on the two sides of the 64-byte
 * block of ChaCha20.
 */
#define KAT_SEAL_COUNT	4
#define KAT_SEAL_VECTORS { \
	{ \
		"070000004041424344454647", \
		"736c6f743a2031370a", \
		"3a801e562b615df793aaadb6302ad70a40b68a1c89f6034f" \
		"67" \
	}, \
	{ \
		"000000000000000000000000", \
		"a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7" \
		"b8b9babbbcbdbebf", \
		"b819e09209430076bbc8f6ca03eee088480041465518edeb" \
		"544146a99688cbe3e928cb8b24895da2b5c7311633d34ad7" \
	}, \
	{ \
		"ffffffffffffffffffffffff", \
		"63616e6469646174652d70617373776f72643a207468652d" \
		"746573742d76616c75652d6f662d7468652d7365616c2d76" \
		"6563746f72730a736c6f743a2031370a", \
		"a2c2314109c1da64b187bf322428c4ed108c7b393ee596c8" \
		"c2213d06ae98f4cf1495afce84489e94e4ef6b8e770a4d2b" \
		"5079e29456dcfee2a3fa9122e7bda2afb723c6175c431c89" \
		"24c01de67a4edb2c" \
	}, \
	{ \
		"0102030405060708090a0b0c", \
		"63616e6469646174652d70617373776f72643a207468652d" \
		"746573742d76616c7565732d6f662d7468652d7365616c2d" \
		"766563746f72730a736c6f743a2031370a", \
		"07e92a0e6036c5c72dc43526a7d2fb61cc98a9be32e1da66" \
		"0fb8dfbd6b998e596ddefa85f7540c8e2fd367ab03dbf91d" \
		"b122809e14434ff1c218586c2a1c34e4e518042a6f840a6a" \
		"8fb7204f0b92a48f41" \
	}, \
}

/*
 * The body of the first row, under a version byte that the
 * tool does not read (VAULT-SEAL-1). The tag of it is right,
 * so the open must fail on the version byte alone.
 */
#define KAT_SEAL_OTHER	0x02
#define KAT_SEAL_OTHER_BODY \
	"3a801e562b615df793ae6f7a7317ed9360573bf14cbbaa96a1"

#endif /* VECTORS_SEAL_H */
