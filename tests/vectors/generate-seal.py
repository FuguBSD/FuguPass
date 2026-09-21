#!/usr/bin/env python3
#
# Copyright (c) 2026 Dick Olsson <hi@senzilla.io>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""The generator of the seal vectors (TEST-KAT-2).

The script writes the whole seal header to the standard output. The
cryptography module of PyPI holds the AEAD. That module stays
outside the dependency set of this repository, and deps/ gains no
entry for it (D-15). A developer builds a throwaway environment
under scratch/, which the repository ignores, and runs the script
once:

    python3 -m venv scratch/venv
    scratch/venv/bin/pip install cryptography
    scratch/venv/bin/python tests/vectors/generate-seal.py \\
        > tests/vectors/seal.h

A seal draws a fresh nonce for each write (VAULT-SEAL-3), so no
vector can pin the output of seal_seal(). Each row here pins the
nonce as an input: the key, the nonce, the version byte, the
plaintext, and the body. The body is the ciphertext and the 16-byte
tag. The test builds the sealed value from the row and opens it, so
the rows gate seal_open() and the layout of VAULT-SEAL.

The rows take the additional authenticated data of the seal: the
one version byte (VAULT-SEAL-5). The AEAD vector of RFC 8439,
section 2.8.2, takes 12 bytes of additional data, so no row can
hold that vector. The script proves the module against it instead,
before the script prints.

The cryptography module calls OpenSSL, and the C calls the AEAD of
LibreSSL libcrypto. LibreSSL is a fork of OpenSSL, so these rows
pin no independent ChaCha20-Poly1305. They pin the layout, the
additional data, the key length and the nonce length of
VAULT-SEAL, which spec/vault.md states. The vector of RFC 8439
pins the primitive itself.

The script reads no file of the C build, and it copies no C code. A
difference between the script and the C is a defect of one of them,
and the known-answer test shows that difference.

The script also prints one body under a version byte that the
tool does not read. The tag of that body is right, so it proves
the version gate of the open, and no other gate.

The script proves its own data before it prints. It proves the
module against RFC 8439. It proves that each body opens, and that a
changed body, a changed nonce, a changed version byte and a changed
key each fail the open. It proves the length of each field, and it
proves that the rows stand on both sides of the 64-byte block of
ChaCha20. A failed proof stops the run, and the script prints
nothing.
"""

import cryptography
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# The seal version byte (VAULT-SEAL-1). It is the additional
# authenticated data of every row (VAULT-SEAL-5).
VERSION = 0x01

# A version byte that the tool does not read (VAULT-SEAL-1). One
# body of the header takes it, so a test can prove the version gate
# with a body whose tag is right.
OTHER_VERSION = 0x02

# The lengths of the layout (VAULT-SEAL-1).
KEY_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16

# The block of ChaCha20, in bytes. Two rows stand on the two sides
# of it, so a keystream that stops at the block shows here.
BLOCK = 64

# The key of every row. It is a public test constant, and it is not
# a secret.
KEY = bytes(range(KEY_LEN))

# The plaintext of the canary check seal: the raw 32-byte check
# value, and no line format (VAULT-FORMAT-1).
CANARY_CHECK = bytes(range(0xA0, 0xA0 + 32))

# Two plaintexts of a slot file, of 64 and of 65 bytes
# (VAULT-FORMAT-1, VAULT-FORMAT-4). The value of the secret field
# is a public test constant, and it is not a secret.
SLOT_BLOCK = (
    b"candidate-password: the-test-value-of-the-seal-vectors\n"
    b"slot: 17\n")
SLOT_OVER = (
    b"candidate-password: the-test-values-of-the-seal-vectors\n"
    b"slot: 17\n")

# The rows: the nonce and the plaintext of each one. The first
# nonce comes from RFC 8439, section 2.8.2. The second and the
# third are the two edges of the field, because the first four
# bytes of a nonce enter the block counter of ChaCha20.
VECTORS = (
    (bytes.fromhex("070000004041424344454647"), b"slot: 17\n"),
    (bytes.fromhex("000000000000000000000000"), CANARY_CHECK),
    (bytes.fromhex("ffffffffffffffffffffffff"), SLOT_BLOCK),
    (bytes.fromhex("0102030405060708090a0b0c"), SLOT_OVER),
)

# The AEAD vector of RFC 8439, section 2.8.2. The body is the
# ciphertext of the section, and then the tag of it.
RFC_KEY = bytes.fromhex(
    "808182838485868788898a8b8c8d8e8f"
    "909192939495969798999a9b9c9d9e9f")
RFC_NONCE = bytes.fromhex("070000004041424344454647")
RFC_AAD = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
RFC_PLAIN = (
    b"Ladies and Gentlemen of the class of '99: If I could offer "
    b"you only one tip for the future, sunscreen would be it.")
RFC_BODY = bytes.fromhex(
    "d31a8d34648e60db7b86afbc53ef7ec2"
    "a4aded51296e08fea9e2b5a736ee62d6"
    "3dbea45e8ca9671282fafb69da92728b"
    "1a71de0a9e060b2905d6a5b67ecd3b36"
    "92ddbd7f2d778b8c9803aee328091b58"
    "fab324e4fad675945585808b4831d7bc"
    "3ff4def08e4b7a9de576d26586cec64b"
    "6116"
    "1ae10b594f09e26a7e902ecbd0600691")

# The characters of one line of a hex value in the header. A value
# of a row stands two tabs deep, so a shorter line holds the file
# inside 80 columns.
HEX_WIDTH = 64
ROW_WIDTH = 48

# The head of the generated header.
HEADER = f"""/*
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
 *\tpython3 -m venv scratch/venv
 *\tscratch/venv/bin/pip install cryptography
 *\tscratch/venv/bin/python tests/vectors/generate-seal.py \\
 *\t    > tests/vectors/seal.h
 *
 * The generator rests on a third-party reference of the AEAD,
 * outside the dependency set of this repository (D-15). The
 * reference is the cryptography module of PyPI, and the rows here
 * come from version {cryptography.__version__}. That module calls
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
"""


def _fail(message):
    """Stop the run, and report the message on the error output."""
    raise SystemExit("generate-seal.py: " + message)


def seal(nonce, plain, version=VERSION, key=KEY):
    """The body of one seal: the ciphertext, and then the tag.

    The additional data is the one version byte (VAULT-SEAL-5).
    """
    return ChaCha20Poly1305(key).encrypt(nonce, plain, bytes([version]))


def opens(nonce, body, version=VERSION, key=KEY):
    """True when the body opens under the key, the nonce and the version."""
    try:
        ChaCha20Poly1305(key).decrypt(nonce, body, bytes([version]))
    except InvalidTag:
        return False
    return True


def _check_reference():
    """Prove the module against RFC 8439, section 2.8.2."""
    if len(RFC_PLAIN) != 114:
        _fail("the plaintext of RFC 8439 does not hold 114 bytes")
    body = ChaCha20Poly1305(RFC_KEY).encrypt(RFC_NONCE, RFC_PLAIN, RFC_AAD)
    if body != RFC_BODY:
        _fail("the module fails the vector of RFC 8439")


def _check_other(other):
    """Prove the body of the version byte that no tool reads."""
    nonce, plain = VECTORS[0]
    if not opens(nonce, other, version=OTHER_VERSION):
        _fail("the body of the other version does not open")
    if opens(nonce, other):
        _fail("the body of the other version opens under version 1")
    if len(other) != len(plain) + TAG_LEN:
        _fail("the body of the other version holds the wrong count")


def _check_rows(rows):
    """Prove every row before the script prints it."""
    if len(KEY) != KEY_LEN:
        _fail(f"the key does not hold {KEY_LEN} bytes")
    for nonce, plain, body in rows:
        if len(nonce) != NONCE_LEN:
            _fail(f"a nonce does not hold {NONCE_LEN} bytes")
        if len(plain) == 0:
            _fail("a plaintext holds no byte")
        if len(body) != len(plain) + TAG_LEN:
            _fail("a body is not the ciphertext and the tag")
        if not opens(nonce, body):
            _fail("a body does not open")
        if opens(nonce, body, version=VERSION + 1):
            _fail("a body opens under another version byte")
        if opens(nonce, body, key=_flip(KEY)):
            _fail("a body opens under another key")
        if opens(_flip(nonce), body):
            _fail("a body opens under another nonce")
        if opens(nonce, _flip(body)):
            _fail("a changed body opens")
    lengths = {len(plain) for _, plain, _ in rows}
    if not {BLOCK, BLOCK + 1} <= lengths:
        _fail(f"no two rows stand on the sides of {BLOCK} bytes")
    if len({nonce for nonce, _, _ in rows}) != len(rows):
        _fail("two rows hold one nonce")


def _flip(value):
    """The bytes, with the low bit of the first one exchanged."""
    changed = bytearray(value)
    changed[0] ^= 0x01
    return bytes(changed)


def _hex_parts(value, width=HEX_WIDTH):
    """The lower-case hex of the bytes, in parts of width characters."""
    text = value.hex()
    return [text[at:at + width] for at in range(0, len(text), width)]


def _define(name, value):
    """Print one #define of a name and a plain value."""
    print(f"#define {name}\t{value}")


def _define_text(name, parts):
    """Print one #define of a C string, with one part on each line."""
    print(f"#define {name} \\")
    for at, part in enumerate(parts):
        tail = "" if at + 1 == len(parts) else " \\"
        print(f"\t\"{part}\"{tail}")


def _print_value(value, tail):
    """Print one hex value of a row, with the tail after the last part."""
    parts = _hex_parts(value, ROW_WIDTH)
    for at, part in enumerate(parts):
        end = tail if at + 1 == len(parts) else ""
        print(f"\t\t\"{part}\"{end} \\")


def _define_rows(name, rows):
    """Print the #define of the table, one block for each row."""
    print(f"#define {name} {{ \\")
    for nonce, plain, body in rows:
        print("\t{ \\")
        print(f"\t\t\"{nonce.hex()}\", \\")
        _print_value(plain, ",")
        _print_value(body, "")
        print("\t}, \\")
    print("}")


def main():
    """Prove the data of the script, and print the seal vectors."""
    _check_reference()
    rows = tuple(
        (nonce, plain, seal(nonce, plain)) for nonce, plain in VECTORS)
    other = seal(VECTORS[0][0], VECTORS[0][1], version=OTHER_VERSION)
    _check_rows(rows)
    _check_other(other)
    sizes = [str(len(plain)) for _, plain, _ in rows]
    lengths = ", ".join(sizes[:-1]) + " and " + sizes[-1]

    print(HEADER)
    print("/* The version byte of every row (VAULT-SEAL-1). */")
    _define("KAT_SEAL_VERSION", f"{VERSION:#04x}")
    print()
    print("/* The seal key of every row: a public test constant. */")
    _define_text("KAT_SEAL_KEY", _hex_parts(KEY))
    print()
    print("/*")
    print(" * The rows: the nonce, the plaintext, and the body. The body")
    print(" * is the ciphertext and the 16-byte tag. One plaintext is the")
    print(" * raw check value of a canary check seal, and the others are")
    print(f" * line format (VAULT-FORMAT-1). The plaintexts hold {lengths}")
    print(f" * bytes, so two rows stand on the two sides of the {BLOCK}-byte")
    print(" * block of ChaCha20.")
    print(" */")
    _define("KAT_SEAL_COUNT", len(rows))
    _define_rows("KAT_SEAL_VECTORS", rows)
    print()
    print("/*")
    print(" * The body of the first row, under a version byte that the")
    print(" * tool does not read (VAULT-SEAL-1). The tag of it is right,")
    print(" * so the open must fail on the version byte alone.")
    print(" */")
    _define("KAT_SEAL_OTHER", f"{OTHER_VERSION:#04x}")
    _define_text("KAT_SEAL_OTHER_BODY", _hex_parts(other))
    print()
    print("#endif /* VECTORS_SEAL_H */")


if __name__ == "__main__":
    main()
