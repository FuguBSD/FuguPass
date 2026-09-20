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

"""The generator of the share vectors (TEST-SPLIT-4).

The script writes the head of the share header and the share
vectors to the standard output. The galois module of PyPI holds the
field arithmetic and the interpolation. That module stays outside
the dependency set of this repository, and deps/ gains no entry for
it (D-15). A developer builds a throwaway environment under
scratch/, which the repository ignores, and runs the script once:

    python3 -m venv scratch/venv
    scratch/venv/bin/pip install galois
    scratch/venv/bin/python tests/vectors/generate-share.py \\
        > tests/vectors/share.h

tests/vectors/generate-pin.py appends the pin vectors and the last
line of the file.

The script writes no field arithmetic of its own. galois builds
GF(256) from the field polynomial of KEY-SHARE-2. It multiplies, it
inverts, it evaluates each polynomial of the split, and it
interpolates the reconstruction. The script copies no C code, it
reads no file of the C build, and it shares no helper with
tests/vectors/generate.py.

The coefficients stay on the hmac module of the Python standard
library (KEY-DERIVE-1, KEY-SHARE-3). That module calls _hashlib,
the extension module of CPython over OpenSSL, and the C calls the
HMAC-SHA256 of LibreSSL libcrypto. LibreSSL is a fork of OpenSSL,
so these vectors pin no independent HMAC-SHA256. They pin the label
assembly, the key choice and the message construction of
KEY-SHARE-3. The label strings come from spec/keys.md, which is
specification and not an implementation, so a misreading of
KEY-SHARE-3 shows in the vectors. A difference between this reference and the C is a
defect of one of them, and the known-answer test shows that
difference.

The script proves its own data before it prints. It reads the field
polynomial back from galois, and it proves the field against two
products of FIPS 197. It proves that every nonzero element has one
inverse. It proves that each index set reconstructs the secret, and
that a set of one element less does not. A failed proof stops the
run, and the script prints nothing.
"""

import hashlib
import hmac

import galois

# The field polynomial x^8 + x^4 + x^3 + x + 1 of GF(256), as the
# number 0x11b (KEY-SHARE-2). The field holds 256 elements.
FIELD_POLY = 0x11B
FIELD_SIZE = 0x100

# The field of the split. galois holds every product, every inverse,
# every evaluation and the interpolation of this script.
FIELD = galois.GF(2**8, irreducible_poly=FIELD_POLY)

# The coefficient label of a split, from the label table of
# spec/keys.md. The threshold and the coefficient index follow it,
# as unpadded decimal ASCII (KEY-SHARE-3).
LABEL_SHAMIR = "fugupass/v1/shamir/"

# The secret of the vectors. It is a public test constant, and it is
# not a secret. Byte 0 is 0, and byte 1 is 255, so the vectors hold
# both edges of the field.
SECRET = bytes.fromhex(
    "00ff00ff0f1e2d3c4b5a69788796a5b4"
    "c3d2e1f00123456789abcdef0fedcba9")
SECRET_BYTES = 32

# The oracle positions of the vectors, and the thresholds. The
# evaluation point of an oracle is its index, and an index counts
# from 1 (KEY-SHARE-5).
ORACLES = 5
THRESHOLDS = (1, 2, 3)

# The index set that reconstructs the secret at each threshold. A
# set holds k distinct indexes, and no set takes the first k
# indexes alone (KEY-SHARE-6).
INDEX_SETS = {
    1: (3,),
    2: (2, 5),
    3: (1, 3, 4),
}

# The pairs of the multiplication vectors. The cases are the zero
# element, the one element, the reduction of a shift that leaves the
# byte, the two products of FIPS 197, one inverse pair, and the
# square of the last element of the field.
MUL_PAIRS = (
    (0x00, 0x57),
    (0x57, 0x00),
    (0x01, 0x57),
    (0x57, 0x01),
    (0x80, 0x02),
    (0x57, 0x83),
    (0x57, 0x13),
    (0x53, 0xCA),
    (0xFF, 0xFF),
)

# The elements of the inverse vectors: the one element, the element
# that needs one reduction, two elements of the S-box example of
# FIPS 197, and the last element of the field.
INV_VALUES = (0x01, 0x02, 0x53, 0x57, 0x80, 0x1B, 0xFF)

# Two products of the standard that fixes this field (FIPS 197,
# section 4.2). The script proves the field of galois against them.
KNOWN_PRODUCTS = (
    (0x57, 0x83, 0xC1),
    (0x57, 0x13, 0xFE),
)

# The characters of one line of a hex value in the header.
HEX_WIDTH = 64

# The head of the generated header. tests/vectors/generate-pin.py
# prints the tail of it, because that script holds the last vectors.
# The guard name differs from the guard of src/share.h, because one
# test reads both files.
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
 * The known-answer vectors of the share split and of the pin secret
 * (TEST-SPLIT-4, TEST-KAT-4). Two generators made this file, and no
 * person edits it by hand. The first one writes the head of the
 * file and the share vectors:
 *
 *	python3 -m venv scratch/venv
 *	scratch/venv/bin/pip install galois
 *	scratch/venv/bin/python tests/vectors/generate-share.py \\
 *	    > tests/vectors/share.h
 *
 * The second one appends the pin vectors and the last line:
 *
 *	scratch/venv/bin/python tests/vectors/generate-pin.py \\
 *	    >> tests/vectors/share.h
 *
 * Each generator rests on a third-party reference of its part,
 * outside the dependency set of this repository (D-15). The field
 * arithmetic and the interpolation of the share vectors come from
 * the galois module of PyPI. The pin vectors come from the bcrypt
 * module of PyPI, and the block below names its version. The share
 * vectors here come from galois {galois.__version__}.
 *
 * tests/vectors/generate-share.py writes no field arithmetic of its
 * own. galois builds GF(256) from the field polynomial of
 * KEY-SHARE-2. It multiplies, it inverts, it evaluates each
 * polynomial of the split, and it interpolates the reconstruction.
 * The coefficients stay on the hmac module of the Python standard
 * library (KEY-SHARE-3). That module calls _hashlib, the extension
 * module of CPython over OpenSSL, and the C calls the HMAC-SHA256
 * of LibreSSL libcrypto. LibreSSL is a fork of OpenSSL, so these
 * vectors pin no independent HMAC-SHA256. They pin the label
 * assembly, the key choice and the message construction of
 * KEY-SHARE-3. The label strings come from spec/keys.md, which is
 * specification and not an implementation, so a misreading of
 * KEY-SHARE-3 shows here.
 *
 * Neither generator reads a file of the C build, and neither one
 * copies C code. A difference between a generator and the C is a
 * defect of one of them, and the known-answer test shows that
 * difference.
 *
 * KAT_SHARE_SECRET is a public test constant, and it is not a
 * secret. A secret and a share stand as lower-case hex, with no
 * separator and no prefix. A field element stands as one byte.
 */

#ifndef VECTORS_SHARE_H
#define VECTORS_SHARE_H
"""


def _fail(message):
    """Stop the run, and report the message on the error output."""
    raise SystemExit("generate-share.py: " + message)


def mul(left, right):
    """The product of two field elements (KEY-SHARE-2).

    galois multiplies. This function maps the two bytes into the
    field, and it maps the product back to a byte.
    """
    return int(FIELD(left) * FIELD(right))


def inverse(value):
    """The multiplicative inverse of a nonzero field element.

    galois inverts. The field holds 255 nonzero elements, and each
    one has exactly one inverse.
    """
    if value == 0:
        _fail("the field holds no inverse of zero")
    return int(FIELD(value) ** -1)


def coefficient(secret, threshold, index):
    """A_j: coefficient j of one split, at the threshold.

    The coefficient is HMAC-SHA256 with the secret as the key
    (KEY-DERIVE-1, KEY-SHARE-3). It comes from the hmac module of
    the Python standard library, and not from galois.
    """
    label = f"{LABEL_SHAMIR}{threshold}/{index}"
    return hmac.new(secret, label.encode(), hashlib.sha256).digest()


def share(secret, threshold, oracle):
    """share(S, i): the share of the oracle (KEY-SHARE-4, KEY-SHARE-5).

    Byte b takes the polynomial of byte b, at the oracle index. The
    constant term is the secret byte, and coefficient j multiplies
    the index to the power j. galois.Poly evaluates the polynomial,
    and it takes the coefficient of the highest power first.
    """
    table = [
        coefficient(secret, threshold, index)
        for index in range(1, threshold)]
    point = FIELD(oracle)
    result = bytearray(len(secret))
    for at in range(len(secret)):
        coeffs = [column[at] for column in reversed(table)]
        coeffs.append(secret[at])
        result[at] = int(galois.Poly(FIELD(coeffs))(point))
    return bytes(result)


def reconstruct(shares):
    """The secret at x = 0, from an index set of shares (KEY-SHARE-6).

    The argument maps each oracle index to its share.
    galois.lagrange_poly builds the polynomial of byte b through the
    points of the set, and the value of it at x = 0 is the byte.
    """
    indexes = sorted(shares)
    points = FIELD(indexes)
    zero = FIELD(0)
    result = bytearray(len(shares[indexes[0]]))
    for at in range(len(result)):
        values = FIELD([shares[index][at] for index in indexes])
        result[at] = int(galois.lagrange_poly(points, values)(zero))
    return bytes(result)


def _check_field():
    """Prove the field of galois, and prove every inverse.

    The first proof reads the field polynomial back, so a field of
    another polynomial stops the run. The second proof takes two
    products of FIPS 197, section 4.2.
    """
    if int(FIELD.irreducible_poly) != FIELD_POLY:
        _fail("galois built the field of another polynomial")
    for left, right, product in KNOWN_PRODUCTS:
        if mul(left, right) != product:
            _fail(f"the product of {left:#04x} and {right:#04x} is wrong")
    for value in range(1, FIELD_SIZE):
        if mul(value, inverse(value)) != 1:
            _fail(f"the inverse of {value:#04x} is wrong")


def _check_split(shares):
    """Prove each index set against the secret (KEY-SHARE-6).

    A set of k shares must give the secret, and a set of one share
    less must give another value. A threshold of 1 holds no smaller
    set, so that case proves the equality of each share and the
    secret (KEY-SHARE-7).
    """
    for threshold in THRESHOLDS:
        indexes = INDEX_SETS[threshold]
        if len(indexes) != threshold:
            _fail(f"the index set of threshold {threshold} is wrong")
        table = {index: shares[threshold][index] for index in indexes}
        if reconstruct(table) != SECRET:
            _fail(f"the index set of threshold {threshold} fails")
        if threshold == 1:
            continue
        del table[indexes[-1]]
        if reconstruct(table) == SECRET:
            _fail(f"a short set of threshold {threshold} gives the secret")
    for index in range(1, ORACLES + 1):
        if shares[1][index] != SECRET:
            _fail("a share of threshold 1 differs from the secret")


def _hex_parts(value):
    """The lower-case hex of the bytes, in parts of 32 bytes."""
    text = value.hex()
    return [text[at:at + HEX_WIDTH] for at in range(0, len(text), HEX_WIDTH)]


def _define(name, value):
    """Print one #define of a name and a plain value."""
    print(f"#define {name}\t{value}")


def _define_text(name, parts):
    """Print one #define of a C string, with one part on each line."""
    print(f"#define {name} \\")
    for at, part in enumerate(parts):
        tail = "" if at + 1 == len(parts) else " \\"
        print(f"\t\"{part}\"{tail}")


def _define_list(name, lines):
    """Print one #define of a C initializer, one element on a line."""
    print(f"#define {name} {{ \\")
    for line in lines:
        print(f"\t{line}, \\")
    print("}")


def main():
    """Prove the data of the script, and print the head and the shares."""
    _check_field()
    shares = {
        threshold: {
            index: share(SECRET, threshold, index)
            for index in range(1, ORACLES + 1)}
        for threshold in THRESHOLDS}
    _check_split(shares)

    print(HEADER)
    print("/* The field polynomial of GF(256) (KEY-SHARE-2). */")
    _define("KAT_SHARE_POLY", f"{FIELD_POLY:#05x}")
    print()
    print("/* The split secret of every vector below. */")
    _define_text("KAT_SHARE_SECRET", _hex_parts(SECRET))
    print()
    print("/* The oracle count: the indexes 1 to 5. */")
    _define("KAT_SHARE_ORACLES", ORACLES)
    print()
    print("/* Products of the field: a, b, and the product of them. */")
    _define("KAT_SHARE_MUL_COUNT", len(MUL_PAIRS))
    _define_list("KAT_SHARE_MUL", [
        f"{{ {left:#04x}, {right:#04x}, {mul(left, right):#04x} }}"
        for left, right in MUL_PAIRS])
    print()
    print("/* Inverses of the field: a, and the inverse of a. */")
    _define("KAT_SHARE_INV_COUNT", len(INV_VALUES))
    _define_list("KAT_SHARE_INV", [
        f"{{ {value:#04x}, {inverse(value):#04x} }}"
        for value in INV_VALUES])
    for threshold in THRESHOLDS:
        print()
        if threshold == 1:
            print("/*")
            print(" * The shares of threshold 1, for the oracle indexes")
            print(" * 1 to 5. Every share equals the secret")
            print(" * (KEY-SHARE-7).")
            print(" */")
        else:
            print(f"/* The shares of threshold {threshold}, for the oracle"
                  " indexes 1 to 5. */")
        _define_list(f"KAT_SHARE_K{threshold}", [
            f"\"{shares[threshold][index].hex()}\""
            for index in range(1, ORACLES + 1)])
        print()
        print("/* The index set that reconstructs the secret"
              " (KEY-SHARE-6). */")
        _define(
            f"KAT_SHARE_SET_K{threshold}",
            "{ " + ", ".join(str(index) for index in INDEX_SETS[threshold])
            + " }")


if __name__ == "__main__":
    main()
