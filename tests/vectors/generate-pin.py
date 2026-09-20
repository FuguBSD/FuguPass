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

"""The generator of the pin vectors (KEY-PIN-3, TEST-KAT-4).

The script appends the pin vectors and the last line of the share
header to the standard output. The Python standard library holds no
bcrypt_pbkdf(3), so the script takes the bcrypt module of PyPI. That
module is outside the dependency set of this repository, and deps/
gains no entry for it (D-15). A developer builds a throwaway
environment under scratch/, which the repository ignores, and runs
the script once:

    python3 -m venv scratch/venv
    scratch/venv/bin/pip install bcrypt
    scratch/venv/bin/python tests/vectors/generate-pin.py \\
        >> tests/vectors/share.h

bcrypt.kdf() takes the password, then the salt, then the byte count,
then the round count. bcrypt_pbkdf(3) of libutil takes the same
order, and KEY-PIN-3 states it: the passphrase, then salt_ei, then
the rounds, with 32 bytes out.

The script holds its own chain from the test master to the two pin
salts: root, then the device factor of the machine name, then the
pin salt of the record. It reads no file of the C build, and it
copies no C code. The chain gives the same two salts as
KAT_TEST_PIN_SALT and KAT_TEST_CANARY_PIN_SALT of
tests/vectors/derive.h.

The script proves its own data before it prints. It proves that the
two salts give two pin secrets, and that the password and the salt
do not exchange places. A failed proof stops the run, and the
script prints nothing.
"""

import hashlib
import hmac
import warnings

import bcrypt

# The BIP39 seed of a mnemonic: PBKDF2-HMAC-SHA512 with 2048 rounds
# and 64 bytes out, over the fixed salt of BIP39 and an empty
# passphrase (KEY-MASTER-4).
BIP39_ROUNDS = 2048
BIP39_SALT = b"mnemonic"
ROOT_LEN = 64

# The two labels of this script, from the label table of
# spec/keys.md (KEY-DEVICE-1, KEY-PIN-2).
LABEL_DEVICE_FACTOR = "fugupass/v1/device-factor"
LABEL_PIN_SALT = "fugupass/v1/pin-salt"

# The fixed test master, the machine name, the oracle index and the
# slot index of the vectors. tests/vectors/generate.py holds the
# same constants, and tests/vectors/derive.h prints the salts of
# this chain.
TEST_MASTER = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about")
TEST_MACHINE = "laptop-1"
TEST_ORACLE = 2
TEST_SLOT = 17
CANARY = "canary"

# The passphrase of the vectors. It is a public test constant, and
# it is not a secret.
TEST_PASSPHRASE = "fugupass test passphrase"

# The round count of the vectors, and the output length. The count
# is far below a safe count, and the vectors take it so that the
# test stays fast. The config file records the count of a vault
# (KEY-PIN-5). The output length is the one that KEY-PIN-3 fixes.
TEST_ROUNDS = 8
PIN_LEN = 32

# The characters of one line of a hex value in the header, and the
# last line of the header. The guard name comes from
# tests/vectors/generate-share.py, which opens the guard.
HEX_WIDTH = 64
FOOTER = "#endif /* VECTORS_SHARE_H */"


def _fail(message):
    """Stop the run, and report the message on the error output."""
    raise SystemExit("generate-pin.py: " + message)


def _f(key, label):
    """f(key, label): HMAC-SHA256, with 32 bytes out (KEY-DERIVE-1)."""
    return hmac.new(key, label.encode(), hashlib.sha256).digest()


def root_of(mnemonic):
    """root: the BIP39 seed of the mnemonic, with no passphrase."""
    return hashlib.pbkdf2_hmac(
        "sha512", mnemonic.encode(), BIP39_SALT, BIP39_ROUNDS, ROOT_LEN)


def pin_salt(root, suffix):
    """salt_ei of one record, through the device factor.

    The factor comes from root and the machine name (KEY-DEVICE-1),
    and the salt comes from the factor and the suffix (KEY-PIN-2).
    """
    factor = _f(root, LABEL_DEVICE_FACTOR + TEST_MACHINE)
    return _f(factor, LABEL_PIN_SALT + suffix)


def pin_secret(passphrase, salt):
    """pin_ei = bcrypt_pbkdf(passphrase, salt_ei, rounds) (KEY-PIN-3).

    bcrypt.kdf() warns below 50 rounds, and the vectors take 8
    rounds on purpose, so the call accepts the small count without
    the warning.
    """
    return bcrypt.kdf(
        passphrase.encode(), salt, PIN_LEN, TEST_ROUNDS,
        ignore_few_rounds=True)


def _check(entry_salt, entry_pin, canary_pin):
    """Prove the pin secrets before the script prints them."""
    if len(entry_pin) != PIN_LEN or len(canary_pin) != PIN_LEN:
        _fail("a pin secret does not hold 32 bytes")
    if entry_pin == canary_pin:
        _fail("the two salts give one pin secret")
    if entry_pin != pin_secret(TEST_PASSPHRASE, entry_salt):
        _fail("the function gives two results for one input")
    exchanged = bcrypt.kdf(
        entry_salt, TEST_PASSPHRASE.encode(), PIN_LEN, TEST_ROUNDS,
        ignore_few_rounds=True)
    if exchanged == entry_pin:
        _fail("the password and the salt exchange places")


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


def main():
    """Prove the data of the script, and print the pin vectors."""
    warnings.simplefilter("error")
    root = root_of(TEST_MASTER)
    entry_salt = pin_salt(root, f"{TEST_ORACLE}/{TEST_SLOT}")
    canary_salt = pin_salt(root, f"{TEST_ORACLE}/{CANARY}")
    entry_pin = pin_secret(TEST_PASSPHRASE, entry_salt)
    canary_pin = pin_secret(TEST_PASSPHRASE, canary_salt)
    _check(entry_salt, entry_pin, canary_pin)

    print()
    print("/*")
    print(" * The pin vectors (KEY-PIN-3). tests/vectors/generate-pin.py")
    print(" * made this part of the file, and no person edits it by")
    print(" * hand:")
    print(" *")
    print(" *\tpython3 -m venv scratch/venv")
    print(" *\tscratch/venv/bin/pip install bcrypt")
    print(" *\tscratch/venv/bin/python tests/vectors/generate-pin.py \\")
    print(" *\t    >> tests/vectors/share.h")
    print(" *")
    print(" * The Python standard library holds no bcrypt_pbkdf(3), so")
    print(" * the generator takes the bcrypt module"
          f" {bcrypt.__version__} of PyPI.")
    print(" * That module stays outside the dependency set of this")
    print(" * repository, and the repository ignores scratch/, so no")
    print(" * part of it enters the checkout (D-15).")
    print(" *")
    print(" * The two salts come from the chain of KAT_TEST_PIN_SALT")
    print(" * and KAT_TEST_CANARY_PIN_SALT of tests/vectors/derive.h:")
    print(" * root, then the device factor of the machine name, then")
    print(" * the pin salt of the record. The regress test derives each")
    print(" * salt from root, so a difference between the two headers")
    print(" * fails the test.")
    print(" */")
    print()
    print("/* The passphrase of the vectors: a public test constant. */")
    _define_text("KAT_PIN_PASSPHRASE", [TEST_PASSPHRASE])
    print()
    print("/*")
    print(" * The round count of the vectors. It is small, so the test")
    print(" * stays fast.")
    print(" */")
    _define("KAT_PIN_ROUNDS", TEST_ROUNDS)
    print()
    print("/* pin_ei over KAT_TEST_PIN_SALT, with 32 bytes out. */")
    _define_text("KAT_PIN_ENTRY", _hex_parts(entry_pin))
    print()
    print("/*")
    print(" * pin_ei over KAT_TEST_CANARY_PIN_SALT. Two salts give two")
    print(" * values.")
    print(" */")
    _define_text("KAT_PIN_CANARY", _hex_parts(canary_pin))
    print()
    print(FOOTER)


if __name__ == "__main__":
    main()
