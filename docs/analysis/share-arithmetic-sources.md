# The source evaluation of the share arithmetic

|         |                                                                       |
| ------- | --------------------------------------------------------------------- |
| Status  | Record. It holds the source evaluation of TEST-SPLIT-5.               |
| Covers  | The GF(256) arithmetic of the split, and the sources of the vectors.  |
| Decides | Nothing. D-15 decides, and this record states the reason of the pick. |

## The question

D-15 closes the primitive set of FuguPass. The AEAD, the curve, the hash and the
passphrase KDF come from LibreSSL `libcrypto`, from `libsecp256k1`, and from
`bcrypt_pbkdf(3)` of `libutil`. That set holds no share arithmetic. KEY-SHARE-2
needs multiplication and division in GF(256), with the field polynomial
`x^8 + x^4 + x^3 + x + 1`.

D-15 opens two paths. The first path imports a vetted implementation under the
ISC licence, or under a BSD licence. The second path writes the arithmetic in
the tree. The second path holds two conditions: the specification states the
full arithmetic, and known-answer vectors from an independent reference pin the
outputs. This record states the candidates of the first path, and the reason of
the pick.

## The candidates

Each candidate below is a possible import: it answers which implementation this
repository ships. Which reference pins the outputs is a separate question, and
"The sources of the vectors" answers it.

| Candidate                 | Form                 | Licence | Timing of the arithmetic                     |
| ------------------------- | -------------------- | ------- | -------------------------------------------- |
| libgfshare                | C library            | MIT     | Log and exp tables, with a secret index      |
| sss, of Daan Sprenkels    | C library            | MIT     | Branch-free, and with no table               |
| ssss, of B. Poettering    | Command-line tool    | GPL     | Multiprecision arithmetic, through `libgmp`  |
| The in-tree `src/share.c` | C of this repository | ISC     | Shift and reduce, branch-free, with no table |

### libgfshare

libgfshare splits a secret over GF(2^8). Daniel Silverstone holds the copyright
of it, and the library carries the MIT licence. It multiplies through a
logarithm table and an exponent table, as in
`share_byte = exps[ilog + logs[share_byte]];`. A table index there comes from a
secret byte, so the memory read pattern follows the secret. The licence also
falls outside the set that D-15 names.

### sss, of Daan Sprenkels

This library splits a key over GF(256) in C, and its arithmetic is branch-free
and free of tables. The project states side-channel resistance as a goal, and it
names the tables of libgfshare as the counter-example. The library carries the
MIT licence, which falls outside the set that D-15 names. The library also holds
a complete key-sharing scheme, with its own share format. FuguPass needs the
byte-wise arithmetic of KEY-SHARE-2 alone, under its own share layout.

### ssss, of B. Poettering

ssss is a command-line tool, and not a library. It carries the GPL, and it links
the GNU `libgmp` multiprecision library. The licence falls outside the set that
D-15 names, and a GPL import changes the licence of this repository. The tool
form also gives no function to call.

## The timing behavior

A table index that comes from a secret byte moves the memory read pattern with
that byte. An attacker on the same machine can read that pattern through the
cache. libgfshare multiplies that way, so an import of it must add a
constant-time replacement of the table.

The picked arithmetic multiplies with a loop of 8 steps. Each step doubles the
left operand, and it adds the field polynomial when the double leaves the byte.
The loop takes the same 8 steps for every input. The implementation must hold no
table and no branch on a secret value, in the multiplication and in the inverse.
The split evaluates one polynomial for each byte of the secret, so the byte
count of the work stays fixed at 32.

## The pick

The arithmetic lives in the tree, in `src/share.c`, under the ISC licence of
this repository. No candidate of the first path carries a licence of the set
that D-15 names. The one candidate with constant-time arithmetic also brings a
share format that this design does not take.

The second path of D-15 therefore holds. KEY-SHARE-2 to KEY-SHARE-6 state the
field, the polynomial, the coefficients, the evaluation and the reconstruction.
The section below names the source of each vector set.

## The sources of the vectors

The section above answers which implementation this repository ships. This
section answers the other question of D-15: which reference pins the outputs of
that implementation.

This repository holds three generators, and they write the vectors.
`tests/vectors/generate.py` takes the Python standard library alone. The other
two also call a module of PyPI. `deps/` gains no entry for either module, and
the regress build needs no Python. The developer installs each module into a
throwaway environment under `scratch/`, which the repository ignores.

`tests/vectors/generate-share.py` writes no field arithmetic of its own. It
calls the `galois` module of PyPI, which Matt Hostetter holds under the MIT
licence. `galois.GF(2**8, irreducible_poly=0x11b)` builds the field of
KEY-SHARE-2. That module multiplies and it inverts. `galois.Poly` evaluates each
polynomial of the split, and `galois.lagrange_poly` interpolates the
reconstruction. The script therefore shares no arithmetic with `src/share.c`,
and one misreading of KEY-SHARE-2 cannot enter both. The vectors in
`tests/vectors/share.h` come from version 0.4.11 of that module, on 2026-09-20.

The licence set that D-15 names governs an imported implementation. `galois`
ships no code into this repository, and no file of it enters the checkout, so
that set does not reach it. The same holds for the `bcrypt` module below.

The script proves the field before it prints. It reads the field polynomial back
from `galois`, so a field of another polynomial stops the run. It then checks
two products of FIPS 197, section 4.2: `0x57 · 0x83 = 0xc1`, and
`0x57 · 0x13 = 0xfe`. It also checks that every nonzero element has one inverse.

The coefficients stay outside `galois`. The script derives each one with the
`hmac` module of the Python standard library (KEY-DERIVE-1, KEY-SHARE-3). That
module is independent of the C, because the C calls HMAC-SHA256 of `libcrypto`.

`tests/vectors/generate-pin.py` holds no arithmetic of its own. The Python
standard library holds no `bcrypt_pbkdf(3)`, so the script calls `bcrypt.kdf()`
of the `bcrypt` module of PyPI. That function computes `bcrypt_pbkdf(3)`, and it
takes the same argument order: the password, the salt, the byte count, and the
round count (KEY-PIN-3). The vectors in `tests/vectors/share.h` come from
version 5.0.0 of that module, on 2026-09-20.

`tests/vectors/generate.py` writes the label vectors of the derivation tree,
with the `hmac` module alone. It writes coefficient values too, and no test
reads them. `share_coeff()` is static in `src/share.c`, so no test can call it.
Those values also split `KAT_TEST_ENTRY_KEY`, and the share vectors split
`KAT_SHARE_SECRET`. The share vectors above pin the coefficients of the
thresholds 2 and 3, through the share values.
