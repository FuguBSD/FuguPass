# 001 — The derivation tree

## Status

Proposed. It can land now, and it depends on no other plan. Every other plan of
this repository waits on it.

Implements: KEY-DERIVE, KEY-ENTRY, KEY-BIP85. Implements: KEY-MASTER without
KEY-MASTER-2. Implements: TEST-KAT without TEST-KAT-2 and TEST-KAT-3.
Implements: SEC-ENTROPY, SEC-MEMORY. Defers: VAULT-SEAL, PROG-SCAN.

Of the two security units, this plan lands SEC-ENTROPY-1, SEC-ENTROPY-2, and
SEC-ENTROPY-6, and SEC-MEMORY-1 and SEC-MEMORY-2. The other rules land with the
code that they bind, and the register names each absent rule. KEY-MASTER-2 is
the scan path, and plan 012 lands it with the scan helper. TEST-KAT-2 is the
seal vectors of plan 002, and TEST-KAT-3 is the SeedQR vectors of plan 012.

## Purpose

Every vault key derives from one 12-word master (D-01). This plan lands the root
of that tree: the master gate, the BIP39 seed, and the one derivation function
`f`. It also lands the complete label table, the entry key, the plate check
value, and the two BIP85 applications. Known-answer vectors pin every label
before any vault file exists (TEST-KAT-4). The plan also lands the build
skeleton that every later plan extends.

## Constraints that shape the design

**The sources stay flat.** The register names `src/derive.c` and `src/bip85.c`,
so the C sources sit flat in `src/`. The build follows the layout of
`usr.bin/ssh` in the OpenBSD tree. `src/lib/Makefile` builds `libfugupass.a`
from the flat sources with `.PATH`. One directory per program follows
`bsd.prog.mk`, and `src/regress/` follows `bsd.regress.mk`. GNU make reads the
synced `GNUmakefile` for the document gates, and OpenBSD make reads
`src/Makefile`. The programs run on OpenBSD only, so every C test runs in the
guest that `fuguvm` supplies. `make check` on the host stays a document and Perl
gate.

**One word list, one digest.** `src/wordlist.c` holds the 2048 words of the
BIP39 English list as one table. A test computes the SHA-256 of the words with
one line feed after each word. It must equal the digest that FuguSeed pins for
the same list. The two projects then agree on the list by one number.

**The master gate rejects, and never names a word.** The gate takes 12 words as
one line of text, the form that the scan helper emits. A count other than 12 or
an unknown word is a failure that names the position. A wrong BIP39 checksum is
a failure that names the checksum (KEY-MASTER-6). The BIP39 seed is
PBKDF2-HMAC-SHA512 from `libcrypto` with an empty passphrase.

**The BIP32 master key holds a fixed HMAC key.** BIP32 fixes the ASCII string of
that key, and the first word of that string is a banned word of D-21. `bip85.c`
holds the 12 bytes as a byte array, with a comment that names BIP32 as the
source. No file then holds the word, and the artifact names the standard.

**BIP85 uses hardened steps only.** A hardened child is HMAC-SHA512 over the
parent key and the index, then a scalar addition with
`secp256k1_ec_seckey_tweak_add`. The DRNG is HMAC-SHA512 with the key
`bip-entropy-from-k`. The PWD BASE64 application takes 21 characters, and the
BIP39 application takes 12 English words (KEY-BIP85-8). No library beyond
`libcrypto` and `libsecp256k1` enters (D-15).

**The vectors come from an independent script.** `tests/vectors/generate.py` is
a Python 3 script on the standard library alone. It derives every label of the
table for the fixed test master. It also derives the two BIP85 applications from
the reference vectors of the BIP85 document. The developer runs it once and
commits `tests/vectors/derive.h`. The regress build needs no Python
(TEST-KAT-5).

## The interface contract

`derive.h` declares the master gate, the seed, `f`, each label of the table as
one function, and the plate check value. `bip85.h` declares the BIP32 master
from the seed, the two applications, and the DRNG. Every function takes buffers
and lengths and returns 0 or -1, and every function clears its temporaries on
each exit path (SEC-MEMORY-1).

## Files

| File                               | Change                                               |
| ---------------------------------- | ---------------------------------------------------- |
| `src/Makefile`                     | `SUBDIR` over the library, the programs, and regress |
| `src/lib/Makefile`                 | `libfugupass.a` from the flat sources                |
| `src/regress/Makefile`             | The `kat` target                                     |
| `src/derive.c`, `src/derive.h`     | The gate, the seed, `f`, the labels, the check value |
| `src/bip85.c`, `src/bip85.h`       | BIP32 hardened steps, the DRNG, the two applications |
| `src/wordlist.c`, `src/wordlist.h` | The 2048 words                                       |
| `src/regress/kat.c`                | The known-answer tests below                         |
| `tests/vectors/generate.py`        | The one-time generator                               |
| `tests/vectors/derive.h`           | The committed vectors, as hex                        |
| `spec/STATUS.md`                   | The cited units, and the new code roots              |

## Tests

`src/regress/kat` holds:

- The word table has the pinned digest, and each word maps to its index and
  back.
- The gate accepts the fixed test master. It rejects 11 words, 13 words, an
  unknown word, and a wrong checksum, with a message that holds no word
  (TEST-KAT-6).
- The seed of the test master equals the vector.
- Every label of the table gives the vector value for slot 17 at oracle 2, with
  threshold 3 and coefficient 1 (TEST-KAT-4).
- The two BIP85 applications give the reference values of the BIP85 document
  (TEST-KAT-1).
- The PWD BASE64 password has 21 characters, and the BIP39 child has 12 words
  with a valid checksum.

## Acceptance

- `make check` passes on the host, and `make regress` passes in the guest.
- Every cited unit reads `done`, except the four units with a named absent rule,
  which read `partial`.
- The change deletes this plan.

## What this plan does not do

It seals no file and touches no oracle. It reads no camera: the gate takes one
line of text.
