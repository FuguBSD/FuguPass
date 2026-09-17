# 002 — The vault on disk

## Status

Proposed. It waits on plan 001 for the entry key and the build skeleton.

Implements: VAULT-LAYOUT, VAULT-SEAL, VAULT-FORMAT, VAULT-ATOMIC, ENTRY-MODEL,
ENTRY-TYPES, TEST-KAT. Implements: VAULT-CONFIG without VAULT-CONFIG-5.
Implements: VAULT-INDEX without VAULT-INDEX-3 and VAULT-INDEX-6. Implements:
VAULT-BACKUP without VAULT-BACKUP-3 and VAULT-BACKUP-4. Implements:
ENTRY-ROTATION without ENTRY-ROTATION-1. Defers: SEC-ENTROPY, SEC-MEMORY,
ENTRY-POOL, ENTRY-SHADOW, KEY-MASK.

The absent rules are session and documentation rules. VAULT-INDEX-3 and
VAULT-INDEX-6 bind the daily index read of plan 007. ENTRY-ROTATION-1 consumes a
pool slot, in plan 007. VAULT-BACKUP-4 is the paper QR of plan 012.
VAULT-CONFIG-5 and VAULT-BACKUP-3 are statements of the manual pages, in
plan 013. This plan adds TEST-KAT-2, the seal vectors.

## Purpose

The vault is a directory of flat files, one sealed file per entry, with a shared
set and a machine-local set (D-13). This plan lands the seal, the line format
and its strict reader, the directory layout, and the atomic write. It also lands
the config file, the index file, and the entry model. After it, a test can write
a vault that no oracle has touched, and read it back.

## Constraints that shape the design

**The seal is one function pair.** `seal.c` seals a plaintext under a 32-byte
key into the layout of VAULT-SEAL. The layout is the version byte, a fresh
12-byte nonce from `arc4random(3)`, then the ChaCha20-Poly1305 body from
`libcrypto`. The version byte is the additional authenticated data
(VAULT-SEAL-5). The open returns one failure for every wrong key, so the caller
learns no cause (VAULT-SEAL-4).

**The reader is a scanner, and the tables are complete.** `vault.c` reads
`field: value` lines with a strict scanner: no YAML, no JSON, and a line of at
most 4096 bytes. It accepts no unknown field and no line feed in a value
(VAULT-FORMAT-5 to VAULT-FORMAT-7). Each file kind has its own field table from
the specification, and the scanner takes the table as data. The secret block
comes first in a sealed file (VAULT-FORMAT-4).

**Every write is the same sequence.** `mkstemp(3)` in the target directory,
write, `fsync(2)`, `rename(2)`, then `fsync(2)` of the directory
(VAULT-ATOMIC-1). One function does it, and every file kind calls it.

**The layout is a table of paths.** The entry file of slot `e` is the lowercase
hex of `H(K_e)` at the vault root. The machine-local files sit under `machine/`
with the fixed names of VAULT-LAYOUT (VAULT-LAYOUT-5, VAULT-LAYOUT-6). One
function maps a file kind and its indexes to a path.

**The config keeps its positions.** Oracle positions run from 1 to `n` with no
gap, a position never disappears, and two positions never exchange values
(VAULT-CONFIG-6). The reader rejects a config that breaks the rule. The config
holds no secret (VAULT-CONFIG-3).

**The entry model is data.** `entry.c` holds the origin classes and the six
types as tables. The tables hold the secret field, the metadata fields, and the
classes that a type allows (ENTRY-MODEL-2, ENTRY-TYPES-5). It computes a TOTP
code from a totp entry with HMAC from `libcrypto` (ENTRY-TYPES-3). The version
of an entry is the position of its slot in `slots` (ENTRY-ROTATION-2).

## Files

| File                         | Change                                                    |
| ---------------------------- | --------------------------------------------------------- |
| `src/seal.c`, `src/seal.h`   | The seal and the open                                     |
| `src/vault.c`, `src/vault.h` | The paths, the scanner, the writer, the config, the index |
| `src/entry.c`, `src/entry.h` | The classes, the types, the field tables, TOTP            |
| `src/regress/vault.c`        | The tests below                                           |
| `tests/vectors/seal.h`       | The seal vectors                                          |
| `spec/STATUS.md`             | The cited units                                           |

## Tests

`src/regress/vault` holds:

- A seal then an open return the plaintext. A modified byte in the nonce, the
  body, or the version fails the open (TEST-KAT-2).
- Two seals of one plaintext write two different nonces.
- The scanner rejects an unknown field, a line of 4097 bytes, and a value with a
  line feed. It also rejects a field that repeats where the table forbids it.
- Each file kind round-trips through its field table. The kinds are the slot
  file, the index, the counters file, the change marker, the config, and each of
  the six entry types.
- The config reader rejects a gap in the positions and a threshold above the
  live count (VAULT-CONFIG-6).
- A write that stops before the `rename(2)` leaves the target intact
  (VAULT-ATOMIC-2).
- The entry file of a slot sits at the lowercase hex of `H(K_e)`. A directory
  listing shows hex names, `index`, and `machine/` alone (VAULT-LAYOUT-7).
- The TOTP code of the RFC 6238 test vectors is correct for SHA-1, SHA-256, and
  SHA-512.

## Acceptance

- `make check` passes on the host, and `make regress` passes in the guest.
- Every cited unit reads `done`, except the five units with a named absent rule,
  which read `partial`.
- The change deletes this plan.

## What this plan does not do

It derives no wrap and touches no oracle. It creates no vault for a user: the
ceremony of plan 006 does.
