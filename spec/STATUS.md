# Implementation register

This register is the one record of implementation state. One row exists for each
unit of the specification. A unit is one design element of one specification
document. The [conventions](index.md#conventions) define the unit IDs. Each row
describes the current state only. A row must not carry a plan name or a
reference to an earlier state. A note can carry the date of a recorded fact.

## States

| State   | Meaning                                                              |
| ------- | -------------------------------------------------------------------- |
| open    | No code implements the unit.                                         |
| partial | Code implements a part of the unit. The note names each absent part. |
| done    | Code implements the full unit. The note links the code or the tests. |
| n-a     | No code can implement the unit. It exists for citation only.         |

The "Done by" column names a phase of the [roadmap](ROADMAP.md), or "—" when no
phase applies.

## Units

| Unit                                         | State   | Done by | Note                                                                                                                                                                                                                       |
| -------------------------------------------- | ------- | ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [OVW-PURPOSE](overview.md#ovw-purpose)       | n-a     | —       | Citation only.                                                                                                                                                                                                             |
| [OVW-MODEL](overview.md#ovw-model)           | n-a     | —       | Citation only.                                                                                                                                                                                                             |
| [OVW-SCOPE](overview.md#ovw-scope)           | n-a     | —       | Citation only.                                                                                                                                                                                                             |
| [OVW-VOCABULARY](overview.md#ovw-vocabulary) | done    | —       | [vocabulary.t](../t/fugupass/vocabulary.t) reads the five words and scans the tree outside `ports/`.                                                                                                                       |
| [OVW-RISKS](overview.md#ovw-risks)           | n-a     | —       | Citation only.                                                                                                                                                                                                             |
| [KEY-MASTER](keys.md#key-master)             | partial | P3      | KEY-MASTER-2 is absent. The SeedQR scan path and the BIP85-child path both enter by a scan, so each one needs PROG-SCAN and CER-CREATE.                                                                                    |
| [KEY-DERIVE](keys.md#key-derive)             | done    | P1      | [derive.c](../src/derive.c) holds `f` and the two labels of the table, and [kat.c](../src/regress/kat.c) pins the values.                                                                                                  |
| [KEY-ENTRY](keys.md#key-entry)               | partial | P2      | KEY-ENTRY-1 and KEY-ENTRY-3 are absent. The slot reservation needs ENTRY-POOL, and the entry file needs VAULT-SEAL.                                                                                                        |
| [KEY-DEVICE](keys.md#key-device)             | open    | P2      | —                                                                                                                                                                                                                          |
| [KEY-CLIENT](keys.md#key-client)             | open    | P2      | —                                                                                                                                                                                                                          |
| [KEY-PIN](keys.md#key-pin)                   | open    | P2      | —                                                                                                                                                                                                                          |
| [KEY-SHARE](keys.md#key-share)               | open    | P2      | —                                                                                                                                                                                                                          |
| [KEY-MASK](keys.md#key-mask)                 | open    | P2      | —                                                                                                                                                                                                                          |
| [KEY-BIP85](keys.md#key-bip85)               | partial | P3      | KEY-BIP85-5 and KEY-BIP85-6 are absent. The two candidates of a slot need ENTRY-POOL, VAULT-SEAL, and CER-CREATE.                                                                                                          |
| [VAULT-LAYOUT](vault.md#vault-layout)        | open    | P1      | —                                                                                                                                                                                                                          |
| [VAULT-SEAL](vault.md#vault-seal)            | open    | P1      | —                                                                                                                                                                                                                          |
| [VAULT-FORMAT](vault.md#vault-format)        | open    | P1      | —                                                                                                                                                                                                                          |
| [VAULT-INDEX](vault.md#vault-index)          | open    | P1      | —                                                                                                                                                                                                                          |
| [VAULT-CONFIG](vault.md#vault-config)        | open    | P1      | —                                                                                                                                                                                                                          |
| [VAULT-ATOMIC](vault.md#vault-atomic)        | open    | P1      | —                                                                                                                                                                                                                          |
| [VAULT-BACKUP](vault.md#vault-backup)        | open    | P1      | —                                                                                                                                                                                                                          |
| [ENTRY-MODEL](entries.md#entry-model)        | open    | P1      | —                                                                                                                                                                                                                          |
| [ENTRY-TYPES](entries.md#entry-types)        | open    | P1      | —                                                                                                                                                                                                                          |
| [ENTRY-ROTATION](entries.md#entry-rotation)  | open    | P1      | —                                                                                                                                                                                                                          |
| [ENTRY-POOL](entries.md#entry-pool)          | open    | P2      | —                                                                                                                                                                                                                          |
| [ENTRY-SHADOW](entries.md#entry-shadow)      | open    | P2      | —                                                                                                                                                                                                                          |
| [ORC-CONFORM](oracle.md#orc-conform)         | open    | P2      | —                                                                                                                                                                                                                          |
| [ORC-PROVISION](oracle.md#orc-provision)     | open    | P2      | —                                                                                                                                                                                                                          |
| [ORC-RECORDS](oracle.md#orc-records)         | open    | P2      | —                                                                                                                                                                                                                          |
| [ORC-COUNTER](oracle.md#orc-counter)         | open    | P2      | —                                                                                                                                                                                                                          |
| [ORC-ENROLL](oracle.md#orc-enroll)           | open    | P2      | —                                                                                                                                                                                                                          |
| [ORC-REVEAL](oracle.md#orc-reveal)           | open    | P2      | —                                                                                                                                                                                                                          |
| [ORC-QUORUM](oracle.md#orc-quorum)           | open    | P2      | —                                                                                                                                                                                                                          |
| [ORC-CANARY](oracle.md#orc-canary)           | open    | P2      | —                                                                                                                                                                                                                          |
| [ORC-REVOKE](oracle.md#orc-revoke)           | open    | P2      | —                                                                                                                                                                                                                          |
| [CER-CREATE](ceremonies.md#cer-create)       | open    | P3      | —                                                                                                                                                                                                                          |
| [CER-REFILL](ceremonies.md#cer-refill)       | open    | P3      | —                                                                                                                                                                                                                          |
| [CER-PROVISION](ceremonies.md#cer-provision) | open    | P3      | —                                                                                                                                                                                                                          |
| [CER-VERIFY](ceremonies.md#cer-verify)       | open    | P3      | —                                                                                                                                                                                                                          |
| [REC-PRINCIPLE](recovery.md#rec-principle)   | n-a     | —       | Citation only.                                                                                                                                                                                                             |
| [REC-PLATE](recovery.md#rec-plate)           | open    | P3      | —                                                                                                                                                                                                                          |
| [REC-VAULT](recovery.md#rec-vault)           | open    | P3      | —                                                                                                                                                                                                                          |
| [REC-WIPE](recovery.md#rec-wipe)             | open    | P3      | —                                                                                                                                                                                                                          |
| [REC-RESTORE](recovery.md#rec-restore)       | open    | P3      | —                                                                                                                                                                                                                          |
| [PROG-SPLIT](programs.md#prog-split)         | open    | P3      | —                                                                                                                                                                                                                          |
| [PROG-IFACE](programs.md#prog-iface)         | open    | P3      | Fugu LIB-REPL supplies the line editor, and its `.pod` sidecar is the contract of record. The interface program is absent.                                                                                                 |
| [PROG-REPL](programs.md#prog-repl)           | open    | P2      | Fugu LIB-REPL supplies the line editor, and its `.pod` sidecar is the contract of record. The interface program is absent.                                                                                                 |
| [PROG-ONESHOT](programs.md#prog-oneshot)     | open    | P2      | —                                                                                                                                                                                                                          |
| [PROG-OUTPUT](programs.md#prog-output)       | open    | P2      | —                                                                                                                                                                                                                          |
| [PROG-SCAN](programs.md#prog-scan)           | open    | P3      | —                                                                                                                                                                                                                          |
| [PROG-QR](programs.md#prog-qr)               | open    | P3      | —                                                                                                                                                                                                                          |
| [PROG-PORT](programs.md#prog-port)           | open    | P4      | —                                                                                                                                                                                                                          |
| [PROG-BUILD](programs.md#prog-build)         | partial | P3      | Every program directory is absent. PROG-BUILD-1 needs each one to link the archive, and PROG-BUILD-2 needs each one to read `bsd.prog.mk`. They need PROG-SPLIT. [src/Makefile](../src/Makefile) is the build entry point. |
| [SEC-ENTROPY](security.md#sec-entropy)       | partial | P2      | SEC-ENTROPY-3, SEC-ENTROPY-4, SEC-ENTROPY-5, and SEC-ENTROPY-7 are absent. They need KEY-DEVICE, VAULT-SEAL, ORC-CONFORM, KEY-PIN, and KEY-SHARE.                                                                          |
| [SEC-MEMORY](security.md#sec-memory)         | partial | P3      | SEC-MEMORY-3 to SEC-MEMORY-6 are absent. They need PROG-IFACE, PROG-ONESHOT, CER-CREATE, and ENTRY-POOL.                                                                                                                   |
| [SEC-FLOOR](security.md#sec-floor)           | open    | P4      | —                                                                                                                                                                                                                          |
| [SEC-DETECT](security.md#sec-detect)         | open    | P4      | —                                                                                                                                                                                                                          |
| [SEC-CLAIMS](security.md#sec-claims)         | open    | P4      | —                                                                                                                                                                                                                          |
| [TEST-HARNESS](testing.md#test-harness)      | open    | P2      | —                                                                                                                                                                                                                          |
| [TEST-MASK](testing.md#test-mask)            | open    | P2      | —                                                                                                                                                                                                                          |
| [TEST-ANALYSIS](testing.md#test-analysis)    | open    | P2      | —                                                                                                                                                                                                                          |
| [TEST-SPLIT](testing.md#test-split)          | open    | P2      | —                                                                                                                                                                                                                          |
| [TEST-CALIBRATE](testing.md#test-calibrate)  | open    | P4      | —                                                                                                                                                                                                                          |
| [TEST-KAT](testing.md#test-kat)              | partial | P3      | TEST-KAT-2 needs VAULT-SEAL, and TEST-KAT-3 needs PROG-SCAN. Eight labels of TEST-KAT-4 are absent: they need KEY-DEVICE, KEY-CLIENT, KEY-PIN, KEY-MASK, and KEY-SHARE.                                                    |

## Update protocol

1. The change that implements a unit, or a part of one, sets the unit state in
   this register in the same change.
2. A `partial` note names each absent rule or part. For each absent part, the
   note names the unit that the part needs.
3. A `done` note holds at least one relative link to code or to tests.
4. A change to the text of a `partial` or `done` unit updates the row of that
   unit in the same change. The CI drift check enforces this rule.
5. The human merge review compares the register diff with the code diff.

## Code roots

The drift gate maps each document to the code that implements it.

| Document      | Roots                                                                                                                                                   |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| overview.md   | `t/fugupass/vocabulary.t`                                                                                                                               |
| keys.md       | `src/derive.c`, `src/bip85.c`, `src/wordlist.c`                                                                                                         |
| vault.md      | `src/vault.c`, `src/seal.c`                                                                                                                             |
| entries.md    | `src/entry.c`                                                                                                                                           |
| oracle.md     | `src/oracle.c`, `src/envelope.c`                                                                                                                        |
| ceremonies.md | `src/ceremony.c`                                                                                                                                        |
| recovery.md   | `src/recover.c`                                                                                                                                         |
| programs.md   | `src/Makefile`, `src/lib/Makefile`, `src/regress/Makefile`, `src/fugupass.c`, `bin/fugupass-repl`, `src/fugupass-scan.c`, `src/fugupass-qr.c`, `ports/` |
| security.md   | `src/`                                                                                                                                                  |
| testing.md    | `tests/`, `src/regress/`                                                                                                                                |
