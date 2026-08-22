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

The “Done by” column names a phase of the [roadmap](ROADMAP.md). At the exit of
that phase, the unit must have the state `done`. A unit can reach `done` before
that phase. An `n-a` unit has no “Done by” value.

## Units

| Unit                                         | State | Done by | Note                                                                                                                       |
| -------------------------------------------- | ----- | ------- | -------------------------------------------------------------------------------------------------------------------------- |
| [OVW-PURPOSE](overview.md#ovw-purpose)       | n-a   | —       | Citation only.                                                                                                             |
| [OVW-MODEL](overview.md#ovw-model)           | n-a   | —       | Citation only.                                                                                                             |
| [OVW-SCOPE](overview.md#ovw-scope)           | n-a   | —       | Citation only.                                                                                                             |
| [OVW-ATTACKS](overview.md#ovw-attacks)       | n-a   | —       | Citation only.                                                                                                             |
| [OVW-LIMITS](overview.md#ovw-limits)         | n-a   | —       | Citation only.                                                                                                             |
| [KEY-MASTER](keys.md#key-master)             | open  | P1      | —                                                                                                                          |
| [KEY-DERIVE](keys.md#key-derive)             | open  | P1      | —                                                                                                                          |
| [KEY-ENTRY](keys.md#key-entry)               | open  | P1      | —                                                                                                                          |
| [KEY-DEVICE](keys.md#key-device)             | open  | P2      | —                                                                                                                          |
| [KEY-CLIENT](keys.md#key-client)             | open  | P2      | —                                                                                                                          |
| [KEY-PIN](keys.md#key-pin)                   | open  | P2      | —                                                                                                                          |
| [KEY-SHARE](keys.md#key-share)               | open  | P2      | —                                                                                                                          |
| [KEY-MASK](keys.md#key-mask)                 | open  | P2      | —                                                                                                                          |
| [KEY-BIP85](keys.md#key-bip85)               | open  | P1      | —                                                                                                                          |
| [VAULT-LAYOUT](vault.md#vault-layout)        | open  | P1      | —                                                                                                                          |
| [VAULT-SEAL](vault.md#vault-seal)            | open  | P1      | —                                                                                                                          |
| [VAULT-FORMAT](vault.md#vault-format)        | open  | P1      | —                                                                                                                          |
| [VAULT-INDEX](vault.md#vault-index)          | open  | P1      | —                                                                                                                          |
| [VAULT-CONFIG](vault.md#vault-config)        | open  | P1      | —                                                                                                                          |
| [VAULT-ATOMIC](vault.md#vault-atomic)        | open  | P1      | —                                                                                                                          |
| [VAULT-BACKUP](vault.md#vault-backup)        | open  | P1      | —                                                                                                                          |
| [ENTRY-MODEL](entries.md#entry-model)        | open  | P1      | —                                                                                                                          |
| [ENTRY-TYPES](entries.md#entry-types)        | open  | P1      | —                                                                                                                          |
| [ENTRY-ROTATION](entries.md#entry-rotation)  | open  | P1      | —                                                                                                                          |
| [ENTRY-POOL](entries.md#entry-pool)          | open  | P2      | —                                                                                                                          |
| [ENTRY-SHADOW](entries.md#entry-shadow)      | open  | P2      | —                                                                                                                          |
| [ORC-CONFORM](oracle.md#orc-conform)         | open  | P2      | —                                                                                                                          |
| [ORC-PROVISION](oracle.md#orc-provision)     | open  | P2      | —                                                                                                                          |
| [ORC-RECORDS](oracle.md#orc-records)         | open  | P2      | —                                                                                                                          |
| [ORC-COUNTER](oracle.md#orc-counter)         | open  | P2      | —                                                                                                                          |
| [ORC-ENROLL](oracle.md#orc-enroll)           | open  | P2      | —                                                                                                                          |
| [ORC-REVEAL](oracle.md#orc-reveal)           | open  | P2      | —                                                                                                                          |
| [ORC-QUORUM](oracle.md#orc-quorum)           | open  | P2      | —                                                                                                                          |
| [ORC-CANARY](oracle.md#orc-canary)           | open  | P2      | —                                                                                                                          |
| [ORC-REVOKE](oracle.md#orc-revoke)           | open  | P2      | —                                                                                                                          |
| [CER-DICE](ceremonies.md#cer-dice)           | open  | P1      | —                                                                                                                          |
| [CER-CREATE](ceremonies.md#cer-create)       | open  | P3      | —                                                                                                                          |
| [CER-REFILL](ceremonies.md#cer-refill)       | open  | P3      | —                                                                                                                          |
| [CER-PROVISION](ceremonies.md#cer-provision) | open  | P3      | —                                                                                                                          |
| [CER-VERIFY](ceremonies.md#cer-verify)       | open  | P3      | —                                                                                                                          |
| [REC-PRINCIPLE](recovery.md#rec-principle)   | n-a   | —       | Citation only.                                                                                                             |
| [REC-PLATE](recovery.md#rec-plate)           | open  | P3      | —                                                                                                                          |
| [REC-VAULT](recovery.md#rec-vault)           | open  | P3      | —                                                                                                                          |
| [REC-WIPE](recovery.md#rec-wipe)             | open  | P3      | —                                                                                                                          |
| [REC-RESTORE](recovery.md#rec-restore)       | open  | P3      | —                                                                                                                          |
| [CLI-SPLIT](programs.md#cli-split)           | open  | P3      | —                                                                                                                          |
| [CLI-IFACE](programs.md#cli-iface)           | open  | P3      | Fugu LIB-REPL supplies the line editor, and its `.pod` sidecar is the contract of record. The interface program is absent. |
| [CLI-REPL](programs.md#cli-repl)             | open  | P2      | Fugu LIB-REPL supplies the line editor, and its `.pod` sidecar is the contract of record. The interface program is absent. |
| [CLI-ONESHOT](programs.md#cli-oneshot)       | open  | P2      | —                                                                                                                          |
| [CLI-OUTPUT](programs.md#cli-output)         | open  | P2      | —                                                                                                                          |
| [CLI-SCAN](programs.md#cli-scan)             | open  | P3      | —                                                                                                                          |
| [CLI-QR](programs.md#cli-qr)                 | open  | P3      | —                                                                                                                          |
| [SAFE-ENTROPY](security.md#safe-entropy)     | open  | P1      | —                                                                                                                          |
| [SAFE-MEMORY](security.md#safe-memory)       | open  | P1      | —                                                                                                                          |
| [SAFE-FLOOR](security.md#safe-floor)         | open  | P4      | —                                                                                                                          |
| [SAFE-DETECT](security.md#safe-detect)       | open  | P4      | —                                                                                                                          |
| [SAFE-CLAIMS](security.md#safe-claims)       | open  | P4      | —                                                                                                                          |
| [QA-HARNESS](testing.md#qa-harness)          | open  | P2      | —                                                                                                                          |
| [QA-MASK](testing.md#qa-mask)                | open  | P2      | —                                                                                                                          |
| [QA-ANALYSIS](testing.md#qa-analysis)        | open  | P2      | —                                                                                                                          |
| [QA-SPLIT](testing.md#qa-split)              | open  | P2      | —                                                                                                                          |
| [QA-CALIBRATE](testing.md#qa-calibrate)      | open  | P4      | —                                                                                                                          |
| [QA-KAT](testing.md#qa-kat)                  | open  | P1      | —                                                                                                                          |

## Update protocol

1. The change that implements a unit, or a part of a unit, sets the state of the
   unit in this register, in the same change.
2. A `partial` note names each absent rule or part. For each absent part, the
   note names the unit that the part needs.
3. A `done` note holds at least one relative link to code or to tests.
4. A change to the text of a `partial` or `done` unit updates the row of that
   unit in the same change. The CI drift check enforces this rule.
5. The human merge review compares the register diff with the code diff.

## Code roots

The roots are the code paths that implement a document, relative to the
repository root.

| Document      | Roots                                                                             |
| ------------- | --------------------------------------------------------------------------------- |
| keys.md       | `src/derive.c`, `src/bip85.c`                                                     |
| vault.md      | `src/vault.c`, `src/seal.c`                                                       |
| entries.md    | `src/entry.c`                                                                     |
| oracle.md     | `src/oracle.c`, `src/envelope.c`                                                  |
| ceremonies.md | `src/ceremony.c`, `src/dice.c`                                                    |
| recovery.md   | `src/recover.c`                                                                   |
| programs.md   | `src/fugupass.c`, `bin/fugupass-repl`, `src/fugupass-scan.c`, `src/fugupass-qr.c` |
| security.md   | `src/`                                                                            |
| testing.md    | `tests/`                                                                          |

## Retired IDs

| ID  | Unit |
| --- | ---- |
