# FuguPass specification

FuguPass is a password manager for any secret, built on proven seed-phrase
standards and air-gapped custody patterns. It derives every vault key from one
master: a BIP39 mnemonic of 12 words on a SeedQR plate. It seals every entry as
one flat ciphertext file. Per-entry records at an ordered set of blind PIN
oracles gate each reveal. The passphrase plus any k of the n oracle masks open
one entry. The wire protocol is version 2 of the Blockstream `blind_pin_server`
protocol, and FuguOracle is the reference oracle deployment. No theft of data at
rest exposes a secret. An attacker also needs the passphrase and k queries to
live oracles per entry. Each request leaves one log line at its oracle. The
plate alone restores every derived and sovereign entry, so the oracle gates
reveals, never recovery. The master appears only during ceremonies.

This document is the entry point of the specification. It holds the plan
contract, the ID conventions, and the document tables.

## Plan contract

- Read [DECISIONS.md](DECISIONS.md) before you make a plan.
- A plan must not go against a decision. To go against a decision, propose a
  change to [DECISIONS.md](DECISIONS.md) and get human approval first.
- A plan must cite each unit that it implements, for example
  `Implements: KEY-DERIVE, ORC-REVEAL`.
- A plan can exclude a rule from a cited unit with `without`, for example
  `Implements: KEY-DERIVE without KEY-DERIVE-3`.
- A plan must cite each `done` unit that it extends, for example
  `Extends: KEY-MASTER`.
- A plan must cite each unit that it touches but defers, for example
  `Defers: ORC-REVOKE`.
- The change that implements a unit, or a part of one, must set the unit state
  in [STATUS.md](STATUS.md) in the same change.

<a id="conventions"></a>

## Conventions

The ID overlay lives in [spec/CLAUDE.md](CLAUDE.md): the unit anchors, the rule
shape, the append-only numbers, the retire procedure, and the citation forms.

## Specification documents

Each document specifies one area of work. The code of a document prefixes the
IDs of its units.

| Code  | Document                       | Area                      |
| ----- | ------------------------------ | ------------------------- |
| OVW   | [overview.md](overview.md)     | Purpose, scope, and risks |
| KEY   | [keys.md](keys.md)             | Key derivation            |
| VAULT | [vault.md](vault.md)           | Vault storage             |
| ENTRY | [entries.md](entries.md)       | Entry model               |
| ORC   | [oracle.md](oracle.md)         | Blind-oracle client       |
| CER   | [ceremonies.md](ceremonies.md) | Ceremonies                |
| REC   | [recovery.md](recovery.md)     | Recovery                  |
| CLI   | [programs.md](programs.md)     | Programs                  |
| SAFE  | [security.md](security.md)     | Security design           |
| QA    | [testing.md](testing.md)       | Test strategy             |

## Governance documents

These documents carry no units.

| Document                     | Role                                                  |
| ---------------------------- | ----------------------------------------------------- |
| [DECISIONS.md](DECISIONS.md) | The decisions. A plan must not go against a decision. |
| [ROADMAP.md](ROADMAP.md)     | The phases of the work.                               |
| [STATUS.md](STATUS.md)       | The implementation register.                          |
