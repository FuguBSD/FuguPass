# FuguPass specification

FuguPass is a password manager for operators of air-gapped Bitcoin custody. It
derives every vault key from one master: a BIP39 mnemonic of 12 words on a
SeedQR plate. It seals every entry as one flat ciphertext file. Per-entry
records at an ordered set of blind PIN oracles gate each reveal: the passphrase
plus any k of the n oracle masks open one entry. The wire protocol is version 2
of the Blockstream `blind_pin_server` protocol, and FuguOracle is the reference
oracle deployment. No theft of data at rest exposes a secret. An attacker also
needs the passphrase and k queries to live oracles per entry. Each request
leaves one log line at its oracle. The plate alone restores every derived and
sovereign entry, so the oracle gates reveals, never recovery. The master appears
only during ceremonies.

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
- A plan must cite each unit that it touches but defers, for example
  `Defers: ORC-REVOKE`.
- The change that implements a unit, or a part of a unit, must set the state of
  the unit in [STATUS.md](STATUS.md) in the same change.

<a id="conventions"></a>

## Conventions

A unit is one implementable design element. An invisible HTML anchor marks each
unit, and the unit ID is the anchor in upper case:

```markdown
<a id="key-derive"></a>

## Derivation functions

- **KEY-DERIVE-1** — The derivation function must …
```

- The anchor of a unit must start with the code of its document, in lower case,
  followed by a hyphen.
- A unit extends from its anchor to the next unit anchor or heading, whichever
  comes first.
- A rule ID names one requirement inside a unit. A rule is a bold-lead list
  item: the bold rule ID, one em dash, then the requirement text, as the example
  above shows.
- Rule numbers only append: never renumber a rule, and never reuse a number.
- An ID must not change. To retire a unit: delete its anchor and its register
  row, and add the ID to the "Retired IDs" table of [STATUS.md](STATUS.md).
- Each document describes the target design in the current state only. Only
  [ROADMAP.md](ROADMAP.md) and [STATUS.md](STATUS.md) say when work occurs.
- A citation of a FuguOracle unit or rule is a prose token with the word
  FuguOracle in front, for example FuguOracle OPS-GET-4. It is never a link.

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
