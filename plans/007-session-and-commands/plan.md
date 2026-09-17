# 007 — The session and the six commands

## Status

Proposed. It waits on plan 006 for a vault. Plan 008, plan 009, and plan 011
wait on it.

Implements: ORC-QUORUM, ENTRY-SHADOW, VAULT-INDEX, ENTRY-POOL, ENTRY-ROTATION,
TEST-HARNESS. Implements: ORC-CANARY without ORC-CANARY-10. Implements:
PROG-REPL, PROG-ONESHOT, SEC-MEMORY. Implements: PROG-OUTPUT without
PROG-OUTPUT-2. Defers: CER-VERIFY, REC-PLATE, PROG-IFACE.

Of PROG-REPL, this plan lands PROG-REPL-1 to PROG-REPL-5: the unlock, the index
open, the six commands, the quorum events, and the refusal. PROG-REPL-6 is plan
010, and PROG-REPL-7 to PROG-REPL-9 are plan 011. It completes PROG-ONESHOT-1 to
PROG-ONESHOT-3, ORC-CANARY-1, ORC-CANARY-3, ORC-CANARY-4, ORC-CANARY-8, and
ORC-CANARY-9, VAULT-INDEX-3 and VAULT-INDEX-6, ENTRY-POOL-3 to ENTRY-POOL-9,
ENTRY-ROTATION-1, and SEC-MEMORY-6. It adds the quorum reveal legs of
TEST-HARNESS-5. PROG-OUTPUT-2 is the QR display of plan 012. ORC-CANARY-10 is a
statement of plan 013.

## Purpose

A reveal is the passphrase plus any `k` of the `n` oracle masks, through this
machine's records (D-06). This plan lands the session core: the canary checks in
quorum order, and the index open through the index wraps. It also lands the
quorum reveal with substitution, and the refusal below `k`. On that core it
lands the six commands as one-shot subcommands: `ls`, `show`, `add`, `gen`,
`totp`, and `audit`. The interface of plan 011 adds no core path
(PROG-ONESHOT-2).

## Constraints that shape the design

**The session opens in one order.** The core reads the passphrase once
(PROG-REPL-1). It selects the quorum from the reachable oracles in list order,
with a preference for oracles that hold live index wraps (ORC-QUORUM-2). It
verifies the canaries one oracle at a time and stops at the first failure,
before any entry record (ORC-CANARY-1, ORC-CANARY-4). The same `k` canary
answers open the index (ORC-CANARY-3, VAULT-INDEX-3).

**A failure report names its cause set.** A first canary failure names the typo
case and the per-oracle causes. A failure after a pass excludes the typo
(ORC-CANARY-4, ORC-CANARY-9). An index decrypt failure after the canaries names
the index file and the index wraps of the quorum, never junk (VAULT-INDEX-6).
Every quorum failure names the oracles of the attempt (ORC-QUORUM-5).

**The reveal is `k` requests and one decrypt.** For each quorum oracle the core
reveals one record and unmasks one share. After `k` shares it reconstructs `K_e`
and decrypts the entry file (ORC-QUORUM-3, ORC-QUORUM-4). On a decrypt failure,
an HTTP error, or a transport failure it substitutes the next reachable oracle
after that oracle's canary. It continues until no untried quorum remains
(ORC-QUORUM-5). Below `k` reachable oracles it performs no reveal
(ORC-QUORUM-6). `K_e` clears directly after the decrypt (SEC-MEMORY-6).

**A dead index wrap heals in session.** A canary re-enrollment replaces the
canary mask, so the index wrap of that oracle dies. A session that holds `K_idx`
re-wraps at once, and a session without `K_idx` deletes the wrap file and
reports it (ORC-CANARY-8).

**Consumption is one quorum event, in a fixed order.** `add` and `gen` take the
lowest free slot with wraps at `k` or more live oracles, and verify the two
candidates. They write the index with the slot consumed, then write the entry
file (ENTRY-POOL-3, ENTRY-POOL-4, ENTRY-POOL-8, ENTRY-POOL-9). The records and
the wraps of the slot stay as they are (ENTRY-POOL-5). The tool warns at 8 free
slots and refuses at zero, and each message names the refill ceremony
(ENTRY-POOL-6, ENTRY-POOL-7).

**Rotation reuses two commands.** The specification names no rotation command.
`gen` on an existing derived name rotates it: a new slot, a version increment,
and the slot list extended (ENTRY-ROTATION-1). `add` on an existing stored name
seals the new secret in place (ENTRY-ROTATION-4). The implementation adds this
sentence to ENTRY-ROTATION.

**Output has one shape.** Non-secret output is one record per line on standard
output, with no decoration (PROG-ONESHOT-3). A secret prints to the terminal
(PROG-OUTPUT-1), and a mnemonic prints as words on an explicit flag until plan
012 lands the QR display.

## Files

| File                               | Change                                               |
| ---------------------------------- | ---------------------------------------------------- |
| `src/session.c`, `src/session.h`   | The unlock, the quorum, the canaries, the index open |
| `src/commands.c`, `src/commands.h` | The six commands                                     |
| `src/entry.c`                      | The consumption, the rotation, the shadow audit      |
| `src/fugupass.c`                   | The six subcommands                                  |
| `src/fugupass/fugupass.1`          | The six commands and the report states               |
| `tests/harness.d/session`          | The legs below                                       |
| `spec/entries.md`                  | The rotation sentence of ENTRY-ROTATION              |
| `spec/STATUS.md`                   | The cited units                                      |

## Tests

The harness holds, against each counterparty, with one oracle and with the
2-of-3 topology of TEST-HARNESS-5:

- `ls` lists the entries of the open index and sends no entry request.
- `gen` and `add` consume the lowest free slot, and `show` reveals the entry on
  every two-oracle quorum of the 2-of-3 set (TEST-HARNESS-5).
- One mask alone fails the decrypt, and the report names the quorum
  (ORC-QUORUM-4, TEST-HARNESS-5).
- A wrong passphrase stops at the first canary with the typo case in the report,
  and no entry record receives a request.
- A stopped oracle of the quorum leads to a substitution. Two stopped oracles of
  three lead to a refusal with each oracle state (ORC-QUORUM-5, ORC-QUORUM-6).
- A re-enrolled canary heals its index wrap in session (ORC-CANARY-8).
- `totp` prints the code of the RFC 6238 vector for a stored totp entry.
- `audit` lists a shadow entry with an old verification date and skips a fresh
  one (ENTRY-SHADOW-4).
- A pool of 8 free slots warns, a pool of 0 refuses, and both messages name the
  refill (ENTRY-POOL-6, ENTRY-POOL-7).
- `gen` on an existing derived name increments the version and extends the slot
  list (ENTRY-ROTATION-1).

## Acceptance

- `make check` passes on the host, and `make harness` passes.
- Every cited unit reads `done`, except ORC-CANARY, PROG-REPL, PROG-ONESHOT,
  PROG-OUTPUT, SEC-MEMORY, and TEST-HARNESS, which read `partial` with the
  absent rules named.
- The change deletes this plan.

## What this plan does not do

It changes no passphrase and refills no pool. It renders no QR code, and it
reads no command line with a line editor.
