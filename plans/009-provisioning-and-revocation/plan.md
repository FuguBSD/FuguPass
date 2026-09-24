# 009 — Machine provisioning, revocation, and recovery after oracle loss

## Status

Proposed. It waits on no other plan. It completes the quorum leg of the harness.

Implements: REC-WIPE, TEST-HARNESS, CER-PROVISION. Implements: VAULT-INDEX,
KEY-MASK. Implements: ORC-REVOKE without ORC-REVOKE-7 and ORC-REVOKE-9.
Implements: ORC-PROVISION without ORC-PROVISION-3 and ORC-PROVISION-8.
Implements: ORC-COUNTER without ORC-COUNTER-7.

Of ORC-PROVISION, this plan lands ORC-PROVISION-6 and ORC-PROVISION-7, the list
changes. Of VAULT-INDEX, this plan lands VAULT-INDEX-7, the retirement mark. It
adds the revocation exception of ORC-COUNTER-1 and ORC-COUNTER-5. Of
CER-PROVISION-13 it lands the behavior: the ceremony records the new list or the
new threshold before any enrollment. The last sentence of CER-PROVISION-13 is a
documentation statement, and plan 013 lands it. CER-PROVISION stays partial on
that sentence. ORC-PROVISION-3, ORC-PROVISION-8, ORC-COUNTER-7, ORC-REVOKE-7,
and ORC-REVOKE-9 are statements of plan 013 too. It completes TEST-HARNESS-5
with the provisioning loop. CER-PROVISION-15 re-enrolls every record with a
fresh mask, so this plan completes KEY-MASK-10.

## Purpose

Machine provisioning adds a machine to a vault. The same ceremony changes the
oracle list, changes the threshold, re-enrolls after a loss, and runs the full
re-enrollment (CER-PROVISION). Revocation destroys or locks a stolen machine's
records from the plate (ORC-REVOKE). This plan lands the ceremony, its five
variants, the revocation subcommands, and the recovery after an oracle loss that
rests on them.

## Constraints that shape the design

**One ceremony, one loop, one criterion.** The ceremony runs CER-PROVISION-1 to
CER-PROVISION-10 in rule order. The loop of CER-PROVISION-7 covers each
slot-oracle pair for which this machine holds no wrap (CER-PROVISION-12). The
variants change the criterion: an added oracle adds pairs (CER-PROVISION-14),
and a retirement deletes the files of a position first (CER-PROVISION-16). A
threshold change covers every pair (CER-PROVISION-15), and the full run covers
every pair too (CER-PROVISION-17).

**The threshold change uses the marker.** It persists the marker with the kind
`threshold` before its first `set_pin`, and re-splits every `K_e` and `K_idx`
with the new `k`. It re-enrolls every record with a fresh `set_pin`, and
recomputes every wrap. An interrupted change re-runs from the start, and the
ceremony removes the marker after the last wrap (CER-PROVISION-15). The full
re-enrollment run removes a `passphrase` marker the same way (CER-PROVISION-17,
ORC-ENROLL-12).

**A ceremony refuses under a marker, with two exceptions.** While the marker
exists, a ceremony that enrolls refuses to start and names the resume or the
re-run (CER-PROVISION-18). The threshold re-run and the full run are exempt.

**The config changes before the first request.** A list or threshold change
writes the config first. A stopped ceremony then leaves a config that names the
target state and a machine that reveals against its own recorded list
(CER-PROVISION-13). A position never disappears, and a retired position keeps
its index (ORC-PROVISION-6, VAULT-CONFIG-6).

**Revocation is two subcommands and one counter.** `fugupass revoke` derives the
client keys of the named machine from the plate. It sends, per record at each
chosen oracle, one wrong attempt at the counter `0xFFFFFFFF`, or one `set_pin`
replacement (ORC-REVOKE-3, ORC-REVOKE-8). `fugupass kit` exports the kit of a
machine (ORC-REVOKE-6). The counter exception lives in one function, and every
other request refuses that value (ORC-COUNTER-5).

**A lock retires the machine name.** A record with the stored counter
`0xFFFFFFFF` accepts no later `set_pin` (FuguOracle OPS-SET-2), so the lock
retires the machine name at that oracle (ORC-REVOKE-11). The revocation
subcommand marks the name retired in the index registry (VAULT-INDEX-7). The
provisioning ceremony refuses a retired name (CER-PROVISION-3). The report
directs the owner to the remaining oracles and to a passphrase change
(ORC-REVOKE-12).

**A wiped or lost record heals in the loop.** After a wipe, a host loss, or a
static key rotation, the ceremony deletes the files of the position. It
re-enrolls the affected pairs (REC-WIPE-2, CER-PROVISION-16). A fresh `set_pin`
creates fresh key material, so no old mask returns (REC-WIPE-3).

## Files

| File                           | Change                                                           |
| ------------------------------ | ---------------------------------------------------------------- |
| `src/ceremony.c`               | Machine provisioning, its variants, and the retired-name refusal |
| `src/revoke.c`, `src/revoke.h` | The kit, the lock, the replacement                               |
| `src/vault.c`                  | The retirement mark of the machine registry                      |
| `src/oracle.c`                 | The revocation counter exception                                 |
| `src/fugupass.c`               | The `provision`, `revoke`, and `kit` subcommands                 |
| `src/fugupass/fugupass.1`      | The subcommands, the variants, the retired machine name          |
| `tests/harness.d/provision`    | The legs below                                                   |
| `spec/STATUS.md`               | The cited units                                                  |

## Tests

The harness holds, against the 2-of-3 topology of TEST-HARNESS-5:

- A second machine provisions from a copy of the shared set and reveals every
  entry through its own records (CER-PROVISION-7, TEST-HARNESS-5).
- A re-run on the same machine sends no `set_pin` when every wrap exists
  (CER-PROVISION-12).
- An added fourth oracle takes position 4, and the loop enrolls exactly the new
  pairs (CER-PROVISION-14).
- A retirement of position 3 deletes its wrap files, its canary seal, and its
  index wrap, and the report names the kit (CER-PROVISION-16).
- A threshold change from 2 to 3 leaves every old wrap useless and every new
  reveal working on three oracles. An interrupted change leaves the marker, and
  the re-run removes it (CER-PROVISION-15).
- A full run removes a `passphrase` marker (CER-PROVISION-17).
- A lock at one oracle makes that machine's records answer junk to every caller,
  and a later `set_pin` under the same key fails (ORC-REVOKE-8).
- Locks at `n − k + 1` oracles deny a quorum to the locked machine
  (ORC-REVOKE-10).
- A wiped record at one oracle blocks no reveal while two records remain, and
  the ceremony restores the third (REC-WIPE-6).
- The kit of a machine names the record files that the oracle store holds
  (ORC-REVOKE-6).
- The lock retires the machine name at that oracle, the index registry marks it,
  and the report says so (ORC-REVOKE-11, VAULT-INDEX-7).
- A provisioning run under a retired name refuses, and the refusal names a new
  machine name (CER-PROVISION-3).
- The lock leg of TEST-HARNESS-3 runs at each counterparty. One wrong attempt at
  the revocation counter, then junk on every `get_pin` and an HTTP error on
  every `set_pin` of that record.

## Acceptance

- `make check` passes on the host, and `make harness` passes.
- REC-WIPE, TEST-HARNESS, VAULT-INDEX, and KEY-MASK read `done`. ORC-PROVISION,
  ORC-COUNTER, and ORC-REVOKE read `partial` with the absent rules named.
- CER-PROVISION reads `partial`, and the documentation sentence of
  CER-PROVISION-13 is the absent part.
- The change deletes this plan.

## What this plan does not do

It restores no data from the plate: plan 010 does. It writes no runbook.
