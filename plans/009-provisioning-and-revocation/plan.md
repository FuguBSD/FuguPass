# 009 — Machine provisioning, revocation, and recovery after oracle loss

## Status

Proposed. It waits on plan 008 for the change marker. It completes the quorum
leg of the harness.

Implements: CER-PROVISION, REC-WIPE, TEST-HARNESS. Implements: ORC-REVOKE
without ORC-REVOKE-7 and ORC-REVOKE-9. Implements: ORC-PROVISION, ORC-COUNTER.

Of ORC-PROVISION, this plan lands ORC-PROVISION-6 and ORC-PROVISION-7, the list
changes. It adds the revocation exception of ORC-COUNTER-1 and ORC-COUNTER-5.
CER-PROVISION-13 holds one statement for the documentation, and plan 013 lands
that sentence. ORC-REVOKE-7 and ORC-REVOKE-9 are statements of plan 013 too. It
completes TEST-HARNESS-5 with the provisioning loop.

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

**A lock burns the machine name at that oracle.** A record with the stored
counter `0xFFFFFFFF` accepts no later `set_pin`, because the oracle rejects a
counter that is not greater (FuguOracle OPS-SET-2). The records of a revoked
machine name at a locked oracle can therefore never re-enroll, and REC-WIPE-2
and CER-PROVISION-12 do not reach them. The revocation report states that the
machine name retires, and a replacement machine provisions under a new name. The
implementation adds this rule to ORC-REVOKE, because the specification holds no
sentence for it today.

**A wiped or lost record heals in the loop.** After a wipe, a host loss, or a
static key rotation, the ceremony deletes the files of the position. It
re-enrolls the affected pairs (REC-WIPE-2, CER-PROVISION-16). A fresh `set_pin`
creates fresh key material, so no old mask returns (REC-WIPE-3).

## Files

| File                           | Change                                                 |
| ------------------------------ | ------------------------------------------------------ |
| `src/ceremony.c`               | Machine provisioning and its variants                  |
| `src/revoke.c`, `src/revoke.h` | The kit, the lock, the replacement                     |
| `src/oracle.c`                 | The revocation counter exception                       |
| `src/fugupass.c`               | The `provision`, `revoke`, and `kit` subcommands       |
| `src/fugupass/fugupass.1`      | The subcommands, the variants, the burned machine name |
| `tests/harness.d/provision`    | The legs below                                         |
| `spec/STATUS.md`               | The cited units                                        |

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
- The lock leaves a machine name that cannot re-enroll at that oracle, and the
  report says so.

## Acceptance

- `make check` passes on the host, and `make harness` passes.
- CER-PROVISION, REC-WIPE, TEST-HARNESS, ORC-PROVISION, and ORC-COUNTER read
  `done`. ORC-REVOKE reads `partial` with ORC-REVOKE-7 and ORC-REVOKE-9 as the
  absent rules.
- The change deletes this plan.

## What this plan does not do

It restores no data from the plate: plan 010 does. It writes no runbook.
