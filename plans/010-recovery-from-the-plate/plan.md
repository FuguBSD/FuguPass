# 010 — Recovery from the plate

## Status

Proposed. It waits on plan 006 for the program and the scan boundary. Its
harness legs wait on plan 007 for a vault and on plan 009 for a second machine.

Implements: REC-PLATE, REC-VAULT, REC-RESTORE, CER-VERIFY. Implements:
PROG-REPL, PROG-ONESHOT. Defers: PROG-SCAN, ORC-ENROLL.

Of PROG-REPL, this plan lands PROG-REPL-6. Of PROG-ONESHOT, it lands the
recovery and verification subcommands of PROG-ONESHOT-4. REC-VAULT-4 names the
re-enrollment of plan 009 as its second step, and this plan lands the restore
half.

## Purpose

The oracle gates reveals and never recovery (D-04). This plan lands the paths
that need no oracle and no passphrase: plate-alone recovery and plate-plus-files
recovery. It also lands the restore from a backup copy, and plate verification.
After it, a person with the plate and nothing else gets every derived secret
back.

## Constraints that shape the design

**Recovery is derivation in a loop.** Plate-alone recovery scans the plate,
re-derives `K_e` for every slot from 0 to the ceiling, and re-materializes both
BIP85 candidates (REC-PLATE-1). The ceiling is 1024 slots, the report names the
scanned range, and a `--ceiling` option raises it (REC-PLATE-2). An unused slot
maps to no entry and costs nothing (REC-PLATE-3).

**With files, the name is the match.** Plate-plus-files recovery computes
`H(K_e)` for each slot and matches the entry file by its name, with no index
(REC-VAULT-1). Each match decrypts under its `K_e`, and the index opens under
`K_idx` from `root` (REC-VAULT-2, REC-VAULT-3). A stale index degrades names
only (REC-RESTORE-5).

**A restore is a file copy.** Any copy of the shared set restores by copy onto a
machine that keeps its machine-local set (REC-RESTORE-1). The counters stay
valid through the clock (REC-RESTORE-2). A fresh machine is a provisioning
ceremony (REC-RESTORE-3). The manual page states the four cases of REC-RESTORE-4
to REC-RESTORE-6 and the limit of REC-PLATE-5.

**Verification touches no record.** `fugupass verify` scans the plate,
re-derives the plate check value, and compares it with the config (CER-VERIFY-1,
CER-VERIFY-2). On a match it records the date in the index under `K_idx` from
`root`, and it erases `M`, `root`, and `K_idx` (CER-VERIFY-4, CER-VERIFY-5). The
audit of plan 007 reports that date (CER-VERIFY-3).

**Secrets print, and nothing else.** A recovered secret follows PROG-OUTPUT: the
terminal, one entry at a time, and never a file. The master clears at the end of
each path.

## Files

| File                             | Change                                         |
| -------------------------------- | ---------------------------------------------- |
| `src/recover.c`, `src/recover.h` | The two recovery paths                         |
| `src/ceremony.c`                 | Plate verification                             |
| `src/fugupass.c`                 | The `recover` and `verify` subcommands         |
| `src/fugupass/fugupass.1`        | The subcommands, the restore cases, the limits |
| `tests/harness.d/recover`        | The legs below                                 |
| `spec/STATUS.md`                 | The cited units                                |

## Tests

The harness holds, with the stub master and no oracle running:

- `fugupass recover` from the plate alone prints every derived secret of a vault
  that plan 007 built, up to the last used slot. It reports the range
  (REC-PLATE-1, REC-PLATE-2).
- `fugupass recover <dir>` on a copy of the shared set returns every stored
  entry and every entry name, with no `machine/` directory present (REC-VAULT-1
  to REC-VAULT-3).
- A copy without the index returns every entry by file name (REC-RESTORE-5).
- A copy of the shared set onto a second provisioned machine reveals every entry
  there, and its counters stay valid (REC-RESTORE-1, REC-RESTORE-2).
- `fugupass verify` matches the plate of the vault, and records the date. It
  rejects the plate of another test master with a report that names a wrong or
  damaged plate (CER-VERIFY-1, CER-VERIFY-5).
- No path of this plan sends one request: the harness runs the legs with every
  counterparty stopped (REC-PRINCIPLE-4).

## Acceptance

- `make check` passes on the host, and `make harness` passes.
- REC-PLATE, REC-VAULT, REC-RESTORE, and CER-VERIFY read `done`. PROG-ONESHOT
  reads `partial` with the absent rules named.
- PROG-REPL reads `done` after plan 011 lands PROG-REPL-7 to PROG-REPL-9, and
  the later of the two plans sets the row.
- The change deletes this plan.

## What this plan does not do

It re-enrolls nothing: the reveal flow after a recovery returns through
plan 009. It reads no camera.
