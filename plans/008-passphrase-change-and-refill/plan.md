# 008 — The passphrase change and the pool refill

## Status

Proposed. It waits on no other plan. Plan 009 waits on it for the change marker.

Implements: ORC-ENROLL, CER-REFILL, TEST-HARNESS. Implements: ORC-CANARY without
ORC-CANARY-10. Defers: CER-PROVISION.

This plan completes ORC-ENROLL with ORC-ENROLL-4 to ORC-ENROLL-12. It adds the
passphrase change leg of TEST-HARNESS-5, and plan 009 adds the provisioning
loop. ORC-CANARY stays `partial` on ORC-CANARY-10, a statement of plan 013. The
threshold change shares the marker and lands in plan 009.

## Purpose

A passphrase change re-enrolls every record of the machine at every live oracle,
without the master (ORC-ENROLL-4). A pool refill extends the free slots with the
master present (CER-REFILL). Both are loops over records with a `set_pin` per
record, and both must survive an interruption. This plan lands the two loops,
the change marker, and the resume.

## Constraints that shape the design

**The marker comes before the first request.** The change persists the marker
with the kind `passphrase` before its first `set_pin`. It appends a done line
after each record's persisted writes, and removes the marker after the last
record (ORC-ENROLL-10). While the marker exists, a session refuses reveals and
names the resume command (ORC-ENROLL-10, ORC-ENROLL-11).

**The loop order bounds the loss.** Each slot in turn, and inside a slot each
oracle in list order, with the new wrap persisted before the next `set_pin`
(ORC-ENROLL-5). The canary records come last (ORC-ENROLL-10). A crash then loses
at most one wrap at one oracle, and the plate recovers it.

**Verification precedes every replacement.** The change reads both passphrases
twice, and verifies the old one at each live canary. It re-enrolls a canary that
fails for record-side causes first (ORC-ENROLL-8). Before the first `set_pin` of
a slot it reconstructs `K_e` through the quorum and decrypts the slot's file
(ORC-ENROLL-9). A decrypt failure with no untried reachable oracle stops the
change before any `set_pin` of that slot. The report holds the slot and each
quorum.

**The resume splits the records by the marker.** A restarted change uses the new
pin for every record in the marker list and the old pin for every other record.
It verifies the old passphrase at each unlisted canary and the new one at each
listed canary (ORC-ENROLL-10).

**The canary re-wrap needs `K_idx`.** After a canary re-enrollment the change
seals the fresh canary check value. It re-wraps the index share under the fresh
mask, with `K_idx` from the session (ORC-ENROLL-6). Without `K_idx` it deletes
the index wrap file and names the provisioning ceremony.

**The refill is the slot loop again.** The refill scans the plate, verifies the
passphrase at each live canary, and reserves the next sequential indexes. It
runs the slot loop of CER-CREATE-6 for each new slot. It records the pool state
in the index, and erases the master (CER-REFILL-1 to CER-REFILL-7). It refuses
to start while the marker exists (CER-REFILL-8). It changes no existing entry
(CER-REFILL-4).

## Files

| File                           | Change                                           |
| ------------------------------ | ------------------------------------------------ |
| `src/change.c`, `src/change.h` | The passphrase change, the marker, the resume    |
| `src/ceremony.c`               | The refill                                       |
| `src/session.c`                | The refusal while the marker exists              |
| `src/fugupass.c`               | The `passwd`, `resume`, and `refill` subcommands |
| `src/fugupass/fugupass.1`      | The three subcommands and the marker             |
| `tests/harness.d/change`       | The legs below                                   |
| `spec/STATUS.md`               | The cited units                                  |

## Tests

The harness holds, against the 2-of-3 topology of TEST-HARNESS-5:

- A passphrase change over three oracles ends with every record under the new
  pin, every wrap fresh, and no marker (ORC-ENROLL-4, TEST-HARNESS-5).
- A change that stops after the third record leaves a marker with three done
  lines. A session then refuses a reveal and names the resume. The resume
  completes the change, and every record answers the new pin (ORC-ENROLL-10).
- A change with one oracle stopped stays incomplete with its marker, and a
  restart after the oracle returns completes it (ORC-ENROLL-11).
- A mistyped old passphrase stops the change at the first canary with no
  `set_pin` sent (ORC-ENROLL-8).
- A slot file with one damaged byte stops the change at that slot before its
  `set_pin`. The report holds the slot and the quorums (ORC-ENROLL-9).
- A refill with the stub master adds 64 slots, keeps every existing entry
  byte-identical, and records `pool-next` in the index (CER-REFILL-2,
  CER-REFILL-4).
- A refill with the marker present refuses to start (CER-REFILL-8).

## Acceptance

- `make check` passes on the host, and `make harness` passes.
- ORC-ENROLL and CER-REFILL read `done`. ORC-CANARY reads `partial` with
  ORC-CANARY-10 as the absent rule.
- TEST-HARNESS reads `partial`, and the provisioning loop of TEST-HARNESS-5 is
  the absent part.
- The change deletes this plan.

## What this plan does not do

It adds no machine, changes no threshold, and removes no marker by ceremony:
plan 009 holds those paths.
