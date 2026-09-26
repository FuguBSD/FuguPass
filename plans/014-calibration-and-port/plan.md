# 014 — Calibration, the audit, and the port

## Status

Proposed. It waits on plan 013, so the port packages the complete programs and
pages. The latency measurement needs real OpenBSD hardware, and the operator
supplies it.

Implements: TEST-CALIBRATE.

## Purpose

The round count of `bcrypt_pbkdf(3)` sets the cost of an offline passphrase
search, and a wrong default is either slow or weak (D-09). This plan lands the
calibration record, the scaling check against a flat-file oracle, and the
sandbox and memory-hygiene audit of the P4 exit. It also lands the OpenBSD port
with p5-Fugu as its run dependency.

## Constraints that shape the design

**Latency measures on hardware.** The calibration runs `bcrypt_pbkdf(3)` at a
range of round counts on a target laptop. It runs in no guest, because emulation
gives a false count (TEST-CALIBRATE-4). It weighs the unlock latency, times `k`
per reveal, against the search cost on the attack hardware that the record names
(TEST-CALIBRATE-1). The record holds the measurements, the assumption, and the
chosen default, and the default enters the config writer of plan 006
(TEST-CALIBRATE-2).

**The scaling check runs in a guest.** The check enrolls hundreds of records at
a FuguOracle instance in the guest, through the ceremonies of plan 006 and
plan 009. It records the request rate, the store size, and the time per ceremony
against the posture of a few requests per day (TEST-CALIBRATE-3, ORC-RECORDS-4).
A guest snapshot holds the enrolled set. The result goes to the FuguOracle
project as a measured number for its workload assumption.

**The audit is a checklist with evidence.** The developer runs each program in
the guest under `ktrace(1)` and confirms the pledge promises and the unveil list
of PROG-SPLIT against the syscalls. The developer greps every exit path of a
secret for `explicit_bzero(3)` and every secret comparison for
`timingsafe_bcmp(3)` (SEC-MEMORY). The record lists each finding and its fix.

**The port is one directory.** `ports/security/fugupass` builds the four
programs from a release tag, and installs them with the five manual pages. It
declares `devel/p5-Fugu` as a run dependency and `graphics/libqrencode` as a
library dependency (PROG-PORT-1 to PROG-PORT-3). The distfile is a tag of this
repository through the GitHub mechanism of the ports tree.

## Files

| File                               | Change                                                    |
| ---------------------------------- | --------------------------------------------------------- |
| `docs/analysis/kdf-calibration.md` | The calibration record                                    |
| `docs/analysis/scaling-check.md`   | The scaling record                                        |
| `docs/analysis/sandbox-audit.md`   | The audit record                                          |
| `tests/calibrate.c`                | The round count timer, built in the guest and on hardware |
| `tests/harness.d/scale`            | The scaling leg                                           |
| `src/vault.c`                      | The default round count                                   |
| `spec/STATUS.md`                   | The cited units                                           |

## Tests

- `tests/calibrate` prints one line per round count with the measured
  milliseconds, on the hardware that the record names.
- The scaling leg enrolls 300 records on 3 machines at one FuguOracle instance
  and records the numbers.
- `make port-lib-depends-check` and `portcheck` pass, and `make regress` of the
  port runs the offline tests.
- A `pkg_add` of the built package runs `fugupass create` against an oracle in
  the guest.

## Acceptance

- `make check` passes on the host, and the port builds on amd64 and on arm64.
- TEST-CALIBRATE reads `done`, and PROG-PORT reads `done`.
- The change deletes this plan.

## Open questions

The `devel/p5-Fugu` port of the Fugu repository must be in place before this
port builds. The ports tree or a local ports directory of the guest holds it.
The default round count is the operator's choice from the measurements, not the
developer's.

## What this plan does not do

It submits nothing to the ports tree: the submission is the operator's act.
