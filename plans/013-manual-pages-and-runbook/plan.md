# 013 — The manual pages and the runbook

## Status

Proposed. It waits on plan 009 and plan 012, so that every program and every
procedure exists before the pages state their limits.

Implements: SEC-FLOOR, SEC-DETECT, SEC-CLAIMS. Implements: VAULT-CONFIG,
VAULT-BACKUP, ORC-PROVISION, ORC-RECORDS, ORC-COUNTER, ORC-CANARY, ORC-REVOKE,
CER-PROVISION.

Each of the eight shared units holds one or two statements for the
documentation, and this plan lands them. The statements are VAULT-CONFIG-5,
VAULT-BACKUP-3, ORC-PROVISION-3 and ORC-PROVISION-8, ORC-RECORDS-4,
ORC-COUNTER-7, ORC-CANARY-10, ORC-REVOKE-7 and ORC-REVOKE-9, and the last
sentence of CER-PROVISION-13. Each unit then reads `done`.

## Purpose

The honest bounds of the design are documentation duties (SEC-FLOOR, SEC-DETECT,
SEC-CLAIMS). This plan lands the one page that holds them, `fugupass(7)`, the
operator runbook. It completes the statements that the other units place in the
manual pages. It also lands the test that keeps a prohibited claim out of every
page.

## Constraints that shape the design

**One page holds the operator text.** `fugupass(7)` follows `fuguseed(7)` of
FuguSeed: a section 7 page in ASD-STE100. It holds the threat table of OVW-RISKS
in prose, and the offline floor and its three cases (SEC-FLOOR-2 to
SEC-FLOOR-4). It also holds the detection duties and the coverage bound
(SEC-DETECT-3 to SEC-DETECT-6), and the runbook of SEC-DETECT-5. The runbook
covers the provisioning of each oracle, the 2-of-3 example, and the log reading
at each oracle. It also covers the log coverage of every quorum, and the
revocation.

**The other pages point, and one page holds.** Each fact lives in one page.
`fugupass(1)` holds what a copy of the config leaks (VAULT-CONFIG-5), the one
minting machine (VAULT-BACKUP-3), and the same list on every machine
(ORC-PROVISION-8). It also holds the load against the oracle posture
(ORC-RECORDS-4), the counter residuals (ORC-COUNTER-7), the poisoned canary
(ORC-CANARY-10), and the weakest threshold (CER-PROVISION-13). `fugupass(7)`
holds the transport risks that TLS mitigates (ORC-PROVISION-3), the operator
paths (ORC-REVOKE-7), and the restore residual of the oracle (ORC-REVOKE-9).
Each page points to the other for the rest.

**The detection story rests on FuguOracle alone.** The pages promise one log
line per request with the outcome class and a prominent wipe line, and nothing
more (SEC-DETECT-1, SEC-DETECT-2). They state that detection is manual and that
slow malware looks like the owner (SEC-DETECT-3, SEC-DETECT-4).

**A test keeps the claims honest.** `t/fugupass/claims.t` scans every manual
page and every document under `docs/` for the words of the prohibited claims.
The words are coercion, freeze, delayed reveal, velocity, alarm, and rate limit
(SEC-CLAIMS-1 to SEC-CLAIMS-3). A hit outside the sentence that prohibits the
claim fails the test. The scan mirrors the vocabulary test.

## Files

| File                      | Change                                        |
| ------------------------- | --------------------------------------------- |
| `src/fugupass/fugupass.7` | The runbook and the bounds                    |
| `src/fugupass/fugupass.1` | The statements listed above                   |
| `src/fugupass/Makefile`   | The second page                               |
| `t/fugupass/claims.t`     | The prohibited claims scan                    |
| `t/fugupass/man.t`        | `mandoc -Tlint` on every page, as in FuguSeed |
| `spec/STATUS.md`          | The cited units                               |

## Tests

- `t/fugupass/claims.t` passes on the pages, and fails on a page with the word
  "freeze" outside the prohibition sentence.
- `t/fugupass/man.t` reports no `mandoc -Tlint` error on the five pages.
- Each statement above has one home: a grep for its key phrase hits one page.
- The runbook holds the `n − k + 1` bound with the 2-of-3 numbers worked out
  (SEC-DETECT-6).

## Acceptance

- `make check` passes on the host.
- Every cited unit reads `done`.
- The change deletes this plan.

## What this plan does not do

It measures nothing: the calibration and the scaling check are plan 014. It adds
no code path.
