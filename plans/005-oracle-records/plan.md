# 005 — The oracle records and the interop harness

## Status

Proposed. It waits on plan 002 for the vault files and on plan 004 for the
envelope. Plan 006 waits on it.

Implements: ORC-REVEAL, TEST-MASK, ORC-CONFORM. Implements: ORC-RECORDS without
ORC-RECORDS-4. Implements: ORC-COUNTER without ORC-COUNTER-7. Implements:
ORC-ENROLL without the passphrase change rules ORC-ENROLL-4 to ORC-ENROLL-12.
Implements: ORC-CANARY without ORC-CANARY-1, ORC-CANARY-3, ORC-CANARY-4, and
ORC-CANARY-8 to ORC-CANARY-10. Implements: ORC-PROVISION without ORC-PROVISION-3
and ORC-PROVISION-6 to ORC-PROVISION-8. Implements: SEC-ENTROPY. Implements:
KEY-MASK without KEY-MASK-8. Implements: TEST-HARNESS without TEST-HARNESS-5 and
TEST-HARNESS-8. Defers: ORC-QUORUM, ENTRY-POOL, CER-CREATE.

This plan lands the record side of the canary: ORC-CANARY-2, ORC-CANARY-5,
ORC-CANARY-6, ORC-CANARY-7, and ORC-CANARY-11. The session rules of the canary
are plan 007, and ORC-CANARY-10 is a statement of plan 013. Of ORC-PROVISION it
lands ORC-PROVISION-1, ORC-PROVISION-2, ORC-PROVISION-4, ORC-PROVISION-5, and
ORC-PROVISION-9. The list changes are plan 009, and the statements are plan 013.
It completes ORC-CONFORM, KEY-MASK-4, and SEC-ENTROPY-4. KEY-MASK-8 is the plate
ceremony of plan 006. Plan 006 also writes the index wrap of KEY-MASK-7. The
quorum leg and the terminal driver of the harness follow in plan 006 and
plan 007.

## Purpose

Each entry has one record at each oracle, on each machine (D-07). This plan
lands the record client: the enrollment of one record, the reveal of one record,
and the counters file. It also lands the canary record of one oracle. It also
lands the interop harness that runs the record client against the upstream
server. It also lands the mask-stability test that the custody layer rests on
(D-19).

## Constraints that shape the design

**One record, one request.** `oracle.c` enrolls a record with one `set_pin`
under `ck_ei` and `pin_ei`, with 32 fresh entropy bytes, and it verifies the
HTTP success (ORC-ENROLL-1, ORC-ENROLL-2). It then computes the wrap from the
re-derived share, persists it, and erases the mask and the share (ORC-ENROLL-3).
A reveal is one `get_pin`, and the unmask returns the share of that oracle
(ORC-REVEAL-1, ORC-REVEAL-3). The reconstruction of `K_e` is the quorum of
plan 007.

**The counter is the clock.** The sent counter is
`max(wall-clock seconds, stored + 1)`, and the counters file holds the last
value per record name (ORC-COUNTER-1, ORC-COUNTER-2). The client never sends
`0xFFFFFFFF` outside a revocation (ORC-COUNTER-5), and plan 009 lands that
exception.

**Four states, four reports.** The record client returns the HTTP error, the
transport failure, the authentication failure, and the junk answer as four
values (ORC-REVEAL-6, ORC-REVEAL-8). The junk answer exists only after the
caller's own decrypt fails, so the record client returns a candidate share and
the caller decides.

**The canary is a record with a constant.** The canary enrollment reads the
passphrase twice, warns that no verifier exists, enrolls, and verifies with one
immediate `get_pin`. It then seals 32 zero bytes under the canary check seal key
and persists the seal (ORC-CANARY-2, ORC-CANARY-6, ORC-CANARY-7, ORC-CANARY-11).
The client can re-enroll a canary at any time (ORC-CANARY-5).

**A driver stands in for the program.** `src/regress/oracle-client` is a small C
program. It reads the oracle URL, the static key, the device factor, the slot,
and the oracle index as arguments. It reads the passphrase on standard input. It
enrolls, reveals, or verifies a canary, and it prints the state as one word. The
harness drives it before `fugupass` exists, and the six commands of plan 007
replace no line of it.

**The harness starts the counterparty as data.** `tests/harness` is a Perl
program on Fugu, on the host. It starts the upstream server with `Fugu::Process`
and an argument list, and waits for readiness with `Fugu::Timeout::wait_until`.
It gives the server a fresh record store, and removes the store after the run
(TEST-HARNESS-6). The start recipe of each counterparty is one data record, so
the suite never branches on the counterparty (TEST-HARNESS-4). The legs run in
the guest through `fuguvm put` and `fuguvm ssh`, and the client reaches the host
server at the QEMU gateway address (TEST-HARNESS-7). When a FuguOracle build
exists, a second record names its stack in the guest, and the same legs run
against it (TEST-HARNESS-2).

## Files

| File                                | Change                                                   |
| ----------------------------------- | -------------------------------------------------------- |
| `src/oracle.c`, `src/oracle.h`      | The records, the counters, the canary, the states        |
| `src/regress/oracle-client.c`       | The driver                                               |
| `tests/harness`                     | The harness, and the two counterparty records            |
| `tests/harness.d/`                  | The legs: enroll, reveal, states, counters, canary, mask |
| `mk/local.mk`                       | The `harness` target                                     |
| `deps/Darwin.txt`, `deps/Linux.txt` | `Fugu`, for the harness                                  |
| `spec/STATUS.md`                    | The cited units                                          |

## Tests

The harness holds, against each counterparty:

- An enrollment then a reveal return the enrolled mask, and the wrap file exists
  (ORC-ENROLL-1 to ORC-ENROLL-3).
- A wrong passphrase, a wiped record, and a stale counter each return a share
  that fails the caller's decrypt, with identical response sizes (ORC-REVEAL-4).
- A stopped counterparty is a transport failure, and a `500` is an HTTP error. A
  wrong static key is an authentication failure. Each has its own report
  (ORC-REVEAL-6, ORC-REVEAL-8).
- A removed counters file re-establishes a valid counter from the clock. A stale
  stored counter takes the junk path and burns no strike (ORC-COUNTER-3,
  ORC-COUNTER-6).
- A canary enrollment, its round trip, and its seal pass, and a mistyped second
  read stops the enrollment (ORC-CANARY-6, ORC-CANARY-7).
- The mask stays identical over ten reveals, and a re-enrollment changes it. A
  third strike ends it with junk that never equals the old mask, and two junk
  answers differ (TEST-MASK-1 to TEST-MASK-4). Each run starts a fresh store
  (TEST-MASK-6).

## Acceptance

- `make check` passes on the host, and `make harness` passes against the
  upstream server.
- ORC-REVEAL, TEST-MASK, ORC-CONFORM, and SEC-ENTROPY read `done`.
- ORC-RECORDS, ORC-ENROLL, ORC-CANARY, ORC-PROVISION, KEY-MASK, and TEST-HARNESS
  read `partial` with the absent rules named.
- ORC-COUNTER reads `partial` with ORC-COUNTER-7 as the absent rule. The
  revocation exception of ORC-COUNTER-1 and ORC-COUNTER-5 is the absent part,
  and plan 009 lands it.
- The KEY-MASK note also names the absent index wrap of KEY-MASK-7.
- The TEST-HARNESS note also names the absent parts of TEST-HARNESS-3. The
  quorum coverage lands in plan 007, and the re-enrollment coverage lands in
  plan 008.
- The change deletes this plan.

## What this plan does not do

It reconstructs no entry key and opens no entry. It creates no vault, and it
drives no terminal.
