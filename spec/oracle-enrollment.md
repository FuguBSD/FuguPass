# Oracle enrollment and reveal

This document is a part of the [oracle client](oracle.md) specification. It
specifies the enrollment of a record, the re-enrollment of a passphrase change,
and the reveal of a record.

<a id="orc-enroll"></a>

## Enrollment and re-enrollment

- **ORC-ENROLL-1** — The enrollment of a record at oracle `i` is one `set_pin`
  request under the record's client key `ck_ei`, with `pin_ei` as `pin_secret`.
  The response is the mask `s_ei` (FuguOracle OPS-SET-5). The enrollment of a
  slot covers each live oracle of the set: one `set_pin` request per live
  oracle.
- **ORC-ENROLL-2** — Every `set_pin` failure returns an HTTP error status
  (FuguOracle OPS-SET-7). The client must verify the HTTP success of every
  enrollment.
- **ORC-ENROLL-3** — After a successful enrollment at oracle `i`, the client
  must compute the wrap `c_ei` from the re-derived share
  ([KEY-SHARE](keys.md#key-share), [KEY-MASK](keys.md#key-mask)). It must
  persist the wrap in the machine-local set. It must then erase `s_ei` and the
  share from memory. The client must erase `K_e` directly after its last use
  ([SEC-MEMORY](security.md#sec-memory)).
- **ORC-ENROLL-4** — A passphrase change must re-enroll every record of the
  machine at every live oracle, without the master. For each slot, `get_pin`
  with the old pins at any `k` oracles unmasks `k` shares, and the
  reconstruction yields `K_e` ([ORC-QUORUM](oracle-quorum.md#orc-quorum),
  [KEY-SHARE](keys.md#key-share)). A `set_pin` with the new `pin_ei` at each
  oracle yields a fresh mask. The client recomputes that oracle's wrap from the
  re-derived share.
- **ORC-ENROLL-5** — The client must persist the new wrap of a record before the
  next `set_pin`. The loop order is each slot in turn, and inside a slot each
  oracle in list order. The canary records come last (ORC-ENROLL-10).
- **ORC-ENROLL-6** — The client must re-enroll the canary record of each oracle
  the same way. It must seal that oracle's canary check value under the fresh
  canary check seal key ([KEY-MASK](keys.md#key-mask)). It must re-wrap that
  oracle's index share from the re-derived `share(K_idx, i)` under the fresh
  canary mask. `K_idx` is in session memory from the index read
  ([KEY-MASK](keys.md#key-mask)). Without `K_idx`, the client must delete each
  affected index wrap file (ORC-CANARY-8), and the report must name the
  provisioning ceremony ([CER-PROVISION](ceremonies.md#cer-provision)).
- **ORC-ENROLL-7** — A passphrase change runs on one machine, over that
  machine's own records. Each other machine keeps the old passphrase on its own
  records until the change runs on that machine.
- **ORC-ENROLL-8** — The passphrase change must read the new passphrase twice
  with `readpassphrase(3)` and must require a match. On the initial run, the
  change must verify the old passphrase against the canary record of each live
  oracle before the first re-enrollment
  ([ORC-CANARY](oracle-quorum.md#orc-canary)). A resumed run verifies per
  ORC-ENROLL-10. The client must re-enroll a canary that fails for record-side
  causes (ORC-CANARY-5) before the change starts.
- **ORC-ENROLL-9** — Before the first `set_pin` of a slot, the client must
  verify the reconstructed `K_e`. The check is a decrypt of that slot's entry or
  slot file ([VAULT-SEAL](vault.md#vault-seal)). For the canary phase, the
  verification is the canary check decrypt of ORC-ENROLL-8. On a decrypt failure
  with an untried reachable oracle, the tool can retry with a different quorum.
  It runs the canary check of each substitute oracle first (ORC-QUORUM-5). A
  decrypt failure with no untried reachable oracle must stop the change before
  any `set_pin` of that slot. The client must report the failing slot and each
  quorum used. The change stays incomplete, and the marker records the progress
  (ORC-ENROLL-10).
- **ORC-ENROLL-10** — The client must persist the change marker with the kind
  `passphrase` in the machine-local set ([VAULT-LAYOUT](vault.md#vault-layout)).
  The marker holds the list of re-enrolled records by record name
  ([VAULT-FORMAT](vault.md#vault-format)). The client must persist the marker
  before the first `set_pin` of the change. The client must append a record's
  done line after that record's persisted writes, and before the next `set_pin`.
  Those writes are the wrap (ORC-ENROLL-5). For a canary, they also are the seal
  and the index wrap (ORC-ENROLL-6, ORC-CANARY-11). While the marker exists, a
  session must refuse reveals and must name the resume command. A restarted
  change must resume at the first unmigrated record. It uses the new pin for
  every record in the marker list, and the old pin for every other record. A
  resumed change must read both passphrases again. It must verify the old
  passphrase at the canary of each oracle whose canary is not in the marker
  list. It must verify the new passphrase at each canary in the marker list. The
  client must remove the marker after the last re-enrollment. The canary records
  re-enroll last, one per oracle. An interrupted change therefore still verifies
  with the old passphrase at every oracle whose canary is unmigrated.
- **ORC-ENROLL-11** — A passphrase change needs every live oracle reachable.
  With a live oracle unreachable, the change stays incomplete, and the marker
  stays. A change that starts with fewer than `k` reachable oracles must stop
  before the marker write and before the first re-enrollment
  ([ORC-QUORUM](oracle-quorum.md#orc-quorum)). Sessions refuse reveals until the
  change completes, or until a plate ceremony removes the marker
  (ORC-ENROLL-12). The quorum availability claim covers reveals only
  ([OVW-RISKS](overview.md#ovw-risks)).
- **ORC-ENROLL-12** — A plate ceremony that re-enrolls every record of this
  machine under one passphrase must remove the change marker. The ceremony
  report must name the removal (CER-PROVISION-17). This ceremony is the recovery
  path for a change blocked by a lost oracle.

A `set_pin` on an existing record replaces the record's key material at the
oracle. No oracle operation returns an old mask of that record (FuguOracle
OPS-SET-3 and FuguOracle OPS-SET-4). A `set_pin` also re-creates a missing
record: to the oracle, the request is a normal enrollment (FuguOracle
OPS-SET-2). A crash between a re-enrollment and its wrap write therefore loses
the wrap of one record at one oracle. The record recovers from the plate, never
from an oracle ([REC-WIPE](recovery.md#rec-wipe)). A crash between a record's
persisted writes and its done line leaves that one record migrated but unlisted.
The resume then addresses it with the old pin, and each attempt burns one strike
(FuguOracle OPS-GET-5). The record recovers by quorum substitution and a fresh
`set_pin` (ORC-ENROLL-9). The ordering rule ORC-ENROLL-5 bounds the loss to one
record at one oracle.

<a id="orc-reveal"></a>

## The reveal

- **ORC-REVEAL-1** — A reveal of a record at oracle `i` is one `get_pin` request
  under the record's client key `ck_ei`, with `pin_ei` as `pin_secret`.
- **ORC-REVEAL-2** — On a correct pin, the answer is the mask `s_ei`, stable for
  an unchanged record: identical bytes on every correct request. Stability is a
  consequence of FuguOracle OPS-GET-4, never a stated interface guarantee.
  [TEST-MASK](testing.md#test-mask) pins it by test.
- **ORC-REVEAL-3** — The client must unmask oracle `i`'s share as
  `share(K_e, i) = c_ei ⊕ f(s_ei, "fugupass/v1/wrap" ‖ i/e)`
  ([KEY-MASK](keys.md#key-mask)). [ORC-QUORUM](oracle-quorum.md#orc-quorum)
  governs the reconstruction and the entry decrypt.
- **ORC-REVEAL-4** — A wrong passphrase, a missing or wiped record, and a
  counter violation all return junk, indistinguishable by response bytes
  (FuguOracle OPS-JUNK-2). The only failure signal is the client's own decrypt
  failure, and the client cannot learn the cause from the response bytes.
- **ORC-REVEAL-5** — The third wrong attempt on a record destroys that record's
  key material at the oracle (FuguOracle OPS-GET-6). The entry still reveals
  while `k` live records remain for it
  ([ORC-QUORUM](oracle-quorum.md#orc-quorum)). Recovery of the record is a plate
  ceremony or the re-enrollment loop of a passphrase change
  ([REC-WIPE](recovery.md#rec-wipe)).
- **ORC-REVEAL-6** — An HTTP error status is not an attempt, and the request is
  retryable. An attempt that the oracle cannot count receives no answer
  (FuguOracle OPS-GET-7). A transport failure after the client sends the request
  is ambiguous. The oracle persists a record change before it sends the response
  (FuguOracle OPS-GET-7), so a lost response can follow a counted attempt. The
  client must report an HTTP error, a transport failure, and a junk answer as
  distinct states, with distinct user reports.
- **ORC-REVEAL-7** — `K_e` must exist in memory for seconds only, and `M` must
  not appear in a reveal ([SEC-MEMORY](security.md#sec-memory)).
- **ORC-REVEAL-8** — A `200` response whose envelope MAC or decrypt fails is an
  oracle-authentication failure. It is a distinct client state: it is not a junk
  answer, and it does not prove that the oracle skipped the attempt. The tool
  must report it as a provisioning or transport fault, distinct from the junk
  report and from the HTTP-error report.
