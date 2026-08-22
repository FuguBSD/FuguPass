# Blind-oracle client

This document specifies the FuguPass oracle client. FuguPass is a client of the
Blockstream `blind_pin_server` wire protocol, version 2. FuguOracle is the
reference deployment, not a requirement (D-02). [keys.md](keys.md) defines the
notation `K_e`, `ck_ei`, `pin_ei`, `s_ei`, `c_ei`, `s_canary_i`, `c_idx_i`,
`K_idx`, `share(S, i)`, `n`, and `k`. This document cites FuguOracle rules as
prose tokens, for example FuguOracle OPS-GET-4.

<a id="orc-conform"></a>

## Protocol conformance

- **ORC-CONFORM-1** — FuguPass must speak unmodified `blind_pin_server` protocol
  v2 to any conforming oracle and must not require a change to FuguOracle
  (D-02).
- **ORC-CONFORM-2** — The client must conform to the FuguOracle client model
  (FuguOracle CLIENT-MODEL). The client key of a record must not depend on the
  passphrase ([KEY-CLIENT](keys.md#key-client)). The client must enroll a record
  with `set_pin` and must reveal a mask with `get_pin`.
- **ORC-CONFORM-3** — The passphrase must enter a request as the `pin_secret`
  value only ([KEY-PIN](keys.md#key-pin)).
- **ORC-CONFORM-4** — The client must authenticate the oracle with the envelope
  MAC, computed from the provisioned static public key of that oracle. TLS is
  not the authenticator.
- **ORC-CONFORM-5** — Every request must use a fresh ephemeral keypair and a
  fresh IV from `arc4random(3)`. Every `set_pin` request must carry 32 bytes of
  fresh entropy from `arc4random(3)`.

The interop harness proves conformance against every available conforming oracle
([QA-HARNESS](testing.md#qa-harness)).

<a id="orc-provision"></a>

## Provisioning

- **ORC-PROVISION-1** — The config file must hold, for each oracle position, the
  two provisioned values: the oracle URL and the static public key as a hex
  string. This mirrors FuguOracle CLIENT-PROVISION-1. The full config field list
  is in [VAULT-CONFIG](vault.md#vault-config); this unit governs the oracle
  values only.
- **ORC-PROVISION-2** — A vault must use one ordered oracle set of `n` oracles
  and one threshold `k`, with `1 ≤ k ≤ n ≤ 255`, both vault-wide (D-20,
  [VAULT-CONFIG](vault.md#vault-config)).
- **ORC-PROVISION-3** — The client must not require TLS: the envelope
  authenticates the oracle (FuguOracle CLIENT-PROVISION-2). The documentation
  must name the transport risks that TLS mitigates: traffic metadata,
  availability, and envelope replay.
- **ORC-PROVISION-4** — An oracle URL must not end with a slash. The client
  appends `/get_pin` and `/set_pin` to each URL to build the request paths
  (FuguOracle CLIENT-PROVISION-1).
- **ORC-PROVISION-5** — The oracle index `i` of an oracle is its 1-based
  position in the ordered list. The index enters the derivation labels and the
  share evaluation points ([KEY-CLIENT](keys.md#key-client),
  [KEY-PIN](keys.md#key-pin), [KEY-SHARE](keys.md#key-share)). The tool must not
  reorder the list, and a position must not change its index (D-20).
- **ORC-PROVISION-6** — The value of a position can change to a replacement
  oracle or to the retired state ([VAULT-CONFIG](vault.md#vault-config)). A
  replacement orphans this machine's records at that position, and a plate
  ceremony re-enrolls them ([CER-PROVISION](ceremonies.md#cer-provision),
  [REC-WIPE](recovery.md#rec-wipe)). A retired position keeps its index, and no
  oracle takes it. The threshold `k` must not exceed the count of live
  positions. On the retirement of a position, the tool must delete this
  machine's wrap files, canary check seal, and index wrap of that position: the
  shares re-derive from the plate, so nothing is lost
  ([KEY-SHARE](keys.md#key-share)). The documentation must direct the owner to
  destroy this vault's records at the departing oracle with the revocation kit
  ([ORC-REVOKE](oracle.md#orc-revoke)) before the config discards the URL.
- **ORC-PROVISION-7** — A change of the oracle list or of the threshold is a
  plate ceremony ([CER-PROVISION](ceremonies.md#cer-provision)).
- **ORC-PROVISION-8** — The documentation must state that every machine of a
  vault must record the same ordered oracle list and the same threshold.
  Revocation from the plate re-derives a stolen machine's client keys from this
  list ([ORC-REVOKE](oracle.md#orc-revoke)), so a divergent list breaks
  revocation, and a divergent list on a ceremony machine enrolls records that
  other flows cannot address.
- **ORC-PROVISION-9** — A live position is a config position that is not retired
  ([VAULT-CONFIG](vault.md#vault-config)). A live oracle is the oracle of a live
  position. A reachable oracle is a live oracle that answers.

<a id="orc-records"></a>

## Per-entry records

- **ORC-RECORDS-1** — Each entry must use one oracle record at each oracle of
  the set, on each machine (D-07).
- **ORC-RECORDS-2** — Each machine must hold one canary record at each oracle
  ([ORC-CANARY](oracle.md#orc-canary)).
- **ORC-RECORDS-3** — To the oracle, every record is an independent client.
  FuguOracle OVR-PURPOSE-4 permits many clients on one instance. Each record
  burns its own three strikes, so a wipe destroys one record and touches no
  other. A record holds no entry name, no purpose, and no content.
- **ORC-RECORDS-4** — The documentation must state the load that FuguPass
  generates against the stated workload assumption of the oracle: `k` `get_pin`
  requests per revealed entry, and one `set_pin` request per live oracle for
  each slot of each machine at enrollment.

A session that reveals ten entries sends ten entry requests plus one canary
request to each quorum oracle. One oracle instance sees one request per event;
the multiplier spreads across instances. This load can exceed the oracle
workload assumption of a few requests per day. This is a posture mismatch on a
self-hosted oracle, not a correctness problem. The scaling check in
[QA-CALIBRATE](testing.md#qa-calibrate) records the result.

<a id="orc-counter"></a>

## Replay counters

- **ORC-COUNTER-1** — The counter sent for a record must be
  `max(wall-clock Unix seconds, stored + 1)`, encoded as uint32 LE. A revocation
  request is the one exception ([ORC-REVOKE](oracle.md#orc-revoke)).
- **ORC-COUNTER-2** — The client must persist the last-sent counter of each
  record in the plaintext counters file, keyed by record name. The record names
  are `<e>-<i>` and `canary-<i>` ([VAULT-FORMAT](vault.md#vault-format)). The
  counters file is in the machine-local set
  ([VAULT-LAYOUT](vault.md#vault-layout)).
- **ORC-COUNTER-3** — The counters file must hold no secret. The loss of the
  counters file is safe: the wall-clock term re-establishes a valid counter.
- **ORC-COUNTER-4** — A vault restored from an old copy must stay able to
  address its records. The wall clock exceeds any stale stored counter.
- **ORC-COUNTER-5** — The client must not send the counter value `0xFFFFFFFF`,
  except in a revocation request ([ORC-REVOKE](oracle.md#orc-revoke)). A
  persisted counter of `0xFFFFFFFF` leaves no strictly greater value, so the
  record becomes unaddressable by any later request (FuguOracle OPS-GET-2). The
  Unix-seconds scheme stays below this value until the year 2106.
- **ORC-COUNTER-6** — A too-low counter takes the junk path and burns no strike:
  the attempt count moves only on a wrong PIN (FuguOracle OPS-GET-2, FuguOracle
  OPS-GET-5). The client recovers when it sends a higher counter.
- **ORC-COUNTER-7** — The documentation must state the residual risks of the
  counter scheme: the stale-clock case, the cause ambiguity of a junk answer,
  and the replay of captured envelopes.

A machine with a stale clock and a lost counters file sends a too-low counter,
and the request takes the junk path. The honest residual is cause ambiguity, not
a strike. Junk is uniform (FuguOracle OPS-JUNK-2): a counter desync, a wrong
passphrase, and a wiped record look identical by response bytes. The runbook
states what to check before the operator concludes a wipe
([SAFE-DETECT](security.md#safe-detect)). Envelopes captured before a
re-enrollment stay replayable until the stored counter passes their values. This
is an accepted FuguOracle transport risk, and TLS mitigates it.

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
  ([KEY-SHARE](keys.md#key-share), [KEY-MASK](keys.md#key-mask)), must persist
  it in the machine-local set, and must then erase `s_ei` and the share from
  memory. The client must erase `K_e` directly after its last use
  ([SAFE-MEMORY](security.md#safe-memory)).
- **ORC-ENROLL-4** — A passphrase change must re-enroll every record of the
  machine at every live oracle, without the master. For each slot, `get_pin`
  with the old pins at any `k` oracles unmasks `k` shares, and the
  reconstruction yields `K_e` ([ORC-QUORUM](oracle.md#orc-quorum),
  [KEY-SHARE](keys.md#key-share)). A `set_pin` with the new `pin_ei` at each
  oracle yields a fresh mask. The client recomputes that oracle's wrap from the
  re-derived share.
- **ORC-ENROLL-5** — The client must persist the new wrap of a record before the
  next `set_pin`. The loop order is each slot in turn, and inside a slot each
  oracle in list order. The canary records come last (ORC-ENROLL-10).
- **ORC-ENROLL-6** — The client must re-enroll the canary record of each oracle
  the same way, must seal that oracle's canary check value under the fresh
  canary check seal key ([KEY-MASK](keys.md#key-mask)), and must re-wrap that
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
  oracle before the first re-enrollment ([ORC-CANARY](oracle.md#orc-canary)). A
  resumed run verifies per ORC-ENROLL-10. The client must re-enroll a canary
  that fails for record-side causes (ORC-CANARY-5) before the change starts.
- **ORC-ENROLL-9** — Before the first `set_pin` of a slot, the client must
  verify the reconstructed `K_e` by a decrypt of that slot's entry or slot file
  ([VAULT-SEAL](vault.md#vault-seal)). For the canary phase, the verification is
  the canary check decrypt of ORC-ENROLL-8. On a decrypt failure with an untried
  reachable oracle, the tool can retry with a different quorum, after the canary
  check of each substitute oracle (ORC-QUORUM-5). A decrypt failure with no
  untried quorum must stop the change before any `set_pin` of that slot, and the
  client must report the failing slot and each quorum used. The change stays
  incomplete, and the marker records the progress (ORC-ENROLL-10).
- **ORC-ENROLL-10** — The client must persist the change marker with the kind
  `passphrase` in the machine-local set ([VAULT-LAYOUT](vault.md#vault-layout)),
  with the list of re-enrolled records by record name
  ([VAULT-FORMAT](vault.md#vault-format)). The client must persist the marker
  before the first `set_pin` of the change. The client must append a record's
  done line after that record's persisted writes — the wrap (ORC-ENROLL-5), and
  for a canary the seal and the index wrap (ORC-ENROLL-6, ORC-CANARY-11) — and
  before the next `set_pin`. While the marker exists, a session must refuse
  reveals and must name the resume command. A restarted change must resume at
  the first unmigrated record, with the new pin for every record in the marker
  list and the old pin for every other record. A resumed change must read both
  passphrases again, must verify the old passphrase at the canary of each oracle
  whose canary is not in the marker list, and must verify the new passphrase at
  each canary in the marker list. The client must remove the marker after the
  last re-enrollment. The canary records re-enroll last, one per oracle, so an
  interrupted change still verifies with the old passphrase at every oracle
  whose canary is unmigrated.
- **ORC-ENROLL-11** — A passphrase change needs every live oracle reachable.
  With a live oracle unreachable, the change stays incomplete, the marker stays,
  and sessions refuse reveals until the change completes or until a plate
  ceremony removes the marker (ORC-ENROLL-12). The quorum availability claim
  covers reveals only ([OVW-LIMITS](overview.md#ovw-limits)).
- **ORC-ENROLL-12** — A plate ceremony that re-enrolls every record of this
  machine under one passphrase must remove the change marker, and the ceremony
  report must name the removal (CER-PROVISION-17). This ceremony is the recovery
  path for a change blocked by a lost oracle.

A `set_pin` on an existing record replaces the record's key material at the
oracle, and no oracle operation returns an old mask of that record (FuguOracle
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
  [QA-MASK](testing.md#qa-mask) pins it by test.
- **ORC-REVEAL-3** — The client must unmask oracle `i`'s share as
  `share(K_e, i) = c_ei ⊕ f(s_ei, "fugupass/v1/wrap" ‖ i/e)`
  ([KEY-MASK](keys.md#key-mask)). [ORC-QUORUM](oracle.md#orc-quorum) governs the
  reconstruction and the entry decrypt.
- **ORC-REVEAL-4** — A wrong passphrase, a missing or wiped record, and a
  counter violation all return junk, indistinguishable by response bytes
  (FuguOracle OPS-JUNK-2). The only failure signal is the client's own decrypt
  failure, and the client cannot learn the cause from the response bytes.
- **ORC-REVEAL-5** — The third wrong attempt on a record destroys that record's
  key material at the oracle (FuguOracle OPS-GET-6). The entry still reveals
  while `k` live records remain for it ([ORC-QUORUM](oracle.md#orc-quorum)).
  Recovery of the record is a plate ceremony or the re-enrollment loop of a
  passphrase change ([REC-WIPE](recovery.md#rec-wipe)).
- **ORC-REVEAL-6** — An HTTP error status is not an attempt, and the request is
  retryable: an attempt that the oracle cannot count receives no answer
  (FuguOracle OPS-GET-7). A transport failure after the client sends the request
  is ambiguous: the oracle persists a record change before it sends the response
  (FuguOracle OPS-GET-7), so a lost response can follow a counted attempt. The
  client must report an HTTP error, a transport failure, and a junk answer as
  distinct states, with distinct user reports.
- **ORC-REVEAL-7** — `K_e` must exist in memory for seconds only, and `M` must
  not appear in a reveal ([SAFE-MEMORY](security.md#safe-memory)).
- **ORC-REVEAL-8** — A `200` response whose envelope MAC or decrypt fails is an
  oracle-authentication failure. It is a distinct client state: it is not a junk
  answer, and it does not prove that the oracle skipped the attempt. The tool
  must report it as a provisioning or transport fault, distinct from the junk
  report and from the HTTP-error report.

<a id="orc-quorum"></a>

## The quorum

- **ORC-QUORUM-1** — A reveal of an entry needs the typed passphrase plus the
  masks of any `k` oracles of the set (D-06, D-20,
  [KEY-SHARE](keys.md#key-share)).
- **ORC-QUORUM-2** — The client must select the session quorum from the
  reachable oracles, in list order. While `k` or more reachable oracles hold
  live index wraps on this machine, the client must prefer those oracles
  (ORC-CANARY-8). The client must verify the canary of each quorum oracle before
  any entry record of that oracle ([ORC-CANARY](oracle.md#orc-canary)).
- **ORC-QUORUM-3** — For each quorum oracle `i`, an entry reveal sends one
  `get_pin` under `ck_ei` with `pin_ei` ([ORC-REVEAL](oracle.md#orc-reveal)) and
  unmasks that oracle's share ([KEY-MASK](keys.md#key-mask)).
- **ORC-QUORUM-4** — After `k` unmasked shares, the client must reconstruct
  `K_e` by interpolation at `x = 0` ([KEY-SHARE](keys.md#key-share)) and must
  decrypt the entry file under `K_e` ([VAULT-SEAL](vault.md#vault-seal)). The
  decrypt failure is the only junk detector, and it does not name the failing
  oracle.
- **ORC-QUORUM-5** — On a decrypt failure, an HTTP error, or a transport failure
  at a quorum oracle, the tool can substitute the next reachable oracle, after
  the canary check of that oracle. The tool must stop the substitutions when no
  untried quorum remains. Every failure report must name the quorum oracles of
  the attempt.
- **ORC-QUORUM-6** — With fewer than `k` reachable oracles, the tool must
  perform no reveal and must report the state of each oracle, with the distinct
  states of [ORC-REVEAL](oracle.md#orc-reveal).
- **ORC-QUORUM-7** — With `k = 1`, the quorum is one oracle, and the reveal is
  one `get_pin`. This is the general rule, not a special case.

A junk answer from one quorum oracle yields a wrong share, and the
reconstruction then fails the entry decrypt. The response bytes attribute
nothing (FuguOracle OPS-JUNK-2). The canary check verifies the passphrase at
each quorum oracle, so an entry decrypt failure signals a missing, wiped, or
desynchronized record, or a stale wrap on this machine. Strikes move only on a
pin that the record was not enrolled under (FuguOracle OPS-GET-2, FuguOracle
OPS-GET-5), so a retry with the session's verified pin burns no strike at a
healthy record. A record enrolled under a different pin burns one strike per
attempt, so the tool bounds the retries per record per session.

<a id="orc-canary"></a>

## The canary

- **ORC-CANARY-1** — The client must verify the typed passphrase against the
  canary record of each oracle that the session uses, before any entry record of
  that oracle (D-08). A typo burns canary strikes only, per oracle.
- **ORC-CANARY-2** — The canary check value is a fixed constant of 32 zero
  bytes. The tool seals it once per oracle, in the vault seal format
  ([VAULT-SEAL](vault.md#vault-seal)), under that oracle's canary check seal key
  ([KEY-MASK](keys.md#key-mask)), and stores each seal in the machine-local set
  ([VAULT-LAYOUT](vault.md#vault-layout)).
- **ORC-CANARY-3** — The canary masks also wrap the index-key shares
  ([KEY-MASK](keys.md#key-mask)). The session's `k` canary `get_pin` requests
  verify the passphrase. While the session quorum covers `k` live index wraps of
  this machine, the same requests also open the index.
- **ORC-CANARY-4** — The client must verify the canaries one oracle at a time,
  in quorum order, and must stop at the first canary decrypt failure, before it
  touches any entry record. A failure at the first canary is cause-ambiguous:
  the report must name the typo case and the per-oracle causes (ORC-CANARY-9). A
  failure after a pass at another oracle excludes the typo: the report must name
  the record-side causes of that oracle only. A re-run can exclude a suspect
  oracle from the quorum when more than `k` oracles are reachable.
- **ORC-CANARY-5** — A canary record guards nothing derived from the master. The
  client can re-enroll a wiped canary with `set_pin` at any time, without a
  ceremony.
- **ORC-CANARY-6** — A canary enrollment must read the passphrase twice and must
  require a match. The tool must warn that no verifier exists at this step.
- **ORC-CANARY-7** — The client must verify a fresh canary with one immediate
  `get_pin` round trip before the session proceeds.
- **ORC-CANARY-8** — A canary re-enrollment at oracle `i` replaces that oracle's
  canary mask. This machine's index wrap of oracle `i` is then dead. A client
  that holds `K_idx` in session memory must re-wrap at once: it must re-derive
  `share(K_idx, i)` ([KEY-SHARE](keys.md#key-share)) and must wrap it under the
  fresh canary mask ([KEY-MASK](keys.md#key-mask)). A session that opens the
  index and holds `K_idx` must re-wrap every dead index wrap of this machine at
  once. A client without `K_idx` must delete this machine's index wrap file of
  oracle `i` ([VAULT-LAYOUT](vault.md#vault-layout)), so the dead state is
  detectable. The index opens while the session quorum covers `k` live index
  wraps of this machine (ORC-QUORUM-2). While the quorum cannot cover `k` live
  index wraps, the session cannot resolve an entry name: the tool must report
  each dead or unreachable index wrap and must name the provisioning ceremony
  ([CER-PROVISION](ceremonies.md#cer-provision)). Entry records and entry wraps
  stay valid throughout.
- **ORC-CANARY-9** — A canary junk answer is cause-ambiguous like every junk
  answer. The tool must report the ambiguity: a wrong passphrase, a wiped
  canary, and a counter desync look identical by response bytes, and a stale
  canary check seal on this machine yields the same decrypt failure.
- **ORC-CANARY-10** — The documentation must state the mass-strike consequence
  of a poisoned canary enrollment. A ceremony that enrolls canaries under a
  mistyped passphrase accepts that mistyped passphrase at every canary of that
  ceremony. The entry reveals of the session then burn strikes at each quorum
  oracle.
- **ORC-CANARY-11** — After a canary enrollment at oracle `i` and its
  verification round trip, the client must seal the canary check value under
  that oracle's fresh canary check seal key ([KEY-MASK](keys.md#key-mask)) and
  must persist the seal ([VAULT-ATOMIC](vault.md#vault-atomic)). This rule
  applies to every canary enrollment: at a ceremony, after a wipe, and at a
  passphrase change.

The double read stops a single typo at enrollment. The immediate `get_pin` round
trip proves that the record answers with the enrolled mask. Neither check
detects a passphrase mistyped the same way twice.

<a id="orc-revoke"></a>

## Revocation

- **ORC-REVOKE-1** — No oracle operation freezes a record. The specification and
  the documentation must not claim a freeze capability (D-03).
- **ORC-REVOKE-2** — Revocation has exactly three paths: deliberate strike-burn
  or `set_pin` replacement under regenerated client keys; an operator service
  stop; and operator deletion of named record files.
- **ORC-REVOKE-3** — An owner who can derive a machine's client keys can destroy
  or lock that machine's records at each oracle over the wire: one wrong attempt
  per record at the revocation counter, or one `set_pin` replacement per record
  (ORC-REVOKE-8), at each oracle the owner chooses. No oracle operation reverses
  either path.
- **ORC-REVOKE-4** — The plate regenerates the device factor and the client keys
  of any machine name ([KEY-DEVICE](keys.md#key-device)). The owner can
  therefore run the strike-burn path from the plate, after a total loss of the
  stolen machine.
- **ORC-REVOKE-5** — An operator of a self-hosted oracle can stop the service. A
  service stop is reversible, and it affects every machine. The operator can
  delete named record files. No oracle operation reverses a deletion, and a
  deletion needs the revocation kit.
- **ORC-REVOKE-6** — The client must export a revocation kit for each machine:
  the machine name, plus, for each oracle of the set, that oracle's record file
  names. A record file name is the lowercase hex of the hash of the record's
  compressed public key, with the suffix `.pin` (FuguOracle STORE-KEYS-3).
  Client keys carry the oracle index ([KEY-CLIENT](keys.md#key-client)), so each
  oracle holds different record names. Record names are not secret.
- **ORC-REVOKE-7** — The documentation must state that the operator paths need a
  self-hosted or cooperative operator.
- **ORC-REVOKE-8** — A revocation request must send the counter value
  `0xFFFFFFFF`. This value passes anti-replay against every lower stored
  counter, so an attacker who raises a record's stored counter cannot block
  revocation. A `set_pin` replacement at this value replaces the record's key
  material at the oracle and resets the stored counter (FuguOracle OPS-SET-4).
  One wrong attempt at this value burns one strike and locks the record: no
  later request passes anti-replay, and the record answers junk to every caller.
  A locked record keeps its file, and only the operator paths remove it.
- **ORC-REVOKE-9** — The runbook must state the FuguOracle restore residual: a
  filesystem restore of the records directory rewinds records to the backup
  time, so a restore from a pre-revocation backup revives revoked records
  (FuguOracle DEPLOY-BACKUP-4). The operator restores records only after an
  incident review.
- **ORC-REVOKE-10** — To deny a stolen machine a quorum, the owner locks that
  machine's records at enough live oracles that at most `k − 1` live oracles
  stay unlocked, by the counter-sentinel path of ORC-REVOKE-8 at each of those
  oracles. With the full set of `n` live oracles, the count is `n − k + 1`
  locks. Locks at every oracle are not necessary: the locks leave at most
  `k − 1` obtainable masks per entry.

Each ceremony exports the kit of its machine
([CER-PROVISION](ceremonies.md#cer-provision)). An attacker who first raises a
record's stored counter to `0xFFFFFFFF` locks that record for every caller. A
locked record denies its mask to the attacker too. The revocation paths destroy
or deny records, never data: every entry recovers from the plate
([REC-WIPE](recovery.md#rec-wipe)).
