# Oracle quorum, canary, and revocation

This document is a part of the [oracle client](oracle.md) specification. It
specifies the quorum of a reveal, the canary record, and the revocation of a
machine.

<a id="orc-quorum"></a>

## The quorum

- **ORC-QUORUM-1** — A reveal of an entry needs the typed passphrase plus the
  masks of any `k` oracles of the set (D-06, D-20,
  [KEY-SHARE](keys.md#key-share)).
- **ORC-QUORUM-2** — The client must select the session quorum from the
  reachable oracles, in list order. While `k` or more reachable oracles hold
  live index wraps on this machine, the client must prefer those oracles
  (ORC-CANARY-8). The client must verify the canary of each quorum oracle before
  any entry record of that oracle ([ORC-CANARY](oracle-quorum.md#orc-canary)).
- **ORC-QUORUM-3** — For each quorum oracle `i`, an entry reveal sends one
  `get_pin` under `ck_ei` with `pin_ei`
  ([ORC-REVEAL](oracle-enrollment.md#orc-reveal)) and unmasks that oracle's
  share ([KEY-MASK](keys.md#key-mask)).
- **ORC-QUORUM-4** — After `k` unmasked shares, the client must reconstruct
  `K_e` by interpolation at `x = 0` ([KEY-SHARE](keys.md#key-share)) and must
  decrypt the entry file under `K_e` ([VAULT-SEAL](vault.md#vault-seal)). The
  decrypt failure is the only junk detector, and it does not name the failing
  oracle.
- **ORC-QUORUM-5** — A decrypt failure or a failed request can happen at a
  quorum oracle. A request fails at the oracle
  ([ORC-REVEAL](oracle-enrollment.md#orc-reveal)). It also fails at this
  machine, at a record with no greater counter (ORC-COUNTER-5). The tool can
  then substitute the next reachable oracle, after the canary check of that
  oracle. The tool must try each reachable oracle at most once per reveal as a
  substitute. It must stop the substitutions when no untried reachable oracle
  remains. Every failure report must name the quorum oracles of the attempt.
- **ORC-QUORUM-6** — With fewer than `k` reachable oracles, the tool must
  perform no reveal. It must report the state of each oracle, with the distinct
  states of [ORC-REVEAL](oracle-enrollment.md#orc-reveal).
- **ORC-QUORUM-7** — With `k = 1`, the quorum is one oracle, and the reveal is
  one `get_pin`. This is the general rule, not a special case.
- **ORC-QUORUM-8** — A record of this machine is one slot at one oracle
  ([ORC-RECORDS](oracle.md#orc-records)). The tool must count one request of
  each quorum record, before it sends that request. One session must send no
  third request to one record, because the third wrong attempt destroys that
  record (ORC-REVEAL-5). The tool must stop the reveal before the third request,
  and the report must name the slot and the oracle of that record.

A junk answer from one quorum oracle yields a wrong share, and the
reconstruction then fails the entry decrypt. The response bytes attribute
nothing (FuguOracle OPS-JUNK-2). The canary check verifies the passphrase at
each quorum oracle. An entry decrypt failure therefore signals a missing, wiped,
or desynchronized record, or a stale wrap on this machine. Strikes move only on
a pin that the record was not enrolled under (FuguOracle OPS-GET-2, FuguOracle
OPS-GET-5). A retry with the session's verified pin therefore burns no strike at
a healthy record. A record enrolled under a different pin burns one strike per
attempt, and ORC-QUORUM-8 bounds the requests per record per session.

<a id="orc-canary"></a>

## The canary

- **ORC-CANARY-1** — The client must verify the typed passphrase against the
  canary record of each oracle that the session uses. It must do this before any
  entry record of that oracle (D-08). A typo burns canary strikes only, per
  oracle.
- **ORC-CANARY-2** — The canary check value is a fixed constant of 32 zero
  bytes. The tool seals it once per oracle, in the vault seal format
  ([VAULT-SEAL](vault.md#vault-seal)), under that oracle's canary check seal key
  ([KEY-MASK](keys.md#key-mask)). It stores each seal in the machine-local set
  ([VAULT-LAYOUT](vault.md#vault-layout)).
- **ORC-CANARY-3** — The canary masks also wrap the index-key shares
  ([KEY-MASK](keys.md#key-mask)). The session's `k` canary `get_pin` requests
  verify the passphrase. While the session quorum covers `k` live index wraps of
  this machine, the same requests also open the index.
- **ORC-CANARY-4** — The client must verify the canaries one oracle at a time,
  in quorum order. It must stop at the first canary decrypt failure, before it
  touches any entry record. A failure at the first canary is cause-ambiguous:
  the report must name the typo case and the per-oracle causes (ORC-CANARY-9). A
  failure after a pass at another oracle excludes the typo: the report must name
  the record-side causes of that oracle only. A re-run can exclude a suspect
  oracle from the quorum when more than `k` oracles are reachable.
- **ORC-CANARY-5** — A canary record guards nothing derived from the master. The
  client can re-enroll a wiped canary with `set_pin` at any time, without a
  ceremony.
- **ORC-CANARY-6** — A canary enrollment must read the passphrase twice and must
  require a match. The tool must warn that no verifier exists when this session
  verified the typed passphrase against no canary record. The tool must not warn
  when the unlock of this session verified that passphrase (ORC-CANARY-1).
- **ORC-CANARY-7** — The client must verify a fresh canary with one immediate
  `get_pin` round trip before the session proceeds.
- **ORC-CANARY-8** — A canary re-enrollment at oracle `i` replaces that oracle's
  canary mask. This machine's index wrap of oracle `i` is then dead. A client
  that holds `K_idx` in session memory must re-wrap at once. It must re-derive
  `share(K_idx, i)` ([KEY-SHARE](keys.md#key-share)) and must wrap it under the
  fresh canary mask ([KEY-MASK](keys.md#key-mask)). A session that opens the
  index and holds `K_idx` must re-wrap every dead index wrap of this machine at
  once. A client without `K_idx` must delete this machine's index wrap file of
  oracle `i` ([VAULT-LAYOUT](vault.md#vault-layout)), so the dead state is
  detectable. A re-enrollment that fails after the `set_pin` must also delete
  that file. The index opens while the session quorum covers `k` live index
  wraps of this machine (ORC-QUORUM-2). While the quorum cannot cover `k` live
  index wraps, the session cannot resolve an entry name. The tool must report
  each dead or unreachable index wrap, and must name the provisioning ceremony
  ([CER-PROVISION](ceremonies.md#cer-provision)). Entry records and entry wraps
  stay valid throughout.
- **ORC-CANARY-9** — A canary junk answer is cause-ambiguous like every junk
  answer. The tool must report the ambiguity. A wrong passphrase, a wiped
  canary, and a counter desync look identical by response bytes. A stale canary
  check seal on this machine yields the same decrypt failure.
- **ORC-CANARY-10** — The documentation must state the mass-strike consequence
  of a poisoned canary enrollment. A ceremony that enrolls canaries under a
  mistyped passphrase accepts that mistyped passphrase at every canary of that
  ceremony. The entry reveals of the session then burn strikes at each quorum
  oracle.
- **ORC-CANARY-11** — After a canary enrollment at oracle `i` and its
  verification round trip, the client must seal the canary check value. The seal
  key is that oracle's fresh canary check seal key
  ([KEY-MASK](keys.md#key-mask)). The client must persist the seal
  ([VAULT-ATOMIC](vault.md#vault-atomic)). This rule applies to every canary
  enrollment: at a ceremony, after a wipe, and at a passphrase change.

The double read stops a single typo at enrollment. The immediate `get_pin` round
trip proves that the record answers with the enrolled mask. Neither check
detects a passphrase mistyped the same way twice.

<a id="orc-revoke"></a>

## Revocation

- **ORC-REVOKE-1** — No oracle operation freezes a record. The specification and
  the documentation must not claim a freeze capability (D-03).
- **ORC-REVOKE-2** — Revocation has exactly three paths. The first is a
  deliberate strike-burn, or a `set_pin` replacement under regenerated client
  keys. The others are an operator service stop, and operator deletion of named
  record files.
- **ORC-REVOKE-3** — An owner who can derive a machine's client keys can destroy
  or lock that machine's records at each oracle over the wire. The paths are one
  wrong attempt per record at the revocation counter, or one `set_pin`
  replacement per record (ORC-REVOKE-8). The owner chooses each oracle. No
  oracle operation reverses either path.
- **ORC-REVOKE-4** — The plate regenerates the device factor and the client keys
  of any machine name ([KEY-DEVICE](keys.md#key-device)). The owner can
  therefore run the strike-burn path from the plate, after a total loss of the
  stolen machine. The strike-burn path retires that machine name at each oracle
  where it lands (ORC-REVOKE-11).
- **ORC-REVOKE-5** — An operator of a self-hosted oracle can stop the service. A
  service stop is reversible, and it affects every machine. The operator can
  delete named record files. No oracle operation reverses a deletion, and a
  deletion needs the revocation kit.
- **ORC-REVOKE-6** — The tool must produce the revocation kit of a machine on
  demand, on the standard output. The tool must not store a kit. A stored kit is
  a copy of derived data, and each refill makes it stale
  ([CER-REFILL](ceremonies.md#cer-refill)). The kit holds the machine name, and
  the record file names of each position of the config, live or retired
  ([VAULT-CONFIG](vault.md#vault-config)). Each live position carries its URL,
  and a retired position carries the word `retired` in its place. A record file
  name is the lowercase hex of the hash of the record's compressed public key,
  with the suffix `.pin` (FuguOracle STORE-KEYS-3). Client keys carry the oracle
  index ([KEY-CLIENT](keys.md#key-client)), so each oracle holds different
  record names. Record names are not secret.
- **ORC-REVOKE-7** — The documentation must state that the operator paths need a
  self-hosted or cooperative operator. It must state that a saved copy of the
  kit is a snapshot (ORC-REVOKE-6), and that the operator regenerates the kit
  before a revocation.
- **ORC-REVOKE-8** — A revocation request must send the counter value
  `0xFFFFFFFF`. This value passes anti-replay against every lower stored
  counter, so an attacker who raises a record's stored counter cannot block
  revocation. A `set_pin` replacement at this value replaces the record's key
  material at the oracle and resets the stored counter (FuguOracle OPS-SET-4).
  One wrong attempt at this value burns one strike and locks the record. A lock
  that is the first or the second strike of the record keeps its file at the
  oracle (FuguOracle OPS-GET-5). No later request of that record passes
  anti-replay, and the record answers junk to every caller. Only the operator
  paths remove a kept file. A lock that is the third strike wipes the record
  (FuguOracle OPS-GET-6). The oracle then accepts an enrollment of that record
  name (FuguOracle OPS-SET-2). The lock retires the machine name at that oracle
  (ORC-REVOKE-11).
- **ORC-REVOKE-9** — The runbook must state the FuguOracle restore residual. A
  filesystem restore of the records directory rewinds records to the backup
  time. A restore from a pre-revocation backup therefore revives revoked records
  (FuguOracle DEPLOY-BACKUP-4). The operator restores records only after an
  incident review.
- **ORC-REVOKE-10** — To deny a stolen machine a quorum, the owner locks that
  machine's records at enough live oracles. At most `k − 1` live oracles must
  stay unlocked. The owner uses the counter-sentinel path of ORC-REVOKE-8 at
  each of those oracles. With the full set of `n` live oracles, the count is
  `n − k + 1` locks. Locks at every oracle are not necessary: the locks leave at
  most `k − 1` obtainable masks per entry.
- **ORC-REVOKE-11** — A lock retires the machine name at that oracle. The stored
  counter of a kept record is the highest value, so no later `set_pin` of that
  record passes anti-replay there (FuguOracle OPS-SET-2). A wiped record leaves
  no file, so the oracle accepts a `set_pin` of that record name (FuguOracle
  OPS-SET-2). The tool must mark the name retired in the machine registry
  ([VAULT-INDEX](vault.md#vault-index)). The mark keeps this vault from that
  enrollment. A retired name must not provision again
  ([CER-PROVISION](ceremonies.md#cer-provision)), and a replacement machine
  provisions under a new name.
- **ORC-REVOKE-12** — The revocation report must direct the owner to lock or
  delete the remaining records of the retired name at every other oracle. It
  must also direct the owner to a passphrase change on every other machine when
  the passphrase may be known ([ORC-ENROLL](oracle-enrollment.md#orc-enroll)).

The `kit` subcommand of [PROG-ONESHOT](programs-commands.md#prog-oneshot)
produces the kit of this machine, or of a named machine from the plate. An
attacker who first raises a record's stored counter to `0xFFFFFFFF` locks that
record for every caller. A locked record denies its mask to the attacker too.
The revocation paths destroy or deny records, never data: every entry recovers
from the plate ([REC-WIPE](recovery.md#rec-wipe)).

A lock at the third strike of a record is a wipe (FuguOracle OPS-GET-6). A wipe
unlinks the file, and a fresh `set_pin` re-creates the record (REC-WIPE-3). A
lock at the first or the second strike keeps the file with the highest counter.
The oracle then rejects every later request for that record. Only the operator
paths remove a kept file.
