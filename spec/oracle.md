# Blind-oracle client

This document specifies the FuguPass oracle client. FuguPass is a client of the
Blockstream `blind_pin_server` wire protocol, version 2. FuguOracle is the
reference deployment, not a requirement (D-02). [keys.md](keys.md) defines the
notation `K_e`, `ck_ei`, `pin_ei`, `s_ei`, `c_ei`, `s_canary_i`, `c_idx_i`,
`K_idx`, `share(S, i)`, `n`, and `k`. This document cites FuguOracle rules as
prose tokens, for example FuguOracle OPS-GET-4.

Two more documents specify the oracle client.
[oracle-enrollment.md](oracle-enrollment.md) specifies the enrollment and the
reveal. [oracle-quorum.md](oracle-quorum.md) specifies the quorum, the canary,
and the revocation.

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
  fresh entropy from `arc4random(3)` (FuguOracle OPS-SET-1).
- **ORC-CONFORM-6** — The transport must be HTTP/1.1 over a socket, or over
  `libtls` of the base system. It must run in the core process
  ([PROG-SPLIT](programs.md#prog-split)). The client must send one POST per
  request, and must read the response with a strict reader. The reader must
  remove the chunked transfer coding of an answer, and must take no other
  coding. `httpd(8)` sends a FastCGI answer with no length in that coding. The
  reader must take one JSON object that holds one `data` member. The value of
  that member must be a base64 string, and must hold no escape sequence. The
  reader must step over each unknown member, and must accept insignificant JSON
  whitespace. It must treat a duplicate `data` member, and every other shape, as
  malformed (FuguOracle PROTO-HTTP-7). A malformed body of a `200` response must
  be a transport failure. A response of more than 4096 bytes must be a transport
  failure.

The interop harness proves conformance against every available conforming oracle
([TEST-HARNESS](testing.md#test-harness)).

<a id="orc-provision"></a>

## Provisioning

- **ORC-PROVISION-1** — The config file must hold, for each oracle position, the
  two provisioned values. They are the oracle URL and the static public key as a
  hex string. This mirrors FuguOracle CLIENT-PROVISION-1. The full config field
  list is in [VAULT-CONFIG](vault.md#vault-config); this unit governs the oracle
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
  machine's wrap files, canary check seal, and index wrap of that position. The
  shares re-derive from the plate, so nothing is lost
  ([KEY-SHARE](keys.md#key-share)). The documentation must direct the owner to
  destroy this vault's records at the departing oracle. The owner derives the
  revocation kit ([ORC-REVOKE](oracle-quorum.md#orc-revoke)) to name those
  records.
- **ORC-PROVISION-7** — A change of the oracle list or of the threshold is a
  plate ceremony ([CER-PROVISION](ceremonies.md#cer-provision)).
- **ORC-PROVISION-8** — The documentation must state that every machine of a
  vault must record the same ordered oracle list and the same threshold.
  Revocation from the plate re-derives a stolen machine's client keys from this
  list ([ORC-REVOKE](oracle-quorum.md#orc-revoke)). A divergent list therefore
  breaks revocation. A divergent list on a ceremony machine enrolls records that
  other flows cannot address.
- **ORC-PROVISION-9** — A live position is a config position that is not retired
  ([VAULT-CONFIG](vault.md#vault-config)). A live oracle is the oracle of a live
  position. A reachable oracle is a live oracle that answers.

<a id="orc-records"></a>

## Per-entry records

- **ORC-RECORDS-1** — Each entry must use one oracle record at each oracle of
  the set, on each machine (D-07).
- **ORC-RECORDS-2** — Each machine must hold one canary record at each oracle
  ([ORC-CANARY](oracle-quorum.md#orc-canary)).
- **ORC-RECORDS-3** — To the oracle, every record is an independent client.
  FuguOracle OVW-PURPOSE-4 permits many clients on one instance. Each record
  burns its own three strikes, so a wipe destroys one record and touches no
  other. A record holds no entry name, no purpose, and no content.
  [OVW-RISKS](overview.md#ovw-risks) states the guess budget that the record
  count sets.
- **ORC-RECORDS-4** — The documentation must state the load that FuguPass
  generates against the stated workload assumption of the oracle. The load is
  `k` `get_pin` requests per revealed entry. It is also one `set_pin` request
  per live oracle, for each slot of each machine at enrollment.

A session that reveals ten entries sends ten entry requests plus one canary
request to each quorum oracle. One oracle instance sees one request per event;
the multiplier spreads across instances. This load can exceed the oracle
workload assumption of a few requests per day (FuguOracle D-04). This is a
posture mismatch on a self-hosted oracle, not a correctness problem. The scaling
check in [TEST-CALIBRATE](testing.md#test-calibrate) records the result.

<a id="orc-counter"></a>

## Replay counters

- **ORC-COUNTER-1** — The counter sent for a record must be
  `max(wall-clock Unix seconds, stored + 1)`, encoded as uint32 LE (FuguOracle
  PROTO-ENVELOPE). A revocation request is the one exception
  ([ORC-REVOKE](oracle-quorum.md#orc-revoke)).
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
  except in a revocation request ([ORC-REVOKE](oracle-quorum.md#orc-revoke)). A
  persisted counter of `0xFFFFFFFF` leaves no strictly greater value, so the
  record becomes unaddressable by any later request (FuguOracle OPS-GET-2,
  FuguOracle OPS-SET-2). The Unix-seconds scheme stays below this value until
  the year 2106.
- **ORC-COUNTER-6** — A too-low counter takes the junk path and burns no strike.
  The attempt count moves only on a wrong PIN (FuguOracle OPS-GET-2, FuguOracle
  OPS-GET-5). The client recovers when it sends a higher counter.
- **ORC-COUNTER-7** — The documentation must state the residual risks of the
  counter scheme. The risks are the stale-clock case, the cause ambiguity of a
  junk answer, and the replay of captured envelopes.

A machine with a stale clock and a lost counters file sends a too-low counter,
and the request takes the junk path. The honest residual is cause ambiguity, not
a strike. Junk is uniform (FuguOracle OPS-JUNK-2): a counter desync, a wrong
passphrase, and a wiped record look identical by response bytes. The runbook
states what to check before the operator concludes a wipe
([SEC-DETECT](security.md#sec-detect)). Envelopes captured before a
re-enrollment stay replayable until the stored counter passes their values. This
is an accepted FuguOracle transport risk, and TLS mitigates it.
