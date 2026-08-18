# Test strategy

This document specifies the tests and the analyses that gate the FuguPass
implementation.
[keys.md](keys.md) defines the notation `K_e`, `s_ei`, `c_ei`, `share(S, i)`,
`f`, `n`, and `k`.
This document cites FuguOracle rules as prose tokens, for example FuguOracle
OPS-GET-4.

<a id="qa-harness"></a>

## Interop harness

- **QA-HARNESS-1** — One interop harness must run the oracle-client suite against
  every available conforming oracle (D-19).
- **QA-HARNESS-2** — The harness must run against the upstream Python
  `blind_pin_server` at minimum. When a FuguOracle build exists, the harness must
  run against FuguOracle.
- **QA-HARNESS-3** — The suite must cover the client behavior end to end. The
  suite must cover the conformance rules ([ORC-CONFORM](oracle.md#orc-conform)).
  The suite must cover enrollment and re-enrollment
  ([ORC-ENROLL](oracle.md#orc-enroll)). The suite must cover the reveal
  ([ORC-REVEAL](oracle.md#orc-reveal)). The suite must cover the canary round trip
  ([ORC-CANARY](oracle.md#orc-canary)). The suite must cover the counter policy
  ([ORC-COUNTER](oracle.md#orc-counter)). The suite must cover the report
  distinction between an HTTP error, a transport failure, an oracle-authentication
  failure, and a junk answer ([ORC-REVEAL](oracle.md#orc-reveal)). The suite must
  cover the quorum reveal and the quorum failure reports
  ([ORC-QUORUM](oracle.md#orc-quorum)).
- **QA-HARNESS-4** — The same suite must pass against every counterparty. The
  suite must not branch on the counterparty.
- **QA-HARNESS-5** — The suite must run one leg against the documented example
  topology: three oracle instances with a threshold of two. The leg must prove
  the reveal on every two-oracle quorum, the decrypt failure with one mask, the
  passphrase change over three oracles, and the provisioning loop
  ([ORC-QUORUM](oracle.md#orc-quorum), [ORC-ENROLL](oracle.md#orc-enroll)).

FuguPass is a second client of the wire protocol, beside the Blockstream Jade.
A pass against every counterparty proves the FuguOracle claim that the oracle
serves any conforming client, and it touches nothing in the FuguOracle
specification (D-02).

<a id="qa-mask"></a>

## Mask stability

- **QA-MASK-1** — The mask-stability test must send repeated `get_pin` requests to
  an unchanged record and must assert an identical 32-byte answer plaintext on
  every request.
- **QA-MASK-2** — The test must assert that a `set_pin` re-enrollment changes the
  answer.
- **QA-MASK-3** — The test must drive a record to the third-strike wipe and must
  assert that every later request receives junk: no later answer equals the old
  mask.
- **QA-MASK-4** — The test must assert that junk answers differ between requests.
- **QA-MASK-5** — The test must run against the upstream `blind_pin_server` at
  minimum. When a FuguOracle build exists, the test must run against FuguOracle.

Stability is a consequence of FuguOracle OPS-GET-4, never a stated interface
guarantee.
The custody layer rests on the stable answer ([KEY-MASK](keys.md#key-mask)), so
this test pins the consequence against every counterparty (D-19).
A junk answer carries a fresh random key (FuguOracle OPS-JUNK-1), so identical
junk answers signal a defect.
The test runs against one instance.
The quorum leg of [QA-HARNESS](testing.md#qa-harness) covers the composition.

<a id="qa-analysis"></a>

## The mask-composition analysis

- **QA-ANALYSIS-1** — A written analysis of the composition
  `c_ei = share(K_e, i) ⊕ f(s_ei, "fugupass/v1/wrap" ‖ i/e)` as a long-term
  keystore over the stable oracle answer must exist in the repository.
- **QA-ANALYSIS-2** — The analysis must cover key reuse across reveals, the KDF of
  the mask, and the wrap XOR of a share.
- **QA-ANALYSIS-3** — The analysis must have human approval.
- **QA-ANALYSIS-4** — Acceptance of the custody layer includes this analysis
  (D-19).

The mask composition uses the oracle answer beyond the protocol's analyzed
purpose ([KEY-MASK](keys.md#key-mask)).
[QA-MASK](testing.md#qa-mask) pins the behavior by test, and the analysis judges
the construction that FuguPass builds over that behavior.

<a id="qa-split"></a>

## The share-split analysis and vectors

- **QA-SPLIT-1** — A written soundness analysis of the deterministic Shamir
  coefficients must exist in the repository ([KEY-SHARE](keys.md#key-share)). The
  analysis must cover the derived-versus-uniform coefficient question, the domain
  separation of the coefficient labels, the non-reuse of coefficients across
  entries and against the index key, and the independence of coefficients across
  threshold values and across re-enrollments of one secret.
- **QA-SPLIT-2** — The analysis must have human approval.
- **QA-SPLIT-3** — Acceptance of the custody layer includes this analysis, as a
  sibling of the mask-composition analysis
  ([QA-ANALYSIS](testing.md#qa-analysis), D-19).
- **QA-SPLIT-4** — Known-answer vectors from an independent reference
  implementation must pin the share arithmetic: the field operations, the
  coefficient derivation, the share evaluation, the reconstruction, and the
  `k = 1` reduction ([KEY-SHARE](keys.md#key-share)). The coefficient label
  carries the threshold, so the vectors must cover more than one threshold
  value.
- **QA-SPLIT-5** — The repository must record the source evaluation of the
  share-arithmetic implementation: the evaluated candidates, the licenses, the
  timing behavior of the arithmetic, and the choice (D-15).
- **QA-SPLIT-6** — The share-split known-answer tests must run offline, with no
  oracle and no network.

The standard Shamir argument assumes uniformly random coefficients, and the
derived coefficients replace that assumption ([KEY-SHARE](keys.md#key-share)).
The analysis judges the replacement, and the vectors pin the arithmetic.

<a id="qa-calibrate"></a>

## Calibration and scaling

- **QA-CALIBRATE-1** — A calibration must set the default bcrypt_pbkdf round count
  ([KEY-PIN](keys.md#key-pin), D-09). The calibration weighs unlock latency on
  target laptops against offline search cost on current attack hardware.
- **QA-CALIBRATE-2** — The repository must record the calibration: the measured
  latency, the assumed attack hardware, and the chosen default round count.
- **QA-CALIBRATE-3** — A scaling check must enroll hundreds of records at a
  flat-file oracle and must record the result against the stated workload posture
  of the oracle ([ORC-RECORDS](oracle.md#orc-records)).

A session computes bcrypt_pbkdf once per quorum canary and `k` times per
revealed entry, so the round count multiplies into the session latency by `k`.
A ceremony enrolls one record per slot ([ENTRY-POOL](entries.md#entry-pool)), so
the record count at the oracle grows with the pool size and with the machine
count.

<a id="qa-kat"></a>

## Known-answer tests

- **QA-KAT-1** — Known-answer vectors from a reference implementation must gate
  the BIP85 implementation: the PWD BASE64 application and the BIP39 application
  ([KEY-BIP85](keys.md#key-bip85), D-17).
- **QA-KAT-2** — Dice-mapping vectors must cover the word mapping of the dice
  ceremony and the final-word checksum ([CER-DICE](ceremonies.md#cer-dice)).
- **QA-KAT-3** — Seal round-trip vectors must cover the seal format: a seal, a
  decrypt, and a decrypt failure on a modified byte
  ([VAULT-SEAL](vault.md#vault-seal)).
- **QA-KAT-4** — SeedQR and CompactSeedQR vectors, for 12 words and for 24 words,
  must match the SeedSigner specification ([CLI-SCAN](programs.md#cli-scan)).
- **QA-KAT-5** — A fixed test master must provide a vector for every derivation
  label in [keys.md](keys.md).
- **QA-KAT-6** — The repository must hold the vectors. The known-answer
  tests must run offline, with no oracle and no network.

The test master is a public constant for tests only.
Its vectors pin the whole derivation tree, so a derivation defect fails a test
before it corrupts a vault.
