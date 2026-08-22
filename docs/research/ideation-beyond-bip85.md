# Beyond BIP85: multisig custody for every secret — ideation notes

|           |                                                                      |
| --------- | -------------------------------------------------------------------- |
| Status    | Research notes, round 2. Not normative.                              |
| Builds on | [ideation-initial.md](ideation-initial.md)                           |
| Purpose   | Input for `spec/DECISIONS.md` and the first specification documents. |

Round 1 proposed a tiered vault with BIP85 derivation and an oracle-gated
unlock. The critique of round 1 is correct: BIP85 improves backup, not security.
A BIP85 vault still dies like every password manager dies: one machine, one
moment, one master secret in memory, and everything is gone at once.

These notes design against that failure mode. The available infrastructure —
blind PIN oracles, SeedQR plates, hardware signers, and multisig discipline —
supports a stronger claim than "easy to back up".

## 1. The thesis

Bitcoin did not get secure because seeds became easier to back up. It got secure
because multisig removed every single point of failure: no single device, no
single backup, no single moment holds spending power.

Apply the same move to secrets:

> **Separate what a secret _is_ from who can _reveal_ it.** Derivation (BIP85)
> answers backup. A custody layer answers security. Every entry gets a reveal
> policy: a quorum of factors that must cooperate, at reveal time, for that one
> entry.

BIP85 did not take off because it only answers the first question. The second
question is the one that matters, and the audience already owns the hardware to
answer it.

The frame in audience language:

| Bitcoin custody                    | FuguPass                               |
| ---------------------------------- | -------------------------------------- |
| UTXO                               | Entry                                  |
| Output descriptor / miniscript     | Reveal descriptor                      |
| Cosigner service (Casa, Unchained) | Blind oracle — but it can read nothing |
| Hardware signer                    | Hardware signer, same device           |
| Seed plates, k-of-n                | Share plates, k-of-n                   |
| Spend = quorum signs               | Reveal = quorum co-decrypts            |

The frame has one honest limit. A Bitcoin cosigner verifies a transaction on its
own screen before it signs. A blind oracle verifies a PIN and nothing else. The
oracle is a rate limiter with a kill switch, not a judge of content. Section 4
states what this limit costs.

## 2. The primitive: blind share masking

One protocol fact carries the whole design.
[OPS-GET-4](../../../FuguOracle/spec/operations.md#ops-get) makes the oracle
answer a correct PIN with `HMAC(key = saved aes_key, msg = pin_secret)`. For an
unchanged record, this value is **stable**: the same 32 bytes on every correct
request.

So one v2 record is, as-is, a **PIN-gated, three-strike, remotely-wipeable cell
that stores one stable 32-byte secret**, and the oracle that serves it cannot
read the cell's purpose, name, or content.

Call the stable value a _mask_, `s`. The client never stores `s`. The client
stores `c = σ ⊕ KDF(s)` in its vault, where `σ` is a share of an entry key. `c`
alone is ciphertext. `s` alone is a random string on a server that knows
nothing. Only a correct PIN, presented to a live oracle that has not struck out,
reunites them.

Everything below composes this primitive. The wire protocol does not change.
FuguOracle does not change. All threshold logic lives in the client, which is
where OpenBSD taste wants it.

## 3. The construction

Notation: `f(k, x)` is deterministic key derivation (HMAC-family), `M` is the
vault master, `X` is a local device key on disk, `e` names an entry, `i` names
an oracle.

### 3.1 Keys

```
K_e        = f(M, "entry-key" ‖ e)            ; entry data key, deterministic
C_e        = AEAD(K_e, secret ‖ metadata)     ; the entry file in the vault
X          = local device factor, on disk     ; created at enrollment ceremony
ck_ei      = f(X, "client-key" ‖ i ‖ e)       ; per-oracle, per-entry client keypair
pin_ei     = bcrypt_pbkdf(passphrase, salt_ei) ; per-record pin_secret
salt_ei    = f(X, "pin-salt" ‖ i ‖ e)         ; per-record KDF salt
```

`K_e` derives from `M`, so the plates alone always decrypt the vault. This is
the recovery path, and no oracle can ever gate it.

`f` takes high-entropy keys only. Every key that derives from a typed passphrase
must pass through `bcrypt_pbkdf(3)`, the OpenBSD base passphrase KDF, with a
tunable round count. This rule sets the cost of the offline search in the
disk-plus-oracle breach case (section 4).

### 3.2 Enrollment ceremony (master present, once)

1. Derive `K_e`.
2. Split `K_e` into `n` Shamir shares `σ_1 … σ_n` with threshold `k`. The Shamir
   coefficients derive from `M`, so the split is deterministic and the system
   RNG still generates no stored secret. The standard Shamir argument assumes
   uniformly random coefficients, so the derived coefficients need a written
   analysis, with strict domain separation per entry, before the specification
   adopts them (section 10).
3. For each oracle `i`: enroll a record with `set_pin` under `ck_ei` and
   `pin_ei`. Learn the stable mask `s_ei` from the response.
4. Store `c_ei = σ_i ⊕ KDF(s_ei)` in the vault metadata.
5. Erase `M`, `K_e`, all `σ_i`, and all `s_ei` from memory.

### 3.3 Daily reveal (master absent)

1. Read the passphrase once. Verify it against one **canary record** first, so a
   typo never burns an attempt on a real entry record.
2. For any `k` oracles: `get_pin` under `ck_ei`, `pin_ei` → `s_ei`.
3. Unmask: `σ_i = c_ei ⊕ KDF(s_ei)`. Interpolate → `K_e`. Decrypt `C_e`.
4. `K_e` lives in memory for seconds. `M` never appears at all.

A wrong reconstruction fails the AEAD check on `C_e`, so the client detects junk
responses exactly as the Jade does: by its own decrypt failing.

### 3.4 Policy composition

- **AND** of factors: mix with KDF — `K_e` needs every input.
- **Threshold** of factors: Shamir.
- Nesting covers any monotone policy, in the miniscript manner.

A **reveal descriptor** names the policy per entry:

```
password:    reveal(and(local, oracle(home)))
mail:        reveal(and(local, thresh(2, oracle(home), oracle(vps), oracle(friend))))
btc-pass:    reveal(and(local, thresh(2, oracles), signer(jade-1)))
inheritance: reveal(thresh(3, plate(1), plate(2), plate(3), plate(4)))
travel:      reveal(local)
```

The policy is enforced by construction, not by a referee: the shares physically
do not exist in one place until the quorum cooperates. This claim is narrower
than the Bitcoin multisig claim. A cosigner verifies a transaction before it
signs, and a blind oracle only gates a share behind a PIN. The construction
removes the single point of _theft at rest_. During a reveal, the laptop remains
a single party whose compromise is sufficient for that entry.

## 4. What each attacker now gets

The table answers "no additional security over a regular password manager".

| Attack                                               | Classic manager, BIP85 included      | FuguPass custody layer                                                                                                                                                                                                                                                |
| ---------------------------------------------------- | ------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Vault file plus master password stolen               | Total loss, offline, silent, forever | Nothing, while fewer than `k` oracles are also breached. Reveals need a live oracle quorum. Each entry burns its own three strikes. The owner can freeze or wipe records remotely. The `k`-oracle breach case falls back to the offline floor (see the limits below). |
| Malware during an unlocked session                   | One bulk dump of everything          | Per-entry reveals only, each one a per-record event in the oracle logs. High-tier entries need a signer or plates that are not present. Phases 1 to 3 log and do not alert (see the limits below).                                                                    |
| Password-manager server breach                       | Cloud vault blobs, offline-crackable | Oracles hold meaningless masks. Fewer than `k` oracles hold nothing at all. The oracle is blind by protocol.                                                                                                                                                          |
| One backup plate stolen                              | Total loss                           | One share of `k`-of-`n`: nothing.                                                                                                                                                                                                                                     |
| One component lost or seized (laptop, oracle, plate) | Often total data loss                | Zero data loss. Quorums route around any single loss.                                                                                                                                                                                                                 |
| Coercion at the keyboard                             | Everything, immediately              | Delay-policy entries (section 7) cannot be revealed before notification and a waiting period, wrench or no wrench.                                                                                                                                                    |

Limits, stated plainly:

- A compromised endpoint sees every secret it reveals while compromised. The
  custody layer bounds the rate and the blast radius; it cannot make a hostile
  machine safe.
- The oracles are blind, so they judge nothing. An oracle cannot tell the owner
  from malware that holds `X` and the passphrase. The oracle gates, counts, and
  wipes; it does not verify intent.
- The scheme has an offline floor. An attacker who takes the laptop disk and
  breaches `k` oracles holds `X`, the masked shares, and the stored
  `H(pin_secret)` values, and can search the passphrase offline.
  `bcrypt_pbkdf(3)` raises the cost of that search. Passphrase quality and KDF
  cost are the floor of the whole scheme in that case.
- Detection is manual before phase 4. Phases 1 to 3 write oracle logs and send
  no alerts. Malware that reveals a few entries per day looks like the owner.
  The owner must read the logs, or the remote freeze never happens.
- Oracles see traffic patterns per record, never content. Onion provisioning
  (CLIENT-PROVISION-4) and decoy traffic can blur this.

## 5. The root: shard the master itself

If one plate restores everything, the master plate is still a single point of
catastrophic theft. The fix is the same fix: the master exists only as
`k`-of-`n` plates.

- Encoding candidates: **codex32 (BIP93)** — Shamir over Bech32, verifiable by
  hand with paper worksheets, dice-friendly, exactly this audience's aesthetic;
  **SLIP39** — wide tool interop; or plain GF(256) Shamir over the 16 entropy
  bytes, each share encoded as a BIP39 mnemonic and stamped as an ordinary
  SeedQR plate. The SeedQR-native option reuses every existing plate product and
  every signer's scan flow.
- The assembled master appears only at ceremonies: vault creation, minting a new
  batch of derived entries, adding an oracle, disaster recovery. Ceremonies can
  run on an offline live-boot.
- Between ceremonies, the master is not in RAM, not on disk, not in any oracle —
  it is metal in `n` places.

With this, the end-to-end story is uniform: **no single anything — device,
oracle, plate, person, moment — reveals or loses anything.**

### The pre-derivation pool

Daily life must not need ceremonies. At each ceremony, FuguPass pre-derives a
pool of future entry keys and BIP85 indexes, wraps each under the custody layer,
and forgets the master. Creating a new password entry then consumes one pooled
slot: no master, no dice, no ceremony. The pool size is a tunable (say, 64
future entries per ceremony).

## 6. The signer as a reveal factor

Two workable mechanisms, weakest assumptions first:

1. **Factor seed, universal.** A signer stores a dedicated factor seed and
   displays it as a SeedQR after its own PIN unlock. The laptop scans it,
   derives the share, uses it, and forgets it. Works with every SeedQR-capable
   signer today, no firmware changes. The signer's own PIN and flash protection
   guard the factor.
2. **Deterministic signature, no secret on screen.** The signer signs a fixed
   per-entry challenge over its QR message-signing flow; RFC 6979 makes the
   signature deterministic, and `KDF(signature)` is the share. The share never
   appears on any screen. Feasibility varies: anti-exfil signing modes randomize
   signatures and break determinism. A firmware support matrix is required
   (verification list, section 10).

Either way, the audience's existing signers become per-entry hardware factors:
"your multisig's passphrase deserves multisig custody too."

## 7. Oracle policy layer (later, requires FuguOracle changes)

Everything above runs on the unmodified v2 wire protocol. One further class of
value needs FuguOracle spec evolution, so it is strictly phase-gated and needs a
decision-change proposal there first (it collides with
[OPS-GET-4](../../../FuguOracle/spec/operations.md#ops-get) semantics and D-02's
spirit):

- **Delayed reveal.** A record flagged "notify, then wait" answers junk (without
  counting an attempt) until the delay passes, and notifies the operator
  channel. A thief with the laptop and the passphrase still cannot take the
  inheritance entry before the owner notices. This is the Bitcoin vault/covenant
  idea applied to secrets.
- **Velocity alarms.** Per-record rate limits and anomaly alerts, server-side,
  content-blind.

These stay wire-compatible (policy, not protocol), but they change specified
`get_pin` behavior, so they go through FuguOracle governance, not around it.

## 8. What stays from round 1

The custody layer replaces the _tier_ model with a _policy_ model; tiers become
example descriptors. Everything else in round 1 stands: the dice ceremony (now
also usable for share generation worksheets), the flat-file vault with one
ChaCha20-Poly1305 seal per entry, the `bcrypt_pbkdf(3)` rule for typed
passphrases, encrypted metadata, the strict line format, small pledged helper
programs, the REPL, SeedQR import and export, shadow entries, the plate audit,
offline TOTP, and the scoped entropy rule. The BIP85 derivation layer also
stands — it is the backup story, and the reveal layer is the security story.

## 9. Phasing

Each phase ships a usable tool and never blocks on the next.

| Phase | Ships                                                                                                                                                                                                                                                   | Requires                                              |
| ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| 1     | Per-entry blind co-decryption against **one** oracle: per-entry records, canary, per-record log observability, remote freeze, per-entry three strikes. This removes the silent offline bulk-loss case of every offline manager; detection stays manual. | FuguOracle or upstream `blind_pin_server`, unmodified |
| 2     | `k`-of-`n` oracles, deterministic Shamir, reveal descriptors (`and`, `thresh`), decoy traffic option                                                                                                                                                    | Nothing new on the wire                               |
| 3     | Signer factors (factor-seed first), sharded master (codex32 / SLIP39 / SSS-as-BIP39), inheritance descriptors, pre-derivation pool                                                                                                                      | Firmware support matrix                               |
| 4     | Delay and alarm policies at the oracle                                                                                                                                                                                                                  | FuguOracle decision change, human approval            |

## 10. To verify before specification

- Confirm mask stability end-to-end against the upstream Python server: repeated
  `get_pin` on an unchanged record returns identical bytes (OPS-GET-4 says yes;
  test it).
- Oracle record scaling: hundreds of records per client at a flat-file oracle
  (D-05 workload assumptions still hold; confirm).
- Shamir arithmetic source: GF(256) share math is small and standard, but D-03
  culture says do not hand-roll crypto — evaluate existing ISC/BSD-licensed SSS
  code, codex32 reference code, and SLIP39 libraries for auditability.
- Deterministic message signing over QR: SeedSigner, Krux, Jade current
  firmware; anti-exfil interaction.
- codex32 (BIP93) maturity and hand-computation worksheets; SLIP39 interop
  matrix.
- Traffic-analysis posture: per-record access patterns at a curious oracle; cost
  of decoy queries; onion transport via CLIENT-PROVISION-4.
- A written analysis of the deterministic Shamir split: coefficients derived
  from `M` with per-entry domain separation, against the uniform-coefficient
  assumption of the standard argument.
- A written analysis of the mask composition `c = σ ⊕ KDF(s)` as a long-term
  keystore over OPS-GET-4, beyond the protocol's analyzed use.
- `bcrypt_pbkdf(3)` round-count calibration: unlock latency on target laptops
  against offline search cost on current attack hardware.

## 11. Candidate decisions (delta to round 1)

| #   | Candidate decision                                                                                                                                              | Rationale                                                                                                                                                                                      |
| --- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 12  | Every entry has a reveal policy. The policy compiles to shares and KDF mixes. The shares must not coexist in one place outside a reveal.                        | Quorum custody per secret, enforced by construction, not by a referee. The claim covers theft at rest; the oracle gates and does not judge, and the endpoint stays sufficient during a reveal. |
| 13  | Each entry uses its own oracle records, one per oracle, with client keys derived from the local factor. Reveals are per-entry oracle events.                    | Rate limiting, audit, remote freeze, and three-strike containment per secret.                                                                                                                  |
| 14  | The client verifies the passphrase against a canary record before any real record.                                                                              | A typo must not burn attempts on entry records.                                                                                                                                                |
| 15  | Threshold logic is client-side only. FuguPass must speak unmodified protocol v2 to any conforming oracle.                                                       | Keeps FuguOracle small and generic (D-01, D-02). The oracle stays blind to policy.                                                                                                             |
| 16  | Shamir coefficients and all shares derive deterministically from the master. The written analysis of the derived coefficients (section 10) gates this decision. | Plates restore everything, and the system RNG still generates no stored secret. The standard Shamir argument assumes uniform coefficients, so the derivation needs its own proof of soundness. |
| 17  | The vault master can exist as k-of-n share plates, and the assembled master appears only during ceremonies.                                                     | Removes the last single point of catastrophic theft.                                                                                                                                           |
| 18  | Oracle-side policy features (delay, alarms) require a FuguOracle decision change before any FuguPass work assumes them.                                         | Respects FuguOracle governance; keeps phases 1–3 dependency-free.                                                                                                                              |

## 12. Open questions

1. **Root default:** sharded master (k-of-n plates) as the flagship default, or
   single master plate with sharding as the paranoid option?
2. **Share plate encoding:** codex32, SLIP39, or SSS-as-BIP39-on-SeedQR?
   Hand-verifiability versus interop versus plate-product reuse.
3. **Oracle count default:** is 2-of-3 (home box, VPS, friend) the blessed
   topology, and does the documentation ship a "run your oracle mesh" runbook?
4. **Signer factor default:** factor-seed scan (universal, secret on screen for
   seconds) or deterministic signature (cleaner, firmware-dependent)?
5. **Offline entries:** which default policy for the travel/airplane tier, and
   how loudly does the tool warn that `reveal(local)` forfeits the custody
   layer?
6. **Naming:** "reveal descriptor" — keep, or align harder with miniscript
   vocabulary?
