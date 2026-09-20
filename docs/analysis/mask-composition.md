# The mask composition as a long-term keystore

|          |                                                            |
| -------- | ---------------------------------------------------------- |
| Status   | Analysis. It gates the custody layer (D-19).               |
| Covers   | TEST-ANALYSIS-1, TEST-ANALYSIS-2, TEST-ANALYSIS-3          |
| Judges   | `c_ei = share(K_e, i) ⊕ f(s_ei, "fugupass/v1/wrap" ‖ i/e)` |
| Notation | [spec/keys.md](../../spec/keys.md)                         |

Each point of TEST-ANALYSIS-2 has one section of its own:

| Point of TEST-ANALYSIS-2 | Section |
| ------------------------ | ------- |
| Key reuse across reveals | 4       |
| The KDF of the mask      | 5       |
| The wrap XOR of a share  | 6       |

## 1. What this analysis judges

FuguPass stores one wrap for each record of each machine. The wrap is
`c_ei = share(K_e, i) ⊕ wk_ei`, and the wrap key is
`wk_ei = f(s_ei, "fugupass/v1/wrap" ‖ i/e)` (KEY-MASK-3, KEY-MASK-4). The mask
`s_ei` is the answer of oracle `i` for that record. The mask reaches no disk
(KEY-MASK-1, KEY-MASK-2).

The blind PIN oracle releases one answer to a correct PIN, and it counts three
strikes per record. The protocol states no guarantee that the answer repeats.
The repetition is a consequence of FuguOracle OPS-GET-4 (KEY-MASK-1). FuguPass
builds a keystore of years over that consequence, so the construction uses the
oracle answer beyond the protocol's analyzed purpose. This analysis judges that
step.

## 2. The conclusion

The composition is sound under the four assumptions of section 3. One wrap key
covers exactly one plaintext, so the wrap gives the secrecy of a one-time pad.
The claim is computational, because the wrap key is a PRF output and not a
uniform draw. The construction adds no attack that
[OVW-RISKS](../../spec/overview.md#ovw-risks) does not already record.

The composition gives confidentiality alone. It gives no integrity, and it gives
no forward secrecy. It lays one duty on the ceremonies: no wrap key covers a
second plaintext. CER-PROVISION-15 carries that duty, and section 4 states the
case that it covers.

## 3. The assumptions

- **A1** — The mask is unpredictable. The oracle computes its key share
  `aes_key` as `HMAC(key = server_random32, msg = entropy)`, with
  `server_random32` from `arc4random_buf(3)` and `entropy` from the client
  (FuguOracle OPS-SET-3). The client draws that entropy from `arc4random(3)`
  (SEC-ENTROPY-4). The mask is `HMAC(key = aes_key, msg = pin_ei)` (FuguOracle
  OPS-GET-4). An attacker needs `aes_key` and `pin_ei` to compute the mask.
- **A2** — HMAC-SHA256 is a pseudorandom function. `f` is HMAC-SHA256
  (KEY-DERIVE-1), and the mask meets the entropy condition of KEY-DERIVE-3 under
  A1.
- **A3** — One mask covers one plaintext under one label. The ceremonies hold
  this rule (CER-PROVISION-15, ORC-ENROLL-4).
- **A4** — The mask repeats for an unchanged record (KEY-MASK-1).
  [TEST-MASK](../../spec/testing.md#test-mask) pins the repetition against every
  counterparty (D-19).

Section 7 states what an attacker gains when one of the four fails.

## 4. Key reuse across reveals

The mask is stable for an unchanged record (KEY-MASK-1), so the same wrap key
`wk_ei` recurs at every reveal. The judgement of this analysis: the recurrence
is safe, and the two-time-pad case does not arise.

A reveal reads `c_ei`, computes `wk_ei`, and recovers one share. A reveal writes
no wrap to the client's disk. The count of plaintexts under `wk_ei` therefore
stays at one for the life of the record. Key reuse harms a stream cipher when
two plaintexts meet one keystream, and one plaintext meets this key.

The recurrence still costs three things, and each one is real.

1. No forward secrecy exists. A breach of the record unmasks every wrap that the
   machine wrote before the breach. The attacker also needs the disk and the
   passphrase (OVW-RISKS-3).
2. The rotation is manual. Only a `set_pin` gives a record a fresh key share
   (FuguOracle OPS-SET-3), so a leaked mask stays valid until a re-enrollment.
3. The client re-reads the same 32 bytes at every reveal. Each read is one more
   moment for a compromised endpoint to take the mask (OVW-RISKS-1). The erasure
   rules bound that window (SEC-MEMORY-1, SEC-MEMORY-6).

One case breaks the rule of one plaintext per key (KEY-MASK-10), and the
specification names it. A threshold change alters every share, while `K_e`, the
oracle index, and the label all stay the same (CER-PROVISION-15). A tool that
wrote the new wrap under the old mask would publish `share_old ⊕ share_new` to a
holder of both wraps. CER-PROVISION-15 forbids that case. The ceremony takes a
fresh `set_pin` for every record of this machine, at every live oracle. Every
mask therefore rotates before the new wraps land. CER-PROVISION-15 puts the
fresh-mask duty on the availability reason: a stale wrap under a live mask would
keep the old threshold reachable. That rule records the two-plaintext case too,
and it states that the case adds no new capability against the master. Section 6
states what the case costs.

The opposite direction is safe. A passphrase change rotates the mask and keeps
the share (ORC-ENROLL-4). Two wraps of one plaintext under two keys give the XOR
of the two wrap keys, and that value says nothing about the share.

## 5. The KDF of the mask

The mask and the share are both 32 bytes, so `f` adds no length. The KDF gives
four other things over the raw mask.

1. Per-record domain separation. The suffix `i/e` binds the wrap key to one slot
   at one oracle (KEY-DERIVE-2). One leaked wrap key therefore opens one record,
   and no other record of that machine. The canary mask shows the second need:
   `s_canary_i` carries the canary check seal key and the index wrap key
   (KEY-MASK-5, KEY-MASK-7). The two labels differ, so the two keys are
   independent under A2. Without a label, one mask would give one key for every
   use of that mask.
2. Extraction. The mask comes from the oracle, and the client cannot audit the
   draw. HMAC over a high-entropy input gives a pseudorandom output, also when
   the input carries structure. A1 and A2 state the conditions.
3. A one-way step. A client that holds a wrap key cannot compute the mask. A
   scrape of one index wrap key therefore gives no canary check seal key, and no
   other key of the same mask.
4. A version marker. Every label carries the prefix `fugupass/v1/`
   (KEY-DERIVE-2), so a later construction takes new keys and leaves this one
   whole.

The KDF gives nothing against a breached oracle record. That oracle holds the
key share, and one passphrase guess gives `pin_ei` and then the mask
(SEC-FLOOR-2). The KDF adds one HMAC call to each guess, and the
`bcrypt_pbkdf(3)` cost dominates the guess (KEY-PIN-3).

## 6. The wrap XOR of a share

The XOR hides the share exactly when two conditions hold at once.

- The wrap key covers exactly one plaintext for its whole life.
- The attacker can neither compute the wrap key nor read it.

Under the two conditions and A2, `c_ei` is indistinguishable from 32 random
bytes. A uniform one-time key would give an information-theoretic claim. This
key is a PRF output over the mask, so the claim is computational, and the PRF
strength of HMAC-SHA256 sets it.

Four things break the construction, and each one has a bound.

**Two plaintexts under one wrap key.** A holder of both wraps reads
`share_old ⊕ share_new`. The two polynomials share the constant term, so the XOR
cancels the secret and holds coefficient terms alone. The value still tests a
candidate master: a guess gives `root`, then `K_e`, then both coefficient sets,
then both shares. That test is not new. The machine-local set holds the config
file, and the config file holds the plate check value (VAULT-LAYOUT-4,
VAULT-CONFIG-1). One HMAC on `root` tests the same guess against that value
(KEY-MASTER-5, VAULT-CONFIG-5). The case therefore gives the attacker no new
capability against the master. SEC-FLOOR-1 forbids a passphrase verifier on the
disk, and this value is not one. The risk table names the same offline test for
a machine's disk ([OVW-RISKS](../../spec/overview.md#ovw-risks)). The search
also stays at the entropy of the master, 128 bits (KEY-MASTER-1). What the case
breaks is A3 and KEY-MASK-10, and the claim of this section then covers neither
wrap.

**A predictable mask.** A failure of the oracle RNG and a failure of the client
draw together give the key share to an attacker. The key material mixes server
entropy and client entropy (FuguOracle OPS-SET-3), so a prediction needs both
draws. The client can detect neither failure.

**A read of the mask.** Three paths give the mask away: a live oracle answer
with the passphrase, a breached record with the passphrase, and a compromised
endpoint. [OVW-RISKS](../../spec/overview.md#ovw-risks) records all three.

**The missing tag.** The XOR carries no authentication. An attacker with write
access to the machine-local set can flip bits of `c_ei`. The flip carries into
the reconstructed key, because the XOR and the interpolation are both linear.
The client sees the damage at the entry decrypt alone, where the
ChaCha20-Poly1305 seal fails (VAULT-SEAL-2). The malleability gives denial, and
it gives no disclosure.

The share contributes nothing at `k = 1`. Every share equals the secret
(KEY-SHARE-7), so one mask with the disk and the passphrase gives `K_e`. The
quorum makes the mask one factor of several, and a 1-of-1 topology has no
quorum.

## 7. What an attacker gains when an assumption fails

| Assumption | The failure                              | What the attacker gains                                                                                                    |
| ---------- | ---------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| A1         | The oracle draw and the client draw fail | The mask, and then the share, with `pin_ei`                                                                                |
| A2         | HMAC-SHA256 is not a PRF                 | The computational claim of section 6 falls, and with it each claim here                                                    |
| A3         | Two plaintexts meet one wrap key         | The XOR of the two shares. It tests a candidate master, and the plate check value on the disk tests one too (KEY-MASTER-5) |
| A4         | The oracle answer changes                | No secret. The wraps stop opening, and the plate restores the vault                                                        |

## 8. Approval

TEST-ANALYSIS-3 requires one human approval of this analysis, and D-19 makes the
approval part of the acceptance of the custody layer. The approver reads
sections 2, 3 and 7, and accepts the assumptions and the residual risks. The
approver then replaces both placeholders of the line below.

Approved by `<name>` on `<date>`.
