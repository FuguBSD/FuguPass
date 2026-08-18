# Key derivation

This document specifies the derivation tree of FuguPass.
Each derived key has exactly one defining rule in this document.
Other documents cite these units.
A document that repeats a formula must cite the defining unit in this document.

Notation, defined here and used across the specification:

- `M` is the master mnemonic.
- `root` is the BIP39 seed of `M` with an empty BIP39 passphrase.
- `f(k, label)` is HMAC-SHA256 with key `k` and message `label`. The output is
  32 bytes.
- `H(x)` is SHA-256.
- `e` is a slot index. A label encodes `e` as unpadded decimal ASCII.
- `i` is an oracle index: the 1-based position of an oracle in the ordered oracle
  list ([VAULT-CONFIG](vault.md#vault-config)). A label encodes `i` as unpadded
  decimal ASCII.
- `n` is the count of oracle positions, and `k` is the threshold. Both are
  vault-wide (D-20).
- `i/e` is the per-record label suffix: `i`, one solidus, then `e`. The canary
  form is `i/canary`, with the literal `canary` in place of `e`. The solidus
  keeps the suffix unambiguous, because a decimal index holds no solidus.
- `share(S, i)` is the share of oracle `i` from the split of a 32-byte secret `S`
  ([KEY-SHARE](keys.md#key-share)).
- `s_ei` is the mask of the record of slot `e` at oracle `i`. `s_canary_i` is the
  canary mask at oracle `i`. `c_ei` and `c_idx_i` are the stored wraps.
- `‖` is byte concatenation. `⊕` is byte-wise exclusive or.

`f` takes high-entropy keys only.
A label suffix concatenates after the label string with `‖`.
The machine-name suffix is the UTF-8 bytes of the machine name.
Every derivation label is unique and carries the prefix `fugupass/v1/`:

| Label | Derives | Suffix |
| --- | --- | --- |
| `fugupass/v1/entry-key` | the entry key `K_e` | the slot index `e` |
| `fugupass/v1/device-factor` | the device factor `X` | the machine name |
| `fugupass/v1/client-key` | the client key `ck_ei` | `i/e`, or `i/canary` |
| `fugupass/v1/pin-salt` | the pin salt `salt_ei` | `i/e`, or `i/canary` |
| `fugupass/v1/wrap` | the wrap key `wk_ei` | `i/e` |
| `fugupass/v1/shamir/` | coefficient `j` of a share split | the threshold `k`, one solidus, the coefficient index `j` |
| `fugupass/v1/index-key` | the index key `K_idx` | none |
| `fugupass/v1/wrap-index` | the index wrap key of oracle `i` | `i` |
| `fugupass/v1/canary-check` | the canary check seal key of oracle `i` | `i` |
| `fugupass/v1/plate-check` | the plate check value | none |

Exact label strings, fully expanded, for slot 17 at oracle 2, with threshold 3
and coefficient 1: `fugupass/v1/client-key` ‖ `2/17`, `fugupass/v1/pin-salt` ‖
`2/17` (canary: `2/canary`), `fugupass/v1/wrap` ‖ `2/17`,
`fugupass/v1/wrap-index` ‖ `2`, `fugupass/v1/canary-check` ‖ `2`,
`fugupass/v1/shamir/` ‖ `3/1`.
`e`, `i`, `j`, and `k` are unpadded decimal ASCII. `i` is 1-based.

<a id="key-master"></a>

## The master

- **KEY-MASTER-1** — One vault has one master `M`: a BIP39 mnemonic of 12 words
  (D-01).
- **KEY-MASTER-2** — The master enters a vault by the dice ceremony
  ([CER-DICE](ceremonies.md#cer-dice)), by a SeedQR scan, or as a BIP85 child of an
  external seed.
- **KEY-MASTER-3** — The master appears only during ceremonies and must not persist
  on disk.
- **KEY-MASTER-4** — Every vault key derives from `root`.
- **KEY-MASTER-5** — The plate check value is `f(root, "fugupass/v1/plate-check")`.
  This one-way 32-byte value can persist on disk. `M` and `root` must not persist
  on disk.

The dice-rolled master is the documented default.
A BIP85 child of an existing cold seed is a supported alternative, and the tool
stays neutral between the two input paths.
BIP85 derivation is one-way: a vault compromise reveals nothing about the parent
seed.
The master and the vault passphrase are different secrets: `M` is the recovery root
on the plate, and the passphrase is the daily reveal secret
([KEY-PIN](keys.md#key-pin)).

<a id="key-derive"></a>

## Derivation functions

- **KEY-DERIVE-1** — `f(k, label)` is HMAC-SHA256 with key `k` and message `label`,
  with a 32-byte output.
- **KEY-DERIVE-2** — Every derivation label must be unique and must carry the
  prefix `fugupass/v1/`. The label table above is the complete list.
- **KEY-DERIVE-3** — Every input key of `f` must be high-entropy. This rule has no
  exception.
- **KEY-DERIVE-4** — A typed passphrase must not enter `f`. A typed passphrase
  passes through `bcrypt_pbkdf(3)` only, and the bcrypt_pbkdf output serves only as
  the oracle `pin_secret` ([KEY-PIN](keys.md#key-pin), D-09).

The passphrase rule keeps the disk free of an offline passphrase verifier.
[SAFE-FLOOR](security.md#safe-floor) states the offline search floor for the case
where an attacker holds both the disk and the oracle record.

<a id="key-entry"></a>

## Entry keys and slots

- **KEY-ENTRY-1** — Slot indexes are sequential unsigned integers. A ceremony
  reserves them ([ENTRY-POOL](entries.md#entry-pool)), and they stay below 2^31.
- **KEY-ENTRY-2** — The entry key of slot `e` is
  `K_e = f(root, "fugupass/v1/entry-key" ‖ e)`.
- **KEY-ENTRY-3** — The entry file of slot `e` seals under `K_e`
  ([VAULT-SEAL](vault.md#vault-seal)).
- **KEY-ENTRY-4** — The slot index is the derivation domain separator. The entry
  name must not enter any derivation.

Entry names are mutable, and slot indexes are not.
The derivation of `K_e` from `root` carries the plate-alone recovery path
([REC-PLATE](recovery.md#rec-plate)): the plate re-derives every `K_e` with no
oracle and no passphrase.
The entry file name is the lowercase hex of `H(K_e)`
([VAULT-LAYOUT](vault.md#vault-layout)).

<a id="key-device"></a>

## Device factor

- **KEY-DEVICE-1** — The device factor of a machine is
  `X = f(root, "fugupass/v1/device-factor" ‖ machine-name)`.
- **KEY-DEVICE-2** — `X` persists on disk on its machine, in the machine-local set
  ([VAULT-LAYOUT](vault.md#vault-layout)), and must not move to another machine.
- **KEY-DEVICE-3** — The machine name is a user-chosen label. The config file and
  the revocation kit record it. The machine name is not secret. The machine name
  holds lowercase ASCII letters, digits, and hyphens only, with 1 to 64 bytes.
- **KEY-DEVICE-4** — The plate regenerates `X` for any machine name.

KEY-DEVICE-4 carries provisioning and revocation (D-10).
A plate ceremony re-derives a stolen machine's `X` and client keys on a surviving
machine, so the owner revokes the stolen machine's records from the plate alone
([ORC-REVOKE](oracle.md#orc-revoke)).

<a id="key-client"></a>

## Client keys

- **KEY-CLIENT-1** — The client key material of the record for slot `e` at
  oracle `i` is `t_ei = f(X, "fugupass/v1/client-key" ‖ i/e)`.
- **KEY-CLIENT-2** — The client must interpret `t_ei` as a big-endian integer and
  must compute the secp256k1 private key as `ck_ei = (t_ei mod (q − 1)) + 1`,
  where `q` is the secp256k1 group order.
- **KEY-CLIENT-3** — The canary client key of oracle `i` uses the label suffix
  `i/canary`.
- **KEY-CLIENT-4** — A client key must not depend on the passphrase.

The reduction in KEY-CLIENT-2 keeps the private key in the range 1 to `q − 1`.
The bias of the reduction is negligible, because `q` is close to 2^256.
The FuguOracle client model requires a keypair that does not depend on the reveal
secret, or the attempt counter never moves (FuguOracle CLIENT-MODEL).

<a id="key-pin"></a>

## Passphrase and pin secrets

- **KEY-PIN-1** — One vault has one passphrase. The reveal secret is a passphrase
  of any length, never a numeric PIN (D-09).
- **KEY-PIN-2** — The pin salt of the record for slot `e` at oracle `i` is
  `salt_ei = f(X, "fugupass/v1/pin-salt" ‖ i/e)`. The canary pin salt of oracle
  `i` uses the suffix `i/canary`.
- **KEY-PIN-3** — The pin secret of the record for slot `e` at oracle `i` is
  `pin_ei = bcrypt_pbkdf(passphrase, salt_ei, rounds)`, with an output of exactly
  32 bytes.
- **KEY-PIN-4** — `pin_ei` serves only as the oracle `pin_secret`. No other
  derivation takes `pin_ei`.
- **KEY-PIN-5** — The round count is tunable, and the config file records it
  ([VAULT-CONFIG](vault.md#vault-config)).

The oracle payload requires a 32-byte `pin_secret`, which matches the
bcrypt_pbkdf output length.
KEY-PIN-4 keeps the disk free of an offline passphrase verifier: no stored value
verifies the passphrase without the oracle.
Each record has its own salt, so a session computes bcrypt_pbkdf once per canary
record of the quorum and once per oracle for each revealed entry: `k` runs per
revealed entry.
[QA-CALIBRATE](testing.md#qa-calibrate) records the round-count calibration.

<a id="key-share"></a>

## The share split

- **KEY-SHARE-1** — A split secret is one 32-byte key. Exactly two secrets split:
  the entry key `K_e` of each slot, and the index key `K_idx`. The split takes
  the vault-wide parameters `n` and `k`, with `1 ≤ k ≤ n ≤ 255` (D-20,
  [VAULT-CONFIG](vault.md#vault-config)).
- **KEY-SHARE-2** — The split is byte-wise Shamir over GF(256) with the field
  polynomial `x^8 + x^4 + x^3 + x + 1`. A byte is a polynomial over GF(2).
  Addition and subtraction are `⊕`. Multiplication is polynomial multiplication,
  reduced modulo the field polynomial. Division is multiplication by the
  multiplicative inverse.
- **KEY-SHARE-3** — Coefficient `j` of the split of a secret `S` at threshold `k`
  is the 32-byte value `A_j = f(S, "fugupass/v1/shamir/" ‖ k ‖ "/" ‖ j)`, for
  `j` = 1 to `k − 1`, with `k` and `j` as unpadded decimal ASCII. The
  coefficients are deterministic. The tool must not draw a coefficient from the
  system RNG ([SAFE-ENTROPY](security.md#safe-entropy)).
- **KEY-SHARE-4** — Byte `b` of the secret splits under the polynomial
  `p_b(x) = S[b] ⊕ A_1[b]·x ⊕ … ⊕ A_{k−1}[b]·x^{k−1}`, in GF(256). The secret
  sits at `x = 0`: `p_b(0) = S[b]`.
- **KEY-SHARE-5** — The share of oracle `i` is the 32-byte value `share(S, i)`,
  with byte `b` equal to `p_b(i)`. The evaluation point of oracle `i` is its
  oracle index, 1-based ([ORC-PROVISION](oracle.md#orc-provision)). The share
  size equals the secret size: 32 bytes.
- **KEY-SHARE-6** — The reconstruction takes any `k` shares with distinct
  indexes, from an index set `Q`, and interpolates at `x = 0`, byte-wise:
  `S[b] = ⊕_{i∈Q} share(S, i)[b] · L_i`, with `L_i = Π_{m∈Q, m≠i} m / (m ⊕ i)`
  in GF(256).
- **KEY-SHARE-7** — With `k = 1`, the polynomial is the constant `S[b]`, and
  every share equals the secret. The wrap of [KEY-MASK](keys.md#key-mask) is then
  `c_ei = K_e ⊕ wk_ei`, with no special case in code or in text.
- **KEY-SHARE-8** — A share must not persist on disk, and the tool must not
  retain a share between uses. Every use re-derives the coefficients from the
  split secret and evaluates the polynomial at the oracle index
  ([ORC-ENROLL](oracle.md#orc-enroll),
  [CER-PROVISION](ceremonies.md#cer-provision)).
- **KEY-SHARE-9** — A written soundness analysis of the deterministic
  coefficients gates the custody layer ([QA-SPLIT](testing.md#qa-split), D-19).

The deterministic split keeps the entropy rule exact: the system RNG stores no
secret, and the plate re-derives every share through `K_e`
([REC-PLATE](recovery.md#rec-plate)).
Per-entry domain separation comes from the split secret itself: each `K_e` is
unique, so no coefficient repeats across entries or against the index key.
The coefficient label carries the threshold, so a threshold change derives a
fresh coefficient set ([CER-PROVISION](ceremonies.md#cer-provision)).
The standard Shamir argument assumes uniformly random coefficients, so the
derived coefficients need their own analysis ([QA-SPLIT](testing.md#qa-split)).

<a id="key-mask"></a>

## Mask and wrap keys

- **KEY-MASK-1** — The mask `s_ei` is the 32-byte answer of oracle `i` for the
  record of slot `e`. The mask is stable for an unchanged record. Stability is a
  consequence of FuguOracle OPS-GET-4, and [QA-MASK](testing.md#qa-mask) verifies
  it by test.
- **KEY-MASK-2** — The client must not store a mask. This rule covers every
  `s_ei` and every `s_canary_i`.
- **KEY-MASK-3** — The wrap key of slot `e` at oracle `i` is
  `wk_ei = f(s_ei, "fugupass/v1/wrap" ‖ i/e)`.
- **KEY-MASK-4** — The stored wrap of slot `e` at oracle `i` is
  `c_ei = share(K_e, i) ⊕ wk_ei` ([KEY-SHARE](keys.md#key-share)). `c_ei` lives
  in the machine-local set. Each machine's records yield their own masks, so each
  machine holds its own wraps, one per oracle.
- **KEY-MASK-5** — The seal key of the canary check of oracle `i` is
  `f(s_canary_i, "fugupass/v1/canary-check" ‖ i)`, where `s_canary_i` is that
  machine's canary mask at oracle `i`. The canary check value seals under this
  key ([ORC-CANARY](oracle.md#orc-canary)).
- **KEY-MASK-6** — The index key is `K_idx = f(root, "fugupass/v1/index-key")`.
  The index file is a shared ciphertext object sealed under `K_idx`
  ([VAULT-INDEX](vault.md#vault-index)).
- **KEY-MASK-7** — Each machine holds one machine-local index wrap per oracle:
  `c_idx_i = share(K_idx, i) ⊕ f(s_canary_i, "fugupass/v1/wrap-index" ‖ i)`
  ([KEY-SHARE](keys.md#key-share)).
- **KEY-MASK-8** — A plate ceremony re-derives `K_idx` directly from `root`.
- **KEY-MASK-9** — No offline passphrase verifier exists on disk.

`c_ei` alone is ciphertext, and `s_ei` alone is a meaningless string at the
oracle (D-06).
A daily index read unwraps `k` index shares through the session's canary masks,
so the read needs no oracle request beyond the session's `k` canary `get_pin`
requests ([ORC-CANARY](oracle.md#orc-canary)).
The composition `c_ei = share(K_e, i) ⊕ wk_ei` uses the oracle answer beyond the
protocol's analyzed purpose, and the deterministic split replaces the
uniform-coefficient assumption.
A written analysis gates each construction
([QA-ANALYSIS](testing.md#qa-analysis), [QA-SPLIT](testing.md#qa-split), D-19).

<a id="key-bip85"></a>

## BIP85 applications

- **KEY-BIP85-1** — A derived password comes from the BIP85 application PWD BASE64
  (D-17).
- **KEY-BIP85-2** — A derived child mnemonic comes from the BIP85 application
  BIP39.
- **KEY-BIP85-3** — Both applications take `root` as the BIP32 seed.
- **KEY-BIP85-4** — The BIP85 index of a slot is the slot index `e`.
- **KEY-BIP85-5** — A ceremony materializes, for every new slot, the PWD BASE64
  password and the BIP39 child mnemonic, and seals both candidates in the slot
  file under `K_e`.
- **KEY-BIP85-6** — Entry creation keeps the candidate that the entry type needs.
  A derived passphrase entry consumes the PWD BASE64 candidate.
- **KEY-BIP85-7** — Known-answer vectors from a reference implementation gate the
  implementation ([QA-KAT](testing.md#qa-kat)).
- **KEY-BIP85-8** — The PWD BASE64 derivation must use the fixed password length of
  21 characters. The BIP39 derivation must use the English wordlist and 12 words.
  The parameters are fixed constants, because plate-alone recovery re-derives with
  no metadata ([REC-PLATE](recovery.md#rec-plate)).

Slot indexes stay below 2^31 ([KEY-ENTRY](keys.md#key-entry)), so every slot index
is a valid BIP85 index.
Ceremony-time materialization keeps the master out of daily life: entry creation
never needs `M` ([ENTRY-POOL](entries.md#entry-pool)).
