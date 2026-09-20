# The deterministic share split

|          |                                                   |
| -------- | ------------------------------------------------- |
| Status   | Analysis. It gates the custody layer (D-19).      |
| Covers   | TEST-SPLIT-1, TEST-SPLIT-2                        |
| Judges   | `A_j = f(S, "fugupass/v1/shamir/" ‖ k ‖ "/" ‖ j)` |
| Notation | [spec/keys.md](../../spec/keys.md)                |

Each point of TEST-SPLIT-1 has one section of its own:

| Point of TEST-SPLIT-1                              | Section |
| -------------------------------------------------- | ------- |
| Derived coefficients against uniform ones          | 4       |
| The domain separation of the coefficient labels    | 5       |
| Non-reuse across entries and against the index key | 6       |
| Independence across thresholds and re-enrollments  | 7       |

## 1. What this analysis judges

FuguPass splits two secrets: the entry key `K_e` of each slot, and the index key
`K_idx` (KEY-SHARE-1). The split is byte-wise Shamir over GF(256) (KEY-SHARE-2,
KEY-SHARE-4). Coefficient `j` at threshold `k` is
`A_j = f(S, "fugupass/v1/shamir/" ‖ k ‖ "/" ‖ j)`, for `j` from 1 to `k − 1`
(KEY-SHARE-3). The coefficients hold no fresh entropy, and they follow from the
split secret.

The standard Shamir argument assumes uniformly random coefficients. This
analysis judges what the derived coefficients do to that argument.

## 2. The conclusion

The security claim moves from information-theoretic to computational. Any
`k − 1` shares determine `S`, so perfect secrecy does not hold. The protection
that remains is the cost of a search, and `f` opens no shortcut into it. The
bound of that search is the entropy of the master: 128 bits (KEY-MASTER-1).

The surrounding design never held the property that the split gives up. Every
`K_e` and `K_idx` follows from `root` (KEY-MASTER-4). An attacker with unbounded
work recovers `root` and reads every entry, with no share at all. The derived
coefficients therefore lower no floor of the design. They do change one
statement: the sub-quorum case of OVW-RISKS-3 rests on a computational bound,
and not on an unconditional one.

The reconstruction, the correctness, and the threshold behavior stay as they
are.

## 3. The assumptions

- **B1** — HMAC-SHA256 is a pseudorandom function, and no attack recovers its
  key from outputs faster than a search (KEY-DERIVE-1).
- **B2** — The master holds 128 bits of entropy: a BIP39 mnemonic of 12 words
  (KEY-MASTER-1, D-01).
- **B3** — The coefficient label encoding is injective. Section 5 states the
  reason.
- **B4** — Under the key `S`, `f` takes coefficient labels alone. Section 5
  states the check.

Section 9 states what an attacker gains when one of the four fails.

## 4. Derived coefficients against uniform ones

### The standard argument

With uniform coefficients, any `k − 1` shares leave every candidate secret
equally likely. The argument rests on the freedom of the coefficients. One
coefficient set fits the held shares for each candidate secret, and every set
has the same probability.

### What the derivation changes

The freedom is gone. Count the equations for a 32-byte secret and `k − 1`
shares. Each share gives 32 byte equations, so the attacker holds `32(k − 1)` of
them. The unknowns are the 32 bytes of `S` alone, because the coefficients
follow from `S`. At `k = 2` the two counts match. At a higher threshold the
equations outnumber the unknowns. A wrong candidate fits 32 byte equations with
probability `2^-256`.

One candidate therefore stands, and that candidate is `S`. An attacker with
`k − 1` shares and unbounded work recovers the secret. Perfect secrecy does not
hold, and no wording restores it.

### What the claim becomes

> With any `k − 1` shares, no bounded attacker recovers `S` faster than a search
> over the candidates of `S`. One candidate costs `k − 1` calls of `f` and one
> polynomial evaluation.

The clean form of this claim needs the random oracle model for `f`. In that
model, an attacker with `q` queries and any `k − 1` shares wins with probability
near `q / N`, where `N` counts the candidates. The plain PRF assumption gives no
direct reduction here. The attacker's view holds `S` in the linear terms of the
shares. It also holds `S` in the key of `f`. The random oracle model is the
stronger assumption, and the bound above rests on it.

### The size of the candidate space

`S` is a 32-byte output of `f`, so a direct search over `S` costs `2^256`. An
attacker does better against the master. `root` holds 128 bits (B2), and every
`K_e` and `K_idx` follows from `root` (KEY-ENTRY-2, KEY-MASK-6). One candidate
root costs one BIP39 seed derivation and the calls above, and a hit opens the
whole vault. The honest bound of this construction is therefore 128 bits, and
not 256.

The same 128 bits already bound every entry key of the vault. The derived
coefficients open no weaker path, and they remove the unconditional part of the
sub-quorum claim.

### The gain that pays for the loss

Determinism keeps the entropy rule exact: no stored secret comes from the system
RNG (SEC-ENTROPY-1, SEC-ENTROPY-7). The plate re-derives every share through
`K_e`, with no oracle and no stored coefficient
([REC-PLATE](../../spec/recovery.md#rec-plate)).

Two flows show why the coefficients must be deterministic. Each flow needs a
share at an index that no live wrap covers. KEY-SHARE-8 forbids a share on disk,
and forbids a retained share between uses. Every use re-derives the coefficients
from the split secret, and evaluates the polynomial. The secret in hand is
therefore the only source of a missing share.

- **A canary repair.** A canary re-enrollment at oracle `i` replaces that
  oracle's canary mask, and this machine's index wrap of that oracle dies. A
  client that holds `K_idx` in session memory must re-wrap at once. It must
  re-derive `share(K_idx, i)`, and it must wrap that share under the fresh
  canary mask (ORC-CANARY-8). The old mask never returns (REC-WIPE-3). The
  client can run this repair at any time, without a ceremony (ORC-CANARY-5). The
  master stays absent outside a ceremony (D-12), so `root` is out of reach here.
- **An added oracle.** An added oracle takes the next free position. For each
  slot, the tool re-derives the split of `K_e`, and evaluates the share at the
  new index (CER-PROVISION-14). The oracle is new, so no wrap holds a share at
  that index. This ceremony does hold `root` (CER-PROVISION-1), and `root` gives
  `K_e`. It gives no coefficient of a random split.

### Alternatives considered

**A random coefficient set.** The machine draws a fresh set at provisioning,
writes every wrap in one pass, and discards the set. Neither flow above can then
rebuild its missing share. An added oracle would need the original polynomial.
The tool must collect `k` shares from a quorum, and interpolate it first. The
below-threshold secrecy would also rest on the system RNG, and SEC-ENTROPY-7
forbids that draw. A predictable RNG gives the coefficients, and one share then
gives the secret. This alternative moves no floor either. The plate check value
sits on the disk (KEY-MASTER-5, VAULT-CONFIG-5). It tests a candidate master at
128 bits, with no share at all.

**A root-keyed coefficient.** The tool derives `A_j` from `root`, under a label
that carries the slot. `S` then leaves the key of `f`. The attacker's view no
longer holds `S` in the key of `f` and in the linear terms together. The
alternative fails on two counts. The canary repair needs `root` under it, so
that repair becomes a plate ceremony. ORC-CANARY-5 grants that repair at any
time, without a ceremony, and this alternative takes the grant away. The index
key carries the second count. `K_idx` has no slot number (KEY-MASK-6), so the
proposed label has no form for it.

## 5. The domain separation of the coefficient labels

The label is `"fugupass/v1/shamir/" ‖ k ‖ "/" ‖ j`, with `k` and `j` as unpadded
decimal ASCII (KEY-SHARE-3).

The encoding is injective, and the solidus carries that property. Neither `k`
nor `j` holds a solidus, so one string names one pair. Without the separator the
encoding would fail: the pair `(1, 23)` and the pair `(12, 3)` would both give
`123`. The solidus keeps them apart as `1/23` and `12/3`.

The key domain is the tighter check. Under the key `S`, `f` takes coefficient
labels and nothing else. The label table of [keys.md](../../spec/keys.md) keys
every other label with `root`, with the device factor `X`, or with a mask. The
separation question reduces to the pair `(k, j)`, and the paragraph above
settles it. B4 names this condition, because a later label under the key `S`
would reopen the question.

One reuse deserves the record. `K_e` keys two primitives: HMAC-SHA256 for the
coefficients (KEY-SHARE-3), and ChaCha20-Poly1305 for the entry seal
(KEY-ENTRY-3, VAULT-SEAL-2). No known attack crosses the two primitives under
one key, and this analysis rests on that absence. A separate derivation for each
use would remove the question.

## 6. Non-reuse across entries and against the index key

The split secret carries the separation. No nonce and no counter exist.

- Each entry key is unique. `K_e = f(root, "fugupass/v1/entry-key" ‖ e)`
  (KEY-ENTRY-2), and the slot index is the only separator (KEY-ENTRY-4). Two
  slots give two labels, so two independent keys under B1.
- The index key takes its own label: `K_idx = f(root, "fugupass/v1/index-key")`
  (KEY-MASK-6). No slot label matches it, because a slot label carries different
  text before the suffix.
- Coefficient `A_j` of one slot and coefficient `A_j` of another slot take one
  label under two different keys. The two values are independent under B1. A
  share of one entry therefore says nothing about another entry, and nothing
  about the index key.
- A vault holds fewer than `2^31` slots (KEY-ENTRY-1). The chance of two equal
  entry keys stays below `2^-195`.

One case breaks the separation: a repeated split secret. Two slots with one
entry key would share every coefficient and every share. The uniqueness of the
slot index therefore carries the whole property, and a ceremony reserves each
index (KEY-ENTRY-1).

## 7. Independence across thresholds and across re-enrollments

### Across thresholds

The label carries the threshold (KEY-SHARE-3). The coefficient set of one
threshold and the set of another take different labels. Both take one key, so
the two sets are independent under B1. A threshold change derives a fresh set.

The freshness has a cost. The share of oracle `i` changes while `K_e` stays, so
two shares of one entry at one oracle exist. Their XOR cancels the secret term
and holds coefficient terms alone. An attacker who read both wraps under one
mask would gain an offline test of a candidate master. That test is not new. The
plate check value on the disk already gives a cheaper one (KEY-MASTER-5,
VAULT-CONFIG-5), so the case grants no new capability against the master. It
breaks the one-time-pad model of the wrap, and CER-PROVISION-15 closes the case.
The availability reason of that rule carries it. The ceremony takes a fresh
`set_pin` for every record of this machine, at every live oracle. No wrap key
then covers two plaintexts. [mask-composition.md](mask-composition.md) states
the same finding from the other side.

### Across re-enrollments

A re-enrollment changes neither the secret, nor the threshold, nor the oracle
index. Every coefficient is identical after a re-enrollment, and each share is
identical too. Independence does not hold here, and the construction does not
need it: the mask rotates instead (ORC-ENROLL-4). The new wrap covers the same
plaintext under a new key, and that direction is safe.

The consequence for the operator is plain. A passphrase change does not rotate a
share. `K_e` follows from `root` and the slot index (KEY-ENTRY-2), so only a
different slot gives a different share. A share that leaked stays a valid share
of that entry.

## 8. What does not change

- The reconstruction. Any `k` shares with distinct indexes interpolate to the
  secret (KEY-SHARE-6). The source of the coefficients does not enter that step.
- The threshold behavior. `k − 1` shares give no direct reading of the secret,
  and the search of section 4 stays the only path.
- The `k = 1` case. The polynomial is constant, no coefficient exists, and every
  share equals the secret (KEY-SHARE-7). This analysis is empty at that
  threshold, and the mask alone carries the custody.

## 9. What an attacker gains when an assumption fails

| Assumption | The failure                      | What the attacker gains                                                     |
| ---------- | -------------------------------- | --------------------------------------------------------------------------- |
| B1         | HMAC-SHA256 is not a PRF         | `S` from `k − 1` shares, at the cost of the new attack                      |
| B2         | The master holds less entropy    | Every entry key, with a share or without one                                |
| B3         | Two pairs `(k, j)` share a label | One coefficient repeats across two thresholds, and relates their share sets |
| B4         | A later label takes the key `S`  | A value under `S` reaches another use, where its exposure tests `S`         |

## 10. Approval

TEST-SPLIT-2 requires one human approval of this analysis, and D-19 makes the
approval part of the acceptance of the custody layer. The approver reads
sections 2, 3 and 9, and accepts the move from an unconditional claim to a
computational one. The approver then replaces both placeholders of the line
below.

Approved by `<name>` on `<date>`.
