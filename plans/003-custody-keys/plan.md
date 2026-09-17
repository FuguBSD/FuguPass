# 003 — The custody keys and the share split

## Status

Proposed. It waits on plan 001 for `f` and the build skeleton. Plan 005 waits on
it. It is independent of plan 002 and plan 004.

Implements: KEY-CLIENT, KEY-PIN, KEY-SHARE, TEST-SPLIT, TEST-ANALYSIS.
Implements: KEY-DEVICE without KEY-DEVICE-2. Implements: KEY-MASK without
KEY-MASK-4 and KEY-MASK-8. Implements: SEC-ENTROPY. Defers: ORC-ENROLL,
ORC-REVEAL, VAULT-INDEX.

KEY-DEVICE-2 and KEY-MASK-4 are the writes of the device factor and the wraps,
in plan 005 and plan 006. KEY-MASK-8 is the plate ceremony of plan 006. This
plan adds SEC-ENTROPY-3, SEC-ENTROPY-5, and SEC-ENTROPY-7. The two analyses
reach `done` when the human approval line holds a name and a date.

## Purpose

The custody layer splits each entry key across the oracle set and masks each
share with a stable oracle answer (D-06, D-20). This plan lands the math of that
layer, offline and with no oracle: the device factor and the client keys. It
also lands the pin salts and the pin secret, the deterministic Shamir split over
GF(256), and the wrap keys. It also lands the vectors and the two written
analyses that gate the layer (D-19).

## Constraints that shape the design

**The split is in-tree, and the arithmetic is stated.** D-15 allows an in-tree
implementation when the specification states the full arithmetic and an
independent reference pins the outputs. KEY-SHARE-2 to KEY-SHARE-6 state it.
`share.c` multiplies in GF(256) with a branch-free shift-and-reduce loop over
the polynomial `0x11B`, with no table, so the arithmetic takes constant time.
The source evaluation of TEST-SPLIT-5 records the candidates that the developer
weighed and this choice.

**The coefficients derive, and the shares never rest.** Coefficient `j` is
`f(S, "fugupass/v1/shamir/" ‖ k ‖ "/" ‖ j)` (KEY-SHARE-3). The split function
takes the secret, `k`, and `i`, and it returns the one share of oracle `i`. No
function returns every share at once, so a caller cannot hold a share set
between uses (KEY-SHARE-8). With `k = 1`, the share equals the secret with no
branch (KEY-SHARE-7).

**The client key reduces with a big number.** `ck_ei = (t_ei mod (q − 1)) + 1`
needs a 256-bit modulus, and `libsecp256k1` exposes no scalar arithmetic. The
reduction uses the `BN` functions of `libcrypto` with the constant-time flag
(KEY-CLIENT-2, D-15). The source evaluation records this too.

**The passphrase touches one function.** `pin_ei` is `bcrypt_pbkdf(3)` from
`libutil` over the passphrase and `salt_ei`, with the round count as an argument
and 32 output bytes (KEY-PIN-3). No other function takes the passphrase
(KEY-DERIVE-4).

**Two documents wait for a human.** `docs/analysis/mask-composition.md` covers
the key reuse across reveals, the KDF of the mask, and the wrap XOR of a share
(TEST-ANALYSIS-2). `docs/analysis/share-split.md` covers the derived
coefficients against uniform ones, the label domain separation, and the
non-reuse across entries and the index key. It also covers the independence
across thresholds and re-enrollments (TEST-SPLIT-1). Each document ends with one
approval line. The reviewer fills the name and the date at the merge, or the
unit stays `partial`.

**The vectors come from an independent implementation.** An independent
implementation pins the standard parts: the GF(256) field operations, the
polynomial evaluation, and the Lagrange interpolation (TEST-SPLIT-4, D-15). The
source evaluation names the implementation that produced the vectors
(TEST-SPLIT-5). The coefficient derivation is FuguPass-specific: it is `f` under
the `shamir/` label (KEY-SHARE-3). No external implementation produces it. The
vectors of `f` in plan 001 and the coefficient vectors of this plan pin it. The
vectors cover the thresholds 1, 2, and 3 with up to 5 oracles, and threshold 1
holds the `k = 1` reduction. The committed header pins the C code.

## Files

| File                                        | Change                                                              |
| ------------------------------------------- | ------------------------------------------------------------------- |
| `src/share.c`, `src/share.h`                | GF(256), the split, the reconstruction                              |
| `src/derive.c`, `src/derive.h`              | `X`, `t_ei`, `ck_ei`, `salt_ei`, `wk_ei`, the index and canary keys |
| `src/pin.c`, `src/pin.h`                    | `pin_ei` through `bcrypt_pbkdf(3)`                                  |
| `src/regress/share.c`                       | The tests below                                                     |
| `tests/vectors/generate.py`                 | The custody labels and the coefficients                             |
| `tests/vectors/share.h`                     | The committed vectors                                               |
| `docs/analysis/mask-composition.md`         | The analysis of TEST-ANALYSIS                                       |
| `docs/analysis/share-split.md`              | The analysis of TEST-SPLIT-1                                        |
| `docs/analysis/share-arithmetic-sources.md` | The source evaluation of TEST-SPLIT-5                               |
| `spec/STATUS.md`                            | The cited units, and `src/share.c` in the code roots                |

## Tests

`src/regress/share` runs offline and holds (TEST-SPLIT-6):

- The field multiplication and the inverse match the vectors, and `a · a⁻¹` is 1
  for every nonzero byte.
- The share of each oracle matches the vectors for each threshold.
- Any `k` shares reconstruct the secret, and `k − 1` shares give a value that
  differs from it.
- With `k = 1`, every share equals the secret.
- The client key of the test master at oracle 2 for slot 17 matches the vector,
  and `secp256k1_ec_seckey_verify` accepts it (KEY-CLIENT-2).
- The machine name gate accepts `laptop-1` and rejects an upper-case letter, a
  space, an empty name, and 65 bytes (KEY-DEVICE-3).
- `pin_ei` matches the vector for the test passphrase, and two salts give two
  values.
- The wrap key and the canary check seal key match the vectors.

## Acceptance

- `make check` passes on the host, and `make regress` passes in the guest.
- KEY-CLIENT, KEY-PIN, and KEY-SHARE read `done`. KEY-DEVICE and KEY-MASK read
  `partial` with the absent rules named. TEST-SPLIT and TEST-ANALYSIS read
  `done` when the approval lines hold a name and a date.
- The change deletes this plan.

## What this plan does not do

It sends no request, writes no wrap, and holds no masks: it computes what plan
005 persists.
