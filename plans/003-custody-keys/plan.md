# 003 — The custody keys and the share split

## Status

Proposed. It waits on plan 001 for `f` and the build skeleton. Plan 005 waits on
it. It is independent of plan 002 and plan 004.

Implements: KEY-CLIENT, KEY-PIN, KEY-SHARE, TEST-SPLIT, TEST-ANALYSIS.
Implements: KEY-DEVICE without KEY-DEVICE-2. Implements: KEY-MASK without
KEY-MASK-4 and KEY-MASK-8. Implements: TEST-KAT without TEST-KAT-2 and
TEST-KAT-3. Implements: SEC-ENTROPY without SEC-ENTROPY-4. Defers: ORC-ENROLL,
ORC-REVEAL, VAULT-INDEX.

KEY-DEVICE-2 and KEY-MASK-4 are the writes of the device factor and the wraps,
in plan 005 and plan 006. KEY-MASK-8 is the plate ceremony of plan 006. This
plan derives the index wrap key of KEY-MASK-7, and plan 006 writes the index
wrap itself. This plan adds SEC-ENTROPY-3, SEC-ENTROPY-5, and SEC-ENTROPY-7.
Three plans land SEC-ENTROPY-4. Plan 002 draws the seal nonce, plan 004 draws
the ephemeral keypair and the IV, and plan 005 draws the `set_pin` entropy. This
plan lands the eight custody labels of TEST-KAT-4, and plan 001 landed the other
two. Plan 002 lands TEST-KAT-2, and the later of plan 002 and plan 003 sets the
TEST-KAT row. The two analyses reach `done` when the human approval line holds a
name and a date.

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
(KEY-DERIVE-4). The Python standard library holds no `bcrypt_pbkdf(3)`, so a
third one-time generator, `tests/vectors/generate-pin.py`, writes the `pin_ei`
vector. It runs on the `bcrypt` module of PyPI, outside the dependency set, so
`deps/` gains no entry. The developer runs it once and commits the vector, as
with the share generator. `docs/analysis/share-arithmetic-sources.md` names this
source too.

**Two documents wait for a human.** `docs/analysis/mask-composition.md` covers
the key reuse across reveals, the KDF of the mask, and the wrap XOR of a share
(TEST-ANALYSIS-2). `docs/analysis/share-split.md` covers the derived
coefficients against uniform ones, the label domain separation, and the
non-reuse across entries and the index key. It also covers the independence
across thresholds and re-enrollments (TEST-SPLIT-1). Each document ends with one
approval line. The reviewer fills the name and the date at the merge, or the
unit stays `partial`.

**The vectors come from implementations that this project does not own.** Two
generators write the share vectors, and they pin every part of TEST-SPLIT-4
(D-15). The `hmac` module of the Python standard library is an independent
HMAC-SHA256. `tests/vectors/generate.py` keeps each coefficient `f(S, label)` of
KEY-SHARE-3 on that module, because `f` is HMAC-SHA256 (KEY-DERIVE-1). A
separate one-time generator, `tests/vectors/generate-share.py`, produces the
field operations, the share evaluation, and the reconstruction. It runs on an
independent GF(256) Shamir implementation, outside the dependency set of this
repository, so `deps/` gains no entry. The developer runs it once and commits
the vectors. `docs/analysis/share-arithmetic-sources.md` names that
implementation, and the source evaluation records both sources (TEST-SPLIT-5).
The label strings come from `spec/keys.md`, which is specification and not an
implementation. The vectors cover the thresholds 1, 2, and 3 with up to 5
oracles, and threshold 1 holds the `k = 1` reduction. The committed header pins
the C code.

## Files

| File                                        | Change                                                              |
| ------------------------------------------- | ------------------------------------------------------------------- |
| `src/share.c`, `src/share.h`                | GF(256), the split, the reconstruction                              |
| `src/derive.c`, `src/derive.h`              | `X`, `t_ei`, `ck_ei`, `salt_ei`, `wk_ei`, the index and canary keys |
| `src/pin.c`, `src/pin.h`                    | `pin_ei` through `bcrypt_pbkdf(3)`                                  |
| `src/regress/share.c`                       | The tests below                                                     |
| `tests/vectors/generate.py`                 | The eight custody labels and the coefficients                       |
| `tests/vectors/generate-share.py`           | The share generator, outside the dependency set                     |
| `tests/vectors/generate-pin.py`             | The pin generator, outside the dependency set                       |
| `tests/vectors/share.h`                     | The committed vectors of the three generators                       |
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
- The device factor of `laptop-1` and the pin salt of slot 17 at oracle 2 match
  the vectors (TEST-KAT-4).
- `pin_ei` matches the vector for the test passphrase, and two salts give two
  values.
- The wrap key, the index key, the index wrap key, and the canary check seal key
  match the vectors (TEST-KAT-4).

## Acceptance

- `make check` passes on the host, and `make regress` passes in the guest.
- KEY-CLIENT, KEY-PIN, and KEY-SHARE read `done`. KEY-DEVICE, KEY-MASK, and
  SEC-ENTROPY read `partial` with the absent rules named. TEST-SPLIT and
  TEST-ANALYSIS read `done` when the approval lines hold a name and a date.
- The KEY-MASK note also names the absent index wrap of KEY-MASK-7.
- TEST-KAT reads `partial` with TEST-KAT-2 and TEST-KAT-3 as the absent rules.
  Plan 002 lands TEST-KAT-2, and the later of the two plans sets the row.
- The change deletes this plan.

## What this plan does not do

It sends no request, writes no wrap, and holds no masks: it computes what plan
005 persists.
