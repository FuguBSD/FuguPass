# Security design

This document specifies the security design of FuguPass: the entropy policy, the
memory hygiene rules, and the honesty duties of the documentation.
The derivation rules are in [keys.md](keys.md).
The accepted limits of the design are in [OVW-LIMITS](overview.md#ovw-limits).

<a id="safe-entropy"></a>

## Entropy policy

- **SAFE-ENTROPY-1** — The system RNG must not generate a stored secret.
- **SAFE-ENTROPY-2** — Long-term secrets must come from dice or from derivation
  ([KEY-MASTER](keys.md#key-master), [KEY-DERIVE](keys.md#key-derive)).
- **SAFE-ENTROPY-3** — The device factor must derive from the master
  ([KEY-DEVICE](keys.md#key-device)). The tool must not create a device factor from
  the system RNG.
- **SAFE-ENTROPY-4** — Ephemeral request keypairs, IVs, seal nonces, and `set_pin`
  entropy must come from `arc4random(3)`.
- **SAFE-ENTROPY-5** — Every salt must derive from the device factor
  ([KEY-PIN](keys.md#key-pin)). A salt is not random.
- **SAFE-ENTROPY-6** — The master and `root` must not persist on disk. A one-way
  32-byte check value derived from `root` can persist on disk
  ([KEY-MASTER](keys.md#key-master)).
- **SAFE-ENTROPY-7** — A Shamir coefficient must derive from the split secret
  ([KEY-SHARE](keys.md#key-share)). The tool must not draw a coefficient from the
  system RNG.

The scope of the rule keeps the oracle protocol possible.
Every oracle request needs an ephemeral keypair and a fresh IV.
Every seal write needs a fresh nonce.
That randomness is ephemeral or public, never a stored secret.
The derived device factor lets the plate regenerate the client keys of every machine.
Revocation from the plate rests on that property
(see [ORC-REVOKE](oracle.md#orc-revoke)).

<a id="safe-memory"></a>

## Memory hygiene

- **SAFE-MEMORY-1** — Every exit path that held a secret must clear the secret with
  `explicit_bzero(3)`.
- **SAFE-MEMORY-2** — Every secret comparison must use `timingsafe_bcmp(3)`.
- **SAFE-MEMORY-3** — Every FuguPass program must set `RLIMIT_CORE` to zero with
  `setrlimit(2)`, first in `main()`. A crash must not write a secret to a core file.
- **SAFE-MEMORY-4** — The passphrase must enter through `readpassphrase(3)`.
- **SAFE-MEMORY-5** — The master must exist in memory only inside a ceremony
  ([KEY-MASTER](keys.md#key-master)).
- **SAFE-MEMORY-6** — An entry key must exist in memory for seconds only. The client
  must erase an entry key directly after the seal write or the decrypt that uses it.

OpenBSD encrypts swap by default, and the base clang hardening applies to every
build.
These platform properties support the rules above.
They replace none of them.

<a id="safe-floor"></a>

## The offline floor

- **SAFE-FLOOR-1** — The disk must hold no offline passphrase verifier. An attacker
  who holds every file on the disk cannot test a passphrase guess offline
  ([KEY-PIN](keys.md#key-pin)).
- **SAFE-FLOOR-2** — The man pages and the documentation must state the verifier
  case: an attacker with the machine's disk and one breached oracle record, with
  that oracle's static key, can search the passphrase offline. The record stores
  the hash of that record's pin secret, and the disk holds every salt. The KDF
  cost and the passphrase quality are the floor of the scheme in that case.
- **SAFE-FLOOR-3** — The documentation must state the loss case: the disk plus `k`
  breached oracles yields full offline loss of the covered entries. The attacker
  searches the passphrase against one record hash, then unmasks `k` shares per
  entry and reconstructs every entry key with no live oracle.
- **SAFE-FLOOR-4** — The documentation must state the middle case: an attacker with
  the disk, the passphrase, and `j` breached oracles, with `j` less than `k`, must
  query the remaining live oracles, online and logged: `k − j` requests per entry.

The positive claim covers the disk alone.
An oracle record stores the hash of that record's pin secret, encrypted under keys
that derive from that oracle's static key and the client public key (FuguOracle
OPS-SET-4, FuguOracle STORE-KEYS).
An attacker who takes the machine's disk, one oracle's records, and that oracle's
static key gains a verifier: the device factor derives every salt and the client
public keys, and one decrypted record hash tests every guess.
The verifier case (SAFE-FLOOR-2) assumes this breach at one oracle, and the loss
case (SAFE-FLOOR-3) assumes the same breach at `k` oracles.
A breached record of a retired or removed oracle counts toward the `k`-breach bound
until the owner destroys it by the revocation paths
([ORC-REVOKE](oracle.md#orc-revoke)).
A breached record of a retired position still serves as a passphrase verifier.
`bcrypt_pbkdf(3)` sets the cost of one guess, with the tunable round count of
[KEY-PIN](keys.md#key-pin).
The round-count calibration is a test duty ([QA-CALIBRATE](testing.md#qa-calibrate)).

<a id="safe-detect"></a>

## Detection duties

- **SAFE-DETECT-1** — The detection story must rest only on the guarantees of the
  FuguOracle specification: one log line per request with the outcome class, and a
  prominent wipe log (FuguOracle SEC-LOGGING-2).
- **SAFE-DETECT-2** — The specification and the documentation must not promise
  per-record log attribution. Record names at `LOG_DEBUG` are a permission of the
  oracle, never a promise (FuguOracle SEC-LOGGING-3).
- **SAFE-DETECT-3** — Detection is manual. No alert mechanism exists. The owner must
  read the oracle logs, or revocation never happens.
- **SAFE-DETECT-4** — The documentation must state this limit: malware that reveals
  a few entries per day looks like the owner in the logs.
- **SAFE-DETECT-5** — The documentation must ship an operator runbook that covers
  the provisioning of each oracle of the set, the example 2-of-3 topology, log
  reading at each oracle, the log coverage of every possible quorum
  (SAFE-DETECT-6), and revocation ([ORC-REVOKE](oracle.md#orc-revoke)).
- **SAFE-DETECT-6** — The documentation must state the coverage bound: an attacker
  with the machine's disk and the passphrase selects its own quorum. Guaranteed
  log coverage therefore needs logs at enough live oracles that every possible
  quorum intersects them: at most `k − 1` live oracles stay unread. With the full
  set of `n` live oracles, the count is `n − k + 1` oracles.

The observable signals are the request count and the wipe events.
Each entry reveal is one `get_pin` request at each of `k` quorum oracles
([ORC-QUORUM](oracle.md#orc-quorum)), so each quorum oracle's daily log volume
tracks the full reveal volume.
An oracle outside the session quorum sees nothing.
A prominent wipe line marks a burned record.

<a id="safe-claims"></a>

## Prohibited claims

- **SAFE-CLAIMS-1** — The documentation must not claim coercion resistance.
- **SAFE-CLAIMS-2** — The documentation must not claim a delayed reveal, a velocity
  alarm, or an oracle-side freeze. No such oracle operation exists.
- **SAFE-CLAIMS-3** — The documentation must not claim any oracle-side rate limit
  beyond the per-record three strikes.
- **SAFE-CLAIMS-4** — The specification must not assume any oracle behavior beyond
  protocol v2 as the FuguOracle specification states it (D-03).

The word "freeze" names no oracle operation.
The honest term is revocation, and [ORC-REVOKE](oracle.md#orc-revoke) lists the
three paths that exist.
The FuguOracle specification defines the junk, strike, and wipe semantics exactly.
A claim beyond that behavior misleads the user about the window between theft and
revocation.
