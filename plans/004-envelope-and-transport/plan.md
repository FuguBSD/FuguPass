# 004 — The envelope and the transport

## Status

Proposed. It waits on plan 001 for the build skeleton. Plan 005 waits on it. It
is independent of plan 002.

Implements: ORC-CONFORM without ORC-CONFORM-2 and ORC-CONFORM-3. Implements:
SEC-ENTROPY without SEC-ENTROPY-4. Defers: ORC-PROVISION, PROG-SPLIT,
TEST-HARNESS.

ORC-CONFORM-2 and ORC-CONFORM-3 bind the records, in plan 005. The transport
rule that this plan adds to ORC-CONFORM names the client. The unveil path that
it needs lands with the program in plan 006. This plan draws the ephemeral
keypair and the IV of SEC-ENTROPY-4. Plan 002 draws the seal nonce, and plan 005
draws the `set_pin` entropy.

## Purpose

FuguPass speaks version 2 of the `blind_pin_server` protocol to any conforming
oracle, unmodified (D-02). This plan lands the client side of that protocol: the
request envelope, the response open, and one small HTTP client. Every function
is bytes in, bytes out, and the known-answer vectors of FuguOracle pin them.

## Constraints that shape the design

**The envelope mirrors the oracle shim.** `envelope.c` derives the tweaked
oracle key with `secp256k1_xonly_pubkey_tweak_add` from the provisioned static
public key, the ephemeral key, and the counter. It runs ECDH, splits HMAC-SHA512
under the two labels, seals with AES-256-CBC and HMAC-SHA256, and opens the
response. It signs the payload hash with `secp256k1_ecdsa_sign_recoverable`, in
the 65-byte form of the protocol. Every primitive comes from `libsecp256k1` and
`libcrypto` (D-15).

**The vectors are the FuguOracle vectors.** The generator of FuguOracle writes
both sides of each transcript, with the ephemeral private key. This plan copies
that header into `tests/vectors/oracle.h`, with a comment that names its source
and its commit. A seal with the vector's ephemeral key and IV must equal the
vector request, and the vector response must open to the vector key.

**The oracle authenticates through the envelope.** A `200` body whose MAC or
decrypt fails is an authentication failure, distinct from an HTTP error and from
a transport failure (ORC-CONFORM-4). The client returns the three states as
three values, and a later decrypt failure of the caller is the fourth, junk.

**The transport is one POST over `libtls`.** The specification names no HTTP
client. This plan chooses HTTP/1.1 over a plain socket or over `libtls` from
base, inside the core process, within the `inet dns` promises of PROG-SPLIT-3.
`http.c` sends one POST per request with a JSON body, and reads one response of
at most 4096 bytes. It extracts the `data` member with a strict scanner, the
mirror of the oracle's reader. The implementation adds this rule to ORC-CONFORM:
"The transport is HTTP/1.1 over a socket or over `libtls`, in the core process.
It sends one POST per request and reads the response with a strict reader." A
`https` URL needs the CA file, so PROG-SPLIT-3 gains `/etc/ssl/cert.pem` (`r`)
in its unveil list, in plan 006.

**Every request draws fresh.** The ephemeral keypair and the IV come from
`arc4random(3)` for every request (ORC-CONFORM-5, SEC-ENTROPY-4). The regress
build takes both as arguments, so the vectors apply.

## Files

| File                               | Change                                           |
| ---------------------------------- | ------------------------------------------------ |
| `src/envelope.c`, `src/envelope.h` | The tweak, the seal, the open, the signature     |
| `src/http.c`, `src/http.h`         | The POST, the response reader, the JSON scanner  |
| `src/regress/envelope.c`           | The vector tests below                           |
| `src/regress/http.t`               | The transport tests below, with a fixture server |
| `tests/vectors/oracle.h`           | The copied vectors                               |
| `spec/oracle.md`                   | The transport rule of ORC-CONFORM                |
| `spec/STATUS.md`                   | The cited units, and the new code roots          |

## Tests

`src/regress/envelope` holds:

- The tweaked oracle key, the shared secret, and the two key halves match the
  vectors for both labels.
- A request seal with the vector ephemeral key and IV equals the vector bytes,
  for the 97-byte and the 129-byte payload.
- The vector response opens to the vector key, and a response with one changed
  tag byte fails before any decrypt.
- The signature over the vector payload hash recovers to the client public key
  through the FuguOracle recovery function of the same vectors.

`src/regress/http.t` starts a fixture server in Perl, from the OpenBSD base, and
holds:

- A `200` with a `data` member returns the decoded bytes.
- A `500`, a `413`, and a `400` return the HTTP-error state with the status.
- A refused connection and a closed socket return the transport-failure state.
- A body with a duplicate `data` member, without `data`, or over 4096 bytes is a
  transport failure that names the reader.

## Acceptance

- `make check` passes on the host, and `make regress` passes in the guest.
- ORC-CONFORM reads `partial` with ORC-CONFORM-2 and ORC-CONFORM-3 as the absent
  rules, and its text holds the transport rule.
- SEC-ENTROPY reads `partial` with SEC-ENTROPY-4 as the absent rule. The note
  names each absent part of SEC-ENTROPY-4.
- The change deletes this plan.

## What this plan does not do

It knows no record, no counter, and no passphrase. It sends nothing to a live
oracle: plan 005 does.
