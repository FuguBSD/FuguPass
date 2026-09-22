# 012 — The two helpers

## Status

Proposed. It waits on no other plan.

Implements: PROG-SCAN, PROG-QR, KEY-MASTER, TEST-KAT. Implements: PROG-SPLIT,
PROG-OUTPUT, SEC-MEMORY, PROG-BUILD. Implements: VAULT-BACKUP without
VAULT-BACKUP-3.

This plan completes KEY-MASTER-2, TEST-KAT-3, PROG-SPLIT-4 and PROG-SPLIT-5,
PROG-OUTPUT-2, and SEC-MEMORY-3 for the two helpers. It adds VAULT-BACKUP-4, and
VAULT-BACKUP stays `partial` on the statement of plan 013. Of PROG-BUILD, it
lands the directories of the two helper programs, the one absent part.

## Purpose

The camera and the QR codecs are the real parser attack surface, so they live in
two sandboxed helpers. The vault process parses no image (D-15). `fugupass-scan`
turns camera frames into one line of text, and `fugupass-qr` turns standard
input into a QR code on the terminal. This plan lands both, and with them the
real scan path of the master and the QR display of a mnemonic.

## Constraints that shape the design

**The scan helper emits words and nothing else.** It opens one video device,
reads frames through the `video(4)` interface, decodes a QR code, and writes the
decoded payload as text (PROG-SCAN-1). It accepts the Standard SeedQR form
alone: 48 digits in numeric mode, mapped to 12 words of the word table. Every
other digit count and every byte-mode code is a failure (PROG-SCAN-2,
PROG-SCAN-3, D-22). It computes no checksum; the master gate of KEY-MASTER-6
does.

**The decoder and the encoder are named.** The scan helper decodes with a small
ISC-licensed decoder, in tree or from a port. The render helper encodes with
`libqrencode` from the ports tree. The manual page of each helper records the
library, its provenance, and its license (PROG-QR-5). The source evaluation
names the candidates that the developer weighed.

**The sandbox fits each helper.** `fugupass-scan` unveils no path, and it
pledges `stdio video` after it opens the device. The core process carries the
video devices in its unveil list, and its execpromises hold `video`
(PROG-SPLIT-4). `fugupass-qr` pledges `stdio` (PROG-SPLIT-5). Both set
`RLIMIT_CORE` to zero first (SEC-MEMORY-3).

**The render helper knows two shapes.** A mnemonic renders in the Standard
SeedQR form, version 2, numeric mode, so a signer scans it from the screen
(PROG-QR-2). A vault file renders as one QR code up to the one-code capacity. A
larger file is a report, not a code (PROG-QR-3, VAULT-BACKUP-4). Each code
carries a quiet zone of 4 light modules on every side. The output is UTF-8 half
blocks (PROG-QR-1).

**The mnemonic code is mask 0.** FuguSeed pins mask pattern 0 (its D-08 and its
QR-MATRIX-4), and its one picture fixture holds that mask. `libqrencode` picks a
mask by penalty score, so it can emit another one. The helper therefore re-masks
a mnemonic code. It reads the mask number from the format bits of the library
output. It undoes that pattern over the data modules, and applies pattern 0. It
then writes the format bits `111011111000100` for level L and mask 0. The
implementation adds one rule to PROG-QR. "A mnemonic code must be version 2,
level L, numeric mode, and mask pattern 0." The vault-file shape of PROG-QR-3
pins no mask.

**The fixture is the FuguSeed fixture.** Test vector 4 of the SeedQR
specification is the one reference image. FuguSeed holds its 25 x 25 picture as
text at `t/fuguseed/fixtures/qr/vector4.picture`, at commit `18b2bfc`, with the
SHA-256 `6753c34ec4e0029578a9e1d5afe652d3af97f1a32559b4208f904ff513f48d1a`. This
plan copies that file byte for byte, and it records the commit and the digest
beside the copy. It rasterizes the picture into a PGM image with a quiet zone of
4 light modules on each side, and feeds the decoder. The two projects then prove
the handoff on one public vector: FuguSeed draws it, and FuguPass reads it.

**The default of a mnemonic is the code.** `show` on a mnemonic entry pipes the
words to `fugupass-qr`, and an explicit flag prints them as text
(PROG-OUTPUT-2). The core process runs the helper as a child through the
boundary of `src/helper.h`.

## Files

| File                                                     | Change                                      |
| -------------------------------------------------------- | ------------------------------------------- |
| `src/fugupass-scan.c`                                    | The capture, the decode, the digit map      |
| `src/fugupass-qr.c`                                      | The two shapes and the half-block render    |
| `src/fugupass-scan/Makefile`, `src/fugupass-qr/Makefile` | The two programs                            |
| `src/fugupass-scan/fugupass-scan.1`                      | The manual page, with the decoder record    |
| `src/fugupass-qr/fugupass-qr.1`                          | The manual page, with the encoder record    |
| `src/Makefile`                                           | `SUBDIR` for the two program directories    |
| `src/commands.c`                                         | The QR default of a mnemonic                |
| `src/sandbox.h`, `src/sandbox.c`                         | The video rows and the `video` promise      |
| `src/regress/scan.c`, `src/regress/qr.c`                 | The tests below                             |
| `src/regress/sandbox.c`                                  | The video test below                        |
| `src/regress/Makefile`                                   | The two new test programs                   |
| `tests/vectors/seedqr/`                                  | The picture, the PGM, the negative fixtures |
| `tests/harness`, `tests/harness.d/`                      | The real scan helper, and the legs below    |
| `tests/stubs/fugupass-scan.c`                            | The double, apart from the real helper      |
| `docs/analysis/qr-library-sources.md`                    | The source evaluation of the two libraries  |
| `spec/STATUS.md`                                         | The cited units                             |

## Tests

`src/regress/scan` feeds the decoder from fixtures, with no camera, and holds:

- The PGM of test vector 4 decodes to its 48 digits and its 12 words
  (TEST-KAT-3).
- A Compact SeedQR fixture in byte mode and a 24-word Standard SeedQR fixture of
  96 digits both fail (TEST-KAT-3, D-22).
- The output is one line of 12 words and nothing else (PROG-SCAN-5).
- `getrlimit(2)` after the core-limit call of the helper reads a `RLIMIT_CORE`
  of zero (SEC-MEMORY-3).

`src/regress/qr` holds:

- The render of the 12 words of test vector 4, mapped from half blocks back to
  modules, equals the picture module for module. The picture is mask 0, so the
  test fails when the re-mask step is absent.
- The render carries a quiet zone of 4 light modules on each side.
- A vault file of one sealed entry renders as one code, and a file above the
  capacity gives a report and no code (PROG-QR-3).
- A child that makes the pledge call of the helper then opens a file, and the
  kernel kills that child. The promise set is `stdio` alone, and a file open
  needs a promise outside it (PROG-SPLIT-5).
- `getrlimit(2)` after the core-limit call of the helper reads a `RLIMIT_CORE`
  of zero (SEC-MEMORY-3).

`src/regress/sandbox` gains, for the core process of PROG-SPLIT-4:

- `SANDBOX_EXEC_PROMISES` holds `video`, so a child of the exec probe pledges
  `stdio video` and survives. That call dies without the promise.
- The unveil list of `sandbox_enter()` holds each `/dev/video*` device of the
  machine, and a child of the exec probe opens one of them. A hidden path and an
  absent file both give `ENOENT`, so this probe needs the machine of the manual
  scan below.

The harness holds, in the guest:

- `fugupass create` with the real scan helper and a video device fails with a
  report that names the device when none exists (PROG-SCAN-7).
- `show` on a mnemonic entry writes half blocks, and the flag writes words
  (PROG-OUTPUT-2).

A scan from a camera of a drawn code runs by hand, on a machine with a video
device. The manual page names it as the proof of a drawing.

## Acceptance

- `make check` passes on the host, and `make regress` and `make harness` pass in
  the guest.
- PROG-SCAN, PROG-QR, KEY-MASTER, TEST-KAT, PROG-SPLIT, PROG-OUTPUT, PROG-BUILD
  and SEC-MEMORY read `done`. VAULT-BACKUP reads `partial` with VAULT-BACKUP-3
  as the absent rule.
- The change deletes this plan.

## What this plan does not do

It decodes no Compact SeedQR and no 24 words, by decision. It relays no oracle
envelope over a QR code.
