# 006 — The vault program and vault creation

## Status

Proposed. It waits on plan 005 for the record client. Plan 007 to plan 010 wait
on it.

Implements: CER-CREATE, KEY-DEVICE, KEY-MASK. Implements: TEST-HARNESS without
TEST-HARNESS-5. Implements: PROG-SPLIT without PROG-SPLIT-4, PROG-SPLIT-5, and
PROG-SPLIT-7 to PROG-SPLIT-10. Implements: PROG-ONESHOT without PROG-ONESHOT-1
to PROG-ONESHOT-3. Implements: ENTRY-POOL without ENTRY-POOL-3 to ENTRY-POOL-9.
Implements: ORC-REVOKE without ORC-REVOKE-1 to ORC-REVOKE-5 and ORC-REVOKE-7 to
ORC-REVOKE-10. Implements: SEC-MEMORY without SEC-MEMORY-6. Defers: PROG-IFACE,
PROG-REPL, PROG-SCAN, PROG-QR, KEY-MASTER.

Of PROG-SPLIT, this plan lands PROG-SPLIT-1, PROG-SPLIT-2, PROG-SPLIT-3, and
PROG-SPLIT-6. The helper rules are plan 012, and the interface rules are
plan 011. Of PROG-ONESHOT it lands the subcommand frame and the first ceremony
subcommand of PROG-ONESHOT-4, so that rule stays partial. Of ENTRY-POOL it lands
ENTRY-POOL-1 and ENTRY-POOL-2, the pre-derivation. Of ORC-REVOKE it lands the
kit export of ORC-REVOKE-6. It completes KEY-DEVICE-2, KEY-MASK-8, and
TEST-HARNESS-8. It adds SEC-MEMORY-3 for this program, SEC-MEMORY-4, and
SEC-MEMORY-5, so SEC-MEMORY-3 stays partial until plan 012 lands the two
helpers.

## Purpose

`fugupass` is the core process: the vault, the one-shot subcommands, and the
ceremonies (D-16). This plan lands the program with its sandbox, the subcommand
frame, the passphrase read, the helper boundary, and the first ceremony: vault
creation. After it, a person with a plate and one oracle has a vault with a pool
of 64 slots.

## Constraints that shape the design

**The sandbox comes first.** `main()` sets `RLIMIT_CORE` to zero, makes every
unveil call, then pledges `stdio rpath wpath cpath flock proc exec inet dns tty`
(PROG-SPLIT-3, SEC-MEMORY-3). The unveil list is the vault directory,
`/dev/tty`, the three helpers, their runtime files, the resolver files, and
`/etc/ssl/cert.pem` for a `https` oracle. The implementation adds the CA file to
the list of PROG-SPLIT-3, as plan 004 states.

**Text crosses the helper boundary.** The core process runs `fugupass-scan` as a
child and reads one line of 12 words from its standard output. It parses no
image (PROG-SPLIT-2). The helper paths are compile-time constants. The regress
build reads them from the environment variable `FUGUPASS_HELPERS`. The harness
points the scan path at a stub that prints the test master. The implementation
adds one rule to PROG-SPLIT. "A regress build can take the helper paths from the
environment, so a test can put a double in place of a helper." The service build
holds no such path.

**The passphrase enters once, in the core.** `readpassphrase(3)` reads it from
the terminal, twice at a creation, with a required match (CER-CREATE-4,
SEC-MEMORY-4). No argument and no environment variable carries it.

**The ceremony runs its rules in order.** `ceremony.c` runs CER-CREATE-1 to
CER-CREATE-9 as nine steps. The steps start with the scan and the gate, the
device factor, the config with the plate check value, and the passphrase. They
continue with the canaries and the index wraps, the slot loop, the index, the
erasure, and the kit. The slot loop derives `K_e`, materializes both candidates,
enrolls at each oracle in list order, persists each wrap, then seals the slot
file (CER-CREATE-6). An enrollment failure stops the ceremony with the oracle
named, and a re-run is safe because a fresh `set_pin` replaces the record.

**The master lives for the ceremony.** `M`, `root`, `K_idx`, every `K_e`, every
share, and every mask clear with `explicit_bzero(3)`. They clear at the end of
the ceremony and on every failure path (CER-CREATE-8, SEC-MEMORY-5). The kit
holds no secret, so its export follows the erasure (CER-CREATE-9).

**The kit is a text file.** The revocation kit names the machine and, for each
oracle, the record file names of this machine. The record file names are the
lowercase hex of the hash of each compressed client public key, with the suffix
`.pin` (ORC-REVOKE-6). The ceremony writes it into the vault directory, and the
report names the path.

**The harness drives the terminal.** A ceremony test runs in the guest under
`fuguvm expect`, with an `expect(1)` script that answers the two passphrase
prompts (TEST-HARNESS-8). The stub scan helper supplies the master.

## Files

| File                               | Change                                             |
| ---------------------------------- | -------------------------------------------------- |
| `src/fugupass.c`                   | `main()`: the sandbox, the frame, the passphrase   |
| `src/helper.c`, `src/helper.h`     | The child run of a helper, text in and text out    |
| `src/ceremony.c`, `src/ceremony.h` | Vault creation                                     |
| `src/fugupass/Makefile`            | The program, `bsd.prog.mk`                         |
| `src/fugupass/fugupass.1`          | The manual page: the frame and `create`            |
| `tests/harness.d/create`           | The leg below, with its expect script              |
| `tests/stubs/fugupass-scan`        | The double: it prints the test master              |
| `spec/programs.md`                 | The helper-path rule and the CA file of PROG-SPLIT |
| `spec/STATUS.md`                   | The cited units                                    |

## Tests

The harness holds, against each counterparty:

- `fugupass create` with the stub helper and the expect script writes the
  factor, the config, the canary seal, and the index wrap. It also writes 64
  slot files, 64 wraps per oracle, the index, and the kit (CER-CREATE-2 to
  CER-CREATE-9).
- A mistyped second passphrase stops the ceremony before any request.
- A counterparty that refuses one `set_pin` stops the ceremony with its URL in
  the report, and a re-run completes the pool (CER-CREATE-6).
- The config holds the plate check value of the test master, and `M` appears in
  no file of the vault.
- The kit names 65 record files per oracle: the 64 slots and the canary.
- `fugupass` with an unknown subcommand exits 2 with a usage line.

`src/regress/sandbox` proves, in the guest, that the program exits with `EPERM`
on a file outside the unveil list after its pledge call.

## Acceptance

- `make check` passes on the host, and `make harness` passes.
- CER-CREATE, KEY-DEVICE, and KEY-MASK read `done`. TEST-HARNESS, PROG-SPLIT,
  ENTRY-POOL, and ORC-REVOKE read `partial` with the absent rules named.
- PROG-ONESHOT reads `partial`, and the later ceremonies and recovery paths of
  PROG-ONESHOT-4 are the absent part.
- SEC-MEMORY reads `partial` with SEC-MEMORY-6 as the absent rule, and the two
  helpers of SEC-MEMORY-3 are the absent part.
- The change deletes this plan.

## What this plan does not do

It reveals nothing and lists nothing: the pool sits unused until plan 007. It
holds no REPL and no real scan helper.
