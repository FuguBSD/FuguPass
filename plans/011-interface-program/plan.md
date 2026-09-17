# 011 — The interface program

## Status

Proposed. It waits on plan 007 for the six commands. It is independent of plan
008 to plan 010, and plan 012 waits on it.

Implements: PROG-IFACE. Implements: PROG-SPLIT without PROG-SPLIT-4 and
PROG-SPLIT-5. Implements: PROG-REPL without PROG-REPL-6. Defers: PROG-OUTPUT.

This plan lands PROG-REPL-7 to PROG-REPL-9, and it adds PROG-SPLIT-7 to
PROG-SPLIT-10. Plan 010 lands PROG-REPL-6, the paths that work without the
oracle. PROG-SPLIT stays `partial` on the two helper rules of plan 012.

## Purpose

`fugupass-repl` is the interface process: Perl on the Fugu library, with
`Fugu::REPL` as its line editor (D-16). It reads operator command lines and
shows non-secret output, and it holds no secret. This plan lands the program,
the pipe protocol between the two processes, and the display filter. It also
lands the session lock, and the Perl gates of the repository.

## Constraints that shape the design

**The core spawns the interface.** A run of `fugupass` with no subcommand starts
the session: the core spawns `fugupass-repl` with a request pipe and a reply
pipe (PROG-IFACE-1). One request line per command, then reply lines, then one
end line with the outcome (PROG-IFACE-2). No secret and no image crosses the
pipes: a secret prints from the core to the terminal (PROG-IFACE-3).

**One process owns the terminal at a time.** The interface holds the terminal at
the prompt, and the core holds it while a command runs. The interface restores
the terminal state before each request and on every exit path, through
`Fugu::REPL` (PROG-IFACE-4, PROG-IFACE-8). The line editor watches the reply
pipe as a registered handle, so a closed pipe ends the read (PROG-IFACE-6).

**The interface pledges and never opens.** After it loads its modules, it
pledges `stdio tty` with `Fugu::Sandbox->pledge`, and
`Fugu::Sandbox->is_supported` tells enforcement from emulation (PROG-SPLIT-7,
PROG-SPLIT-8). It uses `Fugu::Log` in stderr or quiet mode, never syslog
(PROG-SPLIT-9). It installs its interrupt handler with one `Fugu::Signal`
manager and `setup_interrupt_flag` (PROG-IFACE-9).

**The build derives the unveil list.** A build step runs
`Fugu::Sandbox->perl_lib_dirs` and `Fugu::Sandbox->system_paths` and writes
`src/unveil_paths.h`, and `fugupass` carries the list (PROG-SPLIT-10). Neither
method calls a syscall, so a host test proves the list.

**The filter guards the terminal.** Core output passes the display filter of
`Fugu::REPL`. Each byte outside printable ASCII, newline, and tab is replaced,
`DEL` and the C1 range are removed, and no UTF-8 sequence breaks (PROG-IFACE-5).
Without a terminal on standard input, the interface reads plain lines with no
editing and no escape output, so a test drives it (PROG-IFACE-7).

**Completion comes from the index, and history stays in memory.** The line
editor takes the command names and the entry names of the open index through a
callback. It writes no history file (PROG-REPL-8, PROG-REPL-9). `help` and
`quit` live in the interface and reach no core path (PROG-REPL-3).

**The core locks.** The core ends the session and erases every session secret.
It does so on `quit`, on a closed request pipe, and after the idle timeout of
the config (PROG-REPL-7). The closed reply pipe then ends the interface.

**The Perl gates sync.** `.toolingrc` gains `sync.pack perl`, and `mk/local.mk`
sets `PERL_SRC_DIRS` to `bin` and `t`. The repository makes no CPAN
distribution, so the `dist` target stays unused and the `dist.*` keys stay
absent. `deps/` names Fugu for the interface and the tests.

## Files

| File                                | Change                                           |
| ----------------------------------- | ------------------------------------------------ |
| `bin/fugupass-repl`                 | The interface program                            |
| `src/iface.c`, `src/iface.h`        | The spawn, the pipes, the request loop, the lock |
| `src/fugupass.c`                    | The session start with no subcommand             |
| `src/lib/Makefile`                  | The `unveil_paths.h` step                        |
| `src/fugupass-repl/fugupass-repl.1` | The manual page                                  |
| `.toolingrc`, `mk/local.mk`         | The perl pack and the source directories         |
| `t/fugupass/repl.t`                 | The host tests below                             |
| `tests/harness.d/session`           | The guest legs below                             |
| `spec/STATUS.md`                    | The cited units, and `bin/` in the code roots    |

## Tests

`t/fugupass/repl.t` runs on the host, in plain mode, with a fake core on two
pipes, and holds:

- Each of the six commands and `help` and `quit` map to one request line or to
  no request (PROG-REPL-3).
- The filter replaces a byte outside the printable range, removes `DEL` and a C1
  byte, and keeps a two-byte UTF-8 sequence whole (PROG-IFACE-5).
- A closed reply pipe ends the program with the terminal state restored
  (PROG-IFACE-6).
- The completion callback offers the command names and the entry names of a
  listing (PROG-REPL-9).
- The program writes no file, and `perl_lib_dirs` and `system_paths` give the
  list that `src/unveil_paths.h` holds (PROG-SPLIT-10).

The harness holds, in the guest under `fuguvm expect`:

- A session unlocks, runs `ls` and `show`, and ends on `quit` with every session
  secret erased and the interface gone (PROG-REPL-7).
- An idle session locks after the config timeout (PROG-REPL-7).
- `Fugu::Sandbox->is_supported` reports enforcement, and the interface exits on
  `EPERM` when a test makes it open a file after the pledge (PROG-SPLIT-7).

## Acceptance

- `make check` passes on the host, with `make lint` and `make format` over the
  Perl sources, and `make harness` passes.
- PROG-IFACE reads `done`, and PROG-SPLIT reads `partial` with PROG-SPLIT-4 and
  PROG-SPLIT-5 as the absent rules.
- PROG-REPL reads `partial` with PROG-REPL-6 as the absent rule. It reads `done`
  after plan 010 lands PROG-REPL-6, and the later of the two plans sets the row.
- The change deletes this plan.

## What this plan does not do

It adds no core path and no command. It changes the contract of `Fugu::REPL` in
no way: a need there is a Fugu plan.
