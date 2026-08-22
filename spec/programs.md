# Programs

This document specifies the FuguPass programs: the vault program, the interface
program, the scan helper, and the QR render helper. Each program runs on OpenBSD
and restricts itself with `pledge(2)` and `unveil(2)`. Each program has a man
page in `mdoc(7)`: `fugupass(1)`, `fugupass-repl(1)`, `fugupass-scan(1)`, and
`fugupass-qr(1)`. In an interactive session, `fugupass` is the core process, and
`fugupass-repl` is the interface process.

<a id="cli-split"></a>

## Program split

- **CLI-SPLIT-1** — FuguPass has exactly four programs. Each program has one job
  (D-15, D-16). `fugupass` holds the vault core, the one-shot subcommands, and
  the ceremonies. `fugupass-repl` holds the REPL: it reads operator command
  lines and shows non-secret output ([CLI-IFACE](programs.md#cli-iface)).
  `fugupass-scan` turns camera frames into decoded QR text on stdout.
  `fugupass-qr` turns stdin into a QR code on the terminal.
- **CLI-SPLIT-2** — The vault process must not parse camera data and must not
  parse QR image data (D-15). The camera code and the QR codecs live in the
  helper programs only.
- **CLI-SPLIT-3** — `fugupass` must make its unveil calls before its pledge call
  and must pledge `stdio rpath wpath cpath flock proc exec inet dns tty`. It
  must unveil only these paths: the vault directory (`rwc`), `/dev/tty` (`rw`),
  the three child programs (`x`), the runtime files that the child programs load
  (`r`), and the resolver files that name lookup needs (`r`).
- **CLI-SPLIT-4** — `fugupass-scan` must unveil the video devices
  (`/dev/video*`) only and must pledge `stdio video` after it opens the device.
- **CLI-SPLIT-5** — `fugupass-qr` must pledge `stdio` only.
- **CLI-SPLIT-6** — FuguPass must not implement an agent process and must not
  implement a network service. The oracle client inside `fugupass` is the only
  network code (D-18).
- **CLI-SPLIT-7** — `fugupass-repl` is Perl on the Fugu library, and Fugu::REPL
  is its line editor (D-16). After it loads its modules, it must pledge
  `stdio tty`. It must not open a file, must not create a process, and must not
  reach the network.
- **CLI-SPLIT-8** — `fugupass-repl` must make its pledge call with
  `Fugu::Sandbox->pledge`, with the promises `stdio tty`. Off OpenBSD the method
  restricts nothing and returns success. `Fugu::Sandbox->is_supported` reports
  the difference, so a test can tell enforcement from emulation.
- **CLI-SPLIT-9** — `fugupass-repl` must use `Fugu::Log` in stderr mode or in
  quiet mode. It must not use syslog mode, because syslog mode opens a socket.
  The `stdio tty` promise set holds no socket.
- **CLI-SPLIT-10** — The build must derive the unveil list of the interface
  process from `Fugu::Sandbox->perl_lib_dirs` and `Fugu::Sandbox->system_paths`,
  and `fugupass` must carry the derived list. The first method names the library
  directories of the perl that runs. The second method names `/dev/urandom`, the
  resolver files, the service tables and the time zone file. Neither method
  calls a syscall, so a test can prove the list off OpenBSD.

`fugupass` runs the interface program and the helpers as child processes and
exchanges text over pipes. Text crosses the process boundary, never image data
and never a secret. The scan helper carries the camera and codec attack surface
and holds no vault key and no oracle key. The render helper holds only the bytes
on its stdin. The interface process carries the line editor and the command
parser and holds no secret ([CLI-IFACE](programs.md#cli-iface)). The interface
process lives only for its session, so it is not an agent process (D-18). The
runtime files of a child program are its dynamic linker, its shared libraries,
and, for the interface process, the Perl runtime and the Fugu modules.

<a id="cli-iface"></a>

## The interface boundary

- **CLI-IFACE-1** — A run of `fugupass` with no subcommand must start the
  interactive session: the core process spawns `fugupass-repl` as a child, with
  a request pipe and a reply pipe. The interface process reads operator command
  lines, and the core process executes every command.
- **CLI-IFACE-2** — The pipe protocol is line-oriented text: one request line
  per command, then reply lines, then one end line with the outcome. Image data
  and secret bytes must not cross the pipes.
- **CLI-IFACE-3** — A secret must not enter the interface process. The core
  process reads the passphrase with `readpassphrase(3)` from the terminal
  ([SAFE-MEMORY](security.md#safe-memory)), and it prints each secret to the
  terminal or pipes it to `fugupass-qr` ([CLI-OUTPUT](programs.md#cli-output)).
- **CLI-IFACE-4** — One process at a time owns the terminal: the interface
  process at the prompt, the core process while a command runs. The interface
  process must restore the terminal state before each request and on every exit
  path.
- **CLI-IFACE-5** — The interface process must show core output through the
  display filter of Fugu::REPL. The filter must replace each byte outside
  printable ASCII, newline, and tab, must remove `DEL` (0x7F) and the C1 range
  (0x80–0x9F), and must not break a UTF-8 sequence.
- **CLI-IFACE-6** — When the core process ends the session, the closed reply
  pipe must end the interface process. At the prompt, the line editor must watch
  the reply pipe as a registered handle.
- **CLI-IFACE-7** — When standard input is not a terminal, the interface process
  must read plain lines, with no line editing and no escape output. Scripted
  tests drive the session in this mode.
- **CLI-IFACE-8** — Fugu::REPL must read one line in raw mode, and must restore
  the terminal state on every exit path. It must accept one extra read handle,
  and that handle must end the read when it becomes readable. It must load with
  core Perl only, and it must operate inside the `stdio tty` pledge. The `.pod`
  sidecar of the module in the Fugu repository is its interface contract.
- **CLI-IFACE-9** — The interface process must install its interrupt handlers
  with one `Fugu::Signal` manager: it must build the manager, and it must then
  call `setup_interrupt_flag` on it. The signal path is one exit path, so the
  process must restore the terminal state.

Entry names and oracle error text carry external bytes, so the display filter
guards the operator's terminal. Fugu::REPL holds the terminal in raw mode only
while it reads a line, and it restores the terminal state on every exit path.
The module loads with core Perl only and operates inside the `stdio tty` pledge.
Its interface contract lives in the Fugu repository. FuguTTX builds its operator
REPL on the same module, so a change to the contract coordinates with FuguTTX
through Fugu.

<a id="cli-repl"></a>

## The REPL

- **CLI-REPL-1** — The session must read the passphrase once, in the core
  process, with `readpassphrase(3)` ([CLI-IFACE](programs.md#cli-iface)), and
  must verify it against the canary record of each quorum oracle before any
  entry record of that oracle ([ORC-CANARY](oracle.md#orc-canary),
  [ORC-QUORUM](oracle.md#orc-quorum), D-08).
- **CLI-REPL-2** — When the session quorum covers `k` live index wraps of this
  machine ([ORC-QUORUM](oracle.md#orc-quorum)), the session's canary `get_pin`
  requests must also open the index through those index wraps
  ([KEY-MASK](keys.md#key-mask), [VAULT-INDEX](vault.md#vault-index)). When the
  session quorum cannot cover `k` live index wraps of this machine
  ([ORC-CANARY](oracle.md#orc-canary)), the tool must report each dead or
  unreachable index wrap and must name the provisioning ceremony
  ([CER-PROVISION](ceremonies.md#cer-provision)).
- **CLI-REPL-3** — The REPL must provide six commands: `ls`, `show`, `add`,
  `gen`, `totp`, and `audit`. `ls` lists the entries from the open index. `show`
  reveals one entry. `add` imports a stored secret into a pool slot. `gen`
  creates a derived entry from a pool slot. `totp` reveals a totp entry and
  computes the code locally. `audit` reports stale shadow entries and the last
  plate verification date. The interface process adds `help` and `quit`, and
  they reach no core path.
- **CLI-REPL-4** — Each `show` and each `totp` is one per-entry quorum event:
  `k` `get_pin` requests ([ORC-QUORUM](oracle.md#orc-quorum), D-07). `add` and
  `gen` consume one pool slot each, with one quorum reveal of the consumed slot
  ([ENTRY-POOL](entries.md#entry-pool)). `audit` reads shadow metadata through
  quorum reveals ([ENTRY-SHADOW](entries.md#entry-shadow)).
- **CLI-REPL-5** — With fewer than `k` reachable oracles, the tool must perform
  no reveal and must report the state of each oracle
  ([ORC-QUORUM](oracle.md#orc-quorum)). On an HTTP error or a transport failure
  at a quorum oracle, the tool can substitute the next reachable oracle after
  that oracle's canary check, and must refuse the reveal only when no untried
  quorum remains (ORC-QUORUM-5). The report uses the distinct HTTP-error and
  transport-failure states of [ORC-REVEAL](oracle.md#orc-reveal), and both are
  distinct from the junk report.
- **CLI-REPL-6** — Plate verification and every data-restore path must work
  without the oracle ([CER-VERIFY](ceremonies.md#cer-verify),
  [REC-PRINCIPLE](recovery.md#rec-principle), D-04).
- **CLI-REPL-7** — The core process must lock on the end of the session and
  after an idle timeout with no request, and must erase every session secret
  with `explicit_bzero(3)` ([SAFE-MEMORY](security.md#safe-memory)). The lock
  ends the session and, through the closed reply pipe, the interface process
  ([CLI-IFACE](programs.md#cli-iface)). The timeout is a tunable in the config
  file ([VAULT-CONFIG](vault.md#vault-config)).
- **CLI-REPL-8** — The interface process must read each command line with the
  Fugu::REPL line editor: emacs-style line editing, tab completion of command
  names and entry names from the open index listing, and a session history in
  memory. The interface process must not write a history file, because a history
  file leaks entry names (D-14).
- **CLI-REPL-9** — Fugu::REPL must take each completion candidate from a caller
  callback. The interface process gives the command names and the entry names of
  the open index listing, as CLI-REPL-8 states.

`ls` reads the open index and sends no entry request. The unlock reads the
passphrase once and verifies it at the canary record of each quorum oracle. Each
reveal in the session computes one `pin_ei` per quorum oracle
([KEY-PIN](keys.md#key-pin)), so a session that reveals many entries pays the
KDF cost `k` times per entry. An HTTP error is not an attempt and is retryable.
A transport failure is ambiguous, and a junk answer can burn a strike
([ORC-REVEAL](oracle.md#orc-reveal)). The reports therefore name different user
actions.

<a id="cli-oneshot"></a>

## One-shot subcommands

- **CLI-ONESHOT-1** — Every REPL command must exist as a one-shot subcommand of
  `fugupass`.
- **CLI-ONESHOT-2** — A one-shot subcommand and its REPL command must run the
  same core paths, in the same core program: the same canary check, the same
  reveal path, and the same output rules.
- **CLI-ONESHOT-3** — A one-shot subcommand must write non-secret output to
  stdout in a script-friendly form: one record per line, and no decoration. A
  secret follows [CLI-OUTPUT](programs.md#cli-output).
- **CLI-ONESHOT-4** — Each ceremony of [ceremonies.md](ceremonies.md), each
  recovery path of [recovery.md](recovery.md), the passphrase change
  ([ORC-ENROLL](oracle.md#orc-enroll)), the canary re-enrollment
  ([ORC-CANARY](oracle.md#orc-canary)), and the revocation paths
  ([ORC-REVOKE](oracle.md#orc-revoke)) must each run as a `fugupass` subcommand.
  The six REPL commands are the complete REPL command list, and the subcommand
  list extends it.

<a id="cli-output"></a>

## Secret output

- **CLI-OUTPUT-1** — A secret must print to the TTY or render as a QR code on
  the screen (D-18).
- **CLI-OUTPUT-2** — The default output of a mnemonic is the QR display, through
  `fugupass-qr` ([CLI-QR](programs.md#cli-qr)). The tool can print the words as
  text on an explicit flag.
- **CLI-OUTPUT-3** — FuguPass must not implement a clipboard (D-18).
- **CLI-OUTPUT-4** — FuguPass must not write a secret to a file and must not
  write a secret to an environment variable.

The QR display serves the signer flows ([ENTRY-TYPES](entries.md#entry-types)):
a signer scans the mnemonic from the screen, and the secret touches no cable and
no keyboard.

<a id="cli-scan"></a>

## fugupass-scan

- **CLI-SCAN-1** — `fugupass-scan` must decode QR codes from camera frames and
  must write the decoded payload as text to stdout. The program must write no
  other data to stdout.
- **CLI-SCAN-2** — The program must decode the standard SeedQR form: the
  concatenation of the zero-based BIP39 wordlist indexes of the mnemonic, each
  zero-padded to four decimal digits, in QR numeric mode. A 12-word mnemonic is
  48 digits, and a 24-word mnemonic is 96 digits.
- **CLI-SCAN-3** — The program must decode the CompactSeedQR form: the raw
  entropy bytes, without checksum bits, in QR byte mode. A 12-word mnemonic is
  16 bytes, and a 24-word mnemonic is 32 bytes. The program computes the BIP39
  checksum to rebuild the final word.
- **CLI-SCAN-4** — Both codecs follow the SeedSigner SeedQR specification.
  Known-answer vectors pin both codecs ([QA-KAT](testing.md#qa-kat)).
- **CLI-SCAN-5** — The program must emit a decoded mnemonic as the mnemonic
  words, on one line of text.
- **CLI-SCAN-6** — The program must apply the sandbox of
  [CLI-SPLIT](programs.md#cli-split).
- **CLI-SCAN-7** — A plate scan needs a video device on the machine. A machine
  with no video device cannot run a ceremony that scans the plate. A virtual
  machine needs host device passthrough for that device.

<a id="cli-qr"></a>

## fugupass-qr

- **CLI-QR-1** — `fugupass-qr` must read stdin and must render one QR code on
  the terminal, in UTF-8 half blocks.
- **CLI-QR-2** — The program must render a mnemonic export in the standard
  SeedQR form or in the CompactSeedQR form ([CLI-SCAN](programs.md#cli-scan)),
  for the signer scan flow ([ENTRY-TYPES](entries.md#entry-types)).
- **CLI-QR-3** — The program must render a vault file up to the one-code QR
  capacity as one QR code for the paper backup
  ([VAULT-BACKUP](vault.md#vault-backup)), and must report a file that exceeds
  the capacity.
- **CLI-QR-4** — The program must apply the sandbox of
  [CLI-SPLIT](programs.md#cli-split).
- **CLI-QR-5** — The documentation must record the chosen QR decode and render
  libraries, with their ports provenance and their licenses.

A vault file is ciphertext, so its paper QR is a safe backup object
([VAULT-BACKUP](vault.md#vault-backup)).
