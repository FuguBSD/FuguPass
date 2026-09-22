# Programs

This document specifies the FuguPass programs: the vault program, the interface
program, the scan helper, and the QR render helper. Each program runs on OpenBSD
and restricts itself with `pledge(2)` and `unveil(2)`. Each program has a man
page in `mdoc(7)`: `fugupass(1)`, `fugupass-repl(1)`, `fugupass-scan(1)`, and
`fugupass-qr(1)`. In an interactive session, `fugupass` is the core process, and
`fugupass-repl` is the interface process.

<a id="prog-split"></a>

## Program split

- **PROG-SPLIT-1** — FuguPass has exactly four programs. Each program has one
  job (D-15, D-16). `fugupass` holds the vault core, the one-shot subcommands,
  and the ceremonies. `fugupass-repl` holds the REPL: it reads operator command
  lines and shows non-secret output ([PROG-IFACE](programs.md#prog-iface)).
  `fugupass-scan` turns camera frames into decoded QR text on stdout.
  `fugupass-qr` turns stdin into a QR code on the terminal.
- **PROG-SPLIT-2** — The vault process must not parse camera data and must not
  parse QR image data (D-15). The camera code and the QR codecs live in the
  helper programs only.
- **PROG-SPLIT-3** — `fugupass` must make its unveil calls before its pledge
  call and must pledge `stdio rpath wpath cpath flock proc exec inet dns tty`.
  The pledge call must also name the execpromises `stdio rpath prot_exec tty`. A
  child of `execve(2)` takes the unveil list through that argument alone. A
  child of a NULL argument takes the whole file system, and the list below then
  restricts no child program. The execpromises must hold each promise that a
  child pledges, because a child can only make its promise set smaller. `tty` is
  the promise of `fugupass-repl`, and PROG-SPLIT-4 adds the promise of
  `fugupass-scan`. `prot_exec` is the promise of the interpreter of the
  interface process, which maps each XS module with `PROT_EXEC`. The
  execpromises hold no `wpath` and no `cpath`, so a child reads a file of the
  list and writes none. It must unveil only these paths and the video devices of
  PROG-SPLIT-4. They are the vault directory (`rwc`), `/dev/tty` (`rw`), and the
  three child programs (`x`). `fugupass-repl` takes the `r` permission as well,
  because the interpreter reads the program text of it. The other paths are the
  runtime files that the child programs load (`r`), and the resolver files that
  name lookup needs (`r`). The list also holds the trust anchors of
  PROG-SPLIT-12 (`r`). The derived list of PROG-SPLIT-10 carries the random
  device, the resolver files, the service tables and the time zone file. It also
  carries the library tree of the interpreter of the interface process.
- **PROG-SPLIT-4** — `fugupass` must carry the video devices (`/dev/video*`) in
  its unveil list, and the execpromises must hold `video` as well.
  `fugupass-scan` must unveil no path. It must pledge `stdio video` after it
  opens the device. The helper takes the unveil list of the core in its view.
  Its promise set holds no `rpath`, so it reads no file of the vault after that
  pledge call. A child of `execve(2)` cannot unveil a path, and the promise set
  of the child decides the outcome of such a call. The execpromises hold no
  `unveil` promise. An `unveil(2)` call of a child is therefore a pledge
  violation, and the kernel kills that child with `SIGABRT`. A child of a
  promise set that holds `unveil` gets `EPERM` instead, from the
  `unveil(NULL, NULL)` call of the core. The other two children pledge a set
  with no `video` and no `rpath`, so they open no video device.
- **PROG-SPLIT-5** — `fugupass-qr` must pledge `stdio` only.
- **PROG-SPLIT-6** — FuguPass must not implement an agent process and must not
  implement a network service. The oracle client inside `fugupass` is the only
  network code (D-18).
- **PROG-SPLIT-7** — `fugupass-repl` is Perl on the Fugu library, and
  `Fugu::REPL` is its line editor (D-16). After it loads its modules, it must
  pledge `stdio tty`. It must not open a file, must not create a process, and
  must not reach the network.
- **PROG-SPLIT-8** — `fugupass-repl` must make its pledge call with
  `Fugu::Sandbox->pledge`, with the promises `stdio tty`. Off OpenBSD the method
  restricts nothing and returns success. `Fugu::Sandbox->is_supported` reports
  the difference, so a test can tell enforcement from emulation.
- **PROG-SPLIT-9** — `fugupass-repl` must use `Fugu::Log` in stderr mode or in
  quiet mode. It must not use syslog mode, because syslog mode opens a socket.
  The `stdio tty` promise set holds no socket.
- **PROG-SPLIT-10** — The build must derive the unveil list of the interface
  process from `Fugu::Sandbox->perl_lib_dirs` and `Fugu::Sandbox->system_paths`,
  and `fugupass` must carry the derived list. The first method names the library
  directories of the perl that runs. The second method names `/dev/urandom`, the
  resolver files, the service tables and the time zone file. Neither method
  calls a syscall, so a test can prove the list off OpenBSD.
- **PROG-SPLIT-11** — A regress build can take the helper paths from the
  environment, so a test can put a double in place of a helper. The service
  build must hold no such path.
- **PROG-SPLIT-12** — The unveil list of the core process must hold
  `/etc/ssl/cert.pem` with the `r` permission. `libtls` reads the trust anchors
  of that file for an `https` oracle.

`fugupass` runs the interface program and the helpers as child processes and
exchanges text over pipes. Text crosses the process boundary, never image data
and never a secret. The scan helper carries the camera and codec attack surface
and holds no vault key and no oracle key. The render helper holds only the bytes
on its stdin. The interface process carries the line editor and the command
parser and holds no secret ([PROG-IFACE](programs.md#prog-iface)). The interface
process lives only for its session, so it is not an agent process (D-18). The
runtime files of a child program are its dynamic linker and its shared
libraries. The interface process also loads the Perl runtime and the Fugu
modules.

<a id="prog-iface"></a>

## The interface boundary

- **PROG-IFACE-1** — A run of `fugupass` with no subcommand must start the
  interactive session. The core process spawns `fugupass-repl` as a child, with
  a request pipe and a reply pipe. The interface process reads operator command
  lines, and the core process executes every command.
- **PROG-IFACE-2** — The pipe protocol is line-oriented text: one request line
  per command, then reply lines, then one end line with the outcome. Image data
  and secret bytes must not cross the pipes.
- **PROG-IFACE-3** — A secret must not enter the interface process. The core
  process reads the passphrase with `readpassphrase(3)` from the terminal
  ([SEC-MEMORY](security.md#sec-memory)). It prints each secret to the terminal,
  or pipes it to `fugupass-qr` ([PROG-OUTPUT](programs.md#prog-output)).
- **PROG-IFACE-4** — One process at a time owns the terminal: the interface
  process at the prompt, the core process while a command runs. The interface
  process must restore the terminal state before each request and on every exit
  path.
- **PROG-IFACE-5** — The interface process must show core output through the
  display filter of `Fugu::REPL`. The filter must replace each byte outside
  printable ASCII, newline, and tab. It must remove `DEL` (0x7F) and the C1
  range (0x80–0x9F). It must not break a UTF-8 sequence.
- **PROG-IFACE-6** — When the core process ends the session, the closed reply
  pipe must end the interface process. At the prompt, the line editor must watch
  the reply pipe as a registered handle.
- **PROG-IFACE-7** — When standard input is not a terminal, the interface
  process must read plain lines, with no line editing and no escape output.
  Scripted tests drive the session in this mode.
- **PROG-IFACE-8** — `Fugu::REPL` must read one line in raw mode, and must
  restore the terminal state on every exit path. It must accept one extra read
  handle, and that handle must end the read when it becomes readable. It must
  load with core Perl only, and it must operate inside the `stdio tty` pledge.
  The `.pod` sidecar of the module in the Fugu repository is its interface
  contract.
- **PROG-IFACE-9** — The interface process must install its interrupt handlers
  with one `Fugu::Signal` manager. It must build the manager, and it must then
  call `setup_interrupt_flag` on it. The signal path is one exit path, so the
  process must restore the terminal state.
- **PROG-IFACE-10** — The core process must spawn `fugupass-repl` with the
  request pipe on file descriptor 3, and the reply pipe on file descriptor 4.
  The interface process must take no argument. It must report the absent
  descriptor and must stop, because the core process is its only parent.
- **PROG-IFACE-11** — Each line of the two pipes ends with one newline. A
  request line holds the operator command line, without the space at each end.
  An empty command line sends no request. The first byte of a reply line is the
  tag. A reply line starts with `>`, and the rest of that line is one line of
  the command output. The end line starts with `=`, and the rest of that line is
  `ok` or `fail`. The tag keeps the frame apart from the text, so an entry name
  cannot forge an end line. A line with another tag is a protocol failure, and
  the interface process must stop.
- **PROG-IFACE-12** — The core process must split a request line at each space
  and at each tab. The words are the argument list of one command, and the first
  word is the command name. The core process must reject a request line of more
  than 4096 bytes ([VAULT-FORMAT](vault.md#vault-format)). It must answer that
  line with a `fail` end line.
- **PROG-IFACE-13** — The core process must write each output record of a
  command to one sink. A one-shot subcommand takes the standard output as that
  sink ([PROG-ONESHOT](programs.md#prog-oneshot)). A command of the session
  takes the reply pipe, and one reply line carries one record. A secret takes no
  sink, and it goes to the terminal ([PROG-OUTPUT](programs.md#prog-output)).
  Each record must carry one value of a vault line, behind a name that is no
  longer than the name of that line. One record therefore takes the line bound
  of the vault format, without the newline of it
  ([VAULT-FORMAT](vault.md#vault-format)). One reply line adds the tag and the
  newline around the record. A record above that bound reaches no sink, and the
  command must then fail.

Entry names and oracle error text carry external bytes, so the display filter
guards the operator's terminal. `Fugu::REPL` holds the terminal in raw mode only
while it reads a line, and it restores the terminal state on every exit path.
The module loads with core Perl only and operates inside the `stdio tty` pledge.
Its interface contract lives in the Fugu repository. FuguTTX builds its operator
REPL on the same module, so a change to the contract coordinates with FuguTTX
through Fugu.

<a id="prog-repl"></a>

## The REPL

- **PROG-REPL-1** — The session must read the passphrase once, in the core
  process, with `readpassphrase(3)` ([PROG-IFACE](programs.md#prog-iface)). It
  must verify the passphrase against the canary record of each quorum oracle,
  before any entry record of that oracle ([ORC-CANARY](oracle.md#orc-canary),
  [ORC-QUORUM](oracle.md#orc-quorum), D-08).
- **PROG-REPL-2** — The session quorum can cover `k` live index wraps of this
  machine ([ORC-QUORUM](oracle.md#orc-quorum)). The session's canary `get_pin`
  requests must then also open the index through those index wraps
  ([KEY-MASK](keys.md#key-mask), [VAULT-INDEX](vault.md#vault-index)). The
  session quorum can also fail to cover `k` live index wraps of this machine
  ([ORC-CANARY](oracle.md#orc-canary)). The tool must then report each dead or
  unreachable index wrap, and must name the provisioning ceremony
  ([CER-PROVISION](ceremonies.md#cer-provision)).
- **PROG-REPL-3** — The REPL must provide six commands: `ls`, `show`, `add`,
  `gen`, `totp`, and `audit`. `ls` lists the entries from the open index. `show`
  reveals one entry. `add` imports a stored secret into a pool slot. `gen`
  creates a derived entry from a pool slot. `totp` reveals a totp entry and
  computes the code locally. `audit` reports stale shadow entries and the last
  plate verification date. The interface process adds `help` and `quit`, and
  they reach no core path.
- **PROG-REPL-4** — Each `show` and each `totp` is one per-entry quorum event:
  `k` `get_pin` requests ([ORC-QUORUM](oracle.md#orc-quorum), D-07). `add` and
  `gen` consume one pool slot each, with one quorum reveal of the consumed slot
  ([ENTRY-POOL](entries.md#entry-pool)). `audit` reads shadow metadata through
  quorum reveals ([ENTRY-SHADOW](entries.md#entry-shadow)). It must take the
  type of each entry from the index, and it must reveal the shadow entries
  alone. It must send no oracle request for an entry of another type
  ([VAULT-INDEX](vault.md#vault-index)).
- **PROG-REPL-5** — With fewer than `k` reachable oracles, the tool must perform
  no reveal and must report the state of each oracle
  ([ORC-QUORUM](oracle.md#orc-quorum)). A decrypt failure or a failed request
  can happen at a quorum oracle, and a request also fails at this machine
  (ORC-QUORUM-5, ORC-COUNTER-5). The tool can then substitute the next reachable
  oracle, after that oracle's canary check. It must refuse the reveal when no
  untried reachable oracle remains, and when a record of the quorum holds the
  request count of ORC-QUORUM-8. The report uses the distinct HTTP-error and
  transport-failure states of [ORC-REVEAL](oracle.md#orc-reveal), and both are
  distinct from the junk report.
- **PROG-REPL-6** — Plate verification and every data-restore path must work
  without the oracle ([CER-VERIFY](ceremonies.md#cer-verify),
  [REC-PRINCIPLE](recovery.md#rec-principle), D-04).
- **PROG-REPL-7** — The core process must lock on the end of the session, and
  after an idle timeout with no request. It must erase every session secret with
  `explicit_bzero(3)` ([SEC-MEMORY](security.md#sec-memory)). The lock ends the
  session and, through the closed reply pipe, the interface process
  ([PROG-IFACE](programs.md#prog-iface)). The timeout is a tunable in the config
  file ([VAULT-CONFIG](vault.md#vault-config)).
- **PROG-REPL-8** — The interface process must read each command line with the
  `Fugu::REPL` line editor. The editor gives emacs-style line editing, and tab
  completion of command names and entry names from the open index listing. The
  editor also gives a session history in memory. PROG-REPL-12 bounds those entry
  names. The interface process must not write a history file, because a history
  file leaks entry names (D-14).
- **PROG-REPL-9** — `Fugu::REPL` must take each completion candidate from a
  caller callback. The interface process gives the command names and the entry
  names of the open index listing, as PROG-REPL-8 and PROG-REPL-12 state.
- **PROG-REPL-10** — The command names of the completion come from the command
  table of `Fugu::REPL`, and the entry names come from the completion callback.
  The interface process must take the entry names from the reply of each `ls`
  request, and PROG-REPL-12 bounds that set. It must send one `ls` request
  before the first prompt, and it must show no line of that reply. It must send
  no other request of its own, so each operator command is one request line.
- **PROG-REPL-11** — The default lock timeout is 300 seconds. The config file
  holds the tunable value ([VAULT-CONFIG](vault.md#vault-config)).
- **PROG-REPL-12** — The interface process must offer no entry name that the
  display filter of `Fugu::REPL` changes ([PROG-IFACE](programs.md#prog-iface)).
  The editor writes each candidate to the terminal, and it filters no byte
  there. A filtered name is not the name of the entry, and the core process
  finds no entry of it. The interface process must keep such a name out of the
  completion set. The operator can still type that name.

`ls` reads the open index and sends no entry request. The unlock reads the
passphrase once and verifies it at the canary record of each quorum oracle. Each
reveal in the session computes one `pin_ei` per quorum oracle
([KEY-PIN](keys.md#key-pin)). A session that reveals many entries pays the KDF
cost `k` times per entry. The default lock timeout of 300 seconds bounds an
unattended session, and a shorter timeout repeats that unlock cost. An HTTP
error is not an attempt and is retryable. A transport failure is ambiguous, and
a junk answer can burn a strike ([ORC-REVEAL](oracle.md#orc-reveal)). The
reports therefore name different user actions.

<a id="prog-oneshot"></a>

## One-shot subcommands

- **PROG-ONESHOT-1** — Every REPL command must exist as a one-shot subcommand of
  `fugupass`.
- **PROG-ONESHOT-2** — A one-shot subcommand and its REPL command must run the
  same core paths, in the same core program. The paths are the same canary
  check, the same reveal path, and the same output rules.
- **PROG-ONESHOT-3** — A one-shot subcommand must write non-secret output to
  stdout in a script-friendly form: one record per line, and no decoration. A
  secret follows [PROG-OUTPUT](programs.md#prog-output).
- **PROG-ONESHOT-4** — Each ceremony of [ceremonies.md](ceremonies.md) and each
  recovery path of [recovery.md](recovery.md) must run as a `fugupass`
  subcommand. The passphrase change ([ORC-ENROLL](oracle.md#orc-enroll)), the
  canary re-enrollment ([ORC-CANARY](oracle.md#orc-canary)), and the revocation
  paths ([ORC-REVOKE](oracle.md#orc-revoke)) must each run as one too. The six
  REPL commands are the complete REPL command list, and the subcommand list
  extends it.
- **PROG-ONESHOT-5** — `fugupass` must take the vault directory from the `-d`
  option. Without that option, the vault directory must be `.fugupass` of the
  home directory. The `create` subcommand must take the threshold from `-k`, and
  the ordered oracle set from its arguments
  ([VAULT-CONFIG](vault.md#vault-config)).
- **PROG-ONESHOT-6** — Each argument of `create` must hold one position of the
  oracle set: the static public key hex, one space, then the URL
  ([ORC-PROVISION](oracle.md#orc-provision)). The first argument is position 1.
  The subcommand must take the machine name from `-m`
  ([KEY-DEVICE](keys.md#key-device)), and the `bcrypt_pbkdf(3)` round count from
  `-r` ([KEY-PIN](keys.md#key-pin)). The `-k`, `-m` and `-r` options and the
  argument list are mandatory. The subcommand must take the slots of the new
  pool from the optional `-p` option ([ENTRY-POOL](entries.md#entry-pool)).
- **PROG-ONESHOT-7** — The `create` subcommand must write the revocation kit
  ([ORC-REVOKE](oracle.md#orc-revoke)) at the path of
  [VAULT-LAYOUT](vault.md#vault-layout). It must print the path of that file.
- **PROG-ONESHOT-8** — `add` and `gen` must take the entry type of a new entry
  from the `-T` option ([ENTRY-TYPES](entries.md#entry-types)). A rotation must
  take the type from the index, and it must refuse a `-T` option of another type
  ([VAULT-INDEX](vault.md#vault-index)). Each `-f name=value` option gives one
  metadata field of the entry. `add` must take the origin class from the `-c`
  option, and the class `stored` without that option
  ([ENTRY-MODEL](entries.md#entry-model)). The secret of `add` must enter from
  the terminal, and an argument must not carry it.
- **PROG-ONESHOT-9** — `ls` must print one entry name on each line. `show` must
  print each metadata field of the entry as one line of the line format
  ([VAULT-FORMAT](vault.md#vault-format)). `show` must print the words of a
  mnemonic on the `-w` option ([PROG-OUTPUT](programs.md#prog-output)). `audit`
  must print the date of the last plate verification as a `verified` line. It
  must then print one line of each stale shadow entry: the verification date,
  one space, and the entry name.

<a id="prog-output"></a>

## Secret output

- **PROG-OUTPUT-1** — A secret must print to the TTY or render as a QR code on
  the screen (D-18).
- **PROG-OUTPUT-2** — The default output of a mnemonic is the QR display,
  through `fugupass-qr` ([PROG-QR](programs.md#prog-qr)). The tool can print the
  words as text on an explicit flag.
- **PROG-OUTPUT-3** — FuguPass must not implement a clipboard (D-18).
- **PROG-OUTPUT-4** — FuguPass must not write a secret to a file and must not
  write a secret to an environment variable.

The QR display serves the signer flows ([ENTRY-TYPES](entries.md#entry-types)).
A signer scans the mnemonic from the screen, and the secret touches no cable and
no keyboard.

<a id="prog-scan"></a>

## fugupass-scan

- **PROG-SCAN-1** — `fugupass-scan` must decode QR codes from camera frames and
  must write the decoded payload as text to stdout. The program must write no
  other data to stdout.
- **PROG-SCAN-2** — The program must decode the Standard SeedQR form. The form
  is the concatenation of the zero-based BIP39 wordlist indexes of the mnemonic.
  Each index is zero-padded to four decimal digits, in QR numeric mode. A
  12-word mnemonic is 48 digits. Every other digit count is a failure (D-22).
- **PROG-SCAN-3** — The program must not decode the Compact SeedQR form (D-22).
  A QR code in byte mode is a failure. The program computes no checksum. It
  emits the 12 words of the digit string, and the master gate checks them
  ([KEY-MASTER](keys.md#key-master)).
- **PROG-SCAN-4** — The codec follows the Standard SeedQR form of the SeedSigner
  SeedQR specification. Known-answer vectors pin it
  ([TEST-KAT](testing.md#test-kat)).
- **PROG-SCAN-5** — The program must emit a decoded mnemonic as the mnemonic
  words, on one line of text.
- **PROG-SCAN-6** — The program must apply the sandbox of
  [PROG-SPLIT](programs.md#prog-split).
- **PROG-SCAN-7** — A plate scan needs a video device on the machine. A machine
  with no video device cannot run a ceremony that scans the plate. A virtual
  machine needs host device passthrough for that device.

<a id="prog-qr"></a>

## fugupass-qr

- **PROG-QR-1** — `fugupass-qr` must read stdin and must render one QR code on
  the terminal, in UTF-8 half blocks.
- **PROG-QR-2** — The program must render a mnemonic export in the Standard
  SeedQR form only (D-22, [PROG-SCAN](programs.md#prog-scan)). This serves the
  signer scan flow ([ENTRY-TYPES](entries.md#entry-types)).
- **PROG-QR-3** — The program must render a vault file up to the one-code QR
  capacity as one QR code for the paper backup
  ([VAULT-BACKUP](vault.md#vault-backup)). It must report a file that exceeds
  the capacity.
- **PROG-QR-4** — The program must apply the sandbox of
  [PROG-SPLIT](programs.md#prog-split).
- **PROG-QR-5** — The documentation must record the chosen QR decode and render
  libraries, with their ports provenance and their licenses.

A vault file is ciphertext, so its paper QR is a safe backup object
([VAULT-BACKUP](vault.md#vault-backup)).

<a id="prog-port"></a>

## The port

- **PROG-PORT-1** — The project packages FuguPass as the OpenBSD port
  `security/fugupass` (D-16). The port lives under `ports/security/fugupass` of
  this repository. The submission to the ports tree is the operator's act.
- **PROG-PORT-2** — The port must build the four programs from a release tag of
  this repository, and must install them with their manual pages.
- **PROG-PORT-3** — The port must declare `devel/p5-Fugu` as a run dependency
  (D-16), and each library that a helper program links as a library dependency
  ([PROG-QR](programs.md#prog-qr)).
- **PROG-PORT-4** — The developer must build the port on OpenBSD/amd64 and on
  OpenBSD/arm64, and must run the regress target of the port there. The `fuguvm`
  tool can supply the guest, as a command only. The port must not depend on
  `fuguvm`.

The Fugu repository holds the `devel/p5-Fugu` port (Fugu REL-PORT), and the
ports tree must hold it before this port builds.

<a id="prog-build"></a>

## The build

- **PROG-BUILD-1** — The archive sources must sit flat in `src/`. An archive
  source is a source that more than one directory shares. `src/lib` must build
  the archive `libfugupass.a` from them with `.PATH`. Each program directory and
  `src/regress` must link that archive, so each archive source compiles once.
  The test sources must sit in `src/regress`, and each other C source must sit
  flat in `src/`.
- **PROG-BUILD-2** — `src/Makefile` is the build entry point of the C code, and
  the OpenBSD `make` reads it. Each program must have a directory of its own
  under `src/`, and that directory must hold the manual page of the program. A
  program with a C source must build in that directory, and that directory must
  read `bsd.prog.mk`. `SUBDIR` of `src/Makefile` must name each directory that
  builds. A program with no C source gives `bsd.prog.mk` no `PROG`, so its
  directory holds the manual page alone and `SUBDIR` must not name it.
  `src/regress` holds the tests, and it must read `bsd.regress.mk`.
- **PROG-BUILD-3** — The C build and the gates of the repository root must stay
  apart. The OpenBSD `make` reads `src/Makefile`, and it builds the C code. GNU
  `make` reads `GNUmakefile` of the repository root, and it runs the gates. The
  two file names keep the two builds apart. The gates build no C code, so they
  run on a machine that is not OpenBSD. This repository must not edit
  `GNUmakefile`, because the org pack of FuguBSD/Tooling owns it.
- **PROG-BUILD-4** — The build must take libsecp256k1 from `LOCALBASE`, the
  ports tree of the machine (D-15, [PROG-PORT](programs.md#prog-port)).

The layout follows `usr.bin/ssh` of the OpenBSD tree. The archive sources sit
flat, and each program directory holds the manual page of its program. A program
with a C source adds a Makefile to that directory. The archive keeps one object
of each archive source. The C build needs an OpenBSD machine, and the gates of
the repository root need none.
