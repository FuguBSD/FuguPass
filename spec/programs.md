# Programs

This document specifies the FuguPass programs: the vault program, the interface
program, the scan helper, and the QR render helper. Each program runs on OpenBSD
and restricts itself with `pledge(2)` and `unveil(2)`. Each program has a man
page in `mdoc(7)`: `fugupass(1)`, `fugupass-repl(1)`, `fugupass-scan(1)`, and
`fugupass-qr(1)`. In an interactive session, `fugupass` is the core process, and
`fugupass-repl` is the interface process.

Two more documents specify the programs.
[programs-commands.md](programs-commands.md) specifies the REPL, the one-shot
subcommands, and the secret output. [programs-helpers.md](programs-helpers.md)
specifies the scan helper and the QR render helper.

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
  The pledge call must also name the execpromises
  `stdio rpath prot_exec tty video`. A child of `execve(2)` takes the unveil
  list through that argument alone. A child of a NULL argument takes the whole
  file system, and the list below then restricts no child program. The
  execpromises must hold each promise that a child pledges, because a child can
  only make its promise set smaller. `tty` is the promise of `fugupass-repl`,
  and `video` is the promise of `fugupass-scan` (PROG-SPLIT-4). `prot_exec` is
  the promise of the interpreter of the interface process, which maps each XS
  module with `PROT_EXEC`. The execpromises hold no `wpath` and no `cpath`, so a
  child reads a file of the list and writes none. It must unveil only these
  paths and the video devices of PROG-SPLIT-4. They are the vault directory
  (`rwc`), `/dev/tty` (`rw`), and the three child programs (`x`).
  `fugupass-repl` takes the `r` permission as well, because the interpreter
  reads the program text of it. The other paths are the runtime files that the
  child programs load (`r`), and the resolver files that name lookup needs
  (`r`). The list also holds the trust anchors of PROG-SPLIT-12 (`r`). The
  derived list of PROG-SPLIT-10 carries the random device, the resolver files,
  the service tables and the time zone file. It also carries the library tree of
  the interpreter of the interface process.
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
- **PROG-SPLIT-13** — `unveil(2)` takes no glob, so the list must name each
  video device of PROG-SPLIT-4 with the path of it. The paths are `/dev/video`
  and the ten devices `/dev/video0` to `/dev/video9`. `MAKEDEV(8)` makes the
  first four of them on each machine, and `/dev/video` is the link of the first
  device. Each path takes the `r` permission, because the scan helper opens one
  device for a read. A device above that bound stays outside the list, and the
  helper opens no such device.

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
  or pipes it to `fugupass-qr`
  ([PROG-OUTPUT](programs-commands.md#prog-output)).
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
  sink ([PROG-ONESHOT](programs-commands.md#prog-oneshot)). A command of the
  session takes the reply pipe, and one reply line carries one record. A secret
  takes no sink, and it goes to the terminal
  ([PROG-OUTPUT](programs-commands.md#prog-output)). Each record must carry one
  value of a vault line, behind a name that is not longer than the name of that
  line. One record therefore takes the line bound of the vault format, without
  the newline of it ([VAULT-FORMAT](vault.md#vault-format)). One reply line adds
  the tag and the newline around the record. A record above that bound reaches
  no sink, and the command must then fail.

Entry names and oracle error text carry external bytes, so the display filter
guards the operator's terminal. `Fugu::REPL` holds the terminal in raw mode only
while it reads a line, and it restores the terminal state on every exit path.
The module loads with core Perl only and operates inside the `stdio tty` pledge.
Its interface contract lives in the Fugu repository. FuguTTX builds its operator
REPL on the same module, so a change to the contract coordinates with FuguTTX
through Fugu.

<a id="prog-port"></a>

## The port

- **PROG-PORT-1** — The project packages FuguPass as the OpenBSD port
  `security/fugupass` (D-16). The port lives under `ports/security/fugupass` of
  this repository. The submission to the ports tree is the operator's act.
- **PROG-PORT-2** — The port must build the four programs from a release tag of
  this repository, and must install them with their manual pages.
- **PROG-PORT-3** — The port must declare `devel/p5-Fugu` as a run dependency
  (D-16). The build runs `src/unveil-paths` of this repository, and that script
  loads `Fugu::Sandbox` of the library. The port must therefore declare the
  library as a build dependency as well. The port must declare each library that
  a program links as a library dependency. The render helper links
  `graphics/libqrencode` ([PROG-QR](programs-helpers.md#prog-qr)), and the core
  process links `security/libsecp256k1`. The FuguOracle repository holds the
  `security/libsecp256k1` port.
- **PROG-PORT-4** — The developer must build the port on OpenBSD/amd64 and on
  OpenBSD/arm64, and must run the test target of the port (`make test`) there.
  The `fuguvm` tool can supply the guest, as a command only. The port must not
  depend on `fuguvm`.

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
- **PROG-BUILD-5** — The QR decoder of the scan helper must sit in `src/quirc`
  as a vendored source. That directory must hold the license of the library and
  the record of its origin ([PROG-QR](programs-helpers.md#prog-qr)). The
  directory must build the archive `libfuguquirc.a`, and `SUBDIR` of
  `src/Makefile` must name it. `src/fugupass-scan` and `src/regress` must link
  that archive. The archive name must differ from the name of the package of the
  ports tree, so no link line takes the wrong file. The directory must build
  with `-Wall -Werror`, because the vendored source does not take `-Wextra`.
  Every other C source of this repository must keep `-Wextra`.

The layout follows `usr.bin/ssh` of the OpenBSD tree. The archive sources sit
flat, and each program directory holds the manual page of its program. A program
with a C source adds a Makefile to that directory. The archive keeps one object
of each archive source. The C build needs an OpenBSD machine, and the gates of
the repository root need none.

The tree holds the QR decoder, and the ports tree holds the encoder.
`docs/analysis/qr-library-sources.md` records the evaluation of each library and
the reason of each pick (PROG-QR-5).
