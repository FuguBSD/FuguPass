# Program commands

This document is a part of the [programs](programs.md) specification. It
specifies the REPL, the one-shot subcommands, and the secret output.

<a id="prog-repl"></a>

## The REPL

- **PROG-REPL-1** — The session must read the passphrase once, in the core
  process, with `readpassphrase(3)` ([PROG-IFACE](programs.md#prog-iface)). It
  must verify the passphrase against the canary record of each quorum oracle,
  before any entry record of that oracle
  ([ORC-CANARY](oracle-quorum.md#orc-canary),
  [ORC-QUORUM](oracle-quorum.md#orc-quorum), D-08).
- **PROG-REPL-2** — The session quorum can cover `k` live index wraps of this
  machine ([ORC-QUORUM](oracle-quorum.md#orc-quorum)). The session's canary
  `get_pin` requests must then also open the index through those index wraps
  ([KEY-MASK](keys.md#key-mask), [VAULT-INDEX](vault.md#vault-index)). The
  session quorum can also fail to cover `k` live index wraps of this machine
  ([ORC-CANARY](oracle-quorum.md#orc-canary)). The tool must then report each
  dead or unreachable index wrap, and must name the provisioning ceremony
  ([CER-PROVISION](ceremonies.md#cer-provision)).
- **PROG-REPL-3** — The REPL must provide six commands: `ls`, `show`, `add`,
  `gen`, `totp`, and `audit`. `ls` lists the entries from the open index. `show`
  reveals one entry. `add` imports a stored secret into a pool slot. `gen`
  creates a derived entry from a pool slot. `totp` reveals a totp entry and
  computes the code locally. `audit` reports stale shadow entries and the last
  plate verification date. The interface process adds `help` and `quit`, and
  they reach no core path.
- **PROG-REPL-4** — Each `show` and each `totp` is one per-entry quorum event:
  `k` `get_pin` requests ([ORC-QUORUM](oracle-quorum.md#orc-quorum), D-07).
  `add` and `gen` consume one pool slot each, with one quorum reveal of the
  consumed slot ([ENTRY-POOL](entries.md#entry-pool)). `audit` reads shadow
  metadata through quorum reveals ([ENTRY-SHADOW](entries.md#entry-shadow)). It
  must take the type of each entry from the index, and it must reveal the shadow
  entries alone. It must send no oracle request for an entry of another type
  ([VAULT-INDEX](vault.md#vault-index)).
- **PROG-REPL-5** — With fewer than `k` reachable oracles, the tool must perform
  no reveal and must report the state of each oracle
  ([ORC-QUORUM](oracle-quorum.md#orc-quorum)). A decrypt failure or a failed
  request can happen at a quorum oracle, and a request also fails at this
  machine (ORC-QUORUM-5, ORC-COUNTER-5). The tool can then substitute the next
  reachable oracle, after that oracle's canary check. It must refuse the reveal
  when no untried reachable oracle remains, and when a record of the quorum
  holds the request count of ORC-QUORUM-8. The report uses the distinct
  HTTP-error and transport-failure states of
  [ORC-REVEAL](oracle-enrollment.md#orc-reveal), and both are distinct from the
  junk report.
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
a junk answer can burn a strike ([ORC-REVEAL](oracle-enrollment.md#orc-reveal)).
The reports therefore name different user actions.

<a id="prog-oneshot"></a>

## One-shot subcommands

- **PROG-ONESHOT-1** — Every REPL command must exist as a one-shot subcommand of
  `fugupass`.
- **PROG-ONESHOT-2** — A one-shot subcommand and its REPL command must run the
  same core paths, in the same core program. The paths are the same canary
  check, the same reveal path, and the same output rules.
- **PROG-ONESHOT-3** — A one-shot subcommand must write non-secret output to
  stdout in a script-friendly form: one record per line, and no decoration. A
  secret follows [PROG-OUTPUT](programs-commands.md#prog-output).
- **PROG-ONESHOT-4** — Each ceremony of [ceremonies.md](ceremonies.md) and each
  recovery path of [recovery.md](recovery.md) must run as a `fugupass`
  subcommand. The passphrase change
  ([ORC-ENROLL](oracle-enrollment.md#orc-enroll)), the canary re-enrollment
  ([ORC-CANARY](oracle-quorum.md#orc-canary)), and the revocation paths
  ([ORC-REVOKE](oracle-quorum.md#orc-revoke)) must each run as one too. The six
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
- **PROG-ONESHOT-7** — The `kit` subcommand must print the revocation kit of
  this machine on the standard output
  ([ORC-REVOKE](oracle-quorum.md#orc-revoke)). With the `-m` option, it must
  derive the kit of the named machine from the plate
  ([KEY-DEVICE](keys.md#key-device)). The slot set of that kit must come from
  the index ([VAULT-INDEX](vault.md#vault-index)). A constant must not bound it.
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
  mnemonic on the `-w` option ([PROG-OUTPUT](programs-commands.md#prog-output)).
  `audit` must print the date of the last plate verification as a `verified`
  line. It must then print one line of each stale shadow entry: the verification
  date, one space, and the entry name.

<a id="prog-output"></a>

## Secret output

- **PROG-OUTPUT-1** — A secret must print to the TTY or render as a QR code on
  the screen (D-18).
- **PROG-OUTPUT-2** — The default output of a mnemonic is the QR display,
  through `fugupass-qr` ([PROG-QR](programs-helpers.md#prog-qr)). The tool can
  print the words as text on an explicit flag.
- **PROG-OUTPUT-3** — FuguPass must not implement a clipboard (D-18).
- **PROG-OUTPUT-4** — FuguPass must not write a secret to a file and must not
  write a secret to an environment variable.

The QR display serves the signer flows ([ENTRY-TYPES](entries.md#entry-types)).
A signer scans the mnemonic from the screen, and the secret touches no cable and
no keyboard.
