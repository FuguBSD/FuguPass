# Overview

This document states what FuguPass is, what the design defends, and what the design
does not claim.
The other area documents hold the mechanics.
This document holds the claims and the accepted limits.

<a id="ovw-purpose"></a>

## Purpose

FuguPass is a password manager for OpenBSD. The vault core is C, and the interface
program is Perl on the Fugu library (D-16).
It makes a laptop vault behave like a Blockstream Jade. The vault on disk is the flash.
An ordered set of blind PIN oracles is the PIN server, with a k-of-n quorum per
reveal. The SeedQR plate is the recovery phrase.
The oracle speaks version 2 of the Blockstream `blind_pin_server` protocol.
FuguOracle is the reference deployment, not a requirement (D-02).

- **OVW-PURPOSE-1** — FuguPass serves operators of air-gapped Bitcoin custody:
  multisig wallets, SeedQR metal plates, dice entropy, and open source signers.
- **OVW-PURPOSE-2** — Derivation answers backup. Every vault key derives from one
  12-word BIP39 master, so one plate restores the vault
  ([KEY-MASTER](keys.md#key-master)).
- **OVW-PURPOSE-3** — A per-entry custody layer over blind share masking answers theft
  at rest. Each entry key splits across the oracle set, and no theft of data at rest
  exposes any secret ([KEY-SHARE](keys.md#key-share), [KEY-MASK](keys.md#key-mask)).
- **OVW-PURPOSE-4** — An attacker with the data at rest also needs the passphrase and
  `k` queries to live oracles per entry. Each reveal leaves one log line at each
  quorum oracle, inside a detection-and-revocation window
  ([ORC-REVOKE](oracle.md#orc-revoke)).
- **OVW-PURPOSE-5** — The plate alone restores every derived and sovereign entry. The
  oracle gates reveals and must not gate recovery (D-04,
  [REC-PRINCIPLE](recovery.md#rec-principle)).
- **OVW-PURPOSE-6** — Reveals continue while `k` oracles of the set stay live and
  reachable: any `k` reachable oracles serve every reveal, with no ceremony. With
  every position live, the set tolerates the loss, seizure, or wipe of up to
  `n − k` oracles. More losses pause reveals until a plate ceremony re-enrolls, and
  no data is lost ([REC-WIPE](recovery.md#rec-wipe), D-04).

<a id="ovw-model"></a>

## System model

- **OVW-MODEL-1** — A vault has one master plate, one ordered oracle set of `n`
  oracles and one threshold `k`, with `1 ≤ k ≤ n ≤ 255` (D-20), and one or more
  machines. Each machine holds one vault directory: the shared ciphertext set plus
  that machine's machine-local set ([VAULT-LAYOUT](vault.md#vault-layout)).
- **OVW-MODEL-2** — The parts of a reveal live apart. Each oracle holds the mask of
  one share. The device factor, the wraps, and the ciphertext live on disk. The
  passphrase lives with the user.
- **OVW-MODEL-3** — The oracle can read no name, no purpose, and no content of any
  record ([ORC-RECORDS](oracle.md#orc-records)).
- **OVW-MODEL-4** — The factor inputs of a reveal must not coexist at rest.

A reveal joins the passphrase, the device factor, and `k` oracle answers in memory,
for seconds ([ORC-REVEAL](oracle.md#orc-reveal)).
At rest, a disk holds ciphertext, the device factor, and the wraps, and it holds no
passphrase verifier ([KEY-MASK](keys.md#key-mask)).
Any copy of the shared set on any transport is a safe backup, and the machine-local
set never moves between machines ([VAULT-BACKUP](vault.md#vault-backup)).
The documented example topology is 2-of-3: a home box, a VPS, and a friend's box.
One oracle with `k = 1` is the minimum configuration, and the wrap is then the plain
wrap ([KEY-SHARE](keys.md#key-share)).

<a id="ovw-scope"></a>

## Scope and non-goals

The scope covers:

- One 12-word BIP39 master on a SeedQR plate. The master enters by the dice ceremony,
  by a SeedQR scan, or as a BIP85 child of an external seed
  ([KEY-MASTER](keys.md#key-master), [CER-DICE](ceremonies.md#cer-dice)).
- BIP85 derivation of passwords and child mnemonics ([KEY-BIP85](keys.md#key-bip85)).
- A flat-file vault of sealed entries, with an encrypted index and a strict state
  partition ([VAULT-LAYOUT](vault.md#vault-layout)).
- Six entry types over four origin classes, with a pre-derivation pool of entry slots
  ([ENTRY-MODEL](entries.md#entry-model), [ENTRY-POOL](entries.md#entry-pool)).
- Per-entry records at each oracle of one ordered set of `n` blind PIN oracles, with
  a vault-wide threshold `k` and `1 ≤ k ≤ n ≤ 255`, over unmodified protocol v2, with
  a canary record per oracle ([ORC-CONFORM](oracle.md#orc-conform),
  [ORC-QUORUM](oracle.md#orc-quorum), [ORC-CANARY](oracle.md#orc-canary)).
- Ceremonies for vault creation, pool refill, machine provisioning, and plate
  verification ([CER-CREATE](ceremonies.md#cer-create)).
- Recovery from the plate, with or without vault files
  ([REC-PRINCIPLE](recovery.md#rec-principle)).
- Revocation of a stolen machine from the plate ([ORC-REVOKE](oracle.md#orc-revoke)).
- Four sandboxed programs, with SeedQR import and export
  ([CLI-SPLIT](programs.md#cli-split)).

The non-goals bound every claim in this specification:

| Non-goal | Statement |
| --- | --- |
| Sync | FuguPass does not define a sync protocol and does not define write coordination between machines. |
| Clipboard, agent, service | FuguPass does not implement a clipboard, an agent process, or a network service other than the oracle client (D-18). |
| Reveal policy grammar | FuguPass does not define a reveal policy grammar and does not define reveal descriptors: every entry reveals through the single reveal path (D-06). |
| No-oracle reveals | FuguPass does not implement a no-oracle reveal path: the plate ceremony is the only no-oracle path (D-06). |
| Signer factors | FuguPass does not use a hardware signer as a reveal factor. |
| Sharded master | FuguPass does not shard the master (D-01). |
| Inheritance | FuguPass does not implement inheritance policies. |
| Traffic shaping | FuguPass does not send decoy traffic and does not integrate an onion transport. |
| QR-relayed envelopes | FuguPass does not relay oracle envelopes over QR codes. |
| Oracle policy features | The specification does not assume a delayed reveal, a velocity alarm, a freeze operation, or any oracle behavior beyond protocol v2 as the FuguOracle specification states it (D-03). |
| FuguOracle changes | FuguPass does not require a change of any kind to FuguOracle (D-02). |

<a id="ovw-attacks"></a>

## Attacker outcomes

Each row names the artifacts that the attacker holds. Five artifacts exist: a copy of
the shared ciphertext set; a machine's disk with the device factor `X`
([KEY-DEVICE](keys.md#key-device)) and the wraps; the passphrase; the records of one
or more oracles, each with that oracle's static key; and the master plate.

| The attacker holds | Outcome |
| --- | --- |
| A shared-set copy alone | Nothing. Every file is ciphertext, and the copy holds no device factor, no wrap, and no verifier ([VAULT-BACKUP](vault.md#vault-backup)). |
| A shared-set copy plus the passphrase, without `X` | Nothing. The attacker cannot derive a client key without `X`, so the oracle records are unaddressable, and the copy holds no wrap to unmask. |
| A machine's disk with `X` and the wraps, without the passphrase | No offline attack exists, because the disk holds no passphrase verifier. Online guessing burns three strikes per record per oracle, and each oracle wipes its own record. The owner revokes the machine from the plate: the owner locks that machine's records at enough live oracles that at most `k − 1` stay unlocked, and no quorum forms; with the full set of `n` live oracles, the count is `n − k + 1` locks ([ORC-REVOKE](oracle.md#orc-revoke)). An attacker who raises a record's stored counter to `0xFFFFFFFF` locks that record for every caller. A locked record denies its mask to the attacker too. The entry stays revealable while `k` live records remain, and the entry always recovers from the plate ([REC-WIPE](recovery.md#rec-wipe)). |
| A machine's disk with `X` and the wraps, plus the passphrase. Malware in an unlocked session is the same case. | To each oracle, the attacker is the owner. The attacker reveals entries at the attacker's own pace, leaves one log line per entry at each of `k` oracles, and burns no strike. The attacker selects its own quorum, so guaranteed log coverage needs logs at enough live oracles that every possible quorum intersects them; with the full set of `n` live oracles, the count is `n − k + 1` oracles (SAFE-DETECT-6). The window closes when the owner reads logs that cover every possible quorum and revokes from the plate: locks at enough live oracles that at most `k − 1` stay unlocked deny every quorum (OVW-LIMITS-1, OVW-LIMITS-2, OVW-LIMITS-4, [ORC-REVOKE](oracle.md#orc-revoke)). |
| A machine's disk plus a breach of one oracle's records, with that oracle's static key | An offline passphrase verifier: the breached record stores the hash of that record's pin secret, and the disk holds every salt. The KDF cost and the passphrase quality bound the search ([SAFE-FLOOR](security.md#safe-floor)). With `k` greater than 1, the verifier yields the passphrase only. With fewer than `k` breached oracles, every entry secret stays behind the remaining quorum: the attacker must query the live oracles, online and logged. |
| A machine's disk plus a breach of `k` oracles' records, with their static keys | Full offline loss of the covered entries. The attacker searches the passphrase against one record hash, then unmasks `k` shares per entry and reconstructs every entry key with no live oracle. The KDF cost and the passphrase quality are the floor ([SAFE-FLOOR](security.md#safe-floor)). |
| The master plate | The attacker re-derives every derived secret and every machine's keys, with no oracle and no passphrase. Physical plate custody is the countermeasure (OVW-LIMITS-7). |
| Oracle hosts, by seizure, wipe, or loss, while `k` oracles of the set stay live and reachable | Zero data loss and zero interruption: reveals continue on any `k` reachable oracles, with no ceremony ([REC-WIPE](recovery.md#rec-wipe)). With every position live, the set tolerates the loss of up to `n − k` hosts. The seized masks alone are meaningless strings, and fewer than `k` breached oracles unmask nothing. |
| Oracle hosts, by seizure, wipe, or loss, with fewer than `k` oracles left reachable | Zero data loss. Reveals pause until a plate ceremony re-enrolls at replacement oracles ([REC-WIPE](recovery.md#rec-wipe)). Recovery needs no oracle (D-04). |

<a id="ovw-limits"></a>

## Accepted limits

The limits below are the honest bounds of the design.
Every other document must stay inside them, and
[SAFE-CLAIMS](security.md#safe-claims) prohibits claims beyond them.

- **OVW-LIMITS-1** — A compromised endpoint sees every secret that it reveals while
  compromised.
- **OVW-LIMITS-2** — The oracle is blind. It gates, counts, and wipes. It does not
  verify intent.
- **OVW-LIMITS-3** — One breached oracle record, with that oracle's static key, plus
  the machine's disk yields an offline passphrase verifier. The disk plus `k`
  breached oracles yields full offline loss. Between the two: an attacker with the
  passphrase and fewer than `k` breached oracles must query the remaining live
  oracles, online and logged. The KDF cost and the passphrase quality are the floor
  ([SAFE-FLOOR](security.md#safe-floor)).
- **OVW-LIMITS-4** — Detection is manual. The oracle writes logs and sends no alerts.
  The owner must read the logs, or revocation never happens.
- **OVW-LIMITS-5** — The oracle sees traffic patterns per record, never content.
- **OVW-LIMITS-6** — FuguPass generates `k` `get_pin` requests per revealed entry,
  and one `set_pin` request per live oracle for each slot of each machine at
  enrollment. One oracle instance sees one request per event; the multiplier spreads
  across instances. This load can exceed the FuguOracle workload assumption of a few
  requests per day. This is a posture mismatch on a self-hosted oracle, not a
  correctness problem ([ORC-RECORDS](oracle.md#orc-records),
  [QA-CALIBRATE](testing.md#qa-calibrate)).
- **OVW-LIMITS-7** — The master plate is a single point of catastrophic theft.
  Physical custody of the plate is the countermeasure. D-01 excludes a sharded
  master, and only an approved change to D-01 can adopt one.
- **OVW-LIMITS-8** — FuguPass defines no sync protocol and no write coordination
  between machines. Concurrent entry creation on two machines can consume one slot
  twice, and a later file copy then overwrites one entry's file. A pool refill on a
  machine with a stale index can reserve slot indexes that another machine's refill
  already reserved. The documentation recommends one minting machine for entry
  creation and for refills ([VAULT-BACKUP](vault.md#vault-backup)).
- **OVW-LIMITS-9** — The quorum availability claim covers reveals only. A ceremony,
  an enrollment, and a passphrase change need every live oracle reachable. Reveals
  pause while fewer than `k` oracles are reachable. After a loss, seizure, or wipe
  that leaves fewer than `k` oracles reachable, a plate ceremony re-enrolls at
  replacement oracles, and reveals resume
  ([REC-WIPE](recovery.md#rec-wipe)). With every position live, the pause bound is
  the loss of more than `n − k` oracles. With `k = n`, any one oracle loss pauses
  reveals.

[SAFE-FLOOR](security.md#safe-floor) and [SAFE-DETECT](security.md#safe-detect) turn
the limits into documentation duties.
