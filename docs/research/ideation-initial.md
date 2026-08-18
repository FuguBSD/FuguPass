# FuguPass vault design — ideation notes

| | |
| --- | --- |
| Status | Research notes, round 1. Not normative. |
| Purpose | Input for `spec/decisions.md` and the first specification documents. |
| Companion | [FuguOracle specification](../../../FuguOracle/spec/index.md) (separate repository) |

These notes record an ideation round.
They flesh out the directional ideas for FuguPass and test them against the FuguOracle
protocol, the SeedQR ecosystem, and OpenBSD practice.
The specification work selects from these notes.
Decisions come first, then documents, then code.

## 1. Position

FuguPass is a password manager for people who already run air-gapped Bitcoin custody:
multisig wallets, SeedQR metal plates, dice entropy, and open source signers such as
Blockstream Jade, SeedSigner, and Krux.
FuguPass reuses that infrastructure instead of inventing a parallel one.

The design fits one sentence:

> FuguPass makes a laptop behave like a Jade: the vault on disk is the flash,
> FuguOracle is the PIN server, and the SeedQR plate is the recovery phrase.

This symmetry is exact, not poetic.
The Jade stores a secret encrypted under a key that it cannot rebuild alone.
It proves a PIN to a blind oracle and receives the missing key share.
Three wrong attempts destroy the share, and the flash becomes dead ciphertext.
The recovery phrase restores everything without the oracle.
FuguPass gives a laptop vault the same four properties, over the same wire protocol
that FuguOracle already specifies.

Comparison with existing tools, in one table:

| Property | pass(1), gopass | KeePassXC | FuguPass |
| --- | --- | --- | --- |
| Root of trust | GPG keyring | Master password | BIP39 mnemonic on a metal plate |
| Randomness | System RNG | System RNG | Dice, or derivation from the master |
| Offline backup | None defined | File copies | SeedQR plates, paper QR ciphertext |
| Anti-brute-force | GPG passphrase KDF | Argon2 | Blind oracle, three attempts |
| Entry names at rest | Plaintext filenames | Encrypted | Encrypted |
| Dependencies | GPG, git | Qt, botan | OpenBSD base, libsecp256k1, QR tools |

## 2. The custody model: entry tiers

The directional notes contain two entry models.
Model A gives each entry an independent 12-word seed with its own plate.
Model B derives every entry from one master seed with BIP85.
Each model fails alone:

- Model A does not scale. A password manager holds hundreds of entries.
  Nobody stamps two hundred plates, and nobody rolls dice for ten minutes per login.
- Model B cannot hold imported secrets. BIP85 only generates.
  A password manager must also store secrets that arrive from outside:
  existing passwords, TOTP seeds, recovery codes, and passphrases chosen elsewhere.

Bitcoin custody solved this shape of problem with tiers: hot, warm, cold.
FuguPass can apply the same discipline to entries.

| Tier | Secret origin | Backup medium | Restore path |
| --- | --- | --- | --- |
| **Derived** (default) | BIP85 from the vault master | The master plate. Nothing else. | Re-derive from master + index |
| **Stored** | Imported from outside | Encrypted vault files (any copy: disk, git, USB, paper QR) | Decrypt with a key derived from the master |
| **Sovereign** | Its own dice ceremony | Its own SeedQR plate | Its own plate, independent of the vault |
| **Shadow** | Never enters FuguPass | Not applicable | Not applicable |

Notes per tier:

- **Derived** entries cost nothing to back up. A new login password is one command.
  Rotation bumps a version counter, which selects a new BIP85 index.
  Old versions stay recoverable forever, because derivation is deterministic.
- **Stored** entries make FuguPass a real password manager, not only a generator.
  The files are ciphertext, so every copy is a safe backup.
- **Sovereign** entries carry the highest-value secrets, for example the BIP39
  passphrase that guards a multisig wallet.
  A sovereign entry restores with its own plate even if the vault, the laptop, and
  the oracle are all gone.
  This is Model A, kept for the few secrets that deserve it.
- **Shadow** entries hold metadata only: "Wallet X seed. Plate 3. Bank vault. Last
  verified 2026-05-01."
  FuguPass never sees the secret.
  This turns FuguPass into the catalog of the user's metal, which is a real gap in
  the current ecosystem.
  An `audit` command can list plates with stale verification dates.

## 3. Keys and unlock

### 3.1 The master

One vault has one master: a 12-word BIP39 mnemonic.
Everything else derives from it.
The master can enter the vault in three ways:

1. A dice ceremony (section 4).
2. A SeedQR scan through the laptop camera (an existing plate becomes a vault).
3. A BIP85 child mnemonic of an existing cold seed.

Path 3 deserves attention.
The signers this audience already owns (SeedSigner, Krux, Jade) implement BIP85 child
mnemonics.
A user can derive "child 83" from their existing cold seed on the signer, and use that
child as the FuguPass master.
Then the existing steel backup already covers the password vault, and no new plate
exists.
BIP85 is one-way: a vault compromise tells an attacker nothing about the parent seed.
The reverse is not true, but a leaked cold seed is already a catastrophe.
This choice is a custody preference, so FuguPass can support both path 1 and path 3
and stay neutral.

### 3.2 Daily unlock: the oracle path

Scanning a metal plate with a camera is a ceremony, not a login.
The plate lives in a safe, not on the desk.
So the daily unlock must not need the plate, and the plate must stay the recovery
root.
This reframes the directional idea "unlock by scanning a SeedQR": the scan is the
restore and provisioning ceremony, and FuguOracle is the daily unlock.

The daily path transplants the Jade model, and it conforms to
[CLIENT-MODEL](../../../FuguOracle/spec/clients.md#client-model):

- At vault creation, FuguPass generates a client keypair, independent of the
  unlock passphrase, and stores it on disk. Possession of this key is the client
  identity toward the oracle.
- FuguPass computes `pin_secret = bcrypt_pbkdf(passphrase, salt)`, with a salt
  derived from the client secret, and enrolls with `set_pin`.
  The oracle returns a 32-byte share.
- FuguPass writes one cache blob to disk: the master, encrypted under a key mixed
  from the oracle share and local key material.
- Each session unlock reads the passphrase with `readpassphrase(3)`, calls
  `get_pin`, rebuilds the key, and decrypts the master into memory.
- Three wrong passphrases destroy the oracle share.
  The cache blob becomes dead ciphertext.
  The user walks to the safe and scans the plate.

One improvement over the Jade falls out of the hardware:
a laptop has a keyboard, so the "PIN" can be a full passphrase.
The known bound of the blind-oracle scheme is the case where an attacker holds both
the laptop disk and the oracle record, and can search the unlock secret offline.
Six digits fall in that case.
FuguPass must not inherit the six-digit assumption.
The passphrase is the floor of the scheme in that case, and the design must say so.
Every key that derives from a typed passphrase must pass through `bcrypt_pbkdf(3)`,
the OpenBSD base passphrase KDF, with a tunable round count.
The KDF raises the cost of the offline search.
It does not remove the search, and passphrase quality sets the floor.

### 3.3 Recovery independence

One principle must hold as a hard rule:

> The oracle gates convenience, never recovery.
> The plate alone restores every derived and sovereign entry.
> The plate plus any copy of the vault files restores every stored entry.

The oracle can disappear, be seized, or wipe its record.
The user loses a login flow, never data.
This matches the FuguOracle design, where the Jade recovery phrase keeps working after
a wipe.

### 3.4 Paranoid mode

A vault can decline the disk cache.
Then every session starts with a plate scan, and the oracle is not used.
The code path is the same as the restore path, so this mode costs little.
This mode suits an air-gapped vault machine.
The Jade "QR PIN unlock" flow shows that oracle envelopes can even relay over QR
codes through an untrusted phone; the envelopes are a few hundred bytes.
That variant is far future material, but the protocol already permits it.

## 4. Entropy policy

### 4.1 Scope the rule first

"The system never provides randomness" is the right instinct, but it needs a precise
scope, or the client cannot speak the oracle protocol at all.
Every FuguOracle request needs an ephemeral keypair and a fresh IV, and vault writes
need IVs and salts.
The workable rule:

- The system RNG must not generate a secret that is stored, displayed, or backed up.
- Long-term secrets come from dice or from derivation.
- Transport and session randomness (ephemeral keys, IVs, salts) comes from
  `arc4random(3)`, which is the OpenBSD answer and needs no seeding ritual.

### 4.2 The dice ceremony

The proposed dice set is elegant and the arithmetic works exactly:

- Two d16 and one d8 give `16 × 16 × 8 = 2048` outcomes.
- The BIP39 wordlist has 2048 words.
- So one roll of the full set selects one word with full 11-bit entropy, uniformly,
  with no rejection and no modulo bias.

Mapping, with dice `a` (first d16), `b` (second d16), `c` (d8), all 1-based:

```
index = (a-1)*128 + (b-1)*8 + (c-1)        ; 0..2047
word  = wordlist[index]
```

The two d16 must differ in color, because order matters.
A printed lookup card lets the user verify every word by hand against the rolls, so
the tool never chooses a word.

The 12th word needs care.
Eleven rolls give `11 × 11 = 121` bits.
A 12-word mnemonic holds 128 entropy bits plus a 4-bit checksum, so the final word
carries 7 entropy bits plus the checksum.
Two clean options:

1. **Full entropy (recommended).** One extra roll of one d16 and the d8:
   `r = (a-1)*8 + (c-1)`, exactly 7 bits.
   The tool computes the 4 checksum bits and shows word 12 as
   `wordlist[r*16 + checksum]`.
   Total: 128 dice bits, zero RNG bits.
2. **Zero fill.** The tool fixes the 7 bits to zero and computes the checksum.
   Total: 121 dice bits, still far beyond any password need, but the asymmetry is
   ugly for a flagship ceremony.

Verification closes the ceremony: the user loads the 12 words into an air-gapped
signer and confirms the signer accepts the checksum, then stamps the plate and
scan-verifies the plate against the vault.

Two side notes:

- A byte-oriented alternative exists: two d16 rolls give one byte
  (`(a-1)*16 + (b-1)`), and 16 double-rolls give the 16 raw entropy bytes of a
  CompactSeedQR. The word-oriented ceremony is better, because a human can verify
  words against a card, and bytes against nothing.
- Users without d16 dice already own a fallback: roll d6 on a SeedSigner or Krux,
  display the result as a SeedQR, and scan it into FuguPass.
  The signer is an equal entropy source, so FuguPass needs no d6 code path.

## 5. Vault storage

OpenBSD taste, and the FuguOracle precedent, points at flat files:

- One directory per vault. One file per entry. No database
  (mirrors FuguOracle D-05).
- Entry files carry one AEAD seal:
  `version(1) ‖ nonce(12) ‖ ChaCha20-Poly1305 ciphertext and tag`.
  The AEAD comes from LibreSSL `libcrypto`, so the sourcing rule mirrors
  FuguOracle D-03. A fresh nonce comes from `arc4random(3)` at each write.
  A one-pass AEAD gives confidentiality and integrity together, runs in constant
  time without AES hardware, and exposes no padding surface.
  The FuguOracle wire envelope keeps its own shape, because the Jade v2 protocol
  fixes it; the vault format on disk is a FuguPass choice.
- File names are `H(entry key)` in hex, not slugs.
  A directory listing must not reveal that the user has an account at a given site.
  An encrypted index file maps names to files
  (this fixes the known metadata leak of pass(1)).
- Inside the envelope, a strict line format, in the spirit of the FuguOracle JSON
  scanner: `field: value` lines, one secret block, then metadata.
  No YAML library, no JSON library.

Entry types:

| Type | Secret | Notes |
| --- | --- | --- |
| `password` | Derived (BIP85 PWD BASE64) or stored | Username, URL, policy, version counter |
| `mnemonic` | Derived (BIP85 BIP39 child), stored, or sovereign | Exports as SeedQR on screen |
| `passphrase` | Derived, stored, or sovereign | Linked to a wallet fingerprint |
| `totp` | Stored | FuguPass computes codes offline (HMAC from libcrypto) |
| `note` | Stored | Recovery codes, descriptors, xpubs |
| `shadow` | None | Metadata and audit dates only |

Derived password addressing: the default BIP85 index can derive from the entry name
and version, for example the low 31 bits of `H(name ‖ version)`, with a stored
override.
Then the plate plus a remembered name recovers a password even with zero metadata.
Honesty requires a caveat: site password policies, usernames, and rotation counters
still live in metadata, so stateless recovery is partial.
The real answer is that the vault files are ciphertext and deserve promiscuous
backup, including a paper QR export of the blobs.

Backup and sync fall out of the format:

- Every vault file is ciphertext, so rsync, git, or a USB stick are all safe
  transports. No sync protocol exists in FuguPass.
- Oracle state is per machine: each machine holds its own client keypair and its own
  oracle record. The oracle already serves many records (FuguOracle D-01,
  OVR-PURPOSE-4). Provisioning a second machine is a plate scan plus `set_pin`.

## 6. Bitcoin workflows

The generic password manager and the Bitcoin toolbox are the same mechanism.
Concrete flows worth specifying:

- **Passphrase custody.** The community loses BIP39 passphrases more often than
  seeds. A `passphrase` entry stores or derives one, links it to a wallet
  fingerprint, and reveals it as text or as a QR for a signer to scan.
- **Seed export to a signer.** A `mnemonic` entry renders as a SeedQR or
  CompactSeedQR on the laptop screen. The signer scans it and loads the wallet.
  No typing, no cable, and the seed never touches the signer's storage.
- **Seed import from a signer.** SeedSigner and Krux display seeds as SeedQR.
  The laptop camera scans one into the vault as a stored or sovereign entry, or as
  the vault master.
- **Plate inventory.** Shadow entries track plate locations, custodians, and
  verification dates. `fugupass audit` nags about stale plates.
- **Descriptor and xpub notes.** Multisig recovery needs descriptors, which are
  critical but not secret. `note` entries give them a durable, findable home.
- **Offline TOTP.** Second factors live in the same custody model as passwords,
  with no phone app and no network.

## 7. Programs

Small programs, one job each, pledged tight (mirrors the FuguOracle sandbox
posture):

| Program | Job | Sandbox sketch |
| --- | --- | --- |
| `fugupass` | The vault: REPL TUI and subcommands | `pledge("stdio rpath wpath cpath flock unix inet dns tty")`, unveil the vault directory |
| `fugupass-scan` | Camera frames to decoded QR text on stdout | unveil `/dev/video*` only; drops to minimal promises after open |
| `fugupass-qr` | stdin to a QR on the terminal (UTF-8 half blocks) | `pledge("stdio")` |

Notes:

- The REPL matches "a very simple terminal UI": unlock once, then `ls`, `show`,
  `add`, `gen`, `totp`, `audit` inside one session, lock on exit or timeout.
  Scripting-friendly one-shot subcommands wrap the same core.
  A long-lived agent in the ssh-agent style can come later, if ever.
- The camera and the QR codecs stay out of the main binary, so the vault process
  never holds camera or codec attack surface. Candidates: `graphics/zbar` or the
  small `quirc` decoder for scan, `libqrencode` for render. All need a ports check.
- Secret output defaults to the TTY, with an explicit flag for the clipboard and a
  timeout wipe, in the pass(1) manner. Mnemonics prefer QR display over text.
- Memory hygiene follows FuguOracle SEC-MEMORY: `explicit_bzero(3)`,
  `timingsafe_bcmp(3)`, no core dumps, and OpenBSD already encrypts swap by
  default.
- Language and license follow the family line: C in KNF, ISC license, OpenBSD
  -stable (mirrors FuguOracle D-07, D-08).

## 8. What FuguPass gives FuguOracle

The dependency also runs backward, which strengthens both projects:

- FuguOracle D-01 claims the oracle serves any conforming client, with the Jade as
  reference, not as the only client. FuguPass is the second client that proves the
  claim.
- FuguPass can develop its oracle client against the upstream Python
  `blind_pin_server`, exactly as FuguOracle tests against it. The same harness then
  runs FuguPass against FuguOracle, and each project becomes the other's interop
  test.
- The FuguOracle specification can later gain a `CLIENT-FUGUPASS` unit beside
  `CLIENT-JADE`, and the provisioning story (URL plus static public key in a config
  file) already fits CLIENT-PROVISION.

## 9. Tensions and risks

| Tension | Position |
| --- | --- |
| Heavy ceremony (dice, plates, safes) versus login ergonomics | The audience already lives this discipline for Bitcoin. The tier model keeps ceremonies rare: vault creation and sovereign entries only. Daily use is one passphrase. |
| Camera and QR codecs are real attack surface | Quarantine them in `fugupass-scan` with a tight sandbox. The vault process never parses camera data. |
| Oracle record plus laptop disk equals an offline search of the unlock secret | Use a passphrase, not a PIN, and stretch it with `bcrypt_pbkdf(3)`. Passphrase quality and KDF cost are the floor of the design in this case. The documentation must state this floor. |
| A lost metadata index weakens BIP85 recovery | Deterministic default indexes from the entry name, paper QR export of the ciphertext, and promiscuous backup of vault files. |
| d16 dice are niche objects | They exist (hexadecimal dice), the ceremony is optional, and any signer with d6 support is an equal entropy source via SeedQR import. |
| Scope creep against OpenBSD minimalism | Phase the work: vault core first, QR second, oracle third, conveniences last. Every phase ships a usable tool. |
| The tagline "derives all secrets from mnemonics" overpromises | Stored entries are sealed, not derived. The spec language can say "derives or seals". |

## 10. Candidate decisions

Input for `spec/decisions.md`, in the FuguOracle format.
Human approval turns a candidate into a decision.

| # | Candidate decision | Rationale |
| --- | --- | --- |
| 1 | One vault has one master BIP39 mnemonic. Every vault key derives from it. | One plate restores the vault. One root, no key zoo. |
| 2 | Entries live in tiers: derived by default, stored for imports, sovereign for own-plate secrets, shadow for metadata-only records. | Scales like hot/warm/cold custody. Resolves Model A versus Model B. |
| 3 | FuguPass speaks `blind_pin_server` protocol v2 to FuguOracle and conforms to CLIENT-MODEL. | Reuses a specified, blind, brute-force-resistant unlock. Proves FuguOracle D-01. |
| 4 | The oracle gates the daily unlock only. The plate must restore everything without the oracle. | No availability coupling. The user can always walk away with the plate. |
| 5 | The unlock secret is a passphrase of any length, never a numeric PIN. Every key that derives from a typed passphrase must pass through `bcrypt_pbkdf(3)` with a tunable round count. HMAC-family derivation takes high-entropy keys only. | An attacker with the disk and the oracle record can search the passphrase offline. The KDF raises the cost of that search. Passphrase quality sets the floor, and the documentation states the floor. |
| 6 | The system RNG must not generate a stored secret. Long-term secrets come from dice or derivation. Ephemeral keys, IVs, and salts come from `arc4random(3)`. | Keeps the no-RNG principle exact and the protocol possible. |
| 7 | The dice ceremony rolls two distinguishable d16 and one d8 per word, eleven times, plus one d16-and-d8 roll for the final word. The tool computes only the checksum. | 2048 outcomes map 1:1 to the wordlist, bias-free and hand-verifiable. Full 128-bit entropy. |
| 8 | The vault is a directory of flat files, one encrypted file per entry, sealed with ChaCha20-Poly1305 from LibreSSL `libcrypto`, with a fresh `arc4random(3)` nonce per write. No database. | Small audit surface. Ciphertext-safe backups. A one-pass AEAD gives confidentiality and integrity together, and the decrypt failure is the client's own junk detector. |
| 9 | Entry names and metadata are encrypted at rest. A directory listing reveals nothing. | Fixes the pass(1) metadata leak. |
| 10 | Crypto comes from LibreSSL `libcrypto`, `libsecp256k1`, and `bcrypt_pbkdf(3)` from `libutil` only. QR and camera code lives in separate sandboxed helper programs. | Mirrors FuguOracle D-03, plus the OpenBSD base passphrase KDF that `signify(1)` and `ssh-keygen(1)` use. Quarantines the risky parsers. |
| 11 | The implementation is C in KNF for OpenBSD -stable, ISC licensed, packaged as a port. | Mirrors FuguOracle D-07 and D-08. |

## 11. Open questions

1. **Master default.** Standalone dice-rolled master, or BIP85 child of an existing
   cold seed? Both work; which is the documented default?
2. **Cache default.** Oracle-gated disk cache as default with paranoid mode as
   opt-in, or the reverse?
3. **Clipboard.** Support it with a timeout, or refuse it entirely and offer TTY
   and QR only?
4. **BIP85 password application.** PWD BASE64 as specified in BIP85, or passwords
   from BIP85 hex entropy with a local encoding rule? The former buys ecosystem
   compatibility, the latter buys charset policy freedom.
5. **MVP cut.** Vault core plus dice plus BIP85 with no camera and no oracle is
   already a usable air-gapped tool. Ship that first?

## 12. To verify before specification

- OpenBSD ports coverage: `graphics/zbar` (or `quirc`), `libqrencode`; exact names
  and licenses.
- Camera path: `video(4)` and `uvideo(4)` coverage on target laptops, and the
  `kern.video.record` sysctl default.
- BIP85 PWD BASE64 application number and test vectors against a reference
  implementation.
- Signer firmware matrix: SeedQR scan and display, passphrase-by-QR, and BIP85
  child mnemonic support in current Jade, SeedSigner, and Krux releases.
- d16 dice sourcing for the documentation (hexadecimal dice exist as commercial
  products).
- SeedQR format details against the SeedSigner specification: standard digit
  streams and CompactSeedQR byte mode, for both 12 and 24 words.
