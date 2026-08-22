# Entry model

This document specifies the entries of FuguPass: the origin classes, the entry
types, rotation, the pre-derivation pool, and shadow entries. An entry is one
secret, or one metadata record, sealed in one vault file
([VAULT-SEAL](vault.md#vault-seal)). Key derivation lives in [keys.md](keys.md).
This document cites it and does not restate it.

<a id="entry-model"></a>

## Origin classes

| Class     | Secret origin          | Backup medium              | Restore path                 |
| --------- | ---------------------- | -------------------------- | ---------------------------- |
| derived   | BIP85 from the master  | the master plate           | re-derivation from the plate |
| stored    | an import from outside | any copy of the shared set | the plate plus a copy        |
| sovereign | its own dice ceremony  | its own plate              | its own plate                |
| shadow    | none; metadata only    | any copy of the shared set | the plate plus a copy        |

- **ENTRY-MODEL-1** — Each entry has exactly one origin class: derived, stored,
  sovereign, or shadow (D-05). The default class is derived.
- **ENTRY-MODEL-2** — The origin class sets the secret origin, the backup
  medium, and the restore path. The table above is the complete list.
- **ENTRY-MODEL-3** — An entry has no policy attribute. Every entry reveal is
  the vault passphrase plus any `k` of the `n` oracle masks for that entry,
  through this machine's records (D-06, [ORC-QUORUM](oracle.md#orc-quorum)).

Origin and custody stay orthogonal: the classes differ in backup and in restore,
and every class reveals through the same oracle gate. A derived secret restores
from the plate alone ([REC-PLATE](recovery.md#rec-plate)). A stored secret
restores from the plate plus any copy of the shared set
([REC-VAULT](recovery.md#rec-vault), [VAULT-BACKUP](vault.md#vault-backup)). A
sovereign entry restores from its own plate, even when the vault, the machine,
and the oracles are all gone.

<a id="entry-types"></a>

## Entry types

| Type       | Origin classes                | Content and metadata                          |
| ---------- | ----------------------------- | --------------------------------------------- |
| password   | derived or stored             | username, URL, site policy transform, version |
| mnemonic   | derived, stored, or sovereign | a BIP39 mnemonic; SeedQR export parameters    |
| passphrase | derived, stored, or sovereign | the linked wallet fingerprint                 |
| totp       | stored                        | the TOTP key and the RFC 6238 parameters      |
| note       | stored                        | descriptors, xpubs, recovery codes            |
| shadow     | shadow                        | location, custodian, verification date        |

- **ENTRY-TYPES-1** — The entry types are password, mnemonic, passphrase, totp,
  note, and shadow. The table above is the complete list.
- **ENTRY-TYPES-2** — Every type uses the same seal and the same custody
  mechanics ([VAULT-SEAL](vault.md#vault-seal), [KEY-MASK](keys.md#key-mask)).
- **ENTRY-TYPES-3** — A totp entry is stored-origin. The tool computes TOTP
  codes offline, with HMAC from libcrypto.
- **ENTRY-TYPES-4** — A derived password entry and a derived passphrase entry
  consume the PWD BASE64 candidate of their slot. A derived mnemonic entry
  consumes the BIP39 child candidate ([KEY-BIP85](keys.md#key-bip85)).
- **ENTRY-TYPES-5** — The table below defines the entry-file field names of each
  type, for the strict reader ([VAULT-FORMAT](vault.md#vault-format)). Every
  entry file holds the metadata fields `type` and `slots`. `type` holds the type
  name. `slots` holds the slot list of all versions
  ([ENTRY-ROTATION](entries.md#entry-rotation)).

| Type       | Secret field | Type metadata fields                           |
| ---------- | ------------ | ---------------------------------------------- |
| password   | `password`   | `username`, `url`, `transform`, `version`      |
| mnemonic   | `mnemonic`   | `seedqr-format`                                |
| passphrase | `passphrase` | `wallet-fingerprint`                           |
| totp       | `totp-key`   | `totp-algorithm`, `totp-digits`, `totp-period` |
| note       | `note`       | none                                           |
| shadow     | none         | `location`, `custodian`, `verified`            |

A site can reject the PWD BASE64 character set. The site policy transform in the
password metadata maps the derived password onto the site's rules. As an
alternative, the user creates the entry as stored-origin. A mnemonic entry
renders as a SeedQR code for a signer to scan ([CLI-QR](programs.md#cli-qr)).
[ENTRY-SHADOW](entries.md#entry-shadow) specifies shadow entries and the audit.

<a id="entry-rotation"></a>

## Rotation

- **ENTRY-ROTATION-1** — Rotation of a derived entry increments the version. The
  rotation consumes a new slot ([ENTRY-POOL](entries.md#entry-pool)). The
  version of an entry is the position of its slot in `slots`
  ([ENTRY-TYPES](entries.md#entry-types)).
- **ENTRY-ROTATION-2** — The entry metadata records the slot list of all
  versions.
- **ENTRY-ROTATION-3** — Every old version of a derived entry stays recoverable,
  because derivation is deterministic ([KEY-ENTRY](keys.md#key-entry)).
- **ENTRY-ROTATION-4** — Rotation of a stored entry seals the new secret in
  place, in the entry's own slot.

Rotation of a derived entry is entry creation on a new slot: it consumes the
lowest free slot, and it performs one reveal of that slot
([ENTRY-POOL](entries.md#entry-pool)). An old version restores like any derived
secret: the plate re-derives the old slot's key and candidates
([REC-PLATE](recovery.md#rec-plate)).

<a id="entry-pool"></a>

## The pool

- **ENTRY-POOL-1** — Each ceremony pre-derives a pool of future slots on the
  ceremony machine ([CER-CREATE](ceremonies.md#cer-create),
  [CER-REFILL](ceremonies.md#cer-refill)). A pooled slot consists of a reserved
  slot index, a sealed slot file with both materialized candidates
  ([KEY-BIP85](keys.md#key-bip85)), an enrolled record at each oracle
  ([ORC-ENROLL](oracle.md#orc-enroll)), and this machine's wraps, one per oracle
  ([KEY-MASK](keys.md#key-mask)). The slot index is also the BIP85 index.
- **ENTRY-POOL-2** — The default pool size is 64 slots. The pool size is tunable
  (D-12).
- **ENTRY-POOL-3** — Every new entry, of any origin class, consumes the lowest
  free slot for which this machine holds wraps at `k` or more live oracles
  ([KEY-MASK](keys.md#key-mask), [ORC-QUORUM](oracle.md#orc-quorum)). When free
  slots remain and no such slot exists on this machine, the tool must refuse the
  entry, and the refusal must name machine provisioning
  ([CER-PROVISION](ceremonies.md#cer-provision)) or the refill ceremony
  ([CER-REFILL](ceremonies.md#cer-refill)).
- **ENTRY-POOL-4** — Entry creation performs one reveal of the consumed slot
  ([ORC-QUORUM](oracle.md#orc-quorum)): `k` `get_pin` requests, one per quorum
  oracle. The reveal opens the slot file. The tool must keep the candidate that
  the entry type needs. The tool must then seal the secret and the metadata as
  the entry file. Entry creation is one quorum event.
- **ENTRY-POOL-5** — The slot's oracle records continue unchanged as the entry's
  records, one per oracle. Consumption must not change a record. Consumption
  must not change a wrap.
- **ENTRY-POOL-6** — The tool must warn when the count of free slots reaches the
  low watermark of 8. The watermark is tunable.
- **ENTRY-POOL-7** — At pool exhaustion, the tool must refuse a new entry. The
  refusal message must name the refill ceremony
  ([CER-REFILL](ceremonies.md#cer-refill)).
- **ENTRY-POOL-8** — Consumption must write the index, with the slot marked
  consumed, before it writes the entry file
  ([VAULT-INDEX](vault.md#vault-index)).
- **ENTRY-POOL-9** — Before consumption, the tool must decrypt the slot file and
  must verify that it holds the two candidates ([KEY-BIP85](keys.md#key-bip85)).
  When the file does not hold the two candidates, the tool must not consume the
  slot and must report the malformed slot file.

The pool keeps the master out of daily life. Without the pool, every new entry
needs a plate ceremony. That cost pushes the plate to the desk, or it pushes the
design back to a resident master (D-12). With the pool, the master appears at
vault creation and at pool refill only. Entry creation never needs `M`. A
stored, sovereign, or shadow entry uses the slot's key, records, and wraps, and
it discards both candidates.

<a id="entry-shadow"></a>

## Shadow entries and the audit

- **ENTRY-SHADOW-1** — A shadow entry holds no secret. FuguPass never receives
  the secret that a shadow entry describes.
- **ENTRY-SHADOW-2** — Shadow metadata seals under the slot key `K_e` with the
  oracle-gated wraps, like every other entry ([KEY-MASK](keys.md#key-mask)).
- **ENTRY-SHADOW-3** — A read of shadow metadata is an oracle-gated reveal
  ([ORC-QUORUM](oracle.md#orc-quorum)). The plate audit therefore needs a
  reachable oracle quorum.
- **ENTRY-SHADOW-4** — The audit command lists the shadow entries whose
  verification date is older than a tunable age
  ([CLI-REPL](programs.md#cli-repl)).
- **ENTRY-SHADOW-5** — The audit reads shadow metadata only.

Shadow entries are the catalog of the user's plates: locations, custodians, and
verification dates. The single reveal path has no metadata exception (D-06). A
shadow read costs one quorum reveal per entry: `k` oracle requests, exactly like
a password reveal. Without a reachable quorum, the audit does not run. The
shadow metadata itself stays safe: the plate plus the vault files restores it
([REC-VAULT](recovery.md#rec-vault)).
