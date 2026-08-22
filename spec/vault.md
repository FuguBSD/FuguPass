# Vault storage

This document specifies the on-disk format of a FuguPass vault.
[keys.md](keys.md) defines the notation `H(x)`, the entry key `K_e`, the index
key `K_idx`, the device factor `X`, the oracle index `i`, the oracle count `n`,
the threshold `k`, the wraps `c_ei`, and the per-oracle index wraps `c_idx_i`.

<a id="vault-layout"></a>

## Directory layout

One vault is one directory. The file paths inside it are:

| Path                        | Content                                   | Set           |
| --------------------------- | ----------------------------------------- | ------------- |
| `<lowercase hex of H(K_e)>` | the sealed entry file of slot `e`         | shared        |
| `index`                     | the sealed index file                     | shared        |
| `machine/factor`            | the device factor `X`                     | machine-local |
| `machine/wrap.<e>.<i>`      | the wrap `c_ei` of slot `e` at oracle `i` | machine-local |
| `machine/wrap.index.<i>`    | the index wrap `c_idx_i` of oracle `i`    | machine-local |
| `machine/canary.<i>`        | the canary check seal of oracle `i`       | machine-local |
| `machine/counters`          | the counters file, plaintext              | machine-local |
| `machine/config`            | the config file, plaintext                | machine-local |
| `machine/change`            | the change marker, plaintext              | machine-local |

In a file name, `<e>` is the unpadded decimal ASCII of the slot index, and `<i>`
is the unpadded decimal ASCII of the oracle index, the same encodings as in a
label ([keys.md](keys.md)).

- **VAULT-LAYOUT-1** — A vault is one directory of flat files, with no database.
  One sealed file holds one entry (D-13).
- **VAULT-LAYOUT-2** — The on-disk state splits into the shared set and the
  machine-local set (D-13).
- **VAULT-LAYOUT-3** — The shared set holds the entry files and the index file.
  It lives at the vault root.
- **VAULT-LAYOUT-4** — The machine-local set holds the device factor `X`, the
  wraps `c_ei`, the index wraps `c_idx_i`, the canary check seals, the counters
  file, the config file, and the change marker. It lives in the `machine/`
  subdirectory.
- **VAULT-LAYOUT-5** — The name of the entry file of slot `e` must be the
  lowercase hex of `H(K_e)`, with no suffix.
- **VAULT-LAYOUT-6** — The index file, the config file, the counters file, the
  factor file, the wrap files, the index wrap files, the canary check seals, and
  the change marker must use the fixed paths of the table above.
- **VAULT-LAYOUT-7** — A directory listing must reveal nothing about entry names
  or sites (D-14).

A pool slot file occupies the entry-file path of its slot. It uses the same name
rule and the same seal ([ENTRY-POOL](entries.md#entry-pool)). The name rule
carries plate-plus-files recovery: from the plate, the tool re-derives `K_e`,
computes `H(K_e)`, and matches the file with no index
([REC-VAULT](recovery.md#rec-vault)).

<a id="vault-seal"></a>

## The seal

A sealed file has this exact byte layout:

| Offset | Length   | Field     | Content                                                |
| ------ | -------- | --------- | ------------------------------------------------------ |
| 0      | 1        | `version` | `0x01`                                                 |
| 1      | 12       | `nonce`   | fresh random bytes                                     |
| 13     | variable | `body`    | the ChaCha20-Poly1305 ciphertext, then the 16-byte tag |

- **VAULT-SEAL-1** — Every sealed vault file must use this layout. The tool must
  write and must read seal version `0x01` only.
- **VAULT-SEAL-2** — The AEAD is ChaCha20-Poly1305 from LibreSSL libcrypto
  (D-13, D-15).
- **VAULT-SEAL-3** — Every write must draw a fresh nonce from `arc4random(3)`
  (D-13).
- **VAULT-SEAL-4** — The decrypt failure of the seal is the client's junk
  detector ([ORC-REVEAL](oracle.md#orc-reveal)). No other failure signal exists
  for a junk oracle answer.
- **VAULT-SEAL-5** — The AEAD must take the version byte as the additional
  authenticated data.

A junk oracle answer, a wrong passphrase, a wiped record, and a stale wrap on
this machine all yield a wrong key. They all end in the same decrypt failure.
The client can never learn the cause from the seal
([ORC-COUNTER](oracle.md#orc-counter)).

<a id="vault-format"></a>

## Line format

- **VAULT-FORMAT-1** — The seal plaintext of an entry file, of a slot file, and
  of the index is a sequence of `field: value` lines. A line is the field name,
  one colon, one space, then the value. The canary check seals are exempt: their
  plaintext is the raw 32-byte canary check value
  ([ORC-CANARY](oracle.md#orc-canary)). The counters file and the change marker
  are plaintext files in the same line format.
- **VAULT-FORMAT-2** — The encoding is UTF-8, and every line ends with one line
  feed.
- **VAULT-FORMAT-3** — A field name holds lowercase ASCII letters, digits, and
  hyphens only. [ENTRY-TYPES](entries.md#entry-types) defines the field names of
  each entry type. The tables of this unit define the field names of the slot
  file, of the index, of the counters file, and of the change marker.
  [VAULT-CONFIG](vault.md#vault-config) defines the config fields.
- **VAULT-FORMAT-4** — A sealed file that holds a secret places the secret block
  first: the secret fields, then the metadata fields.
- **VAULT-FORMAT-5** — A line has at most 4096 bytes. The reader must reject a
  longer line.
- **VAULT-FORMAT-6** — The reader must be a strict scanner: it must reject an
  unknown field, and it must not use a YAML or a JSON library.
- **VAULT-FORMAT-7** — A value must not hold a line feed. A slot index in a
  field name or in a value is unpadded decimal ASCII. A slot list is slot
  indexes with one comma between indexes and no space. A date value is
  `YYYY-MM-DD`.
- **VAULT-FORMAT-8** — The field tables of this unit are complete. The `entry`
  and the `machine` fields of the index and the `done` field of the marker
  repeat: one line per entry, one line per machine, and one line per re-enrolled
  record. Every other field must appear at most once in its file.

The slot file fields are:

| Field                | Content                                                           |
| -------------------- | ----------------------------------------------------------------- |
| `candidate-password` | secret: the PWD BASE64 candidate ([KEY-BIP85](keys.md#key-bip85)) |
| `candidate-mnemonic` | secret: the BIP39 child candidate of 12 words                     |
| `slot`               | the slot index                                                    |

The index fields are:

| Field       | Content                                                                       |
| ----------- | ----------------------------------------------------------------------------- |
| `entry`     | one entry: the file name, one space, the slot list, one space, the entry name |
| `machine`   | one provisioned machine name                                                  |
| `pool-free` | the free slot indexes, as a slot list                                         |
| `pool-next` | the lowest slot index that no ceremony has reserved                           |
| `verified`  | the date of the last plate verification                                       |

The entry name comes last in the `entry` value, so the name can hold a space.
The file name in the `entry` value is the entry-file name of the current version
([VAULT-LAYOUT](vault.md#vault-layout)).

The counters file fields are:

| Field        | Content                                                                               |
| ------------ | ------------------------------------------------------------------------------------- |
| `<e>-<i>`    | the last-sent counter of the record of slot `e` at oracle `i`, unpadded decimal ASCII |
| `canary-<i>` | the last-sent counter of the canary record at oracle `i`, unpadded decimal ASCII      |

The counters file holds one line per record. The field name is the record name:
`<e>-<i>`, or `canary-<i>` ([ORC-COUNTER](oracle.md#orc-counter)).

The change marker fields are:

| Field  | Content                                                                    |
| ------ | -------------------------------------------------------------------------- |
| `kind` | the change kind: `passphrase` or `threshold`                               |
| `done` | one re-enrolled record per line: the record name `<e>-<i>` or `canary-<i>` |

One marker file covers both change kinds: a passphrase change
([ORC-ENROLL](oracle.md#orc-enroll)) and a threshold change
([CER-PROVISION](ceremonies.md#cer-provision)). The `kind` field names the
change kind.

The strict scanner keeps the parse surface small, in the manner of the strict
scanner discipline of the oracle service.

<a id="vault-index"></a>

## The index

- **VAULT-INDEX-1** — The index is one shared ciphertext object, sealed under
  `K_idx` in the seal format ([KEY-MASK](keys.md#key-mask)).
- **VAULT-INDEX-2** — The index maps each entry name to its file name. It
  records each entry's slot list, the pool state, the machine registry, and the
  date of the last plate verification. The machine registry holds the
  provisioned machine names.
- **VAULT-INDEX-3** — A daily read unwraps `k` index shares through this
  machine's index wraps and reconstructs `K_idx`
  ([KEY-SHARE](keys.md#key-share), [KEY-MASK](keys.md#key-mask)), so the read
  uses the session's canary masks and sends no extra oracle request
  ([ORC-CANARY](oracle.md#orc-canary)).
- **VAULT-INDEX-4** — A plate ceremony re-derives `K_idx` directly from `root`
  ([KEY-MASK](keys.md#key-mask)).
- **VAULT-INDEX-5** — The loss of the index degrades convenience only. No
  recovery path depends on the index ([REC-VAULT](recovery.md#rec-vault)).
- **VAULT-INDEX-6** — An index decrypt failure after a successful canary check
  must stop the session with a report that names the index file and this
  machine's index wraps of the quorum as the possible causes. The tool must not
  report this failure as a junk answer.

The index plaintext uses the line format
([VAULT-FORMAT](vault.md#vault-format)).

<a id="vault-config"></a>

## The config file

The config fields are:

| Field            | Content                                                                                                 |
| ---------------- | ------------------------------------------------------------------------------------------------------- |
| `oracle-<i>`     | the oracle at position `i`: the static public key hex, one space, the URL; or the single word `retired` |
| `threshold`      | the threshold `k`                                                                                       |
| `machine-name`   | the machine name                                                                                        |
| `kdf-rounds`     | the `bcrypt_pbkdf(3)` round count                                                                       |
| `plate-check`    | the plate check value, a hex string                                                                     |
| `pool-size`      | the pool size                                                                                           |
| `pool-watermark` | the low watermark of free slots                                                                         |
| `audit-age`      | the shadow audit age                                                                                    |
| `lock-timeout`   | the session lock timeout                                                                                |

- **VAULT-CONFIG-1** — The table above is the complete config field list. This
  unit solely owns the list, and no other unit adds a field.
- **VAULT-CONFIG-2** — The config file is plaintext, in the line syntax of
  [VAULT-FORMAT](vault.md#vault-format), with no seal.
- **VAULT-CONFIG-3** — The config file must hold no secret.
- **VAULT-CONFIG-4** — `X` and the wraps live in their own machine-local files
  and must not appear in the config.
- **VAULT-CONFIG-5** — The documentation must state that a copy of the config
  file leaks the oracle list, the threshold, the machine name, the plate check
  value, and the tunables. A holder of the plate check value can confirm that a
  candidate plate belongs to this vault.
- **VAULT-CONFIG-6** — Oracle positions are 1 to `n` with no gap. The position
  is the field name, so the line order carries no meaning. The value of a
  position can change to a replacement oracle or to the word `retired`. A
  position must not disappear, and two positions must not exchange values
  ([ORC-PROVISION](oracle.md#orc-provision), D-20). The threshold `k` must not
  exceed the count of live positions.

[ORC-PROVISION](oracle.md#orc-provision) governs the oracle values and the
threshold. [KEY-PIN](keys.md#key-pin) governs the round count, and
[KEY-MASTER](keys.md#key-master) defines the plate check value.
[ENTRY-POOL](entries.md#entry-pool) sets the pool defaults, and
[ENTRY-SHADOW](entries.md#entry-shadow) uses the audit age.
[CLI-REPL](programs.md#cli-repl) uses the lock timeout.

<a id="vault-atomic"></a>

## Atomic writes

- **VAULT-ATOMIC-1** — Every vault write must be atomic. This rule covers an
  entry file, the index, a wrap, an index wrap, the device factor, a canary
  check seal, the counters file, the config file, and the change marker. The
  atomic sequence is: `mkstemp(3)` in the target directory, write, `fsync(2)`,
  `rename(2)` over the target, then `fsync(2)` of the directory file descriptor.
- **VAULT-ATOMIC-2** — A crashed write must not leave a torn file.

The discipline mirrors the atomic record write of the oracle store (FuguOracle
STORE-ATOMIC-3).

<a id="vault-backup"></a>

## Backup properties

- **VAULT-BACKUP-1** — Every file of the shared set is ciphertext. Any copy of
  the shared set, on any transport, is a safe backup.
- **VAULT-BACKUP-2** — The safe-copy claim covers the shared set only. The
  machine-local set must not move between machines, and its loss recovers by a
  plate ceremony ([CER-PROVISION](ceremonies.md#cer-provision)).
- **VAULT-BACKUP-3** — FuguPass defines no sync protocol and no write
  coordination between machines. Concurrent entry creation on two machines can
  consume one slot twice, and a later file copy then overwrites one entry's
  file. A pool refill on a machine with a stale index can reserve slot indexes
  that another machine's refill already reserved. The documentation must
  recommend one minting machine for entry creation and for refills
  ([OVW-LIMITS](overview.md#ovw-limits)).
- **VAULT-BACKUP-4** — The tool can render a vault file up to the one-code QR
  capacity as one QR code for paper backup ([CLI-QR](programs.md#cli-qr)). The
  tool must report a file that exceeds the capacity.

A vault restored from an old copy stays able to address its oracle records,
because the counter policy uses the wall clock
([ORC-COUNTER](oracle.md#orc-counter), [REC-RESTORE](recovery.md#rec-restore)).
No file on disk, in either set, verifies the passphrase without an oracle
([KEY-MASK](keys.md#key-mask), [SAFE-FLOOR](security.md#safe-floor)).
