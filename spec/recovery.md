# Recovery

This document specifies the restore paths of a FuguPass vault. The plate is the
recovery root: the SeedQR plate holds the master `M`. [keys.md](keys.md) defines
the notation `M`, `root`, `f(k, label)`, `H(x)`, `K_e`, `K_idx`, the slot index
`e`, the oracle count `n`, and the threshold `k`. This document cites FuguOracle
rules as prose tokens, for example FuguOracle OPS-SET-3.
[CLI-SCAN](programs.md#cli-scan) states the video-device requirement of a plate
scan.

<a id="rec-principle"></a>

## Recovery independence

- **REC-PRINCIPLE-1** — The oracle gates reveals only. The oracle must not gate
  recovery (D-04).
- **REC-PRINCIPLE-2** — The plate alone must restore every derived and sovereign
  entry.
- **REC-PRINCIPLE-3** — The plate plus any copy of the shared set must restore
  every stored entry ([VAULT-BACKUP](vault.md#vault-backup)).
- **REC-PRINCIPLE-4** — No restore path touches an oracle.

The owner can lose the oracle, a third party can seize it, and the oracle can
wipe a record. The user loses a reveal flow, never data. A restore returns the
data with no oracle. The reveal flow returns by re-enrollment at a live oracle
([REC-WIPE](recovery.md#rec-wipe)).

<a id="rec-plate"></a>

## Plate-alone recovery

Plate-alone recovery starts from the plate and nothing else.

- **REC-PLATE-1** — From the plate, the tool must re-derive the entry key of
  every slot from 0 up to the scan ceiling ([KEY-ENTRY](keys.md#key-entry)) and
  must re-materialize every derived secret from BIP85
  ([KEY-BIP85](keys.md#key-bip85)).
- **REC-PLATE-2** — The scan ceiling is 1024 slots. The tool must report the
  scanned range, and the user can raise the ceiling.
- **REC-PLATE-3** — A scan past the last used slot is safe and costs nothing:
  derivation is deterministic, and an unused slot maps to no entry.
- **REC-PLATE-4** — A sovereign entry restores from its own plate, independent
  of the vault plate ([ENTRY-MODEL](entries.md#entry-model)).
- **REC-PLATE-5** — Without vault files, the entry names and the metadata are
  gone, and a stored secret does not return. The documentation must state this
  limit.

The ceiling of 1024 slots covers sixteen ceremonies at the default pool size of
64 slots ([ENTRY-POOL](entries.md#entry-pool)). The paper QR export and the
promiscuous backup of the shared set answer metadata loss
([VAULT-BACKUP](vault.md#vault-backup)).

<a id="rec-vault"></a>

## Plate-plus-files recovery

Plate-plus-files recovery starts from the plate and a copy of the shared set.

- **REC-VAULT-1** — For each slot in the scanned range, the tool must derive
  `K_e`, must compute `H(K_e)`, and must match the entry file by its name
  ([VAULT-LAYOUT](vault.md#vault-layout)). The match needs no index.
- **REC-VAULT-2** — Every matched entry file decrypts under its re-derived `K_e`
  ([VAULT-SEAL](vault.md#vault-seal)).
- **REC-VAULT-3** — The index opens under `K_idx`, re-derived from `root`, with
  no oracle and no passphrase ([KEY-MASK](keys.md#key-mask)).
- **REC-VAULT-4** — A lost passphrase loses no data. The plate restores the
  entries and the index, and a plate ceremony re-enrolls this machine's records
  under a new passphrase ([ORC-ENROLL](oracle.md#orc-enroll)).

A stored entry has no derivation, so this path is its restore path
([ENTRY-MODEL](entries.md#entry-model)). A `set_pin` needs no old passphrase, so
the re-enrollment of REC-VAULT-4 works without the lost passphrase. The
re-enrollment of REC-VAULT-4 is the full re-enrollment run (CER-PROVISION-17) of
[CER-PROVISION](ceremonies.md#cer-provision).

<a id="rec-wipe"></a>

## Recovery after oracle loss

This unit covers a record wipe, an oracle host loss or seizure, and a rotation
of the oracle static key.

- **REC-WIPE-1** — After any oracle loss, every affected mask is dead, and no
  data is lost: the plate restores every entry with no oracle
  ([REC-PLATE](recovery.md#rec-plate), [REC-VAULT](recovery.md#rec-vault)).
- **REC-WIPE-2** — The reveal flow of an affected record returns by a plate
  ceremony: the tool re-enrolls this machine's records at the affected position,
  or at a replacement oracle in that position, and recomputes the wraps, in the
  loop of [CER-PROVISION](ceremonies.md#cer-provision).
- **REC-WIPE-3** — A fresh `set_pin` creates a fresh record with fresh key
  material, and no old mask returns (FuguOracle OPS-SET-3 and FuguOracle
  OPS-SET-4).
- **REC-WIPE-4** — A rotation of an oracle's static key orphans every record of
  every machine at that oracle and forces this ceremony on each machine
  (FuguOracle DEPLOY-BACKUP-5). The other oracles are untouched, and reveals
  continue while `k` oracles of the set stay live and reachable.
- **REC-WIPE-5** — Reveals continue while `k` oracles of the set stay live and
  reachable: any `k` reachable oracles serve every reveal, with no ceremony
  ([ORC-QUORUM](oracle.md#orc-quorum)). With every position live, the set
  tolerates the loss, seizure, or wipe of up to `n − k` oracles. Reveals pause
  while fewer than `k` oracles are reachable. After a loss, seizure, or wipe
  that leaves fewer than `k` oracles reachable, a plate ceremony re-enrolls at
  replacement oracles, and reveals resume. Data is never lost (REC-WIPE-1,
  D-04).
- **REC-WIPE-6** — A wiped or lost record at one oracle blocks nothing while `k`
  live records remain for its entry. The plate ceremony restores full
  redundancy.

After a host loss, the ceremony can enroll at a replacement oracle in the lost
oracle's position: the ceremony writes the replacement's URL and static public
key to that position in the config file
([ORC-PROVISION](oracle.md#orc-provision),
[VAULT-CONFIG](vault.md#vault-config)). The masks of a seized oracle are
meaningless alone: a record holds no name, no purpose, and no content
([OVW-MODEL](overview.md#ovw-model)).

<a id="rec-restore"></a>

## Restore from a backup copy

- **REC-RESTORE-1** — Any copy of the shared set restores by file copy onto a
  machine that keeps its own machine-local state
  ([VAULT-BACKUP](vault.md#vault-backup)).
- **REC-RESTORE-2** — A restored vault stays able to address its oracle records:
  the counter policy takes the wall clock, and the wall clock exceeds any stale
  stored counter ([ORC-COUNTER](oracle.md#orc-counter)).
- **REC-RESTORE-3** — A restore onto a fresh machine is machine provisioning: a
  plate ceremony ([CER-PROVISION](ceremonies.md#cer-provision)).
- **REC-RESTORE-4** — An entry created after the backup date is absent from the
  copy. A derived entry re-derives from the plate
  ([REC-PLATE](recovery.md#rec-plate)). A stored secret sealed after the backup
  date does not return from this copy.
- **REC-RESTORE-5** — The index in the copy can be stale. A stale index degrades
  names only: every entry file still matches by `H(K_e)` and still decrypts
  under its `K_e` ([REC-VAULT](recovery.md#rec-vault)).
- **REC-RESTORE-6** — A rewind of the machine-local set to an older copy leaves
  an enrollment after the copy date unmatched. The enrollment replaced the
  record's key material at the oracle, so the older wrap of that record is
  stale. A stale wrap recovers by a plate ceremony
  ([CER-PROVISION](ceremonies.md#cer-provision)).

The wraps and the counters of the receiving machine stay valid, because they
bind to that machine's records, and the copy does not touch them. A copied slot
file without a record on this machine does not reveal on this machine until its
next plate ceremony, and it still recovers from the plate
([CER-PROVISION](ceremonies.md#cer-provision)).
