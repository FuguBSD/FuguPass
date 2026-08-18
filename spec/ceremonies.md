# Ceremonies

This document specifies the ceremonies: the dice ceremony, vault creation, pool
refill, machine provisioning, and plate verification.
A ceremony is a procedure with the master present.
Between ceremonies the master exists only on plates (D-12).
The notation `M`, `root`, `f(k, label)`, `K_e`, `K_idx`, `c_ei`, `share(S, i)`,
the slot index `e`, the oracle index `i`, and the threshold `k` comes from
[keys.md](keys.md).
The recovery procedures are in [recovery.md](recovery.md).

<a id="cer-dice"></a>

## The dice ceremony

The dice ceremony generates the master `M` (D-11).
Dice `a` and `b` are two d16 of different colors, and die `c` is one d8.
All die values are 1-based.
The two d16 must stay distinguishable through every roll, because the order of `a`
and `b` matters.

- **CER-DICE-1** — One roll of `a`, `b`, and `c` must select one BIP39 word by
  `index = (a-1)·128 + (b-1)·8 + (c-1)`.
- **CER-DICE-2** — The ceremony must select eleven words by eleven rolls. One final
  roll of `a` and `c` must give the 7 final entropy bits: `r = (a-1)·8 + (c-1)`.
- **CER-DICE-3** — The tool must compute only the 4-bit checksum and must show the
  final word as `wordlist[r·16 + checksum]`.
- **CER-DICE-4** — A printed lookup card must let the user verify every word by hand
  against the rolls.
- **CER-DICE-5** — Verification must close the ceremony. The user must load the
  twelve words into an air-gapped signer. The user must confirm that the signer
  accepts the checksum. The user must stamp the plate. The user must verify the
  plate by a scan against the rolled words.
- **CER-DICE-6** — No d6 code path exists. A signer with d6 support is an equal
  entropy source through a SeedQR import ([KEY-MASTER](keys.md#key-master)).
- **CER-DICE-7** — The tool must erase `M` and `root` with `explicit_bzero(3)` at the
  end of the ceremony.

One roll has 2048 outcomes, which map one-to-one to the BIP39 wordlist, with no
rejection and no modulo bias.
Eleven rolls plus the final roll give the full 128 entropy bits, and the tool
contributes no entropy.

<a id="cer-create"></a>

## Vault creation

Vault creation makes a new vault on its first machine.
The rules of this unit are the steps of the ceremony.
The tool must run the steps in rule order.

- **CER-CREATE-1** — The ceremony must obtain the master by the dice ceremony, by a
  SeedQR scan, or by a scan of a BIP85 child of an external seed
  ([KEY-MASTER](keys.md#key-master)).
- **CER-CREATE-2** — The tool must derive this machine's device factor `X` from its
  machine name ([KEY-DEVICE](keys.md#key-device)) and must persist it in the
  machine-local set ([VAULT-LAYOUT](vault.md#vault-layout)).
- **CER-CREATE-3** — The tool must write the config file
  ([VAULT-CONFIG](vault.md#vault-config)), including the plate check value
  ([KEY-MASTER](keys.md#key-master)).
- **CER-CREATE-4** — The tool must read the passphrase twice with `readpassphrase(3)`
  and must require a match.
- **CER-CREATE-5** — The tool must enroll this machine's canary record at each
  oracle and must verify each canary with one immediate `get_pin` round trip
  ([ORC-CANARY](oracle.md#orc-canary)). The tool must then seal each oracle's
  canary check value. The tool must derive `K_idx`, must split it
  ([KEY-SHARE](keys.md#key-share)), and must persist this machine's index wrap of
  each oracle ([KEY-MASK](keys.md#key-mask)).
- **CER-CREATE-6** — The tool must run the slot loop for each slot of the pool
  ([ENTRY-POOL](entries.md#entry-pool)). The slot loop has these steps, in this
  order. The tool must derive `K_e`. The tool must materialize both BIP85
  candidates ([KEY-BIP85](keys.md#key-bip85)). Then, for each oracle in list
  order: the tool must enroll this machine's record with `set_pin`
  ([ORC-ENROLL](oracle.md#orc-enroll)), must verify the HTTP success of the
  enrollment, and must compute and persist this machine's wrap `c_ei` from the
  re-derived share ([KEY-SHARE](keys.md#key-share), [KEY-MASK](keys.md#key-mask)).
  Last, the tool must seal the slot file under `K_e`. An enrollment failure at any
  oracle must stop the ceremony with a report that names the oracle.
- **CER-CREATE-7** — The tool must seal the index under `K_idx` and must register
  this machine's name in it ([VAULT-INDEX](vault.md#vault-index)).
- **CER-CREATE-8** — The tool must erase `M`, `root`, `K_idx`, every `K_e`, every
  share, and every mask with `explicit_bzero(3)`.
- **CER-CREATE-9** — The tool must export this machine's revocation kit
  ([ORC-REVOKE](oracle.md#orc-revoke)).

Every `set_pin` failure is an HTTP error (FuguOracle OPS-SET-7), so the slot loop
verifies each enrollment by its HTTP status.
A stopped slot loop leaves a slot with wraps at some oracles only.
An oracle addition and a crash between a `set_pin` and its wrap write create the
same partial-wrap state ([ORC-ENROLL](oracle.md#orc-enroll)).
A stopped creation or refill runs again.
A new `set_pin` replaces the record's key material at the oracle, and the tool
recomputes the wrap from the re-derived share, so the re-run is safe.
The revocation kit holds no secret, so its export follows the erasure step.

<a id="cer-refill"></a>

## Pool refill

A pool refill extends the pool of free slots on one machine.

- **CER-REFILL-1** — A plate scan must re-derive `root`.
- **CER-REFILL-2** — The ceremony must reserve the next sequential slot indexes. The
  ceremony must run the slot loop of CER-CREATE-6 for each new slot on this machine.
  The ceremony must record the new pool state in the index
  ([VAULT-INDEX](vault.md#vault-index)).
- **CER-REFILL-3** — The low-watermark warning of
  [ENTRY-POOL](entries.md#entry-pool) must name this ceremony.
- **CER-REFILL-4** — A refill must not change any existing entry.
- **CER-REFILL-5** — Every other machine gains records and wraps for the new slots at
  its next plate ceremony ([CER-PROVISION](ceremonies.md#cer-provision)). Until that
  ceremony, that machine cannot reveal an entry on a new slot, and the entry still
  recovers from the plate ([REC-PLATE](recovery.md#rec-plate)).
- **CER-REFILL-6** — The tool must erase `M`, `root`, `K_idx`, every new `K_e`,
  every share, and every mask with `explicit_bzero(3)` at the end of the ceremony.
- **CER-REFILL-7** — The tool must read the passphrase with `readpassphrase(3)` and
  must verify it against the canary record of each live oracle before the slot loop
  ([ORC-CANARY](oracle.md#orc-canary)).
- **CER-REFILL-8** — While the change marker exists, the refill ceremony must
  refuse to start (CER-PROVISION-18).

<a id="cer-provision"></a>

## Machine provisioning

Machine provisioning adds one machine to an existing vault.
Rules CER-PROVISION-1 to CER-PROVISION-10 are the steps of the ceremony.
The tool must run these steps in rule order.

- **CER-PROVISION-1** — The ceremony must scan the plate and re-derive `root`.
- **CER-PROVISION-2** — The ceremony must copy the shared set onto this machine by
  any transport ([VAULT-BACKUP](vault.md#vault-backup)).
- **CER-PROVISION-3** — The tool must derive this machine's device factor `X` from
  its machine name ([KEY-DEVICE](keys.md#key-device)) and must persist it in the
  machine-local set ([VAULT-LAYOUT](vault.md#vault-layout)). When the machine name is
  already in the machine registry of the index ([VAULT-INDEX](vault.md#vault-index)),
  and this machine holds no machine-local set for that name, the tool must warn that
  the ceremony replaces the records of the machine that holds that name. The tool
  must require an explicit confirmation.
- **CER-PROVISION-4** — The tool must write the config file
  ([VAULT-CONFIG](vault.md#vault-config)), including the plate check value.
- **CER-PROVISION-5** — The tool must read the passphrase twice with
  `readpassphrase(3)` and must require a match.
- **CER-PROVISION-6** — The tool must enroll this machine's canary record at each
  oracle and must verify each canary with one immediate `get_pin` round trip
  ([ORC-CANARY](oracle.md#orc-canary)). The tool must then seal each oracle's
  canary check value. The tool must derive `K_idx`, must split it
  ([KEY-SHARE](keys.md#key-share)), and must persist this machine's index wrap of
  each oracle ([KEY-MASK](keys.md#key-mask)).
- **CER-PROVISION-7** — For each existing slot, the tool must derive `K_e` and,
  for each live oracle in list order, must enroll this machine's record with
  `set_pin` ([ORC-ENROLL](oracle.md#orc-enroll)) and must compute and persist this
  machine's wrap `c_ei` from the re-derived share ([KEY-SHARE](keys.md#key-share)).
  The cost is one `set_pin` request per live oracle, per slot.
- **CER-PROVISION-8** — The tool must register this machine's name in the index
  ([VAULT-INDEX](vault.md#vault-index)).
- **CER-PROVISION-9** — The tool must export this machine's revocation kit
  ([ORC-REVOKE](oracle.md#orc-revoke)).
- **CER-PROVISION-10** — The tool must erase `M`, `root`, `K_idx`, every `K_e`,
  every share, and every mask with `explicit_bzero(3)`.
- **CER-PROVISION-11** — Each machine holds its own records and wraps, so the owner
  can revoke one machine and keep every other machine in service (D-07,
  [ORC-REVOKE](oracle.md#orc-revoke)).
- **CER-PROVISION-12** — Machine provisioning can run again on a provisioned machine.
  On such a machine, the loop of CER-PROVISION-7 covers each slot-oracle pair for
  which this machine holds no wrap, and the tool re-wraps each dead index wrap
  ([ORC-CANARY](oracle.md#orc-canary)) and re-seals each stale canary check value.
- **CER-PROVISION-13** — A change of the oracle list or of the threshold is this
  ceremony, run on each machine of the vault. The ceremony records the new list or
  the new threshold in the config ([VAULT-CONFIG](vault.md#vault-config)) before
  any enrollment. Until every machine runs it, each machine reveals against its own
  recorded list and threshold, and the vault's offline-loss bound is the weakest
  machine's threshold ([SAFE-FLOOR](security.md#safe-floor)). The one-breach
  passphrase verifier is unchanged. The documentation must state this.
- **CER-PROVISION-14** — An added oracle takes the next free position. The loop of
  CER-PROVISION-12 then covers exactly the new slot-oracle pairs: for each slot,
  the tool re-derives the split of `K_e` and evaluates the share at the new index
  ([KEY-SHARE](keys.md#key-share)), enrolls this machine's record at the new
  oracle, and persists the wrap. The canary and the index wrap of the new oracle
  enroll as in CER-PROVISION-6. Existing wraps at other oracles stay unchanged.
- **CER-PROVISION-15** — A threshold change changes every share. The tool must
  re-split every `K_e` and `K_idx` with the new `k`
  ([KEY-SHARE](keys.md#key-share)), must re-enroll this machine's record at every
  live oracle with a fresh `set_pin`, and must recompute every wrap on this
  machine, canaries and index wraps included. A stale wrap under a live mask would
  keep the old threshold reachable, so the tool must obtain fresh masks. The tool
  must persist the change marker with the kind `threshold` before the first
  `set_pin`, in the machine-local set ([VAULT-LAYOUT](vault.md#vault-layout),
  [VAULT-FORMAT](vault.md#vault-format)). While the marker exists, a session must
  refuse reveals and must name the re-run of this ceremony (ORC-ENROLL-10). The
  tool must re-run an interrupted threshold change from the start, and the
  ceremony must remove the marker after the last wrap.
- **CER-PROVISION-16** — A ceremony that retires a position must delete this
  machine's wrap files, canary check seal, and index wrap of that position
  (ORC-PROVISION-6). The same deletion must precede a re-enrollment of this
  machine's records at a position: after a replacement, a static-key rotation, or
  a record loss at that oracle. The loop of CER-PROVISION-12 then covers exactly
  the affected pairs. The shares re-derive from the plate, so nothing is lost
  ([KEY-SHARE](keys.md#key-share)). At a retirement, the ceremony report must
  direct the owner to destroy this vault's records at the departing oracle with
  the revocation kit ([ORC-REVOKE](oracle.md#orc-revoke)) before the config
  discards the URL.
- **CER-PROVISION-17** — A full re-enrollment run re-enrolls every record of this
  machine under one passphrase: the loop of CER-PROVISION-7 over every slot and
  every live oracle, with a fresh `set_pin` per record and every wrap recomputed,
  and the canary and the index wrap of each live oracle per CER-PROVISION-6. The
  run must remove the change marker at the end
  ([ORC-ENROLL](oracle.md#orc-enroll)). The full run overrides the no-wrap
  criterion of CER-PROVISION-12.
- **CER-PROVISION-18** — While the change marker exists, a ceremony that enrolls
  or re-enrolls a record must refuse to start. The refusal must name the resume
  command for the kind `passphrase`, or the ceremony re-run for the kind
  `threshold`. The re-run of an interrupted threshold change (CER-PROVISION-15)
  and the full re-enrollment run (CER-PROVISION-17) are exempt.

The slot loop and the index registration read the index, so the copy of the shared
set precedes them.
After the ceremony, every existing entry reveals on this machine through this
machine's own records.
A ceremony and its enrollment loops need every live oracle reachable.
The quorum availability claim covers reveals only
([OVW-LIMITS](overview.md#ovw-limits)).
A run that re-enrolls every record of this machine under one passphrase removes
the change marker, and the report names the removal (ORC-ENROLL-12).

<a id="cer-verify"></a>

## Plate verification

Plate verification confirms that a plate decodes to the master of this vault.

- **CER-VERIFY-1** — The tool must scan the plate, must re-derive `root`, must
  re-derive the plate check value ([KEY-MASTER](keys.md#key-master)), and must
  compare it with the check value in the config file
  ([VAULT-CONFIG](vault.md#vault-config)).
- **CER-VERIFY-2** — Verification must not touch any oracle record and must not
  reveal any secret.
- **CER-VERIFY-3** — The audit command ([CLI-REPL](programs.md#cli-repl)) must report
  the date of the last plate verification.
- **CER-VERIFY-4** — The tool must erase `M`, `root`, and `K_idx` with
  `explicit_bzero(3)` at the end of the verification.
- **CER-VERIFY-5** — On a match, the tool must record the verification date in the
  index, under `K_idx` re-derived from `root` ([KEY-MASK](keys.md#key-mask)).

The check value is one-way ([KEY-MASTER](keys.md#key-master)), so the config file
leaks nothing about the master.
A mismatch reports a wrong plate or a damaged plate.
