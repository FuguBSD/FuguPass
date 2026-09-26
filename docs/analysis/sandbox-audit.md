# The sandbox and memory-hygiene audit

|         |                                                                                            |
| ------- | ------------------------------------------------------------------------------------------ |
| Status  | Record. It holds the sandbox and memory-hygiene audit of the P4 exit of ROADMAP.md.        |
| Covers  | The promises and the unveil list of PROG-SPLIT, PROG-SCAN-6 and PROG-QR-4, and SEC-MEMORY. |
| Decides | Nothing. Each finding names its fix, or the reason it stands.                              |

## The question

Each program restricts itself with `pledge(2)` and `unveil(2)` (PROG-SPLIT-3 to
PROG-SPLIT-13). Every exit path that held a secret erases it, and every secret
comparison runs in constant time (SEC-MEMORY-1, SEC-MEMORY-2). This record holds
the evidence that the code agrees with those rules. The first part holds the
syscalls and the paths of each program under `ktrace(1)`. The second part holds
the secret buffers and the comparisons of each C source.

## The method

### The traces

The runs took the test guest of the harness: OpenBSD 7.8 arm64 under HVF, on
2026-09-26. The tree of the guest was the harness build of the branch head. The
SHA-256 of each source of `src/` and `bin/` agreed with the head.
`make obj && make FUGUPASS_REGRESS=1` in `src` built it, so the core process
read the helper directory from `FUGUPASS_HELPERS` (PROG-SPLIT-11). One
FuguOracle instance of the `fuguoracle` package served the loopback port, as in
the harness (TEST-HARNESS-2).

Each run started with `ktrace -i -t cnpsx -f <trace> <program> ...`. The trace
points are the syscalls, the path lookups, the pledge violations, the signals
and the arguments of `execve(2)`. The I/O point stayed off, so no trace holds a
byte of a secret. The `-i` option carried the trace into each child, so one
trace of the core process holds its helper as well.

| Run | Command                                                                          | Child                       |
| --- | -------------------------------------------------------------------------------- | --------------------------- |
| 1   | `fugupass create -k 1 -m audit-machine -r 16 -p 4 <oracle>` with the scan double | `fugupass-scan`, the double |
| 2   | `fugupass gen -T mnemonic m1`                                                    | none                        |
| 3   | `fugupass show m1`                                                               | `fugupass-qr`               |
| 4   | `fugupass add -T password -f username=u1 a1`                                     | none                        |
| 5   | `fugupass` with the lines `ls`, `show a1` and `quit` on a named pipe             | `fugupass-repl`             |
| 6   | `fugupass create` with the scan helper of the build                              | `fugupass-scan`             |
| 7   | `fugupass-qr` on 12 words, and on the sealed index of the vault of run 1         | none                        |
| 8   | `fugupass-scan` with no argument                                                 | none                        |

Runs 1 to 5 read the passphrase from `/dev/tty`, so they ran on the serial
console under `tests/expect/console.exp` (TEST-HARNESS-8). Runs 6 to 8 ran over
`fuguvm ssh`. The guest holds four video devices and no camera, so runs 6 and 8
stop at the open of `/dev/video` with `ENXIO` (PROG-SCAN-7).

`kdump(1)` decoded each trace, and one awk script summarized it per process. The
summary holds the syscalls before and after the pledge call, and the `ioctl(2)`
requests. It also holds the paths of each lookup, the failed calls, and the
pledge-violation and signal records. A child runs under the execpromises from
its `execve(2)` on, so its summary splits at that call and again at its own
pledge call. The promise of each syscall comes from the `pledge(2)` manual of
the guest and from the table `pledge_syscalls[]` of `sys/kern/kern_pledge.c`.
That table allows `exit`, `kbind`, `__set_tcb`, `pledge` and `pinsyscalls` under
every promise set, and it puts `mimmutable` and `getthrid` under `stdio`.

### The read of the sources

The memory audit read the 25 C sources of `src/` with their headers, one
function at a time. A secret is the master and its entropy, `root`, the device
factor, and each derived key. A passphrase, a pin secret, a mask, a share, a
coefficient and a decrypted plaintext are secrets as well. So are a mnemonic
word and a word index. A public key, a salt, a ciphertext, a MAC tag, a nonce
and a counter are not secrets. For each buffer that holds a secret, the audit
names the function and the erasure on each exit path. For each comparison call,
it names the operands.

## The core process

PROG-SPLIT-3 names the promises
`stdio rpath wpath cpath flock proc exec inet dns tty`, and the execpromises
`stdio rpath prot_exec tty video`. The unveil list holds the vault directory
(`rwc`), `/dev/tty` (`rw`), and the three helper programs (`x`, and `rx` for the
interface program). It holds the runtime files `/usr/libexec/ld.so`,
`/var/run/ld.so.hints`, `/usr/lib` and `/usr/local/lib` (`r`), and
`/etc/ssl/cert.pem` (`r`). It also holds the derived list (`r`), and
`/dev/video` with `/dev/video0` to `/dev/video9` (`r`). The derived list of the
guest holds `/usr/libdata/perl5`, `/usr/libdata/perl5/aarch64-openbsd`,
`/usr/local/libdata/perl5/site_perl`,
`/usr/local/libdata/perl5/site_perl/aarch64-openbsd`, `/dev/urandom`,
`/etc/resolv.conf`, `/etc/hosts`, `/etc/services`, `/etc/protocols` and
`/etc/localtime` (PROG-SPLIT-10).

Every run of the core process made 32 `unveil(2)` calls and then one `pledge(2)`
call, in that order (PROG-SPLIT-3). The 32 calls are the vault directory, the 16
rows of the list, and the 11 video devices. The three helper paths and the
closing call with two null arguments complete them. The table holds the union of
the syscalls after the pledge call of runs 1 to 6, by promise.

| Promise | Syscalls after the pledge call                                                                                                                                                                                     |
| ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `stdio` | `close`, `exit`, `fcntl`, `fstat`, `fsync`, `getentropy`, `getpid`, `issetugid`, `kbind`, `mimmutable`, `minherit`, `mmap`, `mprotect`, `munmap`, `pipe2`, `poll`, `read`, `sigaction`, `sysctl`, `wait4`, `write` |
| `rpath` | `access`, and `open` for a read                                                                                                                                                                                    |
| `wpath` | `open` for a write                                                                                                                                                                                                 |
| `cpath` | `mkdir`, `rename`                                                                                                                                                                                                  |
| `proc`  | `fork`                                                                                                                                                                                                             |
| `exec`  | `execve`, in the child before the exec                                                                                                                                                                             |
| `inet`  | `socket`, `connect`, `setsockopt`                                                                                                                                                                                  |
| `tty`   | `ioctl` with `TIOCGETA` and `TIOCSETAF`, and the open of `/dev/tty`                                                                                                                                                |
| `dns`   | none: the oracle URL holds a numeric address, and the read of `/etc/resolv.conf` runs under `rpath`                                                                                                                |
| `flock` | none                                                                                                                                                                                                               |

The `mmap` calls with `PROT_EXEC` all sit before the pledge call: the dynamic
linker maps the five libraries there. The paths after the first unveil call are
`/dev/tty`, `/etc/resolv.conf` and the vault directory. Inside the vault they
are its temporary files, the index, the entry files, and the files of
`machine/`. Each of them sits in the list. Two lookups fail with `ENOENT`:
`machine/change`, the marker of an interrupted change, and the config file
before run 1 writes it. The traces hold no pledge-violation record and no signal
record.

Verdict: the core process holds to PROG-SPLIT-3, PROG-SPLIT-12 and
PROG-SPLIT-13.

## The interface process

`fugupass-repl` runs under the execpromises from its exec, and it then pledges
`stdio tty` (PROG-SPLIT-7, PROG-SPLIT-8). Run 5 holds it. Before its pledge
call, the interpreter loads its runtime and the modules. The table holds its
calls by phase and promise.

| Phase                  | Promise     | Syscalls                                                                                                                                                                                                                 |
| ---------------------- | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| before its pledge call | `rpath`     | `open`, `stat`, `getdents`                                                                                                                                                                                               |
| before its pledge call | `prot_exec` | `mmap` with `PROT_EXEC`, 11 times                                                                                                                                                                                        |
| before its pledge call | `stdio`     | `__set_tcb`, `close`, `fcntl`, `fstat`, `getegid`, `getentropy`, `geteuid`, `getgid`, `getthrid`, `getuid`, `issetugid`, `kbind`, `lseek`, `mimmutable`, `minherit`, `mprotect`, `munmap`, `read`, `sigaction`, `sysctl` |
| after its pledge call  | `stdio`     | `close`, `exit`, `fcntl`, `fstat`, `kbind`, `lseek`, `mprotect`, `munmap`, `read`, `select`, `sigaction`, `sigprocmask`, `write`                                                                                         |

No `mprotect` after the pledge call asks for `PROT_EXEC`. The run made no
`ioctl` call: its standard input was a named pipe, so the line editor ran in its
plain mode.

The paths are the program text of `fugupass-repl`, with the `r` permission of
PROG-SPLIT-7. They are also `libc`, `libm` and `libperl` under `/usr/lib`, and
the two files of the dynamic linker. 125 lookups sit under `/usr/libdata/perl5`,
and 100 under `/usr/local/libdata/perl5/site_perl`. 219 of the `stat` calls fail
with `ENOENT`: the module search of the interpreter probes each directory of
`@INC`. Each path sits in the list, except `/usr/bin/perl`: finding S2 holds it.

Verdict: the interface process holds to PROG-SPLIT-7 and PROG-SPLIT-10.

## The scan helper

`fugupass-scan` unveils no path, and it pledges `stdio video` after the open of
the device (PROG-SPLIT-4, PROG-SCAN-6). Runs 6 and 8 hold it. Under the core
process, its calls after the exec sit under `stdio` and `rpath`. They are
`__set_tcb`, `close`, `exit`, `fstat`, `getentropy`, `getrlimit`, `getthrid`,
`issetugid`, `kbind`, `mimmutable`, `mmap`, `mprotect`, `munmap`, `open`,
`pinsyscalls`, `read` and `write`. One `mmap` asks for `PROT_EXEC`, for `libc`.
The paths are `/usr/libexec/ld.so`, `/var/run/ld.so.hints`, `/usr/lib/libc.so`
and `/dev/video`. The helper reads the two core limits and writes none under the
core process: the inherited limits are zero (SEC-MEMORY-3). Standalone, it calls
`setrlimit(2)` once.

The open of `/dev/video` fails with `ENXIO`, and the helper reports and exits 1
before its pledge call. The guest therefore shows no call after the pledge call:
no `poll(2)`, no frame read and no `VIDIOC` request. Two tests of the repository
cover that part. `src/regress/sandbox.c` makes the pledge call of the helper
under the execpromises of the core, and it proves that the call gives no `EPERM`
(PROG-SPLIT-4). `src/regress/scan.c` decodes the test pictures offline through
the same functions (TEST-KAT-3). The scan double of the harness ran under the
same execpromises in run 1, with `stdio` and `rpath` calls alone.

Verdict: the observed part holds to PROG-SPLIT-4. The part after the open stands
on the two tests, because the guest holds no camera (PROG-SCAN-7).

## The render helper

`fugupass-qr` pledges `stdio` first, and it unveils no path (PROG-SPLIT-5,
PROG-QR-4). Runs 3 and 7 hold it. Before its pledge call, the dynamic linker
opens `/var/run/ld.so.hints`, `/usr/lib/libc.so`, `/usr/lib/libpthread.so` and
`/usr/local/lib/libqrencode.so`, and it maps three of them with `PROT_EXEC`. The
helper reads the two core limits, and standalone it calls `setrlimit(2)` once
(SEC-MEMORY-3). After its pledge call, each call sits under `stdio`. The calls
are `exit`, `fstat`, `getentropy`, `issetugid`, `kbind`, `mimmutable`,
`minherit`, `mmap`, `mprotect`, `munmap`, `read`, `sysctl` and `write`. No
lookup of a path follows the pledge call. The 12 words gave a code of 17 lines,
and the sealed index of 252 bytes gave one of 33 lines.

Verdict: the render helper holds to PROG-SPLIT-5.

## The memory audit

### The secret buffers

Each row names the buffers of one function that hold a secret, and the erasure
of them. "The out label" means one `explicit_bzero(3)` call under a label that
every exit path of the function reaches. A caller-owned output is the buffer of
a pointer argument. The callee erases it on each failure, and the caller erases
it after the last use. `sandbox.c`, `fugupass-scan.c`, `fugupass-qr.c` and
`iface.c` hold no secret buffer: the interface holds no secret (PROG-IFACE).

| Source       | Function                                                                                           | Buffers and the secret                                                                                                  | Erasure                                                                                 |
| ------------ | -------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `derive.c`   | `master_sum`                                                                                       | `bits`, `digest`, `want`: the master entropy, its hash and the checksum                                                 | the out label                                                                           |
| `derive.c`   | `derive_master_check`                                                                              | `index`: the 12 word indexes                                                                                            | the out label                                                                           |
| `derive.c`   | `derive_client_reduce`                                                                             | `num`, `key`, `ctx`: the key material and the client key                                                                | `BN_clear_free` and `BN_CTX_free` on every path                                         |
| `derive.c`   | `derive_client_key`, `derive_client_key_canary`                                                    | `t`: the key material                                                                                                   | the out label                                                                           |
| `derive.c`   | `derive_root`, `derive_f`, `derive_client_reduce`, `derive_client_key`, `derive_client_key_canary` | the caller-owned output                                                                                                 | erased on each failure                                                                  |
| `bip85.c`    | `bip85_child`                                                                                      | `data`, `hash`: the parent key and the child chain code                                                                 | the out label                                                                           |
| `bip85.c`    | `bip85_entropy`                                                                                    | `key`, `chain`: the key and the chain code of each step                                                                 | the out label                                                                           |
| `bip85.c`    | `bip85_master`                                                                                     | `hash`: the master key and its chain code                                                                               | the out label                                                                           |
| `bip85.c`    | `bip85_pwd_base64`                                                                                 | `entropy`, `text`: the DRNG output and the password                                                                     | the out label                                                                           |
| `bip85.c`    | `bip85_bip39`                                                                                      | `entropy`, `bits`, `digest`, `word`: the child entropy, its checksum and one word                                       | the out label; a partial mnemonic in the output is erased on a failure                  |
| `share.c`    | `share_split`                                                                                      | `coeff`: one coefficient                                                                                                | the out label; the partial share in the output is erased on a failure                   |
| `pin.c`      | `pin_secret`                                                                                       | the caller-owned pin secret                                                                                             | erased on a failure                                                                     |
| `seal.c`     | `aead_ctx`, `seal_seal`, `seal_open`                                                               | `ctx`: the copy of the seal key in the AEAD context                                                                     | `EVP_AEAD_CTX_free` on every path; `seal_open` erases the plaintext output on a failure |
| `wordlist.c` | `wordlist_index`                                                                                   | `want`: the word of the caller                                                                                          | before each return                                                                      |
| `envelope.c` | `aes_cbc`                                                                                          | `ctx`: the AES key schedule                                                                                             | `EVP_CIPHER_CTX_free` on every path; the partial output is erased on a failure          |
| `envelope.c` | `envelope_keys`                                                                                    | `shared`, `keys`: the ECDH secret, the encryption key and the MAC key                                                   | the out label                                                                           |
| `envelope.c` | `envelope_hash`                                                                                    | `msg`: the pin secret and the entropy                                                                                   | before the return                                                                       |
| `envelope.c` | `envelope_request`                                                                                 | `enckey`, `mackey`, `hash`, `pt`: the two keys, the hash and the plaintext with the pin secret                          | the out label                                                                           |
| `envelope.c` | `envelope_response`                                                                                | `enckey`, `mackey`, `plain`: the two keys and the mask                                                                  | the out label                                                                           |
| `helper.c`   | `helper_run`                                                                                       | `extra`: one byte of the answer; the caller-owned answer                                                                | the out label; the answer is erased on each failure                                     |
| `scan.c`     | `scan_words`                                                                                       | `word`, `out`: one word and the line of 12                                                                              | the out label                                                                           |
| `scan.c`     | `scan_decode`                                                                                      | `code`, `data`, `image`: the cells, the payload and the frame of the plate                                              | before the return                                                                       |
| `scan.c`     | `scan_frames`                                                                                      | `line`, `frame`, `gray`: the 12 words and the two frames                                                                | the out label                                                                           |
| `qr.c`       | `qr_run`                                                                                           | `buf`, `digits`, the modules of the code: the input, the word indexes and the code                                      | the out label; the modules before `QRcode_free`                                         |
| `entry.c`    | `entry_totp`                                                                                       | `mac`: the HMAC of the TOTP key; the caller-owned code                                                                  | the out label; the code is erased on a failure                                          |
| `entry.c`    | `entry_slot_read`                                                                                  | the caller-owned candidate                                                                                              | erased on a failure                                                                     |
| `fugupass.c` | `fugupass_passphrase`                                                                              | the caller-owned passphrase                                                                                             | erased on each failure                                                                  |
| `fugupass.c` | `fugupass_passphrase_new`                                                                          | `again`: the second read                                                                                                | on every path                                                                           |
| `http.c`     | `http_post`, `http_data`                                                                           | `resp`, `b64`, `request`: the answer and the request, both ciphertext                                                   | the out label, although no secret                                                       |
| `oracle.c`   | `request_at`                                                                                       | `body`, `req`, `client`, `ckepriv`: the sealed answer, the sealed request, the client key and the ephemeral private key | the out label; the caller-owned mask is erased on a failure                             |
| `oracle.c`   | `request`                                                                                          | `salt`, `pin`: the pin salt and the pin secret                                                                          | the out label                                                                           |
| `oracle.c`   | `oracle_enroll`                                                                                    | `entropy`, `mask`, `wrapkey`, `wrap`: the entropy, the mask, the wrap key and the share                                 | the out label                                                                           |
| `oracle.c`   | `oracle_reveal`                                                                                    | `mask`, `wrapkey`, `wrap`: the mask, the wrap key and the wrapped share                                                 | the out label; the caller-owned share is erased on a failure                            |
| `oracle.c`   | `canary`                                                                                           | `entropy`, `mask`, `round`, `sealkey`, `wrapkey`, `wrap`: the two masks, the two keys and the share                     | the out label                                                                           |
| `oracle.c`   | `oracle_canary_check`                                                                              | `mask`, `sealkey`, `wrapkey`, `wrap`: the mask, the two keys and the share                                              | the out label                                                                           |
| `oracle.c`   | `oracle_revoke`                                                                                    | `entropy`, `pin`, `mask`: the random pin secret and the answer                                                          | the out label                                                                           |
| `vault.c`    | `vault_scan`                                                                                       | `value`: one value, which can be a secret field                                                                         | the out label                                                                           |
| `vault.c`    | `vault_seal_read`                                                                                  | the caller-owned buffer: the sealed file and its plaintext                                                              | the whole buffer on every path                                                          |
| `ceremony.c` | `ceremony_create`, `ceremony_refill`, `ceremony_provision`, `ceremony_retire`, `ceremony_verify`   | the state: the master, `root`, the device factor, `K_idx`, the passphrase and the index plaintext                       | the one out label of each ceremony erases the state and its heap buffers                |
| `ceremony.c` | `step_slot`                                                                                        | `key`, `password`, `mnemonic`, `plain`: `K_e` and the two candidates                                                    | the out label                                                                           |
| `ceremony.c` | `step_index`                                                                                       | `plain`: the index text of the new vault                                                                                | the out label, after finding M1                                                         |
| `ceremony.c` | `refill_factor`                                                                                    | `buf`: the device factor from disk                                                                                      | the out label                                                                           |
| `ceremony.c` | `refill_canaries`, `provision_canaries`                                                            | `share`: one share of `K_idx`                                                                                           | after the loop                                                                          |
| `ceremony.c` | `provision_slot`                                                                                   | `key`: `K_e`                                                                                                            | the out label                                                                           |
| `recover.c`  | `scan_plate`                                                                                       | `master`: the 12 words from the helper                                                                                  | the out label                                                                           |
| `recover.c`  | `index_open`                                                                                       | `idxkey`, `plain`: `K_idx` and the index plaintext                                                                      | on the success path and on the failure path                                             |
| `recover.c`  | `recover_vault`                                                                                    | `key`, `plain`, `idx`: `K_e`, the entry plaintext and the index plaintext                                               | the out label                                                                           |
| `recover.c`  | `recover_plate`                                                                                    | `pwd`, `mnemonic`: the two candidates                                                                                   | the out label                                                                           |
| `recover.c`  | `recover_run`                                                                                      | `root`                                                                                                                  | before the return                                                                       |
| `recover.c`  | `idx_find_line`, `emit_entry`                                                                      | `buf`, `find`: one entry line of the index, and the name and the type of the entry                                      | the out label, after finding M2                                                         |
| `change.c`   | `state_free`                                                                                       | the state: the device factor, the old and the new passphrase, `K_idx`, the raw file and the plaintext                   | before the free, on every path of the two ceremonies                                    |
| `change.c`   | `read_twice`                                                                                       | `again`: the second read                                                                                                | the out label                                                                           |
| `change.c`   | `verify`, `reconstruct`                                                                            | `shares`: the shares of `K_idx` or of `K_e`                                                                             | the out label; the caller-owned key is erased on a failure                              |
| `change.c`   | `slot_change`                                                                                      | `key`: `K_e`                                                                                                            | the out label                                                                           |
| `revoke.c`   | `kit_close`                                                                                        | the kit: the device factor and `root`                                                                                   | before the free, on every path                                                          |
| `revoke.c`   | `kit_factor`                                                                                       | `buf`: the device factor from disk                                                                                      | the out label                                                                           |
| `revoke.c`   | `kit_index`                                                                                        | `idxkey`, `plain`: `K_idx` and the index plaintext                                                                      | on every path                                                                           |
| `revoke.c`   | `kit_plate`                                                                                        | `master`: the 12 words                                                                                                  | the out label                                                                           |
| `revoke.c`   | `kit_name`                                                                                         | `client`: the client key                                                                                                | the out label                                                                           |
| `session.c`  | `session_close`, `session_drop`                                                                    | the session: the device factor, the passphrase, `K_idx`, `K_e`, the raw file, the plaintext and the index text          | before the free; `session_drop` erases `K_e` after each use (SEC-MEMORY-6)              |
| `session.c`  | `heal`, `substitute`                                                                               | `share`: one share of `K_idx`                                                                                           | the out label                                                                           |
| `session.c`  | `unlock`                                                                                           | `shares`: the shares of the quorum                                                                                      | the out label                                                                           |
| `session.c`  | `reveal`                                                                                           | `shares`, `key`: the shares and `K_e`                                                                                   | the out label                                                                           |
| `session.c`  | `session_canary`                                                                                   | `again`: the second read                                                                                                | the out label                                                                           |
| `commands.c` | `commands_qr`                                                                                      | `code`: the rendered code of a mnemonic                                                                                 | on every path                                                                           |
| `commands.c` | `create`                                                                                           | `pass`, `candidate`, `body`: the secret of an add, the candidate and the entry plaintext                                | the out label                                                                           |
| `commands.c` | `cmd_totp`                                                                                         | `t.key`, `key`, `code`: the TOTP key in two forms and the code                                                          | the out label                                                                           |

### The comparisons

| Source       | Function                  | Operands                                                                        | Call                                    |
| ------------ | ------------------------- | ------------------------------------------------------------------------------- | --------------------------------------- |
| `derive.c`   | `master_sum`              | the checksum nibble and the last bits of the master                             | `timingsafe_bcmp`                       |
| `wordlist.c` | `wordlist_index`          | the word of the caller and each word of the list, in one scan of the whole list | `timingsafe_bcmp`                       |
| `envelope.c` | `envelope_open`           | the computed tag and the tag of the envelope                                    | `timingsafe_bcmp`                       |
| `fugupass.c` | `fugupass_passphrase_new` | the two reads of a new passphrase                                               | `timingsafe_bcmp`, after a length test  |
| `change.c`   | `read_twice`              | the two reads of a passphrase                                                   | `timingsafe_bcmp`, after a length test  |
| `session.c`  | `session_canary`          | the second read and the passphrase of the session                               | `timingsafe_bcmp`, after a length test  |
| `oracle.c`   | `canary`                  | the two reads of the passphrase                                                 | `timingsafe_bcmp`, after a length test  |
| `oracle.c`   | `canary`                  | the second mask and the first                                                   | `timingsafe_bcmp`                       |
| `oracle.c`   | `oracle_canary_check`     | the opened check value and 32 zero bytes                                        | `timingsafe_bcmp`                       |
| `ceremony.c` | `verify_check`            | the derived plate check and the line of the config                              | `timingsafe_bcmp`                       |
| `seal.c`     | `seal_open`               | the Poly1305 tag of the sealed file                                             | inside `EVP_AEAD_CTX_open` of libcrypto |

Every other `memcmp`, `strcmp`, `strncmp` and `strncasecmp` call of `src/`
compares a public value. Such a value is a field name, a command or option name,
a header name, a URL, or a record name. It can also be a machine name, an oracle
public key, or the file name `H(K_e)` of an entry. A length test before
`timingsafe_bcmp(3)` shows the equality of two lengths alone, and the call takes
one length.

Four parsers branch on bytes of a secret: the scan of the master line in
`derive_master_check`, and the digit gate of `scan_words`. The tokenizer of
`mnemonic_digits` and the hex gate of `hex_ok` are the other two. Each one is a
parse, and none compares a secret with a reference value. The length of each
word reaches the timing through them, as it does through the `strlcpy(3)` of a
word. SEC-MEMORY-2 names the comparison alone.

## The findings

S1. The `flock` promise. No call of the code locks a file: no `flock(2)`, no
lock of `fcntl(2)`, and no `O_EXLOCK` or `O_SHLOCK`. The promise of PROG-SPLIT-3
stands unused in every run. It stands: the rule names the promise, and a change
of the rule is a change of PROG-SPLIT, which plan 014 does not cite.

S2. The interpreter path. The unveil list holds `fugupass-repl` with `rx`, and
not `/usr/bin/perl`. The exec of the script passed. `check_exec()` of
`sys/kern/kern_exec.c` sets `BYPASSUNVEIL` on the lookup of the interpreter of a
script (`EXEC_INDIR`). The kernel therefore takes no unveil rule for that path.
It stands: the list of PROG-SPLIT-3 is complete, and the run proves the platform
behavior.

S3. The scan helper after the open. The guest holds no camera, so no run shows a
syscall of the helper after its pledge call. It stands on
`src/regress/sandbox.c` and `src/regress/scan.c`, as the section of the helper
states. A run on a machine with a camera can close it.

M1. The index text of a new vault. `step_index` of `ceremony.c` composed the
index plaintext of `create` on the stack, and it returned without an erasure on
every path. The comment of `index_read` and `ceremony.h` name the index
plaintext a secret that leaves memory (SEC-MEMORY-1). Fixed:
`fix(ceremony): erase the index text of a new vault`. No test of the repository
observes a stack buffer after the return. The guest build and the C regress pass
with the change.

M2. The index copies of the recovery. `idx_find_line` of `recover.c` copied one
entry line of the index to the stack, and `emit_entry` kept the entry name and
the type. Neither erased the copy. The header of `recover.c` states that the
index plaintext leaves memory on every path. Fixed:
`fix(recover): erase the index copies of the recovery`. The proof is the same as
M1.

M3. The word copy of a failed `wordlist_word()`. `wordlist.h` states that a
failed call writes nothing to an output. `strlcpy(3)` copied the head of the
word into a buffer that was too small, and the call returned -1 after it. Each
caller of the repository gives `WORDLIST_MAX + 1` bytes, so no run reached the
path. Fixed: `fix(wordlist): gate the word length before the copy`.
`test_wordlist` of `src/regress/kat.c` gives a buffer of three bytes, and it
proves that no byte of the word enters it. The build of the previous
`wordlist.c` fails that test with
`the word list: a small buffer takes a part of a word`.

M4. The words in the stdio buffer of the scan helper. `scan_frames` wrote the 12
words with `fputs(3)` and `fflush(3)`, and it erased its line. The buffer of the
stream kept a copy of the master until the exit. Fixed:
`fix(scan): write the words with no stdio copy`. `main()` of `fugupass-scan.c`
makes the standard output unbuffered, and `fvwrite` of libc then writes from the
buffer of the caller. The guest build and the C regress pass with the change,
and no test observes a stream buffer.

M5. The input and the render in the stdio buffers of the render helper. `qr_run`
reads its input with `fread(3)` and writes the code with `fputs(3)`, and the two
stream buffers keep a copy until the exit. It stands. An unbuffered input costs
one `read(2)` per byte, and a caller-owned stream buffer adds two static buffers
and their erasure. The header of `qr.c` documents the copy of the 48 digits in
`QRinput_free()` of libqrencode with the same reason. The helper runs for one
render, it holds no key, and the two core limits are zero (SEC-MEMORY-3).

M6. The mask output of a failed `oracle_reveal()`. The function writes the mask
into the caller-owned `maskout` before its last checks, and it erases the share
output alone on a failure. `oracle.h` gives the erasure of `maskout` to the
caller. It stands: `session.c` and `change.c` pass a null pointer, and the one
caller with a buffer is the test driver `src/regress/oracle-client.c`.

M7. The device factor in the raw buffer of a failed read. `factor_read` of
`change.c` and of `session.c` reads the factor file into the raw buffer of the
state. It erases those bytes on the success path alone. It stands: `state_free`
and `session_close` erase the raw buffer before the free on every path, so the
bytes leave memory with the state.

M8. The gate of `session_seal()`. A null plaintext or a wrong length returns
before `session_drop()`, with `K_e` in the session. It stands: the one caller,
`create` of `commands.c`, calls `session_drop()` on every path, and
`session_close` erases the session.

M9. The HMAC output of `hmac_evp()`. The function erases its output on a length
mismatch, and not on a null return of `HMAC()`. It stands: each caller owns the
buffer and erases it.

M10. The library copies. `BN_CTX_free`, `EVP_AEAD_CTX_free` and
`EVP_CIPHER_CTX_free` of LibreSSL release the key material through
`freezero(3)`. `QRinput_free()` of libqrencode and `quirc_destroy()` release the
digits and the grids without an erasure, and `qr.c` and `scan.h` document that.
It stands: the rule binds the buffers that the code owns, and each helper exits
after one run.

## The verdict

The four programs hold to the promises and the unveil list of PROG-SPLIT, with
the one limit of S3. After the fixes of M1 to M4, every secret buffer that the
code owns leaves memory on each exit path. Every secret comparison uses
`timingsafe_bcmp(3)`. The one open path of SEC-MEMORY-1 is the one of the
register. A terminating signal ends the core process with no erasure. The two
zero core limits keep the secret off the disk (SEC-MEMORY-3).
