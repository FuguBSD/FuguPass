# The scaling check of the flat-file oracle

|         |                                                                                   |
| ------- | --------------------------------------------------------------------------------- |
| Status  | Record. It holds the scaling check of TEST-CALIBRATE-3.                           |
| Covers  | The load of FuguPass against the workload posture (ORC-RECORDS-4).                |
| Decides | Nothing. FuguOracle D-04 states the posture, and this record measures against it. |

## The question

FuguPass enrolls one record per slot at each oracle, on each machine, and one
canary per machine (ORC-RECORDS-1, ORC-RECORDS-2). A ceremony therefore sends
one `set_pin` request per record, and a session sends `k` `get_pin` requests per
revealed entry (ORC-RECORDS-4). FuguOracle D-04 states a workload of a few
requests per day. This record measures the enrollment load of hundreds of
records at one FuguOracle instance, and it compares the numbers against that
posture (TEST-CALIBRATE-3).

## The setup

The instance is the `fuguoracle-0.1.1` package, built in the FuguOracle guest on
2026-09-26. It runs in the FuguPass guest: OpenBSD 7.8 arm64 under HVF, two
virtual CPUs, on an Apple M2 Pro host. The bring-up follows the pkg-readme. It
makes the static key with `fuguoracle-keygen`, adds one server block of
`httpd(8)`, and starts the two services under `rcctl(8)`. The block listens on
the loopback port 8080 without TLS, as the upstream counterparty of the harness
does. The `fuguoracle` entry of `tests/harness` holds that recipe.

The leg `tests/harness.d/18-scale.pl` runs the check. The first machine creates
a vault with a pool of 100 slots at that one instance. Each of two more machines
takes a copy of the shared set and runs the provisioning ceremony. Each ceremony
enrolls 101 records: one per slot, and the canary. The round count of the
harness is 16. The clock of the guest console gives the seconds of each
ceremony. The store of the instance gives the records and the disk use.

The first run of the leg found a defect of the client reader. `httpd(8)` sends
the answer of the CGI program in the chunked transfer coding, and the reader
took the size line as the body. Every request to the instance failed as a
transport failure. The reader now removes that coding (ORC-CONFORM-6), and
`src/regress/http.t` proves the decode.

## The numbers

The run of 2026-09-26, with `harness exit: 0`:

| Ceremony  | Machine        | Requests | Seconds | Seconds per request | Requests per second |
| --------- | -------------- | -------- | ------- | ------------------- | ------------------- |
| create    | create-scale   | 101      | 8.2     | 0.08                | 12.38               |
| provision | create-scale-2 | 101      | 8.0     | 0.08                | 12.63               |
| provision | create-scale-3 | 101      | 8.0     | 0.08                | 12.66               |

The three ceremonies sent 303 requests in 24.1 seconds, and the store grew by
one record per request. The store holds 303 records in 632 kilobytes of disk. A
record file holds 129 bytes, and the file system rounds each file up to one
fragment of 2 kilobytes. Each request cost about 80 milliseconds. That time
holds the 16 KDF rounds of about 50 milliseconds in the guest, the envelope, one
CGI process, and the record write. The calibration record gives the KDF time.

## The posture

FuguOracle D-04 states a workload of a few requests per day, with one process
per request. One ceremony of 100 slots sends 101 `set_pin` requests in about 8
seconds. At three requests per day, that is the load of about one month. The
three machines sent the load of about 100 days in 24 seconds. The instance
answered every request with a `200`, and no request failed. The load is a
posture mismatch on a self-hosted oracle, not a correctness problem
(ORC-RECORDS). The numbers of this record go to FuguOracle D-04 as a decision
review. That review weighs the workload assumption against the measured load of
one client: about 12.5 requests per second in a guest.

## The enrolled set

The harness empties the store after the run (TEST-HARNESS-6). The leg copies the
store to `/home/fugupass/harness/vault/scale-store` before that. The snapshot
`enrolled` of the guest holds that copy, the three vault directories beside it,
and the package. A restore of the set copies `private.key` and `pins/` of the
copy back to `/var/www/fuguoracle`, under the owner `_fuguoracle`.

## What stays unproven

The guest is a virtual machine, and the numbers hold for its two virtual CPUs. A
physical oracle host runs the same CGI program at its own rate. The check
enrolls records, and it reveals none. The `get_pin` rate of a session is the
reveal count times `k`, and this record measures no session.
