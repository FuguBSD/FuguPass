# The round-count calibration of bcrypt_pbkdf(3)

|         |                                                                  |
| ------- | ---------------------------------------------------------------- |
| Status  | Record. It holds the calibration of TEST-CALIBRATE-2.            |
| Covers  | The default round count of `bcrypt_pbkdf(3)` (KEY-PIN-5, D-09).  |
| Decides | Nothing. The operator picks the default from the hardware table. |

## The question

`bcrypt_pbkdf(3)` derives each pin secret from the passphrase and one salt
(KEY-PIN-3). The round count sets the cost of one call. A session pays that cost
once per canary record of the quorum at the unlock, and `k` times per revealed
entry (KEY-PIN). An attacker with the disk and one breached oracle record pays
the same cost per guess (SEC-FLOOR-2). This record holds the method, the
measurements, the assumed attack hardware and the chosen default
(TEST-CALIBRATE-1, TEST-CALIBRATE-2).

## The method

`tests/calibrate.c` is the timer. It calls `bcrypt_pbkdf(3)` of libutil with a
public passphrase, a 32-byte salt and a 32-byte output, the shape of KEY-PIN-3.
It runs each count of a fixed table five times. It prints the count and the
median wall time of the five runs in milliseconds, one line per count.
`clock_gettime(2)` with `CLOCK_MONOTONIC` gives the time of each run. The table
holds 16 rounds, the count of the interop harness, and the counts around it from
1 round to 640 rounds.

The median holds against one slow run. The timer measures the wall time, so a
loaded machine gives a high value. Run it on an idle machine. `src/Makefile`
does not build the timer, and no gate runs it (PROG-BUILD). The section of the
hardware table below holds the build line and the run line.

## The attack hardware

The assumed attack hardware is one consumer GPU, an NVIDIA GeForce RTX 4090,
with hashcat. The public hashcat 6.2.6 benchmark of that card (Chick3nman,
October 2022) reports about 184 kH/s for bcrypt at cost 5. Cost 5 is 32
iterations of the bcrypt key schedule. One round of `bcrypt_pbkdf(3)` runs that
key schedule 64 times, and then 64 encryptions of the 32-byte block. One round
therefore costs about one bcrypt hash at cost 6, and one card runs about 92,000
rounds per second.

At `R` rounds, one card tests about `92000 / R` passphrase guesses per second.
At 16 rounds that is about 5,800 guesses per second, and at 128 rounds
about 720. The developer ran no benchmark, so the rate of this record is a
stated estimate and no measurement.

## The guest table

The table below comes from the test guest: OpenBSD 7.8 arm64 under HVF, two
virtual CPUs, on an Apple M2 Pro host. The run of 2026-09-26 is a virtualized
shape check of the curve, and it is not the measurement of TEST-CALIBRATE-4.

| Rounds | Milliseconds |
| ------ | ------------ |
| 1      | 3.2          |
| 2      | 6.4          |
| 4      | 13.6         |
| 8      | 27.6         |
| 12     | 40.5         |
| 16     | 51.5         |
| 24     | 77.3         |
| 32     | 103.0        |
| 48     | 154.3        |
| 64     | 213.3        |
| 96     | 319.9        |
| 128    | 427.3        |
| 192    | 619.3        |
| 256    | 856.2        |
| 384    | 1286.5       |
| 512    | 1647.5       |
| 640    | 2123.8       |

The cost grows in a straight line with the count, at about 3.3 milliseconds per
round in the guest. The count of 640 rounds passes two seconds, so the table
ends there.

## The hardware table

The operator fills the table below on the laptop, on real OpenBSD hardware
(TEST-CALIBRATE-4). Run the two commands below on that laptop, from the
repository root. Copy each output line into the table, and fill the three fields
above it.

```sh
cc -Wall -Wextra -Werror -o calibrate tests/calibrate.c -lutil
./calibrate
```

| Field           | Value |
| --------------- | ----- |
| Machine         | open  |
| OpenBSD release | open  |
| Date            | open  |

| Rounds | Milliseconds |
| ------ | ------------ |
| 1      |              |
| 2      |              |
| 4      |              |
| 8      |              |
| 12     |              |
| 16     |              |
| 24     |              |
| 32     |              |
| 48     |              |
| 64     |              |
| 96     |              |
| 128    |              |
| 192    |              |
| 256    |              |
| 384    |              |
| 512    |              |
| 640    |              |

## The default

The default round count is open: it is the choice of the operator from the
hardware table (TEST-CALIBRATE-2). `fugupass create` and `fugupass provision`
take the count from `-r`, and the config file records it (KEY-PIN-5). No source
file holds a default today, and the interop harness runs at 16 rounds as a test
value. The chosen value enters the code after the hardware run.

## The trade-off

Each unlock computes `k` pin secrets, one per canary record of the quorum, and
each reveal computes `k` more (KEY-PIN). With the 2-of-3 topology of D-20 and
128 rounds, one reveal costs about 0.9 seconds in the guest. One card then tests
about 720 guesses per second, or about 62 million guesses per day. A passphrase
of 40 bits then holds about 50 years against one card, and one of 20 bits falls
in half an hour. A higher count multiplies both sides by the same factor, so the
passphrase quality is the floor (D-09).
