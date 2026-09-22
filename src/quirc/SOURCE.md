# The vendored QR decoder

This directory holds `quirc`, the QR decoder of `fugupass-scan`
([PROG-SCAN](../../spec/programs.md#prog-scan),
[PROG-BUILD](../../spec/programs.md#prog-build)). The six files below are the
`lib/` directory of the release, byte for byte. `LICENSE` is the license file of
the same release.

Do not edit a file of this directory that the table below pins. `Makefile` and
this record are files of this repository, and the table holds no row of them. To
move to another release, replace each pinned file and write the new digests
here.

## The copy

| Item    | Value                                       |
| ------- | ------------------------------------------- |
| Library | quirc, by Daniel Beer                       |
| Release | v1.2                                        |
| Origin  | <https://github.com/dlbeer/quirc>           |
| License | ISC                                         |
| Source  | `lib/` and `LICENSE` of the release tarball |

| File               | SHA-256                                                            |
| ------------------ | ------------------------------------------------------------------ |
| `quirc.h`          | `49660ea710add2d6f304a1323f53190f5a2bf34db4dd160d633db0c3f22bfba5` |
| `quirc_internal.h` | `e383ed1a0ca70c07b0530d76bfeb6bd5525efda182589f48c978921a9e54676b` |
| `quirc.c`          | `0294b6c56f8c021b256c4c153d70483368164c6cf0cce643e1b6be03ed3585c0` |
| `identify.c`       | `c36e93edfbc92a795f3edc9ec42d9e89e4d00aa376a88d48cc2e8118542a5372` |
| `decode.c`         | `d4468c55ecd0d2f905a6813513708005e6d609ef0a3d32a17673313c7552a7c1` |
| `version_db.c`     | `6764aa2f245085080e1e5cefd9dcd59b9727718a0d4606956e0502a57f5dff30` |
| `LICENSE`          | `a70ef3ea032998eead2e2c7573a170a809eae08e3ca134611f707eda5932c8a9` |

To check the copy, run:

```sh
sha256 src/quirc/*.c src/quirc/*.h src/quirc/LICENSE
```

`quirc_version()` of the release gives the string `1.0`. That string is stale
upstream, and the tag of the source is `v1.2`.

## Why the tree holds a copy

[qr-library-sources.md](../../docs/analysis/qr-library-sources.md) holds the
evaluation of each QR library, and it gives the reason of this copy. The port of
FuguPass declares no dependency for the decoder
([PROG-PORT](../../spec/programs.md#prog-port)).

## The build

`Makefile` of this directory builds `libfuguquirc.a`, and `src/fugupass-scan`
and `src/regress` link that archive. The name differs from the `libquirc.a` of
the package, so a link line that reads `LOCALBASE` can never take the wrong
file.
