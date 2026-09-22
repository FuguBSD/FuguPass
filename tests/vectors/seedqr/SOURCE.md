# The SeedQR fixtures

`vector4.picture` is test vector 4 of the SeedQR specification. It is the one
public reference image of the handoff between FuguSeed and FuguPass. FuguSeed
draws the code, and FuguPass renders the same modules
([PROG-QR](../../../spec/programs.md#prog-qr), D-22). `src/regress/scan.c` reads
the same picture, so the scan helper decodes what the render helper draws
([PROG-SCAN](../../../spec/programs.md#prog-scan)).

The three other pictures are the negative fixtures of the scan helper. Each one
is a QR code that a decoder reads, and each one fails one gate of D-22.

A picture holds the modules of one code and no quiet zone. A `#` is a dark
module, and a `.` is a light module. `src/regress/qr.c` and `src/regress/scan.c`
each add the 4 light modules of every side.

## The copy

| Item    | Value                                                              |
| ------- | ------------------------------------------------------------------ |
| Source  | FuguSeed `t/fuguseed/fixtures/qr/vector4.picture`                  |
| Commit  | `18b2bfc`                                                          |
| SHA-256 | `6753c34ec4e0029578a9e1d5afe652d3af97f1a32559b4208f904ff513f48d1a` |
| Size    | 25 rows of 25 characters, and one line feed after each row         |

The copy is byte for byte the file of that commit. Do not regenerate this file.
To check the copy, run:

```sh
sha256 tests/vectors/seedqr/vector4.picture
```

## The mnemonic

The picture encodes 48 digits in QR numeric mode, at version 2, level L, and
mask pattern 0. The digits are the zero-based BIP39 indexes of the 12 words,
each index in four digits:

```text
073318950739065415961602009907670428187212261116
forum undo fragile fade shy sign arrest garment culture tube off merit
```

Both values come from the `%VECTOR` table of FuguSeed `t/fuguseed/qr.t`, entry
`4`. That table states the words and the digits that the SeedQR specification
prints for this vector.

## The negative fixtures

Each picture below decodes as a QR code, and each one fails one gate of
`fugupass-scan` (D-22, [TEST-KAT](../../../spec/testing.md#test-kat)). A fixture
that failed to decode would prove nothing, so `src/regress/scan.c` reads the
cause of each failure and not the failure alone.

| File               | The code                                    | The cause                               |
| ------------------ | ------------------------------------------- | --------------------------------------- |
| `compact.picture`  | Version 1, level L, byte mode, 16 bytes     | The mode is not numeric (PROG-SCAN-3)   |
| `words24.picture`  | Version 3, level L, numeric mode, 96 digits | The digits are not 48 (PROG-SCAN-2)     |
| `overflow.picture` | Version 2, level L, numeric mode, 48 digits | Four digits name no word (PROG-SCAN-10) |

| File               | SHA-256                                                            |
| ------------------ | ------------------------------------------------------------------ |
| `compact.picture`  | `6e06b070322e51777f750134ae5b2fbd30cd904c2bb0e979a09d12063ebf162f` |
| `words24.picture`  | `f31d38e21d91d93bfa2a6810c9c7b2d6cf49bb3ad12bc83daf26ba06e1cd62b3` |
| `overflow.picture` | `766707ddafa02095bb3cfec7f9d7de0c150175641ab210d7271febe45b234467` |

`compact.picture` is the Compact SeedQR of test vector 4. It holds the 16
entropy bytes of the same 12 words, in QR byte mode:

```text
5bbd9d71a8ec7990831aff359d426545
```

`words24.picture` is the Standard SeedQR of the 24 words `abandon` 23 times and
`art`. The BIP39 specification prints that mnemonic as the first 24-word test
vector, and its 96 digits are 23 groups of `0000` and one group of `0103`.

`overflow.picture` holds the 48 digits of test vector 4 with the last group
changed to `9999`. The BIP39 English list holds 2048 words, so no word carries
that index.

`libqrencode` of the ports tree drew the three pictures. To draw one again, feed
the payload above to that library at the version and the level of the table, and
print one character for each module.
