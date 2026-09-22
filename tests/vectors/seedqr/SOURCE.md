# The SeedQR fixture

`vector4.picture` is test vector 4 of the SeedQR specification. It is the one
public reference image of the handoff between FuguSeed and FuguPass. FuguSeed
draws the code, and FuguPass renders the same modules
([PROG-QR](../../../spec/programs.md#prog-qr), D-22).

## The copy

| Item    | Value                                                              |
| ------- | ------------------------------------------------------------------ |
| Source  | FuguSeed `t/fuguseed/fixtures/qr/vector4.picture`                  |
| Commit  | `18b2bfc`                                                          |
| SHA-256 | `6753c34ec4e0029578a9e1d5afe652d3af97f1a32559b4208f904ff513f48d1a` |
| Size    | 25 rows of 25 characters, and one line feed after each row         |

A `#` is a dark module, and a `.` is a light module. The copy is byte for byte
the file of that commit. Do not regenerate this file. To check the copy, run:

```sh
sha256 tests/vectors/seedqr/vector4.picture
```

The picture holds no quiet zone. `src/regress/qr.c` adds the 4 light modules of
each side and compares the inner 25 rows with this file.

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
