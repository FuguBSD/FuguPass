# The source evaluation of the QR libraries

|         |                                                                         |
| ------- | ----------------------------------------------------------------------- |
| Status  | Record. It holds the source evaluation of PROG-QR-5.                    |
| Covers  | The QR decoder of `fugupass-scan`, and the QR encoder of `fugupass-qr`. |
| Decides | Nothing. D-15 decides, and this record states the reason of each pick.  |

## The question

D-15 puts the camera code and the QR codecs in two sandboxed helper programs.
That decision names no library. `fugupass-scan` needs a decoder (PROG-SCAN-1),
and `fugupass-qr` needs an encoder (PROG-QR-1). PROG-QR-5 asks the documentation
for the record of each library, with the provenance of it and the license of it.
This record holds the candidates and the reason of each pick. The manual page of
each helper holds the record of the library that the program links.

FuguPass runs on an air-gapped machine (PROG-PORT). A package of the ports tree
costs the run dependencies of it as well, and each dependency reaches that
machine. A dependency that pulls a window system onto a signing machine is
expensive.

The developer measured each command below in the OpenBSD 7.8 guest on arm64, on
2026-09-22. The packages come from `cdn.openbsd.org`.

## The decoder

| Candidate         | License  | Provenance                                              | Outcome                         |
| ----------------- | -------- | ------------------------------------------------------- | ------------------------------- |
| quirc             | ISC      | `github.com/dlbeer/quirc`, tag `v1.2`; `libquirc-1.0p0` | The pick. `src/quirc` holds it. |
| zbar              | LGPL 2.1 | the package `zbar-0.23.93p1`                            | Rejected                        |
| A decoder in tree | ISC      | this repository                                         | Rejected                        |

### quirc

quirc is a QR decoder in C, and Daniel Beer holds the copyright of it. It
carries the ISC license, the license of this repository (D-16). The library
takes one grey byte of each pixel. It gives the version, the mode and the
payload of each code that it reads, and the gate of D-22 reads those three
fields. The library calls the standard C functions alone.

The ports tree holds `graphics/libquirc`, and that package is unusable on a
machine with the base sets alone. The report of `pkg_add -I -n -v libquirc`
holds the three lines below, among others.

```
Can't install sdl-1.2.15p12 because of libraries
|library X11.19.0 not found
Can't install libquirc-1.0p0: can't resolve sdl-gfx-2.0.25p1
```

The package declares `sdl-gfx` as a run dependency. `sdl-gfx` declares `sdl`,
and `sdl` needs the X11 shared libraries. The demonstration programs of the
release need those libraries, and the library itself needs none of them. A port
dependency therefore pulls SDL and X11 onto an air-gapped machine.

`src/quirc` holds the six source files of the release `v1.2` and the license
file of it, byte for byte. `src/quirc/SOURCE.md` records the origin, the
release, the license and the SHA-256 of each file. `quirc_version()` of that
release gives the string `1.0`, and that string is stale upstream.

### zbar

zbar is a bar code reader with a QR decoder in it. It carries the GNU Lesser
General Public License, version 2.1, and that license falls outside the ISC line
of D-16. The package is `zbar-0.23.93p1`, and `pkg_add -n zbar` reports the line
below.

```
Can't install zbar-0.23.93p1: can't resolve gtk+3-3.24.51,ImageMagick-6.9.13.26p0
```

The package declares a window toolkit and an image suite as run dependencies.
The last line of that run names 15 packages that it cannot install, and the
dependency trees of it name a Python interpreter as well. The decoder of
FuguPass reads one grey frame, so that cost buys nothing.

### A decoder in this repository

D-15 takes an in-tree implementation for the share arithmetic, under two
conditions: the specification states the full arithmetic, and vectors of an
independent reference pin the outputs. A QR decoder is another size of work. It
must find each code of a photograph, it must correct the perspective of the
image, and it must run the Reed-Solomon correction of the payload. quirc carries
the license that this repository takes, so the tree needs no decoder of its own.

### The pick of the decoder

quirc is the pick, and `src/quirc` holds the copy (PROG-BUILD-5). The copy costs
one manual step at each release of the library, and it keeps SDL and X11 off the
signing machine. The directory builds `libfuguquirc.a`, so no link line can take
the `libquirc.a` of the package by mistake.

## The encoder

| Item           | Value                                           |
| -------------- | ----------------------------------------------- |
| Library        | libqrencode, by Kentaro Fukuchi                 |
| Package        | `libqrencode-4.1.1` of OpenBSD 7.8              |
| Port path      | `graphics/libqrencode`                          |
| License        | GNU Lesser General Public License, 2.1 or later |
| Run dependency | `graphics/png`, as `png-1.6.50`                 |

`pkg_add -I libqrencode` installs the package in the guest, and
`pkg_info -f libqrencode` gives the port path and the run dependency. The
package carries the shared library, the static library, the header, the
`qrencode(1)` program and the manual page of that program. `fugupass-qr` links
the shared library, and it runs no program of the package.

The header `/usr/local/include/qrencode.h` of the package states the license.
Kentaro Fukuchi holds the copyright, from 2006 to 2017. The license of the
library is the LGPL, and the license of this repository is ISC. This repository
holds no source of the library, and the port declares the package as a library
dependency (PROG-PORT-3).

The encoder stays a package, and the decoder does not. The cost decides: this
package declares one run dependency, and `png` needs no window system. The
machine of PROG-PORT therefore takes the encoder from the ports tree.

### The mask pattern

`libqrencode` picks the mask pattern of a code by penalty score. It picked
pattern 5 for the digits of test vector 4, and PROG-QR-6 asks for pattern 0.
`src/qr.c` therefore re-masks a mnemonic code, and it writes the format bits of
level L and mask 0. FuguSeed pins the same pattern, so one scanner reads the
code of each project.

### The residue of the input

`fugupass-qr` writes the 48 digits of a mnemonic into a `QRinput` structure.
`QRinput_free()` releases that buffer with `free(3)`, and it erases no byte of
it. `nm(1)` on `/usr/local/lib/libqrencode.a` of the package names no
`explicit_bzero` symbol, so the library holds no erasure call that a compiler
must keep. The digits of a mnemonic stay in the freed heap of the helper
process, and FuguPass cannot reach that memory.

Four properties bound that residue. The helper renders one code, and it then
exits. Its core limit is zero, so a crash of it writes no core file
(SEC-MEMORY-3). OpenBSD encrypts swap by default. `qr_run()` erases each buffer
that this tree owns, and the module bytes of `QRcode.data` are one of them
(SEC-MEMORY-1).

The decoder carries the same shape of residue. `quirc` frees the grids and the
capstones of one frame without an erasure, and `src/scan.h` records that fact.
