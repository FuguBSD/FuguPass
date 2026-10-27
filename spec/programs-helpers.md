# Helper programs

This document is a part of the [programs](programs.md) specification. It
specifies the scan helper `fugupass-scan` and the QR render helper
`fugupass-qr`.

<a id="prog-scan"></a>

## fugupass-scan

- **PROG-SCAN-1** — `fugupass-scan` must decode QR codes from camera frames and
  must write the decoded payload as text to stdout. The program must write no
  other data to stdout.
- **PROG-SCAN-2** — The program must decode the Standard SeedQR form. The form
  is the concatenation of the zero-based BIP39 wordlist indexes of the mnemonic.
  Each index is zero-padded to four decimal digits, in QR numeric mode. A
  12-word mnemonic is 48 digits. Every other digit count is a failure (D-22).
- **PROG-SCAN-3** — The program must not decode the Compact SeedQR form (D-22).
  A QR code in byte mode is a failure. The program computes no checksum. It
  emits the 12 words of the digit string, and the master gate checks them
  ([KEY-MASTER](keys.md#key-master)).
- **PROG-SCAN-4** — The codec follows the Standard SeedQR form of the SeedSigner
  SeedQR specification. Known-answer vectors pin it
  ([TEST-KAT](testing.md#test-kat)).
- **PROG-SCAN-5** — The program must emit a decoded mnemonic as the mnemonic
  words, on one line of text.
- **PROG-SCAN-6** — The program must apply the sandbox of
  [PROG-SPLIT](programs.md#prog-split).
- **PROG-SCAN-7** — A plate scan needs a video device on the machine. A machine
  with no video device cannot run a ceremony that scans the plate. A virtual
  machine needs host device passthrough for that device.
- **PROG-SCAN-8** — The program must take one optional argument, the path of the
  video device, and it must take no option. A run with no argument must read
  `/dev/video`. The core process runs the helper with no argument, so that path
  is the device of a ceremony.
- **PROG-SCAN-9** — The program must read frames through the `read(2)` access of
  `video(4)`. It must ask the device for frames of 640 by 480 pixels, in the
  `YUYV` pixel format. It must take the luminance byte of each pixel as the grey
  value of it. A device that gives another pixel format is a failure. The
  program must read frames for 60 seconds, and it must then report and exit 1.
  The core process reads the standard output of the helper to its end, so an
  endless read would hold a ceremony. `read(2)` on that driver takes no timeout,
  and `O_NONBLOCK` reaches no read of it. The program must therefore wait for
  each frame with `poll(2)` first. The wait must end at the bound of the scan,
  and `poll(2)` needs the `stdio` promise alone. `poll(2)` registers the read
  filter of `video(4)`, and that filter starts the read stream.
  `docs/analysis/video-read-stream.md` holds the kernel source of the stream
  start and of the blocking read. A device that gives no frame is one cause.
  Frames that hold no Standard SeedQR are another cause. The report must name
  the cause that ends the scan.
- **PROG-SCAN-10** — The BIP39 English list holds 2048 words, so a group of four
  digits above 2047 names no word. The program must report such a code as a
  failure.
- **PROG-SCAN-11** — A scan needs the `kern.video.record` variable of
  `sysctl(2)` at 1. The `video(4)` driver blanks the image data of every reader
  at the value 0, and 0 is the default of a machine. The superuser must set that
  variable before a scan.
- **PROG-SCAN-12** — The output line must hold one space between two words, and
  one line feed must end it. The line must hold no other byte.
- **PROG-SCAN-13** — Each failure must write one report line to the standard
  error, and that line must name the cause.

<a id="prog-qr"></a>

## fugupass-qr

- **PROG-QR-1** — `fugupass-qr` must read stdin and must render one QR code on
  the terminal, in UTF-8 half blocks.
- **PROG-QR-2** — The program must render a mnemonic export in the Standard
  SeedQR form only (D-22, [PROG-SCAN](programs-helpers.md#prog-scan)). This
  serves the signer scan flow ([ENTRY-TYPES](entries.md#entry-types)).
- **PROG-QR-3** — The program must render a vault file up to the one-code QR
  capacity as one QR code for the paper backup
  ([VAULT-BACKUP](vault.md#vault-backup)). It must report a file that exceeds
  the capacity.
- **PROG-QR-4** — The program must apply the sandbox of
  [PROG-SPLIT](programs.md#prog-split).
- **PROG-QR-5** — The documentation must record the chosen QR decode and render
  libraries, with their ports provenance and their licenses.
- **PROG-QR-6** — A mnemonic code must be version 2, level L, numeric mode, and
  mask pattern 0. FuguSeed pins that mask pattern, and the picture of test
  vector 4 holds it ([TEST-KAT](testing.md#test-kat)). A render library picks a
  mask pattern by penalty score, so the program must re-mask a mnemonic code.
  The program must read the mask number from the format bits of the library
  output. It must undo that pattern over each module of the encoding region, and
  it must apply pattern 0 there. It must then write the format bits
  `111011111000100` to both copies of that field.
- **PROG-QR-7** — The program must take the shape from the bytes on its standard
  input. An input of 12 words of the BIP39 English list is a mnemonic. One space
  stands between two words, and at most one line feed ends the input. Every
  other input is a vault file. The core process sends the words of a mnemonic
  entry and the bytes of a vault file on the same pipe
  ([PROG-OUTPUT](programs-commands.md#prog-output),
  [PROG-SPLIT](programs.md#prog-split)).
- **PROG-QR-8** — A vault-file code must be level L in byte mode, at the lowest
  version that takes the file. The one-code capacity is 2953 bytes, the byte
  capacity of version 40 at level L. The program must write the report of
  PROG-QR-3 to its standard error, and it must then write no code. The report
  must name that count, so the operator reads the bound from the tool.
- **PROG-QR-9** — The render must write one character for two module rows. A
  block half of a character is a light module, and a space half of it is a dark
  module. The render must use four characters. `U+2588` is two light modules.
  `U+2580` is a light module above a dark one. `U+2584` is a dark module above a
  light one. The space is two dark modules. One line feed must end each line.
  Each code must carry a quiet zone of 4 light modules on each side. An odd
  module count must take one more light module row at the end.

A vault file is ciphertext, so its paper QR is a safe backup object
([VAULT-BACKUP](vault.md#vault-backup)). A signer scans a mnemonic code from the
screen, and the terminal of the operator gives the light modules of it. The
scanners of the signer flow read that one form. The mask pattern and the quiet
zone of a mnemonic code are therefore fixed values.
