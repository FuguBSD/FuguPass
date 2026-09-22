# FuguPass

A password manager for any secret, built on proven seed-phrase standards and
air-gapped custody patterns. FuguPass derives every vault key from one master: a
BIP39 mnemonic of 12 words on a SeedQR plate.

It seals every entry as one flat ciphertext file. Per-entry records at an
ordered set of blind PIN oracles gate each reveal. The passphrase plus any k of
the n oracle masks open one entry.
[FuguSeed](https://github.com/FuguBSD/FuguSeed) makes the master that FuguPass
reads. [FuguOracle](https://github.com/FuguBSD/FuguOracle) is the reference
deployment.

## Commands

```sh
make deps        # install signify, gitleaks and the Fugu library
make deps-test   # add the Perl lint and format modules
make check       # run every gate; run it before each commit
make test        # run the test suite
make harness     # run the interop harness against each counterparty
make format-fix  # fix the Markdown, JSON and YAML formatting
```
