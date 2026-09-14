# FuguPass

A password manager for any secret, built on proven seed-phrase standards and
air-gapped custody patterns. FuguPass derives every vault key from one master: a
BIP39 mnemonic of 12 words on a SeedQR plate. No key material leaves the
machine.

It seals every entry as one flat ciphertext file. Per-entry records at an
ordered set of blind PIN oracles gate each reveal. The passphrase plus any k of
the n oracle masks open one entry.
[FuguSeed](https://github.com/FuguBSD/FuguSeed) makes the master that FuguPass
reads. [FuguOracle](https://github.com/FuguBSD/FuguOracle) is the reference
oracle.

## Commands

```sh
make deps        # install gitleaks
make check       # run every gate; run it before each commit
make test        # run the test suite
make format-fix  # fix the Markdown, JSON and YAML formatting
```
