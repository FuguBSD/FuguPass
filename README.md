# FuguPass

A password manager for any secret, built on proven seed-phrase standards and
air-gapped custody patterns.

FuguPass derives every vault key from one master: a BIP39 mnemonic of 12 words
on a SeedQR plate. No key material leaves the device.

It seals every entry as one flat ciphertext file. Per-entry records at an
ordered set of blind PIN oracles gate each reveal: the passphrase plus any k of
the n oracle masks open one entry.

The wire protocol is version 2 of the Blockstream `blind_pin_server` protocol.
[FuguOracle](https://github.com/FuguBSD/FuguOracle) is the reference oracle
deployment.

## Documentation

The project is specification-first: the specification in [spec/](spec/index.md)
is the authoritative reference. Research notes live in `docs/research/`.

## Commands

```sh
make check       # spec-check + ste-lint + test
make spec-check  # validate the specification and the plans
```

`make check` runs the Markdown format gate, and prettier runs through bunx. The
operator installs bun, for example from Homebrew. No deps manifest provides it.

## Commit scopes

`spec`, `docs`, `ci`.

## License

ISC. See [LICENSE](LICENSE).
