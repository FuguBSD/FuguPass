# FuguPass

A password manager for any secret, built on proven seed-phrase standards and
air-gapped custody patterns.

FuguPass derives every vault key from one master: a BIP39 mnemonic of 12 words
on a SeedQR plate. It seals every entry as one flat ciphertext file. Per-entry
records at an ordered set of blind PIN oracles gate each reveal: the passphrase
plus any k of the n oracle masks open one entry. No key material leaves the
device.

The wire protocol is version 2 of the Blockstream `blind_pin_server` protocol.
[FuguOracle](https://github.com/FuguBSD/FuguOracle) is the reference oracle
deployment.

The project is specification-first: the code follows the specification.

## Documentation

The specification in [spec/](spec/index.md) is the authoritative reference. Read
[spec/DECISIONS.md](spec/DECISIONS.md) before you make a plan. Research notes
live in `docs/research/`.

## Commands

```sh
make check       # spec-check + ste-lint + test
make spec-check  # validate the specification and the plans
make format-md   # Markdown formatting check
```

## Commit scopes

`spec`, `docs`, `ci`.

## License

ISC. See [LICENSE](LICENSE).
