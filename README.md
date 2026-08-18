# FuguPass

A password manager for operators of air-gapped Bitcoin custody.

FuguPass derives every vault key from one master: a BIP39 mnemonic of 12 words
on a SeedQR plate. It seals every entry as one flat ciphertext file. Per-entry
records at an ordered set of blind PIN oracles gate each reveal: the passphrase
plus any k of the n oracle masks open one entry. No key material leaves the
device, and no network service holds a secret.

The wire protocol is version 2 of the Blockstream `blind_pin_server` protocol.
[FuguOracle](https://github.com/FuguBSD/FuguOracle) is the reference oracle
deployment.

## Quick start

```sh
just spec-check
```

The project is specification-first: the code follows the specification.

## Documentation

The specification in [spec/](spec/index.md) is the authoritative reference.
Read [spec/decisions.md](spec/decisions.md) before you make a plan.

## Development

See [CLAUDE.md](CLAUDE.md) for the development guide: the specification
process and the writing standard.

## License

ISC. See [LICENSE](LICENSE).
