# FuguPass

A password manager for any secret, built on proven seed-phrase standards and
air-gapped custody patterns.

FuguPass derives every vault key from one master: a BIP39 mnemonic of 12 words
on a SeedQR plate. No key material leaves the device.

It seals every entry as one flat ciphertext file. Per-entry records at an
ordered set of blind PIN oracles gate each reveal. The passphrase plus any k of
the n oracle masks open one entry.

The wire protocol is version 2 of the Blockstream `blind_pin_server` protocol.
[FuguOracle](https://github.com/FuguBSD/FuguOracle) is the reference oracle
deployment.

## Documentation

The project is specification-first: the specification in [spec/](spec/index.md)
is the authoritative reference. Research notes live in `docs/research/`.

## Commands

```sh
make check       # spec-check + ste-lint + gitleaks + test
make spec-check  # validate the specification and the plans
```

`make check` runs the Markdown format gate, and prettier runs through bunx. The
operator installs bun, for example from Homebrew. The manifest does not provide
it, because the format gate needs `bunx` before a target can run.

    make deps        # install the external tools of the repository

`make deps` installs gitleaks, the tool of the secret gate, from the manifest of
the platform in `deps/`. It installs the `tool` environment before every other
environment, so the gate tool is present for each chain. `deps/SHA256.txt`
records the sha256 digest of each versioned download, and `make deps` compares
the downloaded bytes against it. The CI gate installs gitleaks the same way, so
one pin serves the operator gate and the CI gate.

## Commit scopes

`spec`, `docs`, `ci`.

## License

ISC. See [LICENSE](LICENSE).
