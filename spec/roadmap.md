# Roadmap

This document names the phases of the work.
The "Done by" column of the [implementation register](STATUS.md) refers to these phase
IDs.
At the exit of a phase, each unit with that "Done by" value must have the state `done`.

| Phase | Name | Exit condition |
| --- | --- | --- |
| P1 | Vault and derivation core | The derivation tree, the seal, the vault format, the state partition, the entry model, and the dice ceremony math are complete, and all known-answer tests pass. |
| P2 | Oracle client and custody | The oracle client, the enrollment and reveal procedures, the quorum reconstruction, the canary, the counters, and the pool are complete. The interop harness and the mask-stability test pass against every available conforming oracle, the upstream blind_pin_server at minimum, and the quorum leg passes against the example 2-of-3 topology. The mask-composition analysis and the deterministic-share analysis have human approval. The share-arithmetic source evaluation is recorded. |
| P3 | Programs and ceremonies | The four programs, the SeedQR codecs, the ceremonies, and every recovery procedure are complete, and an end-to-end ceremony and recovery walkthrough passes on OpenBSD. |
| P4 | Hardening and distribution | The sandbox and memory-hygiene audit, the KDF calibration, the runbooks, the man pages, and the port are complete. |

The phases run in order: P1, P2, P3, P4.
