# trnm-crypto-primitives

Owner: M01. Reusable candidate component; no consensus activation.

Extract domain hash, strict Ed25519 and canonical fixed-width decoding.

Domains and data schemas use a fresh portability namespace. Never open a deployed
historical database as an upgrade shortcut. Retained tests cover local behavior only.


```bash
cargo test --locked -p trnm-crypto-primitives --all-targets --all-features
```

Run from `trillionnium`. See [modules](../../../docs/modules/README.md) and
[ownership](../../../config/portability-inventory-v1.json).

## Executable PoN candidate

This package now contains an exact experimental PoN finite-field transcript relation and verifier.
See [the exact contract](../../../docs/protocol/pon-nakamoto-v1/details/WORK_PROFILE.md) and
the separate Python oracle. Native code and cross-language vectors are real; no public
network hardness, native node integration or independent acceptance is implied.
