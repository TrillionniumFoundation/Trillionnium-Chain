# trnm-checkpoint-types

Owner: M03. Reusable candidate component; no consensus activation.

Extract canonical checkpoint/CAS record; remove safety-vote and validator types.

Domains and data schemas use a fresh portability namespace. Never open a deployed
historical database as an upgrade shortcut. Retained tests cover local behavior only.


```bash
cargo test --locked -p trnm-checkpoint-types --all-targets --all-features
```

Run from `trillionnium`. See [modules](../../../docs/modules/README.md) and
[ownership](../../../config/portability-inventory-v1.json).
