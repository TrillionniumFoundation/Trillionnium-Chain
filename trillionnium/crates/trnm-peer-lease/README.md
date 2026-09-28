# trnm-peer-lease

Owner: M04. Reusable candidate component; no consensus activation.

Cross-process scope/generation fencing, append-only replay and bounded Unix transport.

Domains and data schemas use a fresh portability namespace. Never open a deployed
historical database as an upgrade shortcut. Retained tests cover local behavior only.


```bash
cargo test --locked -p trnm-peer-lease --all-targets --all-features
```

Run from `trillionnium`. See [modules](../../../docs/modules/README.md) and
[ownership](../../../config/portability-inventory-v1.json).
