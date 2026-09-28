# trnm-checkpoint-store

Owner: M03. Reusable candidate component; no consensus activation.

Independent exact CAS and durable Unix service; generalized owner frontier only.

Domains and data schemas use a fresh portability namespace. Never open a deployed
historical database as an upgrade shortcut. Retained tests cover local behavior only.


```bash
cargo test --locked -p trnm-checkpoint-store --all-targets --all-features
```

Run from `trillionnium`. See [modules](../../../docs/modules/README.md) and
[ownership](../../../config/portability-inventory-v1.json).
