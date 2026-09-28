# trnm-mempool

Owner: M05. Reusable candidate component; no consensus activation.

Bounded admission, nonce reservations and durable handoff independent of BFT.

Domains and data schemas use a fresh portability namespace. Never open a deployed
historical database as an upgrade shortcut. Retained tests cover local behavior only.


```bash
cargo test --locked -p trnm-mempool --all-targets --all-features
```

Run from `trillionnium`. See [modules](../../../docs/modules/README.md) and
[ownership](../../../config/portability-inventory-v1.json).
