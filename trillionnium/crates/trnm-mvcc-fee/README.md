# trnm-mvcc-fee

Owner: M06. Reusable candidate component; no consensus activation.

Deterministic serial/parallel execution, fee deltas and incremental storage.

Domains and data schemas use a fresh portability namespace. Never open a deployed
historical database as an upgrade shortcut. Retained tests cover local behavior only.

This is a local monotonic commit/replay kernel, NOT a branch-reorganization backend.
PoN authoritative integration requires a new branch/undo adapter and crash qualification.

```bash
cargo test --locked -p trnm-mvcc-fee --all-targets --all-features
```

Run from `trillionnium`. See [modules](../../../docs/modules/README.md) and
[ownership](../../../config/portability-inventory-v1.json).
