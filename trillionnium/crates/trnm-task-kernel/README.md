# trnm-task-kernel

Owner: M10. Reusable candidate component; no consensus activation.

Task/lease/capability/escrow local kernel; monotonic local sequence is not chain finality.

Domains and data schemas use a fresh portability namespace. Never open a deployed
historical database as an upgrade shortcut. Retained tests cover local behavior only.

This is a local monotonic commit/replay kernel, NOT a branch-reorganization backend.
PoN authoritative integration requires a new branch/undo adapter and crash qualification.

```bash
cargo test --locked -p trnm-task-kernel --all-targets --all-features
```

Run from `trillionnium`. See [modules](../../../docs/modules/README.md) and
[ownership](../../../config/portability-inventory-v1.json).
