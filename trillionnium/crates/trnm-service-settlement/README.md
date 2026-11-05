# trnm-service-settlement

Owner: M12. Reusable candidate component; no consensus activation.

Bilateral usage/escrow conservation; no consumption-derived voting power.

Domains and data schemas use a fresh portability namespace. Never open a deployed
historical database as an upgrade shortcut. Retained tests cover local behavior only.

This is a local monotonic commit/replay kernel, NOT a branch-reorganization backend.
PoN authoritative integration requires a new branch/undo adapter and crash qualification.

The separate [native owner budget adapter](../../../docs/development/specs/pon/NATIVE_BUDGET_ADAPTER_V1.md)
adds six funded resource lanes and a local journal that is never rolled back
with branch state. It reads existing monetary rows through the actual Node owner;
it does not turn this portable rollup store into a native payment authority.

```bash
cargo test --locked -p trnm-service-settlement --all-targets --all-features
```

Run from `trillionnium`. See [modules](../../../docs/modules/README.md) and
[ownership](../../../config/portability-inventory-v1.json).
