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

## Native PoN application revision2

`pon_executor` implements the twelve actual signed commands with tracked key/prefix
observations, fixed-order validation and bounded re-execution. Identical senders use a
serial nonce lane. The optional `pon_execute` bridge requires exact network/parameter
identity and never falls back. It is exercised against `execute_reference` at1/2/4/8
workers, not advertised as a completed native consensus or database reorg owner.

The original local MVCC store remains a distinct portable component. This change does
not silently make its monotonic storage into the reference Ledger's branch database.
