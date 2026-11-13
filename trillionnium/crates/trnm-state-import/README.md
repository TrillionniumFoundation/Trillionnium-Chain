# trnm-state-import

Owner: M13. Reusable candidate component; no consensus activation.

Bounded independently admitted export/import and root checks; no old proof decoder.

Domains and data schemas use a fresh portability namespace. Never open a deployed
historical database as an upgrade shortcut. Retained tests cover local behavior only.


```bash
cargo test --locked -p trnm-state-import --all-targets --all-features
```

Run from `trillionnium`. See [modules](../../../docs/modules/README.md) and
[ownership](../../../config/portability-inventory-v1.json).

Incremental application bounds output reservation by validated base rows plus
value-bearing delta entries before using the declared target count. This is a
conservative allocation bound, not proof of the exact output count; the merged
rows, count, digest and root are still checked before returning a result. Input
storage, cloning of admitted rows and retained database size remain separate costs.
