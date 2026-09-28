# trnm-data-availability

Owner: M09. Reusable candidate component; no consensus activation.

Signed storage responsibility, chunk retrieval, repair and retention; no block consensus.

Domains and data schemas use a fresh portability namespace. Never open a deployed
historical database as an upgrade shortcut. Retained tests cover local behavior only.

Storage attestation thresholds are storage contracts, not ledger consensus votes.
The current transaction-batch namespace does not yet implement public model artifacts.

```bash
cargo test --locked -p trnm-data-availability --all-targets --all-features
```

Run from `trillionnium`. See [modules](../../../docs/modules/README.md) and
[ownership](../../../config/portability-inventory-v1.json).
