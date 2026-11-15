# trnm-research-protocol

Owner: M10. Reusable candidate component; no consensus activation.

Contribution/evaluation/lineage contracts independent of ledger consensus.

The crate also contains the digest-only `HeptaArtifactAdmissionV1` /
`SignedHeptaAdmissionV1` handoff boundary. It verifies an existing Hepta owner
receipt, withdrawal head, export permission and parent generation without owning a
trainer, registry, journal or final-use token. A chain adapter must revalidate the
live owner frontier and reconcile its operation identity after a reorganization.

Domains and data schemas use a fresh portability namespace. Never open a deployed
historical database as an upgrade shortcut. Retained tests cover local behavior only.


```bash
cargo test --locked -p trnm-research-protocol --all-targets --all-features
```

Run from `trillionnium`. See [modules](../../../docs/modules/README.md) and
[ownership](../../../config/portability-inventory-v1.json).
