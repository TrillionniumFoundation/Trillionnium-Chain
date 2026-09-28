# trnm-poco-node-host

## PoN target and current-source scope

This crate remains existing implementation/reference source; this documentation does
not turn it into a PoN runtime. Selected development profile: `pon-nakamoto-v1`.
Source owner: M15. Target responsibility: Ordinary PoN node, Hepta integration and release composition.
See [M15 technical contract](../../../docs/modules/M15_NODE_RELEASE_TECHNICAL_SPEC_V1.md) and the
[PoN protocol](../../../docs/protocol/pon-nakamoto-v1/README.md).

Reuse thin host/port composition, bounded worker/process controls and release provenance. Old
PoCO candidate host remains legacy source; new runtime is not claimed implemented by these
documents.

## Retained implementation documentation

The source interfaces, stored formats, commands and tests below retain their actual
legacy/profile semantics. PoCO consensus is retired as the target. No old finality,
committee, vote, consumption weight or test pass is new neural-work/efficacy evidence.


Wiring-only host composition for the native PoCO production-shaped node decomposition.

This package is fail-closed and owns no production activation authority. Its
normative architecture contract is
[TRNM_POCO_NODE_DECOMPOSITION_V1.md](../../../docs/architecture/TRNM_POCO_NODE_DECOMPOSITION_V1.md).

Run its focused checks through:

```bash
python3 scripts/ci/check_node_decomposition_v1.py
cargo test --manifest-path trillionnium/Cargo.toml -p trnm-poco-node-host --all-targets --locked
```
