# trnm-poco-node-host

Wiring-only host composition for the native PoCO production-shaped node decomposition.

This package is fail-closed and owns no production activation authority. Its
normative architecture contract is
[TRNM_POCO_NODE_DECOMPOSITION_V1.md](../../../docs/architecture/TRNM_POCO_NODE_DECOMPOSITION_V1.md).

Run its focused checks through:

```bash
python3 scripts/ci/check_node_decomposition_v1.py
cargo test --manifest-path trillionnium/Cargo.toml -p trnm-poco-node-host --all-targets --locked
```
