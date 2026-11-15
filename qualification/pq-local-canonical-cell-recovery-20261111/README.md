# x230 canonical SQL-cell source recovery (HOLD)

This directory preserves a **byte-exact, previously untracked** Rust source file from the original x230 Chain PQ working tree. It is a qualification archive, **not** an active crate migration or acceptance of the optimization.

- Original source tree: `fix/chain-pq-full-20261103-4502`, HEAD `3f3a5c5017367eefc0970d512920a6eaa4a29c35`.
- Original relative path: `trillionnium/crates/trnm-pon-node/src/store/canonical_cell.rs`.
- Original **Git Blob SHA-1**: `4669d2e13bce8212634c16b8217845e3d737b8b5`.
- Original **SHA-256**: `1b05f53c571a44b8085de56e3ab738056713ad2c044acf45127a55483cfc7509`.
- File size: 5,438 bytes, unmodified during recovery.

## Scoped independent checks

The source and standalone harness were transferred by exact content from x230 to mac; mac independently recomputed the original SHA-256. On macOS with Rust/Cargo 1.95.0, `cargo test --offline` in this directory passed **3/3** tests (2 tests preserved from the original source plus one additional control). Original mac test job: `1a1c8c6d03e-135c4-22e`. The isolated harness uses a **minimal local owner-error adapter** to compile the original source against pinned serde_json, so **this does not exercise the actual native store/owner integration or persistence**.

To rerun in this directory:

```sh
cargo test --offline --locked --manifest-path qualification/pq-local-canonical-cell-recovery-20261111/Cargo.toml
```

The archive is intentionally outside `trillionnium/crates`; no wire serialization, state root, validator, PQ signature, admission, History, or Root logic has been modified by this recovery PR. The actual production integration and native full-workload CPU/memory/time gate remain HOLD/NO_GO. Do **not** merge this as evidence of product/security acceptance.

Credential/private-key pattern prescan found no matches in this one source file; it is not a whole-repository security scan. The original dirty working tree contains other files and private .hepta-* markers that are **excluded** from this archive.
