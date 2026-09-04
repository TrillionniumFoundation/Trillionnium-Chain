---
status: canonical
owner: Trillionnium Chain maintainers
last_verified: 2026-09-04
applies_to: Rust workspace
---

# Trillionnium Rust workspace

This directory contains the active Rust workspace. The canonical
production-candidate transition is:

```text
CometBFT -> trnm-consensus-app -> trnm-runtime
```

with typed data from `trnm-protocol`.

## Commands

Run from the repository root:

```bash
cargo check --manifest-path trillionnium/Cargo.toml --workspace --locked
cargo test --manifest-path trillionnium/Cargo.toml --workspace --locked
cargo doc --manifest-path trillionnium/Cargo.toml --workspace --no-deps
```

Run the documentation gate after adding or removing a workspace member:

```bash
python3 scripts/ci/check_documentation_integrity.py
```

## Crate classification

See the [crate index](crates/README.md) and
[module catalog](../docs/MODULE_CATALOG.md). Canonical, legacy, deferred,
operator, client, and test-only labels are intentional security boundaries.

## Development rules

- Add canonical protocol fields in `trnm-protocol`, not in ad-hoc JSON.
- Keep state transition pure and deterministic in `trnm-runtime`.
- Keep storage, ABCI, snapshot, and validator lifecycle in
  `trnm-consensus-app`.
- Do not add new protocol capability to frozen legacy `trnm-node` binaries.
- Unknown versions, payloads, and ambiguous encodings fail closed.
- Update the module README and tests with every behavior change.
