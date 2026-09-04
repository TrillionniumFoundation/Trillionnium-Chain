---
status: canonical
owner: Trillionnium Chain maintainers
last_verified: 2026-09-04
applies_to: Rust workspace
---

# Rust crate index

- [`trnm-consensus-app`](trnm-consensus-app/README.md) — `canonical-production-candidate`
- [`trnm-runtime`](trnm-runtime/README.md) — `canonical-consensus-critical`
- [`trnm-protocol`](trnm-protocol/README.md) — `canonical-consensus-critical`
- [`trnm-finality-types`](trnm-finality-types/README.md) — `supported-consumer-boundary`
- [`trnm-finality-verifier`](trnm-finality-verifier/README.md) — `supported-consumer-boundary`
- [`trnm-node`](trnm-node/README.md) — `legacy-frozen`
- [`trnm-state`](trnm-state/README.md) — `legacy-compatibility`
- [`trnm-pouw`](trnm-pouw/README.md) — `legacy-research`
- [`trnm-executor`](trnm-executor/README.md) — `legacy-experimental`
- [`trnm-mempool`](trnm-mempool/README.md) — `legacy-experimental`
- [`trnm-rpc`](trnm-rpc/README.md) — `operator-read-surface`
- [`trnm-bench`](trnm-bench/README.md) — `test-only`
- [`trnm-worker-agent`](trnm-worker-agent/README.md) — `client-integration`
- [`trnm-cli`](trnm-cli/README.md) — `client-operator-tool`
- [`trnm-bridge-poc`](trnm-bridge-poc/README.md) — `deferred-research`
- [`trnm-oracle`](trnm-oracle/README.md) — `deferred-research`
- [`trnm-research-protocol`](trnm-research-protocol/README.md) — `internal-research`
- [`trnm-types`](trnm-types/README.md) — `legacy-shared-types`

The machine source of workspace membership is
[`../Cargo.toml`](../Cargo.toml). The documentation integrity gate fails when a
workspace member lacks a module contract or catalog entry.

For cross-module maturity and promotion rules, see
[`../../docs/MODULE_CATALOG.md`](../../docs/MODULE_CATALOG.md).
