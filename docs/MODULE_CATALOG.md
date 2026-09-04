---
status: canonical
owner: Trillionnium Chain maintainers
last_verified: 2026-09-04
applies_to: main@b2d485e5641614ea0ca34ebf80a5f7843ff1e6d9
---

# Active Rust module catalog

The active workspace membership comes from
[`trillionnium/Cargo.toml`](../trillionnium/Cargo.toml). A crate's maturity is
not inferred from size, test count, age, or directory location.

| Module | Maturity | Responsibility summary |
|---|---|---|
| [`trnm-consensus-app`](../trillionnium/crates/trnm-consensus-app/README.md) | `canonical-production-candidate` | CometBFT ABCI++ application adapter and durable canonical-state boundary. |
| [`trnm-runtime`](../trillionnium/crates/trnm-runtime/README.md) | `canonical-consensus-critical` | Pure deterministic state-transition engine for the canonical transaction protocol. |
| [`trnm-protocol`](../trillionnium/crates/trnm-protocol/README.md) | `canonical-consensus-critical` | Versioned typed wire and canonical object schema for the production-candidate runtime. |
| [`trnm-finality-types`](../trillionnium/crates/trnm-finality-types/README.md) | `supported-consumer-boundary` | Node-independent finality wire types, signing helpers, and certificate structures. |
| [`trnm-finality-verifier`](../trillionnium/crates/trnm-finality-verifier/README.md) | `supported-consumer-boundary` | Minimal independent verifier for finality receipts and validator-set evidence. |
| [`trnm-node`](../trillionnium/crates/trnm-node/README.md) | `legacy-frozen` | Legacy harness package retained for compatibility, local simulation, and temporarily shared library code. |
| [`trnm-state`](../trillionnium/crates/trnm-state/README.md) | `legacy-compatibility` | Versioned legacy state store, governance, consumption, balance, root, WAL, and restore implementation. |
| [`trnm-pouw`](../trillionnium/crates/trnm-pouw/README.md) | `legacy-research` | Legacy-named PoCO/PoUW task, proof, TEE, ZK, metering, and settlement compatibility implementation. |
| [`trnm-executor`](../trillionnium/crates/trnm-executor/README.md) | `legacy-experimental` | Conflict analysis and adaptive parallel grouping strategies for legacy/benchmark execution. |
| [`trnm-mempool`](../trillionnium/crates/trnm-mempool/README.md) | `legacy-experimental` | Legacy admission, lane fairness, quota, retry, spillover, and recovery queue. |
| [`trnm-rpc`](../trillionnium/crates/trnm-rpc/README.md) | `operator-read-surface` | Legacy/operator HTTP, durable-read, event, capability, oracle, relay, and audit query service. |
| [`trnm-bench`](../trillionnium/crates/trnm-bench/README.md) | `test-only` | Benchmark and evidence generator for execution, state, and workload experiments. |
| [`trnm-worker-agent`](../trillionnium/crates/trnm-worker-agent/README.md) | `client-integration` | Worker-side task polling, adapter normalization, execution, retry, receipt, and audit tooling. |
| [`trnm-cli`](../trillionnium/crates/trnm-cli/README.md) | `client-operator-tool` | Native transaction, query, wallet, template, and wait tooling. |
| [`trnm-bridge-poc`](../trillionnium/crates/trnm-bridge-poc/README.md) | `deferred-research` | Cross-chain relay heartbeat and settlement-loop proof of concept. |
| [`trnm-oracle`](../trillionnium/crates/trnm-oracle/README.md) | `deferred-research` | Oracle report validation, policy enforcement, observation formatting, and snapshot helpers. |
| [`trnm-research-protocol`](../trillionnium/crates/trnm-research-protocol/README.md) | `internal-research` | Consensus-facing contract for bounded research commitments exchanged with Hepta Research League and Nakama. |
| [`trnm-types`](../trillionnium/crates/trnm-types/README.md) | `legacy-shared-types` | Shared legacy/interop types, identity registry, capability, settlement, hashing, and normalization models. |

## Canonical dependency direction

```text
trnm-protocol
      |
      v
trnm-runtime
      |
      v
trnm-consensus-app <-> CometBFT
      |
      +--> committed objects / AppHash / proofs / snapshots
      +--> minimal execution events
```

`trnm-finality-types` and `trnm-finality-verifier` are narrow external-consumer
boundaries. Operator/client modules may submit or read data but do not define
consensus. Legacy and research modules remain non-canonical until promoted with
end-to-end evidence.

## Promotion requirements

A legacy, research, or deferred module may be promoted only when:

1. its protocol is typed and versioned;
2. its transition executes in `trnm-runtime` or another explicitly approved
   deterministic canonical runtime;
3. `trnm-consensus-app` routes it and rejects unsupported versions;
4. all validators converge on objects, events, receipts, and AppHash;
5. recovery, upgrade, security, and resource-abuse tests pass;
6. operator runbooks and observability exist;
7. the release truth source is updated with exact evidence.

See [Documentation standard](DOCUMENTATION_STANDARD.md) and
[Canonical runtime freeze](architecture/TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md).
