# Rust-native external contracts

The `contracts/` subtree contains four independently testable Rust crates:

- [`audit-events`](./audit-events/) — normalized audit-event schemas;
- [`settlement-vault`](./settlement-vault/) — authorization, lock, release, refund, and slash semantics;
- [`bridge-relay`](./bridge-relay/) — proof, nonce, and finality-bound relay semantics;
- [`governance-guard`](./governance-guard/) — timelock, pause/resume, and version-drift guards.

## Current authority boundary

These crates are **MVP contract semantics and shared-schema packages**. They are not
currently a production smart-contract runtime, are not part of the Native PoCO-BFT
production authority path, and do not by themselves establish public-testnet,
mainnet, or release readiness.

Use the active repository authorities in this order:

1. [`RELEASE_READINESS.md`](../RELEASE_READINESS.md) for the current NO-GO/GO projection;
2. the [canonical development plan](../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md) for execution order and blockers;
3. the [M00-M17 technical reference](../docs/modules/TRNM_MODULE_TECHNICAL_REFERENCE_V1.md) for module contracts;
4. the [Rust-native external-contract architecture](../trillionnium/docs/protocol/external-contracts-rust/RUST_NATIVE_EXTERNAL_CONTRACTS_ARCH_2026-03-05.md) for the target WASM/Host-ABI design.

The architecture document is a target contract. Directory existence is not
evidence that the target runtime has been integrated.

## Implemented today

The checked-in workspace provides:

- deterministic Rust state-machine logic for the four current crates;
- explicit authorization and fail-closed error handling;
- normalized audit-event types;
- crate-local unit tests;
- one workspace build/test entry point in [`Cargo.toml`](./Cargo.toml).

Run the current bounded workspace gates from the repository root:

```bash
cargo check --manifest-path contracts/Cargo.toml --locked
cargo test --manifest-path contracts/Cargo.toml --locked
```

## Open implementation boundary

The following remain open and must not be described as completed:

- a versioned `HostAbiV1` and runtime capability model;
- `sdk/`, `runtime-spec/`, and cross-contract `integration-tests/` packages;
- deterministic WASM compilation and artifact reproducibility;
- node-side WASM sandboxing, gas metering, memory limits, and host-call quotas;
- storage-delta application into the canonical state root;
- stable RPC transaction/query/event ABI and generated SDKs;
- package upgrade, migration, rollback, and artifact revocation procedures;
- production dependency closure and end-to-end node evidence.

A future host integration must bind, at minimum:

```text
ContractManifestV1
HostAbiV1
GasScheduleV1
StorageDeltaV1
EventSchemaV1
ErrorRegistryV1
ArtifactProvenanceV1
UpgradeMigrationV1
GoldenHostReplayV1
```

## Day-1 scope rule

No contract enters the Day-1 launch promise merely because its crate exists.
Inclusion requires an explicit scope decision in the canonical plan, exact-source
node integration, state-root inclusion, complete tests and evidence, independent
review, and unchanged release truth.

Until those conditions close, the correct description is:

> `contracts/` is the Rust-native external-contract perimeter and semantic MVP,
> not an activated on-chain contract runtime.
