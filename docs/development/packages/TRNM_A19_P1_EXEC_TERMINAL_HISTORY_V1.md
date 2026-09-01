# A19 / P1-EXEC terminal finalization history v1

Status: **repository source blockers repaired / exact-head and prospective-merge qualification pending / no Gate promotion**

## Exact provenance boundary

```text
repository = TrillionniumFoundation/Trillionnium-Chain
integration_base_ref = feature/chain-p2-node-candidate-devnet-cli-v1-20260831
integration_base_commit = fddc8e919a77f3be42b72ad4b8a7f8ff91d7abdc
ordered_finalization_commit = d8e68c0dc5d9b8950331c2e060be11ed904cf732
terminal_history_import_commit = 8eda2af07b0a61f0b0846926e912354fdde95b20
native_replay_floor_commit = 3c46293e78a125dec9504e51c355a20216341338
namespace_schema_repair_commit = 6d5e6e2ee9923b776a2a64d96e19bc03e84dd79a
consensus_mainline = native-poco-bft
protocol_target = poco-bft-v0
production_candidate = false
production_consensus_activation = false
public_testnet_ready = false
release_ready = false
```

The A04 finalization intent/readback carrier is the direct functional parent.
The A19 history store records only a fully formed
`NativeFinalizationApplyReadbackV0`; it does not execute a block, mint Core or
Safety authority, choose a fork, or authorize production. A23 consumes only the
verified native finalized replay floor derived from this durable history.

This document update follows the Rust repair commit and does not modify the
Rust implementation. The PR head and prospective merge object remain the only
objects eligible for acceptance evidence.

## Closed repository-owned predicates

`SqliteNativeFinalizationHistoryV0` now provides one fail-closed connection
protocol for `audit`, `read_sequence`, new append, and exact replay:

- canonical parent-directory and database identity is pinned before use;
- authoritative SQLite opens use `SQLITE_OPEN_NOFOLLOW`;
- database, WAL, and SHM identities are retained and rechecked;
- the exact two tables, five SQLite automatic indexes, canonical SQL, and
  required connection pragmas form a closed-world schema contract;
- every fresh trusted connection revalidates namespace, schema, scope,
  generation, initial head, and durable metadata;
- no trusted read or replay result is released before explicit SQLite close and
  post-operation descriptor verification;
- fixed-width canonical records, content-addressed record IDs, hash-chained
  durable sequence, contiguous parent enforcement, and atomic row/metadata CAS
  remain enforced;
- exact replay is idempotent and conflicting replay is rejected;
- hostile regressions cover extra table/index/view/trigger injection,
  same-scope valid-database substitution, symlink and hardlink aliases,
  WAL/SHM aliases, parent-directory replacement, metadata rollback, reopen, and
  early-return paths;
- the store retains a hard upper bound of 1,000,000 terminal records.

These predicates close the former `A19-NS-001`, `A19-SCHEMA-001`, and
`A19-RETURN-001` source objections. They do not by themselves constitute
current-head execution evidence or independent acceptance.

## Required exact-object verification

The unchanged final PR head and its current prospective merge object must both
complete non-empty terminal-success evidence for the applicable matrix:

```text
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
cargo check --manifest-path trillionnium/Cargo.toml --workspace --all-targets --locked --offline
cargo clippy --manifest-path trillionnium/Cargo.toml \
  -p trnm-native-application-sqlite --all-targets --locked --offline -- -D warnings
cargo test --manifest-path trillionnium/Cargo.toml \
  -p trnm-native-application-sqlite --all-targets --locked --offline
cargo test --manifest-path trillionnium/Cargo.toml \
  -p trnm-native-application --all-targets --locked --offline
```

The same exact objects must preserve repository-truth, blocker-ledger,
canonical-plan, Native PoCO pre-cutover, project-boundary, capability-authority,
offline-input, payload-replay, replay-to-Core, PoCO-BFT, CometBFT,
canonical-input fuzz, and merge-gate invariants. Skipped, empty, stale,
carrier-only, or different-head runs are not acceptance.

## Remaining fail-closed boundaries

This package does not establish one cross-authority Node Commit Ledger,
application/Core/Safety/checkpoint atomic convergence, a default persistent
production validator, authenticated process-2 catch-up and state sync,
production CheckTx/sign/broadcast/receipt completion, independently
administered monotonic anti-rollback hardware, cross-platform authenticated
peer identity, real multi-host and physical power-loss evidence, external
security audit, soak, public-testnet readiness, release readiness, mainnet
readiness, or consensus activation.
