# A19 / P1-EXEC terminal finalization history v1

Status: **candidate-implemented / canonical qualification pending / no Gate promotion**

## Exact source and provenance boundary

```text
repository = TrillionniumFoundation/Trillionnium-Chain
base_ref = feature/chain-a04-g1-r4-application-finality-canonical-v1-20260831
base_commit = 1fa71c942e129ce88937a030c3054c8f72649aaf
branch = feature/chain-a19-p1-exec-terminal-history-canonical-v1-20260831
reviewed_import_commit = fb19f7346b415fb49ce7b6ed3c577ab5d5d3a7ea
reviewed_import_tree = 46cdfae7493dc09334cf8b1fcd643621e752394e
reviewed_original_base = f38df4ec81cb76f92c709d8cd45311e164fa5753
consensus_mainline = native-poco-bft
protocol_target = poco-bft-v0
production_candidate = false
production_consensus_activation = false
```

The A04 finalization intent/readback prerequisite is the direct parent. The two
modified SQLite destination blobs were proven identical between the canonical
A04 tree and the reviewed A19 base before transplanting the reviewed head blobs.
The new journal implementation is the exact reviewed blob. Obsolete historical
ancestry is not merged.

This package extends `NativeFinalizationQueueV0` with a separate SQLite
terminal-history journal. It records only a fully formed
`NativeFinalizationApplyReadbackV0`; it does not execute a block, mint Core or
Safety capability, choose a fork, or authorize production.

## Implemented repository-owned predicates

`SqliteNativeFinalizationHistoryV0` provides:

- exact scope and initial-application-head identity;
- a frozen strict SQLite schema with no automatic migration;
- fixed-width canonical encoding of the complete intent/readback;
- SHA-256 record identity bound to store scope;
- a monotonic chain digest over previous chain, record and durable sequence;
- contiguous sequence and parent-head enforcement;
- unique target-block and proof identities;
- exact replay idempotence and conflicting replay rejection;
- atomic row plus metadata compare-and-swap in one immediate transaction;
- fresh-connection exact readback after commit;
- full-chain audit on open and on demand;
- record tamper, metadata rollback, scope/head substitution, relative-path,
  symlink and hardlink rejection;
- a hard upper bound of 1,000,000 terminal records.

## Required canonical verification

The exact candidate must pass on the dedicated X230 runner with Rust 1.95.0 and
the frozen offline Cargo cache:

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

## Remaining fail-closed boundaries

This package does not establish:

- cross-store application/Core/Safety/checkpoint atomicity;
- live node-process finalization ownership;
- authenticated live-reference inventory or safe archive pruning;
- an independently administered anti-rollback anchor;
- descriptor-bound SQLite WAL/SHM child-file identity;
- physical power-loss, independent review, audit, multi-host campaign or soak;
- G1 exit, public-testnet readiness, release readiness or activation.

It closes the durable terminal-history and restart-idempotence repository slice
only; the wider `P1-EXEC-001` remains fail-closed until the cross-plane and
external predicates are proven.
