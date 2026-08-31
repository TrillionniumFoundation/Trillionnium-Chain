# A19 / P1-EXEC terminal finalization history v1

Status: **candidate-implemented / exact-head qualification pending / no Gate promotion**

## Exact source and provenance boundary

```text
repository = TrillionniumFoundation/Trillionnium-Chain
base_ref = integration/native-poco-a04-a19-a23-v1-20260831
base_commit = 3f4532a910178e1c9acc496d83db3f6fb4fa0c71
base_tree = f6f7870722e1a317f076985e25bd6b498e53da3d
branch = integration/native-poco-a04-a19-a23-v1-20260831
reviewed_import_commit = fb19f7346b415fb49ce7b6ed3c577ab5d5d3a7ea
reviewed_import_tree = 46cdfae7493dc09334cf8b1fcd643621e752394e
reviewed_original_base = f38df4ec81cb76f92c709d8cd45311e164fa5753
canonical_a19_commit = 44d53c0df1658fa8cd1aadd707ac404ffaf2480f
base_cargo_blob = 233cb331920b05815e35f86bc14adf1083d8c2d7
base_lib_blob = 95a2ff0f7344fe8ffaf960f6f4f59c7ec4a6cf07
imported_cargo_blob = 0edfb6eb38fa8f1c8c9526051d4948f75d847ff7
imported_history_blob = c7e8c1f87c51c7ddbe94fd89bd68d1628d2a7043
imported_lib_blob = 94f16147f236affab1a30707c403fb93e1d61046
consensus_mainline = native-poco-bft
protocol_target = poco-bft-v0
production_candidate = false
production_consensus_activation = false
```

The A04 finalization intent/readback prerequisite is the direct parent. The two
modified SQLite destination blobs were proven byte-identical to the reviewed
A19 base, and `finalization_history.rs` was absent before the exact reviewed
blob was added. No historical merge ancestry or workflow artifact is imported.

This package extends `NativeFinalizationQueueV0` with a separate SQLite terminal
history journal. It records only a fully formed
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

## Required exact-head verification

The exact unchanged candidate must pass on the dedicated X230 runner with Rust
1.95.0 and the frozen offline Cargo cache:

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

Repository truth, capability-authority audit, canonical-plan truth, Native PoCO
pre-cutover truth, project boundary and Cargo-input immutability must remain
valid on the same source commit.

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
