# A19 / P1-EXEC terminal finalization history v1

Status: **candidate-implemented / exact-head restack qualification pending / no Gate promotion**

## Exact source and provenance boundary

```text
repository = TrillionniumFoundation/Trillionnium-Chain
base_ref = integration/native-poco-a04-a19-stack-v1-20260901
base_commit = d8e68c0dc5d9b8950331c2e060be11ed904cf732
base_tree = 1e8d89bafc1d585f63caa22f652375ad8ced054b
reviewed_source_commit = 44d53c0df1658fa8cd1aadd707ac404ffaf2480f
reviewed_source_tree = 53ec59faec5e6cbd6a9eeb35fc733c13df9073cd
reviewed_import_commit = fb19f7346b415fb49ce7b6ed3c577ab5d5d3a7ea
reviewed_import_tree = 46cdfae7493dc09334cf8b1fcd643621e752394e
reviewed_original_base = f38df4ec81cb76f92c709d8cd45311e164fa5753
cargo_blob_before = 233cb331920b05815e35f86bc14adf1083d8c2d7
cargo_blob_after = 0edfb6eb38fa8f1c8c9526051d4948f75d847ff7
lib_blob_before = 95a2ff0f7344fe8ffaf960f6f4f59c7ec4a6cf07
lib_blob_after = 94f16147f236affab1a30707c403fb93e1d61046
history_blob_after = c7e8c1f87c51c7ddbe94fd89bd68d1628d2a7043
consensus_mainline = native-poco-bft
protocol_target = poco-bft-v0
production_candidate = false
production_consensus_activation = false
```

The A04 finalization intent/readback carrier is the direct parent. Both modified
SQLite destination blobs were proven byte-identical to the reviewed A19 base
before the reviewed post-A19 blobs were transplanted. The history module is the
exact reviewed blob; obsolete historical ancestry and publisher files are not
imported.

This package extends `NativeFinalizationQueueV0` with a separate SQLite
terminal-history journal. It records only a fully formed
`NativeFinalizationApplyReadbackV0`; it does not execute a block, mint Core or
Safety authority, choose a fork, or authorize production.

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

The exact stack must also preserve capability-authority, repository-truth,
blocker-ledger, canonical-plan, Native PoCO pre-cutover, project-boundary and
offline-input invariants.

## Remaining fail-closed boundaries

This package does not by itself establish cross-store atomicity, live
node-process finalization ownership, authenticated live-reference inventory,
safe archive pruning, an independently administered anti-rollback anchor,
descriptor-bound SQLite WAL/SHM identity, physical power-loss evidence,
independent review, real multi-host campaign evidence, production readiness or
activation. It closes the durable terminal-history and restart-idempotence
repository slice needed by A23.
