# A19 / P1-EXEC terminal finalization history v1

Status: **candidate-implemented / canonical qualification pending / no Gate promotion**

## Exact source and provenance boundary

```text
repository = TrillionniumFoundation/Trillionnium-Chain
base_ref = feature/chain-p2-node-candidate-devnet-cli-v1-20260831
base_commit = eb0f1de90d2baa5d0f8a7ef1975d7914bd9d4af9
branch = feature/chain-a19-p1-exec-terminal-history-canonical-v1-20260831
reviewed_import_commit = fb19f7346b415fb49ce7b6ed3c577ab5d5d3a7ea
reviewed_import_tree = 46cdfae7493dc09334cf8b1fcd643621e752394e
reviewed_original_base = f38df4ec81cb76f92c709d8cd45311e164fa5753
consensus_mainline = native-poco-bft
protocol_target = poco-bft-v0
production_candidate = false
production_consensus_activation = false
```

The two modified destination files were transplanted only after their canonical
blobs were proven identical to the reviewed original base. The new journal file
is the exact reviewed blob. This preserves the reviewed implementation without
merging the obsolete historical branch ancestry.

This package extends the application-side `NativeFinalizationQueueV0` slice with
a separate SQLite terminal-history journal. It records only a fully formed
`NativeFinalizationApplyReadbackV0`; it does not execute a block, mint a Core or
Safety capability, choose a fork, or authorize production.

## Implemented repository-owned predicates

`SqliteNativeFinalizationHistoryV0` provides:

- an exact scope and initial-application-head store identity;
- a frozen strict SQLite schema with no automatic migration;
- a fixed-width canonical encoding of the complete finalization intent and
  apply readback;
- one SHA-256 record digest over the exact scope and record bytes;
- one monotonic chain digest over the previous chain digest, record digest and
  durable sequence;
- contiguous sequence and parent-head enforcement;
- unique target-block and proof identities;
- exact replay idempotence and conflicting-replay rejection;
- atomic row plus metadata compare-and-swap in one immediate transaction;
- fresh-connection exact readback after commit;
- full-chain audit on open and on demand;
- corruption, metadata rollback, scope substitution, initial-head substitution,
  relative path, symlink and hardlink rejection;
- a hard upper bound of 1,000,000 retained terminal records.

## Required canonical verification

The exact canonical candidate must pass on the dedicated X230 runner using the
pinned Rust 1.95.0 toolchain and the frozen offline Cargo cache:

```text
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
cargo check --manifest-path trillionnium/Cargo.toml --workspace --all-targets --locked --offline
cargo clippy --manifest-path trillionnium/Cargo.toml \
  -p trnm-native-application-sqlite --all-targets --locked --offline -- -D warnings
cargo test --manifest-path trillionnium/Cargo.toml \
  -p trnm-native-application-sqlite --all-targets --locked --offline
cargo test --manifest-path trillionnium/Cargo.toml \
  -p trnm-native-application --lib --locked --offline
```

The tests must demonstrate append/reopen/readback, exact replay, gap rejection,
parent drift rejection, conflicting retry rejection, record tamper rejection,
metadata rollback rejection, persistent scope/head identity and path alias
rejection.

## Remaining blockers not claimed by this package

This package does **not** establish:

- atomic application/Core/Safety/checkpoint commit across multiple stores;
- node-process ownership or a live proposal-to-finality loop;
- authenticated live-reference inventory or fork garbage collection authority;
- safe terminal-history compaction or archive pruning;
- an independently administered anti-rollback floor;
- descriptor-bound protection for SQLite WAL/SHM child files;
- disk-full, torn-controller-write, host reboot or physical power-loss evidence;
- production HSM/KMS custody;
- independent review, audit, multi-host campaign or wall-clock soak;
- G1 exit, public-testnet readiness, release readiness, normative freeze or
  production consensus activation.

Accordingly, `P1-EXEC-001` remains partial after this slice: the durable
terminal-history and restart-idempotence sub-gap is addressed, while the
cross-plane authority and physical evidence predicates remain fail-closed.
