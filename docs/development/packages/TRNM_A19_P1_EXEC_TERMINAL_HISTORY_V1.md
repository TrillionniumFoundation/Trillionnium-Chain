# A19 / P1-EXEC terminal finalization history v1

Status: **candidate-implemented / exact-head qualification pending / no Gate promotion**

## Exact source and import boundary

```text
repository = TrillionniumFoundation/Trillionnium-Chain
base_ref = feature/chain-p2-node-candidate-devnet-cli-v1-20260831
base_commit = 5383d7b47537c52d028d207f3763a65c7cfd86a7
base_tree = 35104c76df8f501218f11a79a5b78e74d6edf3c9
branch = feature/chain-a19-p1-exec-terminal-history-v2-20260830
reviewed_source_commit = fd79754512413d6eecbd23d0b9bb48ebe1128e5f
reviewed_cargo_blob = 0edfb6eb38fa8f1c8c9526051d4948f75d847ff7
reviewed_history_blob = c7e8c1f87c51c7ddbe94fd89bd68d1628d2a7043
reviewed_lib_blob = 94f16147f236affab1a30707c403fb93e1d61046
consensus_mainline = native-poco-bft
protocol_target = poco-bft-v0
production_candidate = false
production_consensus_activation = false
```

The three implementation blobs are transplanted without modification onto the
exact Node/A20/A21/A22 source that passed the trusted payload-recovery gate. The
new commit is a single-parent descendant of that source; obsolete publisher,
diagnostic, and merge ancestry is not imported.

This package extends the A04 in-memory `NativeFinalizationQueueV0` slice with a
separate SQLite terminal-history journal. It records only a fully formed
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

## Required exact-head qualification

The final candidate is acceptable only after the exact unchanged commit passes:

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
rejection. Repository truth, blocker execution, canonical plan, Native PoCO
pre-cutover truth, project boundary, and offline-input immutability must also
remain valid.

## Remaining fail-closed boundaries

This package does **not** establish:

- cross-store application/Core/Safety/checkpoint atomicity;
- live node-process finalization ownership;
- authenticated live-reference inventory or fork garbage collection authority;
- safe terminal-history compaction or archive pruning;
- an independently administered anti-rollback anchor;
- descriptor-bound protection for SQLite WAL/SHM child files;
- disk-full, torn-controller-write, host reboot or physical power-loss evidence;
- production HSM/KMS custody;
- independent review, audit, multi-host campaign or wall-clock soak;
- G1 exit, public-testnet readiness, release readiness, normative freeze or
  production consensus activation.

Accordingly, this package closes only the repository-owned durable
terminal-history and restart-idempotence slice of `P1-EXEC-001`. Wider
cross-plane and external predicates remain explicitly open.