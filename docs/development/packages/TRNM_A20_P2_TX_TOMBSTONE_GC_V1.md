# A20 / P2-TX authenticated tombstone GC v1

Status: **module-closed candidate / exact-source verified / no production activation**

## Exact boundary

```text
repository = TrillionniumFoundation/Trillionnium-Chain
base_ref = feature/chain-a18-repository-truth-ci-hardening-v1-20260830
base_head_at_publication = 1663abd8935be4e5819f5ff0c7ded250a3664097
common_ancestor = 13ecabcbd9ad6f1320d3d5ff1083d1a0b08f47c0
branch = feature/chain-a20-p2-tx-tombstone-gc-v1-20260830
verified_source_commit = 9dfee13c02c0f3f291f838109419405fbab8c435
verified_source_tree = 550f50b9c210b030e0acf2f6d4147293a9b92df3
verification_workflow = trnm-a20-sealed-replay-floor-verify
verification_run = 33314235705
verification_conclusion = completed/success
consensus_mainline = native-poco-bft
protocol_target = poco-bft-v0
production_candidate = false
```

The source commit above is unsigned and is not release-signature evidence. This
documentation descendant records the exact tested source; it does not silently
upgrade or replace it.

The existing transaction-admission WAL retained every committed or released row
forever because deleting either the nonce key or transaction digest would make
replay possible. This package introduces a two-stage, fail-closed lifecycle:

```text
terminal rich row
  -- atomic compact --> immutable replay tombstone
  -- verified application nonce floor + finality --> physical purge
```

## Compaction contract

Only `Committed` and `Released` rows are eligible. `Reserved` and `HandedOff`
rows are never selected. One immediate SQLite transaction:

1. verifies the exact terminal state;
2. for `Committed`, requires the exact native commit receipt, block height and
   nonzero receipt commitment;
3. derives a namespace/signer/nonce/digest/state/height/receipt-bound SHA-256
   tombstone digest;
4. inserts a uniqueness-constrained compact tombstone;
5. deletes the rich receipt when present;
6. deletes the exact terminal pending row.

Reservation checks both rich rows and compact tombstones, so compaction does not
re-open either `(signer, nonce)` or transaction digest authority. Unfiltered
capacity queries include both tables. The state-filtered `HandedOff` query stays
scoped to the rich table and cannot be rewritten into an invalid aggregate.

## Authenticated purge contract

A compact tombstone can be physically deleted only with a private
`VerifiedTxAdmissionReplayFloorV1` token. The token is minted only after a
crate-owned `TxAdmissionReplayFloorVerifierV1` accepts evidence binding. The
verifier trait is sealed: downstream crates can inspect the public contract but
cannot implement an always-accept verifier or mint their own purge capability.
The evidence binds:

- repository namespace;
- canonical signer identity;
- highest nonce permanently rejected by application state;
- finalized block height and state root;
- finality-proof digest;
- retention-policy digest.

Purge is signer-local, nonce-bounded, finality-height-bounded and batch-bounded.
A rejected or foreign-namespace floor leaves all tombstones unchanged. A
`compile_fail` doctest proves that an external crate cannot implement the sealed
verifier authority.

## Storage and restart invariants

- schema version is bumped to v2 with no implicit v1 migration;
- pre-existing v1 databases fail closed rather than silently discarding replay
  history;
- rich rows and tombstones may not overlap;
- all tombstone widths, states, zero/nonzero relations and digests are audited
  on every open;
- combined rich+tombstone inventory remains capped at 1,000,000 rows;
- each compact or purge call is capped at 4,096 rows;
- tombstone digest tamper, cross-table overlap, malformed terminal evidence and
  partial compaction are rejected.

## Exact-source verification

The final source was produced and tested by one workflow run before publication:

```text
run = 33314235705
immutable source chain = success
Rust 1.95.0 = success
workspace all-targets compile = success
trnm-poco-node tx-admission-wal Clippy -D warnings = success
downstream verifier-forgery compile-fail = success
new tombstone regressions = success
retained transaction-admission regressions = success
canonical Plan = success
Native PoCO pre-cutover truth = success
exact tested source push = success
```

The executed commands included:

```text
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
cargo check --manifest-path trillionnium/Cargo.toml --workspace --all-targets --locked
cargo clippy --manifest-path trillionnium/Cargo.toml \
  -p trnm-poco-node --features tx-admission-wal --lib --locked -- -D warnings
cargo test --manifest-path trillionnium/Cargo.toml \
  -p trnm-poco-node --features tx-admission-wal --doc --locked
cargo test --manifest-path trillionnium/Cargo.toml \
  -p trnm-poco-node --features tx-admission-wal --lib \
  tx_admission_wal::tombstone_gc_tests_v1 -- --nocapture
cargo test --manifest-path trillionnium/Cargo.toml \
  -p trnm-poco-node --features tx-admission-wal --lib \
  tx_admission_wal::tests -- --nocapture
```

Temporary write-capable workflows and one-shot transform scripts are absent from
the verified source tree. Historical failed runs remain historical evidence and
were not relabelled as success.

## Non-claims

```text
tx_admission_tombstone_gc = true
tx_admission_tombstone_compaction = true
tx_admission_tombstone_authenticated_purge = true
tx_admission_replay_floor_verifier_sealed = true
tx_admission_tombstone_gc_production = false
tx_admission_replay_floor_native_integration = false
tx_admission_boundary_production_activation = false
tx_admission_boundary_signing = false
tx_admission_boundary_broadcast = false
independent_review_closed = false
multi_host_campaign_closed = false
external_anchor_hsm_closed = false
physical_power_loss_closed = false
independent_audit_closed = false
wall_clock_soak_closed = false
g1_exit = false
production_candidate = false
production_consensus_activation = false
release_ready = false
```

This slice does not provide the production application nonce-floor verifier,
production CheckTx, transaction execution/broadcast, cross-database commit,
external anti-rollback custody, physical power-loss evidence, independent
review, multi-host campaign, audit, soak, public-testnet readiness, release
readiness or production consensus activation. The sealed verifier seam is an
integration point for a future node-owned application/finality adapter, not
permission to accept caller assertions.
