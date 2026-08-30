# A20 / P2-TX authenticated tombstone GC v1

Status: **candidate-implemented / verification pending / no production activation**

## Exact boundary

```text
repository = TrillionniumFoundation/Trillionnium-Chain
candidate_branch = feature/chain-g1-external-blocker-closure-20260830
candidate_base = 1663abd8935be4e5819f5ff0c7ded250a3664097
implementation_refs = 603bccc32, 50bf6cdc1
latest_inspected_remote_tip = 7bc87e153a3d4c6426ff9e0a22e8469923d7ffe4
consensus_mainline = native-poco-bft
protocol_target = poco-bft-v0
production_candidate = false
```

The latest remote A20 tip was inspected read-only. Its hosted workflow is a
one-shot, self-modifying publisher with write permissions and is intentionally
not part of this candidate; its exact-head typed SQLite fixture run also
failed. Only the reviewable Rust/schema/doc slice is carried here; the
candidate source commit and tree are derived again at verification time.

The existing transaction-admission WAL retains every committed or released row
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
re-open either `(signer, nonce)` or transaction digest authority.

## Authenticated purge contract

A compact tombstone can be physically deleted only with a private
`VerifiedTxAdmissionReplayFloorV1` token. The token is minted only after an
owner-installed `TxAdmissionReplayFloorVerifierV1` accepts evidence binding:

- repository namespace;
- canonical signer identity;
- highest nonce permanently rejected by application state;
- finalized block height and state root;
- finality-proof digest;
- retention-policy digest.

Purge is signer-local, nonce-bounded, finality-height-bounded and batch-bounded.
A rejected or foreign-namespace floor leaves all tombstones unchanged.

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

## Required exact-head verification

```text
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
cargo check --manifest-path trillionnium/Cargo.toml --workspace --all-targets --locked
cargo clippy --manifest-path trillionnium/Cargo.toml \
  -p trnm-poco-node --features tx-admission-wal --lib --locked -- -D warnings
cargo test --manifest-path trillionnium/Cargo.toml \
  -p trnm-poco-node --features tx-admission-wal --lib \
  tx_admission_wal::tombstone_gc_tests_v1 -- --nocapture
cargo test --manifest-path trillionnium/Cargo.toml \
  -p trnm-poco-node --features tx-admission-wal --lib \
  tx_admission_wal::tests -- --nocapture
```

## Non-claims

This slice does not provide the production application nonce-floor verifier,
production CheckTx, transaction execution/broadcast, cross-database commit,
external anti-rollback custody, physical power-loss evidence, independent
review, multi-host campaign, audit, soak, public-testnet readiness, release
readiness or production consensus activation. The generic verifier seam is an
integration point, not permission to accept caller assertions.
