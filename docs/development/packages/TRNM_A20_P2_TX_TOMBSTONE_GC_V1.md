# A20 / P2-TX authenticated tombstone GC v1

Status: **candidate-hardened / verification pending / no production activation**

## Exact boundary

```text
repository = TrillionniumFoundation/Trillionnium-Chain
candidate_branch = feature/chain-g1-external-blocker-closure-20260830
candidate_code_closure_commit = c0e309743f9696c8ee8bc035ff4c427df4d0eb25
candidate_code_closure_tree = 3b46b2e72879afb4750aab61ebab955ef2c375d1
candidate_base = 1663abd8935be4e5819f5ff0c7ded250a3664097
implementation_refs = 603bccc32 + 50bf6cdc1 + 7cbca1090 + 53d5818e8
latest_inspected_remote_tip = 9bf9ef2f0cf18183f5a5b0ec459e8affae4d8df5
latest_inspected_remote_tree = 43b00a053971405a8eeb4e4c581d04eaee9ade59
consensus_mainline = native-poco-bft
protocol_target = poco-bft-v0
production_candidate = false
```

The latest remote A20 tip was inspected read-only. Its hosted workflow is a
one-shot, write-capable publisher and is intentionally not part of this
candidate; the exact-head A20 workflow failed, while its required baseline
passed and its payload job was blocked by the trusted self-hosted runner
policy. Only the reviewable Rust/schema slice is carried here; the remote tip
is not treated as accepted or independently signed evidence.

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
`VerifiedTxAdmissionReplayFloorV1` token. The token is minted only after a
crate-owned `TxAdmissionReplayFloorVerifierV1` accepts evidence binding. The
verifier boundary is sealed and the trait/minting method are crate-private:

- repository namespace;
- canonical signer identity;
- highest nonce permanently rejected by application state;
- finalized block height and state root;
- finality-proof digest;
- retention-policy digest.

Purge is signer-local, nonce-bounded, finality-height-bounded and batch-bounded.
A rejected or foreign-namespace floor leaves all tombstones unchanged.

The replay-floor verifier trait and `TxAdmissionReplayFloorEvidenceV1::verify_with`
are crate-private.  The native commit-receipt verifier is also sealed to
crate-owned implementations.  The crate root exports neither the replay trait
nor its minting method, and the native trait's private supertrait blocks an
unconditional `Ok(())` implementation.  Downstream code therefore cannot
manufacture either purge or commit tokens from caller assertions.  Concrete
owners must remain inside this crate until authenticated application/finality
adapters are accepted.

## Path and open fencing

Before opening the database or lock, the candidate validates the canonical
parent and every existing ancestor: directories must be owner/root-controlled
and not group/world writable, with only a root-owned sticky directory (such as
`/tmp`) allowed as the fixture boundary.  The immediate parent is opened with
`O_DIRECTORY|O_NOFOLLOW`, and its device/inode/owner/mode identity is retained
by both the authority and every reservation token.  Parent and child identities
are checked before and after DB/lock opens and around SQLite use; DB/lock files
must be regular, single-link, owner-owned and private, and SQLite is opened with
`SQLITE_OPEN_NOFOLLOW`.  Any mismatch fails closed as `PathReplaced`.

## Storage and restart invariants

- schema version is bumped to v2 with no implicit v1 migration;
- pre-existing v1 databases fail closed rather than silently discarding replay
  history;
- rich rows and tombstones may not overlap;
- all tombstone widths, states, zero/nonzero relations and digests are audited
  on every open;
- the combined rich+tombstone inventory cap is a full-table total across every
  namespace (1,000,000 rows), while replay lookups, validation and retained-row
  reporting remain bound to the opened namespace;
- each compact or purge call is capped at 4,096 rows;
- tombstone digest tamper, cross-table overlap, malformed terminal evidence and
  partial compaction are rejected.

The adjacent G1 process-host ingress now also uses checked generation
successors and rejects a three-block finality-proof horizon that would overflow
before queue/WAL handoff (`c0e309743`).  This protects the candidate host from
stranding a `HandedOff` row at the numeric boundary; it does not turn the A20
nonce-floor seam into a production application owner.

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

The package gate markers for this hardening are
`tx_admission_path_ancestry_identity_fence = true`,
`tx_admission_global_inventory_cap = true`,
`tx_admission_replay_floor_verifier_sealed = true`, and
`tx_admission_native_commit_verifier_sealed = true` in the crate metadata,
plus the exported candidate-only constants
`TX_ADMISSION_WAL_PATH_IDENTITY_FENCE_V0`,
`TX_ADMISSION_WAL_GLOBAL_INVENTORY_CAP_V0`, and
`TX_ADMISSION_REPLAY_FLOOR_VERIFIER_SEALED_V1`, and
`TX_ADMISSION_NATIVE_COMMIT_VERIFIER_SEALED_V1`.  All production/activation
markers remain false.

At the code-closure tree, the A20-focused library run was 158/158 tests and
the tombstone subset was 5/5; strict Clippy and the full payload-recovery gate
also passed.  These are local candidate checks, not external finality or
power-loss evidence.

## Non-claims

This slice does not provide the production application nonce-floor verifier,
production CheckTx, transaction execution/broadcast, cross-database commit,
external anti-rollback custody, physical power-loss evidence, independent
review, multi-host campaign, audit, soak, public-testnet readiness, release
readiness or production consensus activation.  The authenticated application
and finality owner is still absent; keeping the verifier seam crate-private is
an API capability fence, not evidence that production readback exists.
