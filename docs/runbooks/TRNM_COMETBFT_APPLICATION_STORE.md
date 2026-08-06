# TRNM CometBFT Application Store Runbook

Status: internal devnet prototype. This is not a public-testnet backup claim.

The 2026-07-29 release-profile authenticated-tree gate completed exactly one
million initial objects plus one million updates while retaining 64 proof
versions. It verifies incremental JMT planning, pruning, and ICS23 proof
correctness only. The separate persistent gate described below exercises the
SQLite `synchronous=FULL` path, restart, budgeted pruning, format-4
snapshot/restore, WAL, and temporary-disk peaks. Neither gate is a multi-host or
public-testnet SLO.

## Files and authority

For a configured `state_path` such as `app-state.json`:

- `app-state.json.sqlite3` is the authoritative application database.
- `app-state.json.sqlite3-wal` and `app-state.json.sqlite3-shm` may be live while
  the application is running.
- `app-state.json` is only a best-effort height/app-hash status cache. It is
  refreshed from SQLite at startup and must never be used as a backup.
- `app-state.snapshots/*.snapshot` contains bounded, normalized SQLite ABCI
  state-sync payloads. The matching `*.snapshot.manifest.json` file is the
  crash-recoverable local catalog entry.
- `app-state.restore/*.sqlite3.part` and `*.journal.json` are format-4 receive
  staging. A repeated offer or process restart verifies completed chunks and
  resumes. Accepting a valid offer removes staging for every other manifest;
  rejecting or completing the active restore removes its pair. The active
  manifest is still allowed up to the protocol's 4-GiB ceiling.
- No legacy file is rewritten automatically. A v3 source remains byte-for-byte
  unchanged during explicit export/new-genesis review.

Store schema v4 uses SQLite WAL, `synchronous=FULL`, an immediate write
transaction, and an expected-tip compare before every block commit. The same
transaction advances object deltas, validator lifecycle, versioned JMT nodes,
the raw JMT AppHash, height, the durable proof-query floor, and successor
indices for stale value versions. The database advances before the status
cache; a crash between those operations recovers from SQLite. Metadata binds
chain ID, app version 5, and the canonical authorized-signer policy. The app
hash also commits that immutable identity through the validator-lifecycle
state, so a mismatched fresh state-sync target rejects the snapshot instead of
diverging after recovery.

Persistent startup keeps only the committed head and validator lifecycle in
memory. Objects, replay lookups, JMT nodes, values, roots, and preimages remain
SQLite-backed; point reads and proof planning use a single pinned read
transaction and fail-stop on storage/authentication errors. The production
path does not rebuild an in-memory JMT or materialize all objects at startup.

## ABCI state sync

Persistent nodes produce snapshot format 4. The producer pins the committed
SQLite read view before releasing the commit lock, runs the SQLite online
backup in a worker, reduces the copy to latest-only JMT history, checkpoints,
switches the copy to rollback-journal mode, vacuums it, and then publishes the
normalized payload followed by an atomically replaced manifest. Only one worker
runs; while it is busy, later interval requests set a catch-up marker without
opening another SQLite read transaction. Once free, the worker pins the then
latest committed head and catches up. Three validated generations are retained.
The producer catalog is reconstructed and invalid/orphaned `.snapshots`
artifacts are removed at startup.

The receiver writes each chunk at its fixed offset, synchronizes it, and
atomically updates a receive journal. It never concatenates format-4 chunks in
RAM. Before installation it verifies the metadata and payload hashes, exact
canonical SQLite schema, `quick_check`, chain/app/signer bindings, latest-only
root shape, absence of future or unreachable JMT rows, every authenticated
object/lifecycle proof, and the local lifecycle authorization policy. Bad
chunks return the requested refetch index and reject the sender. Re-offering
the same manifest preserves verified progress. Before decoding untrusted rows,
the validator also enforces per-row bounds for JMT nodes/values, key preimages,
domain objects, lifecycle state, and identifiers.

All semantic and local-policy checks run before installation. Once SQLite has
accepted the authoritative backup into the live database, a later
checkpoint/fsync/post-validation failure is fail-stop: the process aborts and
must restart from SQLite rather than returning `RejectSnapshot` while retaining
an installed disk head and an empty in-memory head.

Persistent nodes reject legacy format 3 because that compatibility format
retains and concatenates chunks in memory. Format 3 remains available only to
the memory-only test harness.

Height remains authoritative store metadata but is not itself an app-hash leaf.
An empty block therefore advances the durable height without changing the state
root; this is required for CometBFT `create_empty_blocks=false` to quiesce when
application content is unchanged.

The four-validator live fixture injects a one-shot crash after the SQLite
transaction commits but before ABCI `Commit` returns. On restart, the database
height wins over the deliberately stale JSON cache, CometBFT completes its
handshake, and all validators reconverge. The hidden `--unsafe-test-crash-*`
arguments exist only for this loopback evidence gate and must never appear in an
operator service definition.

## Safe backup

Do not copy only the status JSON. Do not copy a live SQLite main file without
its WAL or without using the SQLite backup mechanism.

For the current prototype, the simplest safe procedure is offline:

1. Stop CometBFT transaction ingress.
2. Stop CometBFT and its TRNM ABCI application and verify both processes exited.
3. Use SQLite's backup API or CLI `.backup` against
   `app-state.json.sqlite3`. If using a checkpoint first, run
   `PRAGMA wal_checkpoint(TRUNCATE);` only after the application is stopped.
4. Copy the resulting backup plus the matching CometBFT data/config and record
   chain ID, application version, height, app hash, and file SHA-256 values.
5. Restart and verify `/abci_info` height/app hash against the recorded values.

Copying the live database, WAL, and SHM as unrelated filesystem operations is
not an atomic backup.

## Persistent scale evidence

Run the release-profile smoke gate with:

```bash
TRNM_PERSISTENT_SCALE_PROFILE=smoke \
  trillionnium/scripts/consensus/run_persistent_scale_gate.sh
```

The smoke profile runs 10,000 initial objects and 10,000 updates. The `formal`
profile runs at least 1,000,000 of each and accepts only a clean checked-out
HEAD that it builds itself. Both profiles preserve their evidence directory
and require a valid JSON report, exact workload counts, durable final prune
floor, value-history collection, prune/Commit/snapshot-pin collision, exact
restart, format-4 restore and continuation, and database/snapshot/restore/temp
disk peaks. Multi-chunk snapshots must resume across a receiver restart. The
formal profile additionally requires a release build, million-gate
classification, nonzero WAL observation, a working systemd user
`MemoryMax=3G` scope, and hashed `report.json` and `/usr/bin/time` evidence.

The workload is deliberately single-process and single-host. It bypasses
CometBFT transaction transport and therefore must not be presented as
end-to-end validator latency or public-testnet evidence.

## Current scale boundary

The format-4 tests include a multi-chunk payload, repeated offer, receive-journal
restart, hostile future/unreachable rows, mutated DDL, signer-policy rebinding,
and restart/catalog retention. The persistent scale gate adds the production
SQLite planning/fsync path and large-state recovery measurements.

The remaining scale blockers are explicit:

- production retained-history deletion is successor-indexed and runs outside
  `Commit` in row/logical-byte/time-budgeted transactions. It yields to a
  waiting consensus writer and to pinned snapshots. The final retained
  lifecycle proofs and SQLite fsync are still scale- and disk-dependent;
- startup and hostile-snapshot validation are memory-bounded but still perform
  full-tree work;
- live-store preimages remain bounded by distinct historical keys rather than
  the proof-retention window; latest-only snapshots collect dead-key
  preimages;
- a pinned online backup can retain WAL pages until the worker finishes, and
  `VACUUM` requires additional temporary disk;
- the current protocol limit is 4096 one-MiB chunks (4 GiB);
- the active receive stage can therefore consume 4 GiB before semantic
  validation; there is not yet a deployment-level disk reservation or
  time/work budget for hostile full-tree verification;
- disk-full/OOM/clock-skew recovery, multi-host P95/P99, and long-duration soak
  remain outside this single-host gate.

## Restore

Prefer a fresh node plus light-client-verified ABCI state sync when healthy
peers are available.

For an offline database restore:

1. Keep CometBFT and the ABCI application stopped.
2. Preserve the failed database and logs as evidence; do not overwrite them.
3. Restore the SQLite backup to the exact configured database path.
4. Remove only a stale status JSON cache; never delete an unexamined WAL.
5. Start the ABCI application first. It must fail closed on chain ID, app
   version, object-value hash, or aggregate app-hash mismatch.
6. Start CometBFT and verify its height/app hash converges with `/abci_info`.

## Migration

Startup never imports `trnm_cometbft_app_state_v3` in place because changing the
AppHash at an already committed height would break the CometBFT handshake.
Instead run `trnm-v3-export-new-genesis` as documented in
`TRNM_V3_TO_V4_EXPORT_NEW_GENESIS.md`. It verifies the complete legacy root and
creates an atomic, review-only bundle for a different chain ID. It does not
produce a ready-to-start node: operators must review and sign the new genesis,
and rollback remains the unchanged v3 network until cutover.

Application state v2 and store schemas 1/2 are also not auto-migrated.
