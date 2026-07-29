# TRNM CometBFT Application Store Runbook

Status: internal devnet prototype. This is not a public-testnet backup claim.

The 2026-07-29 release-profile authenticated-tree gate completed exactly one
million initial objects plus one million updates while retaining 64 proof
versions. It verifies incremental JMT planning, pruning, and ICS23 proof
correctness only. It does not measure this SQLite store's fsync latency,
CometBFT end-to-end commit latency, large-state restart time, or multi-host SLOs.

## Files and authority

For a configured `state_path` such as `app-state.json`:

- `app-state.json.sqlite3` is the authoritative application database.
- `app-state.json.sqlite3-wal` and `app-state.json.sqlite3-shm` may be live while
  the application is running.
- `app-state.json` is only a best-effort height/app-hash status cache. It is
  refreshed from SQLite at startup and must never be used as a backup.
- `app-state.snapshots/*.snapshot` contains bounded ABCI state-sync snapshots.
- No legacy file is rewritten automatically. A v3 source remains byte-for-byte
  unchanged during explicit export/new-genesis review.

Store schema v3 uses SQLite WAL, `synchronous=FULL`, an immediate write
transaction, and an expected-tip compare before every block commit. The same
transaction advances object deltas, validator lifecycle, versioned JMT nodes,
the raw JMT AppHash, and height. The database advances before the status cache; a crash between those
operations recovers from SQLite. Metadata binds chain ID, app version 4, and the
canonical authorized-signer policy. The app hash also commits that immutable
identity through the validator-lifecycle state, so a mismatched fresh state-sync
target rejects the snapshot instead of diverging after recovery.

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
