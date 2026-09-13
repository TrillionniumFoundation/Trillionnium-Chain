# Native application commit coordinator — v0 review slice

This review slice audits the active single-node authority path in
`trnm-native-execution-v0`.

```text
exact parent head
  -> execute complete block
  -> BlockId-keyed durable P / overlay DAG (SQLite transaction)
  -> Core-independent confirmation/readback
  -> ordered successor commit (metadata CAS + P CAS + losing-sibling prune)
  -> database fsync + containing-directory fsync
  -> fresh immutable readback
```

The commit coordinator accepts only the exact child of the current committed
head. Sibling prepared overlays coexist by `BlockId`; committing one child
prunes only prepared siblings that are not descendants of that child. A second
commit request for the same `BlockId` returns the existing head/sequence without
writing again. A lost return after SQLite commit is resolved by exact readback,
not by replaying application writes.

The branch adds three local durability checks:

- a subprocess `SIGKILL` immediately before SQLite commit, immediately after
  commit, and after database/directory fsync;
- startup repair for a regular hot rollback journal through SQLite's own
  write-transaction rollback path; malformed or WAL/SHM sidecars remain
  fail-closed; and
- critical-page SQLite short-write images, which must be rejected rather than
  normalized.

The tests also retry the pre-commit case and issue a duplicate commit after
each post-commit case, checking exact head/sequence and recovery disposition.

## Machine-readable crash/WAL contract

The active crate manifest's `[package.metadata.trnm]` table is a closed,
machine-readable inventory. `scripts/ci/check_trnm_native_execution_v0_boundary.sh`
compares that table exactly; adding, removing, or changing a durability fact
must update the manifest and this gate together. The current crash/recovery
fields mean:

- `commit_directory_fsync_attempted=true`: the commit coordinator attempts a
  database and containing-directory fsync before fresh readback;
- `sigkill_commit_boundary_matrix=true` and
  `short_write_reopen_fail_closed=true`: the local SIGKILL and critical-page
  short-write cases are covered by the Rust test matrix;
- `automatic_hot_rollback_journal_recovery=true`: only a regular, verifiable
  SQLite rollback journal may be repaired through SQLite's own transaction
  rollback path; and
- `automatic_wal_recovery=false`: WAL/SHM sidecars are not auto-recovered and
  remain fail-closed until a separately owned checkpoint/state-sync path exists.

These are application/store evidence flags only. They do not grant Core or
Safety authority and do not change `production_candidate=false`.

This is an application/store authority slice only. It does not install Core or
Safety permits, verify QC/finality, provide a remote monotonic watermark,
operate authenticated consensus transport, or activate a validator runtime.
All production and activation flags remain false.
