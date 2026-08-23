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

This is an application/store authority slice only. It does not install Core or
Safety permits, verify QC/finality, provide a remote monotonic watermark,
operate authenticated consensus transport, or activate a validator runtime.
All production and activation flags remain false.
