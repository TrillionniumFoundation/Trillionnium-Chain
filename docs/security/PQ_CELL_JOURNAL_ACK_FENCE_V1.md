# PQ Cell custody: temporary-schema and post-commit acknowledgement fence (research only)

Parent: PR #472, exact source `ba33e276be15bbb2f29e83fe5d54c60c7948a22e`.
Development target: PQ Cell M09 / `OfflineOneUseJournal`; **HOLD_NO_GO**.
This is not an upgrade of installed PoN consensus, Ed25519 transactions,
W1/PNW1, mining, model-release authority or Hepta Final-use.

## Attacks reproduced

1. `sqlite_master` alone does not expose connection-local `sqlite_temp_master`.
   A same-connection `CREATE TEMP TRIGGER ... AFTER INSERT` may delete an
   inserted observation while the original journal returns `FIRST_RECORD`.
2. A same-name TEMP table can shadow the persistent observation table, causing
   the original unqualified INSERT/SELECT to act on TEMP while acknowledging
   an observation absent from the actual WAL-backed store.
3. SQLite commits can complete on an unlinked/renamed DB inode. If the leaf is
   moved after the pre-write file/schema check, the original implementation
   could return `FIRST_RECORD` or `ALREADY_RECORDED` against an inaccessible
   path. An existing reader's handle alone does not prove the named store exists.

## Incremental protection

* Fail closed if any non-internal temporary schema object is present, in the
  same owned `BEGIN IMMEDIATE` transaction that checks the primary DDL.
* After the original commit, reacquire an owned write snapshot, recheck
  primary/TEMP schema, WAL/FULL, inode identity and the exact durable
  `challenge_id -> (response_digest, provider_key_id)` fact.
* Recheck the named inode before acknowledging either first or repeated
  observation. If commit occurred but readback cannot be trusted, return an
  error and require reconciliation; never reinterpret it as not dispatched.
* The journal still does not produce `VerifiedWork`, `Chainwork`, a custody
  payment, model-release authority or a local `FinalUse`.

## Reproduction / negative regression

```sh
cd formal/pon-nakamoto-v1
PYTHONWARNINGS=error::ResourceWarning python3 -m unittest -v \
  test_pq_cell_custody_journal_hardening.py
```

New regression selectors:
`test_temp_trigger_cannot_erase_an_acknowledged_row`,
`test_temp_table_cannot_shadow_the_persistent_journal`,
`test_filename_rename_inside_precommit_lock_never_acks_first_write`,
`test_filename_rename_inside_precommit_lock_never_acks_repeat`.
Existing 12 tests remain unchanged. Test commands are specified for execution
on this exact source: **they have not been run in a full checked-out repository
in the tool environment of this commit.** The SQLite primitives were reproduced
independently on SQLite 3.46.1; this is not source-qualified suite evidence.

## Blockers not closed

No SQLite-local fix proves safety under the same-UID malicious ancestor/sidecar
controller, externally coordinated DB rollback, physical power loss, compromised
independent witness majority, public P2P Sybil attack, long-term data
availability or adversarial signed storage proofs. Production requires separately
provisioned independent monotonic anchors, real native node integration,
quantum-effective PoN security analysis and external cryptographic acceptance.
