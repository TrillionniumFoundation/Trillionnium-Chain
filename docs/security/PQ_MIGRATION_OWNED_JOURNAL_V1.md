# PQ Ed25519→ML-DSA migration: strict owned local journal (research)

Exact parent PR #399 at `8dcfb79a80c52955aaed1abc08a65d7a4cd6c6c6`. **Draft / HOLD_NO_GO.**
This is a local accountability hardening of a dual-signature experiment,
not a deployed Chain account migration or post-quantum production activation.

## Security defect and exact remediation

The original `OfflineMigrationJournal` opened arbitrary SQLite files,
ran `CREATE TABLE IF NOT EXISTS` and returned first/repeat success without
canonical-schema verification, temporary-schema rejection or persistent
readback. A same-name TEMP table or AFTER INSERT TEMP trigger can keep the
main table empty while producing an apparent acknowledgement.

Now a new store requires `O_CREAT|O_EXCL|O_NOFOLLOW`, mode `0600`, a
single-link regular file and the exact canonical one-table SQLite schema.
Unknown or empty existing namespaces, symlink/hardlink leaves and legacy
`IF NOT EXISTS` schema are refused, not automatically migrated.
In all real transactions, both `sqlite_master` and `sqlite_temp_master`
are checked under `BEGIN IMMEDIATE`. WAL and FULL durability and original
file inode are rechecked before write, after COMMIT and before ACK.
The exact old-PQ identity/statement/receipt is read back under a newly
acquired write snapshot. If facts become uncertain, the call errors and
requires reconciliation; it MUST NOT be interpreted as `NotDispatched`.

Actual Ed25519 and ML-DSA signature verification in `verify_migration`
is unchanged. New journal tests mock that *separate* cryptographic
verdict only to isolate SQLite behavior; the original real signing
tests remain the authority for offline crypto conformance.

## Exact tests to execute on this candidate

```sh
cd formal/pon-nakamoto-v1
PYTHONWARNINGS=error::ResourceWarning python3 -m unittest -v \
  test_pq_account_migration.py test_pq_migration_journal_owner.py
```

The container used for this increment reproduced the TEMP trigger and
same-name TEMP shadow and that WAL COMMIT can succeed after inode rename,
but the exact repository suite was **not executed** in the tool context.
No inherited CI or historical source hashes are repinned.

## Outstanding gates

This local journal is **not** an independent monotonically anchored
chain identity registry. Malicious same-UID parent/sidecar replacement,
whole-store rollback, compromised signed source heads, competing fork
adoption, public-Network PoN hardness and Sybil attacks, native Rust
signer and HSM integration, old liabilities/nonce migration, independent
multi-host review, real Hepta export/Final-use, and physical power-loss
qualification remain open. The schema change is intentionally
incompatible with old untrusted research journals; migrate such data
only by explicit audited export into a new owned namespace.
