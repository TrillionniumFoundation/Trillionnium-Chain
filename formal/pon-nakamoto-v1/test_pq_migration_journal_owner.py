"""SQLite migration journal adversarial tests; crypto is independently covered elsewhere.

These tests mock *only* the successful dual-signature verdict, isolating the
actual owned SQLite write/readback. They grant no PQ migration or ledger authority.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from pq_envelope import Reject
from pq_account_migration import (
    MigrationStatement, SignedMigration, OfflineMigrationJournal,
)

N = b"N"*32
O = b"O"*32
K = b"K"*32
H = b"H"*32
RECEIPT = b"R"*48
STMT = MigrationStatement(N, O, K, H, 3, 5, 9999)
PROOF = SignedMigration(STMT, b"", b"")


class OwnedMigrationJournalTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="trnm-pq-owned-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.path = self.root / "migration.db"

    def open(self):
        j = OfflineMigrationJournal(self.path)
        self.addCleanup(j.close)
        return j

    @staticmethod
    def consume(j, proof=PROOF):
        with patch("pq_account_migration.verify_migration", return_value=RECEIPT):
            return j.consume(proof, new_public_pem=b"", expected_network=N,
                             expected_old_pub=proof.statement.old_ed25519_pub,
                             expected_authority_head=H, expected_generation=3,
                             expected_sequence=5, now=1)

    def rows(self):
        with closing(sqlite3.connect(self.path)) as db:
            return db.execute("SELECT count(*) FROM main.pq_migration").fetchone()[0]

    def test_honest_commit_repeat_cold_reopen(self):
        j = self.open()
        self.assertEqual(self.consume(j)[0], "FIRST_RECORD")
        self.assertEqual(self.consume(j)[0], "ALREADY_RECORDED")
        j.close()
        k = self.open()
        self.assertEqual(self.consume(k)[0], "ALREADY_RECORDED")
        self.assertEqual(self.rows(), 1)

    def test_legacy_if_not_exists_or_foreign_schema_not_silently_claimed(self):
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("CREATE TABLE pq_migration(network BLOB, old_pub BLOB, "
                       "new_key_id BLOB, statement BLOB, receipt BLOB)")
        os.chmod(self.path, 0o600)
        with self.assertRaisesRegex(Reject, "foreign"):
            OfflineMigrationJournal(self.path)

    def test_symlink_and_hardlink_refused(self):
        j = self.open()
        for alias_name, linker in (("alias.db", os.symlink), ("other.db", os.link)):
            alias = self.root / alias_name
            linker(self.path, alias)
            with self.assertRaises(Reject):
                OfflineMigrationJournal(alias)
            alias.unlink()

    def test_temp_trigger_never_acknowledges_deleted_commit(self):
        j = self.open()
        j.db.execute("CREATE TEMP TRIGGER erase AFTER INSERT ON pq_migration "
                     "BEGIN DELETE FROM pq_migration; END")
        with self.assertRaisesRegex(Reject, "temporary SQLite"):
            self.consume(j)
        self.assertEqual(self.rows(), 0)

    def test_temp_shadow_table_cannot_replace_persistent_records(self):
        j = self.open()
        j.db.execute("CREATE TEMP TABLE pq_migration("
                     "network BLOB, old_pub BLOB, new_key_id BLOB, "
                     "statement BLOB, receipt BLOB)")
        with self.assertRaisesRegex(Reject, "temporary SQLite"):
            self.consume(j)
        self.assertEqual(self.rows(), 0)

    def test_mid_transaction_rename_never_acknowledged(self):
        j = self.open()
        moved = self.root / "renamed.db"
        old_audit = j._audit_owned_schema
        once = False

        def relocate_after_audit():
            nonlocal once
            old_audit()
            if not once:
                os.rename(self.path, moved)
                once = True

        with patch.object(j, "_audit_owned_schema", side_effect=relocate_after_audit):
            with self.assertRaisesRegex(Reject, "disappeared"):
                self.consume(j)
        self.assertTrue(moved.exists())
        self.assertFalse(self.path.exists())

    def test_owner_only_permissions_checked(self):
        j = self.open()
        j.close()
        os.chmod(self.path, 0o644)
        with self.assertRaisesRegex(Reject, "owner-only"):
            OfflineMigrationJournal(self.path)

    def test_eight_concurrent_writers_exactly_one_first(self):
        self.open().close()

        def attempt(_):
            journal = OfflineMigrationJournal(self.path)
            try:
                return journal.consume(
                    PROOF, new_public_pem=b"", expected_network=N,
                    expected_old_pub=O, expected_authority_head=H,
                    expected_generation=3, expected_sequence=5, now=1)[0]
            finally:
                journal.close()

        # Patch the crypto verdict ONCE for all threads, not individually
        # per call: overlapping mock.patch scopes can restore each other.
        with patch("pq_account_migration.verify_migration", return_value=RECEIPT):
            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(attempt, range(8)))
        self.assertEqual(results.count("FIRST_RECORD"), 1)
        self.assertEqual(results.count("ALREADY_RECORDED"), 7)
        self.assertEqual(self.rows(), 1)


if __name__ == "__main__":
    unittest.main()
