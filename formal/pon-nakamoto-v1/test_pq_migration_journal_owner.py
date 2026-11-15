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
REUSED_KEY_PROOF = SignedMigration(
    MigrationStatement(N, b"P"*32, K, H, 3, 5, 9999), b"", b"")
DISTINCT_PROOF = SignedMigration(
    MigrationStatement(N, b"P"*32, b"Q"*32, H, 3, 5, 9999), b"", b"")


class OwnedMigrationJournalTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="trnm-pq-owned-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.path = self.root / "migration.db"

    def open(self, path=None):
        j = OfflineMigrationJournal(path or self.path)
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

    @staticmethod
    def records(path):
        with closing(sqlite3.connect(path)) as db:
            return db.execute(
                "SELECT network,old_pub,new_key_id,statement,receipt "
                "FROM main.pq_migration ORDER BY network,old_pub").fetchall()

    def assert_unchanged(self, journal, records, changes):
        self.assertFalse(journal.db.in_transaction)
        self.assertEqual(journal.db.total_changes, changes)
        self.assertEqual(self.records(journal.path), records)

    @staticmethod
    def install_erasing_trigger(journal, name, *, temporary=False):
        # A hidden trigger can erase the first fact before UNIQUE is checked,
        # then leave the new row intact for a misleading successful readback.
        qualifier = "TEMP " if temporary else ""
        journal.db.execute(
            f'CREATE {qualifier}TRIGGER "{name}" BEFORE INSERT ON main.pq_migration '
            "BEGIN DELETE FROM pq_migration "
            "WHERE network=NEW.network AND new_key_id=NEW.new_key_id; END")

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

    def test_sqlite_lookalike_persistent_trigger_rejected_on_cold_open(self):
        for name in ("sqliteXerase_prior", "sqliteYerase_prior"):
            with self.subTest(name=name):
                path = self.root / f"{name}.db"
                j = self.open(path)
                self.assertEqual(self.consume(j)[0], "FIRST_RECORD")
                before = self.records(path)
                self.install_erasing_trigger(j, name)
                j.close()
                with self.assertRaisesRegex(Reject, "foreign"):
                    with closing(OfflineMigrationJournal(path)):
                        pass
                self.assertEqual(self.records(path), before)

    def test_sqlite_lookalike_persistent_trigger_cannot_erase_or_reuse_key(self):
        for name in ("sqliteXerase_prior", "sqliteYerase_prior"):
            with self.subTest(name=name):
                j = self.open(self.root / f"{name}.db")
                self.assertEqual(self.consume(j)[0], "FIRST_RECORD")
                self.install_erasing_trigger(j, name)
                before = self.records(j.path)
                changes = j.db.total_changes
                with self.assertRaisesRegex(Reject, "foreign"):
                    self.consume(j, REUSED_KEY_PROOF)
                self.assert_unchanged(j, before, changes)
                j.db.execute(f'DROP TRIGGER "{name}"')
                with self.assertRaisesRegex(Reject, "PQ key reused by another old account"):
                    self.consume(j, REUSED_KEY_PROOF)
                self.assert_unchanged(j, before, changes)
                self.assertEqual(self.consume(j)[0], "ALREADY_RECORDED")

    def test_sqlite_lookalike_persistent_table_rejected_on_consume_and_cold_open(self):
        for name in ("sqliteXeffects", "sqliteYeffects"):
            for operation in ("consume", "cold_open"):
                with self.subTest(name=name, operation=operation):
                    path = self.root / f"{name}-{operation}.db"
                    j = self.open(path)
                    self.assertEqual(self.consume(j)[0], "FIRST_RECORD")
                    j.db.execute(f'CREATE TABLE "{name}"(value INTEGER)')
                    before = self.records(path)
                    changes = j.db.total_changes
                    if operation == "consume":
                        with self.assertRaisesRegex(Reject, "foreign"):
                            self.consume(j, DISTINCT_PROOF)
                        self.assert_unchanged(j, before, changes)
                    else:
                        j.close()
                        with self.assertRaisesRegex(Reject, "foreign"):
                            with closing(OfflineMigrationJournal(path)):
                                pass
                        self.assertEqual(self.records(path), before)
                    with closing(sqlite3.connect(path)) as db:
                        self.assertEqual(db.execute(
                            f'SELECT count(*) FROM "{name}"').fetchone(), (0,))

    def test_sqlite_lookalike_temp_trigger_cannot_erase_or_reuse_key(self):
        for name in ("sqliteXerase_prior", "sqliteYerase_prior"):
            with self.subTest(name=name):
                j = self.open(self.root / f"{name}.db")
                self.assertEqual(self.consume(j)[0], "FIRST_RECORD")
                self.install_erasing_trigger(j, name, temporary=True)
                before = self.records(j.path)
                changes = j.db.total_changes
                with self.assertRaisesRegex(Reject, "temporary SQLite"):
                    self.consume(j, REUSED_KEY_PROOF)
                self.assert_unchanged(j, before, changes)
                j.db.execute(f'DROP TRIGGER temp."{name}"')
                with self.assertRaisesRegex(Reject, "PQ key reused by another old account"):
                    self.consume(j, REUSED_KEY_PROOF)
                self.assert_unchanged(j, before, changes)
                self.assertEqual(self.consume(j)[0], "ALREADY_RECORDED")

    def test_sqlite_lookalike_temp_table_rejected_before_write(self):
        for name in ("sqliteXeffects", "sqliteYeffects"):
            with self.subTest(name=name):
                j = self.open(self.root / f"{name}.db")
                self.assertEqual(self.consume(j)[0], "FIRST_RECORD")
                j.db.execute(f'CREATE TEMP TABLE "{name}"(value INTEGER)')
                before = self.records(j.path)
                changes = j.db.total_changes
                with self.assertRaisesRegex(Reject, "temporary SQLite"):
                    self.consume(j, DISTINCT_PROOF)
                self.assert_unchanged(j, before, changes)
                self.assertEqual(j.db.execute(
                    f'SELECT count(*) FROM temp."{name}"').fetchone(), (0,))
                j.db.execute(f'DROP TABLE temp."{name}"')
                self.assertEqual(self.consume(j, DISTINCT_PROOF)[0], "FIRST_RECORD")
                self.assertEqual(self.consume(j)[0], "ALREADY_RECORDED")

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
