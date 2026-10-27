"""P0 local journal owner / post-open mutation regressions (not PQ signature tests).

The signed-response verifier is intentionally replaced with an exact immutable
observation so these cases exercise the real SQLite transactions, file identity,
and DDL failures without manufacturing a mock cryptographic acceptance result.
The inherited test_pq_cell_custody.py separately covers genuine ML-DSA-65.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import tempfile
import unittest
from unittest.mock import patch

from pq_envelope import Reject
from pq_cell_custody import OfflineOneUseJournal, RetrievalObservation


A = RetrievalObservation(b'A'*48, b'B'*48, b'C'*32, b'D'*48)
B = RetrievalObservation(b'E'*48, b'F'*48, b'G'*32, b'H'*48)


class JournalOwnerHardeningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='trnm-pq-journal-')
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / 'custody.db'

    def open(self):
        j = OfflineOneUseJournal(self.db)
        self.addCleanup(j.close)
        return j

    def record(self, j, obs=A):
        with patch('pq_cell_custody.verify_response_research', return_value=obs):
            return j.record(b'fixture-not-a-signed-packet')

    def assert_rows(self, n):
        with closing(sqlite3.connect(self.db)) as conn:
            self.assertEqual(conn.execute('SELECT count(*) FROM pq_custody_observation').fetchone()[0], n)

    def test_first_exact_repeat_and_cold_reopen_are_distinct(self):
        j = self.open()
        self.assertEqual(self.record(j)[0], 'FIRST_RECORD')
        self.assertEqual(self.record(j)[0], 'ALREADY_RECORDED')
        j.close()
        # Explicit close does not lose durable result.
        k = self.open()
        self.assertEqual(self.record(k)[0], 'ALREADY_RECORDED')
        self.assert_rows(1)

    def test_created_journal_is_private_single_link_regular_file(self):
        self.open()
        m = os.lstat(self.db)
        self.assertTrue(stat.S_ISREG(m.st_mode))
        self.assertEqual(m.st_nlink, 1)
        self.assertEqual(m.st_mode & 0o077, 0)

    def test_symlink_and_hardlink_leaf_refused_without_writing(self):
        original = self.open()
        self.record(original)
        for which in ('symlink', 'hardlink'):
            alias = Path(self.temp.name) / (which + '.db')
            (os.symlink if which == 'symlink' else os.link)(self.db, alias)
            with self.subTest(which=which), self.assertRaises(Reject):
                OfflineOneUseJournal(alias)
            alias.unlink()
        self.assert_rows(1)

    def test_foreign_empty_file_not_claimed_as_new_owned_store(self):
        self.db.write_bytes(b'')
        os.chmod(self.db, 0o600)
        with self.assertRaisesRegex(Reject, 'empty custody'):
            OfflineOneUseJournal(self.db)

    def test_world_readable_file_refused(self):
        j = self.open()
        j.close()
        os.chmod(self.db, 0o644)
        with self.assertRaisesRegex(Reject, 'owner-only'):
            OfflineOneUseJournal(self.db)

    def test_post_open_trigger_cannot_delete_new_record(self):
        j = self.open()
        with closing(sqlite3.connect(self.db)) as attacker:
            attacker.execute('CREATE TRIGGER erase AFTER INSERT ON pq_custody_observation '
                             'BEGIN DELETE FROM pq_custody_observation; END')
        with self.assertRaisesRegex(Reject, 'schema changed'):
            self.record(j)
        self.assert_rows(0)

    def test_post_open_foreign_table_cannot_make_fake_success(self):
        j = self.open()
        self.record(j)
        with closing(sqlite3.connect(self.db)) as attacker:
            attacker.execute('CREATE TABLE injected(x INTEGER)')
        with self.assertRaisesRegex(Reject, 'schema changed'):
            self.record(j, B)
        self.assert_rows(1)

    def test_schema_injected_after_signature_check_before_write_lock(self):
        j = self.open()
        def concurrent_ddl(*args, **kwargs):
            with closing(sqlite3.connect(self.db)) as attacker:
                attacker.execute('CREATE TRIGGER change_before_ack AFTER INSERT ON '
                                 'pq_custody_observation BEGIN DELETE FROM pq_custody_observation; END')
            return A
        with patch('pq_cell_custody.verify_response_research', side_effect=concurrent_ddl):
            with self.assertRaisesRegex(Reject, 'schema changed'):
                j.record(b'fixture')
        self.assert_rows(0)

    def test_open_file_replacement_refused_even_with_canonical_schema(self):
        j = self.open()
        self.record(j)
        swapped = Path(self.temp.name) / 'copy.db'
        # SQLite online backup produces a well-formed second inode. It does not
        # provide independent rollback security; this is identity replacement.
        with closing(sqlite3.connect(self.db)) as src, closing(sqlite3.connect(swapped)) as dst:
            src.backup(dst)
        os.chmod(swapped, 0o600)
        os.replace(swapped, self.db)
        with self.assertRaisesRegex(Reject, 'replaced after open'):
            self.record(j, B)

    def test_conflicting_observation_has_no_additional_row(self):
        j = self.open()
        self.record(j)
        conflict = RetrievalObservation(A.challenge_id, b'Z'*48, A.provider_key_id, b'Y'*48)
        with self.assertRaisesRegex(Reject, 'same challenge changed'):
            self.record(j, conflict)
        self.assert_rows(1)

    def test_eight_connections_only_one_first(self):
        x = self.open(); x.close()
        def attempt(_):
            j = OfflineOneUseJournal(self.db)
            try:
                return self.record(j)[0]
            finally:
                j.close()
        with ThreadPoolExecutor(max_workers=8) as pool:
            result = list(pool.map(attempt, range(8)))
        self.assertEqual(result.count('FIRST_RECORD'), 1)
        self.assertEqual(result.count('ALREADY_RECORDED'), 7)
        self.assert_rows(1)

    def test_missing_or_relocated_file_does_not_return_success(self):
        j = self.open()
        self.record(j)
        os.rename(self.db, Path(self.temp.name) / 'moved.db')
        with self.assertRaisesRegex(Reject, 'disappeared'):
            self.record(j, B)

if __name__ == '__main__':
    unittest.main()
