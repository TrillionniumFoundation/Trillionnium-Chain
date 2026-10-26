"""Run independently of Chain: SQLite paid-only issuer/receiver crash controls."""
import multiprocessing as mp
import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from w2c_sqlite_spend_owner import SqlitePaidSpendOwner


def worker(path, context, key, queue):
    try:
        owner = SqlitePaidSpendOwner(path, context, capacity=4)
        queue.put(owner.claim(key, 2000, 100))
    except Exception as exc:
        queue.put(('ERROR', str(exc)))


def crash_after_spend(path, context, key):
    owner = SqlitePaidSpendOwner(path, context, capacity=4)
    code = owner.claim(key, 2000, 100)
    os._exit(0 if code == 'READY_RESOURCE_ONLY' else 1)


class DurablePaidSpendTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / 'spent.sqlite')
        self.context = bytes.fromhex('a4' * 32)
        self.owner = SqlitePaidSpendOwner(self.path, self.context, capacity=4)

    def test_one_real_paid_grant_and_replay_after_reopen(self):
        key = bytes([11]) * 32
        self.assertEqual(self.owner.claim(key, 2000, 100), 'READY_RESOURCE_ONLY')
        opened = SqlitePaidSpendOwner(self.path, self.context, capacity=4)
        self.assertEqual(opened.claim(key, 2000, 100), 'REPLAY')
        self.assertEqual(opened.pending_paid(), 1)

    def test_thirty_two_threads_get_one_ready(self):
        key = bytes([15]) * 32
        with ThreadPoolExecutor(max_workers=8) as executor:
            observed = list(executor.map(
                lambda _: self.owner.claim(key, 2000, 100), range(32)))
        self.assertEqual(observed.count('READY_RESOURCE_ONLY'), 1)
        self.assertEqual(observed.count('REPLAY'), 31)

    def test_multiple_real_processes_share_one_atomic_paid_slot(self):
        ctx = mp.get_context('spawn')
        results = ctx.Queue()
        key = bytes([13]) * 32
        processes = [ctx.Process(target=worker, args=(self.path, self.context, key, results)) for _ in range(6)]
        for process in processes:
            process.start()
        responses = [results.get(timeout=20) for _ in processes]
        for process in processes:
            process.join(timeout=20)
            self.assertEqual(process.exitcode, 0)
        self.assertEqual(responses.count('READY_RESOURCE_ONLY'), 1, responses)
        self.assertEqual(responses.count('REPLAY'), 5, responses)

    def test_real_child_exit_after_commit_does_not_refund(self):
        ctx = mp.get_context('spawn')
        key = bytes([27]) * 32
        child = ctx.Process(target=crash_after_spend, args=(self.path, self.context, key))
        child.start()
        child.join(timeout=20)
        self.assertEqual(child.exitcode, 0)
        after = SqlitePaidSpendOwner(self.path, self.context, capacity=4)
        self.assertEqual(after.claim(key, 2000, 100), 'REPLAY')

    def test_capacity_expiration_and_monotonic_watermark_survive_restart(self):
        for i in range(4):
            self.assertEqual(self.owner.claim(bytes([i + 1]) * 32, 300, 100), 'READY_RESOURCE_ONLY')
        key = bytes([9]) * 32
        self.assertEqual(self.owner.claim(key, 300, 110), 'PAID_CAPACITY_BUSY')
        self.assertEqual(self.owner.claim(key, 3000, 300), 'READY_RESOURCE_ONLY')
        after = SqlitePaidSpendOwner(self.path, self.context, capacity=4)
        self.assertEqual(after.claim(bytes([1])*32, 3000, 100), 'CLOCK_REGRESSION')
        self.assertEqual(after.claim(key, 3000, 301), 'REPLAY')

    def test_fresh_context_cannot_claim_existing_owner_database(self):
        with self.assertRaisesRegex(ValueError, 'OWNER_CONTEXT_MISMATCH'):
            SqlitePaidSpendOwner(self.path, bytes([8]) * 32)
        self.assertEqual(self.owner.pending_paid(), 0)

    def test_copied_database_separate_owner_still_not_safe(self):
        first = bytes([42]) * 32
        self.assertEqual(self.owner.claim(first, 2000, 100), 'READY_RESOURCE_ONLY')
        # A clone without the same original durable journal can accept the
        # exact same ticket. This is an explicit FAIL/negative security scope.
        separate = SqlitePaidSpendOwner(str(Path(self.tmp.name) / 'other.sqlite'),self.context)
        self.assertEqual(separate.claim(first, 2000, 100), 'READY_RESOURCE_ONLY')

    def test_untrusted_files_or_bad_ranges_refused(self):
        bad = Path(self.tmp.name) / 'symlink.sqlite'
        bad.symlink_to(self.path)
        with self.assertRaisesRegex(ValueError, 'OWNER_FILE'):
            SqlitePaidSpendOwner(str(bad), self.context)
        with self.assertRaisesRegex(ValueError, 'PAID_KEY'):
            self.owner.claim(b'x', 300, 10)
        with self.assertRaisesRegex(ValueError, 'EXPIRES_MS'):
            self.owner.claim(bytes(32), 1<<64, 10)
        self.assertEqual(self.owner.pending_paid(), 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
