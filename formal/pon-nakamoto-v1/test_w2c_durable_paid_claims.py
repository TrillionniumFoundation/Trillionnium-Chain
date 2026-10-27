"""Cross-process negative controls. No transport, full W1 or consensus authority."""
from concurrent.futures import ProcessPoolExecutor
import base64
import pickle
import subprocess
import sys
import multiprocessing
import os
import sqlite3
from pathlib import Path
import shutil
import tempfile
import unittest

from contract_wire import H
from w2c_durable_paid_claims import DurableStatelessReceiver, provision
from w2c_receiver_admission import solve

R = bytes([0x52]) * 32
S = bytes([0x53]) * 32
E = bytes([0x45]) * 32
A = bytes([0x41]) * 32
P = H('immutable-W2C-durable-test-proposal')


def use_fresh_process(args):
    file, grant, nonce, caller, now, cap = args
    receiver = DurableStatelessReceiver(R, S, E, db_path=file, capacity=cap)
    return receiver.consume(grant, P, caller, nonce, now)


class DurableReceiverTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.file = str(Path(self.tmp.name) / 'paid.db')
        provision(self.file, R, E, capacity=4)
        self.server = DurableStatelessReceiver(R, S, E, db_path=self.file, capacity=4)

    def grant(self, server=None):
        server = server or self.server
        grant = server.offer(P, A, 8, 100)
        nonce, cost = solve(grant, 16384)
        self.assertIsNotNone(nonce)
        self.assertEqual(cost['status'], 'TARGET_HIT_UNVERIFIED')
        return grant, nonce

    def test_cloned_process_epoch_share_one_durable_paid_claim(self):
        grant, nonce = self.grant()
        args = (self.file, grant, nonce, A, 120, 4)
        with ProcessPoolExecutor(max_workers=4, mp_context=multiprocessing.get_context('spawn')) as pool:
            out = list(pool.map(use_fresh_process, [args] * 12))
        self.assertEqual(out.count('READY_RESOURCE_ONLY'), 1, out)
        self.assertEqual(out.count('REPLAY'), 11, out)
        self.assertEqual(self.server.consume(grant, P, A, nonce, 120), 'REPLAY')

    def test_crash_after_commit_before_w1_does_not_refund(self):
        grant, nonce = self.grant()
        with ProcessPoolExecutor(max_workers=1, mp_context=multiprocessing.get_context('spawn')) as pool:
            self.assertEqual(pool.submit(use_fresh_process, (self.file, grant, nonce, A, 130, 4)).result(),
                             'READY_RESOURCE_ONLY')
        restarted = DurableStatelessReceiver(R, S, E, db_path=self.file, capacity=4)
        self.assertEqual(restarted.consume(grant, P, A, nonce, 131), 'REPLAY')

    def test_remote_claim_rejects_mutated_caller_without_consuming(self):
        grant, nonce = self.grant()
        self.assertEqual(self.server.consume(grant, P, bytes([99])*32, nonce, 120), 'CONTEXT')
        self.assertEqual(self.server.consume(grant, P, A, nonce, 121), 'READY_RESOURCE_ONLY')

    def test_persistent_monotonic_high_watermark(self):
        grant, nonce = self.grant()
        self.assertEqual(self.server.consume(grant, P, A, nonce, 150), 'READY_RESOURCE_ONLY')
        clone = DurableStatelessReceiver(R, S, E, db_path=self.file, capacity=4)
        fresh = clone.offer(P, A, 8, 110)
        n, _ = solve(fresh, 16384)
        self.assertEqual(clone.consume(fresh, P, A, n, 120), 'SPEND_OWNER_CLOCK_REGRESSION')

    def test_database_disappearance_fails_closed_after_paid_ticket(self):
        grant, nonce = self.grant()
        os.rename(self.file, self.file + '.gone')
        self.assertEqual(self.server.consume(grant, P, A, nonce, 120), 'SPEND_OWNER_UNAVAILABLE')

    def test_full_global_paid_capacity_is_not_free_w1(self):
        grants = [self.grant() for _ in range(5)]
        for i, (grant, nonce) in enumerate(grants):
            issuer = DurableStatelessReceiver(R, S, E, db_path=self.file, capacity=4)
            out = issuer.consume(grant, P, A, nonce, 120)
            self.assertEqual(out, 'READY_RESOURCE_ONLY' if i < 4 else 'PAID_CAPACITY_BUSY')

    def test_copied_epoch_without_shared_store_still_replays(self):
        grant, nonce = self.grant()
        self.assertEqual(self.server.consume(grant, P, A, nonce, 120), 'READY_RESOURCE_ONLY')
        other_temp = tempfile.TemporaryDirectory()
        self.addCleanup(other_temp.cleanup)
        other = str(Path(other_temp.name) / 'paid.db')
        provision(other, R, E, capacity=4)
        clone = DurableStatelessReceiver(R, S, E, db_path=other, capacity=4)
        # Explicit retained failure: distinct databases with cloned credentials
        # defeat global exactly-once admission across hosts.
        self.assertEqual(clone.consume(grant, P, A, nonce, 120), 'READY_RESOURCE_ONLY')

    def test_abrupt_exit_after_commit_before_w1_retains_paid_record(self):
        grant, nonce = self.grant()
        payload = base64.b64encode(pickle.dumps(
            (self.file, grant, nonce, A, 120, 4))).decode('ascii')
        # A separate process commits one paid claim, writes the result to its
        # raw stdout FD and exits without Python cleanup or any W1 replay.
        code = (
            'import os,sys,pickle,base64; '
            'from test_w2c_durable_paid_claims import use_fresh_process; '
            'args=pickle.loads(base64.b64decode(sys.argv[1])); '
            'result=use_fresh_process(args); '
            'os.write(1,result.encode()); os._exit(0)'
        )
        child = subprocess.run([sys.executable, '-c', code, payload],
                               capture_output=True, timeout=15, check=True)
        self.assertEqual(child.stdout, b'READY_RESOURCE_ONLY')
        restarted = DurableStatelessReceiver(R, S, E, db_path=self.file, capacity=4)
        self.assertEqual(restarted.consume(grant, P, A, nonce, 121), 'REPLAY')

    def test_different_capacity_or_epoch_cannot_mint_larger_claim_budget(self):
        with self.assertRaisesRegex(ValueError, 'SPEND_OWNER_POLICY'):
            DurableStatelessReceiver(R, S, E, db_path=self.file, capacity=1024)
        with self.assertRaisesRegex(ValueError, 'SPEND_OWNER_POLICY'):
            DurableStatelessReceiver(R, S, bytes([6])*32, db_path=self.file, capacity=4)

    def test_live_database_policy_change_fails_before_w1(self):
        grant, nonce = self.grant()
        db = sqlite3.connect(self.file)
        db.execute('UPDATE policy SET capacity=1024 WHERE singleton=1')
        db.commit()
        db.close()
        self.assertEqual(self.server.consume(grant, P, A, nonce, 120), 'SPEND_OWNER_POLICY')

    def test_modified_schema_cannot_be_restarted_as_free_epoch(self):
        db = sqlite3.connect(self.file)
        db.execute('PRAGMA user_version=2')
        db.commit()
        db.close()
        with self.assertRaisesRegex(ValueError, 'SPEND_OWNER_SCHEMA'):
            DurableStatelessReceiver(R, S, E, db_path=self.file, capacity=4)

    def test_bad_unowned_paths_and_missing_schema_fail_closed(self):
        with self.assertRaisesRegex(ValueError, 'ABSOLUTE_PATH'):
            provision('relative-paid.db', R, E, capacity=4)
        link = str(Path(self.tmp.name) / 'link.db')
        os.symlink(self.file, link)
        with self.assertRaisesRegex(ValueError, 'SPEND_OWNER_FILE'):
            DurableStatelessReceiver(R, S, E, db_path=link)


if __name__ == '__main__':
    unittest.main(verbosity=2)
