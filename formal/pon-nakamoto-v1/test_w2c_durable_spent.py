"""Real cross-process SQLite test, not physical-host or W1 consensus testing."""
import multiprocessing
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from w2c_durable_spent import DurablePaidSpendOwner as Owner, OwnerUnavailable

R = b'R' * 32
E = b'E' * 32
K = b'K' * 32


def spend_child(args):
    path, nonce = args
    owner = Owner(path, R, E, capacity=4)
    return owner.spend(K, 2000, 110 + nonce)


class TestDurableOwner(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        os.chmod(self.root, 0o700)
        self.path = self.root / 'paid.sqlite'
        self.owner = Owner(self.path, R, E, capacity=4)

    def tearDown(self):
        self.tmp.cleanup()

    def test_real_cross_process_same_paid_grant_exactly_once(self):
        # Spawn produces independent SQLite connections and interpreter state.
        with multiprocessing.get_context('spawn').Pool(8) as pool:
            verdicts = pool.map(spend_child, [(str(self.path), i) for i in range(24)])
        self.assertEqual(verdicts.count('READY_RESOURCE_ONLY'), 1)
        self.assertEqual(verdicts.count('REPLAY'), 23)
        self.assertEqual(self.owner.pending_paid(), 1)

    def test_restart_clone_same_epoch_is_no_longer_free(self):
        self.assertEqual(self.owner.spend(K, 2000, 100), 'READY_RESOURCE_ONLY')
        clone = Owner(self.path, R, E, 4)
        self.assertEqual(clone.spend(K, 2000, 101), 'REPLAY')

    def test_true_clock_regression_after_process_reopen_is_refused(self):
        self.assertEqual(self.owner.spend(K, 2000, 500), 'READY_RESOURCE_ONLY')
        clone = Owner(self.path, R, E, 4)
        with self.assertRaises(OwnerUnavailable):
            clone.spend(b'M'*32, 2000, 499)
        self.assertEqual(clone.spend(b'M'*32, 2000, 501), 'READY_RESOURCE_ONLY')

    def test_same_file_different_receiver_epoch_or_capacity_refused(self):
        for receiver, epoch, capacity in [(b'X'*32,E,4),(R,b'Z'*32,4),(R,E,5)]:
            with self.assertRaises(OwnerUnavailable):
                Owner(self.path, receiver, epoch, capacity)

    def test_capacity_busy_then_expired_recovery(self):
        for i in range(4):
            self.assertEqual(self.owner.spend(bytes([i])*32, 2000, 100), 'READY_RESOURCE_ONLY')
        self.assertEqual(self.owner.spend(bytes([5])*32, 2000, 101), 'PAID_CAPACITY_BUSY')
        self.assertEqual(self.owner.pending_paid(),4)
        self.assertEqual(self.owner.spend(bytes([5])*32, 2200, 2000), 'READY_RESOURCE_ONLY')
        self.assertEqual(self.owner.pending_paid(),1)

    def test_corrupt_db_refuses_new_issuer_without_w1(self):
        other = self.root/'corrupt.sqlite'
        other.write_bytes(b'not a sqlite database')
        os.chmod(other,0o600)
        with self.assertRaises(OwnerUnavailable):
            Owner(other,R,E,4)

    def test_link_or_unsafe_owner_directory_rejected(self):
        alias = self.root/'alias.sqlite'
        os.symlink(self.path,alias)
        with self.assertRaises(OwnerUnavailable):
            Owner(alias,R,E,4)
        bad_dir=self.root/'insecure'
        bad_dir.mkdir(mode=0o777)
        os.chmod(bad_dir,0o777)
        with self.assertRaises(OwnerUnavailable):
            Owner(bad_dir/'a.sqlite',R,E,4)

    def test_expired_and_invalid_timing_never_mints_ready(self):
        self.assertEqual(self.owner.spend(K,100,100),'EXPIRED')
        self.assertEqual(self.owner.spend(K,3001,100),'LIFETIME_POLICY')
        self.assertEqual(self.owner.pending_paid(),0)
        with self.assertRaises(ValueError):
            self.owner.spend(b'bad',2000,100)

if __name__ == '__main__':
    unittest.main(verbosity=2)
