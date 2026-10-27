"""W2-C durable paid-spend: same-operator multi-process replay controls only."""
from __future__ import annotations
import multiprocessing as mp
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

from contract_wire import H
from w2c_durable_spend import DurableSpentFence, DurableStatelessReceiver
from w2c_receiver_admission import solve


def separate_process_spend(job):
    path, identity, now_ms = job
    fence = DurableSpentFence(path, 64)
    try:
        return fence.spend(identity, 1100, now_ms)
    finally:
        fence.close()


class DurableW2CSpendResearchTests(unittest.TestCase):
    def test_exact_paid_ticket_spends_once_after_durable_reopen(self):
        with tempfile.TemporaryDirectory() as root:
            path = str(Path(root) / 'w2c-paid.sqlite')
            key = H('paid-test', b'one')
            first = DurableSpentFence(path)
            self.assertEqual(first.spend(key, 1100, 100), 'READY_RESOURCE_ONLY')
            first.close()
            second = DurableSpentFence(path)
            try:
                self.assertEqual(second.spend(key, 1100, 120), 'REPLAY')
            finally:
                second.close()

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux process owner test')
    def test_eight_actual_processes_one_spend_seven_replays(self):
        with tempfile.TemporaryDirectory() as root:
            path = str(Path(root) / 'shared-spend.sqlite')
            setup = DurableSpentFence(path)
            setup.close()
            key = H('paid-test', b'parallel')
            with mp.get_context('fork').Pool(8) as pool:
                results = pool.map(
                    separate_process_spend, [(path, key, 100)] * 8)
            self.assertEqual(results.count('READY_RESOURCE_ONLY'), 1)
            self.assertEqual(results.count('REPLAY'), 7)

    def test_shared_db_blocks_same_cloned_receiver_epoch(self):
        with tempfile.TemporaryDirectory() as root:
            path = str(Path(root) / 'spent.sqlite')
            receiver, secret, epoch = bytes([1])*32, bytes([2])*32, bytes([3])*32
            caller, proposal = H('caller'), H('proposal')
            a = DurableStatelessReceiver(
                receiver, secret, epoch, path,
                entropy=lambda n: bytes([4])*n)
            b = DurableStatelessReceiver(
                receiver, secret, epoch, path,
                entropy=lambda n: bytes([4])*n)
            try:
                grant = a.offer(proposal, caller, 8, 100)
                nonce, measured = solve(grant, 8192)
                self.assertIsNotNone(nonce)
                self.assertEqual(measured['status'], 'TARGET_HIT_UNVERIFIED')
                self.assertEqual(a.consume(grant, proposal, caller, nonce, 130),
                                 'READY_RESOURCE_ONLY')
                self.assertEqual(b.consume(grant, proposal, caller, nonce, 131),
                                 'REPLAY')
            finally:
                a.close()
                b.close()

    def test_separate_copied_ledgers_remain_unsafe_under_cloned_secret_epoch(self):
        # Mandatory negative: local DB cannot secure independent operators
        # if both reuse the same MAC key, epoch and token without sharing spend.
        with tempfile.TemporaryDirectory() as root:
            receiver, secret, epoch = bytes([1])*32, bytes([2])*32, bytes([3])*32
            caller, proposal = H('caller'), H('proposal')
            a = DurableStatelessReceiver(receiver, secret, epoch,
                                         str(Path(root)/'a.sqlite'),
                                         entropy=lambda n: bytes([4])*n)
            b = DurableStatelessReceiver(receiver, secret, epoch,
                                         str(Path(root)/'b.sqlite'),
                                         entropy=lambda n: bytes([4])*n)
            try:
                grant = a.offer(proposal, caller, 8, 100)
                nonce, _ = solve(grant, 8192)
                self.assertIsNotNone(nonce)
                self.assertEqual(a.consume(grant,proposal,caller,nonce,130),
                                 'READY_RESOURCE_ONLY')
                self.assertEqual(b.consume(grant,proposal,caller,nonce,131),
                                 'READY_RESOURCE_ONLY')
            finally:
                a.close()
                b.close()

    def test_capacity_is_not_live_evicted_and_clock_frontier_survives_reopen(self):
        with tempfile.TemporaryDirectory() as root:
            path = str(Path(root)/'finite.sqlite')
            a, b = H('a'), H('b')
            fence = DurableSpentFence(path, capacity=1)
            self.assertEqual(fence.spend(a, 1100, 100), 'READY_RESOURCE_ONLY')
            self.assertEqual(fence.spend(b, 1100, 120), 'PAID_CAPACITY_BUSY')
            fence.close()
            restarted = DurableSpentFence(path, capacity=1)
            try:
                with self.assertRaisesRegex(ValueError, 'DURABLE_CLOCK_REGRESSION'):
                    restarted.spend(b, 1100, 119)
                self.assertEqual(restarted.spend(b, 1100, 130), 'PAID_CAPACITY_BUSY')
                self.assertEqual(restarted.spend(b, 2100, 1200), 'READY_RESOURCE_ONLY')
            finally:
                restarted.close()

    def test_closed_or_unavailable_db_does_not_fall_back_to_memory_ready(self):
        with tempfile.TemporaryDirectory() as root:
            path = str(Path(root) / 'unavailable.sqlite')
            fence = DurableSpentFence(path)
            fence.close()
            self.assertEqual(
                fence.spend(H('paid',b'unavailable'), 1100, 100),
                'DURABLE_LEDGER_UNAVAILABLE',
                'a failed SQL owner must never release a W1 verification permit')

    def test_untrusted_parent_symlink_and_long_expiry_fail_closed(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)/'spend.sqlite'
            fence = DurableSpentFence(path)
            with self.assertRaisesRegex(ValueError, 'DURABLE_LIFETIME'):
                fence.spend(H('x'), 7000, 100)
            fence.close()
            link = Path(root)/'link.sqlite'
            link.symlink_to(path)
            with self.assertRaises((OSError, ValueError)):
                DurableSpentFence(link)
            with self.assertRaises(ValueError):
                DurableSpentFence(Path('relative.sqlite'))
            # Caller cannot choose a shared writable /tmp as the DB owner.
            if Path('/tmp').stat().st_mode & 0o022:
                with self.assertRaises(ValueError):
                    DurableSpentFence('/tmp/unsafe-w2c-ledger.sqlite')


if __name__=='__main__':
    unittest.main(verbosity=2)
