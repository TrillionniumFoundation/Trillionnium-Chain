"""Actual SQLite durable W2-C research negatives; no native W1/Chain activation."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from dataclasses import replace
import multiprocessing
from pathlib import Path
import os
import tempfile
import unittest

from contract_wire import H
from w2c_receiver_admission import solve, qualifies, ticket
from w2c_durable_spend import DurableStatelessReceiver

RECEIVER = bytes([0x51]) * 32
SECRET = bytes([0x53]) * 32
EPOCH = bytes([0x45]) * 32
BOOT = bytes([0x62]) * 32
CALLER = bytes([0x43]) * 32
PROPOSAL = H('durable-receiver-w1-proposal')


def new_receiver(path, epoch=EPOCH, secret=SECRET, boot=BOOT,
                 capacity=4, entropy=None):
    return DurableStatelessReceiver(
        RECEIVER, secret, epoch, str(path), boot, capacity=capacity,
        entropy=entropy
    )


def process_consume(arguments):
    path, grant, nonce = arguments
    instance = new_receiver(path)
    try:
        return instance.consume(grant, PROPOSAL, CALLER, nonce, 150)
    finally:
        instance.close()


class DurableReceiverCostControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'spent.sqlite'
        self.counter = 0

        def entropy(n):
            self.assertEqual(n, 32)
            self.counter += 1
            return self.counter.to_bytes(8, 'little') + bytes(24)

        self.receiver = new_receiver(self.path, entropy=entropy)
        self.addCleanup(self.receiver.close)

    def paid(self, now=100):
        grant = self.receiver.offer(PROPOSAL, CALLER, 8, now)
        nonce, cost = solve(grant, 65536)
        self.assertIsNotNone(nonce)
        self.assertEqual(cost['status'], 'TARGET_HIT_UNVERIFIED')
        return grant, nonce

    def test_restart_with_cloned_epoch_keeps_spent_ticket(self):
        grant, nonce = self.paid()
        self.assertEqual(self.receiver.consume(
            grant, PROPOSAL, CALLER, nonce, 110), 'READY_RESOURCE_ONLY')
        restarted = new_receiver(self.path)
        try:
            self.assertEqual(restarted.pending_paid(), 1)
            self.assertEqual(restarted.consume(
                grant, PROPOSAL, CALLER, nonce, 120), 'REPLAY')
        finally:
            restarted.close()

    def test_multiple_distinct_connections_have_one_linearized_spend(self):
        grant, nonce = self.paid()
        peers = [new_receiver(self.path) for _ in range(7)]
        self.addCleanup(lambda: [peer.close() for peer in peers])
        with ThreadPoolExecutor(max_workers=8) as pool:
            result = list(pool.map(
                lambda idx: [self.receiver, *peers][idx].consume(
                    grant, PROPOSAL, CALLER, nonce, 150),
                range(8)))
        self.assertEqual(result.count('READY_RESOURCE_ONLY'), 1)
        self.assertEqual(result.count('REPLAY'), 7)

    def test_two_actual_processes_share_sqlite_one_spend(self):
        grant, nonce = self.paid()
        context = multiprocessing.get_context('spawn')
        with ProcessPoolExecutor(max_workers=2, mp_context=context) as pool:
            result = list(pool.map(process_consume, [(self.path, grant, nonce)] * 2))
        self.assertEqual(result.count('READY_RESOURCE_ONLY'), 1)
        self.assertEqual(result.count('REPLAY'), 1)

    def test_restart_with_different_secret_epoch_or_boot_fails_closed(self):
        grant, nonce = self.paid()
        self.assertEqual(self.receiver.consume(
            grant, PROPOSAL, CALLER, nonce, 120), 'READY_RESOURCE_ONLY')
        for kw in (
            {'secret':bytes([7]) * 32},
            {'epoch':bytes([8]) * 32},
            {'boot':bytes([9]) * 32},
        ):
            with self.assertRaisesRegex(ValueError,'DURABLE_AUTHORITY_MISMATCH'):
                new_receiver(self.path, **kw)

    def test_exact_duplicate_with_another_winning_nonce_is_still_replay(self):
        grant, nonce = self.paid()
        second = next(i for i in range(nonce+1,nonce+10000)
                      if qualifies(ticket(grant,i),grant.bits))
        self.assertEqual(self.receiver.consume(
            grant, PROPOSAL, CALLER, nonce, 120), 'READY_RESOURCE_ONLY')
        self.assertEqual(self.receiver.consume(
            grant, PROPOSAL, CALLER, second, 130), 'REPLAY')

    def test_persisted_clock_regression_rejected_after_restart(self):
        grant, nonce = self.paid()
        self.assertEqual(self.receiver.consume(
            grant, PROPOSAL, CALLER, nonce, 300), 'READY_RESOURCE_ONLY')
        restarted = new_receiver(self.path)
        try:
            changed = restarted.offer(PROPOSAL,CALLER,8,100)
            second, _ = solve(changed, 65536)
            self.assertIsNotNone(second)
            with self.assertRaisesRegex(ValueError,'DURABLE_CLOCK_REGRESSION'):
                restarted.consume(changed,PROPOSAL,CALLER,second,150)
        finally:
            restarted.close()

    def test_expiry_frees_capacity_but_only_after_grant_expired(self):
        limited = new_receiver(Path(self.temp.name)/'limit.sqlite',capacity=1,
                               entropy=lambda n: bytes([0x77])*n)
        self.addCleanup(limited.close)
        first = limited.offer(PROPOSAL,CALLER,8,100)
        second = limited.offer(PROPOSAL,CALLER,8,101)
        n0,_ = solve(first, 65536)
        n1,_ = solve(second, 65536)
        self.assertEqual(limited.consume(first,PROPOSAL,CALLER,n0,110),
                         'READY_RESOURCE_ONLY')
        self.assertEqual(limited.consume(second,PROPOSAL,CALLER,n1,120),
                         'REPLAY' if first == second else 'PAID_CAPACITY_BUSY')
        limited.clock(2100)
        third = limited.offer(PROPOSAL,CALLER,8,2100)
        n2,_ = solve(third,65536)
        self.assertEqual(limited.consume(third,PROPOSAL,CALLER,n2,2110),
                         'READY_RESOURCE_ONLY')

    def test_invalid_grant_and_tamper_never_spends_cpu_ticket(self):
        grant, nonce = self.paid()
        self.assertEqual(self.receiver.consume(grant,PROPOSAL,bytes([0x60])*32,nonce,120),
                         'CONTEXT')
        self.assertEqual(self.receiver.consume(
            replace(grant,mac=bytes(32)),PROPOSAL,CALLER,nonce,120),
            'GRANT_MAC')
        bad_nonce=next(i for i in range(100)
                       if not qualifies(ticket(grant,i),grant.bits))
        self.assertEqual(self.receiver.consume(grant,PROPOSAL,CALLER,bad_nonce,120),
                         'TARGET')
        self.assertEqual(self.receiver.pending_paid(),0)
        self.assertEqual(self.receiver.consume(grant,PROPOSAL,CALLER,nonce,120),
                         'READY_RESOURCE_ONLY')

    def test_private_directory_and_file_symlinks_fail_closed(self):
        with tempfile.TemporaryDirectory() as world:
            os.chmod(world,0o755)
            with self.assertRaisesRegex(ValueError,'PRIVATE_DATABASE_DIRECTORY'):
                new_receiver(Path(world)/'spent.sqlite')
        link=Path(self.temp.name)/'link.sqlite'
        link.symlink_to(self.path)
        with self.assertRaises((ValueError,OSError)):
            new_receiver(link)

    def test_copied_private_database_is_not_a_shared_spend_authority(self):
        # Negative, not a pass for decentralized replay safety:
        # cloning the on-disk state before spending makes two isolated stores.
        import shutil
        sibling=Path(self.temp.name)/'sibling.sqlite'
        shutil.copyfile(self.path,sibling)
        os.chmod(sibling,0o600)
        grant,nonce=self.paid()
        self.assertEqual(self.receiver.consume(grant,PROPOSAL,CALLER,nonce,120),
                         'READY_RESOURCE_ONLY')
        other=new_receiver(sibling)
        try:
            self.assertEqual(other.consume(grant,PROPOSAL,CALLER,nonce,120),
                             'READY_RESOURCE_ONLY')
        finally:
            other.close()

    def test_paid_false_w1_transcript_still_rejected_after_durable_spend(self):
        import work_oracle as W
        zeros=[0]*W.CELLS
        header=H('durable-replay-header')*9+bytes(30)
        challenge=H('challenge',header)
        bad=b'PNW1'+W.field_bytes(zeros)*3+H('false-durable-trace',challenge)
        proposal=H('w2c-proposal',b'w2c-research-security-v0',header,bad)
        grant=self.receiver.offer(proposal,CALLER,8,100)
        nonce,_=solve(grant,65536)
        self.assertEqual(self.receiver.consume(grant,proposal,CALLER,nonce,120),
                         'READY_RESOURCE_ONLY')
        with self.assertRaisesRegex(ValueError,'^TRANSCRIPT$'):
            W.verify(challenge,W.task_id(zeros,zeros),bytes([255])*32,bad)
        self.assertEqual(self.receiver.pending_paid(),1)
        self.assertFalse(hasattr(self.receiver,'VerifiedWork'))


if __name__=='__main__':
    unittest.main(verbosity=2)
