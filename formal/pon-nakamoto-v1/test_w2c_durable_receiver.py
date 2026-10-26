"""Research negative controls for shared durable paid admission, not production W1."""
import os
import multiprocessing
import shutil
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from contract_wire import H
from w2c_receiver_admission import solve, ticket, qualifies
from w2c_durable_receiver import DurableReceiverAdmission as Durable


def _shared_paid_child(path, receiver, secret, proposal, caller, grant, nonce, ready):
    replica = Durable(path, receiver, secret, mode='join', capacity=2)
    try:
        ready.put(replica.consume(grant, proposal, caller, nonce, 140))
    finally:
        replica.close()


def _crashed_paid_child(path, receiver, secret, proposal, caller, grant, nonce):
    replica = Durable(path, receiver, secret, mode='join', capacity=2)
    result = replica.consume(grant, proposal, caller, nonce, 140)
    # Hard process exit *after* the durable spending commit and before any
    # response; the next process must treat the ticket as already paid.
    os._exit(0 if result == 'READY_RESOURCE_ONLY' else 23)


class DurableResearchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / 'receiver.sqlite3')
        self.receiver = b'R' * 32
        self.secret = b'S' * 32
        self.proposal = H('some-original-proposal')
        self.caller = b'C' * 32
        self.tok = 1

        def entropy(n):
            self.tok += 1
            return self.tok.to_bytes(8, 'little') + bytes(24)

        self.entropy = entropy
        self.owner = Durable(self.path, self.receiver, self.secret, entropy=self.entropy, capacity=2)
        self.addCleanup(self.owner.close)

    def grant(self, owner=None, now=100):
        owner = owner or self.owner
        grant = owner.offer(self.proposal, self.caller, 8, now)
        nonce, cost = solve(grant, 8192)
        self.assertIsNotNone(nonce)
        return grant, nonce

    def test_cross_instance_shared_sqlite_cannot_double_spend(self):
        peer = Durable(self.path, self.receiver, self.secret, mode='join', capacity=2)
        self.addCleanup(peer.close)
        grant, nonce = self.grant()
        with ThreadPoolExecutor(max_workers=12) as pool:
            results=list(pool.map(lambda x:(self.owner if x%2 else peer).consume(
                grant,self.proposal,self.caller,nonce,130),range(32)))
        self.assertEqual(results.count('READY_RESOURCE_ONLY'),1)
        self.assertEqual(results.count('REPLAY'),31)
        self.assertEqual(self.owner.paid_count(),1)
        self.assertEqual(peer.paid_count(),1)

    def test_eight_real_processes_share_one_atomic_paid_spend(self):
        grant, nonce = self.grant()
        ctx = multiprocessing.get_context('spawn')
        results = ctx.Queue()
        children = [ctx.Process(target=_shared_paid_child,
                                args=(self.path, self.receiver, self.secret,
                                      self.proposal, self.caller, grant, nonce, results))
                    for _ in range(8)]
        for child in children: child.start()
        for child in children:
            child.join(timeout=10)
            self.assertFalse(child.is_alive())
            self.assertEqual(child.exitcode, 0)
        seen = [results.get(timeout=2) for _ in range(8)]
        self.assertEqual(seen.count('READY_RESOURCE_ONLY'), 1)
        self.assertEqual(seen.count('REPLAY'), 7)
        self.assertEqual(self.owner.paid_count(), 1)

    def test_hard_exit_after_paid_commit_cannot_refund_spend(self):
        grant, nonce = self.grant()
        ctx = multiprocessing.get_context('spawn')
        child = ctx.Process(target=_crashed_paid_child,
                            args=(self.path, self.receiver, self.secret,
                                  self.proposal, self.caller, grant, nonce))
        child.start(); child.join(timeout=10)
        self.assertFalse(child.is_alive())
        self.assertEqual(child.exitcode, 0)
        # The parent never observed an ACK, but the shared DB did commit.
        self.assertEqual(self.owner.consume(grant,self.proposal,self.caller,nonce,141),'REPLAY')
        self.assertEqual(self.owner.paid_count(),1)

    def test_restart_rotates_epoch_and_fences_old_workers(self):
        grant, nonce = self.grant()
        self.assertEqual(self.owner.consume(grant,self.proposal,self.caller,nonce,130),'READY_RESOURCE_ONLY')
        restart = Durable(self.path, self.receiver, self.secret, mode='rotate', entropy=self.entropy)
        self.addCleanup(restart.close)
        self.assertNotEqual(restart.epoch, self.owner.epoch)
        self.assertEqual(restart.consume(grant,self.proposal,self.caller,nonce,130),'CONTEXT')
        self.assertEqual(self.owner.consume(grant,self.proposal,self.caller,nonce,130),'STALE_EPOCH')
        with self.assertRaisesRegex(ValueError,'STALE_EPOCH'):
            self.owner.offer(self.proposal,self.caller,8,140)
        self.assertEqual(restart.paid_count(),0)

    def test_unpaid_grant_flood_does_not_store_spent_rows(self):
        tokens={self.owner.offer(self.proposal,self.caller,8,100).token for _ in range(400)}
        self.assertEqual(len(tokens),400)
        self.assertEqual(self.owner.paid_count(),0)

    def test_paid_capacity_expiry_and_replay_without_refund(self):
        a, na=self.grant()
        b, nb=self.grant()
        c, nc=self.grant()
        self.assertEqual(self.owner.consume(a,self.proposal,self.caller,na,120),'READY_RESOURCE_ONLY')
        self.assertEqual(self.owner.consume(b,self.proposal,self.caller,nb,120),'READY_RESOURCE_ONLY')
        self.assertEqual(self.owner.consume(c,self.proposal,self.caller,nc,120),'PAID_CAPACITY_BUSY')
        self.assertEqual(self.owner.consume(a,self.proposal,self.caller,na,120),'REPLAY')
        self.assertEqual(self.owner.paid_count(),2)
        d, nd=self.grant(now=2100)
        self.assertEqual(self.owner.consume(d,self.proposal,self.caller,nd,2110),'READY_RESOURCE_ONLY')
        self.assertEqual(self.owner.paid_count(),1)

    def test_wrong_caller_mac_target_and_clock_rejected_without_spend(self):
        grant,nonce=self.grant()
        self.assertEqual(self.owner.consume(grant,self.proposal,b'X'*32,nonce,120),'CONTEXT')
        self.assertEqual(self.owner.consume(replace(grant,mac=b'0'*32),self.proposal,self.caller,nonce,120),'GRANT_MAC')
        miss=next(n for n in range(30) if not qualifies(ticket(grant,n),8))
        self.assertEqual(self.owner.consume(grant,self.proposal,self.caller,miss,120),'TARGET')
        other=self.grant(now=100)
        self.assertEqual(self.owner.consume(grant,self.proposal,self.caller,nonce,130),'READY_RESOURCE_ONLY')
        self.assertEqual(self.owner.consume(other[0],self.proposal,self.caller,other[1],120),'CLOCK_REGRESSION')
        self.assertEqual(self.owner.paid_count(),1)

    def test_cloned_durable_database_and_secret_still_double_spends(self):
        # Falsifies the strong claim that local durable storage beats DB + key
        # cloning. This copy takes place BEFORE either receiver consumes.
        grant,nonce=self.grant()
        copydir=Path(self.tmp.name)/'other-host';copydir.mkdir()
        clonepath=str(copydir/'copy.sqlite3')
        self.owner._db.execute('PRAGMA wal_checkpoint(FULL)')
        shutil.copyfile(self.path,clonepath)
        clone=Durable(clonepath,self.receiver,self.secret,mode='join',capacity=2)
        self.addCleanup(clone.close)
        self.assertEqual(self.owner.consume(grant,self.proposal,self.caller,nonce,130),'READY_RESOURCE_ONLY')
        self.assertEqual(clone.consume(grant,self.proposal,self.caller,nonce,130),'READY_RESOURCE_ONLY')

    def test_wrong_identity_cannot_join_or_rotate_existing_owner(self):
        with self.assertRaisesRegex(ValueError,'OWNER_IDENTITY_MISMATCH'):
            Durable(self.path,self.receiver,b'X'*32,mode='join')
        with self.assertRaisesRegex(ValueError,'OWNER_IDENTITY_MISMATCH'):
            Durable(self.path,b'X'*32,self.secret,mode='rotate')


if __name__=='__main__':unittest.main(verbosity=2)
