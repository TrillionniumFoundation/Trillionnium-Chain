"""Research-only tests of one local durable spent owner, not PoN activation."""
from dataclasses import replace
import hashlib
import hmac
import multiprocessing as mp
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from contract_wire import H
from w2c_receiver_admission import Grant, ticket, qualifies
from w2c_durable_spent_owner import DurableSpentOwner

R=bytes([1])*32
K=bytes([2])*32
E=bytes([3])*32
B=bytes([4])*32
CALLER=H('authenticated-caller')
PROPOSAL=H('fixed-exact-proposal')

def grant(bits=8, start=100, token=bytes([7])*32, caller=CALLER, proposal=PROPOSAL):
    binding=H('w2c-stateless-caller-proposal-v1',caller,proposal)
    unsigned=Grant(R,E,binding,token,bits,start,start+2000,b'')
    mac=hmac.new(K,unsigned.unsigned(),hashlib.sha256).digest()
    return replace(unsigned,mac=mac)

def winning_nonce(g,cap=100_000):
    return next(i for i in range(cap) if qualifies(ticket(g,i),g.bits))

def child_consume(path,g,nonce,queue):
    try:
        with DurableSpentOwner(Path(path),receiver=R,secret=K,epoch=E,boot=B) as owner:
            queue.put(owner.consume(g,PROPOSAL,CALLER,nonce,120))
    except Exception as error:
        queue.put('ERROR:'+repr(error))

def child_after_commit_exit(path,g,nonce):
    with DurableSpentOwner(Path(path),receiver=R,secret=K,epoch=E,boot=B) as owner:
        assert owner.consume(g,PROPOSAL,CALLER,nonce,120)=='READY_RESOURCE_ONLY'
        os._exit(0)

class DurableSpentOwnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'paid.sqlite'
        with self.new_owner(create=True):pass
    def new_owner(self,**k):
        return DurableSpentOwner(self.path,receiver=k.pop('receiver',R),secret=k.pop('secret',K),
                                 epoch=k.pop('epoch',E),boot=k.pop('boot',B),**k)
    def test_no_free_replay_across_reopened_process_epoch(self):
        g=grant();n=winning_nonce(g)
        with self.new_owner() as owner:
            self.assertEqual(owner.consume(g,PROPOSAL,CALLER,n,120),'READY_RESOURCE_ONLY')
        with self.new_owner() as owner:
            self.assertEqual(owner.consume(g,PROPOSAL,CALLER,n,120),'REPLAY')
    def test_shared_storage_atomic_across_simultaneous_independent_processes(self):
        g=grant();n=winning_nonce(g)
        ctx=mp.get_context('spawn');queue=ctx.Queue()
        workers=[ctx.Process(target=child_consume,args=(str(self.path),g,n,queue)) for _ in range(12)]
        for p in workers:p.start()
        for p in workers:p.join(15);self.assertEqual(p.exitcode,0)
        verdicts=[queue.get(timeout=3) for _ in workers]
        self.assertEqual(verdicts.count('READY_RESOURCE_ONLY'),1,verdicts)
        self.assertEqual(verdicts.count('REPLAY'),11,verdicts)
    def test_committed_consumption_survives_abrupt_process_exit(self):
        g=grant();n=winning_nonce(g)
        ctx=mp.get_context('spawn')
        p=ctx.Process(target=child_after_commit_exit,args=(str(self.path),g,n));p.start();p.join(10)
        self.assertEqual(p.exitcode,0)
        with self.new_owner() as owner:
            self.assertEqual(owner.consume(g,PROPOSAL,CALLER,n,120),'REPLAY')
    def test_wrong_receiver_epoch_boot_and_lifetime_must_reject(self):
        for overrides in ({'receiver':bytes([9])*32},{'epoch':bytes([9])*32},
                          {'boot':bytes([9])*32},{'lifetime_ms':1000}):
            with self.assertRaisesRegex(ValueError,'OWNER_EPOCH_OR_SCHEMA'):
                with self.new_owner(**overrides):pass
    def test_missing_store_never_silently_creates_paid_credit(self):
        self.path.unlink()
        with self.assertRaises((FileNotFoundError,ValueError,sqlite3.OperationalError)):
            with self.new_owner():pass
    def test_source_caller_binding_and_mac_reject_before_spent_write(self):
        g=grant();n=winning_nonce(g)
        with self.new_owner() as owner:
            self.assertEqual(owner.consume(g,PROPOSAL,H('other'),n,120),'CONTEXT')
            self.assertEqual(owner.consume(g,H('other-p'),CALLER,n,120),'CONTEXT')
            self.assertEqual(owner.consume(replace(g,mac=bytes(32)),PROPOSAL,CALLER,n,120),'GRANT_MAC')
            self.assertEqual(owner.count_spent(),0)
            self.assertEqual(owner.consume(g,PROPOSAL,CALLER,n,120),'READY_RESOURCE_ONLY')
    def test_paid_capacity_blocks_new_full_verification(self):
        second=grant(token=bytes([8])*32)
        g=grant();n=winning_nonce(g);n2=winning_nonce(second)
        self.path.unlink()
        with self.new_owner(capacity=1,create=True) as owner:
            self.assertEqual(owner.consume(g,PROPOSAL,CALLER,n,120),'READY_RESOURCE_ONLY')
            self.assertEqual(owner.consume(second,PROPOSAL,CALLER,n2,130),'PAID_CAPACITY_BUSY')
            self.assertEqual(owner.consume(g,PROPOSAL,CALLER,n,130),'REPLAY')
            self.assertEqual(owner.count_spent(),1)
            self.assertEqual(owner.consume(second,PROPOSAL,CALLER,n2,2100),'EXPIRED_OR_FUTURE')
    def test_clock_regression_is_retained_across_reopen(self):
        g=grant();n=winning_nonce(g)
        with self.new_owner() as owner:
            self.assertEqual(owner.consume(g,PROPOSAL,CALLER,n,130),'READY_RESOURCE_ONLY')
        g2=grant(token=bytes([10])*32);n2=winning_nonce(g2)
        with self.new_owner() as owner:
            self.assertEqual(owner.consume(g2,PROPOSAL,CALLER,n2,120),'CLOCK_REGRESSION')
    def test_symlink_and_weak_mode_fail_closed(self):
        g=grant();n=winning_nonce(g)
        self.path.chmod(0o644)
        with self.assertRaisesRegex(ValueError,'PRIVATE_OWNER_REQUIRED'):
            with self.new_owner():pass
        self.path.chmod(0o600)
        symlink=self.path.parent/'alias.sqlite';symlink.symlink_to(self.path)
        self.path=symlink
        with self.assertRaisesRegex(ValueError,'REGULAR_FILE_REQUIRED'):
            with self.new_owner():pass
    def test_two_cloned_databases_demonstrate_unresolved_distributed_double_spend(self):
        # NEGATIVE result deliberately retained: independent clones are NOT a
        # single owner; a real protocol needs coordinated spent consensus.
        replica=self.path.parent/'copied.sqlite'
        shutil.copy2(self.path,replica)
        g=grant();n=winning_nonce(g)
        with self.new_owner() as first:
            self.assertEqual(first.consume(g,PROPOSAL,CALLER,n,120),'READY_RESOURCE_ONLY')
        with DurableSpentOwner(replica,receiver=R,secret=K,epoch=E,boot=B) as second:
            self.assertEqual(second.consume(g,PROPOSAL,CALLER,n,120),'READY_RESOURCE_ONLY')
    def test_swapped_local_store_is_denied_before_paid_work(self):
        g=grant();n=winning_nonce(g)
        with self.new_owner() as owner:
            original=self.path.parent/'original.sqlite'
            self.path.rename(original)
            shutil.copy2(original,self.path)
            with self.assertRaisesRegex(ValueError,'OWNER_STORE_REPLACED'):
                owner.consume(g,PROPOSAL,CALLER,n,120)
    def test_target_miss_never_spends(self):
        g=grant()
        bad=next(i for i in range(128) if not qualifies(ticket(g,i),g.bits))
        with self.new_owner() as owner:
            self.assertEqual(owner.consume(g,PROPOSAL,CALLER,bad,120),'TARGET')
            self.assertEqual(owner.count_spent(),0)

if __name__=='__main__':unittest.main(verbosity=2)
