"""P3 crash/restart/cloned-owner replay regression for research W2-C only."""
import os
import subprocess
import sys
import sqlite3
from concurrent.futures import ThreadPoolExecutor
import tempfile
import unittest
from pathlib import Path
from contract_wire import H
from w2c_receiver_admission import solve
from w2c_durable_epoch_owner import DurableReceiverOwner


class DurableAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / 'durable.sqlite')
        self.receiver = bytes([71]) * 32
        self.secret = bytes([27]) * 32
        self.caller = bytes([12]) * 32
        self.proposal = H('durable-p3-fixed-proposal')

    def owner(self, **kwargs):
        return DurableReceiverOwner(self.path, self.receiver, self.secret, **kwargs)

    def grant(self, owner, proposal=None, now=100):
        actual = self.proposal if proposal is None else proposal
        g = owner.offer(actual, self.caller, 8, now)
        nonce, cost = solve(g, 65536)
        self.assertIsNotNone(nonce)
        self.assertEqual(cost['status'], 'TARGET_HIT_UNVERIFIED')
        return g, nonce

    def test_same_database_reopened_epoch_fences_paid_and_unpaid_old_grants(self):
        first = self.owner()
        paid, a = self.grant(first)
        unspent = first.offer(H('unspent'), self.caller, 8, 100)
        n, _ = solve(unspent, 65536)
        self.assertEqual(first.consume(paid, self.proposal, self.caller, a, 110),
                         'READY_RESOURCE_ONLY')
        first_epoch = first.epoch
        first.close()
        successor = self.owner()
        self.assertNotEqual(successor.epoch, first_epoch)
        self.assertEqual(successor.consume(paid, self.proposal, self.caller, a, 120),
                         'CONTEXT')
        self.assertEqual(successor.consume(unspent, H('unspent'), self.caller, n, 120),
                         'CONTEXT')
        g, nonce = self.grant(successor,now=130)
        self.assertEqual(successor.consume(g,self.proposal,self.caller,nonce,140),
                         'READY_RESOURCE_ONLY')
        self.assertEqual(successor.consume(g,self.proposal,self.caller,nonce,140),
                         'REPLAY')
        successor.close()

    def test_same_database_parallel_process_owner_supersedes_prior_identity(self):
        first = self.owner()
        old, nonce = self.grant(first)
        second = self.owner()
        self.assertFalse(first.is_current_epoch())
        self.assertTrue(second.is_current_epoch())
        self.assertEqual(first.consume(old,self.proposal,self.caller,nonce,110),
                         'STALE_EPOCH')
        self.assertEqual(first.offer(self.proposal,self.caller,8,110),
                         'STALE_EPOCH')
        fresh, n = self.grant(second)
        self.assertEqual(second.consume(fresh,self.proposal,self.caller,n,120),
                         'READY_RESOURCE_ONLY')
        first.close(); second.close()

    def test_capacity_is_real_paid_not_unpaid_issuance(self):
        owner = self.owner(capacity=1)
        a, na = self.grant(owner)
        b = owner.offer(self.proposal,self.caller,8,100)
        nb,_ = solve(b,65536)
        self.assertEqual(owner.consume(a,self.proposal,self.caller,na,150),
                         'READY_RESOURCE_ONLY')
        self.assertEqual(owner.consume(b,self.proposal,self.caller,nb,150),
                         'PAID_CAPACITY_BUSY')
        self.assertEqual(owner.db.execute('SELECT COUNT(*) FROM paid').fetchone()[0], 1)
        owner.close()

    def test_failed_sqlite_commit_cannot_return_success(self):
        owner = self.owner()
        grant, nonce = self.grant(owner)
        owner.db.close()
        with self.assertRaises(sqlite3.ProgrammingError):
            owner.consume(grant,self.proposal,self.caller,nonce,120)

    def test_reject_unsafe_db_file_mode_and_symlink(self):
        path = Path(self.path)
        path.write_bytes(b'x')
        path.chmod(0o644)
        with self.assertRaisesRegex(ValueError,'DB_OWNER_MODE'):
            self.owner()
        path.unlink()
        another = Path(self.tmp.name) / 'target'
        another.write_bytes(b'')
        path.symlink_to(another)
        with self.assertRaisesRegex(ValueError,'SYMLINK_DB'):
            self.owner()

    def test_unclean_actual_child_exit_keeps_spend_then_restarts_in_new_epoch(self):
        script = """
import os, sys
from contract_wire import H
from w2c_durable_epoch_owner import DurableReceiverOwner
from w2c_receiver_admission import solve
owner=DurableReceiverOwner(sys.argv[1], bytes([71])*32, bytes([27])*32)
grant=owner.offer(H('durable-p3-fixed-proposal'),bytes([12])*32,8,100)
nonce,_=solve(grant,65536)
assert owner.consume(grant,H('durable-p3-fixed-proposal'),bytes([12])*32,nonce,120)=='READY_RESOURCE_ONLY'
os._exit(0)   # deliberately skip close() and all normal teardown
"""
        complete = subprocess.run(
            [sys.executable, '-B', '-c', script, self.path],
            env={**os.environ, 'PYTHONPATH': str(Path(__file__).resolve().parent)},
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(complete.returncode, 0, complete.stderr)
        with sqlite3.connect(self.path) as persisted:
            self.assertEqual(persisted.execute('SELECT seq FROM authority').fetchone()[0],1)
            self.assertEqual(persisted.execute('SELECT COUNT(*) FROM paid').fetchone()[0],1)
            old_epoch=persisted.execute('SELECT epoch FROM authority').fetchone()[0]
        successor=self.owner()
        self.assertNotEqual(old_epoch, successor.epoch)
        self.assertEqual(successor.db.execute('SELECT seq FROM authority').fetchone()[0],2)
        self.assertEqual(successor.db.execute('SELECT COUNT(*) FROM paid').fetchone()[0],0)
        fresh,nonce=self.grant(successor)
        self.assertEqual(successor.consume(fresh,self.proposal,self.caller,nonce,110),
                         'READY_RESOURCE_ONLY')
        successor.close()

    def test_another_receiver_cannot_steal_original_database_epoch(self):
        first=self.owner()
        with self.assertRaisesRegex(ValueError,'AUTHORITY_CONTEXT'):
            DurableReceiverOwner(self.path,bytes([1])*32,self.secret)
        self.assertTrue(first.is_current_epoch())
        first.close()

    def test_bad_cost_nonce_never_persists_spend(self):
        from w2c_receiver_admission import qualifies,ticket
        owner=self.owner()
        grant,nonce=self.grant(owner)
        bad=next(n for n in range(30) if not qualifies(ticket(grant,n),8))
        self.assertEqual(owner.consume(grant,self.proposal,self.caller,bad,110),'TARGET')
        self.assertEqual(owner.db.execute('SELECT COUNT(*) FROM paid').fetchone()[0],0)
        self.assertEqual(owner.consume(grant,self.proposal,self.caller,nonce,120),
                         'READY_RESOURCE_ONLY')
        owner.close()

    def test_same_token_thirty_two_parallel_paid_consumes_only_once(self):
        owner=self.owner(capacity=1)
        grant,nonce=self.grant(owner)
        with ThreadPoolExecutor(max_workers=8) as pool:
            replies=list(pool.map(
                lambda _:owner.consume(grant,self.proposal,self.caller,nonce,120),range(32)))
        self.assertEqual(replies.count('READY_RESOURCE_ONLY'),1)
        self.assertEqual(replies.count('REPLAY'),31)
        self.assertEqual(owner.db.execute('SELECT COUNT(*) FROM paid').fetchone()[0],1)
        owner.close()

    @unittest.skipUnless(hasattr(os,'fork'), 'real OS fork required')
    def test_child_fork_inheriting_the_same_owner_is_fenced(self):
        # Run the fork in a fresh interpreter before a test suite can leave
        # worker threads behind. No sqlite operation may occur in that child.
        script = """
import os, sys
from contract_wire import H
from w2c_durable_epoch_owner import DurableReceiverOwner
from w2c_receiver_admission import solve
owner=DurableReceiverOwner(sys.argv[1],bytes([71])*32,bytes([27])*32)
read_end, write_end=os.pipe()
child=os.fork()
if child==0:
    os.close(read_end)
    try:
        owner.offer(H('durable-p3-fixed-proposal'),bytes([12])*32,8,100)
    except ValueError as error:
        os.write(write_end,str(error).encode())
    else:
        os.write(write_end,b'UNEXPECTED_READY')
    os._exit(0)
os.close(write_end)
answer=os.read(read_end,100)
os.close(read_end)
_, status=os.waitpid(child,0)
assert status==0 and answer==b'FORKED_OWNER', (status,answer)
grant=owner.offer(H('durable-p3-fixed-proposal'),bytes([12])*32,8,100)
nonce,_=solve(grant,65536)
assert owner.consume(grant,H('durable-p3-fixed-proposal'),bytes([12])*32,nonce,120)=='READY_RESOURCE_ONLY'
owner.close()
"""
        completed=subprocess.run([sys.executable,'-B','-c',script,self.path],
                                  env={**os.environ,'PYTHONPATH':str(Path(__file__).resolve().parent)},
                                  capture_output=True,text=True,timeout=10)
        self.assertEqual(completed.returncode,0,completed.stderr)

    def test_no_consensus_authority_ever_created(self):
        owner = self.owner()
        grant, nonce = self.grant(owner)
        self.assertEqual(owner.consume(grant,self.proposal,self.caller,nonce,120),
                         'READY_RESOURCE_ONLY')
        self.assertFalse(hasattr(owner,'VerifiedWork'))
        self.assertFalse(hasattr(owner,'chainwork'))
        owner.close()

    def test_cloned_different_databases_remain_separate_unsafe_authorities(self):
        """Counterexample, not a passing cross-host anti-clone security theorem."""
        a = self.owner(epoch_entropy=lambda n: bytes([8])*n,
                       entropy=lambda n: bytes([9])*n)
        copied_path = str(Path(self.tmp.name)/'different-host.db')
        b = DurableReceiverOwner(copied_path,self.receiver,self.secret,
                                 epoch_entropy=lambda n: bytes([8])*n,
                                 entropy=lambda n: bytes([9])*n)
        # A cloned snapshot + cloned RNG on two independent files creates the
        # SAME epoch, and neither SQLite file shares its paid-grant rows.
        self.assertEqual(a.epoch,b.epoch)
        grant, nonce = self.grant(a)
        self.assertEqual(a.consume(grant,self.proposal,self.caller,nonce,120),
                         'READY_RESOURCE_ONLY')
        self.assertEqual(b.consume(grant,self.proposal,self.caller,nonce,120),
                         'READY_RESOURCE_ONLY')
        a.close(); b.close()

    def test_same_statement_cost_diagnostics_retain_all_attempts_and_no_chainwork(self):
        from w2c_durable_cost import run
        report=run((8,),1,65536)
        self.assertEqual(report['schema'],'w2c-durable-receiver-cost-v1')
        self.assertFalse(report['production_activation'])
        self.assertIsNone(report['attacker_gpu_cost'])
        self.assertEqual(len(report['rows']),1)
        row=report['rows'][0]
        self.assertEqual(row['status'],'COMPLETE_RESEARCH_ONLY')
        self.assertGreater(len(row['w1_ticket_trials']),0)
        self.assertEqual(sum(int(t['target_hit']) for t in row['w1_ticket_trials']),1)
        self.assertGreater(row['search']['attempts'],0)
        self.assertEqual(row['full_w1_outcome'],'TRANSCRIPT')
        self.assertFalse(row['w1_work_verified'])
        self.assertFalse(row['chainwork_granted'])

    def test_cost_diagnostics_reject_invalid_unbounded_cohorts(self):
        from w2c_durable_cost import run
        for bits,samples,cap in [((7,),1,10),((8,),0,10),((8,8),1,10),
                                 ((8,),1,0),((8,),17,10),((8,),1,(1<<20)+1)]:
            with self.assertRaisesRegex(ValueError,'BOUNDED_PROFILE'):
                run(bits,samples,cap)


if __name__ == '__main__':
    unittest.main(verbosity=2)
