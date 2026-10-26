"""Real SQLite/WAL cross-process research tests, no W1 or Chainwork authority."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from contract_wire import H
from w2c_durable_receiver import DurableReceiver,solve

class DurableReceiverResearchTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir=Path(self.temp.name)
        self.path=self.dir/'paid.sqlite'
        self.clock_value=100
        self.receiver=b'A'*32
        self.secret=b'K'*32
        self.proposal=H('fixed-proposal')
        self.caller=H('fixed-authenticated-caller')
        self.epoch=0
        self.next_token=1
        self.open_owner()

    def open_owner(self, **kw):
        def entropy(n):
            token=self.next_token
            self.next_token+=1
            return token.to_bytes(n, 'little')
        self.owner=DurableReceiver(self.path,self.receiver,self.secret,clock=lambda:self.clock_value,entropy=entropy,**kw)
        self.addCleanup(self.owner.close)

    def mint(self, *, caller=None, proposal=None):
        g=self.owner.offer(proposal or self.proposal,caller or self.caller,8)
        n,cost=solve(g,65536)
        self.assertIsNotNone(n)
        self.assertTrue(cost['hit'])
        return g,n

    def test_atomic_parallel_replay_and_no_pseudo_authority(self):
        g,n=self.mint()
        with ThreadPoolExecutor(max_workers=16) as pool:
            replies=list(pool.map(lambda _:self.owner.consume(g,self.proposal,self.caller,n),range(32)))
        self.assertEqual(replies.count('READY_RESOURCE_ONLY'),1)
        self.assertEqual(replies.count('REPLAY'),31)
        self.assertEqual(self.owner.paid_rows(),1)
        self.assertFalse(hasattr(self.owner,'VerifiedWork'))

    def test_fresh_epoch_on_restart_fences_old_ticket_and_retains_spent_row(self):
        g,n=self.mint()
        self.assertEqual(self.owner.consume(g,self.proposal,self.caller,n),'READY_RESOURCE_ONLY')
        old_epoch=self.owner.epoch
        self.owner.close()
        self.open_owner()
        self.assertNotEqual(old_epoch,self.owner.epoch)
        self.assertEqual(self.owner.paid_rows(),1)
        self.assertEqual(self.owner.consume(g,self.proposal,self.caller,n),'CONTEXT')
        fresh,fresh_nonce=self.mint()
        self.assertEqual(self.owner.consume(fresh,self.proposal,self.caller,fresh_nonce),'READY_RESOURCE_ONLY')

    def test_unauthenticated_offer_has_no_pending_slot_state(self):
        for _ in range(2000):
            grant=self.owner.offer(self.proposal,self.caller,8)
            self.assertEqual(grant.epoch,self.owner.epoch)
        self.assertEqual(self.owner.paid_rows(),0)

    def test_capacity_refusal_is_not_invalid_work_and_expiry_releases_rows(self):
        self.owner.close()
        self.open_owner(capacity=1)
        g,n=self.mint()
        self.assertEqual(self.owner.consume(g,self.proposal,self.caller,n),'READY_RESOURCE_ONLY')
        second,n2=self.mint()
        self.assertEqual(self.owner.consume(second,self.proposal,self.caller,n2),'PAID_CAPACITY_BUSY')
        self.clock_value=2100
        # Spent records may be pruned only at/after the original immutable expiry.
        self.assertEqual(self.owner.consume(second,self.proposal,self.caller,n2),'EXPIRED')
        g3,n3=self.mint()
        self.assertEqual(self.owner.consume(g3,self.proposal,self.caller,n3),'READY_RESOURCE_ONLY')
        self.assertEqual(self.owner.paid_rows(),1)

    def test_bad_mac_changed_caller_and_nonce_do_not_spend(self):
        g,n=self.mint()
        self.assertEqual(self.owner.consume(g,self.proposal,H('wrong-caller'),n),'CONTEXT')
        self.assertEqual(self.owner.consume(g,H('wrong-proposal'),self.caller,n),'CONTEXT')
        self.assertEqual(self.owner.consume(replace(g,mac=bytes(32)),self.proposal,self.caller,n),'MAC')
        miss=next(i for i in range(32) if (int.from_bytes(g.ticket(i)[:4],'big')>>(32-g.bits)) !=0)
        self.assertEqual(self.owner.consume(g,self.proposal,self.caller,miss),'TARGET')
        self.assertEqual(self.owner.paid_rows(),0)

    def test_fail_write_aborts_and_disables_owner_without_false_ready(self):
        self.owner.close()
        def fail(stage):
            if stage=='spend':raise OSError('injected SQL pre-commit fault')
        self.open_owner(before_commit=fail)
        g,n=self.mint()
        with self.assertRaisesRegex(RuntimeError,'DURABLE_SPEND_UNKNOWN'):
            self.owner.consume(g,self.proposal,self.caller,n)
        with self.assertRaisesRegex(ValueError,'OWNER_UNAVAILABLE'):
            self.owner.consume(g,self.proposal,self.caller,n)
        self.owner.close()
        self.open_owner()
        self.assertEqual(self.owner.paid_rows(),0)
        self.assertEqual(self.owner.consume(g,self.proposal,self.caller,n),'CONTEXT')

    def test_real_second_process_cannot_create_a_new_spend_owner(self):
        code='''import sys
from w2c_durable_receiver import DurableReceiver
try:
 x=DurableReceiver(sys.argv[1],b'A'*32,b'K'*32)
except Exception as e:
 print(str(e))
else:
 print('WRONG_SUCCESS'); x.close()
'''
        child=subprocess.run([sys.executable,'-c',code,str(self.path)],capture_output=True,text=True,timeout=10,env={**os.environ,'PYTHONPATH':str(Path(__file__).parent)})
        self.assertEqual(child.returncode,0,child.stderr)
        self.assertEqual(child.stdout.strip(),'OWNER_BUSY')

    def test_database_symlinks_and_hardlinks_refused(self):
        self.owner.close()
        original=self.path
        symlink=self.dir/'evil.sqlite'
        symlink.symlink_to(original)
        with self.assertRaises(OSError):
            DurableReceiver(symlink,self.receiver,self.secret)
        hard=self.dir/'hard.sqlite'
        os.link(original,hard)
        with self.assertRaisesRegex(ValueError,'UNTRUSTED_FILE'):
            DurableReceiver(original,self.receiver,self.secret)

    def test_clock_regression_fences_new_paid_operations(self):
        g,n=self.mint()
        self.clock_value=99
        with self.assertRaisesRegex(ValueError,'CLOCK_REGRESSION'):
            self.owner.consume(g,self.proposal,self.caller,n)
        self.clock_value=101
        with self.assertRaisesRegex(ValueError,'OWNER_UNAVAILABLE'):
            self.owner.offer(self.proposal,self.caller,8)

    def test_paid_ticket_still_rejects_actual_false_w1_transcript(self):
        # The cost ticket owns only a durable resource attempt. Full original
        # W1 arithmetic still performs every transcript tile and must refuse.
        import work_oracle as W
        zeros=[0]*W.CELLS
        header=H('durable-study-header')*9 + bytes(30)
        self.assertEqual(len(header),318)
        challenge=H('challenge',header)
        trace=H('w2c-durable-false-trace',challenge)
        proof=b'PNW1'+W.field_bytes(zeros)*3 + trace
        task=W.task_id(zeros,zeros)
        self.assertEqual(W.precheck(challenge,task,bytes([255])*32,proof)[3],
                         H('ticket',challenge,trace))
        proposal=H('w2c-proposal',header,proof)
        grant=self.owner.offer(proposal,self.caller,8)
        nonce,cost=solve(grant,65536)
        self.assertIsNotNone(nonce)
        self.assertEqual(self.owner.consume(grant,proposal,self.caller,nonce),
                         'READY_RESOURCE_ONLY')
        with self.assertRaisesRegex(ValueError,'^TRANSCRIPT
        # Here the parent first closes its DB owner, then a real subprocess
        # creates the durable row and calls os._exit without graceful close.
        self.owner.close()
        code='''import os,sys,json
from contract_wire import H
from w2c_durable_receiver import DurableReceiver,solve
p=sys.argv[1];o=DurableReceiver(p,b'A'*32,b'K'*32)
g=o.offer(H('fixed-proposal'),H('fixed-authenticated-caller'),8)
n,_=solve(g,65536)
a=o.consume(g,H('fixed-proposal'),H('fixed-authenticated-caller'),n)
assert a=='READY_RESOURCE_ONLY'
os._exit(0)
'''
        child=subprocess.run([sys.executable,'-c',code,str(self.path)],capture_output=True,text=True,timeout=15,env={**os.environ,'PYTHONPATH':str(Path(__file__).parent)})
        self.assertEqual(child.returncode,0,child.stderr)
        self.open_owner()
        self.assertEqual(self.owner.paid_rows(),1)
        g,n=self.mint()
        self.assertEqual(self.owner.consume(g,self.proposal,self.caller,n),'READY_RESOURCE_ONLY')

if __name__=='__main__':unittest.main(verbosity=2)
):
            W.verify(challenge,task,bytes([255])*32,proof)
        self.assertEqual(self.owner.consume(grant,proposal,self.caller,nonce),'REPLAY')

    def test_real_crash_after_durable_commit_and_reopen(self):
        # Here the parent first closes its DB owner, then a real subprocess
        # creates the durable row and calls os._exit without graceful close.
        self.owner.close()
        code='''import os,sys,json
from contract_wire import H
from w2c_durable_receiver import DurableReceiver,solve
p=sys.argv[1];o=DurableReceiver(p,b'A'*32,b'K'*32)
g=o.offer(H('fixed-proposal'),H('fixed-authenticated-caller'),8)
n,_=solve(g,65536)
a=o.consume(g,H('fixed-proposal'),H('fixed-authenticated-caller'),n)
assert a=='READY_RESOURCE_ONLY'
os._exit(0)
'''
        child=subprocess.run([sys.executable,'-c',code,str(self.path)],capture_output=True,text=True,timeout=15,env={**os.environ,'PYTHONPATH':str(Path(__file__).parent)})
        self.assertEqual(child.returncode,0,child.stderr)
        self.open_owner()
        self.assertEqual(self.owner.paid_rows(),1)
        g,n=self.mint()
        self.assertEqual(self.owner.consume(g,self.proposal,self.caller,n),'READY_RESOURCE_ONLY')

if __name__=='__main__':unittest.main(verbosity=2)
