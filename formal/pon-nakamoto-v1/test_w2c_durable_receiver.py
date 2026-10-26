"""P5 W2-C local durable paid-spend negative tests; never consensus authority."""
import hashlib
import os
import sqlite3
import stat
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from dataclasses import replace
import work_oracle as W
from contract_wire import H
from w2c_receiver_admission import solve
from w2c_durable_receiver import DurableReceiverAdmission as D

RECEIVER = bytes([11])*32
SECRET = bytes([12])*32
CALLER = bytes([13])*32
PROPOSAL = H('w2c-durable-proposal-test')


def entropy():
    current = 0
    def next_bytes(n):
        nonlocal current
        current += 1
        return hashlib.sha256(current.to_bytes(8,'little')).digest()[:n]
    return next_bytes


class DurablePaidSpendTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def open(self, **kwargs):
        return D(self.root, RECEIVER, SECRET, entropy=entropy(), **kwargs)

    def paid(self, owner, proposal=PROPOSAL, caller=CALLER, now=100):
        grant = owner.offer(proposal,caller,8,now)
        nonce, cost = solve(grant, 65536)
        self.assertIsNotNone(nonce)
        self.assertEqual(cost['status'],'TARGET_HIT_UNVERIFIED')
        return grant, nonce

    def test_32_way_paid_race_has_one_durable_ready(self):
        with self.open() as owner:
            grant, nonce = self.paid(owner)
            with ThreadPoolExecutor(max_workers=8) as workers:
                observations = list(workers.map(
                    lambda _: owner.consume(grant,PROPOSAL,CALLER,nonce,110),
                    range(32)))
            self.assertEqual(observations.count('READY_RESOURCE_ONLY'),1)
            self.assertEqual(observations.count('REPLAY'),31)
            self.assertEqual(owner.paid_count(),1)

    def test_restart_with_same_key_and_reused_rng_rotates_epoch(self):
        with self.open() as original:
            grant, nonce = self.paid(original)
            first_epoch=original.epoch
            self.assertEqual(original.consume(grant,PROPOSAL,CALLER,nonce,110),
                             'READY_RESOURCE_ONLY')
        # A crash/restart is modelled by closing the old owner and opening the
        # unchanged directory with EXACTLY the same receiver/key/RNG sequence.
        with self.open() as restarted:
            self.assertNotEqual(restarted.epoch,first_epoch)
            self.assertEqual(restarted.consume(grant,PROPOSAL,CALLER,nonce,111),
                             'CONTEXT')
            self.assertEqual(restarted.paid_count(),0)
            next_grant,next_nonce=self.paid(restarted)
            self.assertEqual(restarted.consume(next_grant,PROPOSAL,CALLER,next_nonce,112),
                             'READY_RESOURCE_ONLY')
        with self.open() as third:
            self.assertNotEqual(third.epoch,first_epoch)
            self.assertEqual(third.consume(grant,PROPOSAL,CALLER,nonce,113),
                             'CONTEXT')

    def test_same_store_second_live_owner_fails_before_issuing(self):
        with self.open() as owner:
            grant,nonce=self.paid(owner)
            with self.assertRaisesRegex(ValueError,'EXCLUSIVE_RECEIVER_OWNER'):
                self.open()
            self.assertEqual(owner.consume(grant,PROPOSAL,CALLER,nonce,115),
                             'READY_RESOURCE_ONLY')

    def test_real_child_unclean_exit_releases_flock_and_fences_old_epoch(self):
        import json
        import subprocess
        import sys
        from w2c_receiver_admission import Grant
        out=self.root/'child-paid-receipt.json'
        # This is an actual separate Python process. It commits the paid row
        # and exits without destructor, close(), context manager or atexit.
        script = r'''
import json,os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[3])
from contract_wire import H
from w2c_receiver_admission import solve
from w2c_durable_receiver import DurableReceiverAdmission as D
owner=D(sys.argv[1],bytes([11])*32,bytes([12])*32)
p=H('w2c-durable-proposal-test')
g=owner.offer(p,bytes([13])*32,8,100)
n,c=solve(g,65536)
assert n is not None and owner.consume(g,p,bytes([13])*32,n,110)=='READY_RESOURCE_ONLY'
data={'epoch':owner.epoch.hex(),'nonce':n,
      'grant':{k:(v.hex() if isinstance(v,bytes) else v)
               for k,v in vars(g).items()}}
path=Path(sys.argv[2])
with path.open('x',encoding='utf-8') as f:
    json.dump(data,f)
    f.flush()
    os.fsync(f.fileno())
os._exit(17)
'''
        completed=subprocess.run([sys.executable,'-c',script,str(self.root),
                                   str(out),str(Path(__file__).resolve().parent)],
                                  stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                  text=True,timeout=30)
        self.assertEqual(completed.returncode,17,completed.stderr)
        payload=json.loads(out.read_text())
        values={k:(bytes.fromhex(v) if k in
                 ('receiver','epoch','proposal','token','mac') else v)
                for k,v in payload['grant'].items()}
        old=Grant(**values)
        with self.open() as next_owner:
            self.assertNotEqual(next_owner.epoch.hex(),payload['epoch'])
            self.assertEqual(next_owner.consume(
                old,PROPOSAL,CALLER,payload['nonce'],111),'CONTEXT')
            self.assertEqual(next_owner.paid_count(),0)
            # Old spent rows are pruned only after a durable new epoch. This
            # does not claim a physical power loss or cross-host exclusivity.

    def test_wrong_recovery_key_cannot_resume_old_epoch(self):
        with self.open() as owner:
            grant,nonce=self.paid(owner)
        with self.assertRaisesRegex(ValueError,'OWNER_CREDENTIAL_CHANGED'):
            D(self.root,RECEIVER,bytes([99])*32,entropy=entropy())
        with self.open() as next_owner:
            self.assertEqual(next_owner.consume(grant,PROPOSAL,CALLER,nonce,110),'CONTEXT')

    def test_private_directory_and_file_permissions_are_mandatory(self):
        os.chmod(self.root, 0o755)
        with self.assertRaisesRegex(ValueError,'PRIVATE_DIRECTORY_REQUIRED'):
            self.open()
        os.chmod(self.root, 0o700)
        with self.open():
            pass
        os.chmod(self.root/'w2c-paid.sqlite',0o644)
        with self.assertRaisesRegex(ValueError,'PRIVATE_REGULAR_FILE_REQUIRED'):
            self.open()

    def test_paid_insert_fault_never_returns_ready(self):
        with self.open() as owner:
            grant,nonce=self.paid(owner)
            owner.conn.execute("CREATE TRIGGER deny_paid BEFORE INSERT ON paid "
                               "BEGIN SELECT RAISE(ABORT,'injected-disk-failure'); END")
            with self.assertRaises(sqlite3.DatabaseError):
                owner.consume(grant,PROPOSAL,CALLER,nonce,115)
            self.assertEqual(owner.paid_count(),0)
            owner.conn.execute('DROP TRIGGER deny_paid')
            self.assertEqual(owner.consume(grant,PROPOSAL,CALLER,nonce,116),
                             'READY_RESOURCE_ONLY')

    def test_capacity_refusal_then_expiry_reclaims_only_original_rows(self):
        with self.open(capacity=1,lifetime_ms=100) as owner:
            a,an=self.paid(owner)
            b,bn=self.paid(owner)
            self.assertEqual(owner.consume(a,PROPOSAL,CALLER,an,110),
                             'READY_RESOURCE_ONLY')
            self.assertEqual(owner.consume(b,PROPOSAL,CALLER,bn,111),
                             'PAID_CAPACITY_BUSY')
            self.assertEqual(owner.paid_count(),1)
            fresh,fn=self.paid(owner,now=201)
            self.assertEqual(owner.consume(fresh,PROPOSAL,CALLER,fn,210),
                             'READY_RESOURCE_ONLY')
            self.assertEqual(owner.paid_count(),1)

    def test_modified_caller_proposal_mac_and_clock_do_not_grant(self):
        with self.open() as owner:
            grant,nonce=self.paid(owner)
            self.assertEqual(owner.consume(grant,PROPOSAL,bytes(32),nonce,110),
                             'CONTEXT')
            self.assertEqual(owner.consume(grant,H('wrong'),CALLER,nonce,111),
                             'CONTEXT')
            self.assertEqual(owner.consume(replace(grant,bits=9),PROPOSAL,CALLER,nonce,112),
                             'GRANT_MAC')
            self.assertEqual(owner.consume(replace(grant,mac=bytes(32)),PROPOSAL,CALLER,nonce,113),
                             'GRANT_MAC')
            self.assertEqual(owner.consume(grant,PROPOSAL,CALLER,nonce,114),
                             'READY_RESOURCE_ONLY')
            with self.assertRaisesRegex(ValueError,'CLOCK_REGRESSION'):
                owner.offer(PROPOSAL,CALLER,8,113)

    def test_paid_false_w1_transcript_still_no_verified_work(self):
        zeros=[0]*W.CELLS
        challenge=H('w2c-durable-W1-challenge')
        bad=b'PNW1'+W.field_bytes(zeros)*3+H('fake-only-transcript',challenge)
        statement=H('w2c-false-proof-receipt',bad,challenge)
        task=W.task_id(zeros,zeros)
        with self.open() as owner:
            grant,nonce=self.paid(owner,proposal=statement)
            self.assertEqual(owner.consume(grant,statement,CALLER,nonce,111),
                             'READY_RESOURCE_ONLY')
            with self.assertRaisesRegex(ValueError,'^TRANSCRIPT$'):
                W.verify(challenge,task,bytes([255])*32,bad)
            self.assertEqual(owner.consume(grant,statement,CALLER,nonce,112),'REPLAY')
            self.assertEqual(owner.paid_count(),1)
            self.assertFalse(hasattr(owner,'VerifiedWork'))


if __name__=='__main__':
    unittest.main(verbosity=2)
