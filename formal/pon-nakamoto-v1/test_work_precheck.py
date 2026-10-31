"""Malformed work cannot demand branch replay; cheap passing work is still untrusted."""
import copy,struct,tempfile,unittest
from unittest.mock import patch
import ledger as L
import work_oracle as W
class WorkPrecheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory()as d:
            ledger=L.Ledger(d)
            try:cls.header,cls.transactions,cls.proof=ledger.make(L.GENESIS,[])
            finally:ledger.close()
    def test_bad_field_and_task_reject_before_state_replay_or_full_verification(self):
        malformed=bytearray(self.proof);malformed[4:8]=struct.pack('<I',W.Q)
        wrong_task=bytearray(self.proof);wrong_task[4:8]=struct.pack('<I',(int.from_bytes(wrong_task[4:8],'little')+1)%W.Q)
        for proof,error in [(bytes(malformed),'FIELD'),(bytes(wrong_task),'TASK')]:
            with tempfile.TemporaryDirectory()as d:
                ledger=L.Ledger(d)
                try:
                    with patch.object(ledger,'state_at',side_effect=AssertionError('state replay must not run')),patch.object(L.work,'verify',side_effect=AssertionError('full work must not run')):
                        with self.assertRaisesRegex(ValueError,error):ledger.admit(self.header,[],proof,L.PARAMS['genesis_timestamp']+1000)
                    self.assertEqual(ledger.db.execute('SELECT count(*) FROM blocks').fetchone()[0],1)
                finally:ledger.close()
    def test_bad_ticket_rejects_before_state_replay(self):
        header=L.header_decode(self.header);challenge=L.H('challenge',self.header);i=0
        while True:
            trace=L.H('audit-bad-ticket',L.u64(i));i+=1
            if L.H('ticket',challenge,trace)>header['target']:break
        bad=self.proof[:-32]+trace
        with tempfile.TemporaryDirectory()as d:
            ledger=L.Ledger(d)
            try:
                with patch.object(ledger,'state_at',side_effect=AssertionError('branch lookup')):
                    with self.assertRaisesRegex(ValueError,'TARGET'):ledger.admit(self.header,[],bad,L.PARAMS['genesis_timestamp']+1000)
            finally:ledger.close()
    def test_forged_passing_ticket_does_not_become_verified_work(self):
        header=L.header_decode(self.header);challenge=L.H('challenge',self.header);i=0
        while True:
            trace=L.H('audit-forged-passing',L.u64(i));i+=1
            if L.H('ticket',challenge,trace)<=header['target']:break
        bad=self.proof[:-32]+trace
        W.precheck(challenge,header['work_task'],header['target'],bad)
        with tempfile.TemporaryDirectory()as d:
            ledger=L.Ledger(d)
            try:
                with self.assertRaisesRegex(ValueError,'TRANSCRIPT|NATIVE_WORK_INVALID'):ledger.admit(self.header,[],bad,L.PARAMS['genesis_timestamp']+1000)
                self.assertEqual(ledger.db.execute('SELECT count(*) FROM blocks').fetchone()[0],1)
            finally:ledger.close()
    def test_valid_certificate_still_executes_actual_full_verifier(self):
        with tempfile.TemporaryDirectory()as d:
            ledger=L.Ledger(d)
            try:
                original=L.work.verify
                with patch.object(L.work,'verify',wraps=original)as observed:
                    bid=ledger.admit(self.header,[],self.proof,L.PARAMS['genesis_timestamp']+1000)
                    self.assertEqual(observed.call_count,1)
                ledger.recover();self.assertEqual(ledger.active()[0],bid)
            finally:ledger.close()

class FourFromZeroTicketRegression(unittest.TestCase):
    """P0: four distinct forged traces, identical task/challenge/target, no valid work."""
    def test_four_ticket_hits_replay_and_reject(self):
        import time
        a=[0]*W.CELLS
        challenge=bytes(range(32))
        target=bytes.fromhex('7f'+'ff'*31)
        task=W.task_id(a,a)
        self.assertEqual(task.hex(),'6618f8a794517852f621993ccb6ac311c684e1db2b9d1d47166fa00a744c4c29')
        prefix=b'PNW1'+W.field_bytes(a)+W.field_bytes(a)+W.field_bytes(a)
        expected=(
            'e20adbeeda03ed387f4a0ddb92be0210c56047c19f4bbf3768df51619a8c7888',
            '516f779a970c30a78736aecece4fa24d2c55f9932ceaf27657ac2903367464b8',
            '70882ef88c393f966c8f58f51dbf953045e7ba09bae4ea3ab9590e19afe0e720',
            '23490d58b41f730b287d9eeaef73e9308dc8f3057ec591fbcbd00981a3ac768d',
        )
        cases=[]
        with patch.object(W,'prove',side_effect=AssertionError('valid W1 proof forbidden')):
            for nonce in range(128):
                trace=L.H('public-v3-from-zero-v1',challenge,struct.pack('<Q',nonce))
                ticket=L.H('ticket',challenge,trace)
                if ticket <= target:
                    cases.append((nonce,trace,ticket,prefix+trace))
                if len(cases)==4:break
            self.assertEqual(len(cases),4)
            self.assertEqual([row[0] for row in cases],[0,1,2,3])
            self.assertEqual([row[1].hex() for row in cases],list(expected))
            observations=[]
            for nonce,trace,ticket,proof in cases:
                self.assertEqual(len(proof),W.PROOF_BYTES)
                started=time.process_time_ns()
                self.assertEqual(W.precheck(challenge,task,target,proof)[3],ticket)
                precheck_ns=time.process_time_ns()-started
                with patch.object(W,'evaluate',wraps=W.evaluate) as replay:
                    started=time.process_time_ns()
                    with self.assertRaisesRegex(ValueError,'^TRANSCRIPT$'):
                        W.verify(challenge,task,target,proof)
                    receiver_ns=time.process_time_ns()-started
                self.assertEqual(replay.call_count,1)
                self.assertGreaterEqual(precheck_ns,0)
                self.assertGreaterEqual(receiver_ns,0)
                self.assertEqual(proof[-32:],trace)
                observations.append({
                    'nonce':nonce,'trace':trace.hex(),'ticket':ticket.hex(),
                    'proof_sha256':__import__('hashlib').sha256(proof).hexdigest(),
                    'precheck_cpu_ns':precheck_ns,'receiver_oracle_cpu_ns':receiver_ns,
                    'replay_calls':replay.call_count,'outcome':'TRANSCRIPT',
                    'verified_work':False,
                })
            report={
                'schema':'trnm-four-from-zero-python-oracle-p0-v1',
                'challenge':challenge.hex(),'target':target.hex(),'task':task.hex(),
                'proof_generation_used':False,'cases':observations,
                'native_node_state_verified':False,'host_cpu_owner_verified':False,
                'production_activation':False,
            }
            print(__import__('json').dumps(report,sort_keys=True))
            # New, exclusive report path; never overwrite earlier measurements.
            path=__import__('os').environ.get('TRNM_W1_FOUR_PY_REPORT')
            if path:
                with open(path,'x',encoding='utf-8') as stream:
                    __import__('json').dump(report,stream,indent=2,sort_keys=True)
                    stream.write('\n')
        # This oracle-only test grants no Node, chainwork, CPU-owner or WAN acceptance.

if __name__=='__main__':unittest.main(verbosity=2)
