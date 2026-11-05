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
if __name__=='__main__':unittest.main(verbosity=2)
