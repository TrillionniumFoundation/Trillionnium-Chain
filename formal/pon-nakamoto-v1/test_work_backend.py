import os,unittest
from pathlib import Path
from unittest.mock import patch
from contract_wire import ROOT,H
import work_backend,work_oracle

class NativeWorkBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary=Path(os.environ.get('CARGO_TARGET_DIR',str(ROOT/'trillionnium/target')))/'release/examples/pon_work_io'
        if not cls.binary.is_file():raise RuntimeError('Build pon_work_io; absent binary is not a skipped pass')
    def test_proof_bytes_and_verified_product_equal_oracle(self):
        a=[i%31 for i in range(work_oracle.CELLS)];b=[i%17 for i in range(work_oracle.CELLS)];c=H('native-work-parity');target=bytes([255])*32
        expected=work_oracle.prove(c,a,b)
        with patch.dict(os.environ,TRNM_NATIVE_WORK=str(self.binary)):
            actual=work_backend.prove(c,a,b);self.assertEqual(actual,expected)
            self.assertEqual(work_backend.verify(c,work_oracle.task_id(a,b),target,actual),work_oracle.verify(c,work_oracle.task_id(a,b),target,expected))
    def test_wrong_statement_and_bad_trace_reject_without_fallback(self):
        a=[0]*work_oracle.CELLS;c=H('zero-check');proof=work_oracle.prove(c,a,a);task=work_oracle.task_id(a,a)
        with patch.dict(os.environ,TRNM_NATIVE_WORK=str(self.binary)):
            for challenge,t,p in [(H('changed'),task,proof),(c,H('wrong-task'),proof),(c,task,proof[:-1]+bytes([proof[-1]^1]))]:
                with self.assertRaisesRegex(ValueError,'NATIVE_WORK_INVALID'):work_backend.verify(challenge,t,bytes([255])*32,p)
    def test_missing_native_path_does_not_use_oracle(self):
        with patch.dict(os.environ,TRNM_NATIVE_WORK='/no/such/native-work'):
            with self.assertRaisesRegex(ValueError,'NATIVE_WORK_UNAVAILABLE'):work_backend.prove(bytes(32),[0]*work_oracle.CELLS,[0]*work_oracle.CELLS)

if __name__=='__main__':unittest.main(verbosity=2)
