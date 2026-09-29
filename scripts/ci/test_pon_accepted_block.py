#!/usr/bin/env python3
"""A complete accepted block vector, not only syntax-valid transaction samples."""
from pathlib import Path
import json,os,subprocess,sys,tempfile,unittest
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'formal/pon-nakamoto-v1'))
from ledger import Ledger,GENESIS,PARAMS,header_decode,H,state_root,genesis_state
D=ROOT/'formal/pon-nakamoto-v1/vectors/accepted-block'
TARGET=Path(os.environ.get('CARGO_TARGET_DIR',str(ROOT/'trillionnium/target')))
MODE=os.environ.get('TRNM_NATIVE_MODE','release')
class AcceptedBlockTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected=json.loads((D/'expected.json').read_text())
        cls.wire=TARGET/MODE/'examples/pon_wire';cls.work=TARGET/MODE/'examples/pon_work'
        if not cls.wire.is_file()or not cls.work.is_file():raise RuntimeError('Build native probes; missing verifier is not a skip')
    def test_genesis_and_post_state_match_native_sparse_root(self):
        self.assertEqual(GENESIS.hex(),self.expected['genesis'])
        self.assertEqual(state_root(genesis_state()).hex(),self.expected['genesis_state_root'])
        for name,key in [('genesis-state.json','genesis_state_root'),('post-state.json','post_state_root')]:
            r=subprocess.run([str(self.wire),'state',str(D/name)],capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(r.stdout.strip(),self.expected[key])
    def test_header_transaction_and_work_validate_natively(self):
        for name,kind,key in [('header.bin','header','header_challenge'),('transaction.bin','tx','tx_id')]:
            r=subprocess.run([str(self.wire),kind,str(D/name)],capture_output=True,text=True);self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(r.stdout.strip(),self.expected[key])
        e=self.expected;r=subprocess.run([str(self.work),'verify',e['header_challenge'],e['work_task'],e['target'],str(D/'work.bin')],capture_output=True,text=True)
        self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(r.stdout.split()[0],e['ticket'])
    def test_actual_application_accepts_exact_block_and_state(self):
        with tempfile.TemporaryDirectory()as d:
            l=Ledger(d)
            try:
                bid=l.admit((D/'header.bin').read_bytes(),[(D/'transaction.bin').read_bytes()],(D/'work.bin').read_bytes(),self.expected['observed_logical_time']);l.activate(bid)
                self.assertEqual(bid.hex(),self.expected['block_id']);self.assertEqual(state_root(l.read_active()[2]).hex(),self.expected['post_state_root'])
            finally:l.close()
    def test_mutated_body_cannot_commit(self):
        b=bytearray((D/'transaction.bin').read_bytes());b[-1]^=1
        with tempfile.TemporaryDirectory()as d:
            l=Ledger(d)
            try:
                with self.assertRaises(ValueError):l.admit((D/'header.bin').read_bytes(),[bytes(b)],(D/'work.bin').read_bytes(),self.expected['observed_logical_time'])
                self.assertEqual(l.active()[0],GENESIS);self.assertEqual(l.db.execute('SELECT count(*) FROM blocks').fetchone()[0],1)
            finally:l.close()
if __name__=='__main__':unittest.main(verbosity=2)
