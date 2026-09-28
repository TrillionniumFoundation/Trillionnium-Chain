"""Byte and verdict parity against separately coded native Rust probes.
Both implementations were produced in this change; external independent acceptance is absent.
"""
from pathlib import Path
import json,os,subprocess,tempfile,unittest
from contract_wire import *
from work_oracle import verify as oracle_verify
D=Path(__file__).parent/'vectors'
TARGET=Path(os.environ.get('CARGO_TARGET_DIR',str(ROOT/'trillionnium/target')))
MODE=os.environ.get('TRNM_NATIVE_MODE','debug')
WIRE=TARGET/MODE/'examples/pon_wire';WORK=TARGET/MODE/'examples/pon_work'
class InteropTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not WIRE.is_file()or not WORK.is_file():raise RuntimeError('Native probes must be built first; this suite must not be skipped')
        cls.v=json.loads((D/'expected.json').read_text())
    def probe(self,kind,file):return subprocess.run([str(WIRE),kind,str(D/file)],capture_output=True,text=True)
    def test_header(self):
        r=self.probe('header',self.v['header']['file']);self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(r.stdout.strip(),self.v['header']['challenge'])
    def test_all_command_tags(self):
        for row in self.v['transactions']:
            with self.subTest(tag=row['tag']):
                r=self.probe('tx',row['file']);self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(r.stdout.strip(),row['id'])
    def test_independent_sparse_tree_directions_agree(self):
        r=self.probe('state',self.v['state']['file']);self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(r.stdout.strip(),self.v['state']['root'])
    def test_rejection_vectors(self):
        for row in self.v['negative']:
            with self.subTest(file=row['file']):self.assertNotEqual(self.probe(row['kind'],row['file']).returncode,0)
    def test_work_certificate_parity(self):
        v=self.v['work'];r=subprocess.run([str(WORK),'verify',v['challenge'],v['task'],v['target'],str(D/v['file'])],capture_output=True,text=True)
        self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(r.stdout.split()[0],v['ticket'])
        result,_=oracle_verify(bytes.fromhex(v['challenge']),bytes.fromhex(v['task']),bytes.fromhex(v['target']),(D/v['file']).read_bytes());self.assertEqual(result.hex(),v['ticket'])
    def test_native_generation_reproduces_python_bytes(self):
        v=self.v['work']
        with tempfile.TemporaryDirectory()as directory:
            path=Path(directory)/'native.bin';r=subprocess.run([str(WORK),'prove',v['challenge'],str(D/v['inputs']),str(path)],capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(path.read_bytes(),(D/v['file']).read_bytes())
    def test_native_rejects_changed_context_and_output(self):
        v=self.v['work']
        with tempfile.TemporaryDirectory()as directory:
            path=Path(directory)/'bad.bin';b=bytearray((D/v['file']).read_bytes());b[32772]^=1;path.write_bytes(b)
            r=subprocess.run([str(WORK),'verify',v['challenge'],v['task'],v['target'],str(path)],capture_output=True,text=True);self.assertNotEqual(r.returncode,0)
            r=subprocess.run([str(WORK),'verify','11'*32,v['task'],v['target'],str(D/v['file'])],capture_output=True,text=True);self.assertNotEqual(r.returncode,0)
if __name__=='__main__':unittest.main(verbosity=2)
