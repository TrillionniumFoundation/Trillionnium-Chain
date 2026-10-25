"""Opt-in Go/Python 10-case full W1 byte differential. No native Chain authority."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

from contract_wire import H
import work_oracle as W

GO_ROOT = Path(__file__).resolve().parent / 'go_oracle'


class GoW1CrossLanguageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        go = shutil.which('go')
        if not go:
            raise RuntimeError('GO_TOOLCHAIN_REQUIRED_NOT_A_SKIPPED_PASS')
        cls.temp = tempfile.TemporaryDirectory()
        cls.binary = str(Path(cls.temp.name) / 'pon_w1_io')
        cls.env = dict(os.environ, GOWORK='off', GOPROXY='off', GOSUMDB='off')
        build = subprocess.run(
            [go, 'build', '-o', cls.binary, './cmd/pon_w1_io'],
            cwd=GO_ROOT, env=cls.env, capture_output=True, timeout=120)
        if build.returncode:
            raise RuntimeError('GO_BUILD_FAILED: '+build.stderr.decode(errors='replace')[:4096])
        cls.observations = []

    def call(self, mode, payload):
        self.assertLessEqual(len(payload), 96 + W.PROOF_BYTES + 1)
        return subprocess.run([self.binary,mode],input=payload,capture_output=True,
                              env=self.env,timeout=10)

    def test_ten_full_proof_parities_and_late_false_transcripts(self):
        for seed in range(10):
            challenge=H('go-differential-v0',struct.pack('<I',seed))
            a=[((i*7+seed)%97) if seed%3 else 0 for i in range(W.CELLS)]
            b=[((i*11+seed)%83) if seed%4 else 0 for i in range(W.CELLS)]
            payload=challenge+W.field_bytes(a)+W.field_bytes(b)
            native=self.call('prove',payload)
            self.assertEqual(native.returncode,0,native.stderr.decode(errors='replace'))
            original=W.prove(challenge,a,b)
            self.assertEqual(native.stdout,original)
            task=W.task_id(a,b)
            oracle_ticket,oracle_product=W.verify(challenge,task,bytes([255])*32,original)
            self.assertEqual(oracle_ticket,H('ticket',challenge,original[-32:]))
            self.assertEqual(len(oracle_product),W.CELLS)
            statement=challenge+task+bytes([255])*32+original
            result=self.call('verify',statement)
            self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))
            self.assertEqual(result.stdout,H('w2-go-oracle-receipt-test-only',statement))
            altered=bytearray(original)
            altered[-1]^=1
            bad=self.call('verify',challenge+task+bytes([255])*32+altered)
            self.assertNotEqual(bad.returncode,0)
            self.assertEqual(bad.stdout,b'')
            self.assertEqual(bad.stderr.strip(),b'Transcript')
            self.observations.append({
                'seed':seed,
                'challenge':challenge.hex(),
                'proof_sha256':hashlib.sha256(original).hexdigest(),
                'full_bytes_equal':True,
                'valid_go_verifier':True,
                'valid_python_verifier':True,
                'false_trace_rejected_by_go':True,
                'chainwork_authority':False,
            })

    def test_wrong_field_and_packet_length_reject_without_a_valid_proof(self):
        challenge=H('go-negative-no-valid-producer')
        raw=challenge+bytes(W.CELLS*8)
        short=self.call('prove',raw[:-1])
        self.assertNotEqual(short.returncode,0)
        self.assertEqual(short.stderr.strip(),b'Length')
        bad=bytearray(raw)
        bad[32:36]=struct.pack('<I',W.Q)
        noncanonical=self.call('prove',bad)
        self.assertNotEqual(noncanonical.returncode,0)
        self.assertEqual(noncanonical.stderr.strip(),b'Field')
        unknown=self.call('wrong-command',raw)
        self.assertNotEqual(unknown.returncode,0)
        self.assertEqual(unknown.stderr.strip(),b'Mode')

    @classmethod
    def tearDownClass(cls):
        if cls.observations:
            report={
                'schema':'trnm-go-python-w1-full-byte-differential-v0',
                'go_version_required':'1.23+',
                'source':'stdlib-only separate Go mathematical oracle and Python W1 oracle',
                'count':len(cls.observations),
                'independent_operator_review':False,
                'native_chain_consensus_authority':False,
                'cases':cls.observations,
            }
            path=os.environ.get('TRNM_GO_W1_PARITY_REPORT')
            if path:
                with open(path,'x',encoding='utf-8') as output:
                    json.dump(report,output,indent=2,sort_keys=True)
                    output.write('\n')
        if hasattr(cls,'temp'):
            cls.temp.cleanup()


if __name__=='__main__':
    unittest.main(verbosity=2)
