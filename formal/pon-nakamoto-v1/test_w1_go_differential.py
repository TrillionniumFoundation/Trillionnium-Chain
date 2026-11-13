"""Actual full PNW1 proof Rust-independent Go/Python differential, research only.

Runs real 49,188-byte work proofs including full trace recalculation and
independent matrix product. Does NOT mine a native Node block or establish
adversarial minimum work, valid cost per energy, or public ingress fairness.
"""
import hashlib
import json
import os
import random
from pathlib import Path
import subprocess
import struct
import tempfile
import unittest

from contract_wire import H
from work_oracle import PROOF_BYTES, prove, verify, task_id, field_bytes

GO_SOURCE = Path(__file__).resolve().parent / 'w1_verify_go'
HALF_TARGET = bytes.fromhex('7f' + 'ff'*31)
MAX_TARGET = b'\xff' * 32


def materials(kind):
    if kind == 'zero': return [0]*4096, [0]*4096
    if kind == 'rank-one':
        a = [0]*4096; b = [0]*4096
        for i in range(64): a[i*64]=i+1; b[i]=(i*5+2)%100
        return a,b
    if kind == 'sparse':
        a = [0]*4096; b = [0]*4096
        for i in range(64): a[i*64+i]=i+1; b[i*64+i]=i+7
        return a,b
    if kind == 'maintenance':
        return ([(13*i+17)%257 for i in range(4096)],
                [(29*i+31)%263 for i in range(4096)])
    if kind == 'near-modulus':
        q = 4294967291
        return ([q-1-(i%7) for i in range(4096)],
                [q-1-((i*3)%11) for i in range(4096)])
    if kind == 'dense':
        return ([(i*13+17)%1009 for i in range(4096)],
                [(i*29+31)%1009 for i in range(4096)])
    raise ValueError(kind)


class GoW1FullDifferential(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='w1-go-research-')
        cls.exe = str(Path(cls.temp.name) / 'verify')
        subprocess.run(['go','build','-o',cls.exe,str(GO_SOURCE/'main.go')],
                       check=True,timeout=60,capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_go(self, challenge, task, target, proof):
        proof_path = Path(self.temp.name) / 'proof.bin'
        proof_path.write_bytes(proof)
        completed=subprocess.run([self.exe,'--challenge='+challenge.hex(),
                                  '--task='+task.hex(),'--target='+target.hex(),
                                  '--proof-file='+str(proof_path)],
                                 check=False,timeout=20,capture_output=True,text=True)
        self.assertEqual(completed.returncode in (0,1), True, completed.stderr)
        self.assertEqual(completed.stderr,'')
        result=json.loads(completed.stdout)
        self.assertEqual(result['schema'],'trnm-w1-go-scalar-verifier-research-v1')
        self.assertEqual(result['proof_bytes'],len(proof) if len(proof)==PROOF_BYTES else 0)
        self.assertGreaterEqual(result['verification_wall_ns'],0)
        self.assertEqual(completed.returncode,0 if result['status']=='verified' else 1)
        return result

    def case(self,kind):
        a,b=materials(kind)
        task=task_id(a,b)
        proof=None
        for nonce in range(32):
            challenge=H('go-w1-research-challenge',kind.encode(),struct.pack('<I',nonce))
            candidate=prove(challenge,a,b)
            ticket=H('ticket',challenge,candidate[-32:])
            if ticket<=HALF_TARGET:
                proof=candidate
                break
        self.assertIsNotNone(proof,'bounded search must have honest sample')
        py_ticket,py_product=verify(challenge,task,HALF_TARGET,proof)
        self.assertEqual(ticket,py_ticket)
        result=self.run_go(challenge,task,HALF_TARGET,proof)
        self.assertEqual(result['status'],'verified')
        self.assertEqual(result['ticket'],py_ticket.hex())
        self.assertEqual(result['product_sha256'],hashlib.sha256(field_bytes(py_product)).hexdigest())
        return challenge,task,proof

    def test_full_valid_proofs_six_input_classes(self):
        for kind in ('zero','rank-one','sparse','dense','maintenance','near-modulus'):
            with self.subTest(kind=kind):
                self.case(kind)

    def test_noncanonical_and_malformed_proof_rejections(self):
        challenge,task,proof=self.case('sparse')
        for name,mut,expected in (
            ('wrong magic',b'BAD1'+proof[4:],'VERSION'),
            ('short',proof[:-1],'LENGTH'),
            ('field',proof[:4]+b'\xff'*4+proof[8:],'FIELD'),
            ('wrong product',proof[:32772]+bytes([proof[32772]^1])+proof[32773:],'PRODUCT'),
        ):
            with self.subTest(name=name):
                result=self.run_go(challenge,task,HALF_TARGET,mut)
                self.assertEqual(result['error'],expected)

    def test_challenge_and_task_binding_fail_closed(self):
        challenge,task,proof=self.case('zero')
        bad_task=bytes([task[0]^1])+task[1:]
        self.assertEqual(self.run_go(challenge,bad_task,MAX_TARGET,proof)['error'],'TASK')
        changed=bytes([challenge[0]^1])+challenge[1:]
        self.assertEqual(self.run_go(changed,task,MAX_TARGET,proof)['error'],'TRANSCRIPT')
        self.assertEqual(self.run_go(challenge,task,bytes(32),proof)['error'],'TARGET')

    def test_ninety_six_bound_mutations_match_python_refusals(self):
        challenge,task,proof=self.case('maintenance')
        rng=random.Random(20261026)
        counts={}
        for index in range(96):
            region=index%4
            begin,end=((4,16388),(16388,32772),(32772,49156),(49156,49188))[region]
            offset=rng.randrange(begin,end)
            changed=bytearray(proof)
            changed[offset]^=1
            changed=bytes(changed)
            go=self.run_go(challenge,task,MAX_TARGET,changed)
            try:
                verify(challenge,task,MAX_TARGET,changed)
            except ValueError as exc:
                expected=str(exc)
            else:
                self.fail('reference accepted mutated proof')
            self.assertEqual(go['error'],expected,(region,offset))
            counts[expected]=counts.get(expected,0)+1
        self.assertEqual(sum(counts.values()),96)
        self.assertGreater(counts.get('TASK',0),0)
        self.assertGreater(counts.get('PRODUCT',0),0)
        self.assertGreater(counts.get('TRANSCRIPT',0),0)

    def test_forged_ticket_requires_full_transcript_rejection(self):
        challenge,task,proof=self.case('dense')
        # Attacker can change the claimed hash and search the cheap ticket.
        # No valid work is generated or credited by this operation.
        for nonce in range(1,256):
            fake=H('go-w1-false-trace',challenge,struct.pack('<I',nonce))
            if H('ticket',challenge,fake)<=HALF_TARGET:
                mutated=proof[:-32]+fake
                break
        else: self.fail('expected bounded false ticket')
        result=self.run_go(challenge,task,HALF_TARGET,mutated)
        self.assertEqual(result['error'],'TRANSCRIPT')
        self.assertGreater(result['verification_wall_ns'],0)
        with self.assertRaisesRegex(ValueError,'TRANSCRIPT'):
            verify(challenge,task,HALF_TARGET,mutated)


if __name__=='__main__': unittest.main(verbosity=2)
