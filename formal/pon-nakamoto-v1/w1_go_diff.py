"""Strict comparison of independent Go full W1 material with original Python oracle.

A fixed synthetic challenge is NOT a verified native header or a mining ticket.
The result checks byte-identical 49,188-byte proof construction, not hardness.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from contract_wire import H
from work_oracle import task_id, prove, PROOF_BYTES, CELLS


def compare(go_binary: Path) -> dict:
    if not go_binary.is_file():
        raise ValueError('MISSING_GO_BINARY')
    proc = subprocess.run([str(go_binary.resolve())], check=True, capture_output=True,
                          timeout=10, text=True)
    observed = json.loads(proc.stdout)
    if not isinstance(observed, dict) or observed.get('schema') != 'pon-independent-w1-scalar-go-v1':
        raise ValueError('GO_SCHEMA')
    if observed.get('consensus_activation') is not False or observed.get('work_hardness_accepted') is not False:
        raise ValueError('GO_AUTHORITY_CLAIM')
    a = [(13*i+17)%257 for i in range(CELLS)]
    b = [(29*i+31)%263 for i in range(CELLS)]
    challenge = H('challenge', b'stable-pow-input')
    task = task_id(a,b)
    proof = prove(challenge,a,b)
    checked = {'challenge':challenge.hex(),'task':task.hex(),
               'trace':proof[-32:].hex(),'proof_sha256':hashlib.sha256(proof).hexdigest(),
               'proof_bytes':PROOF_BYTES}
    for key,value in checked.items():
        if observed.get(key) != value:
            raise ValueError(f'GO_PYTHON_MISMATCH {key}')
    return {'schema':'pon-w1-go-python-exact-proof-differential-v1',
            'cross_language_equal':True, 'checked':checked,
            'go_binary_sha256':hashlib.sha256(go_binary.read_bytes()).hexdigest(),
            'proof_is_real_work_for_admitted_block':False,
            'test_only_challenge':True,'full_node_executed':False,
            'hardness_accepted':False,'public_sybil_safety_accepted':False}

if __name__=='__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--go-binary',type=Path,required=True)
    p.add_argument('--output',type=Path)
    ns=p.parse_args()
    result=compare(ns.go_binary)
    data=json.dumps(result,sort_keys=True,indent=2)+'\n'
    if ns.output:
        with ns.output.open('x',encoding='utf-8') as f:f.write(data)
    else:
        print(data,end='')
