"""Finite, independent Go-verifier versus Python producer/forger cost screen.

Experimental PNW1 bytes only. No actual chain, native W1 Rust, remote admission,
proof-of-useful-work lower bound, or independently administered hardware.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import tempfile
import time

from contract_wire import H
from work_oracle import prove, verify, task_id, field_bytes
from test_w1_go_differential import GO_SOURCE, HALF_TARGET, materials

CASES = ('zero', 'rank-one', 'sparse', 'dense', 'maintenance', 'near-modulus')


def _go(exe: Path, proof_file: Path, challenge: bytes, task: bytes, proof: bytes) -> dict:
    proof_file.write_bytes(proof)
    p = subprocess.run([str(exe), '--challenge='+challenge.hex(),
                        '--task='+task.hex(), '--target='+HALF_TARGET.hex(),
                        '--proof-file='+str(proof_file)],
                       check=False, text=True, capture_output=True, timeout=20)
    if p.returncode not in (0,1) or p.stderr:
        raise RuntimeError('Go independent verifier did not return a typed verdict')
    result = json.loads(p.stdout)
    if (result['status'] == 'verified') != (p.returncode == 0):
        raise RuntimeError('go verdict/exit divergence')
    return result


def campaign() -> dict:
    source_file = Path(__file__).resolve()
    go_file = GO_SOURCE/'main.go'
    oracle_file = source_file.parent/'work_oracle.py'
    with tempfile.TemporaryDirectory(prefix='trnm-w1-actual-') as td:
        binary=Path(td)/'verify-go'
        subprocess.run(['go','build','-o',str(binary),str(go_file)],
                       check=True,capture_output=True,timeout=60)
        version=subprocess.check_output(['go','version'],text=True).strip()
        rows=[]
        for kind in CASES:
            a,b=materials(kind)
            task=task_id(a,b)
            success=None
            start_ns=time.process_time_ns()
            for attempt in range(1,65):
                challenge=H('w1-fixed-screen',kind.encode(),struct.pack('<I',attempt))
                proof=prove(challenge,a,b)
                ticket=H('ticket',challenge,proof[-32:])
                if ticket<=HALF_TARGET:
                    success=(challenge,proof,attempt,ticket)
                    break
            full_producer_cpu_ns=time.process_time_ns()-start_ns
            if success is None:
                raise RuntimeError('honest search hit declared finite budget')
            challenge,proof,attempt,ticket=success
            python_ticket,_=verify(challenge,task,HALF_TARGET,proof)
            if python_ticket!=ticket:raise RuntimeError('reference producer/verifier mismatch')
            good=_go(binary,Path(td)/'honest.bin',challenge,task,proof)
            if good['status']!='verified' or good['ticket']!=ticket.hex():
                raise RuntimeError('Go verifier rejected the valid W1 transcript')
            # From-zero negative: public A/B and canonical C=0, but no actual
            # matrix multiplication, neural transcript or winning legal proof.
            start_ns=time.process_time_ns()
            forged_prefix=b'PNW1'+field_bytes(a)+field_bytes(b)+bytes(64*64*4)
            if len(forged_prefix)!=49156:raise RuntimeError('forgery framing')
            false=None
            for trial in range(1,1025):
                claim=H('w1-from-zero-false-claim',challenge,struct.pack('<I',trial))
                if H('ticket',challenge,claim)<=HALF_TARGET:
                    false=(forged_prefix+claim,trial)
                    break
            false_cpu_ns=time.process_time_ns()-start_ns
            if false is None:raise RuntimeError('false claim target-hit exhausted')
            fake,tries=false
            rejected=_go(binary,Path(td)/'false.bin',challenge,task,fake)
            if rejected.get('error')!='TRANSCRIPT':
                raise RuntimeError('forged ticket was not rejected by actual transcript verification')
            try: verify(challenge,task,HALF_TARGET,fake)
            except ValueError as exc:
                if str(exc)!='TRANSCRIPT':raise
            else:raise RuntimeError('Python incorrectly accepted false transcript')
            rows.append({
                'class':kind,'target_hex':HALF_TARGET.hex(),
                'challenge_hex':challenge.hex(), 'matrix_task_hex':task.hex(),
                'honest_attempts':attempt,'honest_full_producer_cpu_ns':full_producer_cpu_ns,
                'honest_proof_sha256':hashlib.sha256(proof).hexdigest(),
                'independent_go_valid_wall_ns':good['verification_wall_ns'],
                'false_ticket_hash_trials':tries,'false_from_zero_cpu_ns':false_cpu_ns,
                'false_proof_sha256':hashlib.sha256(fake).hexdigest(),
                'independent_go_rejection_wall_ns':rejected['verification_wall_ns'],
                'false_verdict':rejected['error'],'validated_chainwork':False,
            })
    return {
        'schema':'trnm-w1-full-proof-cross-language-cost-research-v1',
        'scope':'one local Go/Python host; correctness and finite costs only; no native Rust or WAN; not a fastest-adversary bound',
        'source_sha256':{
            'go':hashlib.sha256(go_file.read_bytes()).hexdigest(),
            'python_work_oracle':hashlib.sha256(oracle_file.read_bytes()).hexdigest(),
            'campaign':hashlib.sha256(source_file.read_bytes()).hexdigest(),
        },
        'go_version':version,'python_version':platform.python_version(),
        'cases':rows,'work_profile_qualified':False,'production_activation':False,
    }


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args()
    if args.output.exists() or args.output.is_symlink():
        p.error('output already exists; evidence must be create-only')
    data=campaign()
    # O_EXCL prevents accidental evidence overwrite. Caller owns directory trust.
    with os.fdopen(os.open(args.output,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),'w') as f:
        json.dump(data,f,sort_keys=True,indent=2)
        f.write('\n')
        f.flush();os.fsync(f.fileno())
    print(json.dumps({'schema':data['schema'],'cases':len(data['cases']),
                      'all_false_rejected':all(x['false_verdict']=='TRANSCRIPT' for x in data['cases']),
                      'output':str(args.output)},sort_keys=True))

if __name__=='__main__':main()
