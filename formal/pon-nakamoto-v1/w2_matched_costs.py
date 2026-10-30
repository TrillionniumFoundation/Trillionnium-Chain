"""Matched W1/W2-A/W2-B/W2-C finite CPU comparison; research-only.

One exact challenge/task/target and canonical A/B across all candidates.
The W2 alternatives are NOT mutually compatible proof profiles, not
cryptographic hardness proofs and not a production consensus switch.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import time
from pathlib import Path
from contract_wire import H
import work_oracle as W
import w2a_merkle_sampling as A
import w2b_relation_witness as B
import w2c_separated_security_pow as C

def observed(operation):
    cpu, wall = time.process_time_ns(), time.perf_counter_ns()
    value = operation()
    return value, dict(process_cpu_ns=time.process_time_ns()-cpu,
                       elapsed_wall_ns=time.perf_counter_ns()-wall)

def compare(seed: int=1, sample_count: int=8,
            security_bits=(8,12), security_cap: int=65536):
    if type(seed) is not int or not 0 <= seed < (1<<64):
        raise ValueError('SEED')
    if type(sample_count) is not int or not 1 <= sample_count <= 32:
        raise ValueError('SAMPLES')
    if not security_bits or len(set(security_bits))!=len(security_bits) or any(
            type(x) is not int or not 8 <= x <= 28 for x in security_bits):
        raise ValueError('DIFFICULTY')
    if type(security_cap) is not int or not 1 <= security_cap <= C.MAX_ATTEMPTS:
        raise ValueError('CAP')
    header = H('w2-comparison-header',seed.to_bytes(8,'little')) * 9 + bytes(30)
    assert len(header) == C.HEADER_BYTES
    challenge = H('challenge',header)
    a = [(i*7+seed)%97 for i in range(W.CELLS)]
    b = [(i*11+seed)%89 for i in range(W.CELLS)]
    task, target = W.task_id(a,b), bytes([255])*32
    good, producer = observed(lambda:W.prove(challenge,a,b))
    _, full_check = observed(lambda:W.verify(challenge,task,target,good))
    wrong_trace = H('w2-comparison-false-trace',challenge)
    if wrong_trace == good[-32:]:
        raise AssertionError('MISSING_FALSE_TRACE')
    bad = b'PNW1' + W.field_bytes(a) + W.field_bytes(b) + W.field_bytes([0]*W.CELLS) + wrong_trace
    def reject_false():
        try:
            W.verify(challenge,task,target,bad)
        except ValueError as err:
            if str(err) == 'TRANSCRIPT':
                return 'TRANSCRIPT'
            raise
        raise AssertionError('FALSE_W1_ACCEPTED')
    _, false_check = observed(reject_false)
    report = {
        'schema':'pon-w2-same-task-compare-research-v0',
        'source':'Python equivalent oracles; no native Rust or independent peer',
        'challenge':challenge.hex(),'task':task.hex(),'target':target.hex(),
        'header_sha256':hashlib.sha256(header).hexdigest(),
        'material':{'seed':seed,'a_sha256':hashlib.sha256(W.field_bytes(a)).hexdigest(),
                    'b_sha256':hashlib.sha256(W.field_bytes(b)).hexdigest()},
        'hardware_scope':'nonexclusive process CPU; no GPU, ASIC or power meter',
        'independent_review':False,'public_network_ready':False,
        'consensus_activation':False,
        'w1':{'valid_producer':producer,'valid_verifier':full_check,
              'from_zero_full_refusal':false_check,'false_result':'TRANSCRIPT',
              'proof_bytes':len(good),'cheapest_miner_hardness_proven':False},
    }
    sidecar, a_make = observed(lambda:A.make_sidecar(challenge,a,b,sample_count))
    accepted, a_verify = observed(lambda:A.verify_sidecar(challenge,a,b,sidecar,sample_count))
    corrupt_index,corrupt = A.corrupted_sidecar(challenge,a,b,sample_count)
    missed, a_false = observed(lambda:A.verify_sidecar(challenge,a,b,corrupt,sample_count))
    if not accepted or not missed:
        raise AssertionError('W2A_COUNTEREXAMPLE_MISSING')
    report['w2a']={'sample_count':sample_count,'sidecar_producer':a_make,
                   'valid_sample_verifier':a_verify,'false_tile_filter':a_false,
                   'unsampled_corrupt_index':corrupt_index,
                   'false_tile_missed':True,'complete_proof':False,'consensus_activation':False}
    witness, b_make = observed(lambda:B.construct(challenge,a,b))
    result, b_check = observed(lambda:B.check_relation(challenge,task,target,good,witness))
    if result['cryptographic_proof'] or result['verified_work']:
        raise AssertionError('W2B_UNAUTHORIZED_PROOF')
    report['w2b']={'witness_bytes':len(witness.trace_tiles),'construction':b_make,
                   'full_replay_relation':b_check,'succinct_verifier':False,
                   'cryptographic_proof':False}
    arms=[]
    for bits in security_bits:
        for label,proof in [('valid-W1',good),('false-W1',bad)]:
            candidate,cost=C.search(header,proof,bits,security_cap)
            verification,verify_cost = observed(
                lambda:C.validate(candidate,task,bits)) if candidate else (None,None)
            if label=='false-W1' and verification and verification['outcome']!='W1_TRANSCRIPT':
                raise AssertionError('FALSE_W1_PROMOTED')
            if verification and verification['verified_work'] is not False:
                raise AssertionError('W2C_UNAUTHORIZED_WORK')
            arms.append({'arm':label,'security_bits':bits,'search':cost,
                         'complete_W1_result':verification,'receiver':verify_cost,
                         'GPU_cost':None,'valid_chainwork':False})
    report['w2c']={'arms':arms,'separate_security_hashing_not_neural_work':True,
                   'attacker_min_cost_bound':None,'consensus_activation':False}
    return report

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seed',type=int,default=1)
    parser.add_argument('--samples',type=int,default=8)
    parser.add_argument('--security-bits',nargs='+',type=int,default=[8,12])
    parser.add_argument('--security-cap',type=int,default=65536)
    parser.add_argument('--out',type=Path)
    args=parser.parse_args()
    result=compare(args.seed,args.samples,tuple(args.security_bits),args.security_cap)
    raw=json.dumps(result,sort_keys=True,indent=2)+'\n'
    if args.out:
        with args.out.open('x',encoding='utf-8') as stream:
            stream.write(raw)
    else:
        print(raw,end='')

if __name__=='__main__':
    main()
