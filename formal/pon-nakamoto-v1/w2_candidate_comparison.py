"""P5 finite same-input W1 / W2-A / W2-B / W2-C Python research comparison.

Not a proof of cheapest adversary, hardware neutrality, any cryptographic
soundness of W2-A/B, native node validity, chainwork, or model improvement.
Every row shares the same challenge and canonical 64x64 A/B input.
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


def timed(action):
    cpu,wall=time.process_time_ns(),time.perf_counter_ns()
    value=action()
    return value,{'python_process_cpu_ns':time.process_time_ns()-cpu,
                  'wall_ns':time.perf_counter_ns()-wall}


def report(seed: int, sample_count: int, security_bits: tuple[int, ...], security_cap: int):
    if type(seed) is not int or not 0 <= seed < 2**64 or not 1 <= sample_count <= 32:
        raise ValueError('SEED_OR_SAMPLE')
    if not security_bits or any(not 8 <= b <= 28 for b in security_bits):
        raise ValueError('BITS')
    if not 1 <= security_cap <= C.MAX_ATTEMPTS:
        raise ValueError('CAP')
    # W2-C's sample Header determines the SAME W1 challenge for every arm.
    header=H('w2-comparison-header',seed.to_bytes(8,'little'))*9 + bytes(30)
    assert len(header)==318
    challenge=H('challenge',header)
    a=[(i * 7 + seed) % 97 for i in range(W.CELLS)]
    b=[(i * 11 + seed) % 89 for i in range(W.CELLS)]
    task=W.task_id(a,b)
    target=bytes([255])*32  # reference relation eligibility, NOT a live target
    proof, honest_gen=timed(lambda:W.prove(challenge,a,b))
    (_, valid_check)=timed(lambda:W.verify(challenge,task,target,proof))
    false_trace=H('w2-comparison-false-trace',challenge)
    if false_trace==proof[-32:]:
        raise AssertionError('NO_FALSE_NEGATIVE_CASE')
    bad=b'PNW1'+W.field_bytes(a)+W.field_bytes(b)+W.field_bytes([0]*W.CELLS)+false_trace
    def false_w1_check():
        try:
            W.verify(challenge,task,target,bad)
        except ValueError as err:
            if str(err)!='TRANSCRIPT':
                raise
            return 'TRANSCRIPT'
        raise AssertionError('FALSE_W1_ACCEPTED')
    _,false_check=timed(false_w1_check)
    result={'schema':'trnm-w2-matched-research-comparison-v0',
            'header_sha256':hashlib.sha256(header).hexdigest(),
            'challenge':challenge.hex(),'task':task.hex(),
            'target':'ff'*32,
            'material':{'seed':seed,'a_sha256':hashlib.sha256(W.field_bytes(a)).hexdigest(),
                        'b_sha256':hashlib.sha256(W.field_bytes(b)).hexdigest()},
            'hardware_scope':'single Python process; not exclusive or GPU/ASIC',
            'independent_review':False,'native_work_acceptance':False,
            'consensus_activation':False,'w1':{'valid_producer':honest_gen,
                'valid_verifier':valid_check,
                'new_false_claim_creation_cpu_unknown':True,
                'from_zero_full_refusal':false_check,'false_result':'TRANSCRIPT',
                'proof_bytes':len(proof)}}
    # W2-A can reject sampled invalid tiles; its positive bypass proves
    # why passing a sidecar must not supply consensus authority.
    sidecar, a_prod=timed(lambda:A.make_sidecar(challenge,a,b,sample_count))
    good, a_verify=timed(lambda:A.verify_sidecar(challenge,a,b,sidecar,sample_count))
    bad_idx, wrong_sidecar=A.corrupted_sidecar(challenge,a,b,sample_count)
    wrong, a_false_verify=timed(lambda:A.verify_sidecar(challenge,a,b,wrong_sidecar,sample_count))
    if not good or not wrong:
        raise AssertionError('W2A_KNOWN_UNSOUND_CONTROL_MISSING')
    result['w2a']={'tile_openings':sample_count,'construction':a_prod,
                   'valid_sample_check':a_verify,
                   'one_tile_forgery_filter':a_false_verify,
                   'one_tile_corrupted_index':bad_idx,
                   'false_tile_accepted_by_filter':True,
                   'cryptographic_proof':False,'consensus_activation':False}
    # W2-B's exact witness is a full-replay reference with extra witness bytes;
    # it offers ZERO succinctness or cryptographic proof.
    witness,b_prod=timed(lambda:B.construct(challenge,a,b))
    w_result,b_verify=timed(lambda:B.check_relation(challenge,task,target,proof,witness))
    if w_result['cryptographic_proof'] or w_result['verified_work']:
        raise AssertionError('UNAUTHORIZED_PROOF_PROMOTION')
    result['w2b']={'witness_bytes':len(witness.trace_tiles),'construction':b_prod,
                   'relation_full_replay':b_verify,
                   'cryptographic_proof':False,'succinct_verification':False}
    candidates=[]
    for bits in security_bits:
        for name,p in (('valid-original-W1',proof),('from-zero-false-W1',bad)):
            candidate, cost = C.search(header,p,bits,security_cap)
            verdict,vcost=timed(lambda:C.validate(candidate,task,bits)) if candidate else (None,None)
            if name=='from-zero-false-W1' and verdict and verdict['outcome']!='W1_TRANSCRIPT':
                raise AssertionError('W2C_FALSE_W1_ACCEPTED')
            if verdict and verdict['verified_work'] is not False:
                raise AssertionError('W2C_UNAUTHORIZED_RESULT')
            candidates.append({'arm':name,'security_bits':bits,'search':cost,
                               'full_w1_result':verdict,'total_observed_validation':vcost,
                               'independent_security_pow_not_neural':True})
    result['w2c']={'arms':candidates,'consensus_activation':False,
                   'actual_GPU_cost':None,
                   'attacker_hardware_lower_bound':None}
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seed',type=int,default=1)
    parser.add_argument('--samples',type=int,default=8)
    parser.add_argument('--security-bits',type=int,nargs='+',default=[8,12])
    parser.add_argument('--security-cap',type=int,default=65536)
    parser.add_argument('--out',type=Path)
    args=parser.parse_args()
    if len(args.security_bits)!=len(set(args.security_bits)):
        parser.error('duplicate difficulty')
    doc=report(args.seed,args.samples,tuple(args.security_bits),args.security_cap)
    raw=json.dumps(doc,indent=2,sort_keys=True)+'\n'
    if args.out:
        with args.out.open('x',encoding='utf-8') as stream:
            stream.write(raw)
    else:
        print(raw,end='')


if __name__=='__main__':
    main()
