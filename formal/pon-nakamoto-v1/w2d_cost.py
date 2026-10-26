"""W2-D bounded reference-only witness/verification/forgery CPU research.

No admissible target, production W1 profile change, native Rust, GPU or WAN.
"""
import argparse
import hashlib
import json
import platform
import struct
import time
from pathlib import Path
from contract_wire import H
import work_oracle as W
import w2d_transcript_freivalds as D

SOURCE_BLOB = '9cbfccd2d50af48fc43522b967ffdfb1f45ec098'
SCHEMA = 'trnm-w2d-full-tape-freivalds-cost-research-v1'


def cpu(call):
    begin = time.process_time_ns()
    try:
        result = call()
    except ValueError as e:
        return str(e), time.process_time_ns()-begin
    return result, time.process_time_ns()-begin


def run(seed=1,samples=2):
    if type(seed) is not int or not 0<=seed<1<<64 or type(samples) is not int or not 1<=samples<=8:
        raise ValueError('INPUT_CAP')
    original = Path(W.__file__).read_bytes()
    oracle_blob = hashlib.sha1(b'blob '+str(len(original)).encode()+b'\0'+original).hexdigest()
    if oracle_blob != SOURCE_BLOB:
        raise ValueError('W1_ORACLE_SOURCE_CHANGED')
    proto_bytes = Path(D.__file__).read_bytes()
    proto_blob = hashlib.sha1(b'blob '+str(len(proto_bytes)).encode()+b'\0'+proto_bytes).hexdigest()
    rows=[]
    for sample in range(samples):
        label = 'zero' if sample%2 == 0 else 'dense'
        a=[0]*W.CELLS if label=='zero' else [i%31 for i in range(W.CELLS)]
        b=[0]*W.CELLS if label=='zero' else [i%17 for i in range(W.CELLS)]
        challenge=H('w2d-cost-challenge-v1',struct.pack('<QQ',seed,sample))
        task=W.task_id(a,b)
        target=bytes([255])*32  # deliberately research-only: isolates arithmetic
        candidate, producer_cpu_ns=cpu(lambda:D.produce(challenge,a,b))
        parity, parity_cpu_ns=cpu(lambda:W.prove(challenge,a,b))
        if candidate.proof!=parity:
            raise AssertionError('W1_BYTES_DIVERGED')
        original_verdict, original_cpu_ns=cpu(lambda:W.verify(challenge,task,target,candidate.proof))
        new_verdict, new_cpu_ns=cpu(lambda:D.verify(challenge,task,target,candidate.proof,candidate.sidecar))
        if (not isinstance(original_verdict,tuple) or
            not isinstance(new_verdict,dict) or
            new_verdict.get('outcome')!='RESEARCH_PROBABILISTIC_RELATION_CHECKED'):
            raise AssertionError('HONEST_W1_W2D_RELATION_DIVERGED')
        if new_verdict['verified_work'] or new_verdict['chainwork']:
            raise AssertionError('AUTHORITY_ESCAPE')
        only_trace=candidate.proof[:-32]+H('w2d-claim-only-false-trace',challenge)
        claim_result, claim_cpu_ns=cpu(lambda:D.verify(challenge,task,target,only_trace,candidate.sidecar))
        wrong_tape=D.MAGIC+bytes(D.TAPE_BYTES)
        false_claim=hashlib.sha256(b'TRNM-PON-TRACE1\0'+challenge+wrong_tape[4:]).digest()
        false_proof=candidate.proof[:-32]+false_claim
        wrong_tape_result, wrong_tape_cpu_ns=cpu(lambda:D.verify(challenge,task,target,false_proof,wrong_tape))
        tampered=bytearray(candidate.sidecar)
        i=4+17*4
        word=struct.unpack_from('<I',tampered,i)[0]
        struct.pack_into('<I',tampered,i,(word+1)%W.Q)
        revised_trace=hashlib.sha256(b'TRNM-PON-TRACE1\0'+challenge+tampered[4:]).digest()
        revised_proof=candidate.proof[:-32]+revised_trace
        single_tile_result,single_tile_cpu_ns=cpu(lambda:D.verify(challenge,task,target,revised_proof,bytes(tampered)))
        if (claim_result,wrong_tape_result,single_tile_result)!=('TRACE_BIND','PREFIX','PREFIX'):
            raise AssertionError('FALSE_TRACES_NOT_REJECTED')
        rows.append({'sample':sample,'material':label,'challenge':challenge.hex(),
                     'target':target.hex(),'task':task.hex(),
                     'original_w1_sha256':hashlib.sha256(candidate.proof).hexdigest(),
                     'w2d_tape_sha256':hashlib.sha256(candidate.sidecar).hexdigest(),
                     'original_w1_producer_cpu_ns':parity_cpu_ns,
                     'w2d_producer_cpu_ns':producer_cpu_ns,
                     'original_w1_verify_cpu_ns':original_cpu_ns,
                     'w2d_valid_verify_cpu_ns':new_cpu_ns,
                     'w2d_malformed_trace_refusal_cpu_ns':claim_cpu_ns,
                     'w2d_self_consistent_false_tape_refusal_cpu_ns':wrong_tape_cpu_ns,
                     'w2d_one_changed_tile_refusal_cpu_ns':single_tile_cpu_ns,
                     'source_verified':True,'proven_byte_parity':True,
                     'verified_work':False,'chainwork':0,
                     'original_relation_output_correct':isinstance(original_verdict,tuple)})
    return {'schema':SCHEMA,'source_w1_oracle_blob':oracle_blob,
            'source_w2d_prototype_blob':proto_blob,
            'test_target':'all ff; mathematical research only, NOT consensus difficulty',
            'python_process_cpu':True,'platform':platform.platform(),
            'gpu_cost':None,'independent_review':False,'rust_native':False,
            'w2d_verified_work':False,'w2d_chainwork':0,
            'w2d_sidecar_bytes':D.SIDECAR_BYTES,'w1_proof_bytes':W.PROOF_BYTES,
            'production_activation':False,'rows':rows}


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--seed',type=int,default=1)
    p.add_argument('--samples',type=int,default=2)
    p.add_argument('--out')
    args=p.parse_args()
    result=run(args.seed,args.samples)
    encoded=json.dumps(result,sort_keys=True,indent=2)+'\n'
    if args.out:
        with open(args.out,'x',encoding='utf-8') as f:
            f.write(encoded)
    else:
        print(encoded,end='')

if __name__=='__main__':main()
