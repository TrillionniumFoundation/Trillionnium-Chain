"""W2-D RESEARCH NEGATIVE: late false tile passes ticket, rejects expensively.

The attacker buys one honest W1 witness, then mutates ONLY the final prefix
tile and recomputes the claim digest for the same challenge. It does not reuse
or forge a valid verified-work capability. One-time preparation and all trials
are accounted separately from the amortized marginal invalid packet cost.
No native, actual network, GPU, Chainwork or W2 production authorization.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
import time
from contract_wire import H
import work_oracle as W
import w2d_full_tile_freivalds as D

SCHEMA='w2d-late-tile-false-claim-research-v0'
TARGET=bytes([127])+bytes([255])*31


def campaign(seed: int, cap: int=128, target: bytes=TARGET) -> dict:
    if type(seed) is not int or not 0 <= seed < (1<<32):
        raise ValueError('SEED')
    if type(cap) is not int or not 1 <= cap <= 4096:
        raise ValueError('CAP')
    if type(target) is not bytes or len(target) != 32 or target == bytes(32):
        raise ValueError('TARGET')
    challenge=H('w2d-late-attack-fixed-challenge',struct.pack('<I',seed))
    a=[((i*11+seed)%97) for i in range(W.CELLS)]
    b=[((i*17+seed)%101) for i in range(W.CELLS)]
    task=W.task_id(a,b)
    prep_start=time.process_time_ns()
    original=W.prove(challenge,a,b)
    original_witness=D.witness(challenge,a,b)
    setup_ns=time.process_time_ns()-prep_start
    assert hashlib.sha256(b'TRNM-PON-TRACE1\0'+challenge+original_witness).digest()==original[-32:]
    offset=(D.TILES-1)*D.TILE_BYTES
    previous=int.from_bytes(original_witness[offset:offset+4],'little')
    trial_rows=[]
    for nonce in range(cap):
        start=time.process_time_ns()
        sidecar=bytearray(original_witness)
        sidecar[offset:offset+4]=struct.pack('<I',(previous+nonce+1)%W.Q)
        forged_trace=hashlib.sha256(b'TRNM-PON-TRACE1\0'+challenge+sidecar).digest()
        proof=original[:-32]+forged_trace
        ticket=H('ticket',challenge,forged_trace)
        eligible=ticket <= target
        elapsed=time.process_time_ns()-start
        trial_rows.append({'trial':nonce,'cpu_ns':elapsed,'ticket_hit':eligible,
                           'trace':forged_trace.hex(), 'ticket':ticket.hex()})
        if eligible:
            break
    total_search_ns=sum(row['cpu_ns'] for row in trial_rows)
    if not trial_rows[-1]['ticket_hit']:
        return dict(schema=SCHEMA,status='CAPPED',seed=seed,cap=cap,
                    challenge=challenge.hex(),task=task.hex(),target=target.hex(),
                    one_time_legal_setup_cpu_ns=setup_ns,trial_rows=trial_rows,
                    complete_negative_verifier_cpu_ns=None,verified_work=False,
                    chainwork=False,production_activation=False)
    # This precheck is genuine oracle work, not a claimed hash hit alone.
    W.precheck(challenge,task,target,proof)
    before=time.process_time_ns()
    try:
        D.verify(challenge,task,target,proof,bytes(sidecar))
    except ValueError as error:
        outcome=str(error)
    else:
        raise AssertionError('INVALID_W2D_WITNESS_ACCEPTED')
    receiver_ns=time.process_time_ns()-before
    if outcome != 'TILE_RELATION':
        raise AssertionError('WRONG_LATE_RELATION_ERROR:'+outcome)
    return dict(schema=SCHEMA,status='TICKET_HIT_REJECTED',seed=seed,cap=cap,
                challenge=challenge.hex(),task=task.hex(),target=target.hex(),
                one_time_legal_setup_cpu_ns=setup_ns,trial_rows=trial_rows,
                full_false_attempt_cpu_ns=total_search_ns,
                complete_negative_verifier_cpu_ns=receiver_ns,
                measured_receiver_over_marginal_attack_cpu=(receiver_ns/total_search_ns
                                                          if total_search_ns else None),
                final_tile_corrupted=D.TILES-1,
                outcome=outcome,verified_work=False,chainwork=False,
                production_activation=False)


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--seeds',type=int,nargs='+',default=[1,2,3,4])
    p.add_argument('--cap',type=int,default=128)
    p.add_argument('--out')
    opts=p.parse_args()
    if not 1 <= len(opts.seeds) <= 16 or len(opts.seeds)!=len(set(opts.seeds)):
        raise SystemExit('SEEDS')
    rows=[campaign(seed,opts.cap) for seed in opts.seeds]
    report={'schema':'w2d-late-attack-local-cpu-report-v0',
            'scope':'one process, prepared genuine witness amortized; all ticket misses counted',
            'native_rust_executed':False,'gpu_rate_measured':False,
            'independent_attackers':False,'protocol_change':False,
            'production_activation':False,'rows':rows}
    raw=json.dumps(report,indent=2,sort_keys=True)+'\n'
    if opts.out:
        with open(opts.out,'x',encoding='utf-8') as destination:
            destination.write(raw)
    else:
        print(raw,end='')


if __name__=='__main__':main()
