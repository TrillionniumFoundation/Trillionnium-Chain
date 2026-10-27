"""Bounded same-statement local W2-C receiver scope versus false W1 CPU costs.

Synthetic host/node identifiers and Python process CPU only. Not real V3,
not GPU, not independent host, not production pricing. No W1 authority.
"""
import argparse
import hashlib
import json
from pathlib import Path
import time
import work_oracle as W
from contract_wire import H
import w2c_receiver_admission as C


def observe(bits, cap):
    header = H('w2c-receiver-cost-header') * 9 + bytes(30)
    assert len(header) == 318
    challenge = H('challenge', header)
    a = [0] * W.CELLS
    task = W.task_id(a, a)
    proof = b'PNW1' + W.field_bytes(a)*3 + H('w2c-receiver-forged', challenge)
    proposal = H('w2c-proposal', b'w2c-research-security-v0', header, proof)
    rows = []
    for idx in (0, 1):
        issuer = C.ReceiverAdmission(bytes([idx + 1])*32, bytes([idx + 3])*32,
                                     bytes([idx + 5])*32, capacity=2,
                                     entropy=lambda n, idx=idx:bytes([idx + 7])*n)
        grant = issuer.offer(proposal, bits, 100)
        nonce,search = C.solve(grant, cap)
        if nonce is None:
            rows.append({'receiver_index':idx,'search':search,'w1_cpu_ns':None,
                         'admission':'CAPPED','chainwork':0})
            continue
        # A valid ticket for another receiver is rejected before any W1 work.
        other = C.ReceiverAdmission(bytes([idx+10])*32,bytes([idx+3])*32,
                                    bytes([idx+5])*32)
        assert other.consume(grant,proposal,nonce,110) == 'CONTEXT'
        cpu_start = time.process_time_ns()
        accepted = issuer.consume(grant, proposal, nonce, 110)
        admission_cpu_ns = time.process_time_ns()-cpu_start
        assert accepted == 'READY_RESOURCE_ONLY'
        cpu_start = time.process_time_ns()
        try:
            W.verify(challenge,task,bytes([255])*32,proof)
        except ValueError as error:
            outcome = str(error)
        else:
            raise AssertionError('fake W1 became valid')
        verifier_cpu_ns = time.process_time_ns()-cpu_start
        assert outcome == 'TRANSCRIPT'
        assert issuer.consume(grant,proposal,nonce,111) == 'REPLAY'
        rows.append({'receiver_index':idx,'search':search,
                     'admission_cpu_ns':admission_cpu_ns,
                     'admission':'READY_RESOURCE_ONLY',
                     'false_work_outcome':outcome,
                     'w1_cpu_ns':verifier_cpu_ns,
                     'chainwork':0})
    return {'bits':bits,'same_proposal_sha256':hashlib.sha256(proposal).hexdigest(),
            'same_challenge_sha256':hashlib.sha256(challenge).hexdigest(),
            'rows':rows}


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--bits',nargs='+',type=int,default=[8,12])
    p.add_argument('--cap',type=int,default=65536)
    p.add_argument('--out')
    opts=p.parse_args()
    if len(opts.bits)!=len(set(opts.bits)) or any(not 8<=b<=24 for b in opts.bits):
        raise SystemExit('BIT_RANGE')
    if not 1<=opts.cap<=1<<20:
        raise SystemExit('CAP_RANGE')
    report={'schema':'trnm-w2c-receiver-local-cost-research-v1',
            'scope':'two synthetic receivers, independently priced ticket per receiver; Python process CPU only',
            'w1_rule_changed':False,'public_v3_activated':False,
            'gpu_cost':None,'independent_hosts':False,'chainwork':0,
            'production_activation':False,
            'results':[observe(b,opts.cap) for b in opts.bits]}
    raw=json.dumps(report,sort_keys=True,indent=2)+'\n'
    if opts.out:
        with open(opts.out,'x',encoding='utf-8') as output:
            output.write(raw)
    else:
        print(raw,end='')

if __name__=='__main__':
    main()
