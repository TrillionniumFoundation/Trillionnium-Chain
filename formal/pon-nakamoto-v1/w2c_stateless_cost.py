"""Fixed-input W2-C paid-only admission vs full false W1 CPU diagnostic.

Real process CPU under the local Python interpreter only. Does not measure
Rust, signed V3 Cookies, GPU, honest public traffic or native host admission.
"""
import argparse
import hashlib
import json
import platform
import statistics
import struct
import sys
import time
from contract_wire import H
from w2c_stateless_admission import Issuer, PaidReplayOwner, solve
import work_oracle as W


def cpu_ns():
    return time.process_time_ns()


def measure(seed, bits, samples, cap, unpaid):
    offer_owner = PaidReplayOwner(capacity=32)
    def salt(index):
        return H('w2c-cost-fixed-salt-v1', struct.pack('<Q',seed),
                 struct.pack('<I',bits), struct.pack('<I',index))
    issuer = Issuer(bytes([11])*32, bytes([12])*32,
                    bytes([13])*32, bytes([14])*32, offer_owner,
                    bits=bits, mint_capacity=32, mint_refill_per_second=32,
                    entropy=lambda count: salt(0)[:count])
    proposal=H('w2c-unpaid-proposal')
    started=cpu_ns()
    offered=[issuer.issue(proposal,100) for _ in range(unpaid)]
    unpaid_cpu=cpu_ns()-started
    offered_count=sum(o is not None for o in offered)
    assert len(offer_owner.paid)==0
    # One new test issuer for each independently measured paid proposal: no
    # production-era token bucket invented by the diagnostic receiver.
    rows=[]
    for index in range(samples):
        paid=PaidReplayOwner(capacity=32)
        identity=salt(index+1)
        server=Issuer(bytes([11])*32,bytes([12])*32,bytes([13])*32,
                      bytes([14])*32,paid,bits=bits,
                      entropy=lambda count,identity=identity:identity[:count])
        case=H('w2c-research-proposal',struct.pack('<Q',seed),
               struct.pack('<I',bits),struct.pack('<I',index))
        issue_start=cpu_ns()
        grant=server.issue(case,100)
        issue_cost=cpu_ns()-issue_start
        solve_start=cpu_ns()
        nonce,attempts=solve(grant,cap)
        solve_cost=cpu_ns()-solve_start
        payment=None
        if nonce is not None:
            pay_start=cpu_ns()
            accepted=server.pay(grant,case,nonce,110)
            pay_cost=cpu_ns()-pay_start
            assert accepted=='READY_RESOURCE_ONLY'
            assert server.pay(grant,case,nonce,110)=='REPLAY'
            payment=pay_cost
        rows.append(dict(index=index,bits=bits,attempts=attempts,
                         status='READY_RESOURCE_ONLY' if nonce is not None else 'CAPPED',
                         hash_search_cpu_ns=solve_cost,issue_cpu_ns=issue_cost,
                         first_paid_validation_cpu_ns=payment,
                         offer_identity_sha256=hashlib.sha256(grant.unsigned()+grant.mac).hexdigest(),
                         verified_work=False,chainwork=0))
    return dict(bits=bits,unpaid_requests=unpaid,unpaid_issued=offered_count,
                unpaid_issued_cpu_ns=unpaid_cpu,unpaid_replay_rows=0,
                paid_cases=rows)


def run(seed=7,bits=(8,12),samples=4,cap=65536,unpaid=1000):
    challenge=bytes(range(32))
    a=[0]*W.CELLS
    task=W.task_id(a,a)
    fake=b'PNW1'+W.field_bytes(a)*3+H('w2c-cost-false-W1-v1',challenge)
    target=bytes([255])*32
    true_proof=W.prove(challenge,a,a)
    W.verify(challenge,task,target,true_proof)
    receiver_costs=[]
    for _ in range(8):
        started=cpu_ns()
        try:
            W.verify(challenge,task,target,fake)
        except ValueError as e:
            assert str(e)=='TRANSCRIPT'
        else:
            raise AssertionError('false W1 became valid')
        receiver_costs.append(cpu_ns()-started)
    return dict(schema='trnm-w2c-stateless-paid-only-same-task-process-cpu-v1',
                exact_w1_profile=W.N,seed=seed,platform=platform.platform(),
                python_version=sys.version,
                immutable_challenge_sha256=hashlib.sha256(challenge).hexdigest(),
                immutable_task_sha256=hashlib.sha256(task).hexdigest(),
                forged_w1_sha256=hashlib.sha256(fake).hexdigest(),
                full_false_w1_cpu_ns=receiver_costs,
                full_false_w1_cpu_median_ns=statistics.median(receiver_costs),
                local_cpu_only=True,fixture_signed_cookie=False,
                gpu_cost=None,independent_host=False,chainwork=0,
                production_activation=False,
                results=[measure(seed,b,samples,cap,unpaid) for b in bits])


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--seed',type=int,default=7)
    p.add_argument('--bits',nargs='+',type=int,default=[8,12])
    p.add_argument('--samples',type=int,default=4)
    p.add_argument('--cap',type=int,default=65536)
    p.add_argument('--unpaid',type=int,default=1000)
    p.add_argument('--out')
    opt=p.parse_args()
    if not 0<=opt.seed<1<<64 or not 1<=opt.samples<=8 or not 1<=opt.cap<=1<<20 or not 1<=opt.unpaid<=10000 or not opt.bits or len(set(opt.bits))!=len(opt.bits) or any(not 8<=b<=24 for b in opt.bits):
        raise SystemExit('BOUNDS')
    data=run(opt.seed,opt.bits,opt.samples,opt.cap,opt.unpaid)
    output=json.dumps(data,indent=2,sort_keys=True)+'\n'
    if opt.out:
        with open(opt.out,'x',encoding='utf-8') as f:f.write(output)
    else:
        print(output,end='')

if __name__=='__main__':main()
