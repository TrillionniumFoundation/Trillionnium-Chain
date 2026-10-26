"""Read-only W1-vs-durable-ticket CPU comparisons on one frozen Python oracle.
No native Rust, no real cgroup/GPU/ASIC, no new consensus proof or Chainwork.
"""
import argparse
import hashlib
import json
from pathlib import Path
import statistics
import tempfile
import time
from contract_wire import H
import work_oracle as W
from w2c_durable_receiver import DurableReceiver,solve

MAX_ATTEMPTS=65536
SCHEMA='w2c-durable-ticket-w1-matched-python-cost-v1'


def cpu(call):
    start=time.process_time_ns()
    out=call()
    return out,time.process_time_ns()-start


def generate(seed, target):
    zeros=[0]*W.CELLS
    task=W.task_id(zeros,zeros)
    winner=None
    misses=[]
    start=time.process_time_ns()
    for idx in range(16):
        header=H('w2c-durable-cost-header',seed.to_bytes(8,'little'),idx.to_bytes(8,'little'))*9+bytes(30)
        assert len(header)==318
        challenge=H('challenge',header)
        proof=W.prove(challenge,zeros,zeros)
        ticket=H('ticket',challenge,proof[-32:])
        misses.append({'header_nonce':idx,'ticket':ticket.hex(),'hit':ticket<=target})
        if ticket<=target:
            winner=(header,challenge,proof)
            break
    legal_full_cpu_ns=time.process_time_ns()-start
    if winner is None:
        raise AssertionError('16 honest full tries exhausted: retain all misses')
    header,challenge,valid=winner
    _,valid_receiver_ns=cpu(lambda: W.verify(challenge,task,target,valid))
    invalid_prefix=b'PNW1'+W.field_bytes(zeros)*3
    start=time.process_time_ns()
    forgery_trials=[]
    fake=None
    for idx in range(MAX_ATTEMPTS):
        trace=H('w2c-durable-fake-trace',challenge,idx.to_bytes(8,'little'))
        ticket=H('ticket',challenge,trace)
        if ticket<=target:
            fake=invalid_prefix+trace
            forgery_trials.append({'nonce':idx,'hit':True,'ticket':ticket.hex()})
            break
        forgery_trials.append({'nonce':idx,'hit':False})
    forgery_cpu_ns=time.process_time_ns()-start
    if fake is None:
        raise AssertionError('forgery budget exhausted')
    W.precheck(challenge,task,target,fake)
    start=time.process_time_ns()
    try:
        W.verify(challenge,task,target,fake)
    except ValueError as e:
        if str(e)!='TRANSCRIPT':raise
        invalid_receiver_ns=time.process_time_ns()-start
    else:raise AssertionError('forged W1 was accepted')
    return dict(
        seed=seed,task=task.hex(),target=target.hex(),challenge=challenge.hex(),
        header_sha256=hashlib.sha256(header).hexdigest(),
        honest_proof_sha256=hashlib.sha256(valid).hexdigest(),
        invalid_proof_sha256=hashlib.sha256(fake).hexdigest(),
        honest_trials=misses,
        honest_generation_all_attempts_cpu_ns=legal_full_cpu_ns,
        honest_full_verify_cpu_ns=valid_receiver_ns,
        fake_trials=forgery_trials,
        fake_producer_all_attempts_cpu_ns=forgery_cpu_ns,
        fake_full_W1_rejection_cpu_ns=invalid_receiver_ns,
    ), (header,challenge,task,fake)


def receiver_cost(bits, header, task, fake):
    with tempfile.TemporaryDirectory() as d:
        # Fresh receiver/epoch, no existing paid rows, genuine SQLite FULL
        # transactions; no physical resource observation or installed V3.
        receiver=H('w2c-research-receiver',bits.to_bytes(1,'little'))
        caller=H('w2c-research-attested-caller')
        proposal=H('w2c-proposal',header,fake)
        start=time.process_time_ns()
        with DurableReceiver(Path(d)/'paid.sqlite',receiver,H('w2c-cost-test-secret')) as owner:
            initialized_cpu_ns=time.process_time_ns()-start
            grant,grant_cpu_ns=cpu(lambda:owner.offer(proposal,caller,bits))
            nonce,cost=solve(grant,MAX_ATTEMPTS)
            if nonce is None:
                return {'bits':bits,'grant_init_cpu_ns':initialized_cpu_ns,
                        'grant_cpu_ns':grant_cpu_ns,'search':cost,
                        'result':'CAPPED','admit_cpu_ns':None,
                        'full_W1_rejection_cpu_ns':None,
                        'ticket_chainwork':False}
            decision,consume_ns=cpu(lambda:owner.consume(grant,proposal,caller,nonce))
            if decision!='READY_RESOURCE_ONLY':raise AssertionError(decision)
            _,w1_cpu=cpu(lambda:refuse_w1(H('challenge',header),task,bytes.fromhex('7f'+'ff'*31),fake))
            repeated=owner.consume(grant,proposal,caller,nonce)
            assert repeated=='REPLAY'
            return {'bits':bits,'grant_init_cpu_ns':initialized_cpu_ns,
                    'grant_cpu_ns':grant_cpu_ns,'search':cost,
                    'result':decision,'admit_cpu_ns':consume_ns,
                    'full_W1_rejection_cpu_ns':w1_cpu,
                    'replay':'REPLAY','ticket_chainwork':False}


def refuse_w1(challenge,task,target,fake):
    try:W.verify(challenge,task,target,fake)
    except ValueError as error:
        if str(error)=='TRANSCRIPT':return 'TRANSCRIPT'
        raise
    raise AssertionError('forged work accepted')


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--samples',type=int,default=2)
    parser.add_argument('--bits',nargs='+',type=int,default=[8,12])
    parser.add_argument('--out')
    options=parser.parse_args()
    if not 1<=options.samples<=8 or not options.bits or any(not 8<=b<=16 for b in options.bits):
        raise SystemExit('finite study only: samples 1..8 bits 8..16')
    target=bytes.fromhex('7f'+'ff'*31)
    samples=[]
    for seed in range(1,options.samples+1):
        row,(header,challenge,task,fake)=generate(seed,target)
        row['receiver_cohorts']=[receiver_cost(b,header,task,fake) for b in options.bits]
        samples.append(row)
    doc={'schema':SCHEMA,'W1_relation_modified':False,'native_cgroup':False,
         'real_GPU':None,'real_WAN':False,'independent_operator':False,
         'public_v3_cookie_activated':False,'chainwork':0,'production_activation':False,
         'scope':'Python process CPU + real SQLite, fixed scalar W1 input, full attempts, no physical powercut',
         'samples':samples}
    raw=json.dumps(doc,sort_keys=True,indent=2)+'\n'
    if options.out:
        with open(options.out,'x',encoding='utf-8') as stream:stream.write(raw)
    else:print(raw,end='')

if __name__=='__main__':main()
