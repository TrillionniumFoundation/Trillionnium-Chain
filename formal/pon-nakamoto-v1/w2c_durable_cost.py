"""Same-proof/receiver CPU cost probe. Research-only, no native V3 or GPU."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import statistics
import tempfile
import time

from contract_wire import H
from w2c_durable_paid_claims import DurableStatelessReceiver, provision
from w2c_receiver_admission import solve
from w2c_stateless_receiver import StatelessReceiverAdmission
import work_oracle as W

RECEIVER = bytes([11]) * 32
SECRET = bytes([12]) * 32
EPOCH = bytes([13]) * 32
CALLER = bytes([14]) * 32


def measured(work):
    wall, cpu = time.perf_counter_ns(), time.process_time_ns()
    result = work()
    return result, {'wall_ns': time.perf_counter_ns() - wall,
                    'process_cpu_ns': time.process_time_ns() - cpu}


def run(samples, bits, cap):
    zeros = [0] * W.CELLS
    header = H('durable-matched-work-header') * 9 + bytes(30)
    assert len(header) == 318
    challenge = H('challenge', header)
    proof = b'PNW1' + W.field_bytes(zeros) * 3 + H('durable-matched-false-trace', challenge)
    task = W.task_id(zeros, zeros)
    proposal = H('w2c-proposal', b'w2c-research-security-v0', header, proof)
    rows = []
    with tempfile.TemporaryDirectory() as folder:
        file = str(Path(folder) / 'paid.db')
        provision(file, RECEIVER, EPOCH, capacity=samples)
        counter = 0

        def unique(n):
            nonlocal counter
            counter += 1
            return counter.to_bytes(8,'little')+bytes(n-8)

        paid = DurableStatelessReceiver(RECEIVER, SECRET, EPOCH,
                                       db_path=file, capacity=samples, entropy=unique)
        plain = StatelessReceiverAdmission(RECEIVER, SECRET, EPOCH, capacity=samples)
        for index in range(samples):
            now = 100 + 3 * index
            grant, offer_cost = measured(lambda: paid.offer(proposal, CALLER, bits, now))
            (nonce, ticket_cost), _ = measured(lambda: solve(grant, cap))
            if nonce is None:
                rows.append({'index':index,'offer':offer_cost,'ticket':ticket_cost,
                             'status':'CAPPED','full_w1':None})
                continue
            naive, naive_cost = measured(lambda: plain.consume(grant, proposal, CALLER, nonce, now + 1))
            durable, durable_cost = measured(lambda: paid.consume(grant, proposal, CALLER, nonce, now + 1))
            assert naive == durable == 'READY_RESOURCE_ONLY'

            def rejected():
                try:
                    W.verify(challenge, task, bytes([255])*32, proof)
                except ValueError as err:
                    return str(err)
                raise AssertionError('invalid W1 proof verified')

            error, w1_cost = measured(rejected)
            assert error == 'TRANSCRIPT'
            replay, replay_cost = measured(lambda: DurableStatelessReceiver(
                RECEIVER, SECRET, EPOCH, db_path=file, capacity=samples
            ).consume(grant, proposal, CALLER, nonce, now + 2))
            assert replay == 'REPLAY'
            rows.append({'index':index,'offer':offer_cost,'ticket':ticket_cost,
                         'naive_consume':naive_cost,'durable_consume':durable_cost,
                         'w1_full_false_reject':w1_cost,'replay_after_restart':replay_cost,
                         'hash_attempts':ticket_cost['attempts'],'status':error,
                         'credit':False})
    complete = [row for row in rows if row['status']=='TRANSCRIPT']

    def summary(field, dimension):
        items = [r[field][dimension] for r in complete]
        if not items:
            return None
        return {'n':len(items),'median':statistics.median(items),
                'min':min(items),'max':max(items),'sum':sum(items)}

    return {
        'schema':'trnm-w2c-durable-same-receiver-python-cost-v1',
        'source_scope':'exact single synthetic header/task/false PNW1 proof; local Python CPU and wall only',
        'bits':bits,'samples':samples,'attempt_cap':cap,
        'challenge':challenge.hex(),'task':task.hex(),
        'proof_sha256':hashlib.sha256(proof).hexdigest(),
        'platform':platform.platform(), 'gpu_cpu_ratio':None,
        'native_v3_verified':False,'original_W1_relation_changed':False,
        'independent_accepted':False,'production_activation':False,
        'rows':rows, 'summary':{
            field:{dim:summary(field,dim) for dim in ('wall_ns','process_cpu_ns')}
            for field in ('naive_consume','durable_consume','w1_full_false_reject','replay_after_restart')
        }
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--samples',type=int,default=8)
    parser.add_argument('--bits',type=int,default=8)
    parser.add_argument('--cap',type=int,default=16384)
    parser.add_argument('--out')
    opt=parser.parse_args()
    if not 1<=opt.samples<=64 or not 8<=opt.bits<=24 or not 1<=opt.cap<=1<<20:
        raise SystemExit('BOUNDED_RESEARCH_OPTIONS')
    data=run(opt.samples,opt.bits,opt.cap)
    raw=json.dumps(data,indent=2,sort_keys=True)+'\n'
    if opt.out:
        with open(opt.out,'x',encoding='utf-8') as output: output.write(raw)
    else:
        print(raw,end='')

if __name__=='__main__': main()
