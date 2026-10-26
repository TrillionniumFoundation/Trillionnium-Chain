"""Bounded Python-only W1/false-ticket/W2-C CPU comparison, research only.

A synthetic fixed task/target/challenge stream; no real Header, CPU cgroup, GPU,
WAN service, public V3 Cookie or consensus authority. The complete legal W1
producer denominator includes ALL challenge misses before each winner.
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
import w2c_stateless_receiver_admission as S

SCHEMA = 'trnm-w2c-stateless-same-context-cost-v1'
EXPECTED_W1_ORACLE_BLOB = '9cbfccd2d50af48fc43522b967ffdfb1f45ec098'
TARGET = bytes.fromhex('7f' + 'ff' * 31)


def measured(f):
    start = time.process_time_ns()
    value = f()
    return value, time.process_time_ns() - start


def case(seed, sample, bits, max_w1_attempts, max_ticket_attempts):
    a = [0] * W.CELLS
    b = a.copy()
    task = W.task_id(a, b)
    w1_attempts = []
    winner = None
    for i in range(max_w1_attempts):
        challenge = H('w2c-cost-research-challenge-v1', struct.pack('<QQQ', seed, sample, i))
        proof, cpu_ns = measured(lambda: W.prove(challenge, a, b))
        real_ticket = H('ticket', challenge, proof[-32:])
        hit = real_ticket <= TARGET
        w1_attempts.append({'nonce':i, 'challenge':challenge.hex(),
                            'trace':proof[-32:].hex(), 'ticket':real_ticket.hex(),
                            'producer_cpu_ns':cpu_ns, 'target_hit':hit})
        if hit:
            winner = (challenge, proof)
            break
    if winner is None:
        return {'schema':SCHEMA,'status':'HONEST_W1_EXHAUSTED',
                'sample':sample,'bits':bits,'work_attempts':w1_attempts,
                'verified_work':False,'chainwork':0}

    challenge, legal_proof = winner
    _, legal_receiver_cpu_ns = measured(lambda: W.verify(challenge, task, TARGET, legal_proof))
    attacker_start = time.process_time_ns()
    prefix = b'PNW1' + W.field_bytes(a) * 3
    false_attempts = []
    fake = None
    for nonce in range(max_ticket_attempts):
        trace = H('w2c-cost-false-trace-v1', challenge, struct.pack('<Q', nonce))
        ticket = H('ticket', challenge, trace)
        hit = ticket <= TARGET
        false_attempts.append({'nonce':nonce, 'trace':trace.hex(),
                               'ticket':ticket.hex(),'target_hit':hit})
        if hit:
            fake = prefix + trace
            break
    false_total_cpu_ns = time.process_time_ns() - attacker_start
    if fake is None:
        return {'schema':SCHEMA,'status':'FALSE_TICKET_EXHAUSTED',
                'sample':sample,'bits':bits,'work_attempts':w1_attempts,
                'false_attempts':false_attempts,'false_cpu_ns':false_total_cpu_ns,
                'verified_work':False,'chainwork':0}
    W.precheck(challenge, task, TARGET, fake)
    rejected_start = time.process_time_ns()
    try:
        W.verify(challenge, task, TARGET, fake)
    except ValueError as error:
        outcome = str(error)
    else:
        raise AssertionError('FORGED_W1_ACCEPTED')
    receiver_cpu_ns = time.process_time_ns() - rejected_start
    if outcome != 'TRANSCRIPT':
        raise AssertionError('WRONG_W1_REJECTION:'+outcome)

    # The independent W2-C policy stays receiver-pinned; signing a grant
    # does not grant W1 work or make the false transcript valid.
    proposal = H('w2c-research-proposal', challenge, fake)
    issuer = S.StatelessReceiver(H('receiver',struct.pack('<Q',sample)),
                                 H('local-secret-research',struct.pack('<Q',seed)),
                                 H('ephemeral-epoch-research',struct.pack('<Q',sample)),
                                 bits=bits,capacity=16,ttl_ms=2000,
                                 entropy=lambda n: H('token-research',struct.pack('<QQ',seed,sample)))
    grant, issuer_cpu_ns = measured(lambda: issuer.offer(proposal, bits, 100))
    nonce, ticket_cost = S.solve(grant, max_ticket_attempts)
    admission = None
    if nonce is not None:
        admission, admission_cpu_ns = measured(lambda: issuer.consume(grant,proposal,nonce,110))
        if admission != 'READY_RESOURCE_ONLY':
            raise AssertionError('PAID_ADMISSION:'+str(admission))
        if issuer.consume(grant,proposal,nonce,111) != 'REPLAY':
            raise AssertionError('REPLAY_BYPASS')
    else:
        admission_cpu_ns = None
    return {'schema':SCHEMA,'status':'COMPLETE_TICKET_PAID' if nonce is not None else 'W2C_TICKET_EXHAUSTED', 'seed':seed,
            'sample':sample,'bits':bits,'target':TARGET.hex(),'task':task.hex(),
            'challenge':challenge.hex(),
            'legal_proof_sha256':hashlib.sha256(legal_proof).hexdigest(),
            'false_proof_sha256':hashlib.sha256(fake).hexdigest(),
            'work_attempts':w1_attempts,'work_attempts_executed':len(w1_attempts),
            'legal_full_search_cpu_ns':sum(x['producer_cpu_ns'] for x in w1_attempts),
            'legal_verify_cpu_ns':legal_receiver_cpu_ns,
            'false_attempts':false_attempts,'false_total_cpu_ns':false_total_cpu_ns,
            'false_full_rejection_cpu_ns':receiver_cpu_ns,
            'false_relation_error':outcome,
            'false_verify_over_generation_cpu_ratio': receiver_cpu_ns / false_total_cpu_ns if false_total_cpu_ns else None,
            'w2c_receiver_bound_issuance_cpu_ns':issuer_cpu_ns,
            'w2c_ticket_cost':ticket_cost,'w2c_consume_cpu_ns':admission_cpu_ns,
            'w2c_admission':admission,
            'w2c_grants_chainwork':False,
            'false_work_accepted':False,'production_activation':False}


def run(seed=1, samples=4, bits=(8,12,16), w1_attempts=16, ticket_attempts=131072):
    if (type(seed) is not int or not 0<=seed<1<<64 or
        type(samples) is not int or not 1<=samples<=8 or
        type(w1_attempts) is not int or not 1<=w1_attempts<=64 or
        type(ticket_attempts) is not int or not 1<=ticket_attempts<=1<<20 or
        not bits or len(set(bits))!=len(bits) or any(type(k) is not int or not 8<=k<=20 for k in bits)):
        raise ValueError('BOUNDED_INPUT')
    oracle_bytes = Path(W.__file__).read_bytes()
    oracle_blob = hashlib.sha1(b'blob ' + str(len(oracle_bytes)).encode() + b'\0' + oracle_bytes).hexdigest()
    if oracle_blob != EXPECTED_W1_ORACLE_BLOB:
        raise ValueError('W1_ORACLE_SOURCE_CHANGED')
    rows = [case(seed,i,k,w1_attempts,ticket_attempts) for i in range(samples) for k in bits]
    return {'schema':SCHEMA,'source':'Python scalar W1 oracle + stateless receiver research',
            'w1_oracle_blob_sha1':oracle_blob,
            'cpu_scope':'single process CPU, includes Python interpreter; no real network or GPU',
            'hardware':platform.platform(),'seed':seed,'samples':samples,
            'bits':list(bits),'work_attempt_cap':w1_attempts,
            'ticket_attempt_cap':ticket_attempts,
            'native_rust_runtime':False,'real_v3_cookie':False,
            'gpu_cost':None,'independent_operator':False,
            'production_activation':False,'rows':rows}


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--seed',type=int,default=1)
    p.add_argument('--samples',type=int,default=4)
    p.add_argument('--bits',nargs='+',type=int,default=[8,12,16])
    p.add_argument('--w1-attempts',type=int,default=16)
    p.add_argument('--ticket-attempts',type=int,default=131072)
    p.add_argument('--out')
    args=p.parse_args()
    out=run(args.seed,args.samples,tuple(args.bits),args.w1_attempts,args.ticket_attempts)
    raw=json.dumps(out,indent=2,sort_keys=True)+'\n'
    if args.out:
        with open(args.out,'x',encoding='utf-8') as stream:
            stream.write(raw)
    else:
        print(raw,end='')

if __name__=='__main__':main()
