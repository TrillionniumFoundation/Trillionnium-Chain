"""Bounded measured W2-C receiver journal overhead versus false W1 replay.

Unqualified Python-only same-statement research: no V3 signed Cookie, Rust,
GPU/ASIC, independent operator or Chainwork. All ticket-search attempts count.
"""
import argparse
import hashlib
import json
import os
import platform
import struct
import tempfile
import time
from pathlib import Path
from contract_wire import H
from w2c_receiver_admission import solve
from w2c_durable_epoch_owner import DurableReceiverOwner
import work_oracle as W

SCHEMA = 'w2c-durable-receiver-cost-v1'


def timed(action):
    cpu = time.process_time_ns()
    wall = time.perf_counter_ns()
    value = action()
    return value, {'cpu_ns': time.process_time_ns() - cpu,
                   'wall_ns': time.perf_counter_ns() - wall}


def false_w1(challenge, a, target):
    start = time.process_time_ns()
    prefix = b'PNW1' + W.field_bytes(a) * 3
    task = W.task_id(a, a)
    trials = []
    for nonce in range(128):
        trace = H('w2c-durable-from-zero', challenge, struct.pack('<Q', nonce))
        ticket = H('ticket', challenge, trace)
        hit = ticket <= target
        trials.append({'nonce': nonce, 'target_hit': hit})
        if hit:
            return prefix + trace, task, trials, time.process_time_ns() - start
    raise AssertionError('W1_FALSE_TICKET_EXHAUSTED')


def run(bits=(8, 12), samples=2, cap=65536):
    if not 1 <= samples <= 16 or not 1 <= cap <= (1 << 20) or not bits or len(set(bits)) != len(bits) or any(type(b) is not int or not 8 <= b <= 20 for b in bits):
        raise ValueError('BOUNDED_PROFILE')
    header = H('w2c-durable-fixed-header') * 9 + bytes(30)
    challenge = H('challenge', header)
    target = bytes([127]) + bytes([255]) * 31
    zeros = [0] * W.CELLS
    proposal_tag = b'w2c-research-security-v0'
    rows = []
    for bit in bits:
        for seed in range(samples):
            proof, task, w1_trials, forged_cpu = false_w1(challenge, zeros, target)
            proposal = H('w2c-proposal', proposal_tag, header, proof)
            with tempfile.TemporaryDirectory() as folder:
                path = str(Path(folder) / 'original-owner.db')
                receiver = H('cost-receiver-id', struct.pack('<Q', seed))
                secret = H('local-research-secret', struct.pack('<Q', seed))
                owner, startup = timed(lambda: DurableReceiverOwner(path, receiver, secret))
                caller = H('research-caller', struct.pack('<Q', seed))
                grant, issue = timed(lambda: owner.offer(proposal, caller, bit, 100))
                (nonce, search) = solve(grant, cap)
                if nonce is None:
                    rows.append({'bits': bit, 'seed': seed, 'status': 'CAPPED',
                                 'search': search, 'startup': startup,
                                 'issue': issue, 'w1_false_producer_cpu_ns': forged_cpu,
                                 'w1_ticket_trials': w1_trials,
                                 'w1_work_verified': None})
                    owner.close()
                    continue
                paid, consume = timed(lambda: owner.consume(grant, proposal, caller, nonce, 110))
                if paid != 'READY_RESOURCE_ONLY':
                    raise AssertionError(f'PAID_GRANT_NOT_READY:{paid}')
                replay, replay_cost = timed(lambda: owner.consume(grant, proposal, caller, nonce, 111))
                if replay != 'REPLAY':
                    raise AssertionError(f'REPLAY_FAILED:{replay}')
                def full_w1():
                    try:
                        W.verify(challenge, task, target, proof)
                    except ValueError as exc:
                        return str(exc)
                    return 'INVALID_PROOF_ACCEPTED'
                outcome, receiver = timed(full_w1)
                if outcome != 'TRANSCRIPT':
                    raise AssertionError(f'FORGED_WORK_{outcome}')
                old = grant
                owner.close()
                next_owner, restart = timed(lambda: DurableReceiverOwner(path, owner.receiver, secret))
                stale, stale_cost = timed(lambda: next_owner.consume(old, proposal, caller, nonce, 120))
                if stale != 'CONTEXT':
                    raise AssertionError(f'OLD_EPOCH_REPLAY:{stale}')
                next_owner.close()
                rows.append({'bits': bit, 'seed': seed, 'status': 'COMPLETE_RESEARCH_ONLY',
                             'w1_false_producer_cpu_ns': forged_cpu, 'w1_ticket_trials': w1_trials,
                             'search': search, 'startup': startup, 'issue': issue,
                             'consume': consume, 'replay': replay_cost,
                             'full_w1_reject': receiver, 'full_w1_outcome': outcome,
                             'restart': restart, 'stale': stale_cost,
                             'old_epoch_result': stale,
                             'w1_work_verified': False, 'chainwork_granted': False})
    return {'schema': SCHEMA, 'scope': 'synthetic research receiver and actual Python W1 math; same header/task/target/false proof for every arm',
            'os': platform.platform(), 'python': platform.python_version(),
            'header_sha256': hashlib.sha256(header).hexdigest(),
            'challenge': challenge.hex(), 'task': W.task_id(zeros, zeros).hex(),
            'w1_target': target.hex(), 'fake_proof_sha256': hashlib.sha256(proof).hexdigest(),
            'honest_cookie_service_measured': False, 'actual_native_w1_measured': False,
            'attacker_gpu_cost': None, 'actual_host_cgroup': False,
            'per_byte_network_cost': None, 'independent_operator': False,
            'public_network_ready': False, 'production_activation': False, 'rows': rows}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--bits', type=int, nargs='+', default=[8, 12])
    parser.add_argument('--samples', type=int, default=2)
    parser.add_argument('--cap', type=int, default=65536)
    parser.add_argument('--out')
    opts = parser.parse_args()
    doc = run(opts.bits, opts.samples, opts.cap)
    raw = json.dumps(doc, sort_keys=True, indent=2) + '\n'
    if opts.out:
        with open(opts.out, 'x', encoding='utf-8') as stream:
            stream.write(raw)
    else:
        print(raw, end='')


if __name__ == '__main__':
    main()
