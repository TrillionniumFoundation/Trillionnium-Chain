#!/usr/bin/env python3
"""Read-only cost-accounting envelope for W1 false-proof multi-receiver floods.

One (potentially copied) false proof is charged to the attacker ONCE, while
every *actually recorded* receiver replay is charged to its own receiver.
No self-reported hardware identity, cryptographic validity, independent-host
claim or theoretical hash rate is accepted as production security proof.
"""
from __future__ import annotations
import argparse
from fractions import Fraction
import hashlib
import json
import os
import stat
from pathlib import Path
import re
import struct
import sys

SCHEMA = 'pon-w1-flood-cost-input-v1'
OUT_SCHEMA = 'pon-w1-flood-cost-accounting-v1'
HEX = re.compile(r'[0-9a-f]{64}\Z')
GIT_SHA = re.compile(r'[0-9a-f]{40}\Z')
MAX_BYTES = 4 * 1024 * 1024
MAX_CASES = 512
MAX_RECEIVERS = 4096
MAX_NS = (1 << 64) - 1


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def number(value, label, allow_null=False):
    if value is None and allow_null:
        return None
    require(type(value) is int and 0 <= value <= MAX_NS, label)
    return value


def digest(value, label):
    require(type(value) is str and HEX.fullmatch(value) is not None, label)
    return value



def pon_hash(tag, *parts):
    """Fixed W1 SHA256 grammar; this verifies claimed ticket search, not W1."""
    if type(tag) is str:
        tag = tag.encode()
    h = hashlib.sha256(b'TRNM-PON1\0' + struct.pack('<H', len(tag)) + tag)
    for p in parts:
        require(type(p) is bytes and len(p) < (1 << 32), 'HASH_PART')
        h.update(struct.pack('<I', len(p)))
        h.update(p)
    return h.digest()


def decode_hex(value, length, label):
    require(type(value) is str and len(value) == 2 * length
            and re.fullmatch(r'[0-9a-f]+', value) is not None, label)
    return bytes.fromhex(value)


def statement(case):
    """Reconstruct precisely one from-zero PNW1 payload from claimed public data.

    The ticket is independently recomputed for every trial; none of this
    checks the true mathematical transcript or a Node's durable parent.
    """
    header = decode_hex(case.get('header_hex'), 318, 'HEADER')
    require(header[:6] == b'PNH1\x01\x00', 'HEADER_VERSION')
    target = header[118:150]  # source layout: 3 hashes, 2 u64, then target
    require(target != bytes(32), 'ZERO_TARGET')
    task = header[278:310]  # after miner/transactions/state/receipts
    a = decode_hex(case.get('a_hex'), 16384, 'MATRIX_A')
    b = decode_hex(case.get('b_hex'), 16384, 'MATRIX_B')
    q = 4_294_967_291
    for wire in (a, b):
        require(all(x[0] < q for x in struct.iter_unpack('<I', wire)), 'FIELD')
    require(pon_hash('task', a, b) == task, 'TASK')
    return header, target, task, a, b

def unique(pairs):
    out = {}
    for key, value in pairs:
        require(key not in out, 'DUPLICATE_KEY')
        out[key] = value
    return out


def read(path):
    # A file-borne cost report is untrusted input, not an authority.
    # Refuse symlinks, FIFOs/devices and concurrent replacement rather than
    # blocking in a pipe or confusing a mutable path with immutable evidence.
    require(bool(getattr(os, 'O_NOFOLLOW', 0)), 'NOFOLLOW_UNSUPPORTED')
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC
                 | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode)
                and before.st_size <= MAX_BYTES, 'INPUT_REGULAR_FILE_LIMIT')
        raw = stream.read(MAX_BYTES + 1)
        after = os.fstat(stream.fileno())
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                 before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                 after.st_ctime_ns), 'INPUT_MUTATED')
    require(len(raw) <= MAX_BYTES and len(raw) == before.st_size, 'INPUT_BYTE_LIMIT')
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: require(False, 'NONFINITE'),
                      parse_float=lambda _: require(False, 'FLOAT_NOT_ALLOWED'))


def ratio(numerator, denominator):
    if denominator in (None, 0) or numerator is None:
        return None
    q = Fraction(numerator, denominator)
    return {'numerator': q.numerator, 'denominator': q.denominator,
            'decimal_6': f'{float(q):.6f}'}


def analyze(data, *, oracle_check=False):
    # Optional *offline* full matrix replay by the separately coded scalar
    # Python oracle. This check is NEVER used by any native public listener.
    W = None
    if oracle_check:
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]
                               / 'formal/pon-nakamoto-v1'))
        import work_oracle as W
    require(type(data) is dict and data.get('schema') == SCHEMA, 'SCHEMA')
    source = data.get('source')
    require(type(source) is dict, 'SOURCE')
    head = source.get('head')
    tree = source.get('tree')
    require(type(head) is str and GIT_SHA.fullmatch(head), 'HEAD')
    require(type(tree) is str and GIT_SHA.fullmatch(tree), 'TREE')
    require(type(source.get('profile')) is str and source['profile'],
            'PROFILE')
    cases = data.get('cases')
    require(type(cases) is list and 1 <= len(cases) <= MAX_CASES, 'CASE_LIMIT')
    all_proofs, all_call_ids = set(), set()
    rows = []
    full_attacker_cpu = 0
    all_attack_known = True
    all_receiver_cpu = 0
    all_receiver_known = True
    calls = 0
    for case in cases:
        require(type(case) is dict, 'CASE')
        proof = digest(case.get('proof_sha256'), 'PROOF_DIGEST')
        header, target, task, a, b = statement(case)
        challenge = pon_hash('challenge', header)
        require(proof not in all_proofs, 'DOUBLE_CHARGED_PROOF')
        all_proofs.add(proof)
        trials = case.get('trials')
        require(type(trials) is list and 1 <= len(trials) <= 1_048_576,
                'TRIALS')
        require(number(case.get('attempted_trials'), 'ATTEMPTS') == len(trials),
                'ATTEMPT_DENOMINATOR')
        complete_cpu = number(case.get('complete_attacker_cpu_ns'),
                              'ATTACK_CPU', allow_null=True)
        trial_cost = 0
        found = 0
        all_trials_known = True
        for i, trial in enumerate(trials):
            require(type(trial) is dict
                    and number(trial.get('nonce'), 'TRIAL_NONCE') == i,
                    'TRIAL_SEQUENCE')
            require(type(trial.get('ticket_hit')) is bool, 'TICKET_STATUS')
            trace = pon_hash('public-v3-from-zero-v1', challenge,
                             struct.pack('<Q', i))
            observed_hit = pon_hash('ticket', challenge, trace) <= target
            require(trial['ticket_hit'] == observed_hit, 'TICKET_VECTOR')
            measured = number(trial.get('cpu_ns'), 'TRIAL_CPU', allow_null=True)
            if measured is not None:
                trial_cost += measured
            else:
                all_trials_known = False
            found += int(trial['ticket_hit'])
        require(found == 1 and trials[-1]['ticket_hit'] is True,
                'WINNING_TRIAL_ONLY')
        final_trace = pon_hash('public-v3-from-zero-v1', challenge,
                               struct.pack('<Q', len(trials) - 1))
        forged_w1 = b'PNW1' + a + b + bytes(16384) + final_trace
        require(len(forged_w1) == 49188
                and hashlib.sha256(forged_w1).hexdigest() == proof,
                'EXACT_FALSE_PROOF')
        if W is not None:
            try:
                W.verify(challenge, task, target, forged_w1)
            except ValueError as error:
                require(str(error) == 'TRANSCRIPT', 'ORACLE_NOT_TRANSCRIPT')
            else:
                raise ValueError('ORACLE_ACCEPTED_FALSE_PROOF')
        require(complete_cpu is None or complete_cpu >= trial_cost,
                'NESTED_CPU_NOT_IN_TOTAL')
        if complete_cpu is None or complete_cpu == 0 or not all_trials_known:
            all_attack_known = False
        else:
            full_attacker_cpu += complete_cpu
        receives = case.get('receivers')
        require(type(receives) is list and 1 <= len(receives) <= MAX_RECEIVERS,
                'RECEIVER_LIMIT')
        receiver_cpu = 0
        receiver_known = True
        for record in receives:
            require(type(record) is dict, 'RECEIVER')
            call = digest(record.get('call_sha256'), 'CALL_DIGEST')
            require(call not in all_call_ids, 'DUPLICATE_CALL')
            all_call_ids.add(call)
            digest(record.get('node_claim_sha256'), 'NODE_CLAIM')
            outcome = record.get('outcome')
            require(outcome in ('TRANSCRIPT', 'PRODUCT', 'TARGET',
                                'BUSY', 'CANCELLED', 'UNKNOWN'),
                    'RECEIVER_OUTCOME')
            # Rejected packet never grants work; Busy and cancellation do not
            # assert that the mathematical relation was false.
            require(record.get('chainwork_granted') is False,
                    'INVALID_ATTACK_CHAINWORK')
            cost = number(record.get('whole_receiver_cpu_ns'),
                          'WHOLE_RECEIVER_CPU', allow_null=True)
            if cost is None or (cost == 0 and outcome in ('TRANSCRIPT', 'PRODUCT')):
                # A completed full arithmetic replay cannot be advertised as
                # zero-cost merely because a sampling clock lacked resolution.
                # Keep that observation but withhold any cost completeness.
                receiver_known = False
                all_receiver_known = False
            else:
                receiver_cpu += cost
                all_receiver_cpu += cost
            calls += 1
        rows.append({
            'proof_sha256': proof,
            'challenge': challenge.hex(),
            'task': task.hex(),
            'target': target.hex(),
            'declared_calls': len(receives),
            'full_attacker_cpu_ns': complete_cpu,
            'receiver_cpu_ns': receiver_cpu if receiver_known else None,
            'observed_cpu_ns_ratio_conditional':
                ratio(receiver_cpu, complete_cpu) if receiver_known and all_trials_known else None,
            'observed_all_costs_known': complete_cpu is not None and complete_cpu > 0 and receiver_known and all_trials_known,
            'fully_invalid_work_authorized': False,
        })
    require(calls <= MAX_RECEIVERS, 'TOTAL_RECEIVER_CALL_LIMIT')
    attack = full_attacker_cpu if all_attack_known else None
    receiver = all_receiver_cpu if all_receiver_known else None
    completeness = all_attack_known and all_receiver_known
    return {
        'schema': OUT_SCHEMA,
        'source': {'head': head, 'tree': tree, 'profile': source['profile']},
        'source_attestation_checked': False,
        'sample_hardware_independence_checked': False,
        'attacker_gpu_asic_cost_measured': False,
        'payload_relation_independently_verified': False,
        'local_scalar_oracle_replayed_every_case': oracle_check,
        'local_oracle_is_external_cryptanalysis': False,
        'p0_to_p6_closed': False,
        'production_activation': False,
        'cases': len(cases),
        'calls': calls,
        'unique_proofs': len(all_proofs),
        'all_cpu_observed': completeness,
        'total_attacker_cpu_ns': attack,
        'total_receiver_cpu_ns': receiver,
        'observed_aggregate_amplification': ratio(receiver, attack),
        'scope_verdict': 'CPU_ONLY_OBSERVATION' if completeness else 'UNKNOWN',
        'public_fairness_or_security_verdict': 'UNKNOWN',
        'case_rows': rows,
        'limitations': (
            'Producer charged once per exact proof; receivers charged per complete call; '
            'CPU clocks must be independently qualified on physical hosts. '
            'GPU, networking, honest latency, censorship, live identity churn, '
            'host custody, full W1 relation and replay CPU remain unqualified.'),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--input', required=True)
    ap.add_argument('--out')
    ap.add_argument('--oracle-check', action='store_true',
                    help='offline Python full W1 replay; not native admission or P6 review')
    args = ap.parse_args()
    out = analyze(read(args.input), oracle_check=args.oracle_check)
    raw = json.dumps(out, sort_keys=True, indent=2, allow_nan=False) + '\n'
    if args.out:
        # Exclusive creation: prior actual failures or observations survive.
        with open(args.out, 'x', encoding='utf-8') as stream:
            stream.write(raw)
    else:
        print(raw, end='')


if __name__ == '__main__':
    main()
