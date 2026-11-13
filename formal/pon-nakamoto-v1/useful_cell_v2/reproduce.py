"""Bounded synthetic fixture replay of the existing Cell plus explicit v2 policy.

This is correctness evidence, not real demand, efficacy, PoW or performance.
The native code remains linked to the original Rust grouped operator. Independent
Python products reuse the existing grouped experiment's scalar reference.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from experiments.grouped_cell_operator_v0 import (
    input_commitment as old_input_commitment,
    model_commitment, native_hash, scalar_product,
    statement_commitment as old_statement_commitment,
)

PROFILE = 'pon-useful-cell-int257-postprocess-research-v2'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def h(value):
    return bytes([value] * 32).hex()


def uint(value, size):
    return value.to_bytes(size, 'big')


def sint(value, size):
    return value.to_bytes(size, 'big', signed=True)


def fixture(n, *, large_window):
    model = {
        'model_version': h(7),
        'base': [[(r * 13 + k) % 7 - 3 for k in range(257)] for r in range(3)],
        'router': [[8 if k == r else 0 for k in range(257)] for r in range(3)],
        'deltas': [[[(e * 11 + r * 3 + k) % 5 - 2 for k in range(257)] for r in range(3)] for e in range(3)],
    }
    requests = []
    for i in range(n):
        x = [(i * 3 + k) % 17 - 8 for k in range(257)]
        x[:3] = [-8] * 3
        x[i % 3] = 8
        x[-1] = 8
        requests.append({'id': h(i), 'scope': h(9), 'arrival_ns': 1,
                         'deadline_ns': 3_600_000_000_000 if large_window else 900, 'x': x})
    return {
        'schema': 'pon-useful-cell-task-v2', 'model': model,
        'context': dict(zip(('chain', 'parent', 'challenge', 'batch_id'), map(h, range(1, 5)))),
        'requests': requests,
        'state': {'cell_id': h(10), 'generation': 3, 'snapshot_root': h(11), 'model_commitment': model_commitment(model)},
        'bindings': dict(zip(('program_digest', 'extractor_digest', 'source_inputs_digest', 'consumer', 'allowed_use', 'candidate_artifact'), map(h, range(12, 18)))),
        'policy': {'shift': 2, 'clamp_abs': 64, 'activation': 'relu', 'stop_rule': {'kind': 'margin_at_least', 'threshold': 8}},
        'issued_at_ns': 10, 'valid_until_ns': 3_600_000_000_100 if large_window else 950,
    }


def post(raw, policy):
    divisor = 2 ** policy['shift']
    quotient = [(abs(x) // divisor) * (-1 if x < 0 else 1) for x in raw]
    remainder = [x - q * divisor for x, q in zip(raw, quotient)]
    clamped = [max(-policy['clamp_abs'], min(policy['clamp_abs'], q)) for q in quotient]
    activated = [max(0, x) for x in clamped] if policy['activation'] == 'relu' else clamped
    prediction = max(range(3), key=activated.__getitem__)
    margin = activated[prediction] - max(x for i, x in enumerate(activated) if i != prediction)
    stop = policy['stop_rule']['kind'] != 'disabled' and margin >= policy['stop_rule']['threshold']
    return dict(quotient=quotient, remainder=remainder, clamped=clamped, activated=activated,
                prediction=prediction, margin=margin, stop=stop)


def state_bytes(state):
    return bytes.fromhex(state['cell_id']) + uint(state['generation'], 8) + bytes.fromhex(state['snapshot_root'] + state['model_commitment'])


def independent_claim(task):
    """Reference encode all relation fields; no bytes from the native producer."""
    context, requests, state, p = task['context'], task['requests'], task['state'], task['policy']
    raw = b''.join(bytes.fromhex(context[key]) for key in ('chain', 'parent', 'challenge', 'batch_id')) + uint(len(requests), 2)
    for row in requests:
        raw += bytes.fromhex(row['id'] + row['scope']) + uint(row['arrival_ns'], 8) + uint(row['deadline_ns'], 8)
        raw += b''.join(sint(x, 4) for x in row['x'])
    input_id = native_hash('pon-useful-cell-input-v2', PROFILE.encode(), raw)
    raw = state_bytes(state)
    raw += b''.join(bytes.fromhex(task['bindings'][key]) for key in ('program_digest', 'extractor_digest', 'source_inputs_digest', 'consumer', 'allowed_use', 'candidate_artifact'))
    raw += uint(p['shift'], 1) + sint(p['clamp_abs'], 4) + uint(int(p['activation'] == 'relu'), 1)
    if p['stop_rule']['kind'] == 'disabled':
        raw += bytes(5)
    else:
        raw += bytes([1]) + uint(p['stop_rule']['threshold'], 4)
    raw += uint(task['issued_at_ns'], 8) + uint(task['valid_until_ns'], 8)
    contract_id = native_hash('pon-useful-cell-contract-v2', PROFILE.encode(), bytes.fromhex(input_id), raw)
    product = scalar_product(task['model'], requests)
    model_id = model_commitment(task['model'])
    old_input = old_input_commitment(model_id, {'context': context, 'requests': requests})
    old_statement = old_statement_commitment(model_id, old_input, context, product)
    rows = [post(row, p) for row in product['logits']]
    body = b'UCELLV2\0' + uint(len(requests), 2) + bytes.fromhex(contract_id) + state_bytes(state)
    body += bytes.fromhex(model_id + old_input + old_statement)
    for scores, route, logits, prediction in zip(product['router_outputs'], product['routes'], product['logits'], product['predictions']):
        body += b''.join(sint(x, 8) for x in scores) + uint(route, 1)
        body += b''.join(sint(x, 8) for x in logits) + uint(prediction, 1)
    for group in product['groups']:
        body += uint(len(group), 2) + b''.join(uint(i, 2) for i in group)
    body += uint(product['useful_dense_macs'], 8) + uint(product['padded_macs'], 8) + uint(product['nonempty_expert_groups'], 1)
    for row in rows:
        body += b''.join(sint(x, 8) for key in ('quotient', 'remainder') for x in row[key])
        body += b''.join(sint(x, 4) for key in ('clamped', 'activated') for x in row[key])
        body += uint(row['prediction'], 1) + uint(row['margin'], 4) + uint(row['stop'], 1)
    statement = native_hash('pon-useful-cell-statement-v2', PROFILE.encode(), body)
    return body + bytes.fromhex(statement), dict(contract_id=contract_id, input_commitment=input_id,
        statement_commitment=statement, rows=rows, routes=product['routes'], groups=product['groups'], raw_logits=product['logits'])


def run(runner, mode, task, claim, *args, error=None):
    proc = subprocess.run([str(runner), mode, str(task), str(claim), '20', *args],
                          capture_output=True, timeout=30, check=False)
    if error is not None:
        if proc.returncode == 0 or error.encode() not in proc.stderr:
            raise RuntimeError(('NEGATIVE_NOT_REJECTED', error, proc.returncode, proc.stderr))
        return {'expected_error': error, 'returncode': proc.returncode, 'stderr': proc.stderr.decode().strip()}
    if proc.returncode:
        raise RuntimeError(proc.stderr.decode())
    return json.loads(proc.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runner', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    kat, known = independent_claim(fixture(4, large_window=False))
    required = {
        'contract_id': 'b134d049980556f02edb275d79acd202417186ce98670a957031d75a24bf9d46',
        'input_commitment': '0bf927cecfa78f57a5fac805621b2888523cc1dd5083062e4268065c7e4ea887',
        'statement_commitment': '68b14249be9ab601ef757edd4a9562d2dfcfb4116bf653e93794a0fa34ce63a5',
    }
    if any(known[key] != value for key, value in required.items()) or len(kat) != 817:
        raise RuntimeError('KNOWN_ANSWER_MISMATCH')
    results = []
    for n in (1, 4, 16, 64):
        task = fixture(n, large_window=True)
        task_path = args.out / f'task-{n}.json'
        task_path.write_bytes(canonical(task))
        expected_bytes, oracle = independent_claim(task)
        for kernel in ('direct', 'grouped'):
            claim_path = args.out / f'claim-{n}-{kernel}.bin'
            produced = run(args.runner, 'produce', task_path, claim_path, kernel)
            checked = run(args.runner, 'verify', task_path, claim_path)
            if claim_path.read_bytes() != expected_bytes:
                raise RuntimeError(('BINARY_ORACLE_MISMATCH', n, kernel))
            for key, expected in oracle.items():
                if produced[key] != expected or checked[key] != expected:
                    raise RuntimeError(('ORACLE_MISMATCH', n, kernel, key))
            results.append({'batch': n, 'kernel': kernel, 'claim_bytes': len(expected_bytes),
                            'contract_id': oracle['contract_id'], 'statement_commitment': oracle['statement_commitment'],
                            'stop_count': sum(r['stop'] for r in oracle['rows']), 'groups': list(map(len, oracle['groups'])),
                            'full_python_native_binary_equality': True, 'full_native_verify': True})
    task_path = args.out / 'task-4.json'
    claim_path = args.out / 'claim-4-grouped.bin'
    bad = bytearray(claim_path.read_bytes())
    bad[-33] ^= 1
    bad[-32:] = bytes.fromhex(native_hash('pon-useful-cell-statement-v2', PROFILE.encode(), bytes(bad[:-32])))
    false_stop_path = args.out / 'rehashed-false-stop.bin'
    false_stop_path.write_bytes(bad)
    negative = [run(args.runner, 'verify', task_path, false_stop_path, error='POSTPROCESS_RELATION')]
    other = json.loads(task_path.read_bytes())
    other['bindings']['consumer'] = h(99)
    other_path = args.out / 'other-consumer.json'
    other_path.write_bytes(canonical(other))
    negative.append(run(args.runner, 'verify', other_path, claim_path, error='EXPECTED_CONTRACT'))
    repo = HERE.parents[2]
    source_paths = [p for p in sorted(HERE.rglob('*'))
                    if p.is_file() and p.suffix in ('.rs', '.toml', '.lock', '.py')]
    source_paths += [
        repo / 'trillionnium/crates/trnm-crypto-primitives/src/pon_routed_int257_grouped.rs',
        repo / 'trillionnium/crates/trnm-crypto-primitives/src/lib.rs',
        repo / 'trillionnium/crates/trnm-crypto-primitives/Cargo.toml',
        HERE.parent / 'experiments/grouped_cell_operator_v0.py',
    ]
    report = {'schema': 'pon-useful-cell-v2-replay-evidence-v1', 'result': 'PASS', 'profile': PROFILE,
              'fixture': 'synthetic-existing-3x257-cell-shapes-not-real-demand', 'succinct_proof': False,
              'performance_claim': False, 'known_answer': required, 'runs': results, 'negative_controls': negative,
              'sources': {str(p.relative_to(repo)): hashlib.sha256(p.read_bytes()).hexdigest() for p in source_paths},
              'runner_sha256': hashlib.sha256(args.runner.read_bytes()).hexdigest()}
    (args.out / 'result.json').write_bytes(canonical(report) + b'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
