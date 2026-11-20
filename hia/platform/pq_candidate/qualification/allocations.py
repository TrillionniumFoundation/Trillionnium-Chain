"""Inject each real Candidate allocation failure and observe physical frees."""
from collections import Counter
from pathlib import Path
import argparse
import ctypes as C
import hashlib
import json
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))
from hia.platform.pq_candidate.qualification.api import Scalar, U, buffer, load
from hia.platform.pq_candidate.qualification.cases import PARAMETERS, SEEDS, fixture_map, fixture_requests


parser = argparse.ArgumentParser()
parser.add_argument('--image', type=Path, required=True)
parser.add_argument('--image-sha256', required=True)
parser.add_argument('--fixtures', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
assert not sys.flags.optimize
OUT = args.output.absolute()
OUT.mkdir()
assert hashlib.sha256(args.image.read_bytes()).hexdigest() == args.image_sha256
library, api = load(args.image)
stat = library.trnm_pq_test_stat
stat.argtypes, stat.restype = [U], U
fail = library.trnm_pq_test_fail_after
fail.argtypes, fail.restype = [U], None
probe = library.trnm_pq_test_probe
probe.argtypes, probe.restype = [U], None
fixtures = fixture_map(fixture_requests(), [json.loads(line) for line in args.fixtures.read_bytes().splitlines()])
started = time.monotonic()
report = {'status': 'FAIL', 'image_sha256': args.image_sha256, 'failure_controls': 0,
          'heap_allocation_wipe_scope_only': True, 'constant_time_qualified': False,
          'secret_register_or_stack_erasure_qualified': False, 'operations': []}
live, calls, rows = set(), Counter(), []


def snapshot():
    return [stat(index) for index in range(9)]


def invoke(name, *arguments):
    calls[name] += 1
    return api[name](*arguments)


def own(result, kind):
    assert result.status == 0 and result.value and result.value not in live
    live.add(result.value)
    assert invoke('kind', result.value) == kind
    return result.value


def drop(owner):
    assert owner in live and invoke('drop', owner) == 0
    live.remove(owner)


def save_rows():
    (OUT / 'controls.json').write_text(json.dumps(rows, sort_keys=True, indent=2) + '\n')


try:
    assert snapshot() == [0] * 9
    probe(0)
    assert snapshot() == [1, 1, 0, 0, 0, 0, 1, 32, 0]
    probe(1)
    baseline = snapshot()
    assert baseline == [2, 2, 0, 0, 0, 0, 1, 32, 32]
    report['observer_positive_controls'] = {'unwiped_detected_bytes': 32, 'clean_probe_bytes': 32}
    keys = {}
    for algorithm in PARAMETERS:
        public = bytes.fromhex(fixtures[f'key-{algorithm}-2']['pk'])
        seed = own(invoke('seed_copy', buffer(SEEDS[2]), 32), 1)
        key = own(invoke('signing_from_owned_seed', algorithm, seed), 2)
        live.remove(seed)
        verifier = own(invoke('verifier_from_pinned_raw', algorithm, buffer(public), len(public)), 3)
        error = own(invoke('verify', verifier, None, 0, None, 0), 255)
        signature = bytes.fromhex(fixtures[f'sign-{algorithm}-0']['signature'])
        keys[algorithm] = (key, verifier, error, public, signature)
    permanent = set(live)
    assert len(permanent) == 6 and stat(2) == len(permanent)
    actions = [('seed-copy', 'seed_copy', lambda _: (buffer(SEEDS[2]), 32), 1, None, 1),
               ('all', 'algorithm_all', lambda _: (), 104, None, 4)]
    for algorithm in PARAMETERS:
        key, verifier, error, public, signature = keys[algorithm]
        actions.extend([
            (f'{algorithm}-owned-seed', 'signing_from_owned_seed', lambda temp, a=algorithm: (a, temp), 2, 'seed', 4),
            (f'{algorithm}-verifier', 'verifier_from_pinned_raw', lambda _, a=algorithm, p=public: (a, buffer(p), len(p)), 3, None, 4),
            (f'{algorithm}-sign', 'sign', lambda _, k=key: (k, None, 0), 101, None, 4),
            (f'{algorithm}-verify', 'verify', lambda _, k=verifier, s=signature: (k, None, 0, buffer(s), len(s)), 102, None, 4),
            (f'{algorithm}-name', 'algorithm_name', lambda _, a=algorithm: (a,), 103, None, 4),
            (f'{algorithm}-error-value', 'error_display', lambda _, e=error: (e,), 105, None, 4),
            (f'{algorithm}-error-enum', 'candidate_error_display', lambda _: (3, (1 << 64) - 1, (1 << 63)), 105, None, 4),
            (f'{algorithm}-public-length', 'verifier_from_pinned_raw', lambda _, a=algorithm: (a, None, 0), 255, None, 1),
            (f'{algorithm}-sign-length', 'sign', lambda _, k=key: (k, buffer(bytes(65537)), 65537), 255, None, 1),
            (f'{algorithm}-verify-length', 'verify', lambda _, k=verifier: (k, buffer(bytes(65537)), 65537, None, 0), 255, None, 1),
            (f'{algorithm}-signature-length', 'verify', lambda _, k=verifier: (k, None, 0, None, 0), 255, None, 1),
            (f'{algorithm}-encoding', 'verify', lambda _, k=verifier, s=signature: (k, None, 0, buffer(bytes(len(s))), len(s)), 255, None, 4),
            (f'{algorithm}-challenge', 'verify', lambda _, k=verifier, s=signature: (k, buffer(b'x'), 1, buffer(s), len(s)), 255, None, 4),
        ])
        for name in ('algorithm_public_key_bytes', 'algorithm_signature_bytes', 'algorithm_nist_category'):
            actions.append((f'{algorithm}-{name}', name, lambda _, a=algorithm: (a,), None, None, 4))
    assert len(actions) == 34
    for label, name, arguments, kind, temporary, expected_count in actions:
        count = None
        for fail_at in [0, *range(1, expected_count + 1), 0]:
            assert live == permanent and stat(2) == len(permanent)
            fail(0)
            temp = own(invoke('seed_copy', buffer(SEEDS[2]), 32), 1) if temporary == 'seed' else None
            before = snapshot()
            fail(fail_at)
            result = invoke(name, *arguments(temp))
            after_operation = snapshot()
            fail(0)
            if temporary == 'seed':
                live.remove(temp)
            if fail_at == 0:
                assert result.status == 0
                if kind is not None:
                    owner = own(result, kind)
                    drop(owner)
                else:
                    assert isinstance(result, Scalar) and result.value > 0
                count = after_operation[0] - before[0]
                assert count == expected_count, (label, count, expected_count)
            else:
                assert result.status == 103 and not result.value, (label, fail_at, result.status)
                assert after_operation[0] - before[0] == fail_at
                assert after_operation[4] - before[4] == 1
                report['failure_controls'] += 1
            after = snapshot()
            assert live == permanent and after[2] == len(permanent)
            assert after[5:8] == baseline[5:8], (label, fail_at, after)
            rows.append({'operation': label, 'entry': name, 'fail_at': fail_at,
                'observed_allocations': count, 'result_status': result.status,
                'before': before, 'after_operation': after_operation, 'after_cleanup': after})
            save_rows()
        report['operations'].append({'name': label, 'entry': name, 'allocation_positions': count})
    # Invalid parameters still destroy an otherwise live owned seed, before any
    # allocation is attempted. A wrong-type live owner remains owned by caller.
    for algorithm in (0, 1, 64, 66, 86, 88, 255, 256, (1 << 64) - 1):
        seed = own(invoke('seed_copy', buffer(SEEDS[2]), 32), 1)
        before = snapshot()
        result = invoke('signing_from_owned_seed', algorithm, seed)
        live.remove(seed)
        after = snapshot()
        assert result.status == 104 and not result.value
        assert after[0] == before[0] and after[1] == before[1] + 1
        assert after[2] == len(permanent) and after[5:8] == baseline[5:8]
        rows.append({'operation': 'invalid-algorithm-consumes-seed', 'algorithm': algorithm,
                     'before': before, 'after_cleanup': after, 'result_status': result.status})
        save_rows()
    for owner in tuple(live):
        drop(owner)
    final = snapshot()
    assert final[2:4] == [0, 0] and final[5:8] == baseline[5:8]
    assert final[0] == final[1] + final[4]
    assert report['failure_controls'] == sum(row[5] for row in actions)
    report.update(status='PASS', controls=len(rows), final_stats=final,
                  allocator_observer_baseline=baseline, calls=dict(calls), live_values=len(live))
except BaseException:
    report['traceback'] = traceback.format_exc()
    report['failure_stats'] = snapshot()
    raise
finally:
    report['seconds'] = time.monotonic() - started
    (OUT / 'report.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
print(json.dumps(report, sort_keys=True))
