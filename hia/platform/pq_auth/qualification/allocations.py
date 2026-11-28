"""Fail every actual public-operation allocation and inspect every free."""
from collections import Counter
from pathlib import Path
import argparse
import ctypes as C
import hashlib
import json
import lzma
import struct
import sys
import time
import traceback
sys.path.insert(0, str(Path(__file__).resolve().parent))
from api import U, buffer, data, load

BASE = Path(__file__).parent
parser = argparse.ArgumentParser()
parser.add_argument('--image', type=Path, required=True)
parser.add_argument('--image-sha256', required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
OUT = args.output.absolute()
OUT.mkdir()
IMAGE = args.image.absolute()
image_sha = hashlib.sha256(IMAGE.read_bytes()).hexdigest()
assert image_sha == args.image_sha256
lib, api = load(IMAGE)
stat = lib.trnm_pq_test_stat
stat.argtypes, stat.restype = [U], U
fail = lib.trnm_pq_test_fail_after
fail.argtypes, fail.restype = [U], None
probe = lib.trnm_pq_test_probe
probe.argtypes, probe.restype = [U], None
started = time.monotonic()
report = {'status': 'FAIL', 'image_sha256': hashlib.sha256(IMAGE.read_bytes()).hexdigest(),
        'failure_controls': 0, 'operations': [], 'heap_allocation_wipe_scope_only': True,
    'secret_register_stack_or_constant_time_qualified': False}
live = set()
calls = Counter()
rows = []


def snapshot():
    return [stat(i) for i in range(9)]


def invoke(name, *args):
    result = api[name](*args)
    calls[name] += 1
    return result


def own(answer, kind=None):
    assert answer.status == 0 and answer.value
    assert answer.value not in live
    live.add(answer.value)
    if kind is not None:
        assert invoke('kind', answer.value) == kind
    return answer.value


def drop(value):
    assert value in live and invoke('drop', value) == 0
    live.remove(value)


def bind(v):
    end = v['retirement']
    return b''.join(bytes.fromhex(v[k]) for k in ('network', 'parameters', 'genesis')) + struct.pack(
        '<IBBH3Q', v['version'], v['scope'], int(end is not None), 0, v['activation'], end or 0, 0)


def envelope(v):
    ids = [bytes.fromhex(k) for k in v['signer_ids']]
    payload = bytes.fromhex(v['payload'])
    return struct.pack('<H', v['purpose']) + bytes(6) + struct.pack('<7Q', *(v[k] for k in
        ('generation', 'epoch', 'sequence', 'valid_from', 'valid_until')), len(ids), len(payload)) + b''.join(ids) + payload


def expectation(v):
    return bytes([v['purpose']]) + bytes(7) + b''.join(bytes.fromhex(v[k]) for k in
        ('network', 'owner_context', 'signer_key_id')) + struct.pack('<4Q', *(v[k] for k in
        ('owner_generation', 'operation_sequence', 'expires_at', 'now')))


def fixture_cases():
    return json.loads(lzma.decompress((BASE / 'cases.json.xz').read_bytes()))


def auth_fixtures():
    return {row['label']: row for row in fixture_cases() if row['family'] == 'auth' and row['suite'] == 'methods'}


def profile_fixture():
    rows = {row['label']: row for row in fixture_cases() if row['family'] == 'profile'}
    initial = rows['p65-n1:init']
    verification = rows['p65-n1:verify']
    return {'input': {'binding': initial['original']['binding'], 'expected': verification['original']['steps'][0]['expected']},
            'output': {**initial['native'], 'keys': initial['original']['keys'], 'pinned_keys': initial['native']['keys'],
                       'wire': verification['original']['steps'][0]['wire'], 'message': verification['native']['results'][0]['message']}}


try:
    assert snapshot() == [0] * 9
    probe(0)
    assert snapshot() == [1, 1, 0, 0, 0, 0, 1, 32, 0]
    probe(1)
    baseline = snapshot()
    assert baseline == [2, 2, 0, 0, 0, 0, 1, 32, 32]
    report['observer_positive_controls'] = {'unwiped_detected_bytes': 32, 'clean_probe_bytes': 32}
    owner_cases = auth_fixtures()
    public = owner_cases['derive-public']['native']
    spki, key_id = bytes.fromhex(public['spki']), bytes.fromhex(public['key_id'])
    pin = buffer(key_id)
    seed = own(invoke('seed_copy', buffer(bytes(32)), 32), 1)
    seed2 = own(invoke('seed_copy', buffer(bytes(32)), 32), 1)
    key = own(invoke('signing_from_owned_seed', seed2, pin), 2)
    live.remove(seed2)
    verifier = own(invoke('verifier_from_pinned_spki', buffer(spki), len(spki), pin), 3)
    empty_signature = bytes.fromhex(owner_cases['sign-exact-0']['native']['signature'])
    frame_case = owner_cases['sign-statement']
    statement = bytes.fromhex(frame_case['original']['statement'])
    frame = bytes.fromhex(frame_case['native']['frame'])
    payload = bytes.fromhex(frame_case['original']['payload'])
    expected = expectation(frame_case['original']['expected'])
    fixture = profile_fixture()
    binding = bind(fixture['input']['binding'])
    keys = [bytes.fromhex(k) for k in fixture['output']['keys']]
    encoded_keys = struct.pack('<Q', len(keys)) + b''.join(struct.pack('<Q', len(k)) + k for k in keys)
    profile = own(invoke('profile_from_pinned_keys', 2, buffer(binding), buffer(encoded_keys), len(encoded_keys)), 4)
    wire = bytes.fromhex(fixture['output']['wire'])
    candidate_expected = envelope(fixture['input']['expected'])
    profile_id = bytes.fromhex(fixture['output']['id'])
    bad_seed = own(invoke('seed_copy', buffer(bytes(32)), 32), 1)
    native_error = own(invoke('signing_from_owned_seed', bad_seed, buffer(bytes(32))), 255)
    live.remove(bad_seed)
    profile_error = own(invoke('profile_from_pinned_keys', 1, buffer(binding), buffer(encoded_keys), len(encoded_keys)), 255)
    permanent = set(live)
    assert len(permanent) == 6 and stat(2) == len(permanent)

    # Every Result-returning public entry participates. The second error-display
    # domain and semantic failures exercise their own cleanup and charging paths.
    actions = [
        ('seed-copy', 'seed_copy', lambda _: (buffer(bytes(32)), 32), 1, None),
        ('derive-public', 'public_spki_from_seed', lambda _: (seed,), 100, None),
        ('owned-seed', 'signing_from_owned_seed', lambda temp: (temp, pin), 2, 'seed'),
        ('verifier', 'verifier_from_pinned_spki', lambda _: (buffer(spki), len(spki), pin), 3, None),
        ('sign', 'sign_exact_message', lambda _: (key, None, 0), 101, None),
        ('verify', 'verify_exact_message', lambda _: (verifier, None, 0, buffer(empty_signature), len(empty_signature)), 102, None),
        ('sign-statement', 'sign_statement', lambda _: (key, buffer(statement), len(statement), buffer(expected), buffer(payload), len(payload)), 103, None),
        ('verify-frame', 'verify_frame', lambda _: (verifier, buffer(frame), len(frame), buffer(expected), buffer(payload), len(payload)), 104, None),
        ('verify-tpq1', 'verify_tpq1', lambda _: (buffer(frame), len(frame), buffer(expected), buffer(payload), len(payload), buffer(spki), len(spki)), 104, None),
        ('verify-raw', 'verify_ml_dsa_65', lambda _: (buffer(spki[22:]), 1952, None, 0, None, 0, buffer(empty_signature), 3309), 105, None),
        ('profile-create', 'profile_from_pinned_keys', lambda _: (2, buffer(binding), buffer(encoded_keys), len(encoded_keys)), 4, None),
        ('profile', 'profile_snapshot', lambda _: (profile,), 112, None),
        ('signer-ids', 'profile_signer_ids', lambda _: (profile,), 113, None),
        ('pinned-keys', 'profile_pinned_keys', lambda _: (profile,), 114, None),
        ('profile-verify', 'profile_verify', lambda temp: (profile, temp, buffer(wire), len(wire), buffer(candidate_expected), len(candidate_expected)), 107, 'budget'),
        ('budget-new', 'budget_new', lambda _: (), 5, None),
        ('budget-snapshot', 'budget_snapshot', lambda temp: (temp,), 108, 'budget'),
        ('budget-reserve', 'budget_reserve', lambda temp: (temp, 77, 2), 108, 'budget'),
        ('candidate-message', 'profile_candidate_message', lambda _: (profile, buffer(candidate_expected), len(candidate_expected)), 109, None),
        ('commitment', 'profile_commitment', lambda _: (profile, 1, buffer(b'abc'), 3), 110, None),
        ('active', 'profile_active_at', lambda _: (profile, 0), 111, None),
        ('claim', 'profile_require_claim', lambda _: (profile, buffer(profile_id)), 111, None),
        ('native-error-value', 'error_display', lambda _: (native_error,), 115, None),
        ('profile-error-value', 'error_display', lambda _: (profile_error,), 115, None),
        ('native-error-enum', 'native_error_display', lambda _: (3, 0), 115, None),
        ('profile-error-enum', 'profile_error_display', lambda _: (2, 3, 1952, 9), 115, None),
        ('owned-seed-pin-failure', 'signing_from_owned_seed', lambda temp: (temp, buffer(bytes(32))), 255, 'seed'),
        ('verifier-der-failure', 'verifier_from_pinned_spki', lambda _: (buffer(b'x'), 1, pin), 255, None),
        ('sign-length-failure', 'sign_exact_message', lambda _: (key, buffer(bytes(65537)), 65537), 255, None),
        ('verify-signature-failure', 'verify_exact_message', lambda _: (verifier, None, 0, buffer(bytes(3309)), 3309), 255, None),
        ('frame-digest-failure', 'verify_frame', lambda _: (verifier, buffer(frame), len(frame), buffer(expected), buffer(b'wrong'), 5), 255, None),
        ('candidate-wire-failure', 'profile_verify', lambda temp: (profile, temp, buffer(b'x'), 1, buffer(candidate_expected), len(candidate_expected)), 255, 'budget'),
    ]
    assert len(actions) == 32
    for label, name, arguments, kind, temporary in actions:
        count = None
        for fail_at in [0, *range(1, 5), 0]:
            if count is not None and fail_at > count:
                continue
            assert live == permanent and stat(2) == len(permanent)
            fail(0)
            temp = None
            if temporary == 'seed':
                temp = own(invoke('seed_copy', buffer(bytes(32)), 32), 1)
            elif temporary == 'budget':
                temp = own(invoke('budget_new'), 5)
            before = snapshot()
            fail(fail_at)
            result = invoke(name, *arguments(temp))
            after_operation = snapshot()
            fail(0)
            if temporary == 'seed':
                live.remove(temp)
            if not fail_at:
                actual = own(result, kind)
                if count is None:
                    count = after_operation[0] - before[0]
                    assert count == (1 if name == 'seed_copy' else 4), (label, count)
                drop(actual)
            else:
                assert result.status == 103 and not result.value, (label, fail_at, result.status)
                assert after_operation[0] - before[0] == fail_at
                assert after_operation[4] - before[4] == 1
                report['failure_controls'] += 1
            if temporary == 'budget':
                attempts = invoke('budget_attempts', temp)
                consumed = invoke('budget_total_bytes', temp)
                if fail_at in (1, 2, 3) or name == 'budget_snapshot':
                    assert (attempts, consumed) == (0, 0), (label, fail_at, attempts, consumed)
                elif name == 'budget_reserve':
                    assert (attempts, consumed) == (2, 77)
                elif name == 'profile_verify':
                    assert attempts == 1 and consumed == (len(wire) if kind == 107 else 1)
                drop(temp)
            after = snapshot()
            assert live == permanent and after[2] == len(permanent), (label, fail_at, after)
            assert after[5:8] == baseline[5:8], (label, fail_at, after)
            rows.append({'operation': label, 'entry': name, 'fail_at': fail_at, 'observed_allocations': count,
                'result_status': result.status, 'before': before, 'after_operation': after_operation, 'after_cleanup': after})
            (OUT / 'controls.json').write_text(json.dumps(rows, sort_keys=True, indent=2) + '\n')
        report['operations'].append({'name': label, 'entry': name, 'allocation_positions': count})
    assert report['failure_controls'] == 125
    # Invalid pin pointers still consume and wipe an otherwise valid owned seed.
    temp = own(invoke('seed_copy', buffer(bytes(32)), 32), 1)
    before = snapshot()
    result = invoke('signing_from_owned_seed', temp, None)
    live.remove(temp)
    assert result.status == 104 and not result.value and snapshot()[0] == before[0]
    assert stat(2) == len(permanent)
    rows.append({'operation': 'null-pin-consumes-seed', 'entry': 'signing_from_owned_seed',
                 'before': before, 'after_cleanup': snapshot(), 'result_status': result.status,
                 'has_value': bool(result.value)})
    (OUT / 'controls.json').write_text(json.dumps(rows, sort_keys=True, indent=2) + '\n')
    while live:
        drop(next(iter(live)))
    final = snapshot()
    assert final[2:4] == [0, 0] and final[5:8] == baseline[5:8]
    assert final[0] == final[1] + final[4]
    report.update(status='PASS', final_stats=final, allocator_observer_baseline=baseline,
        controls=len(rows), calls=dict(calls), live_values=len(live))
except BaseException:
    report['traceback'] = traceback.format_exc()
    report['failure_stats'] = snapshot()
    raise
finally:
    report['seconds'] = time.monotonic() - started
    (OUT / 'report.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    (OUT / 'fixture.py').write_bytes(Path(__file__).read_bytes())
print(json.dumps({key: value for key, value in report.items() if key not in ('operations', 'calls')}, sort_keys=True), flush=True)
