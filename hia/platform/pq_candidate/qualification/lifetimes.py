"""Actual Candidate ownership, live-type refusal, const borrowing and threads."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import argparse
import ctypes as C
import hashlib
import json
import sys
import threading
import time
import traceback

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))
from hia.platform.pq_candidate.qualification.api import Result, Scalar, View, buffer, load
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
fixtures = fixture_map(fixture_requests(), [json.loads(line) for line in args.fixtures.read_bytes().splitlines()])
started = time.monotonic()
report = {'status': 'FAIL', 'image_sha256': args.image_sha256, 'abi_calls': 0, 'abi_refusals': 0,
    'caller_live_pointer_and_const_contract_required': True,
    'arbitrary_foreign_pointer_gate_qualified': False, 'constant_time_qualified': False}
records, live, aliases = [], set(), []
guard = threading.Lock()
inflight = {65: 0, 87: 0}
peak = {65: 0, 87: 0}
algorithms = {}


def call(name, *arguments):
    primary = name in ('sign', 'verify')
    algorithm = algorithms[arguments[0]] if primary and arguments[0] in algorithms else None
    before = time.monotonic()
    if algorithm:
        with guard:
            inflight[algorithm] += 1
            peak[algorithm] = max(peak[algorithm], inflight[algorithm])
    result = api[name](*arguments)
    with guard:
        if algorithm:
            inflight[algorithm] -= 1
        report['abi_calls'] += 1
        row = {'sequence': report['abi_calls'], 'name': name, 'thread': threading.get_ident(),
               'started': before, 'seconds': time.monotonic() - before}
        if primary:
            row['algorithm'] = algorithm
        if isinstance(result, Result):
            row.update(status=result.status, has_value=bool(result.value))
        elif isinstance(result, Scalar):
            row.update(status=result.status, value=result.value)
        elif isinstance(result, View):
            raw = C.string_at(result.data, result.size) if result.data else b''
            row.update(has_data=bool(result.data), size=result.size, sha256=hashlib.sha256(raw).hexdigest())
        else:
            row['value'] = result
        records.append(row)
    return result


def own(result, kind):
    assert result.status == 0 and result.value
    with guard:
        assert result.value not in live
        live.add(result.value)
    assert call('kind', result.value) == kind
    return result.value


def drop(owner):
    assert owner in live and call('drop', owner) == 0
    with guard:
        live.remove(owner)


def view(name, owner):
    result = call(name, owner)
    assert result.data
    return C.string_at(result.data, result.size)


try:
    keys = {}
    for algorithm in PARAMETERS:
        expected_public = bytes.fromhex(fixtures[f'key-{algorithm}-2']['pk'])
        source_seed = buffer(SEEDS[2])
        seed = own(call('seed_copy', source_seed, 32), 1)
        # The input has been copied into its own explicit seed owner.
        C.memset(source_seed, 0xa5, 32)
        key = own(call('signing_from_owned_seed', algorithm, seed), 2)
        live.remove(seed)
        assert view('signing_public_key', key) == expected_public
        source_public = buffer(expected_public)
        verifier = own(call('verifier_from_pinned_raw', algorithm, source_public, len(expected_public)), 3)
        C.memset(source_public, 0x77, len(expected_public))
        assert view('verifier_public_key', verifier) == expected_public
        algorithms[key] = algorithms[verifier] = algorithm
        signature = bytes.fromhex(fixtures[f'sign-{algorithm}-1']['signature'])
        keys[algorithm] = (key, verifier, expected_public, signature)
        borrowed = call('signing_public_key', key)
        signed = own(call('sign', key, borrowed.data, borrowed.size), 101)
        encoded = view('signature_bytes', signed)
        observed = own(call('verify', verifier, borrowed.data, borrowed.size, buffer(encoded), len(encoded)), 102)
        assert view('signing_public_key', key) == view('verifier_public_key', verifier) == expected_public
        aliases.append({'algorithm': algorithm, 'signature': signed, 'observation': observed, 'encoded': encoded})
        alias_case = {'label': f'const-public-key-as-message-{algorithm}',
            'original': {'op': 'sign', 'parameter': algorithm, 'seed': SEEDS[2].hex(), 'message': expected_public.hex()},
            'native': {'code': 0, 'name': f'ML-DSA-{algorithm}', 'pk': expected_public.hex(), 'signature': encoded.hex()}}
        (OUT / f'alias-original-{algorithm}.json').write_text(json.dumps(alias_case, sort_keys=True, indent=2) + '\n')

        invalid = [
            ('seed_copy', (None, 32)), ('seed_copy', (buffer(bytes(33)), 31)),
            ('seed_copy', (buffer(bytes(33)), 33)),
            ('signing_from_owned_seed', (algorithm, None)),
            ('signing_from_owned_seed', (algorithm, verifier)),
            ('verifier_from_pinned_raw', (algorithm, None, len(expected_public))),
            ('sign', (verifier, None, 0)), ('verify', (key, None, 0, None, 0)),
            ('sign', (key, None, 1)), ('verify', (verifier, None, 1, None, 0)),
            ('verify', (verifier, None, 0, None, len(signature))),
            ('error_display', (key,)), ('error_display', (verifier,)),
        ]
        for name, arguments in invalid:
            result = call(name, *arguments)
            assert result.status == 104 and not result.value, (name, result.status)
            report['abi_refusals'] += 1
        for name, owner in (('signing_algorithm', verifier), ('verifier_algorithm', key),
                            ('signing_algorithm', None), ('verifier_algorithm', None)):
            result = call(name, owner)
            assert result.status == 104 and result.value == 0
            report['abi_refusals'] += 1
        error = own(call('verify', verifier, None, 0, None, 0), 255)
        for name in ('signing_public_key', 'verifier_public_key', 'signature_bytes',
                     'algorithm_name_bytes', 'algorithm_all_bytes'):
            result = call(name, error)
            assert not result.data and result.size == 0
        for owner in (key, verifier):
            for name in ('value_bytes', 'signature_bytes', 'algorithm_name_bytes', 'algorithm_all_bytes'):
                result = call(name, owner)
                assert not result.data and result.size == 0
            for name in ('value_code', 'value_expected', 'value_actual'):
                assert call(name, owner) == (1 << 64) - 1
        drop(error)

    for parameter in (0, 1, 64, 66, 86, 88, 255, 256, (1 << 64) - 1):
        for name in ('algorithm_name', 'algorithm_public_key_bytes', 'algorithm_signature_bytes', 'algorithm_nist_category'):
            result = call(name, parameter)
            assert result.status == 104 and not result.value, (name, parameter, result.status)
            report['abi_refusals'] += 1
    assert call('kind', None) == 0 and call('drop', None) == 0
    source_message = buffer(b'\0')
    barrier = threading.Barrier(8)

    def thread(index):
        kept = []
        barrier.wait(timeout=30)
        before = time.monotonic()
        for repeat in range(4):
            for algorithm in PARAMETERS:
                key, verifier, _, signature = keys[algorithm]
                signed = own(call('sign', key, source_message, 1), 101)
                assert view('signature_bytes', signed) == signature
                verified = own(call('verify', verifier, source_message, 1, buffer(signature), len(signature)), 102)
                kept.extend(((algorithm, 101, signed), (algorithm, 102, verified)))
        return {'index': index, 'thread': threading.get_ident(), 'started': before,
                'seconds': time.monotonic() - before, 'values': kept}

    with ThreadPoolExecutor(max_workers=8) as pool:
        threads = list(pool.map(thread, range(8)))
    assert len({row['thread'] for row in threads}) == 8
    assert all(peak[algorithm] >= 2 for algorithm in PARAMETERS)
    kept = [value for row in threads for value in row['values']]
    assert len(kept) == 128 and len({value[2] for value in kept}) == 128
    for key, verifier, _, _ in keys.values():
        drop(key)
        drop(verifier)
    C.memset(source_message, 0xc7, 1)
    for algorithm, kind, owner in kept:
        assert call('kind', owner) == kind
        if kind == 101:
            assert view('signature_bytes', owner) == keys[algorithm][3]
        else:
            assert all(call(name, owner) == 0 for name in ('value_code', 'value_expected', 'value_actual'))
        drop(owner)
    for alias in aliases:
        assert view('signature_bytes', alias['signature']) == alias['encoded']
        assert call('value_code', alias['observation']) == 0
        drop(alias['signature'])
        drop(alias['observation'])
    assert not live
    report.update(status='PASS', readonly_owner_shared_threads=8,
        per_algorithm_maximum_concurrent_calls=peak, independent_post_owner_values=132,
        owned_values_remaining=0,
        threads=[{key: value for key, value in row.items() if key != 'values'} for row in threads])
except BaseException:
    report['traceback'] = traceback.format_exc()
    raise
finally:
    report['seconds'] = time.monotonic() - started
    (OUT / 'calls.json').write_text(json.dumps(records, sort_keys=True, indent=2) + '\n')
    (OUT / 'report.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
print(json.dumps(report, sort_keys=True))
