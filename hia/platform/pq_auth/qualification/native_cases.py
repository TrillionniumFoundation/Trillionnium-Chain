"""Exercise the actual public HIA DSO against complete retained original cases."""
from collections import Counter
from pathlib import Path
import argparse
import ctypes as C
import fcntl
import gzip
import hashlib
import json
import lzma
import os
import struct
import sys
import time
import traceback

BASE = Path(__file__).parent
sys.path.insert(0, str(BASE.parents[3]))
from hia.platform.pq_auth.qualification.contract import PARTITIONS, partition_cases
parser = argparse.ArgumentParser()
parser.add_argument('--image', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--image-sha256', required=True)
parser.add_argument('--partition', choices=tuple(row[0] for row in PARTITIONS), required=True)
args = parser.parse_args()
OUT = args.output.absolute()
OUT.mkdir()
started = time.monotonic()
image = args.image.read_bytes()
assert hashlib.sha256(image).hexdigest() == args.image_sha256
report = {'status': 'FAIL', 'image_sha256': hashlib.sha256(image).hexdigest(),
          'native_calls': 0, 'method_cases': 0, 'fresh_original_process_executed': False,
          'comparison_scope': 'native observations; formal qualification must run the unchanged original adapters'}
fd = os.memfd_create('pq-public-owned', os.MFD_ALLOW_SEALING)
os.write(fd, image)
fcntl.fcntl(fd, getattr(fcntl, 'F_ADD_SEALS', 1033), 15)
lib = C.CDLL('/proc/self/fd/' + str(fd))
os.close(fd)


class Result(C.Structure):
    _fields_ = [('status', C.c_uint64), ('value', C.c_void_p)]


class View(C.Structure):
    _fields_ = [('data', C.c_void_p), ('size', C.c_uint64)]


U, P = C.c_uint64, C.c_void_p
signatures = {
    'seed_copy': (Result, P, U), 'public_spki_from_seed': (Result, P),
    'signing_from_owned_seed': (Result, P, P), 'verifier_from_pinned_spki': (Result, P, U, P),
    'sign_exact_message': (Result, P, P, U), 'verify_exact_message': (Result, P, P, U, P, U),
    'sign_statement': (Result, P, P, U, P, P, U), 'verify_frame': (Result, P, P, U, P, P, U),
    'verify_tpq1': (Result, P, U, P, P, U, P, U), 'verify_ml_dsa_65': (Result, P, U, P, U, P, U, P, U),
    'profile_from_pinned_keys': (Result, U, P, P, U), 'profile_snapshot': (Result, P),
    'profile_signer_ids': (Result, P), 'profile_pinned_keys': (Result, P),
    'profile_verify': (Result, P, P, P, U, P, U), 'budget_new': (Result,),
    'budget_snapshot': (Result, P), 'budget_reserve': (Result, P, U, U),
    'profile_candidate_message': (Result, P, P, U), 'profile_commitment': (Result, P, U, P, U),
    'profile_active_at': (Result, P, U), 'profile_require_claim': (Result, P, P),
    'drop': (U, P), 'kind': (U, P), 'value_code': (U, P), 'value_detail_a': (U, P), 'value_detail_b': (U, P),
    'candidate_signer_count': (U, P), 'bound_kind': (U, P),
    'budget_attempts': (U, P), 'budget_total_bytes': (U, P), 'budget_exhausted': (U, P),
    'profile_signer_id_at': (View, P, U), 'profile_pinned_key_at': (View, P, U),
    'error_display': (Result, P), 'native_error_display': (Result, U, U),
    'profile_error_display': (Result, U, U, U, U),
}
for suffix in ('value_bytes', 'identity_spki', 'identity_key_id', 'signature_bytes', 'key_public_spki',
    'key_public_key_id', 'message_authenticated_message', 'message_signer_key_id', 'signed_frame_bytes',
    'frame_authenticated_statement', 'frame_statement', 'frame_signer_key_id', 'candidate_message',
    'candidate_crypto_profile_id', 'bound_profile_id', 'bound_work_digest', 'bound_binding', 'bound_configuration_bytes'):
    signatures[suffix] = (View, P)
functions = {}
for name, types in signatures.items():
    function = getattr(lib, 'trnm_pq_' + name)
    function.restype, function.argtypes = types[0], list(types[1:])
    functions[name] = function
assert len(functions) == 55
counts = Counter()
case_rows = []
live = set()
label = 'initial'
log = gzip.open(OUT / 'native-calls.jsonl.gz', 'wb', compresslevel=1)


def call(name, *arguments):
    answer = functions[name](*arguments)
    counts[name] += 1
    report['native_calls'] += 1
    row = {'case': label, 'function': name}
    if isinstance(answer, Result):
        row.update(status=answer.status, has_value=bool(answer.value))
    elif isinstance(answer, View):
        row.update(size=answer.size, value=(C.string_at(answer.data, answer.size).hex() if answer.data else None))
    else:
        row['value'] = answer
    log.write((json.dumps(row, sort_keys=True) + '\n').encode())
    return answer


def value(answer, kind=None):
    assert answer.status == 0 and answer.value, (label, answer.status)
    assert answer.value not in live
    live.add(answer.value)
    actual = call('kind', answer.value)
    if kind is not None:
        assert actual == kind, (label, kind, actual)
    return answer.value


def drop(handle):
    assert handle in live and call('drop', handle) == 0
    live.remove(handle)


def buf(data):
    return C.create_string_buffer(data, max(1, len(data)))


def view(name, *arguments):
    observed = call(name, *arguments)
    assert observed.data, (label, name)
    return C.string_at(observed.data, observed.size)


def error(handle, profile=False, compatibility=False):
    kind = call('kind', handle)
    if kind < 100:
        assert kind in (1, 2, 3, 4, 5)
        return None
    code = call('value_code', handle)
    if code == 0:
        return None
    assert kind == 255
    detail = call('value_detail_a', handle)
    if profile:
        row = {'code': code, 'detail': detail}
    elif code == (6 if compatibility else 1):
        row = {'code': code, 'frame': {'code': detail}}
    else:
        row = {'code': code}
    if not compatibility:
        text = value(call('error_display', handle), 115)
        assert view('value_bytes', text)
        drop(text)
    return row


def expectation(v):
    return bytes([v['purpose']]) + bytes(7) + b''.join(bytes.fromhex(v[k]) for k in
        ('network', 'owner_context', 'signer_key_id')) + struct.pack('<4Q', *(v[k] for k in
        ('owner_generation', 'operation_sequence', 'expires_at', 'now')))


def payload(v):
    if 'generated_payload_bytes' in v:
        size, width = v['generated_payload_bytes'], v['generated_chunk_bytes']
        assert 0 <= size <= 67108865 and 1 <= width <= 1048512
        chunk = bytes(i % 251 for i in range(width))
        return chunk * (size // width) + chunk[:size % width]
    return bytes.fromhex(v['payload'])


def auth_case(v):
    op = v['op']
    if op == 'verify':
        pk, message, context, signature = [bytes.fromhex(v[k]) for k in ('pk', 'message', 'context', 'signature')]
        result = value(call('verify_ml_dsa_65', buf(pk), len(pk), buf(message), len(message), buf(context), len(context), buf(signature), len(signature)))
        return error(result, compatibility=True) or {'code': 0}
    if op == 'native_error_display':
        handle = value(call('native_error_display', v['code'], v['detail']), 115)
        return {'code': 0, 'display': view('value_bytes', handle).decode()}
    if op.startswith('seed'):
        seed = value(call('seed_copy', buf(bytes.fromhex(v['seed'])), 32), 1)
        public = value(call('public_spki_from_seed', seed), 100)
        spki = view('identity_spki', public)
        key_id = view('identity_key_id', public)
        pin = bytes.fromhex(v['pin']) if 'pin' in v else key_id
        key = value(call('signing_from_owned_seed', seed, buf(pin)))
        live.remove(seed)  # Consumed by this API on success and failure.
        row = error(key)
        if row:
            return row
        assert call('kind', key) == 2
        assert view('key_public_spki', key) == spki and view('key_public_key_id', key) == key_id
        if op == 'seed_public':
            return {'code': 0, 'spki': spki.hex(), 'derived_spki': spki.hex(), 'key_id': key_id.hex()}
        if op == 'seed':
            message = bytes.fromhex(v['message'])
            signed = value(call('sign_exact_message', key, buf(message), len(message)))
            return error(signed) or {'code': 0, 'spki': spki.hex(), 'derived_spki': spki.hex(),
                'key_id': key_id.hex(), 'signature': view('signature_bytes', signed).hex()}
        statement, message_payload = bytes.fromhex(v['statement']), payload(v)
        signed = value(call('sign_statement', key, buf(statement), len(statement), buf(expectation(v['expected'])), buf(message_payload), len(message_payload)))
        return error(signed) or {'code': 0, 'spki': spki.hex(), 'key_id': key_id.hex(), 'frame': view('signed_frame_bytes', signed).hex()}
    spki = bytes.fromhex(v['spki'])
    if op == 'verify_tpq1':
        frame, message_payload = bytes.fromhex(v['frame']), payload(v)
        result = value(call('verify_tpq1', buf(frame), len(frame), buf(expectation(v['expected'])), buf(message_payload), len(message_payload), buf(spki), len(spki)))
        return error(result, compatibility=True) or {'code': 0,
            'statement': view('frame_authenticated_statement', result).hex(),
            'statement_alias': view('frame_statement', result).hex(), 'key_id': view('frame_signer_key_id', result).hex()}
    key = value(call('verifier_from_pinned_spki', buf(spki), len(spki), buf(bytes.fromhex(v['pin']))))
    row = error(key)
    if row:
        return row
    public_id = view('key_public_key_id', key).hex()
    public_spki = view('key_public_spki', key).hex()
    if op == 'native_public':
        return {'code': 0, 'key_id': public_id, 'spki': public_spki}
    if op == 'native_verify':
        message, signature = bytes.fromhex(v['message']), bytes.fromhex(v['signature'])
        result = value(call('verify_exact_message', key, buf(message), len(message), buf(signature), len(signature)))
        return error(result) or {'code': 0, 'message': view('message_authenticated_message', result).hex(),
            'key_id': view('message_signer_key_id', result).hex(), 'public_key_id': public_id, 'spki': public_spki}
    assert op == 'native_frame'
    frame, message_payload = bytes.fromhex(v['frame']), payload(v)
    result = value(call('verify_frame', key, buf(frame), len(frame), buf(expectation(v['expected'])), buf(message_payload), len(message_payload)))
    return error(result) or {'code': 0, 'statement': view('frame_authenticated_statement', result).hex(),
        'statement_alias': view('frame_statement', result).hex(), 'key_id': view('frame_signer_key_id', result).hex()}


def binding(v):
    end = v['retirement']
    return b''.join(bytes.fromhex(v[k]) for k in ('network', 'parameters', 'genesis')) + struct.pack(
        '<IBBH3Q', v['version'], v['scope'], int(end is not None), 0, v['activation'], end or 0, 0)


def envelope(v):
    ids = [bytes.fromhex(item) for item in v['signer_ids']]
    payload = bytes.fromhex(v['payload'])
    return struct.pack('<H', v['purpose']) + bytes(6) + struct.pack('<7Q', *(v[k] for k in
        ('generation', 'epoch', 'sequence', 'valid_from', 'valid_until')), len(ids), len(payload)) + b''.join(ids) + payload


def profile_owner(v):
    keys = [bytes.fromhex(key) for key in v['keys']]
    encoded = struct.pack('<Q', len(keys)) + b''.join(struct.pack('<Q', len(key)) + key for key in keys)
    return value(call('profile_from_pinned_keys', v['profile'], buf(binding(v['binding'])), buf(encoded), len(encoded)))


def profile_row(owner, arrays):
    snapshot = value(call('profile_snapshot', owner), 112)
    row = {'code': 0, 'profile': call('bound_kind', snapshot), 'id': view('bound_profile_id', snapshot).hex(),
        'work': view('bound_work_digest', snapshot).hex(), 'binding': view('bound_binding', snapshot).hex(),
        'config': view('bound_configuration_bytes', snapshot).hex()}
    if arrays:
        for suffix, item, field in [('profile_signer_ids', 'profile_signer_id_at', 'signer_ids'),
                                    ('profile_pinned_keys', 'profile_pinned_key_at', 'keys')]:
            values = value(call(suffix, owner))
            count = call('value_detail_a', values)
            row[field] = [view(item, values, index).hex() for index in range(count)]
            refused = call(item, values, count)
            assert not refused.data and refused.size == 0
            drop(values)
    drop(snapshot)
    return row


def profile_case(v):
    op = v['op']
    if op == 'display':
        result = value(call('profile_error_display', v['category'], v['detail'], v['expected'], v['actual']), 115)
        return {'code': 0, 'display': view('value_bytes', result).decode()}
    if op == 'sequence':
        owners = [profile_owner(descriptor) for descriptor in v['owners']]
        assert all(call('kind', owner) == 4 for owner in owners)
        budget = value(call('budget_new'), 5)
        results = []
        for step in v['steps']:
            if step['op'] == 'reserve':
                result = value(call('budget_reserve', budget, step['bytes'], step['attempts']))
                row = error(result, profile=True) or {'code': 0}
            elif step['op'] == 'budget':
                result = value(call('budget_snapshot', budget), 108)
                row = {'code': 0}
                assert call('value_detail_a', result) == call('budget_attempts', budget)
                assert call('value_detail_b', result) == call('budget_total_bytes', budget)
                assert view('value_bytes', result) == bytes([call('budget_exhausted', budget)])
            else:
                assert step['op'] == 'verify'
                wire, expected = bytes.fromhex(step['wire']), envelope(step['expected'])
                result = value(call('profile_verify', owners[step['owner']], budget, buf(wire), len(wire), buf(expected), len(expected)))
                row = error(result, profile=True) or {'code': 0, 'message': view('candidate_message', result).hex(),
                    'id': view('candidate_crypto_profile_id', result).hex(), 'signers': call('candidate_signer_count', result)}
            row.update(attempts=call('budget_attempts', budget), bytes=call('budget_total_bytes', budget))
            results.append(row)
            drop(result)
        return {'code': 0, 'results': results}
    owner = profile_owner(v)
    row = error(owner, profile=True)
    if row:
        return row
    if op in ('init', 'profile'):
        return profile_row(owner, op == 'init')
    if op == 'message':
        data = envelope(v['expected'])
        result = value(call('profile_candidate_message', owner, buf(data), len(data)))
        return error(result, profile=True) or {'code': 0, 'message': view('value_bytes', result).hex()}
    if op == 'commitment':
        data = bytes.fromhex(v['bytes'])
        result = value(call('profile_commitment', owner, v['purpose'], buf(data), len(data)))
        return error(result, profile=True) or {'code': 0, 'digest': view('value_bytes', result).hex()}
    if op == 'active':
        result = value(call('profile_active_at', owner, v['height']), 111)
        return {'code': 0, 'active': bool(call('value_detail_a', result))}
    assert op == 'claim'
    result = value(call('profile_require_claim', owner, buf(bytes.fromhex(v['claim']))))
    return error(result, profile=True) or {'code': 0}


try:
    packed = (BASE / 'cases.json.xz').read_bytes()
    supplied = json.loads(lzma.decompress(packed))
    assert len(supplied) == 1609
    (OUT / 'supplied-cases.json.xz').write_bytes(packed)
    selected = partition_cases(supplied, args.partition)
    corpora = [([case], profile_case if case['family'] == 'profile' else auth_case) for case in selected]
    for cases, evaluate in corpora:
        for case in cases:
            label = case['label']
            assert not live
            actual = evaluate(case['original'])
            case_rows.append({'label': label, 'family': case['family'], 'suite': case['suite'], 'original': case['original'], 'native': actual})
            if actual != case['native']:
                (OUT / 'difference.json').write_text(json.dumps({'label': label, 'actual': actual, 'expected': case['native']}, sort_keys=True, indent=2) + '\n')
            assert actual == case['native'], label
            report['method_cases'] += 1
            while live:
                drop(next(iter(live)))
    assert report['method_cases'] == len(selected)
    report['status'] = 'PASS'
except BaseException:
    report['traceback'] = traceback.format_exc()
    raise
finally:
    log.close()
    report.update(seconds=time.monotonic() - started, live_values=len(live), functions=dict(counts),
                  partition=args.partition, corpus=next(row[1] for row in PARTITIONS if row[0] == args.partition))
    (OUT / 'report.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    (OUT / 'cases.json.xz').write_bytes(lzma.compress(json.dumps(case_rows, sort_keys=True).encode(), preset=3))
    (OUT / 'fixture.py').write_bytes(Path(__file__).read_bytes())
print(json.dumps({'status': report['status'], 'native_calls': report['native_calls'], 'method_cases': report['method_cases'],
                  'seconds': report['seconds'], 'live_values': report['live_values']}, sort_keys=True), flush=True)
