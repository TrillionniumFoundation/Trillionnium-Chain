"""Check live-handle ABI, const borrows, independent values and concurrency."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import argparse
import ctypes as C
import hashlib
import json
import lzma
import struct
import threading
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
started = time.monotonic()
report = {'status': 'FAIL', 'image_sha256': image_sha, 'abi_calls': 0, 'abi_refusals': 0,
    'caller_live_pointer_and_const_contract_required': True, 'arbitrary_foreign_pointer_gate_qualified': False,
    'concurrent_mutation_of_same_budget_supported': False, 'constant_time_qualified': False}
records = []
guard = threading.Lock()
inflight = 0
peak = 0
kept = []


def call(name, *args):
    global inflight, peak
    primary = name in ('sign_exact_message', 'verify_exact_message', 'profile_verify')
    before = time.monotonic()
    if primary:
        with guard:
            inflight += 1
            peak = max(peak, inflight)
    answer = api[name](*args)
    with guard:
        if primary:
            inflight -= 1
        report['abi_calls'] += 1
        row = {'name': name, 'thread': threading.get_ident(), 'started': before, 'seconds': time.monotonic() - before}
        if hasattr(answer, 'status'):
            row.update(status=answer.status, has_value=bool(answer.value))
        elif hasattr(answer, 'size'):
            row.update(has_data=bool(answer.data), size=answer.size,
                       data_hex=C.string_at(answer.data, answer.size).hex() if answer.data else None)
        else:
            row['value'] = answer
        records.append(row)
    return answer


def own(answer, kind):
    assert answer.status == 0 and answer.value
    assert call('kind', answer.value) == kind
    return answer.value


def drop(handle):
    assert call('drop', handle) == 0


def view(name, handle):
    result = call(name, handle)
    assert result.data
    return C.string_at(result.data, result.size)


def bind(v):
    end = v['retirement']
    return b''.join(bytes.fromhex(v[k]) for k in ('network', 'parameters', 'genesis')) + struct.pack(
        '<IBBH3Q', v['version'], v['scope'], int(end is not None), 0, v['activation'], end or 0, 0)


def envelope(v):
    ids = [bytes.fromhex(x) for x in v['signer_ids']]
    payload = bytes.fromhex(v['payload'])
    return struct.pack('<H', v['purpose']) + bytes(6) + struct.pack('<7Q', *(v[k] for k in
        ('generation', 'epoch', 'sequence', 'valid_from', 'valid_until')), len(ids), len(payload)) + b''.join(ids) + payload


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
    old = auth_fixtures()
    spki = bytes.fromhex(old['derive-public']['native']['spki'])
    key_id = bytes.fromhex(old['derive-public']['native']['key_id'])
    original_seed = buffer(bytes(32))
    seed = own(call('seed_copy', original_seed, 32), 1)
    C.memset(original_seed, 0xa5, 32)
    identity = own(call('public_spki_from_seed', seed), 100)
    assert view('identity_spki', identity) == spki
    key = own(call('signing_from_owned_seed', seed, buffer(key_id)), 2)
    spki_source = buffer(spki)
    verifier = own(call('verifier_from_pinned_spki', spki_source, len(spki), buffer(key_id)), 3)
    C.memset(spki_source, 0x77, len(spki))
    assert view('key_public_spki', verifier) == spki
    fixture = profile_fixture()
    key_list = [bytes.fromhex(x) for x in fixture['output']['keys']]
    packed_keys = struct.pack('<Q', len(key_list)) + b''.join(struct.pack('<Q', len(x)) + x for x in key_list)
    binding_source = buffer(bind(fixture['input']['binding']))
    keys_source = buffer(packed_keys)
    profile = own(call('profile_from_pinned_keys', 2, binding_source, keys_source, len(packed_keys)), 4)
    C.memset(binding_source, 0x17, 128)
    C.memset(keys_source, 0x19, len(packed_keys))
    profile_snapshot = own(call('profile_snapshot', profile), 112)
    ids = own(call('profile_signer_ids', profile), 113)
    pinned = own(call('profile_pinned_keys', profile), 114)
    # A valid const view from the owner can be passed back as an input. The
    # independently allocated private arenas never alias that owner storage.
    borrowed = call('key_public_spki', key)
    alias_signature = own(call('sign_exact_message', key, borrowed.data, borrowed.size), 101)
    signed_bytes = view('signature_bytes', alias_signature)
    alias_observation = own(call('verify_exact_message', verifier, borrowed.data, borrowed.size, buffer(signed_bytes), len(signed_bytes)), 102)
    assert view('message_authenticated_message', alias_observation) == spki
    (OUT / 'alias-original-case.json').write_text(json.dumps({'label': 'borrowed-public-spki-as-input',
        'original': {'op': 'seed', 'seed': bytes(32).hex(), 'message': spki.hex()},
        'native': {'code': 0, 'spki': spki.hex(), 'derived_spki': spki.hex(), 'key_id': key_id.hex(), 'signature': signed_bytes.hex()}}, sort_keys=True, indent=2) + '\n')
    assert view('key_public_spki', key) == view('key_public_spki', verifier) == spki

    # Only live objects are used for wrong-type inputs; no arbitrary addresses
    # are dereferenced and no broader foreign-pointer contract is asserted.
    invalid = [
        ('seed_copy', (None, 32)), ('seed_copy', (original_seed, 31)),
        ('public_spki_from_seed', (key,)), ('signing_from_owned_seed', (None, buffer(key_id))),
        ('signing_from_owned_seed', (verifier, buffer(key_id))),
        ('verifier_from_pinned_spki', (None, len(spki), buffer(key_id))),
        ('verifier_from_pinned_spki', (buffer(spki), len(spki), None)),
        ('sign_exact_message', (verifier, None, 0)), ('verify_exact_message', (key, None, 0, None, 0)),
        ('sign_statement', (verifier, None, 0, None, None, 0)), ('verify_frame', (key, None, 0, None, None, 0)),
        ('verify_tpq1', (None, 0, None, None, 0, buffer(spki), len(spki))),
        ('verify_ml_dsa_65', (None, 1952, None, 0, None, 0, None, 0)),
        ('profile_from_pinned_keys', (2, None, buffer(packed_keys), len(packed_keys))),
        ('profile_snapshot', (verifier,)), ('profile_signer_ids', (key,)), ('profile_pinned_keys', (identity,)),
        ('profile_verify', (profile, verifier, None, 0, None, 0)), ('budget_snapshot', (verifier,)),
        ('budget_reserve', (key, 1, 1)), ('profile_candidate_message', (key, None, 0)),
        ('profile_commitment', (verifier, 1, None, 0)), ('profile_active_at', (key, 0)),
        ('profile_require_claim', (profile, None)), ('error_display', (identity,)),
    ]
    for name, arguments in invalid:
        result = call(name, *arguments)
        assert result.status == 104 and not result.value, (name, result.status)
        report['abi_refusals'] += 1
    assert view('key_public_spki', key) == spki and view('key_public_spki', verifier) == spki
    error = own(call('verify_exact_message', verifier, None, 0, buffer(bytes(3309)), 3309), 255)
    for name in ('message_authenticated_message', 'message_signer_key_id', 'frame_statement',
                 'candidate_message', 'candidate_crypto_profile_id', 'signature_bytes'):
        result = call(name, error)
        assert not result.data and result.size == 0
    drop(error)

    source_message = buffer(b'\x00')
    signature = bytes.fromhex(old['sign-exact-1']['native']['signature'])
    candidate_wire = buffer(bytes.fromhex(fixture['output']['wire']))
    candidate_expected = buffer(envelope(fixture['input']['expected']))
    original_candidate_message = bytes.fromhex(fixture['output']['message'])
    barrier = threading.Barrier(8)

    def thread(index):
        budget = own(call('budget_new'), 5)
        held = []
        barrier.wait(timeout=30)
        first = time.monotonic()
        for repeat in range(8):
            signed = own(call('sign_exact_message', key, source_message, 1), 101)
            assert view('signature_bytes', signed) == signature
            checked = own(call('verify_exact_message', verifier, source_message, 1, buffer(signature), len(signature)), 102)
            candidate = own(call('profile_verify', profile, budget, candidate_wire, len(candidate_wire),
                candidate_expected, len(candidate_expected)), 107)
            assert view('candidate_message', candidate) == original_candidate_message
            held.extend((signed, checked, candidate))
        assert call('budget_attempts', budget) == 8
        drop(budget)
        return {'index': index, 'thread': threading.get_ident(), 'started': first,
                'seconds': time.monotonic() - first, 'values': held}

    with ThreadPoolExecutor(max_workers=8) as pool:
        threads = list(pool.map(thread, range(8)))
    assert len({row['thread'] for row in threads}) == 8 and peak >= 2
    kept = [value for row in threads for value in row['values']]
    assert len(kept) == 192 and len(set(kept)) == 192
    # Every observation and snapshot remains usable after its original owner
    # and every caller input buffer have been destroyed or mutated.
    drop(key)
    drop(verifier)
    drop(profile)
    C.memset(source_message, 0xc7, 1)
    C.memset(candidate_wire, 0xc8, len(candidate_wire))
    C.memset(candidate_expected, 0xc9, len(candidate_expected))
    assert view('identity_spki', identity) == spki
    assert view('message_authenticated_message', alias_observation) == spki
    assert view('signature_bytes', alias_signature) == signed_bytes
    assert view('bound_profile_id', profile_snapshot).hex() == fixture['output']['id']
    assert view('bound_binding', profile_snapshot).hex() == fixture['output']['binding']
    assert view('bound_configuration_bytes', profile_snapshot).hex() == fixture['output']['config']
    for array, getter, original in [(ids, 'profile_signer_id_at', fixture['output']['signer_ids']),
                                     (pinned, 'profile_pinned_key_at', fixture['output']['pinned_keys'])]:
        for index, expected_value in enumerate(original):
            result = call(getter, array, index)
            assert result.data and C.string_at(result.data, result.size).hex() == expected_value
    for value in kept:
        kind = call('kind', value)
        if kind == 101:
            assert view('signature_bytes', value) == signature
        elif kind == 102:
            assert view('message_authenticated_message', value) == b'\0'
            assert view('message_signer_key_id', value) == key_id
        else:
            assert kind == 107 and view('candidate_message', value) == original_candidate_message
            assert view('candidate_crypto_profile_id', value).hex() == fixture['output']['id']
        drop(value)
    kept = []
    for value in (identity, alias_signature, alias_observation, profile_snapshot, ids, pinned):
        drop(value)
    assert call('drop', None) == 0
    report.update(status='PASS', threads=[{k: v for k, v in row.items() if k != 'values'} for row in threads],
        maximum_concurrent_primary_calls=peak, independent_post_owner_values=198,
        readonly_owner_shared_threads=8, owned_values_remaining=0)
except BaseException:
    report['traceback'] = traceback.format_exc()
    raise
finally:
    report['seconds'] = time.monotonic() - started
    (OUT / 'calls.json').write_text(json.dumps(records, sort_keys=True, indent=2) + '\n')
    (OUT / 'report.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    (OUT / 'fixture.py').write_bytes(Path(__file__).read_bytes())
print(json.dumps({key: value for key, value in report.items() if key != 'threads'}, sort_keys=True), flush=True)
