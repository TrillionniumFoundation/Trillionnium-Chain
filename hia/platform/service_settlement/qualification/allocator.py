"""Every observed calloc refusal rolls back, permits retry, and balances free."""
from pathlib import Path
import argparse
import concurrent.futures
import ctypes as C
import json
import lzma
import struct
import threading
import time
import traceback

from hia.platform.service_settlement.qualification.native import Capture, PublicEngine
from hia.platform.service_settlement.qualification.common import identity, save

HERE = Path(__file__).resolve().parent
parser = argparse.ArgumentParser()
parser.add_argument('--build', type=Path, required=True)
parser.add_argument('--observer', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
OUT = args.output.resolve()
OUT.mkdir(mode=0o700)
(OUT / 'executed-qualifier.py').write_bytes(Path(__file__).read_bytes())
(OUT / 'public-harness.py').write_bytes((HERE / 'native.py').read_bytes())
REPORT = {'status': 'INCOMPLETE', 'test_only_interposer': True,
          'production_image_changed': False, 'controls': [], 'actual_allocation_failures': 0}
capture = Capture(OUT)
build_raw = (args.observer / 'build.json').read_bytes()
build = json.loads(build_raw)
assert build['status'] == 'TEST_OBSERVER_LINKED_NOT_EXECUTED'
api = PublicEngine(args.build, capture,
                   observed_image=(args.observer / 'engine-observed.so', build['image']))
REPORT['observer_build'] = identity(build_raw)
REPORT['observed_image'] = build['image']
stats = {}
for name in ('calls', 'frees', 'live', 'bytes', 'failures', 'bad_frees'):
    function = getattr(api.library, 'trnm_settlement_test_alloc_' + name)
    function.argtypes = []; function.restype = C.c_uint64; stats[name] = function
inject = api.library.trnm_settlement_test_alloc_fail_after
inject.argtypes = [C.c_uint64]; inject.restype = None


def counters(): return {name: fn() for name, fn in stats.items()}


def actions(fixture):
    data = bytes.fromhex(fixture['input']); p = 16; result = []
    for _ in range(struct.unpack_from('<Q', data, 8)[0]):
        op, slot, height, n = struct.unpack_from('<4Q', data, p)
        p += 32; result.append((op, slot, height, data[p:p+n])); p += n
    assert p == len(data)
    return result


def record(row):
    REPORT['controls'].append(row)
    save(OUT / 'report.json', REPORT)


try:
    fixture_raw = (HERE / 'fixtures.json.xz').read_bytes()
    assert identity(fixture_raw)['sha256'] == 'bf417e6b3d4086767b0614c9de0094d8794945100a8e6e149823d84869decc26'
    fixtures = json.loads(lzma.decompress(fixture_raw))['fixtures']
    lifecycle = actions(fixtures[1])
    trust = lifecycle[0][3]
    engines = [api.owned('engine_new', body=trust)]
    for index in (1, 2, 5, 8):
        _, _, height, command = lifecycle[index]
        engines.append(api.owned('engine_apply', engines[-1], command, height))
    error = api.owned('engine_apply', engines[3], lifecycle[6][3], lifecycle[6][2])
    assert api.kind(error) == 255
    baseline_owners = set(api.live)
    baseline_contents = {p: api.snapshot(p) for p in api.live}
    initial = counters()
    assert initial['live'] == len(api.live) == 6 and initial['bad_frees'] == initial['failures'] == 0
    cases = [
        ('new-valid', 'engine_new', None, trust, None),
        ('new-domain-error', 'engine_new', None, actions(fixtures[2])[0][3], None),
        ('new-malformed', 'engine_new', None, b'', None),
        ('receipt-success', 'engine_apply', engines[0], lifecycle[1][3], lifecycle[1][2]),
        ('rollup-success', 'engine_apply', engines[2], lifecycle[5][3], lifecycle[5][2]),
        ('settle-not-mature', 'engine_apply', engines[3], lifecycle[6][3], lifecycle[6][2]),
        ('settle-success', 'engine_apply', engines[3], lifecycle[8][3], lifecycle[8][2]),
        ('settle-already-consumed', 'engine_apply', engines[4], lifecycle[9][3], lifecycle[9][2]),
        ('replay-exact', 'engine_replay', engines[4], lifecycle[10][3], lifecycle[10][2]),
        ('replay-conflict', 'engine_replay', engines[4], lifecycle[11][3], lifecycle[11][2]),
        ('engine-clone', 'engine_clone', engines[4], None, None),
        ('owned-engine-clone', 'owned_clone', engines[4], None, None),
        ('state-copy', 'engine_state_copy', engines[4], None, None),
        ('error-display', 'error_display', error, None, None),
        ('owned-error-clone', 'owned_clone', error, None, None),
    ]
    for op, name in [(6, 'consumption_receipt_id'), (7, 'consumption_rollup_id'),
                     (8, 'settlement_policy_hash'), (11, 'operation_id')]:
        body = next(data for f in fixtures for code, slot, height, data in actions(f) if code == op)
        cases.append((name+'-valid', name, None, body, None))
        cases.append((name+'-malformed', name, None, b'', None))
    execution = next(data for f in fixtures for op, slot, height, data in actions(f) if op == 10)
    cases.append(('execution-context', 'engine_validate_execution', engines[0], execution, None))
    cases.append(('execution-malformed', 'engine_validate_execution', engines[0], b'', None))
    for label, name, owner, data, height in cases:
        before = counters()
        result = api.owned(name, owner, data, height)
        expected = api.snapshot(result)
        after = counters(); allocations = after['calls'] - before['calls']
        assert allocations > 0 and after['failures'] == before['failures']
        assert after['live'] == before['live'] + 1
        api.drop(result)
        normal = counters()
        assert normal['live'] == before['live'] and normal['bytes'] == before['bytes']
        record({'name': label+'-normal', 'allocations': allocations,
                'expected_owner': capture.blob(expected), 'before': before, 'after': normal})
        for ordinal in range(1, allocations + 1):
            before = counters()
            inject(ordinal)
            try:
                result = api.owned(name, owner, data, height, expected_status=103)
                assert result is None
            finally:
                inject(0)
            failed = counters()
            assert failed['failures'] == before['failures'] + 1
            assert failed['calls'] - before['calls'] == ordinal
            assert failed['live'] == before['live'] and failed['bytes'] == before['bytes']
            assert failed['bad_frees'] == 0
            assert set(api.live) == baseline_owners
            assert all(api.snapshot(p) == value for p, value in baseline_contents.items())
            retried = api.owned(name, owner, data, height)
            assert api.snapshot(retried) == expected
            api.drop(retried)
            after = counters()
            assert after['live'] == before['live'] and after['bytes'] == before['bytes'] and after['bad_frees'] == 0
            record({'name': label+'-allocation-failure', 'ordinal': ordinal, 'status': 103,
                    'before': before, 'after_failure': failed, 'after_retry': after,
                    'no_output': True, 'existing_owners_unchanged': True, 'retry_equal': True})
            REPORT['actual_allocation_failures'] += 1
    # Real parallel immutable operations; each result and temporary arena belongs
    # to that call. The observer's book-keeping uses a separate test-only mutex.
    function = api.functions['engine_clone']
    drop = api.functions['owned_drop']
    state = api.functions['engine_state']
    root = api.functions['engine_state_root']
    barrier = threading.Barrier(8)
    state_expected = api.view('engine_state', engines[4])
    root_expected = api.view('engine_state_root', engines[4])
    before = counters()

    def worker(index):
        barrier.wait(timeout=10)
        observations = []
        for ordinal in range(32):
            owned = C.c_void_p()
            code = function(engines[4], C.byref(owned))
            assert code == 0 and owned.value
            sizes = []
            try:
                for getter, expected in [(state, state_expected), (root, root_expected)]:
                    pointer, size = C.c_void_p(), C.c_uint64()
                    assert getter(owned, C.byref(pointer), C.byref(size)) == 0
                    actual = C.string_at(pointer.value, size.value)
                    assert actual == expected
                    sizes.append(identity(actual))
            finally: assert drop(owned) == 0
            observations.append({'ordinal': ordinal, 'status': code, 'views': sizes})
        return {'worker': index, 'operations': observations}

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        threads = list(pool.map(worker, range(8)))
    after = counters()
    assert after['live'] == before['live'] and after['bytes'] == before['bytes'] and after['bad_frees'] == 0
    assert after['calls'] - before['calls'] == after['frees'] - before['frees'] == 256
    assert all(api.snapshot(p) == value for p, value in baseline_contents.items())
    save(OUT / 'concurrent-observations.json', threads)
    record({'name': 'eight-readers-clone-view-drop', 'threads': 8, 'owners': 256,
            'before': before, 'after': after, 'existing_owners_unchanged': True})
    for owner in list(api.live): api.drop(owner)
    final = counters()
    assert not api.live and final['live'] == final['bytes'] == final['bad_frees'] == 0
    assert final['calls'] == final['frees'] + final['failures']
    REPORT.update(status='PASS', final_counters=final, complete_lifetime_balance=True,
                  public_allocator_failure_paths_qualified=True, tested_shapes=len(cases))
except BaseException:
    REPORT.update(status='FAIL', exception=traceback.format_exc(), observed_counters=counters())
finally:
    inject(0)
    REPORT['capture'] = capture.close()
    save(OUT / 'report.json', REPORT)
    print(json.dumps({k: REPORT.get(k) for k in ('status', 'actual_allocation_failures', 'tested_shapes', 'final_counters', 'exception')}), flush=True)
raise SystemExit(0 if REPORT['status'] == 'PASS' else 1)
