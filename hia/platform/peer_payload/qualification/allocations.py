"""Observe actual HIA allocation/refusal/lifetime behavior, with no replay oracle."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import ctypes
import fcntl
import hashlib
import json
import os
import resource
import struct
import sys
import threading
import time
import traceback

request = json.loads(Path(sys.argv[1]).read_bytes())
out = Path(request['output'])
out.mkdir(mode=0o700)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
resource.setrlimit(resource.RLIMIT_AS, (512 << 20, 512 << 20))
resource.setrlimit(resource.RLIMIT_CPU, (240, 240))

def identity(path):
    raw = Path(path).read_bytes()
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}

image_descriptors = []

def load(name):
    item = request[name]
    assert identity(item['path']) == item['identity']
    raw = Path(item['path']).read_bytes()
    fd = os.memfd_create('trnm-payload-alloc-' + name, os.MFD_ALLOW_SEALING)
    try:
        at = 0
        while at < len(raw):
            count = os.write(fd, raw[at:]); assert count > 0; at += count
        fcntl.fcntl(fd, getattr(fcntl, 'F_ADD_SEALS', 1033), 15)
        module = ctypes.CDLL('/proc/self/fd/' + str(fd))
    except BaseException:
        os.close(fd)
        raise
    image_descriptors.append(fd)
    module.f0.argtypes = [ctypes.c_void_p, ctypes.c_uint64] * 3
    module.f0.restype = ctypes.c_uint64
    return module

production, observed = load('production'), load('observed')
observed.trnm_pq_test_stat.argtypes = [ctypes.c_uint64]
observed.trnm_pq_test_stat.restype = ctypes.c_uint64
observed.trnm_pq_test_fail_after.argtypes = [ctypes.c_uint64]
observed.trnm_pq_test_fail_after.restype = None

def stats():
    return [observed.trnm_pq_test_stat(i) for i in range(9)]

journal = (out / 'abi.jsonl').open('x')
journal_lock = threading.Lock()
call_sequence = 0

def write_event(value):
    with journal_lock:
        journal.write(json.dumps(value, sort_keys=True) + '\n')
        journal.flush()

def invoke(module, payload, capacity):
    global call_sequence
    with journal_lock:
        index = call_sequence
        call_sequence += 1
    write_event({'phase':'begin','index':index,'input_bytes':len(payload),
                 'input_sha256':hashlib.sha256(payload).hexdigest(),'capacity':capacity})
    originals = [payload, bytes([0xa5]) * capacity, bytes([0x73]) * 137]
    prefix, suffix = bytes([0x6d]) * 64 + b'!', bytes([0xd6]) * 64
    buffers, args = [], []
    for raw in originals:
        buffer = ctypes.create_string_buffer(prefix + raw + suffix)
        buffers.append(buffer)
        args.extend([ctypes.c_void_p(ctypes.addressof(buffer) + len(prefix)), len(raw)])
    started = time.monotonic_ns()
    result = module.f0(*args)
    elapsed = time.monotonic_ns() - started
    after = [bytes(buffer.raw[:-1]) for buffer in buffers]
    write_event({'phase':'returned','index':index,'return':result,'elapsed_ns':elapsed,
        'output_hex':after[1][len(prefix):-len(suffix)].hex(),
        'guards_preserved':all(raw[:len(prefix)] == prefix and raw[-len(suffix):] == suffix for raw in after),
        'input_after_sha256':hashlib.sha256(after[0][len(prefix):-len(suffix)]).hexdigest(),
        'scratch_after_sha256':hashlib.sha256(after[2][len(prefix):-len(suffix)]).hexdigest()})
    assert all(raw[:len(prefix)] == prefix and raw[-len(suffix):] == suffix for raw in after)
    assert after[0][len(prefix):-len(suffix)] == originals[0]
    assert after[2][len(prefix):-len(suffix)] == originals[2]
    output = after[1][len(prefix):-len(suffix)]
    assert result >> 32 == 0
    if result:
        assert output == originals[1]
    else:
        assert len(output) >= 80 and struct.unpack_from('<Q', output)[0] == 72
        assert output[80:] == originals[1][80:]
    return {'return': result, 'output_hex': output.hex(), 'elapsed_ns': elapsed}

report = {'status':'FAIL','whole_payload_owner_qualified':False}
rows = []
parallel = []
try:
    assert stats() == [0] * 9
    cases_path = Path(request['cases']['path'])
    assert identity(cases_path) == request['cases']['identity']
    cases = json.loads(cases_path.read_bytes())
    assert len(cases) == 840
    baseline = {}
    rows = []
    failures = 0
    no_allocations = 0
    sequential_calls = 0

    def pair(name, payload, capacity):
        global failures, no_allocations, sequential_calls
        before = stats()
        observed.trnm_pq_test_fail_after(0)
        reference = invoke(production, payload, capacity)
        actual = invoke(observed, payload, capacity)
        sequential_calls += 2
        assert (reference['return'], reference['output_hex']) == (actual['return'], actual['output_hex'])
        after = stats()
        allocated = after[0] - before[0]
        assert allocated in (0, 1) and after[1] - before[1] == allocated
        assert after[2] == after[3] == after[5] == 0 and after[4] == before[4]
        observed.trnm_pq_test_fail_after(1)
        denied = invoke(observed, payload, capacity)
        sequential_calls += 1
        observed.trnm_pq_test_fail_after(0)
        final = stats()
        if allocated:
            assert denied['return'] == 103 and final[0] - after[0] == 1 and final[4] - after[4] == 1
            failures += 1
        else:
            assert (denied['return'], denied['output_hex']) == (actual['return'], actual['output_hex'])
            assert final == after
            no_allocations += 1
        assert final[1] == after[1] and final[2] == final[3] == final[5] == 0
        rows.append({'name': name, 'capacity': capacity, 'input_bytes': len(payload),
            'input_sha256': hashlib.sha256(payload).hexdigest(), 'production': reference,
            'observed': actual, 'allocation_denied': denied, 'before': before, 'after': after, 'final': final})
        return reference

    for case in cases:
        payload = struct.pack('<Q', 1) + bytes.fromhex(case['payload_hex'])
        baseline[case['name']] = pair(case['name'], payload, 256)

    genesis = next(case for case in cases if case['name'] == 'genesis-only')
    valid = struct.pack('<Q', 1) + bytes.fromhex(genesis['payload_hex'])
    for capacity in (0, 1, 7, 8, 63, 71, 72, 79, 80, 81):
        pair('capacity-' + str(capacity), valid, capacity)
    for length in (0, 1, 7, 8, 135, 143):
        pair('short-input-' + str(length), valid[:length], 256)
    pair('unknown-op', struct.pack('<Q', 2) + valid[8:], 256)

    observed.trnm_pq_test_fail_after(0)
    before_parallel = stats()
    parallel_case_names = ['genesis-only', 'first-frame', 'distinct-keys-31', 'interleaved-18-keys']
    selected = [case for case in cases if case['name'] in parallel_case_names]
    assert len(selected) == 4 and all(baseline[case['name']]['return'] == 0 for case in selected)
    barrier = threading.Barrier(8)

    def thread(number):
        results = []
        barrier.wait(timeout=10)
        for index in range(32):
            case = selected[(index + number) % len(selected)]
            payload = struct.pack('<Q', 1) + bytes.fromhex(case['payload_hex'])
            result = invoke(observed, payload, 256)
            expected = baseline[case['name']]
            assert (result['return'], result['output_hex']) == (expected['return'], expected['output_hex'])
            results.append({'name': case['name'], **result})
        return {'thread': number, 'calls': results}

    # Bound observer worker stacks independently of the platform default.
    previous_thread_stack_bytes = threading.stack_size(1 << 20)
    try:
        parallel_thread_stack_bytes = threading.stack_size()
        assert parallel_thread_stack_bytes == 1 << 20
        with ThreadPoolExecutor(max_workers=8) as executor:
            parallel = list(executor.map(thread, range(8)))
    finally:
        threading.stack_size(previous_thread_stack_bytes)
    final = stats()
    assert sum(len(row['calls']) for row in parallel) == 256
    assert final[0] - before_parallel[0] == final[1] - before_parallel[1] == 256
    assert final[4] == before_parallel[4] and final[2] == final[3] == final[5] == 0
    assert final[0] == final[1] + final[4]
    assert not any(name.startswith('hepta') for name in sys.modules)
    report = {'status': 'PASS_ACTUAL_HIA_ALLOCATION_AND_LIFETIME', 'original_cases': len(cases),
              'paired_shapes': len(rows), 'actual_allocation_failures': failures,
              'zero_allocation_refusals': no_allocations, 'sequential_native_calls': sequential_calls,
              'parallel_threads': 8, 'parallel_native_calls': 256, 'allocation_counters': final,
              'parallel_thread_stack_bytes': parallel_thread_stack_bytes,
              'production_object_unchanged': True, 'test_observer_supplies_business_logic': False,
              'whole_payload_owner_qualified': False, 'original_service_budget_qualified': False,
              'original_tests_rerun_by_this_control': False}
    (out / 'calls.json').write_text(json.dumps({'sequential': rows, 'parallel': parallel}, indent=2, sort_keys=True) + '\n')
    (out / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps(report, sort_keys=True))
except BaseException as error:
    report.update(status='FAIL',failure=repr(error),traceback=traceback.format_exc())
    raise
finally:
    report['actual_abi_calls_started'] = call_sequence
    (out / 'calls.json').write_text(json.dumps({'sequential':rows,'parallel':parallel},sort_keys=True,indent=2)+'\n')
    (out / 'report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    journal.close()
    for descriptor in image_descriptors:
        os.close(descriptor)
