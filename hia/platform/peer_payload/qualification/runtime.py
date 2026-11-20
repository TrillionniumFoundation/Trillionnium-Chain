"""Compare the private arena dispatcher with exact qualified native kernels.

This process supplies fixtures and observes bytes. Every validation, hash,
replay decision and output value is computed by the actual HIA libraries.
"""
from pathlib import Path
import ctypes
import fcntl
import hashlib
import json
import mmap
import os
import resource
import struct
import sys
import time
import traceback

request = json.loads(Path(sys.argv[1]).read_bytes())
out = Path(request['output'])
out.mkdir(mode=0o700)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
resource.setrlimit(resource.RLIMIT_AS, (512 << 20, 512 << 20))
resource.setrlimit(resource.RLIMIT_CPU, (240, 240))
MAX_RECORDS = (64 << 20) // 380
INDEX = 8192 + MAX_RECORDS * 380
EXTENT = INDEX + MAX_RECORDS * 128
PREFIX = b'\x6d' * 64 + b'!'
SUFFIX = b'\xd6' * 64
descriptors, mappings, views = [], [], []


def identity(path):
    raw = Path(path).read_bytes()
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def load(name):
    item = request[name]
    assert identity(item['path']) == item['identity']
    raw = Path(item['path']).read_bytes()
    fd = os.memfd_create('trnm-payload-runtime-' + name, os.MFD_ALLOW_SEALING)
    at = 0
    while at < len(raw):
        count = os.write(fd, raw[at:])
        assert count > 0
        at += count
    fcntl.fcntl(fd, getattr(fcntl, 'F_ADD_SEALS', 1033), 15)
    module = ctypes.CDLL('/proc/self/fd/' + str(fd))
    # Keep the descriptor numbers distinct for the dynamic loader cache.
    descriptors.append(fd)
    module.f0.argtypes = [ctypes.c_void_p, ctypes.c_uint64] * 3
    module.f0.restype = ctypes.c_uint64
    return module


def guarded(size):
    memory = mmap.mmap(-1, len(PREFIX) + size + len(SUFFIX))
    memory[:len(PREFIX)] = PREFIX
    memory[len(PREFIX) + size:] = SUFFIX
    view = (ctypes.c_ubyte * len(memory)).from_buffer(memory)
    mappings.append((memory, size))
    views.append(view)
    return memory, ctypes.addressof(view) + len(PREFIX)


def data(memory, start, size):
    return bytes(memory[len(PREFIX) + start:len(PREFIX) + start + size])


def put(memory, start, raw):
    memory[len(PREFIX) + start:len(PREFIX) + start + len(raw)] = raw


def word(memory, offset, value):
    struct.pack_into('<Q', memory, len(PREFIX) + offset, value)


def read_word(memory, offset):
    return struct.unpack_from('<Q', memory, len(PREFIX) + offset)[0]


def guards():
    assert all(memory[:len(PREFIX)] == PREFIX and memory[len(PREFIX) + size:] == SUFFIX
               for memory, size in mappings)


runtime, codec, replay = load('runtime'), load('codec'), load('replay')
events, ep = guarded(64)
commands, cp = guarded(192)
state, sp = guarded(EXTENT)
put(events, 0, b'\x5b' * 64)


def reference(module, raw):
    originals = [raw, b'\xa5' * 4096, b'\x73' * 137]
    buffers, args = [], []
    for item in originals:
        buffer = ctypes.create_string_buffer(PREFIX + item + SUFFIX)
        buffers.append(buffer)
        args.extend([ctypes.addressof(buffer) + len(PREFIX), len(item)])
    result = module.f0(*args)
    after = [bytes(buffer.raw[:-1]) for buffer in buffers]
    assert all(item[:len(PREFIX)] == PREFIX and item[-len(SUFFIX):] == SUFFIX for item in after)
    assert after[0][len(PREFIX):-len(SUFFIX)] == raw
    assert after[2][len(PREFIX):-len(SUFFIX)] == originals[2]
    assert result >> 32 == 0
    output = after[1][len(PREFIX):-len(SUFFIX)]
    if result:
        assert output == originals[1]
        return result, b''
    size = struct.unpack_from('<Q', output)[0]
    assert size <= 4088 and output[8 + size:] == originals[1][8 + size:]
    return result, output[8:8 + size]


def dispatch(operation, argument, length=0):
    put(commands, 0, b'\xa5' * 192)
    word(commands, 152, operation)
    word(commands, 160, argument)
    word(commands, 176, length)
    before = data(commands, 0, 192)
    started = time.monotonic_ns()
    result = runtime.f0(ep, 64, cp, 192, sp, EXTENT)
    elapsed = time.monotonic_ns() - started
    assert result == 2
    expected = bytearray(before)
    struct.pack_into('<Q', expected, 144, 0)
    code = read_word(commands, 184)
    struct.pack_into('<Q', expected, 184, code)
    assert data(commands, 0, 192) == expected
    assert data(events, 0, 64) == b'\x5b' * 64
    guards()
    return code, elapsed


report = {'status': 'FAIL', 'whole_payload_owner_qualified': False,
          'original_tests_rerun_by_this_control': False,
          'original_service_budget_qualified': False,
          'private_arena_bytes': EXTENT}
started = time.monotonic_ns()
rows = []
try:
    for key in ('codec_cases', 'replay_cases', 'priority_cases'):
        assert identity(request[key]['path']) == request[key]['identity']
    codec_cases = json.loads(Path(request['codec_cases']['path']).read_bytes())
    replay_cases = json.loads(Path(request['replay_cases']['path']).read_bytes())
    priority_cases = json.loads(Path(request['priority_cases']['path']).read_bytes())
    assert len(codec_cases) == 4472 and len(replay_cases) == 840
    assert len(priority_cases) == 8
    for case in [*codec_cases, *priority_cases]:
        payload = bytes.fromhex(case['payload_hex'])
        assert len(payload) <= 512
        expected_code, expected_output = reference(codec, struct.pack('<Q', case['op']) + payload)
        put(state, 0, bytes(8192))
        put(state, 2048, payload)
        code, elapsed = dispatch(1, case['op'], len(payload))
        assert code == expected_code, (case['name'], code, expected_code)
        output = data(state, 6144, read_word(state, 0)) if code == 0 else b''
        assert output == expected_output, case['name']
        rows.append({'kind': 'priority' if case['name'].startswith('priority-') else 'codec', 'name': case['name'], 'code': code,
            'input_sha256': hashlib.sha256(payload).hexdigest(),
            'output_hex': output.hex(), 'runtime_elapsed_ns': elapsed})
    for case in replay_cases:
        payload = bytes.fromhex(case['payload_hex'])
        assert len(payload) >= 136 and len(payload) - 136 <= MAX_RECORDS * 380
        expected_code, expected_output = reference(replay, struct.pack('<Q', 1) + payload)
        put(state, 0, bytes(8192))
        put(state, 2048, payload[:136])
        put(state, 8192, payload[136:])
        code, elapsed = dispatch(0, len(payload) - 136)
        assert code == expected_code, (case['name'], code, expected_code)
        output = data(state, 6144, 72) if code == 0 else b''
        assert output == expected_output, case['name']
        rows.append({'kind': 'replay', 'name': case['name'], 'code': code,
            'input_sha256': hashlib.sha256(payload).hexdigest(),
            'output_hex': output.hex(), 'runtime_elapsed_ns': elapsed})

    controls = []
    for field, declared_lengths in ((0, (0, 1, 63)), (1, (0, 1, 143, 184, 191)),
                                    (2, (0, 1, 8192, EXTENT - 1))):
        for declared in declared_lengths:
            put(commands, 0, b'\xa5' * 192)
            word(commands, 152, 0)
            before = data(commands, 0, 192)
            extent = [64, 192, EXTENT]
            extent[field] = declared
            digest_before = hashlib.sha256(memoryview(state)[len(PREFIX):-len(SUFFIX)]).hexdigest()
            result = runtime.f0(ep, extent[0], cp, extent[1], sp, extent[2])
            assert result == 206 and data(commands, 0, 192) == before
            assert hashlib.sha256(memoryview(state)[len(PREFIX):-len(SUFFIX)]).hexdigest() == digest_before
            guards()
            controls.append({'kind': 'short-argument', 'field': field, 'bytes': declared, 'return': result})
    for operation in (3, (1 << 64) - 1):
        put(commands, 0, b'\xa5' * 192)
        word(commands, 152, operation)
        before = data(commands, 0, 192)
        result = runtime.f0(ep, 64, cp, 192, sp, EXTENT)
        assert result == 206 and data(commands, 0, 192) == before
        controls.append({'kind': 'unknown-dispatch', 'operation': operation, 'return': result})
    genesis = bytes.fromhex(next(case['payload_hex'] for case in replay_cases if case['name'] == 'genesis-only'))
    for length, wanted in ((0, 2), (1, 2), (379, 2), ((64 << 20) + 1, 8), ((1 << 64) - 1, 8)):
        put(state, 0, bytes(8192))
        put(state, 2048, genesis[:136])
        code, elapsed = dispatch(0, length)
        assert code == wanted
        controls.append({'kind': 'original-length-order', 'bytes': length, 'code': code})
    put(state, 2048, bytes(136))
    code, elapsed = dispatch(0, (1 << 64) - 1)
    assert code == 10
    controls.append({'kind': 'namespace-before-length', 'code': code})
    assert len(controls) == 20
    # Operation 2 now owns the seven native query methods. Keep the old
    # invalid selector stimulus and require a real query refusal, then retain
    # two unknown outer opcodes above under their still-unsupported values.
    put(commands, 0, b'\xa5' * 192)
    word(commands, 152, 2)
    before_state = hashlib.sha256(memoryview(state)[len(PREFIX):-len(SUFFIX)]).hexdigest()
    before_command = bytearray(data(commands, 0, 192))
    result = runtime.f0(ep, 64, cp, 192, sp, EXTENT)
    assert result == 2 and read_word(commands, 184) == 100
    struct.pack_into('<Q', before_command, 144, 0)
    struct.pack_into('<Q', before_command, 184, 100)
    assert data(commands, 0, 192) == before_command
    assert hashlib.sha256(memoryview(state)[len(PREFIX):-len(SUFFIX)]).hexdigest() == before_state
    guards()
    controls.append({'kind':'new-query-invalid-selector','return':result,'code':100})

    def persistent():
        h=hashlib.sha256()
        h.update(data(state,1536,256))
        h.update(data(state,2240,32))
        h.update(memoryview(state)[len(PREFIX)+8192:len(PREFIX)+EXTENT])
        return h.hexdigest()
    def index_bytes_digest():
        return hashlib.sha256(memoryview(state)[len(PREFIX)+INDEX:len(PREFIX)+EXTENT]).hexdigest()
    def record_frame(record):
        value=bytearray(272)
        for to,at,n in ((0,52,32),(32,84,32),(64,132,32),(112,164,32),(144,196,32),(176,228,32),(240,284,32)):
            value[to:to+n]=record[at:at+n]
        for to,at,n in ((96,116,1),(104,124,8),(208,260,8),(216,268,8),(224,276,1),(232,280,4)):
            struct.pack_into('<Q',value,to,int.from_bytes(record[at:at+n],'big'))
        return bytes(value)
    query_rows=[]; commit_rows=[]
    selected=[r for r in replay_cases if r['name']=='first-frame' or r['name'] in ['prefix-'+str(i) for i in (2,3,4,7,8,12,16)]]
    assert len(selected)>=5
    for case in selected:
        payload=bytes.fromhex(case['payload_hex']);wal=payload[136:]
        put(state,0,bytes(8192));put(state,2048,payload[:136]);put(state,8192,wal)
        code,elapsed=dispatch(0,len(wal));assert code==0,case['name']
        record=wal[-380:];current=record_frame(record)
        put(state,3072,current);before=persistent()
        # Expected values come from retained original-generated WAL bytes.
        expected={0:struct.pack('<QQ',1,int.from_bytes(record[260:268],'big')),
                  1:struct.pack('<Q',1),
                  2:struct.pack('<QQ',1,int.from_bytes(record[12:20],'big'))+record[348:380]}
        for operation in (0,1,2,3,5,6):
            code,elapsed=dispatch(2,operation)
            assert code==(5 if operation==3 else 0),(case['name'],operation,code)
            if operation in expected:
                assert data(state,6144,len(expected[operation]))==expected[operation]
            assert persistent()==before,(case['name'],operation,'readonly state changed')
            query_rows.append({'case':case['name'],'operation':operation,'code':code,'elapsed_ns':elapsed,'persistent_sha256':before,'persistent_after_sha256':persistent(),'output_hex':data(state,6144,len(expected[operation])).hex() if operation in expected else ''})
        # Rebuild the previous prefix, append the retained exact original WAL
        # record through the new native commit method, and compare every index
        # byte with a full native replay of the complete retained WAL.
        count=len(wal)//380-1
        put(state,0,bytes(8192));put(state,2048,payload[:136]);put(state,8192,wal[:-380])
        code,elapsed=dispatch(0,len(wal)-380);assert code==0
        put(state,4608,record)
        code,elapsed=dispatch(2,4,count);assert code==0,(case['name'],code)
        committed=data(state,6144,72);index_digest=index_bytes_digest()
        assert data(state,8192,len(wal))==wal
        code,elapsed=dispatch(0,len(wal));assert code==0
        assert data(state,6144,72)==committed and index_bytes_digest()==index_digest
        commit_rows.append({'case':case['name'],'records':count+1,'index_sha256':index_digest,'summary_hex':committed.hex(),'replayed_index_sha256':index_bytes_digest(),'replayed_summary_hex':data(state,6144,72).hex()})
    report['readonly_queries']=query_rows
    report['incremental_commit_replay_pairs']=commit_rows
    assert len(controls)==21
    assert not any(name.startswith('hepta') for name in sys.modules)
    for key in ('runtime', 'codec', 'replay', 'codec_cases', 'replay_cases', 'priority_cases'):
        assert identity(request[key]['path']) == request[key]['identity']
    report.update(status='PASS_ACTUAL_PRIVATE_ARENA_DISPATCH', codec_pairs=4472, priority_pairs=8, replay_pairs=840,
        paired_native_calls=2 * len(rows), boundary_native_calls=len(controls),
        controls=controls, guards_preserved=True, command_writes_confined=True,
        host_business_logic_used=False)
except BaseException as error:
    report.update(error=repr(error), traceback=traceback.format_exc(), completed_pairs=len(rows))
    raise
finally:
    report['elapsed_ns'] = time.monotonic_ns() - started
    report['max_rss_kib'] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    (out / 'calls.json').write_text(json.dumps(rows, indent=2, sort_keys=True) + '\n')
    (out / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: value for key, value in report.items() if key not in ('controls', 'traceback')}, sort_keys=True))
    for descriptor in descriptors:
        os.close(descriptor)
