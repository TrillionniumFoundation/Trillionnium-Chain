"""Execute one exact native metadata-WAL call with file-backed observations.

The caller owns the 240-second process-family deadline and one 3-second cleanup.
This worker supplies fixtures and records bytes; HIA performs all replay work.
The index mode exposes private HIA-produced state for structural inspection.
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


def identity(path):
    assert path.is_file() and not path.is_symlink()
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'bytes': path.stat().st_size, 'sha256': digest}


request_path = Path(sys.argv[1])
request = json.loads(request_path.read_bytes())
out = Path(request['output'])
out.mkdir(mode=0o700)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
resource.setrlimit(resource.RLIMIT_AS, (512 << 20, 512 << 20))
resource.setrlimit(resource.RLIMIT_CPU, (240, 240))
library_path = Path(request['library'])
input_path = Path(request['input'])
assert identity(library_path) == request['library_identity']
assert identity(input_path) == request['input_identity']
assert 144 <= request['input_identity']['bytes'] <= (64 << 20) + 144 + 380
report = {'status': 'FAIL', 'request': identity(request_path), 'mode': request['mode'],
          'library': request['library_identity'], 'input': request['input_identity'],
          'whole_payload_owner_qualified': False, 'original_service_budget_qualified': False}
prefix, suffix = b'\x6d' * 64 + b'!', b'\xd6' * 64
mappings = []
views = []


def guarded(size, fill=None):
    memory = mmap.mmap(-1, len(prefix) + size + len(suffix))
    memory[:len(prefix)] = prefix
    memory[len(prefix) + size:] = suffix
    if fill is not None:
        memory[len(prefix):len(prefix) + size] = fill
    view = (ctypes.c_ubyte * len(memory)).from_buffer(memory)
    mappings.append((memory, size))
    views.append(view)
    return memory, ctypes.addressof(view) + len(prefix)


def payload(memory, size):
    return memoryview(memory)[len(prefix):len(prefix) + size]


try:
    executable = library_path.read_bytes()
    fd = os.memfd_create('trnm-metadata-wal-observed', os.MFD_ALLOW_SEALING)
    try:
        at = 0
        while at < len(executable):
            count = os.write(fd, executable[at:])
            assert count > 0
            at += count
        os.fchmod(fd, 0o500)
        fcntl.fcntl(fd, getattr(fcntl, 'F_ADD_SEALS', 1033), 15)
        library = ctypes.CDLL('/proc/self/fd/' + str(fd))
    finally:
        os.close(fd)
    fn = library.f0
    fn.argtypes = [ctypes.c_void_p, ctypes.c_uint64] * 3
    fn.restype = ctypes.c_uint64
    source_size = request['input_identity']['bytes']
    if request['mode'] == 'replay':
        input_size = source_size
        inputs, input_address = guarded(input_size)
        with input_path.open('rb') as source:
            at = len(prefix)
            while block := source.read(1 << 20):
                inputs[at:at + len(block)] = block
                at += len(block)
        assert at == len(prefix) + input_size
        work_size = 137
        work, work_address = guarded(work_size, b'\x73' * work_size)
    elif request['mode'] == 'index':
        wal_size = source_size - 144
        assert wal_size % 380 == 0 and 0 < wal_size <= (64 << 20)
        count = wal_size // 380
        input_size = 8
        inputs, input_address = guarded(input_size, struct.pack('<Q', count))
        work_size = 8192 + wal_size + count * 128
        work, work_address = guarded(work_size)
        with input_path.open('rb') as source:
            assert source.read(8) == struct.pack('<Q', 1)
            namespace = source.read(136)
            work[len(prefix) + 2048:len(prefix) + 2184] = namespace
            at = len(prefix) + 8192
            while block := source.read(1 << 20):
                work[at:at + len(block)] = block
                at += len(block)
            assert at == len(prefix) + 8192 + wal_size
        struct.pack_into('<Q', work, len(prefix) + 1544, count)
        for mode in range(4):
            struct.pack_into('<Q', work, len(prefix) + 1552 + mode * 8,
                             8192 + wal_size + mode * count * 32)
    else:
        raise ValueError('Unknown private observation mode')
    output_size = request.get('output_size', 256)
    assert type(output_size) is int and 0 <= output_size <= 4096
    output, output_address = guarded(output_size, b'\xa5' * output_size)
    before_input = hashlib.sha256(payload(inputs, input_size)).hexdigest()
    before_work = hashlib.sha256(payload(work, work_size)).hexdigest()
    started = time.monotonic_ns()
    result = fn(input_address, input_size, output_address, output_size, work_address, work_size)
    elapsed = time.monotonic_ns() - started
    assert all(memory[:len(prefix)] == prefix and memory[len(prefix) + size:] == suffix
               for memory, size in mappings)
    assert hashlib.sha256(payload(inputs, input_size)).hexdigest() == before_input
    assert result >> 32 == 0
    data = bytes(payload(output, output_size))
    (out / 'output.raw').write_bytes(data)
    if request['mode'] == 'replay':
        assert hashlib.sha256(payload(work, work_size)).hexdigest() == before_work
        if result == 0:
            assert output_size >= 80 and struct.unpack_from('<Q', data)[0] == 72
            assert data[80:] == b'\xa5' * (output_size - 80)
        else:
            assert data == b'\xa5' * output_size
    else:
        assert data == b'\xa5' * output_size
        with (out / 'work.raw').open('xb') as stream:
            for at in range(0, work_size, 1 << 20):
                stream.write(payload(work, work_size)[at:at + (1 << 20)])
        report['work'] = identity(out / 'work.raw')
    report.update(status='ACTUAL_NATIVE_RETURNED', value=result & 0xffffffff,
                  abi_status=result >> 32, native_elapsed_ns=elapsed,
                  input_argument_bytes=input_size, input_argument_sha256=before_input,
                  initial_work_bytes=work_size, initial_work_sha256=before_work,
                  output=identity(out / 'output.raw'), guards_preserved=True,
                  read_only_argument_unchanged=True,
                  host_compiler_modules_loaded=[name for name in sys.modules if name.startswith('hepta')])
    assert report['host_compiler_modules_loaded'] == []
    assert identity(library_path) == request['library_identity']
    assert identity(input_path) == request['input_identity']
except BaseException as error:
    report.update(error=repr(error), traceback=traceback.format_exc())
    raise
finally:
    report['max_rss_kib'] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    (out / 'report.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({key: value for key, value in report.items() if key != 'traceback'}), flush=True)
