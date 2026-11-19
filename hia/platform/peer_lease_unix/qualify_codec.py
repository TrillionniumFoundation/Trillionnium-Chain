"""Actual native/original byte comparisons; this is an observer, not a Unix authority."""
from __future__ import annotations
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import random
import select
import struct
import subprocess
import time
import traceback


def word(value):
    return struct.pack('<Q', value)


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def framed(body):
    return b'TPLS' + struct.pack('<I', len(body)) + body


def cases():
    scope = b'\x01' * 32 + b'\x02' * 32 + b'\x01' + word(0) + b'\x03' * 32
    request = word(1) + scope + b'\x04' * 32 + word(1) + word(0) + word(1000) + b'\x05' * 32
    token = scope + b'\x04' * 32 + word(1) + word(0) + b'\x05' * 32
    request_frame = framed(b'\x01\x01' + request[8:])
    response_frame = framed(b'\x01\x00' + token)
    for op, raw in ((2, request), (1, request_frame), (4, word(0) + token), (3, response_frame)):
        yield 'positive-' + str(op), word(op) + raw
    # This is valid for original private encode/new but invalid for decode.
    zero_token = scope + bytes(32) + word(0) + word(0) + bytes(32)
    yield 'private-new-zero-values-encode', word(4) + word(0) + zero_token
    yield 'public-decode-zero-values-refused', word(3) + framed(b'\x01\x00' + zero_token)
    for op, raw in ((1, request_frame), (3, response_frame)):
        for length in range(len(raw) + 1):
            yield f'cut-{op}-{length}', word(op) + raw[:length]
            if length >= 8:
                yield f'resealed-cut-{op}-{length}', word(op) + framed(raw[8:length])
        for index in range(len(raw)):
            for byte in (0, 1, 127, 255):
                changed = raw[:index] + bytes((byte,)) + raw[index + 1:]
                yield f'byte-{op}-{index}-{byte}', word(op) + changed
        for count in (0, 1, 2, 3, 16, 105, 185, 194, 195, 196, 16384, 16385, 0xffffffff):
            yield f'declared-{op}-{count}', word(op) + raw[:4] + struct.pack('<I', count) + raw[8:]
        for count in (1, 17, 16384 - len(raw) + 8, 16385 - len(raw) + 8):
            yield f'trailing-{op}-{count}', word(op) + framed(raw[8:] + b'\xa5' * count)
        for direction in range(256):
            yield f'direction-{op}-{direction}', word(op) + raw[:74] + bytes((direction,)) + raw[75:]
    for code in range(256):
        yield f'reject-decode-{code}', word(3) + framed(bytes((1, 1, code)))
        yield f'operation-decode-{code}', word(1) + request_frame[:9] + bytes((code,)) + request_frame[10:]
        yield f'response-kind-{code}', word(3) + response_frame[:9] + bytes((code,)) + response_frame[10:]
    for code in range(1, 13):
        yield f'reject-encode-{code}', word(4) + word(1) + word(code)
    for op, raw in ((2, request), (4, word(0) + token)):
        for length in range(len(raw)):
            yield f'typed-cut-{op}-{length}', word(op) + raw[:length]
        yield f'typed-trailing-{op}', word(op) + raw + b'\0'
    rng = random.Random(0x504c554e)
    for index in range(160):
        ids = [rng.randbytes(32) for _ in range(5)]
        direction = 1 + index % 2
        epoch = (0, (1 << 64) - 1, rng.getrandbits(64))[index % 3]
        s = ids[0] + ids[1] + bytes((direction,)) + word(epoch) + ids[2]
        generation, expiry, ttl = [rng.getrandbits(64) for _ in range(3)]
        if index % 4 == 0:
            generation, ttl = 0, 0
        request = word(1 + index % 4) + s + ids[3] + word(generation) + word(expiry) + word(ttl) + ids[4]
        token = s + ids[3] + word(generation) + word(expiry) + ids[4]
        yield f'random-request-encode-{index}', word(2) + request
        yield f'random-request-decode-{index}', word(1) + framed(bytes((1, 1 + index % 4)) + request[8:])
        yield f'random-token-encode-{index}', word(4) + word(0) + token
        yield f'random-token-decode-{index}', word(3) + framed(b'\x01\0' + token)
    for n in range(8):
        yield f'outer-cut-{n}', bytes(n)
    for op in (0, 5, (1 << 64) - 1):
        yield f'outer-operation-{op}', word(op)


def read_exact(stream, length):
    result = bytearray()
    deadline = time.monotonic() + 5
    while len(result) < length:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([stream], [], [], remaining)[0]:
            raise TimeoutError('original native process exceeded the fixed observer deadline')
        raw = os.read(stream.fileno(), length - len(result))
        if not raw:
            raise EOFError('original process ended before the complete observation')
        result.extend(raw)
    return bytes(result)


def identity(path):
    raw = Path(path).read_bytes()
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--native', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700)
    report = {'schema': 'trnm.hia.peer-unix-codec-comparison.v1', 'status': 'INCOMPLETE',
              'native': identity(args.native), 'original': identity(args.reference),
              'comparisons': 0, 'capacity_controls': 0, 'whole_peer_package_retired': False,
              'unix_daemon_qualified': False, 'production_activation': False}
    before = {str(p): identity(p) for p in (args.native, args.reference, Path(__file__))}
    started = time.monotonic_ns()
    library = ctypes.CDLL(str(args.native.resolve()))
    entry = library.f0
    entry.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t,
                     ctypes.c_void_p, ctypes.c_size_t)
    entry.restype = ctypes.c_uint32
    stderr = (args.output / 'original.stderr.raw').open('wb')
    original = subprocess.Popen([str(args.reference.resolve())], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=stderr, start_new_session=True)
    raw_in = (args.output / 'stdin.raw').open('wb')
    raw_native = (args.output / 'native.stdout.raw').open('wb')
    raw_original = (args.output / 'original.stdout.raw').open('wb')
    rows = (args.output / 'observations.jsonl').open('w')
    failure = None
    try:
        for label, raw in cases():
            request = struct.pack('<I', len(raw)) + raw
            raw_in.write(request)
            original.stdin.write(request)
            original.stdin.flush()
            header = read_exact(original.stdout, 16)
            expected_code, count = struct.unpack('<QQ', header)
            if count > 4096:
                raise ValueError('original observer response extent')
            expected = read_exact(original.stdout, count)
            raw_original.write(header + expected)
            native_input = ctypes.create_string_buffer(raw)
            output = ctypes.create_string_buffer(b'\xa5' * 4096)
            scratch = ctypes.create_string_buffer(b'\xc7' * 263)
            code = int(entry(native_input, len(raw), output, 4096, scratch, 263))
            actual_length = int.from_bytes(output.raw[:8], 'little') if code == 0 else 0
            if actual_length > 4088:
                raise ValueError('native observer response extent')
            actual = output.raw[8:8 + actual_length] if code == 0 else b''
            raw_native.write(struct.pack('<QQ', code, actual_length) + actual)
            need(native_input.raw[:len(raw)] == raw, 'borrowed input changed')
            need(scratch.raw[:263] == b'\xc7' * 263, 'unused scratch changed')
            if code:
                need(output.raw[:4096] == b'\xa5' * 4096, 'refusal changed output')
            else:
                need(output.raw[8 + actual_length:4096] == b'\xa5' * (4088 - actual_length), 'output suffix changed')
            equal = code == expected_code and actual == expected
            rows.write(json.dumps({'case': label, 'input_sha256': hashlib.sha256(raw).hexdigest(),
                                   'native_status': code, 'original_status': expected_code,
                                   'native_bytes': actual_length, 'original_bytes': count,
                                   'equal': equal}, sort_keys=True) + '\n')
            rows.flush()
            need(equal, (label, code, expected_code, actual.hex(), expected.hex()))
            report['comparisons'] += 1
            if code == 0 and report['capacity_controls'] < 40:
                capacity = 7 + actual_length
                guarded = ctypes.create_string_buffer(b'\x96' * (capacity + 31))
                rejected = int(entry(native_input, len(raw), guarded, capacity, scratch, 263))
                need(rejected == 102 and guarded.raw[:capacity + 31] == b'\x96' * (capacity + 31),
                     'capacity refusal changed guarded output')
                rows.write(json.dumps({'case': label, 'capacity': capacity, 'status': rejected,
                                       'all_output_guard_bytes_preserved': True}, sort_keys=True) + '\n')
                report['capacity_controls'] += 1
        report['status'] = 'PASS'
    except BaseException:
        failure = traceback.format_exc()
        report['status'] = 'FAIL'
        report['failure'] = failure
    finally:
        original.stdin.close()
        try:
            original.wait(timeout=3)
        except subprocess.TimeoutExpired:
            original.kill()
            original.wait(timeout=3)
            report['status'] = 'FAIL'
            report['cleanup'] = 'original required SIGKILL after input close'
        original.stdout.close()
        for stream in (stderr, raw_in, raw_native, raw_original, rows):
            stream.close()
        report['original_exit_code'] = original.returncode
        if original.returncode:
            report['status'] = 'FAIL'
        after = {str(p): identity(p) for p in (args.native, args.reference, Path(__file__))}
        report['source_and_binaries_unchanged'] = before == after
        if before != after:
            report['status'] = 'FAIL'
        report['source_and_binaries'] = before
        report['elapsed_ns'] = time.monotonic_ns() - started
        report['streams'] = {p.name: identity(p) for p in args.output.iterdir() if p.is_file()}
        (args.output / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps(report, sort_keys=True))
    if failure:
        print(failure, file=__import__('sys').stderr)
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
