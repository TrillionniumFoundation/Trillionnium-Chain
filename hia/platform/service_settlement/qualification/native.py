"""Actual public immutable Engine ABI against retained, exact original fixtures.

The fee-only private operation is executed by the current arithmetic image;
every other operation uses the public ownership DSO. Fresh original execution
is a separate mandatory stage, not inferred from this retained-fixture check.
"""
from pathlib import Path
import argparse
import ctypes as C
import hashlib
import json
import lzma
import struct
import time
import traceback
import zlib

HERE = Path(__file__).resolve().parent
from hia.platform.service_settlement.qualification.common import CODES, identity, save


class Capture:
    def __init__(self, root):
        self.root = root
        self.stream = (root / 'actual-bytes.chunked-zlib.bin').open('xb')
        self.chunk_journal = (root / 'chunks.jsonl').open('x')
        self.index = (root / 'calls.jsonl').open('x')
        self.chunks = {}
        self.offset = 0
        self.calls = 0
        self.native_calls = 0
        self._last_exact_blob = None

    def blob(self, data):
        # Always receive the fresh snapshot. Reuse only after full byte equality.
        # A single immutable bytes value is retained, with an explicit 8 MiB cap.
        eligible = type(data) is bytes and 65536 <= len(data) <= 8 * 1024 * 1024
        previous = self._last_exact_blob
        if eligible and previous is not None and data == previous[0]:
            descriptor = previous[1]
            return {'bytes': descriptor['bytes'], 'sha256': descriptor['sha256'],
                    'chunks': list(descriptor['chunks'])}
        chunks = []
        for p in range(0, len(data), 65536):
            chunk = data[p:p + 65536]
            digest = hashlib.sha256(chunk).hexdigest()
            if digest not in self.chunks:
                packed = zlib.compress(chunk, level=1)
                row = {'offset': self.offset, **identity(chunk),
                       'compressed_bytes': len(packed),
                       'compressed_sha256': hashlib.sha256(packed).hexdigest()}
                self.stream.write(packed)
                self.stream.flush()
                self.chunk_journal.write(json.dumps(row, sort_keys=True) + '\n')
                self.chunk_journal.flush()
                self.chunks[digest] = row
                self.offset += len(packed)
            chunks.append(digest)
        descriptor = {**identity(data), 'chunks': chunks}
        if eligible:
            self._last_exact_blob = (data, {'bytes': descriptor['bytes'], 'sha256': descriptor['sha256'],
                                           'chunks': tuple(chunks)})
        return descriptor

    def record(self, record):
        record['ordinal'] = self.calls
        self.calls += 1
        self.native_calls += int(record.get('native_call', False))
        self.index.write(json.dumps(record, sort_keys=True) + '\n')
        self.index.flush()

    def close(self):
        self.stream.close()
        self.chunk_journal.close()
        self.index.close()
        save(self.root / 'chunk-index.json', self.chunks)
        return {'records': self.calls, 'native_calls': self.native_calls, 'chunks': len(self.chunks),
                'uncompressed_unique_bytes': sum(row['bytes'] for row in self.chunks.values()),
                'encoding': 'independent-zlib-chunks-with-immediate-journal-v1',
                'stream': identity((self.root / 'actual-bytes.chunked-zlib.bin').read_bytes()),
                'chunk_journal': identity((self.root / 'chunks.jsonl').read_bytes()),
                'index': identity((self.root / 'calls.jsonl').read_bytes()),
                'chunks_index': identity((self.root / 'chunk-index.json').read_bytes())}


class PublicEngine:
    def __init__(self, build_dir, capture, *, observed_image=None):
        self.capture = capture
        self.live = {}
        self.next_id = 1
        self.errors = []
        self.build_dir = Path(build_dir)
        self.build = json.loads((self.build_dir / 'build.json').read_bytes())
        assert self.build['status'] == 'PUBLIC_NATIVE_LINKED_NOT_QUALIFIED'
        raw = (self.build_dir / 'settlement-engine.so').read_bytes()
        assert identity(raw) == self.build['artifact']
        image_path = self.build_dir / 'settlement-engine.so'
        if observed_image is not None:
            image_path, expected_identity = observed_image
            assert identity(Path(image_path).read_bytes()) == expected_identity
        self.library = C.CDLL(str(image_path))
        self.functions = {}
        ptr, word, out = C.c_void_p, C.c_uint64, C.POINTER(C.c_void_p)
        signatures = {
            'engine_new': [ptr, word, out],
            'engine_apply': [ptr, word, ptr, word, out],
            'engine_replay': [ptr, word, ptr, word, out],
            'engine_validate_execution': [ptr, ptr, word, out],
            'engine_clone': [ptr, out], 'owned_clone': [ptr, out],
            'owned_drop': [ptr], 'owned_kind': [ptr],
            'engine_history_count': [ptr, C.POINTER(word)],
            'error_code': [ptr, C.POINTER(word)],
            'engine_state_copy': [ptr, out], 'error_display': [ptr, out],
        }
        for name in ('engine_trust', 'engine_state', 'engine_state_root',
                     'error_message', 'bytes_view'):
            signatures[name] = [ptr, out, C.POINTER(word)]
        for name in ('consumption_receipt_id', 'consumption_rollup_id',
                     'settlement_policy_hash', 'operation_id'):
            signatures[name] = [ptr, word, out]
        assert set('trnm_settlement_' + name for name in signatures) == set(self.build['exports'])
        for name, arguments in signatures.items():
            function = getattr(self.library, 'trnm_settlement_' + name)
            function.argtypes, function.restype = arguments, word
            self.functions[name] = function

    def snapshot(self, owner):
        assert owner in self.live
        header = C.string_at(owner, 32)
        assert header[:8] == b'SSOWN001'
        kind, size, reserved = struct.unpack_from('<3Q', header, 8)
        assert kind in (1, 2, 3, 4, 255) and reserved == 0 and size < 1 << 32
        return C.string_at(owner, size + 32)

    def call(self, name, *args, owners=(), request=None, result=None, scalar_inputs=None):
        before = {owner: self.snapshot(owner) for owner in owners}
        record = {'function': name, 'native_call': True, 'owners': [self.live[x] for x in owners],
                  'before': [self.capture.blob(before[x]) for x in owners]}
        if scalar_inputs is not None:
            assert name in ('engine_apply', 'engine_replay')
            assert type(args[1]) is C.c_uint64
            assert scalar_inputs == {'height': args[1].value}
            record['scalar_inputs'] = dict(scalar_inputs)
        if request is not None:
            record['request'] = self.capture.blob(request)
        start = time.monotonic_ns()
        status = self.functions[name](*args)
        record.update(status=status, elapsed_ns=time.monotonic_ns() - start)
        after = {owner: self.snapshot(owner) for owner in owners}
        record['after'] = [self.capture.blob(after[x]) for x in owners]
        if result is not None:
            pointer = result.value
            record['result_pointer_nonnull'] = pointer is not None
            if status == 0:
                assert pointer is not None and pointer not in self.live
                self.live[pointer] = self.next_id
                self.next_id += 1
                record['result_owner'] = self.live[pointer]
                record['result'] = self.capture.blob(self.snapshot(pointer))
            else:
                assert pointer is None
        self.capture.record(record)
        assert before == after, (name, 'existing immutable owner changed')
        return status

    def owned(self, name, owner=None, body=None, height=None, *, expected_status=0):
        result = C.c_void_p(0x1234)
        owners = () if owner is None else (owner,)
        data = None
        scalar_inputs = None
        if body is not None:
            data = (C.c_ubyte * (len(body) + 64))()
            C.memset(data, 0xA7, len(data))
            C.memmove(C.byref(data, 32), body, len(body))
            before = bytes(data)
            pointer = C.byref(data, 32)
        if name == 'engine_new' or name in ('consumption_receipt_id', 'consumption_rollup_id', 'settlement_policy_hash', 'operation_id'):
            args = (pointer, len(body), C.byref(result))
        elif name in ('engine_apply', 'engine_replay'):
            assert type(height) is int and 0 <= height < 1 << 64
            actual_height = C.c_uint64(height)
            args = (owner, actual_height, pointer, len(body), C.byref(result))
            scalar_inputs = {'height': actual_height.value}
        elif name == 'engine_validate_execution':
            args = (owner, pointer, len(body), C.byref(result))
        else:
            args = (owner, C.byref(result))
        status = self.call(name, *args, owners=owners, request=body, result=result, scalar_inputs=scalar_inputs)
        if data is not None:
            assert before == bytes(data), (name, 'input or guards mutated')
        assert status == expected_status, (name, status, expected_status)
        return result.value

    def scalar(self, name, owner):
        value = C.c_uint64(0x1234)
        status = self.call(name, owner, C.byref(value), owners=(owner,))
        self.capture.record({'function': name + ':scalar', 'value': value.value})
        assert status == 0
        return value.value

    def kind(self, owner):
        return self.call('owned_kind', owner, owners=(owner,))

    def view(self, name, owner):
        pointer, size = C.c_void_p(0x1234), C.c_uint64(0x1234)
        status = self.call(name, owner, C.byref(pointer), C.byref(size), owners=(owner,))
        assert status == 0
        full_size = len(self.snapshot(owner))
        assert pointer.value is not None and owner + 32 <= pointer.value <= owner + full_size
        assert size.value <= owner + full_size - pointer.value
        value = C.string_at(pointer.value, size.value)
        self.capture.record({'function': name + ':view', 'owner': self.live[owner],
                             'relative_offset': pointer.value - owner,
                             'value': self.capture.blob(value)})
        return value

    def drop(self, owner):
        if owner is None:
            assert self.call('owned_drop', None) == 0
            return
        old = self.snapshot(owner)
        logical = self.live[owner]
        start = time.monotonic_ns()
        status = self.functions['owned_drop'](owner)
        self.capture.record({'function': 'owned_drop', 'native_call': True, 'owner': logical,
                             'before': self.capture.blob(old), 'status': status,
                             'elapsed_ns': time.monotonic_ns() - start})
        assert status == 0
        del self.live[owner]

    def error(self, owner):
        assert self.kind(owner) == 255
        code = self.scalar('error_code', owner)
        message = self.view('error_message', owner)
        display = self.owned('error_display', owner)
        assert self.kind(display) == 3
        actual = self.view('bytes_view', display)
        assert actual == CODES[code - 1].encode() + b': ' + message
        clone = self.owned('owned_clone', owner)
        assert clone != owner and self.snapshot(clone) == self.snapshot(owner)
        self.drop(owner)
        assert self.scalar('error_code', clone) == code and self.view('error_message', clone) == message
        self.drop(clone)
        assert self.view('bytes_view', display) == actual
        self.drop(display)
        self.errors.append({'code': code, 'message': message.decode(), 'display': actual.decode()})
        return code, message


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--fee-build', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve(); out.mkdir(mode=0o700)
    (out / 'executed-qualifier.py').write_bytes(Path(__file__).read_bytes())
    report = {'status': 'INCOMPLETE', 'public_owned_api_tested': True,
              'fresh_original_executed_here': False, 'whole_engine_or_store_closed': False,
              'fixture_operations': 0, 'fixtures': 0, 'fee_private_calls': 0}
    capture = Capture(out)
    public = PublicEngine(args.build, capture)
    report['build'] = identity((args.build / 'build.json').read_bytes())
    report['image'] = public.build['artifact']
    report['source_inputs'] = public.build['source_inputs']
    error_rows = json.loads((HERE / 'errors.json').read_bytes())
    error_ids = {(CODES.index(code) + 1, message.encode()): i
                 for i, (_, code, message) in enumerate(error_rows, 1)}
    fee = None
    slots = [None, None]
    results = []
    try:
        packed = (HERE / 'fixtures.json.xz').read_bytes()
        assert identity(packed)['sha256'] == 'bf417e6b3d4086767b0614c9de0094d8794945100a8e6e149823d84869decc26'
        fixtures = json.loads(lzma.decompress(packed))['fixtures']
        for case in fixtures:
            slots = [None, None]
            request, expected = map(bytes.fromhex, (case['input'], case['expected']))
            p = 16; count = struct.unpack_from('<Q', request, 8)[0]
            actual = bytearray(b'SSR10001' + struct.pack('<3Q', count, 0, 0))
            for ordinal in range(count):
                op, slot, height, n = struct.unpack_from('<4Q', request, p)
                p += 32; data = request[p:p+n]; p += n
                code, body = 0, b''
                result = None
                if op == 0:
                    if slots[slot] is not None: code = 104
                    else: result = public.owned('engine_new', body=data)
                elif op in (1, 5, 10):
                    if slots[slot] is None: code = 103
                    else:
                        result = public.owned({1: 'engine_apply', 5: 'engine_replay', 10: 'engine_validate_execution'}[op], slots[slot], data, height)
                elif op == 2:
                    if slots[slot] is None: code = 103
                elif op == 3:
                    if slots[slot] is None: code = 103
                    elif slots[1-slot] is not None: code = 104
                    else:
                        result = public.owned('engine_clone', slots[slot])
                        assert public.snapshot(result) == public.snapshot(slots[slot])
                        slots[1-slot], result = result, None
                elif op == 4:
                    if slots[slot] is None: code = 103
                    else: public.drop(slots[slot]); slots[slot] = None
                elif op in (6, 7, 8, 11):
                    result = public.owned({6: 'consumption_receipt_id', 7: 'consumption_rollup_id', 8: 'settlement_policy_hash', 11: 'operation_id'}[op], body=data)
                elif op == 9:
                    if fee is None:
                        build = json.loads((args.fee_build / 'build.json').read_bytes())
                        assert build['status'] == 'NATIVE_EMITTED_NOT_EXECUTED'
                        assert identity((args.fee_build / 'module.so').read_bytes()) == build['artifact']
                        fee_library = C.CDLL(str(args.fee_build / 'module.so'))
                        fee = fee_library.f0; fee.argtypes = [C.c_void_p, C.c_uint64] * 3; fee.restype = C.c_uint32
                        report['fee_build'] = identity((args.fee_build / 'build.json').read_bytes())
                        report['fee_image'] = build['artifact']
                    inp = struct.pack('<Q', 0) + data
                    b = [(C.c_ubyte * z)() for z in (len(inp) + 64, 17 + 64, 160 + 64)]
                    for buffer in b: C.memset(buffer, 0x6B, len(buffer))
                    C.memmove(C.byref(b[0], 32), inp, len(inp)); before = list(map(bytes, b))
                    start = time.monotonic_ns()
                    status = fee(C.byref(b[0], 32), len(inp), C.byref(b[1], 32), 17, C.byref(b[2], 32), 160)
                    after = list(map(bytes, b))
                    capture.record({'function': 'private_proportional_fee', 'native_call': True, 'status': status,
                                    'elapsed_ns': time.monotonic_ns() - start,
                                    'before': [capture.blob(v) for v in before],
                                    'after': [capture.blob(v) for v in after]})
                    assert status == 0 and before[0] == after[0]
                    for i in (1, 2): assert before[i][:32] == after[i][:32] and before[i][-32:] == after[i][-32:]
                    assert after[1][32] in (0, 1)
                    body = after[1][32:33 + 16 * after[1][32]]
                    assert after[1][32 + len(body):] == before[1][32 + len(body):]
                    report['fee_private_calls'] += 1
                else: raise AssertionError(('unsupported operation', op))
                if result is not None:
                    kind = public.kind(result)
                    if kind == 255:
                        error = public.error(result)
                        code = error_ids.get(error, 101)
                    elif op in (0, 1, 5):
                        assert kind == 1
                        if slots[slot] is not None: public.drop(slots[slot])
                        slots[slot] = result
                    elif op == 10:
                        assert kind == 4 and public.view('bytes_view', result) == b''
                        public.drop(result)
                    else:
                        assert kind == 2
                        body = public.view('bytes_view', result)
                        assert len(body) == 32
                        public.drop(result)
                if (op < 6 or op == 10) and slots[slot] is not None:
                    root = public.view('engine_state_root', slots[slot]); assert len(root) == 32
                    body += root + struct.pack('<Q', public.scalar('engine_history_count', slots[slot]))
                    if op == 2:
                        state = public.view('engine_state', slots[slot])
                        copied = public.owned('engine_state_copy', slots[slot])
                        assert public.kind(copied) == 3 and public.view('bytes_view', copied) == state
                        public.drop(copied)
                        body += state
                    if op == 0 and code == 0:
                        assert public.view('engine_trust', slots[slot]) == data
                actual.extend(struct.pack('<4Q', op, slot, code, len(body)) + body)
                report['fixture_operations'] += 1
            assert p == len(request)
            struct.pack_into('<Q', actual, 16, len(actual))
            row = {'name': case['name'], 'input': capture.blob(request), 'expected': capture.blob(expected),
                   'actual': capture.blob(bytes(actual)), 'equal': actual == expected}
            results.append(row); save(out / 'fixture-results.json', results)
            assert actual == expected, (case['name'], identity(actual), identity(expected))
            for owner in slots:
                if owner is not None: public.drop(owner)
            slots = [None, None]
            report['fixtures'] += 1
            assert not public.live
            if report['fixtures'] % 20 == 0:
                print(json.dumps({'fixtures': report['fixtures'], 'operations': report['fixture_operations'], 'calls': capture.calls}), flush=True)
        report.update(status='PASS', complete_fixture_bytes_equal=True, live_owners=0,
                      explicit_public_immutable_lifecycle=True,
                      public_error_observations=public.errors,
                      retained_fixtures_only=True)
    except BaseException:
        report.update(status='FAIL', exception=traceback.format_exc(), live_owners=len(public.live))
    finally:
        report['capture'] = capture.close()
        save(out / 'report.json', report)
        print(json.dumps({k: report.get(k) for k in ('status', 'fixtures', 'fixture_operations', 'fee_private_calls', 'live_owners', 'exception')}), flush=True)
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__': raise SystemExit(main())
