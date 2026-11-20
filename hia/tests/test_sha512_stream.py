"""Actual selfhost SHA-512 streaming and independent hashlib comparisons.

The original one-shot SHA-512 remains the only constants/compression source.
These tests call its incremental HIA owner through the pinned native compiler.
The large-input child bypasses only native_support's 1 MiB JSON transport cap;
it calls the same emitted f0 with real unaligned buffers and full canaries.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import unittest

from hia.tests.native_support import NativeModule

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'hia/src/crypto/sha512_stream.hepta'
CONTEXT = 1512
DIGEST = 131168
MIN_ARENA = DIGEST + 64
SCRATCH = b'\xc7' * 143553
OUTPUT = b'\xa5' * 83
MASK = (1 << 64) - 1


def pattern(length):
    return bytes((index * 79 + index // 256 + 17) & 255 for index in range(length))


def words(*values):
    return struct.pack('<' + 'Q' * len(values), *values)


LARGE_WORKER = r'''
import ctypes,fcntl,hashlib,json,os,resource,struct,sys,time
request=json.load(sys.stdin)
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
resource.setrlimit(resource.RLIMIT_AS,(256<<20,256<<20))
resource.setrlimit(resource.RLIMIT_CPU,(30,30))
libc=ctypes.CDLL(None,use_errno=True)
if libc.prctl(4,0,0,0,0):raise OSError(ctypes.get_errno(),'disable core dumps')
with open(request['library'],'rb') as stream:binary=stream.read()
if hashlib.sha256(binary).hexdigest()!=request['sha256']:raise ValueError('changed native artifact')
fd=os.memfd_create('trnm-hia-sha512-stream',os.MFD_ALLOW_SEALING)
try:
 position=0
 while position<len(binary):
  count=os.write(fd,binary[position:])
  if count<=0:raise OSError('short native artifact capture')
  position+=count
 fcntl.fcntl(fd,getattr(fcntl,'F_ADD_SEALS',1033),15)
 library=ctypes.CDLL('/proc/self/fd/'+str(fd))
finally:os.close(fd)
entry=library.f0
entry.argtypes=[ctypes.c_void_p,ctypes.c_uint64]*3
entry.restype=ctypes.c_uint64
answers=[]
for case in request['cases']:
 message=bytes((index*79+index//256+17)&255 for index in range(case['length']))
 raw=struct.pack('<QQ',0,case['chunk'])+message
 payloads=[raw,b'\xa5'*83,b'\xc7'*143553]
 copies=[];arguments=[];residues=[]
 for payload,residue in zip(payloads,case['residues']):
  storage=ctypes.create_string_buffer(b'\x69'*(len(payload)+32))
  begin=8+((residue-ctypes.addressof(storage))%8)
  address=ctypes.addressof(storage)+begin
  ctypes.memmove(address,payload,len(payload))
  copies.append((storage,begin,len(payload)))
  arguments.extend((ctypes.c_void_p(address),len(payload)))
  residues.append(address%8)
 start=time.monotonic_ns();result=entry(*arguments);elapsed=time.monotonic_ns()-start
 after=[storage.raw[begin:begin+size] for storage,begin,size in copies]
 guards=all(storage.raw[:begin]==b'\x69'*begin and
  storage.raw[begin+size:-1]==b'\x69'*(len(storage.raw)-1-begin-size) and
  storage.raw[-1:]==b'\0' for storage,begin,size in copies)
 answers.append({'length':case['length'],'chunk':case['chunk'],
  'input_sha256':hashlib.sha256(raw).hexdigest(),'value':result&0xffffffff,
  'abi_status':result>>32,'residues':residues,'guards':guards,
  'input_unchanged':after[0]==raw,'output':after[1].hex(),
  'digest':after[2][131168:131232].hex(),
  'context_gap_unchanged':after[2][1512:131168]==payloads[2][1512:131168],
  'complete_tail_unchanged':after[2][131232:]==payloads[2][131232:],
  'total_low':int.from_bytes(after[2][1472:1480],'little'),
  'total_high':int.from_bytes(after[2][1480:1488],'little'),
  'elapsed_ns':elapsed})
print(json.dumps({'artifact_sha256':request['sha256'],'cases':answers,
 'compiler_modules_loaded':[name for name in sys.modules if name.startswith('hepta')]}))
'''


class Sha512StreamNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources = {path: path.read_bytes() for path in (
            SOURCE, SOURCE.with_name('sha512_arena.hepta'))}
        cls.native = NativeModule(SOURCE, byte_exports=('f0',), backend='selfhost')
        cls.native_calls = 0
        cls.large_pointer_calls = 0

    @classmethod
    def tearDownClass(cls):
        try:
            stable = all(path.read_bytes() == raw for path, raw in cls.sources.items())
            if not stable:
                raise AssertionError('SHA-512 source changed during actual execution')
            print(json.dumps({
                'schema': 'trnm.hia.sha512-stream-native-observation.v1',
                'backend': 'selfhost', 'shared_runner_calls': cls.native_calls,
                'additional_large_pointer_calls': cls.large_pointer_calls,
                'source_sha256': {path.relative_to(ROOT).as_posix(): hashlib.sha256(raw).hexdigest()
                                  for path, raw in cls.sources.items()},
                'sources_unchanged': stable, 'artifact_sha256': cls.native.artifact_sha256,
                'compiler_sha256': cls.native.receipt['compiler_sha256'],
                'whole_chain_native': False,
            }, sort_keys=True))
        finally:
            cls.native.close()

    def call(self, raw, *, scratch=SCRATCH, output=OUTPUT, expected=0):
        result = self.native.call('f0', [raw, output, scratch], timeout=30).require_returned()
        self.assertEqual(result.value, expected, result)
        self.assertEqual(result.abi_status, 0)
        self.assertEqual(result.arguments[0], raw)
        type(self).native_calls += 1
        return result.arguments

    def assert_untouched_regions(self, before, after, *, finalized=False):
        self.assertEqual(after[CONTEXT:DIGEST], before[CONTEXT:DIGEST])
        if finalized:
            self.assertEqual(after[DIGEST + 64:], before[DIGEST + 64:])
        else:
            self.assertEqual(after[DIGEST:], before[DIGEST:])

    def assert_digest(self, message, result, before=SCRATCH):
        expected = hashlib.sha512(message).digest()
        self.assertEqual(result[1], expected + OUTPUT[64:])
        self.assertEqual(result[2][DIGEST:DIGEST + 64], expected)
        self.assertEqual(struct.unpack_from('<QQ', result[2], 1472), (len(message), 0))
        self.assertEqual(struct.unpack_from('<Q', result[2], 1504)[0], 1)
        self.assert_untouched_regions(before, result[2], finalized=True)

    def test_padding_boundaries_and_all_small_lengths_with_multiple_chunks(self):
        for length in (*range(260), 511, 512, 513, 4095, 4096, 4097):
            message = pattern(length)
            chunk = (1, 7, 111, 112, 127, 128, 129, 8192)[length % 8]
            with self.subTest(length=length, chunk=chunk):
                self.assert_digest(message, self.call(words(0, chunk) + message))
        for length in (0, 111, 112, 127, 128, 129):
            for chunk in (1, 7, 111, 112, 127, 128, 129, MASK):
                message = pattern(length)
                with self.subTest(length=length, chunk=chunk):
                    self.assert_digest(message, self.call(words(0, chunk) + message))

    def test_messages_beyond_the_original_128_kib_cap(self):
        for length in (131071, 131072, 131073, 131167, 131168, 131169, 262145, 524289):
            for chunk in (127, 4096, MASK):
                message = pattern(length)
                with self.subTest(length=length, chunk=chunk):
                    self.assert_digest(message, self.call(words(0, chunk) + message))

    def test_separate_updates_hash_the_actual_concatenation(self):
        pieces = [b'', b'prefix\x00' * 9, pattern(111), b'', pattern(129), pattern(131201)]
        initialized = self.call(words(1))
        self.assertEqual(initialized[1], OUTPUT)
        self.assert_untouched_regions(SCRATCH, initialized[2])
        arena = initialized[2]
        for piece in pieces:
            raw = words(2, 29, len(piece)) + b'guard' + piece + b'suffix'
            result = self.call(raw, scratch=arena)
            self.assertEqual(result[1], OUTPUT)
            self.assert_untouched_regions(arena, result[2])
            arena = result[2]
        self.assert_digest(b''.join(pieces), self.call(words(4), scratch=arena))

    def test_same_arena_prefix_message_and_signature_regions_are_preserved(self):
        prefix = pattern(96)
        message = pattern(131201)
        arena = bytearray(pattern(143360 + len(message) + 31))
        arena[141216:141216 + len(prefix)] = prefix
        arena[143360:143360 + len(message)] = message
        initial = bytes(arena)
        arena = self.call(words(1), scratch=initial)[2]
        for offset, length in ((141216, len(prefix)), (143360, 111), (143471, len(message) - 111)):
            result = self.call(words(3, offset, length), scratch=arena)
            self.assertEqual(result[1], OUTPUT)
            self.assert_untouched_regions(arena, result[2])
            arena = result[2]
        self.assert_digest(prefix + message, self.call(words(4), scratch=arena), before=initial)

    def test_capacity_ranges_and_bad_requests_refuse_without_any_write(self):
        initialized = self.call(words(1))[2]
        cases = [(words(0, 1) + b'abc', OUTPUT[:n], SCRATCH, 100)
                 for n in (0, 1, 31, 63)]
        cases += [(words(1), OUTPUT, SCRATCH[:n], 100)
                  for n in (0, 1511, 1512, DIGEST, MIN_ARENA - 1)]
        cases += [(raw, OUTPUT, initialized, 101) for raw in (
            b'', b'\0' * 7, words(0), words(0, 0), words(5), words(1) + b'x',
            words(4) + b'x', words(2), words(3), words(3, 1512, 0) + b'x',
            words(2, MASK, 0), words(2, 24, MASK), words(2, 25, 0),
            words(3, 0, 0), words(3, 1511, 1), words(3, MASK, 0),
            words(3, len(initialized), 1), words(3, 1512, MASK))]
        for raw, output, scratch, status in cases:
            with self.subTest(raw=raw[:24].hex(), output=len(output), scratch=len(scratch)):
                self.assertEqual(self.call(raw, output=output, scratch=scratch, expected=status),
                                 [raw, output, scratch])
        minimum = self.call(words(0, 128) + b'abc', scratch=bytes(MIN_ARENA))
        self.assert_digest(b'abc', minimum, before=bytes(MIN_ARENA))

    def test_state_validation_finalization_and_explicit_reinitialization(self):
        initialized = self.call(words(1))[2]
        invalid = [SCRATCH]
        for offset, value in ((1496, 0), (1504, 1), (1488, 128), (1488, 1),
                              (1480, 1 << 61)):
            changed = bytearray(initialized)
            struct.pack_into('<Q', changed, offset, value)
            invalid.append(bytes(changed))
        for arena in invalid:
            for raw in (words(2, 24, 0), words(3, 1512, 0), words(4)):
                self.assertEqual(self.call(raw, scratch=arena, expected=102), [raw, OUTPUT, arena])
        finished = self.call(words(0, 128) + b'first')[2]
        for raw in (words(2, 24, 1) + b'x', words(4)):
            self.assertEqual(self.call(raw, scratch=finished, expected=102), [raw, OUTPUT, finished])
        reset = self.call(words(1), scratch=finished)[2]
        result = self.call(words(2, 24, 6) + b'second', scratch=reset)
        self.assert_digest(b'second', self.call(words(4), scratch=result[2]), before=finished)

    def test_128_bit_length_carry_padding_and_prewrite_overflow_refusal(self):
        initialized = self.call(words(1))[2]
        maximum = bytearray(initialized)
        struct.pack_into('<QQQ', maximum, 1472, MASK, (1 << 61) - 1, 127)
        maximum = bytes(maximum)
        for raw in (words(2, 24, 1) + b'x', words(3, 1512, 1)):
            self.assertEqual(self.call(raw, scratch=maximum, expected=103), [raw, OUTPUT, maximum])
        carry = bytearray(initialized)
        struct.pack_into('<QQQ', carry, 1472, MASK - 1, 3, 126)
        carry = bytes(carry)
        updated = self.call(words(2, 24, 2) + b'xy', scratch=carry)
        self.assertEqual(struct.unpack_from('<QQQ', updated[2], 1472), (0, 4, 0))
        self.assert_untouched_regions(carry, updated[2])
        final = self.call(words(4), scratch=updated[2])
        self.assertEqual(final[2][1344 + 112:1344 + 128], ((4 << 64) * 8).to_bytes(16, 'big'))
        self.assert_untouched_regions(updated[2], final[2], finalized=True)

    def test_real_unaligned_inputs_above_one_mebibyte_preserve_every_guard(self):
        cases = [{'length': length, 'chunk': chunk, 'residues': [7, 3, 5]}
                 for length, chunk in (((1 << 20) + 1, 127), ((2 << 20) + 17, 8192),
                                       ((4 << 20) + 257, MASK))]
        request = {'library': str(self.native.library), 'sha256': self.native.artifact_sha256,
                   'cases': cases}
        process = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', LARGE_WORKER],
                                 input=json.dumps(request), text=True, capture_output=True,
                                 check=True, timeout=40)
        self.assertEqual(process.stderr, '')
        observed = json.loads(process.stdout)
        self.assertEqual(observed['artifact_sha256'], self.native.artifact_sha256)
        self.assertEqual(observed['compiler_modules_loaded'], [])
        self.assertEqual(len(observed['cases']), len(cases))
        for case, actual in zip(cases, observed['cases']):
            message = pattern(case['length'])
            expected = hashlib.sha512(message).hexdigest()
            self.assertEqual(actual['input_sha256'], hashlib.sha256(words(0, case['chunk']) + message).hexdigest())
            self.assertEqual(actual['value'], 0)
            self.assertEqual(actual['abi_status'], 0)
            self.assertEqual(actual['output'], (bytes.fromhex(expected) + OUTPUT[64:]).hex())
            self.assertEqual(actual['digest'], expected)
            self.assertEqual(actual['residues'], case['residues'])
            self.assertEqual((actual['total_low'], actual['total_high']), (len(message), 0))
            for flag in ('guards', 'input_unchanged', 'context_gap_unchanged', 'complete_tail_unchanged'):
                self.assertIs(actual[flag], True, flag)
            type(self).large_pointer_calls += 1

    def test_backend_is_selfhost_and_uses_the_original_compression_source(self):
        receipt = self.native.receipt
        self.assertEqual(receipt['chain_migration']['backend'], 'selfhost')
        self.assertFalse(receipt['claims']['python_emitter_used'])
        self.assertFalse(receipt['claims']['fallback_used'])
        inputs = receipt['chain_migration']['inputs']
        self.assertIn('src/crypto/sha512_arena.hepta', [row['path'] for row in inputs])


if __name__ == '__main__':
    unittest.main()
