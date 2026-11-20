"""Actual selfhost SHA-512 execution, independently compared with hashlib.

Algorithm source: NIST FIPS PUB 180-4, August 2015, sections 4.1.3,
4.2.3, 5.1.2, 5.3.5 and 6.4:
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
The algorithm was authored directly in HIA. The source binding for the 80 K
words followed by the eight initial words, each encoded as unsigned BE64, is
SHA256 793ec16c351a74a85c8ac55b055259a93fa42ece8a702308d0969ab7ec2a853b.
This is a constants-transcript hash, not a hash of the NIST PDF.

The bounded three-buffer wrapper and bytewise internal work load/store reuse
hia/src/crypto/sha256_arena.hepta at source SHA256
201072727d86f6f55c1c45f0012b4d850fa4ebcd078ba5bad30c682a90be8694,
with explicit SHA-512 names, capacities and work offsets. No host SHA or Rust
fallback appears in the product HIA. Test hashing is an independent oracle.

sha512_arena accepts one arena and an input length <= 131168. It preserves the
whole input region, writes its BE64 digest at [131168,131232), and uses only
[131232,132576) for K[80], W[80] and H[8]. The required arena capacity is 133120.
The final reserved work bytes and every trailing byte remain unchanged.
f0 copies the message into the arena and returns 64, or 0xfffffffd on capacity
refusal before any output or scratch write. The 128-bit SHA-512 length field
has zero upper 64 bits for this explicitly bounded byte-input interface.
No constant-time, signature-verification or FIPS-validation claim is made.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import random
import subprocess
import sys
import unittest

from hia.tests.native_support import NativeModule


SOURCE = Path(__file__).resolve().parents[1] / "src/crypto/sha512_arena.hepta"
MAX_INPUT = 131168
DIGEST_BEGIN = 131168
WORK_BEGIN = 131232
USED_WORK_END = 132576
ARENA_BYTES = 133120
REFUSED = 0xfffffffd
OUTPUT = b"\xa5" * 83
SCRATCH = b"\xc7" * (ARENA_BYTES + 31)


def pattern(length):
    return bytes((index * 79 + index // 256 + 17) & 255 for index in range(length))


# The child loads the exact native artifact through a sealed memfd. It does not
# run the compiler, an interpreter or a SHA-512 oracle. Each pointer is actually
# offset to the requested residue; Python slicing alone would not establish it.
UNALIGNED_WORKER = r"""
import base64, ctypes, fcntl, hashlib, json, os, resource, sys
request = json.load(sys.stdin)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
resource.setrlimit(resource.RLIMIT_AS, (256 << 20, 256 << 20))
resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(4, 0, 0, 0, 0):
    raise OSError(ctypes.get_errno(), 'disable core dumps')
with open(request['library'], 'rb') as stream:
    binary = stream.read()
if hashlib.sha256(binary).hexdigest() != request['sha256']:
    raise ValueError('changed native artifact')
fd = os.memfd_create('trnm-hia-sha512-unaligned', os.MFD_ALLOW_SEALING)
try:
    position = 0
    while position < len(binary):
        count = os.write(fd, binary[position:])
        if count <= 0:
            raise OSError('short native artifact capture')
        position += count
    fcntl.fcntl(fd, getattr(fcntl, 'F_ADD_SEALS', 1033), 15)
    library = ctypes.CDLL('/proc/self/fd/' + str(fd))
finally:
    os.close(fd)
entry = library.f0
entry.argtypes = [ctypes.c_void_p, ctypes.c_uint64] * 3
entry.restype = ctypes.c_uint64
answers = []
for case in request['cases']:
    raw = base64.b64decode(case['input'], validate=True)
    data = [raw, b'\xa5' * 83, b'\xc7' * 133151]
    copies, arguments, residues = [], [], []
    for payload, residue in zip(data, case['residues']):
        storage = ctypes.create_string_buffer(b'\x69' * (len(payload) + 32))
        begin = 8 + ((residue - ctypes.addressof(storage)) % 8)
        address = ctypes.addressof(storage) + begin
        ctypes.memmove(address, payload, len(payload))
        copies.append((storage, begin, len(payload)))
        arguments.extend((ctypes.c_void_p(address), len(payload)))
        residues.append(address % 8)
    result = entry(*arguments)
    after = [storage.raw[begin:begin + size] for storage, begin, size in copies]
    guards = all(storage.raw[:begin] == b'\x69' * begin
                 and storage.raw[begin + size:-1] == b'\x69' * (len(storage.raw) - 1 - begin - size)
                 and storage.raw[-1:] == b'\0'
                 for storage, begin, size in copies)
    answers.append({
        'value': result & 0xffffffff, 'abi_status': result >> 32,
        'residues': residues, 'guards': guards,
        'input_unchanged': after[0] == raw,
        'output': after[1].hex(),
        'arena_message': after[2][:len(raw)] == raw,
        'arena_gap': after[2][len(raw):131168] == data[2][len(raw):131168],
        'arena_digest': after[2][131168:131232].hex(),
        'reserved_work_and_tail': after[2][132576:] == data[2][132576:],
    })
print(json.dumps({
    'artifact_sha256': request['sha256'], 'cases': answers,
    'compiler_modules_loaded': [name for name in sys.modules if name.startswith('hepta')],
}))
"""


class Sha512NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source_bytes = SOURCE.read_bytes()
        cls.native = NativeModule(SOURCE, byte_exports=("f0",), backend="selfhost")
        cls.native_calls = 0
        cls.raw_pointer_calls = 0

    @classmethod
    def tearDownClass(cls):
        try:
            print(json.dumps({
                "schema": "trnm.hia.sha512-native-observation.v1",
                "backend": "selfhost",
                "shared_runner_calls": cls.native_calls,
                "additional_raw_pointer_calls": cls.raw_pointer_calls,
                "source_sha256": hashlib.sha256(cls.source_bytes).hexdigest(),
                "source_unchanged": SOURCE.read_bytes() == cls.source_bytes,
                "artifact_sha256": cls.native.artifact_sha256,
                "compiler_sha256": cls.native.receipt["compiler_sha256"],
                "constant_time_qualified": False,
                "signature_verification_qualified": False,
            }, sort_keys=True))
        finally:
            cls.native.close()

    def check(self, messages, *, output=OUTPUT, scratch=SCRATCH):
        messages = list(messages)
        for start in range(0, len(messages), 16):
            batch = messages[start:start + 16]
            observed = self.native.call_many(
                [("f0", [raw, output, scratch]) for raw in batch], timeout=60)
            self.assertEqual(len(observed), len(batch))
            for raw, result in zip(batch, observed):
                with self.subTest(length=len(raw), input_sha256=hashlib.sha256(raw).hexdigest()):
                    result.require_returned()
                    self.assertEqual(result.value, 64)
                    self.assertEqual(result.abi_status, 0)
                    expected = hashlib.sha512(raw).digest()
                    self.assertEqual(result.arguments[0], raw)
                    self.assertEqual(result.arguments[1], expected + output[64:])
                    arena = result.arguments[2]
                    self.assertEqual(arena[:len(raw)], raw)
                    self.assertEqual(arena[len(raw):DIGEST_BEGIN], scratch[len(raw):DIGEST_BEGIN])
                    self.assertEqual(arena[DIGEST_BEGIN:WORK_BEGIN], expected)
                    self.assertEqual(arena[USED_WORK_END:], scratch[USED_WORK_END:])
                    self.assertEqual(len(arena), len(scratch))
                type(self).native_calls += 1

    def test_standard_empty_and_abc_digests(self):
        vectors = {
            b"": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                 "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
            b"abc": "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                    "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        }
        for raw, encoded in vectors.items():
            self.assertEqual(hashlib.sha512(raw).hexdigest(), encoded)
        self.check(vectors)

    def test_every_byte_length_zero_through_259(self):
        self.check(pattern(length) for length in range(260))

    def test_padding_and_block_boundaries(self):
        lengths = sorted({block * 128 + relative
                          for block in (2, 3, 7, 8, 15, 16, 31, 32, 63, 64)
                          for relative in (-17, -16, -1, 0, 1, 111, 112, 127)})
        self.check(pattern(length) for length in lengths)

    def test_large_message_and_maximum_input_boundary(self):
        lengths = (16383, 16384, 16385, 65535, 65536, 65537,
                   130943, 130944, 131055, 131056, 131071, 131072,
                   131073, 131167, MAX_INPUT)
        self.check(pattern(length) for length in lengths)

    def test_bit_patterns_and_seeded_binary_messages(self):
        messages = [bytes([value]) * length
                    for value in (0, 1, 0x55, 0x80, 0xaa, 0xff)
                    for length in (1, 112, 128, 259)]
        messages.extend(bytes(range(256)) * copies for copies in (1, 3, 17))
        random_source = random.Random(0x5121804)
        messages.extend(random_source.randbytes(random_source.randrange(1, 8193)) for _ in range(48))
        self.check(messages)

    def test_minimum_capacity_and_preexisting_arena_bytes(self):
        for canary in (0, 0x5a, 0xff):
            self.check((b"", b"abc", pattern(112), pattern(128), pattern(MAX_INPUT)),
                       output=bytes([canary]) * 64,
                       scratch=bytes([canary]) * ARENA_BYTES)
        self.check((b"short", pattern(257)), output=pattern(129),
                   scratch=pattern(ARENA_BYTES + 4096))

    def test_capacity_refusals_preserve_all_caller_bytes(self):
        cases = [(b"abc", b"\xa5" * size, SCRATCH) for size in (0, 1, 7, 8, 31, 32, 63)]
        cases.extend((b"abc", OUTPUT, b"\xc7" * size) for size in (
            0, 1, DIGEST_BEGIN - 1, DIGEST_BEGIN, WORK_BEGIN - 1,
            WORK_BEGIN, USED_WORK_END - 1, USED_WORK_END, ARENA_BYTES - 1))
        cases.extend((pattern(size), OUTPUT, SCRATCH) for size in (MAX_INPUT + 1, MAX_INPUT + 128, 1 << 20))
        cases.append((pattern(MAX_INPUT + 1), b"\xa5" * 63, b"\xc7" * (ARENA_BYTES - 1)))
        for start in range(0, len(cases), 8):
            batch = cases[start:start + 8]
            observed = self.native.call_many([("f0", list(case)) for case in batch], timeout=60)
            self.assertEqual(len(observed), len(batch))
            for original, result in zip(batch, observed):
                result.require_returned()
                self.assertEqual(result.abi_status, 0)
                self.assertEqual(result.value, REFUSED)
                self.assertEqual(result.arguments, list(original))
                type(self).native_calls += 1

    def test_real_unaligned_pointers_preserve_every_guard(self):
        cases = []
        for residue in range(8):
            for length in (0, 1, 111, 112, 127, 128, 129, 259):
                raw = pattern(length)
                cases.append({"input": base64.b64encode(raw).decode(),
                              "residues": [residue, (residue + 3) % 8, (residue + 5) % 8]})
        cases.append({"input": base64.b64encode(pattern(MAX_INPUT)).decode(),
                      "residues": [7, 1, 3]})
        request = {"library": str(self.native.library), "sha256": self.native.artifact_sha256,
                   "cases": cases}
        process = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", UNALIGNED_WORKER],
                                 input=json.dumps(request), capture_output=True, text=True,
                                 timeout=30, check=True)
        self.assertEqual(process.stderr, "")
        observed = json.loads(process.stdout)
        self.assertEqual(observed["artifact_sha256"], self.native.artifact_sha256)
        self.assertEqual(observed["compiler_modules_loaded"], [])
        self.assertEqual(len(observed["cases"]), len(cases))
        for case, result in zip(cases, observed["cases"]):
            raw = base64.b64decode(case["input"], validate=True)
            expected = hashlib.sha512(raw).digest()
            self.assertEqual(result["residues"], case["residues"])
            self.assertEqual(result["value"], 64)
            self.assertEqual(result["abi_status"], 0)
            self.assertEqual(bytes.fromhex(result["output"]), expected + OUTPUT[64:])
            self.assertEqual(bytes.fromhex(result["arena_digest"]), expected)
            for flag in ("guards", "input_unchanged", "arena_message", "arena_gap", "reserved_work_and_tail"):
                self.assertTrue(result[flag], flag)
            type(self).raw_pointer_calls += 1

    def test_backend_is_the_pinned_native_compiler(self):
        receipt = self.native.receipt
        self.assertEqual(receipt["chain_migration"]["backend"], "selfhost")
        self.assertEqual(receipt["exports"], ["f0"])
        self.assertFalse(receipt["claims"]["python_emitter_used"])
        self.assertFalse(receipt["claims"]["fallback_used"])
        self.assertEqual(SOURCE.read_bytes(), self.source_bytes)


if __name__ == "__main__":
    unittest.main()
