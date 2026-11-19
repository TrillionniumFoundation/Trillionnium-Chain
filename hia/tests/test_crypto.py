"""Native SHA-256 and PoN domain framing qualification.

SHA-256 derives from TrillionniumFoundation/Hepta f33d8da316de8fdf27b504371f1a5310997ff548
examples/hia_bootstrap/sha256.hepta, original file SHA256
93e97ac37f91fea4e0fa927f1af3b197bff31fb5f8edd2bfd4e70566fdc23c80.
The public entry changes only module identity and input maximum (1 MiB).
The arena continuation mechanically combines three private views into one
mutbuf, propagates explicit input length, and relocates digest/work addresses.
The added framing entry constructs the original TRNM-PON1 domain bytes in HIA.
No generator, host SHA implementation or Rust fallback enters native product code.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import unittest

from hia.tests.native_support import NativeModule

ROOT = Path(__file__).resolve().parents[2]
SOURCES = ROOT / "hia/src/crypto"
BOUND = 0xfffffffd
INPUT_MAX = 1 << 20
ARENA_INPUT_MAX = 131136
DIGEST_BEGIN = 131136
WORK_BEGIN = 131168
ARENA_BYTES = 132256


def descriptor(tag, parts):
    return (struct.pack("<HH", len(tag), len(parts)) + tag
            + b"".join(struct.pack("<I", len(part)) + part for part in parts))


def original_hash_bytes(tag, parts):
    return (b"TRNM-PON1\0" + struct.pack("<H", len(tag)) + tag
            + b"".join(struct.pack("<I", len(part)) + part for part in parts))


def pattern(length):
    # Nonconstant bytes include every possible byte and do not require random state.
    return bytes((i * 73 + i // 256 + 19) & 255 for i in range(length))


# Actual pointer-offset test child. No language/compiler module or hash oracle is
# used to produce the verdict. The library is captured by SHA into a sealed memfd.
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
    raise ValueError('changed artifact')
fd = os.memfd_create('trnm-hia-unaligned', os.MFD_ALLOW_SEALING)
position = 0
while position < len(binary):
    count = os.write(fd, binary[position:])
    if count <= 0:
        raise OSError('short library capture')
    position += count
fcntl.fcntl(fd, getattr(fcntl, 'F_ADD_SEALS', 1033), 15)
try:
    library = ctypes.CDLL('/proc/self/fd/' + str(fd))
finally:
    os.close(fd)
fn = library.f0
fn.argtypes = [ctypes.c_void_p, ctypes.c_uint64] * 3
fn.restype = ctypes.c_uint64
answers = []
for item in request['cases']:
    raw = base64.b64decode(item['input'], validate=True)
    data = [raw, b'\xa5' * 45, b'\x5a' * 1107]
    copies, args, residues = [], [], []
    for payload, remainder in zip(data, item['remainders']):
        storage = ctypes.create_string_buffer(b'\xc7' * (len(payload) + 32))
        begin = 8 + ((remainder - ctypes.addressof(storage)) % 8)
        address = ctypes.addressof(storage) + begin
        ctypes.memmove(address, payload, len(payload))
        copies.append((storage, begin, len(payload)))
        args.extend((ctypes.c_void_p(address), len(payload)))
        residues.append(address % 8)
    returned = fn(*args)
    after = [storage.raw[begin:begin+length] for storage, begin, length in copies]
    guards = all(storage.raw[:begin] == b'\xc7' * begin
                 and storage.raw[begin+length:-1] == b'\xc7' * (len(storage.raw) - 1 - begin - length)
                 and storage.raw[-1:] == b'\0'
                 for storage, begin, length in copies)
    answers.append({'value': returned & 0xffffffff, 'abi': returned >> 32,
                    'remainders': residues, 'guards': guards,
                    'input_unchanged': after[0] == raw,
                    'output': base64.b64encode(after[1]).decode(),
                    'scratch_tail_unchanged': after[2][1088:] == data[2][1088:],
                    'scratch_unchanged': after[2] == data[2]})
print(json.dumps({'sha256': request['sha256'], 'cases': answers,
                  'compiler_modules_loaded': [name for name in sys.modules if name.startswith('hepta')]}))
"""


class CryptoNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules = {}
        cls.observations = {name: 0 for name in ["sha256", "sha256_arena", "pon_hash"]}
        try:
            for name in cls.observations:
                cls.modules[name] = NativeModule(SOURCES / (name + ".hepta"), byte_exports=("f0",))
        except BaseException:
            for module in cls.modules.values():
                module.close()
            raise

    @classmethod
    def tearDownClass(cls):
        report = {"schema": "trnm.hia.crypto-native-observation.v1", "backend": "selfhost",
                  "calls": cls.observations, "modules": {}}
        for name, module in cls.modules.items():
            report["modules"][name] = {
                "source_sha256": hashlib.sha256(module.source.read_bytes()).hexdigest(),
                "artifact_sha256": module.artifact_sha256,
                "compiler_sha256": module.receipt["compiler_sha256"],
            }
            module.close()
        print(json.dumps(report, sort_keys=True))

    def public_sha_cases(self, inputs):
        rows = list(inputs)
        for start in range(0, len(rows), 16):
            batch = rows[start:start + 16]
            calls = [("f0", [raw, b"\xa5" * 48, b"\x5a" * 1107]) for raw in batch]
            observations = self.modules["sha256"].call_many(calls, timeout=60)
            for raw, observed in zip(batch, observations):
                with self.subTest(length=len(raw), input_sha=hashlib.sha256(raw).hexdigest()):
                    result = observed.require_returned()
                    self.assertEqual(result.value, 32)
                    self.assertEqual(result.arguments[0], raw)
                    self.assertEqual(result.arguments[1], hashlib.sha256(raw).digest() + b"\xa5" * 16)
                    self.assertEqual(result.arguments[2][1088:], b"\x5a" * 19)
                    self.observations["sha256"] += 1

    def test_standard_and_complete_short_length_sha256_vectors(self):
        self.public_sha_cases([b"", b"abc", b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                               b"The quick brown fox jumps over the lazy dog"])
        self.public_sha_cases(pattern(n) for n in range(130))
        self.public_sha_cases(bytes((b,)) for b in range(256))

    def test_sha256_multiblock_and_one_mib_boundary(self):
        self.public_sha_cases(pattern(n) for n in [255, 256, 257, 511, 512, 513, 1023, 1024, 1025,
                                                    4095, 4096, 4097, 65535, 65536, 65537,
                                                    INPUT_MAX - 1, INPUT_MAX])
        # The classic million-'a' vector exercises a different large content family.
        raw = b"a" * 1000000
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
        self.public_sha_cases([raw])

    def test_actual_unaligned_buffers_and_oversized_input_refusal(self):
        cases = [(pattern(length), [shift, (shift + 2) % 8, (shift + 5) % 8], 32)
                 for shift in range(1, 8) for length in [0, 3, 55, 56, 63, 64, 65, 1087]]
        cases.append((pattern(INPUT_MAX + 1), [1, 3, 5], BOUND))
        module = self.modules["sha256"]
        request = {"library": str(module.library), "sha256": module.artifact_sha256,
                   "cases": [{"input": base64.b64encode(raw).decode(), "remainders": residues}
                             for raw, residues, _ in cases]}
        process = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", UNALIGNED_WORKER],
                                 input=json.dumps(request), text=True, capture_output=True,
                                 check=False, timeout=45)
        self.assertEqual(process.returncode, 0, process.stderr)
        observed = json.loads(process.stdout)
        self.assertEqual(observed["sha256"], module.artifact_sha256)
        self.assertEqual(observed["compiler_modules_loaded"], [])
        self.assertEqual(len(observed["cases"]), len(cases))
        for (raw, residues, expected), got in zip(cases, observed["cases"]):
            with self.subTest(length=len(raw), residues=residues):
                self.assertEqual(got["value"], expected)
                self.assertEqual(got["abi"], 0)
                self.assertEqual(got["remainders"], residues)
                self.assertTrue(got["guards"])
                self.assertTrue(got["input_unchanged"])
                self.assertTrue(got["scratch_tail_unchanged"])
                output = base64.b64decode(got["output"], validate=True)
                if expected == 32:
                    self.assertEqual(output, hashlib.sha256(raw).digest() + b"\xa5" * 13)
                else:
                    self.assertEqual(output, b"\xa5" * 45)
                    self.assertTrue(got["scratch_unchanged"])
                self.observations["sha256"] += 1

    def test_sha256_capacity_rejection_is_transactional(self):
        cases = []
        for output_len in [0, 1, 31]:
            cases.append((b"abc", b"\xa5" * output_len, b"\x5a" * 1088))
        for scratch_len in [0, 1, 1087]:
            cases.append((b"abc", b"\xa5" * 32, b"\x5a" * scratch_len))
        observations = self.modules["sha256"].call_many([("f0", list(case)) for case in cases])
        for sent, observed in zip(cases, observations):
            result = observed.require_returned()
            self.assertEqual(result.value, BOUND)
            self.assertEqual(result.arguments, list(sent))
            self.observations["sha256"] += 1

    def test_single_arena_sha_preserves_input_gap_and_guard_tail(self):
        inputs = [pattern(n) for n in [0, 1, 3, 7, 31, 55, 56, 57, 63, 64, 65, 127, 128,
                                        129, 1000, 65535, 131119, ARENA_INPUT_MAX - 1, ARENA_INPUT_MAX]]
        calls = [("f0", [raw, b"\xa5" * 40, b"\x5a" * (ARENA_BYTES + 17)]) for raw in inputs]
        observations = self.modules["sha256_arena"].call_many(calls, timeout=60)
        for raw, observed in zip(inputs, observations):
            with self.subTest(length=len(raw)):
                result = observed.require_returned()
                expected = hashlib.sha256(raw).digest()
                self.assertEqual(result.value, 32)
                self.assertEqual(result.arguments[0], raw)
                self.assertEqual(result.arguments[1], expected + b"\xa5" * 8)
                arena = result.arguments[2]
                self.assertEqual(arena[:len(raw)], raw)
                self.assertEqual(arena[len(raw):DIGEST_BEGIN], b"\x5a" * (DIGEST_BEGIN - len(raw)))
                self.assertEqual(arena[DIGEST_BEGIN:WORK_BEGIN], expected)
                self.assertEqual(arena[ARENA_BYTES:], b"\x5a" * 17)
                self.observations["sha256_arena"] += 1

    def test_single_arena_refuses_overlap_and_short_capacity_before_writes(self):
        cases = [(pattern(ARENA_INPUT_MAX + 1), b"\xa5" * 32, b"\x5a" * ARENA_BYTES),
                 (b"abc", b"\xa5" * 31, b"\x5a" * ARENA_BYTES),
                 (b"abc", b"\xa5" * 32, b"\x5a" * (ARENA_BYTES - 1))]
        observations = self.modules["sha256_arena"].call_many([("f0", list(case)) for case in cases])
        for sent, observed in zip(cases, observations):
            result = observed.require_returned()
            self.assertEqual(result.value, BOUND)
            self.assertEqual(result.arguments, list(sent))
            self.observations["sha256_arena"] += 1

    def pon_cases(self, values):
        values = list(values)
        for start in range(0, len(values), 16):
            batch = values[start:start + 16]
            calls = [("f0", [descriptor(tag, parts), b"\xa5" * 41, b"\x5a" * (ARENA_BYTES + 17)])
                     for tag, parts in batch]
            outputs = self.modules["pon_hash"].call_many(calls, timeout=60)
            for (tag, parts), sent, observed in zip(batch, calls, outputs):
                result = observed.require_returned()
                frame = original_hash_bytes(tag, parts)
                expected = hashlib.sha256(frame).digest()
                self.assertEqual(result.value, 32)
                self.assertEqual(result.arguments[0], sent[1][0])
                self.assertEqual(result.arguments[1], expected + b"\xa5" * 9)
                self.assertEqual(result.arguments[2][:len(frame)], frame)
                self.assertEqual(result.arguments[2][len(frame):DIGEST_BEGIN],
                                 b"\x5a" * (DIGEST_BEGIN - len(frame)))
                self.assertEqual(result.arguments[2][DIGEST_BEGIN:WORK_BEGIN], expected)
                self.assertEqual(result.arguments[2][ARENA_BYTES:], b"\x5a" * 17)
                self.observations["pon_hash"] += 1

    def test_pon_domains_parts_and_exact_framing_against_original_oracle(self):
        path = ROOT / "formal/pon-nakamoto-v1/contract_wire.py"
        spec = importlib.util.spec_from_file_location("trnm_hia_hash_oracle", path)
        oracle = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(oracle)
        cases = [(b"", []), (b"", [b""]), (b"task", [bytes(16384), bytes(16384)]),
                 (b"noise", [bytes(range(32)), b"\0", struct.pack("<I", 127)]),
                 (b"challenge", [(ROOT / "formal/pon-nakamoto-v1/vectors/header.bin").read_bytes()]),
                 (b"block", [pattern(318), pattern(32)]),
                 (b"tx-sign", [pattern(159)]), (b"null\0tag", [b"a", b"b\0c", b""])]
        for tag, parts in cases:
            self.assertEqual(oracle.H(tag, *parts), hashlib.sha256(original_hash_bytes(tag, parts)).digest())
        self.pon_cases(cases)

    def test_pon_length_prefixes_disambiguate_parts(self):
        families = [(b"task", [b"ab", b"c"]), (b"task", [b"a", b"bc"]),
                    (b"task", [b"abc"]), (b"task", [b"", b"abc"]),
                    (b"task", [b"abc", b""]), (b"tasks", [b"abc"])]
        expected = {hashlib.sha256(original_hash_bytes(tag, parts)).digest() for tag, parts in families}
        self.assertEqual(len(expected), len(families))
        self.pon_cases(families)

    def test_pon_full_declared_boundaries(self):
        self.pon_cases([(b"x" * 65535, []), (b"", [b""] * 64),
                        (b"t", [pattern(131119)])])
        # Input is 131128 bytes and exact constructed frame reaches 131136.
        self.assertEqual(len(descriptor(b"t", [pattern(131119)])), 131128)

    def test_pon_malformed_descriptor_preserves_entire_outputs(self):
        good = descriptor(b"task", [b"first", b"second"])
        cases = [(good[:n], 1) for n in range(len(good))]
        cases += [(good + b"\0", 1), (struct.pack("<HH", 0, 65) + b"\0" * 260, 4),
                  (struct.pack("<HH", 65535, 0), 1),
                  (struct.pack("<HHI", 0, 1, 0xffffffff), 1),
                  (descriptor(b"t", [b"x" * 131120]), BOUND)]
        for start in range(0, len(cases), 8):
            batch = cases[start:start + 8]
            calls = [("f0", [raw, b"\xa5" * 32, b"\x5a" * ARENA_BYTES]) for raw, _ in batch]
            outputs = self.modules["pon_hash"].call_many(calls)
            for (raw, expected), sent, observed in zip(batch, calls, outputs):
                result = observed.require_returned()
                self.assertEqual(result.value, expected)
                self.assertEqual(result.arguments, sent[1])
                self.observations["pon_hash"] += 1


if __name__ == "__main__":
    unittest.main()
