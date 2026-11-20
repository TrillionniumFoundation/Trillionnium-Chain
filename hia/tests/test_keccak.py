"""Pinned selfhost Keccak-f[1600], SHA3 and SHAKE execution tests.

The product algorithm is authored directly in keccak_stream.hepta from NIST
FIPS 202 (August 2015), sections 3--6 and Appendix B.2:
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

The fixture contains every vector in the six official byte-oriented ShortMsg
files and both VariableOut files. Its archive URLs, byte counts, SHA256s and
original member SHA256s are retained in the fixture. These tests do not confer
CAVP/FIPS validation, constant-time qualification, ML-DSA, identity, or retirement.

The product f0 entry has the pinned private-buffer ABI. A request is the
24-byte header TRNMK3Q1, operation u8, mode u8, six reserved zero bytes,
output count LE64, then byte-aligned payload. Operations 0..6 are one-shot,
initialize, update, finalize, squeeze, clear and raw permutation. Modes 1..6
are SHA3-224/256/384/512 and SHAKE128/256. Total request extent is <= 1 MiB;
therefore this envelope permits <= 1 MiB-24 payload bytes per update.
Output and scratch borrowed extents also use the existing 1 MiB ABI ceiling.

Scratch [0,232) is a private, caller-owned incremental context: TRNMK3C1,
mode u8, phase u8, six zero bytes, position LE64, remaining digest bytes LE64,
and 200 state bytes in little-endian x+5*y lane order. It is not persisted or
authenticated, and importing arbitrary state does not establish provenance.
Phase 0 absorbs; phase 1 squeezes. Fixed digests cannot extend beyond their
remaining bytes, and require position+remaining=digest_size. SHAKE may stream
across any number of bounded calls. Clear and successful one-shot erase all
232 context bytes. Every trailing byte is preserved. Invalid public requests
return 0xfffffffd before writing caller bytes; an unexpected internal helper
result in the one-shot chain returns 0xfffffffc and cannot become success.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import unittest

from hia.tests.native_support import NativeModule

SOURCE = Path(__file__).resolve().parents[1] / "src/crypto/keccak_stream.hepta"
VECTORS = Path(__file__).resolve().parent / "vectors/keccak_fips202.json"
VECTOR_SHA256 = "cbaf383ab66719229c7ec6890a7aa7502a535e8c0f81b8d8741b8d6a75e5cace"
FIXTURE_COUNTS = {
    "SHA3_224ShortMsg.rsp": 145, "SHA3_256ShortMsg.rsp": 137,
    "SHA3_384ShortMsg.rsp": 105, "SHA3_512ShortMsg.rsp": 73,
    "SHAKE128ShortMsg.rsp": 337, "SHAKE256ShortMsg.rsp": 273,
    "SHAKE128VariableOut.rsp": 1126, "SHAKE256VariableOut.rsp": 1246,
}
RATES = {1: 144, 2: 136, 3: 104, 4: 72, 5: 168, 6: 136}
DIGESTS = {1: 28, 2: 32, 3: 48, 4: 64, 5: 0, 6: 0}
HASHES = {1: hashlib.sha3_224, 2: hashlib.sha3_256, 3: hashlib.sha3_384,
          4: hashlib.sha3_512, 5: hashlib.shake_128, 6: hashlib.shake_256}
MAX_EXTENT = 1 << 20
MAX_PAYLOAD = MAX_EXTENT - 24
CONTEXT_BYTES = 232
SCRATCH = b"\xc7" * 263
REFUSED = 0xfffffffd


def request(operation, mode=0, count=0, payload=b""):
    return b"TRNMK3Q1" + bytes((operation, mode)) + bytes(6) + count.to_bytes(8, "little") + payload


def pattern(length):
    return bytes((i * 79 + i // 251 + 17) & 255 for i in range(length))


def digest(mode, payload, count):
    h = HASHES[mode](payload)
    return h.digest() if mode <= 4 else h.digest(count)


def patch(data, offset, replacement):
    return data[:offset] + replacement + data[offset + len(replacement):]


def independent_permutation(raw):
    """Separate array-based FIPS 202 permutation, used only as a test oracle."""
    if len(raw) != 200:
        raise ValueError("A Keccak-f[1600] state has exactly 200 bytes")
    a = [int.from_bytes(raw[i:i + 8], "little") for i in range(0, 200, 8)]
    mask = (1 << 64) - 1
    rotations = [0] * 25
    x, y = 1, 0
    for t in range(24):
        rotations[x + 5 * y] = ((t + 1) * (t + 2) // 2) % 64
        x, y = y, (2 * x + 3 * y) % 5
    # Independent bit-register calculation of Algorithms 5 and 6.
    def rc(t):
        register = [1] + [0] * 7
        for _ in range(t % 255):
            register.insert(0, 0)
            for index in (0, 4, 5, 6):
                register[index] ^= register[8]
            register.pop()
        return register[0]
    def rotate(word, count):
        return ((word << count) | (word >> ((64 - count) % 64))) & mask
    for round_index in range(24):
        columns = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20]
                   for x in range(5)]
        deltas = [columns[(x - 1) % 5] ^ rotate(columns[(x + 1) % 5], 1)
                  for x in range(5)]
        b = [0] * 25
        for y in range(5):
            for x in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = rotate(a[x + 5 * y] ^ deltas[x],
                                                        rotations[x + 5 * y])
        a = [b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
             for y in range(5) for x in range(5)]
        constant = sum(rc(j + 7 * round_index) << ((1 << j) - 1) for j in range(7))
        a[0] ^= constant
    return b"".join(word.to_bytes(8, "little") for word in a)


# This child uses the exact sealed native library and real offset pointers.
# It contains neither a hash oracle nor a compiler/emitter. The same scratch
# allocation remains owned throughout each history.
SEQUENCE_WORKER = r"""
import base64, ctypes, fcntl, hashlib, json, os, resource, sys
req = json.load(sys.stdin)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
resource.setrlimit(resource.RLIMIT_AS, (256 << 20, 256 << 20))
resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(4, 0, 0, 0, 0):
    raise OSError(ctypes.get_errno(), "disable core dumps")
with open(req["library"], "rb") as stream:
    image = stream.read()
if hashlib.sha256(image).hexdigest() != req["sha256"]:
    raise ValueError("changed native artifact")
fd = os.memfd_create("trnm-hia-keccak-sequence", os.MFD_ALLOW_SEALING)
try:
    position = 0
    while position < len(image):
        written = os.write(fd, image[position:])
        if written <= 0:
            raise OSError("short artifact capture")
        position += written
    fcntl.fcntl(fd, getattr(fcntl, "F_ADD_SEALS", 1033), 15)
    library = ctypes.CDLL("/proc/self/fd/" + str(fd))
finally:
    os.close(fd)
entry = library.f0
entry.argtypes = [ctypes.c_void_p, ctypes.c_uint64] * 3
entry.restype = ctypes.c_uint64

def allocate(data, residue):
    storage = ctypes.create_string_buffer(b"\x69" * (len(data) + 48))
    begin = 16 + ((residue - ctypes.addressof(storage)) % 8)
    pointer = ctypes.addressof(storage) + begin
    ctypes.memmove(pointer, data, len(data))
    return storage, begin, len(data), pointer

def contents(item):
    return item[0].raw[item[1]:item[1] + item[2]]

def guarded(item):
    storage, begin, size, _ = item
    return (storage.raw[:begin] == b"\x69" * begin
            and storage.raw[begin + size:-1] == b"\x69" * (len(storage.raw) - begin - size - 1)
            and storage.raw[-1:] == b"\0")

histories = []
for case in req["cases"]:
    residues = case.get("residues", [0, 3, 5])
    scratch = allocate(bytes.fromhex(case["context"]), residues[2])
    observations = []
    for action in case["actions"]:
        raw = base64.b64decode(action["request"], validate=True)
        before_output = bytes.fromhex(action["output"])
        incoming = allocate(raw, residues[0])
        outgoing = allocate(before_output, residues[1])
        before_context = contents(scratch)
        result = entry(incoming[3], incoming[2], outgoing[3], outgoing[2],
                       scratch[3], scratch[2])
        observations.append({
            "value": result & 0xffffffff, "abi_status": result >> 32,
            "input_unchanged": contents(incoming) == raw,
            "guards": all(guarded(x) for x in (incoming, outgoing, scratch)),
            "residues": [x[3] % 8 for x in (incoming, outgoing, scratch)],
            "output_before": before_output.hex(), "output": contents(outgoing).hex(),
            "context_before": before_context.hex(), "context": contents(scratch).hex(),
        })
    histories.append(observations)
print(json.dumps({"artifact_sha256": req["sha256"], "histories": histories,
                  "compiler_modules_loaded": [x for x in sys.modules if x.startswith("hepta")]}))
"""


class KeccakNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source_before = SOURCE.read_bytes()
        cls.test_before = Path(__file__).read_bytes()
        fixture = VECTORS.read_bytes()
        if hashlib.sha256(fixture).hexdigest() != VECTOR_SHA256:
            raise AssertionError("Official vector fixture identity changed")
        cls.vectors = json.loads(fixture)
        counts = {f["member"]: len(f["vectors"]) for f in cls.vectors["files"]}
        if counts != FIXTURE_COUNTS or sum(counts.values()) != 3442:
            raise AssertionError("Incomplete official byte-vector roster")
        cls.native = NativeModule(SOURCE, byte_exports=("f0",), backend="selfhost")
        cls.native_calls = cls.native_attempts = cls.raw_pointer_calls = cls.official_vectors = 0
        cls.evidence = None
        cls.evidence_path = None
        destination = os.environ.get("TRNM_HIA_KECCAK_EVIDENCE_DIR")
        if destination:
            cls.evidence_path = Path(destination).resolve()
            cls.evidence_path.mkdir(parents=True, exist_ok=False)
            (cls.evidence_path / "module.so").write_bytes(cls.native.library.read_bytes())
            (cls.evidence_path / "source.hepta").write_bytes(cls.source_before)
            (cls.evidence_path / "test-source.py").write_bytes(cls.test_before)
            (cls.evidence_path / "build.json").write_text(
                json.dumps(cls.native.receipt, sort_keys=True, indent=2) + "\n")
            cls.evidence = (cls.evidence_path / "observations.jsonl").open("x")

    @classmethod
    def tearDownClass(cls):
        try:
            unchanged = SOURCE.read_bytes() == cls.source_before and Path(__file__).read_bytes() == cls.test_before
            report = {
                "schema": "trnm.hia.keccak-native-observation.v1", "backend": "selfhost",
                "shared_runner_calls": cls.native_calls, "shared_runner_attempts": cls.native_attempts,
                "raw_pointer_calls": cls.raw_pointer_calls,
                "official_byte_vectors": cls.official_vectors,
                "source_sha256": hashlib.sha256(cls.source_before).hexdigest(),
                "test_sha256": hashlib.sha256(cls.test_before).hexdigest(),
                "fixture_sha256": VECTOR_SHA256, "source_unchanged": unchanged,
                "artifact_sha256": cls.native.artifact_sha256,
                "compiler_sha256": cls.native.receipt["compiler_sha256"],
                "claims": {"cavp_validation": False, "fips_validation": False,
                           "constant_time_qualified": False, "ml_dsa_complete": False,
                           "identity_qualified": False, "original_retired": False},
            }
            if cls.evidence_path:
                (cls.evidence_path / "observation-summary.json").write_text(
                    json.dumps(report, sort_keys=True, indent=2) + "\n")
            print(json.dumps(report, sort_keys=True))
            if not unchanged:
                raise AssertionError("Source changed during native execution")
        finally:
            if cls.evidence:
                cls.evidence.close()
            cls.native.close()

    def observe(self, cases, batch_size=16):
        cases = list(cases)
        answers = []
        for begin in range(0, len(cases), batch_size):
            batch = cases[begin:begin + batch_size]
            type(self).native_attempts += len(batch)
            observed = self.native.call_many([("f0", list(args)) for args in batch], timeout=30)
            self.assertEqual(len(observed), len(batch))
            for original, result in zip(batch, observed):
                if self.evidence:
                    self.evidence.write(json.dumps({
                        "test": self.id(), "call": type(self).native_calls,
                        "sent": [base64.b64encode(x).decode() for x in original],
                        "result": {"status": result.status, "returncode": result.returncode,
                                   "value": result.value, "abi_status": result.abi_status,
                                   "arguments": None if result.arguments is None else
                                       [base64.b64encode(x).decode() for x in result.arguments],
                                   "stderr": result.stderr},
                    }, sort_keys=True) + "\n")
                result.require_returned()
                type(self).native_calls += 1
                self.assertEqual(result.abi_status, 0)
                answers.append(result)
        return answers

    def check_oneshots(self, rows, batch_size=16):
        rows = list(rows)
        cases = [(request(0, mode, len(expected), message),
                  b"\xa5" * min(MAX_EXTENT, len(expected) + 17), SCRATCH)
                 for mode, message, expected in rows]
        for original, (_, _, expected), result in zip(cases, rows, self.observe(cases, batch_size)):
            self.assertEqual(result.value, len(expected))
            self.assertEqual(result.arguments[0], original[0])
            self.assertEqual(result.arguments[1], expected + original[1][len(expected):])
            self.assertEqual(result.arguments[2], bytes(CONTEXT_BYTES) + SCRATCH[CONTEXT_BYTES:])

    def check_refusals(self, cases):
        cases = list(cases)
        for original, result in zip(cases, self.observe(cases)):
            self.assertEqual(result.value, REFUSED)
            self.assertEqual(result.arguments, list(original))

    def sequences(self, cases):
        cases = list(cases)
        incoming = {"library": str(self.native.library), "sha256": self.native.artifact_sha256,
                    "cases": cases}
        result = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", SEQUENCE_WORKER],
                                input=json.dumps(incoming), capture_output=True, text=True,
                                timeout=30, check=False)
        if self.evidence:
            self.evidence.write(json.dumps({"test": self.id(), "sequence_request": incoming,
                                           "returncode": result.returncode, "stdout": result.stdout,
                                           "stderr": result.stderr}, sort_keys=True) + "\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        decoded = json.loads(result.stdout)
        self.assertEqual(decoded["artifact_sha256"], self.native.artifact_sha256)
        self.assertEqual(decoded["compiler_modules_loaded"], [])
        self.assertEqual(len(decoded["histories"]), len(cases))
        for case, history in zip(cases, decoded["histories"]):
            self.assertEqual(len(history), len(case["actions"]))
            previous = bytes.fromhex(case["context"])
            for action, observation in zip(case["actions"], history):
                self.assertTrue(observation["guards"])
                self.assertTrue(observation["input_unchanged"])
                self.assertEqual(observation["residues"], case.get("residues", [0, 3, 5]))
                self.assertEqual(bytes.fromhex(observation["context_before"]), previous)
                self.assertEqual(observation["output_before"], action["output"])
                previous = bytes.fromhex(observation["context"])
                type(self).raw_pointer_calls += 1
        return decoded["histories"]

    @staticmethod
    def action(req, capacity=81):
        return {"request": base64.b64encode(req).decode(), "output": (b"\xa5" * capacity).hex()}

    def context(self, mode, finalized=False):
        init = self.observe([(request(1, mode), b"\xa5" * 81, SCRATCH)])[0]
        self.assertEqual(init.value, 0)
        ctx = init.arguments[2]
        self.assertEqual(ctx[:8], b"TRNMK3C1")
        self.assertEqual(ctx[8:16], bytes((mode, 0)) + bytes(6))
        self.assertEqual(ctx[16:24], bytes(8))
        self.assertEqual(ctx[24:32], DIGESTS[mode].to_bytes(8, "little"))
        self.assertEqual(ctx[32:232], bytes(200))
        self.assertEqual(ctx[232:], SCRATCH[232:])
        if finalized:
            final = self.observe([(request(3), b"\xa5" * 81, ctx)])[0]
            self.assertEqual(final.value, 0)
            ctx = final.arguments[2]
        return ctx

    def test_01_empty_and_abc_all_six_modes(self):
        rows = []
        for mode in RATES:
            for message in (b"", b"abc"):
                count = DIGESTS[mode] or 64
                rows.append((mode, message, digest(mode, message, count)))
        self.check_oneshots(rows)

    def test_02_all_3442_official_byte_vectors(self):
        rows = []
        for file in self.vectors["files"]:
            for index, vector in enumerate(file["vectors"]):
                self.assertEqual(index, vector["index"])
                message = bytes.fromhex(vector["input_hex"])
                expected = bytes.fromhex(vector["output_hex"])
                self.assertEqual(len(message) * 8, vector["input_bits"])
                self.assertEqual(len(expected) * 8, vector["output_bits"])
                self.assertEqual(digest(file["mode"], message, len(expected)), expected)
                rows.append((file["mode"], message, expected))
        self.assertEqual(len(rows), 3442)
        self.check_oneshots(rows)
        type(self).official_vectors += len(rows)

    def test_03_every_length_and_multiblock_padding_boundaries(self):
        rows = []
        for mode, rate in RATES.items():
            lengths = set(range(2 * rate + 2))
            lengths.update(block * rate + offset
                           for block in (3, 7, 8, 15, 16, 31, 32)
                           for offset in (-1, 0, 1))
            for length in sorted(lengths):
                message = pattern(length)
                count = DIGESTS[mode] or (3 * rate + length % 19)
                rows.append((mode, message, digest(mode, message, count)))
        self.check_oneshots(rows)

    def test_04_arbitrary_states_and_all_1600_single_state_bits(self):
        random_source = random.Random(0x2021600)
        states = [bytes(200), bytes([255]) * 200, bytes(range(200)), pattern(200)]
        states.extend(random_source.randbytes(200) for _ in range(24))
        states.extend((1 << bit).to_bytes(200, "little") for bit in range(1600))
        for start in range(0, len(states), 16):
            batch = states[start:start + 16]
            cases = [(request(6), b"\xa5" * 81, SCRATCH[:32] + raw + SCRATCH[232:])
                     for raw in batch]
            for raw, original, result in zip(batch, cases, self.observe(cases)):
                self.assertEqual(result.value, 0)
                self.assertEqual(result.arguments[0], original[0])
                self.assertEqual(result.arguments[1], original[1])
                self.assertEqual(result.arguments[2],
                                 original[2][:32] + independent_permutation(raw) + original[2][232:])

    def test_05_request_and_capacity_refusals_write_nothing(self):
        good = request(0, 2, 32, b"abc")
        frames = [good[:n] for n in range(24)]
        frames += [patch(good, i, bytes([good[i] ^ 1])) for i in range(8)]
        frames += [patch(good, i, b"\x01") for i in range(10, 16)]
        frames += [request(op, 2, 32, b"abc") for op in (7, 255)]
        frames += [request(op, mode, 0 if op else 32, b"" if op else b"abc")
                   for op in (0, 1) for mode in (0, 7, 255)]
        frames += [request(0, 5, count, b"abc") for count in (MAX_EXTENT + 1, (1 << 64) - 1)]
        frames += [request(op, 0 if op != 1 else 2, 0, b"x") for op in (1, 3, 4, 5, 6)]
        frames += [request(op, 1) for op in (2, 3, 4, 5, 6)]
        frames += [request(op, 2 if op == 1 else 0, 1) for op in (1, 2, 3, 5, 6)]
        for mode in range(1, 5):
            frames += [request(0, mode, count, b"abc")
                       for count in (0, DIGESTS[mode] - 1, DIGESTS[mode] + 1)]
        cases = [(raw, b"\xa5" * 81, SCRATCH) for raw in frames]
        cases += [(good, b"\xa5" * n, SCRATCH) for n in (0, 1, 7, 31)]
        cases += [(good, b"\xa5" * 81, b"\xc7" * n) for n in (0, 1, 31, 32, 199, 200, 231)]
        self.check_refusals(cases)

    def test_06_context_phases_and_canonical_headers_refuse_before_write(self):
        cases = [(request(op, count=0), b"\xa5" * 81, SCRATCH) for op in (2, 3, 4)]
        for mode, rate in RATES.items():
            absorbing = self.context(mode)
            mutations = [patch(absorbing, i, bytes([absorbing[i] ^ 1])) for i in range(8)]
            mutations += [patch(absorbing, i, b"\x01") for i in range(10, 16)]
            mutations += [patch(absorbing, 8, bytes([value])) for value in (0, 7, 255)]
            mutations += [patch(absorbing, 9, b"\x02")]
            mutations += [patch(absorbing, 16, value.to_bytes(8, "little"))
                          for value in (rate, rate + 1, (1 << 64) - 1)]
            mutations += [patch(absorbing, 24, (DIGESTS[mode] + 1).to_bytes(8, "little"))]
            cases += [(request(2, payload=b"x"), b"\xa5" * 81, ctx) for ctx in mutations]
            cases.append((request(4, count=0), b"\xa5" * 81, absorbing))
            finalized = self.context(mode, finalized=True)
            cases += [(request(op), b"\xa5" * 81, finalized) for op in (2, 3)]
            cases += [(request(4, count=0), b"\xa5" * 81,
                       patch(finalized, 16, value.to_bytes(8, "little")))
                      for value in (rate + 1, (1 << 64) - 1)]
            cases.append((request(4, count=0), b"\xa5" * 81,
                          patch(finalized, 24, (DIGESTS[mode] + 1).to_bytes(8, "little"))))
            if mode <= 4:
                for pos, remaining in ((1, DIGESTS[mode]), (0, DIGESTS[mode] - 1),
                                       (rate, DIGESTS[mode]), (DIGESTS[mode] + 1, 0)):
                    bad = patch(patch(finalized, 16, pos.to_bytes(8, "little")),
                                24, remaining.to_bytes(8, "little"))
                    cases.append((request(4, count=0), b"\xa5" * 81, bad))
                cases.append((request(4, count=DIGESTS[mode] + 1), b"\xa5" * 81, finalized))
        self.check_refusals(cases)

    def test_07_incremental_absorb_finalize_squeeze_clear_and_unaligned_pointers(self):
        cases, descriptions = [], []
        for mode, rate in RATES.items():
            for length in (0, 1, rate - 1, rate, rate + 1, 2 * rate, 2 * rate + 1, 4097):
                message = pattern(length)
                actions = [self.action(request(1, mode))]
                expected_values = [0]
                operations = [(1, 0)]
                position = 0
                chunks = (0, 1, 7, rate - 1, 0, rate, rate + 1, 31)
                step = 0
                while position < len(message) or step == 0:
                    n = min(chunks[step % len(chunks)], len(message) - position)
                    actions.append(self.action(request(2, payload=message[position:position + n])))
                    expected_values.append(n)
                    operations.append((2, n))
                    position += n
                    step += 1
                actions.append(self.action(request(3)))
                expected_values.append(0)
                operations.append((3, 0))
                output_chunks = ([0, 1, DIGESTS[mode] - 2, 0, 1, 0] if mode <= 4 else
                                 [0, 1, rate - 1, 0, rate, 1, rate + 1, 7])
                for count in output_chunks:
                    actions.append(self.action(request(4, count=count), count + 17))
                    expected_values.append(count)
                    operations.append((4, count))
                actions.append(self.action(request(5)))
                expected_values.append(0)
                operations.append((5, 0))
                residue = len(cases) % 8
                cases.append({"context": SCRATCH.hex(), "actions": actions,
                              "residues": [residue, (residue + 3) % 8, (residue + 5) % 8]})
                descriptions.append((mode, message, output_chunks, expected_values, operations))
        for start in range(0, len(cases), 8):
            observed = self.sequences(cases[start:start + 8])
            for history, description in zip(observed, descriptions[start:start + 8]):
                mode, message, output_chunks, expected_values, operations = description
                absorbed = produced = 0
                chunks = []
                for row, value, (operation, n) in zip(history, expected_values, operations):
                    self.assertEqual(row["abi_status"], 0)
                    self.assertEqual(row["value"], value)
                    context = bytes.fromhex(row["context"])
                    self.assertEqual(context[232:], SCRATCH[232:])
                    output = bytes.fromhex(row["output"])
                    before = bytes.fromhex(row["output_before"])
                    if operation == 4:
                        chunks.append(output[:n])
                        self.assertEqual(output[n:], before[n:])
                        produced += n
                    else:
                        self.assertEqual(output, before)
                    if operation == 5:
                        self.assertEqual(context[:232], bytes(232))
                        continue
                    self.assertEqual(context[:8], b"TRNMK3C1")
                    self.assertEqual(context[8], mode)
                    self.assertEqual(context[10:16], bytes(6))
                    if operation == 2:
                        absorbed += n
                    if operation in (1, 2):
                        self.assertEqual(context[9], 0)
                        self.assertEqual(int.from_bytes(context[16:24], "little"), absorbed % RATES[mode])
                        self.assertEqual(int.from_bytes(context[24:32], "little"), DIGESTS[mode])
                    else:
                        self.assertEqual(context[9], 1)
                        pos = ((produced - 1) % RATES[mode] + 1) if produced else 0
                        self.assertEqual(int.from_bytes(context[16:24], "little"), pos)
                        remaining = DIGESTS[mode] - produced if mode <= 4 else 0
                        self.assertEqual(int.from_bytes(context[24:32], "little"), remaining)
                self.assertEqual(b"".join(chunks), digest(mode, message, sum(output_chunks)))

    def test_08_input_envelope_maximum_and_beyond_are_distinct(self):
        rows = []
        for mode in RATES:
            for length in (MAX_PAYLOAD - 1, MAX_PAYLOAD):
                message = pattern(length)
                rows.append((mode, message, digest(mode, message, DIGESTS[mode] or 64)))
        self.check_oneshots(rows, batch_size=1)
        # Direct owned pointers exercise the actual byte ABI on extents which
        # NativeModule intentionally refuses to send. No borrowed pointer is fake.
        cases = [{"context": SCRATCH.hex(),
                  "actions": [self.action(request(0, mode, DIGESTS[mode] or 64,
                                                  pattern(MAX_PAYLOAD + 1)))]}
                 for mode in RATES]
        for history in self.sequences(cases):
            self.assertEqual(len(history), 1)
            row = history[0]
            self.assertTrue(row["abi_status"] != 0 or row["value"] == REFUSED)
            self.assertEqual(row["context"], row["context_before"])
            self.assertEqual(row["output"], row["output_before"])

    def test_09_xof_output_capacity_and_streams_exceeding_one_mib(self):
        rows = []
        for mode in (5, 6):
            for count in (0, 1, RATES[mode] - 1, RATES[mode], RATES[mode] + 1,
                          65535, 65536, MAX_EXTENT - 1, MAX_EXTENT):
                rows.append((mode, b"abc", digest(mode, b"abc", count)))
        self.check_oneshots(rows, batch_size=1)
        for mode in (5, 6):
            parts = [pattern((1 << 19) - 24), pattern((1 << 19) - 23), pattern(32769)]
            output_chunks = [1 << 19, 1 << 19, 257]
            actions = [self.action(request(1, mode))]
            actions += [self.action(request(2, payload=part)) for part in parts]
            actions.append(self.action(request(3)))
            actions += [self.action(request(4, count=count), count) for count in output_chunks]
            actions.append(self.action(request(5)))
            history = self.sequences([{"context": SCRATCH.hex(), "actions": actions}])[0]
            expected_values = [0] + [len(part) for part in parts] + [0] + output_chunks + [0]
            for row, value in zip(history, expected_values):
                self.assertEqual(row["abi_status"], 0)
                self.assertEqual(row["value"], value)
                self.assertEqual(bytes.fromhex(row["context"])[232:], SCRATCH[232:])
            produced = b"".join(bytes.fromhex(row["output"]) for row in history[5:8])
            self.assertEqual(len(produced), sum(output_chunks))
            self.assertGreater(len(b"".join(parts)), MAX_EXTENT)
            self.assertGreater(len(produced), MAX_EXTENT)
            self.assertEqual(produced, digest(mode, b"".join(parts), len(produced)))
            self.assertEqual(bytes.fromhex(history[-1]["context"]), bytes(232) + SCRATCH[232:])

    def test_10_clear_and_reinitialize_invalid_state_without_touching_tails(self):
        cases = []
        for residue in range(8):
            actions = [self.action(request(5)), self.action(request(1, 6)),
                       self.action(request(2, payload=b"abc")), self.action(request(3)),
                       self.action(request(4, count=64)), self.action(request(5)),
                       self.action(request(1, 2)), self.action(request(3)),
                       self.action(request(4, count=32)), self.action(request(4, count=1))]
            cases.append({"context": SCRATCH.hex(), "actions": actions,
                          "residues": [residue, (residue + 1) % 8, (residue + 7) % 8]})
        for history in self.sequences(cases):
            for index, row in enumerate(history):
                self.assertEqual(row["abi_status"], 0)
                self.assertEqual(bytes.fromhex(row["context"])[232:], SCRATCH[232:])
                if index == 9:
                    self.assertEqual(row["value"], REFUSED)
                    self.assertEqual(row["output"], row["output_before"])
                    self.assertEqual(row["context"], row["context_before"])
                else:
                    self.assertEqual(row["value"], {2: 3, 4: 64, 8: 32}.get(index, 0))
            for index in (0, 5):
                self.assertEqual(bytes.fromhex(history[index]["context"])[:232], bytes(232))
            self.assertEqual(bytes.fromhex(history[4]["output"])[:64], hashlib.shake_256(b"abc").digest(64))
            self.assertEqual(bytes.fromhex(history[8]["output"])[:32], hashlib.sha3_256(b"").digest())

    def test_11_backend_is_pinned_selfhost_and_source_remains_exact(self):
        receipt = self.native.receipt
        self.assertEqual(receipt["chain_migration"]["backend"], "selfhost")
        self.assertEqual(receipt["exports"], ["f0"])
        self.assertFalse(receipt["claims"]["python_emitter_used"])
        self.assertFalse(receipt["claims"]["fallback_used"])
        self.assertEqual(SOURCE.read_bytes(), self.source_before)
        self.assertEqual(hashlib.sha256(VECTORS.read_bytes()).hexdigest(), VECTOR_SHA256)


if __name__ == "__main__":
    unittest.main()
