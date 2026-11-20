"""Native ML-DSA polynomial arithmetic, with independent evaluation oracles.

FIPS 204 (2024), Algorithms 41 and 42, q=8380417, n=256, zeta=1753:
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
The NTT oracle evaluates the polynomial once at each root
zeta**(2*BitRev8(i)+1).

This is an arithmetic prerequisite, not an ML-DSA signer/verifier. There is
no CAVP/FIPS certification, constant-time, private-key, Node authority or
retirement claim. All polynomial coefficients use canonical LE32 residues.
The product source uses bounded u64 modular arithmetic, not Montgomery form.

The 16-byte TRNMDPQ1 header contains operation u8 at 8 and seven zero bytes.
Operations 0/1 take one 1024-byte polynomial (NTT/inverse); 2/3/4/5 take two
(pointwise/add/subtract/negacyclic product). The output is 1024 bytes. Scratch
has at least 2048 bytes; success clears exactly that prefix. Input is immutable,
and output/scratch tails remain unchanged. Every borrowed extent is <=1 MiB.
Malformed public requests return 0xfffffffd before any caller write. A trap
after valid-request admission does not have a transactional rollback claim.
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

SOURCE = Path(__file__).resolve().parents[1] / "src/crypto/ml_dsa_poly.hepta"
Q, N, ZETA, INV_N = 8380417, 256, 1753, 8347681
REFUSED = 0xfffffffd
MAX_EXTENT = 1 << 20
SCRATCH_BYTES = 2048
SCRATCH = b"\xc7" * 2081
OUTPUT = b"\xa5" * 1051
ZERO = [0] * N


def bit_reverse_8(value):
    return int(f"{value:08b}"[::-1], 2)


ROOT_EXPONENTS = [2 * bit_reverse_8(i) + 1 for i in range(N)]
ZETA_POWERS = [pow(ZETA, i, Q) for i in range(512)]
ROOTS = [ZETA_POWERS[e] for e in ROOT_EXPONENTS]


def encode(poly):
    if len(poly) != N:
        raise ValueError("A polynomial has exactly 256 coefficients")
    return b"".join(int(value).to_bytes(4, "little") for value in poly)


def decode(data):
    if len(data) != 1024:
        raise ValueError("A polynomial has exactly 1024 bytes")
    return [int.from_bytes(data[i:i + 4], "little") for i in range(0, 1024, 4)]


def request(operation, first, second=None):
    return b"TRNMDPQ1" + bytes((operation,)) + bytes(7) + encode(first) + (
        b"" if second is None else encode(second))


def polynomial_evaluation(poly):
    # Horner evaluation has no staged butterflies or product implementation.
    result = []
    for root in ROOTS:
        value = 0
        for coefficient in reversed(poly):
            value = (value * root + coefficient) % Q
        result.append(value)
    return result


def inverse_evaluation(values):
    # Full inverse evaluation matrix; no forward or inverse NTT code is used.
    return [sum(value * ZETA_POWERS[(-j * exponent) % 512]
                for value, exponent in zip(values, ROOT_EXPONENTS)) * INV_N % Q
            for j in range(N)]


def schoolbook(a, b):
    # Ordinary quadratic convolution followed by x**256 == -1.
    out = [0] * 512
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            out[i + j] += x * y
    return [(out[i] - out[i + N]) % Q for i in range(N)]


def patch(data, offset, replacement):
    return data[:offset] + replacement + data[offset + len(replacement):]


RAW_WORKER = r"""
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
fd = os.memfd_create("trnm-hia-ml-dsa-polynomial", os.MFD_ALLOW_SEALING)
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


class MlDsaPolynomialNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source_before = SOURCE.read_bytes()
        cls.test_before = Path(__file__).read_bytes()
        cls.native = NativeModule(SOURCE, byte_exports=("f0",), backend="selfhost")
        cls.native_calls = cls.native_attempts = cls.raw_pointer_calls = 0
        cls.evidence = cls.evidence_path = None
        destination = os.environ.get("TRNM_HIA_MLDSA_POLY_EVIDENCE_DIR")
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
            unchanged = (SOURCE.read_bytes() == cls.source_before
                         and Path(__file__).read_bytes() == cls.test_before)
            report = {
                "schema": "trnm.hia.ml-dsa-polynomial-native-observation.v1",
                "backend": "selfhost", "shared_runner_calls": cls.native_calls,
                "shared_runner_attempts": cls.native_attempts,
                "raw_pointer_calls": cls.raw_pointer_calls,
                "source_sha256": hashlib.sha256(cls.source_before).hexdigest(),
                "test_sha256": hashlib.sha256(cls.test_before).hexdigest(),
                "source_unchanged": unchanged,
                "artifact_sha256": cls.native.artifact_sha256,
                "compiler_sha256": cls.native.receipt["compiler_sha256"],
                "claims": {"ml_dsa_complete": False, "constant_time_qualified": False,
                           "cavp_validation": False, "fips_validation": False,
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

    def observe(self, cases, batch_size=32):
        cases = list(cases)
        answers = []
        for begin in range(0, len(cases), batch_size):
            batch = cases[begin:begin + batch_size]
            type(self).native_attempts += len(batch)
            actual = self.native.call_many([("f0", list(case)) for case in batch], timeout=30)
            self.assertEqual(len(actual), len(batch))
            for sent, result in zip(batch, actual):
                if self.evidence:
                    self.evidence.write(json.dumps({
                        "test": self.id(), "call": type(self).native_calls,
                        "sent": [base64.b64encode(x).decode() for x in sent],
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

    def successful(self, rows):
        rows = list(rows)
        cases = [(req, OUTPUT, SCRATCH) for req, _ in rows]
        answers = self.observe(cases)
        for (req, expected), sent, result in zip(rows, cases, answers):
            self.assertEqual(result.value, 1024)
            self.assertEqual(result.arguments[0], req)
            self.assertEqual(result.arguments[1], encode(expected) + sent[1][1024:])
            self.assertEqual(result.arguments[2], bytes(2048) + sent[2][2048:])
        return [decode(row.arguments[1][:1024]) for row in answers]

    def refusals(self, cases):
        cases = list(cases)
        for sent, result in zip(cases, self.observe(cases)):
            self.assertEqual(result.value, REFUSED)
            self.assertEqual(result.arguments, list(sent))

    def raw_histories(self, cases):
        payload = {"library": str(self.native.library),
                   "sha256": self.native.artifact_sha256, "cases": cases}
        run = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", RAW_WORKER],
                             input=json.dumps(payload), capture_output=True, text=True,
                             timeout=30, check=False)
        if self.evidence:
            self.evidence.write(json.dumps({"test": self.id(), "raw_request": payload,
                                           "returncode": run.returncode, "stdout": run.stdout,
                                           "stderr": run.stderr}, sort_keys=True) + "\n")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stderr, "")
        result = json.loads(run.stdout)
        self.assertEqual(result["artifact_sha256"], self.native.artifact_sha256)
        self.assertEqual(result["compiler_modules_loaded"], [])
        self.assertEqual(len(result["histories"]), len(cases))
        for case, observations in zip(cases, result["histories"]):
            self.assertEqual(len(observations), len(case["actions"]))
            context = bytes.fromhex(case["context"])
            for action, row in zip(case["actions"], observations):
                self.assertTrue(row["guards"])
                self.assertTrue(row["input_unchanged"])
                self.assertEqual(row["residues"], case.get("residues", [0, 3, 5]))
                self.assertEqual(bytes.fromhex(row["context_before"]), context)
                self.assertEqual(row["output_before"], action["output"])
                context = bytes.fromhex(row["context"])
                type(self).raw_pointer_calls += 1
        return result["histories"]

    @staticmethod
    def action(req, output=OUTPUT):
        return {"request": base64.b64encode(req).decode(), "output": output.hex()}

    def test_01_all_forward_basis_polynomials_match_evaluation_matrix(self):
        self.assertEqual(pow(ZETA, 256, Q), Q - 1)
        self.assertEqual(pow(ZETA, 512, Q), 1)
        self.assertEqual(256 * INV_N % Q, 1)
        self.assertEqual(len(set(ROOTS)), 256)
        rows = []
        for j in range(N):
            a = ZERO.copy()
            a[j] = 1
            rows.append((request(0, a),
                         [ZETA_POWERS[j * exponent % 512] for exponent in ROOT_EXPONENTS]))
        self.successful(rows)

    def test_02_all_inverse_basis_vectors_match_inverse_matrix(self):
        rows = []
        for k in range(N):
            a = ZERO.copy()
            a[k] = 1
            rows.append((request(1, a),
                         [INV_N * ZETA_POWERS[-j * ROOT_EXPONENTS[k] % 512] % Q
                          for j in range(N)]))
        self.successful(rows)

    def test_03_dense_boundary_and_random_forward_and_inverse(self):
        rng = random.Random(0x2042026)
        polys = [ZERO, [1] * N, [Q - 1] * N, list(range(N)),
                 [0 if i % 2 else Q - 1 for i in range(N)],
                 [Q - 1 - i for i in range(N)]]
        polys += [[rng.randrange(Q) for _ in range(N)] for _ in range(20)]
        self.successful([(request(0, a), polynomial_evaluation(a)) for a in polys])
        self.successful([(request(1, a), inverse_evaluation(a)) for a in polys])

    def test_04_roundtrip_and_transform_product_identities(self):
        rng = random.Random(0x5121753)
        a = [[rng.randrange(Q) for _ in range(N)] for _ in range(16)]
        transformed = self.successful([(request(0, p), polynomial_evaluation(p)) for p in a])
        self.successful([(request(1, p), expected) for p, expected in zip(transformed, a)])
        products = []
        expected = []
        for i in range(0, len(a), 2):
            expected.append(schoolbook(a[i], a[i + 1]))
            products.append((request(2, transformed[i], transformed[i + 1]),
                             [(x * y) % Q for x, y in zip(transformed[i], transformed[i + 1])]))
        actual = self.successful(products)
        self.successful([(request(1, value), want) for value, want in zip(actual, expected)])

    def test_05_negacyclic_product_matches_independent_schoolbook(self):
        rng = random.Random(0x8380417)
        rows = [(ZERO, ZERO), ([1] * N, [Q - 1] * N)]
        for i, j in ((0, 0), (0, 255), (1, 255), (127, 129), (255, 255)):
            a, b = ZERO.copy(), ZERO.copy()
            a[i], b[j] = Q - 1, Q - 2
            rows.append((a, b))
        rows += [([rng.randrange(Q) for _ in range(N)],
                  [rng.randrange(Q) for _ in range(N)]) for _ in range(16)]
        self.successful([(request(5, a, b), schoolbook(a, b)) for a, b in rows])

    def test_06_pointwise_add_subtract_all_coefficient_positions(self):
        rows = []
        for i in range(N):
            a, b = ZERO.copy(), ZERO.copy()
            a[i], b[i] = (0, 1, Q // 2, Q - 2, Q - 1)[i % 5], (Q - 1, 0, Q - 2)[i % 3]
            for operation in (2, 3, 4):
                expected = [((x * y) if operation == 2 else
                             (x + y) if operation == 3 else (x - y)) % Q
                            for x, y in zip(a, b)]
                rows.append((request(operation, a, b), expected))
        self.successful(rows)

    def test_07_header_shape_and_all_noncanonical_coefficients_refuse_before_write(self):
        single = request(0, ZERO)
        pair = request(5, ZERO, ZERO)
        invalid = [single[:i] for i in range(17)]
        invalid += [single[:-1], single + b"\0", pair[:-1], pair + b"\0"]
        for offset in range(8):
            for bit in range(8):
                invalid.append(patch(single, offset, bytes((single[offset] ^ (1 << bit),))))
        for offset in range(9, 16):
            for bit in range(8):
                invalid.append(patch(single, offset, bytes((1 << bit,))))
        invalid += [patch(single, 8, bytes((op,))) for op in range(6, 256)]
        invalid += [request(op, ZERO, ZERO) for op in (0, 1)]
        invalid += [request(op, ZERO) for op in (2, 3, 4, 5)]
        for i in range(N):
            for value in (Q, Q + 1, 0xffffffff):
                invalid.append(patch(single, 16 + i * 4, value.to_bytes(4, "little")))
                invalid.append(patch(pair, 16 + (N + i) * 4, value.to_bytes(4, "little")))
        self.refusals([(bad, OUTPUT, SCRATCH) for bad in invalid])
        self.refusals([(single, OUTPUT[:n], SCRATCH) for n in (0, 1, 1023)]
                      + [(single, OUTPUT, SCRATCH[:n]) for n in (0, 1, 2047)])

    def test_08_real_unaligned_pointers_guarded_scratch_reuse(self):
        a = [Q - 1 - i for i in range(N)]
        b = [(i * i * 17 + 31) % Q for i in range(N)]
        actions = [self.action(request(0, a)), self.action(request(1, polynomial_evaluation(a))),
                   self.action(request(2, a, b)), self.action(request(3, a, b)),
                   self.action(request(4, a, b)), self.action(request(5, a, b)),
                   self.action(patch(request(0, a), 16, Q.to_bytes(4, "little")))]
        expected = [polynomial_evaluation(a), a, [x * y % Q for x, y in zip(a, b)],
                    [(x + y) % Q for x, y in zip(a, b)],
                    [(x - y) % Q for x, y in zip(a, b)], schoolbook(a, b)]
        cases = [{"context": SCRATCH.hex(), "actions": actions,
                  "residues": [i, (i + 3) % 8, (i + 5) % 8]} for i in range(8)]
        for history in self.raw_histories(cases):
            for index, row in enumerate(history):
                self.assertEqual(row["abi_status"], 0)
                self.assertEqual(bytes.fromhex(row["context"])[2048:], SCRATCH[2048:])
                if index == len(expected):
                    self.assertEqual(row["value"], REFUSED)
                    self.assertEqual(row["output"], row["output_before"])
                    self.assertEqual(row["context"], row["context_before"])
                else:
                    self.assertEqual(row["value"], 1024)
                    self.assertEqual(bytes.fromhex(row["output"]),
                                     encode(expected[index]) + OUTPUT[1024:])
                    self.assertEqual(bytes.fromhex(row["context"])[:2048], bytes(2048))

    def test_09_maximum_extents_and_no_write_oversize_refusals(self):
        req = request(0, ZERO)
        cases = [
            {"context": (b"\xc7" * MAX_EXTENT).hex(),
             "actions": [self.action(req, b"\xa5" * MAX_EXTENT)]},
            {"context": SCRATCH.hex(),
             "actions": [self.action(req + bytes(MAX_EXTENT - len(req)))]},
        ]
        histories = self.raw_histories(cases)
        row = histories[0][0]
        self.assertEqual((row["abi_status"], row["value"]), (0, 1024))
        self.assertEqual(bytes.fromhex(row["output"]),
                         bytes(1024) + b"\xa5" * (MAX_EXTENT - 1024))
        self.assertEqual(bytes.fromhex(row["context"]),
                         bytes(2048) + b"\xc7" * (MAX_EXTENT - 2048))
        row = histories[1][0]
        self.assertEqual((row["abi_status"], row["value"]), (0, REFUSED))
        self.assertEqual(row["output"], row["output_before"])
        self.assertEqual(row["context"], row["context_before"])
        for oversized in ("input", "output", "scratch"):
            context = b"\xc7" * (MAX_EXTENT + 1) if oversized == "scratch" else SCRATCH
            incoming = req + bytes(MAX_EXTENT + 1 - len(req)) if oversized == "input" else req
            outgoing = b"\xa5" * (MAX_EXTENT + 1) if oversized == "output" else OUTPUT
            case = {"context": context.hex(), "actions": [self.action(incoming, outgoing)]}
            row = self.raw_histories([case])[0][0]
            self.assertTrue(row["abi_status"] != 0 or row["value"] == REFUSED)
            self.assertEqual(row["output"], row["output_before"])
            self.assertEqual(row["context"], row["context_before"])

    def test_10_backend_is_pinned_selfhost_and_source_remains_exact(self):
        receipt = self.native.receipt
        self.assertEqual(receipt["chain_migration"]["backend"], "selfhost")
        self.assertEqual(receipt["exports"], ["f0"])
        self.assertFalse(receipt["claims"]["python_emitter_used"])
        self.assertFalse(receipt["claims"]["fallback_used"])
        self.assertEqual(SOURCE.read_bytes(), self.source_before)


if __name__ == "__main__":
    unittest.main()
