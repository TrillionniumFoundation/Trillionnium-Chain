"""Independent strict-Ed25519 probes for native pointers, reuse and torsion.

These tests do not import test_ed25519.py. The small mathematical oracle uses
affine coordinates and modular inverses, independent of the product's extended
coordinates and 16-limb arithmetic. It constructs public test inputs only.

The original trnm-crypto-primitives first requires canonical point encodings,
then ed25519-dalek 3.0.0 verify_strict rejects small-order A/R and checks the
uncofactored equation. A nonzero low-order residual must fail even when both
points are nonweak and multiplication by eight makes the equation true.
Upstream source/validation policy, observed with the 3.0.0 page heading:
https://docs.rs/crate/ed25519-dalek/latest/source/src/verifying.rs
https://docs.rs/crate/ed25519-dalek/latest/source/tests/validation_criteria.rs
The retained original Rust oracle remains a separate required CI check.

Every arithmetic result under test comes from the pinned selfhost-generated
artifact. The custom child loads sealed artifact bytes, supplies actual pointer
residues and retains the same physical arena through a sequence of calls. It
does not import the HIA compiler or an arithmetic/signature oracle.
"""
from __future__ import annotations

import base64
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest

from hia.tests.native_support import NativeModule


ROOT = Path(__file__).resolve().parents[1]
P = (1 << 255) - 19
L = (1 << 252) + 27742317777372353535851937790883648493
D = -121665 * pow(121666, -1, P) % P
SQRT_I = pow(2, (P - 1) // 4, P)
IDENTITY = (0, 1)
ARENA = 140800
OUTPUT = b"\xa5" * 47
ED_FIELDS = [(133120, 139776), (139904, 139936)]
GROUP_WRITES = ED_FIELDS + [(140160, 140224), (140544, 140576)]
VERIFY_WRITES = ED_FIELDS + [(140032, 140064), (140160, 140192),
                            (140288, 140320), (140416, 140448)]


def little(value):
    return value.to_bytes(32, "little")


def affine_add(left, right):
    x, y = left
    u, v = right
    cross = D * x * u * y * v % P
    return ((x * v + y * u) * pow(1 + cross, -1, P) % P,
            (y * v + x * u) * pow(1 - cross, -1, P) % P)


def affine_mul(scalar, point):
    answer = IDENTITY
    while scalar:
        if scalar & 1:
            answer = affine_add(answer, point)
        point = affine_add(point, point)
        scalar //= 2
    return answer


def affine_decode(encoded):
    number = int.from_bytes(encoded, "little")
    y, sign = number & ((1 << 255) - 1), number >> 255
    if y >= P:
        raise ValueError("noncanonical y")
    square = (y * y - 1) * pow(D * y * y + 1, -1, P) % P
    x = pow(square, (P + 3) // 8, P)
    if x * x % P != square:
        x = x * SQRT_I % P
    if x * x % P != square:
        raise ValueError("not on Edwards curve")
    if not x and sign:
        raise ValueError("negative zero")
    if x & 1 != sign:
        x = -x % P
    return x, y


def affine_encode(point):
    x, y = point
    return little(y | ((x & 1) << 255))


BASE = affine_decode(bytes.fromhex("58" + "66" * 31))


@lru_cache(maxsize=1)
def torsion_points():
    for y in range(2, 128):
        try:
            point = affine_decode(little(y))
        except ValueError:
            continue
        generator = affine_mul(L, point)
        if affine_mul(8, generator) == IDENTITY and affine_mul(4, generator) != IDENTITY:
            points = tuple(affine_mul(index, generator) for index in range(8))
            assert len(set(points)) == 8
            return points
    raise AssertionError("no order-eight test point found")


def challenge(public, r, message):
    digest = hashlib.sha512(r + public + message).digest()
    return int.from_bytes(digest, "little") % L


def prime_order_vector(message):
    # Public deterministic fixture: these tiny scalars are not signing keys.
    public = affine_encode(affine_mul(5, BASE))
    r = affine_encode(affine_mul(7, BASE))
    scalar = (7 + 5 * challenge(public, r, message)) % L
    return public + r + little(scalar) + message


@lru_cache(maxsize=1)
def cofactor_only_vectors():
    """Small set covering every A/R torsion coset and nonzero residual."""
    torsion = torsion_points()
    prime_a, prime_r = affine_mul(5, BASE), affine_mul(7, BASE)
    remaining_a, remaining_r, remaining_residual = set(range(8)), set(range(8)), set(range(1, 8))
    selected = []
    for public_coset in range(8):
        a = affine_add(prime_a, torsion[public_coset])
        public = affine_encode(a)
        for r_coset in range(8):
            r_point = affine_add(prime_r, torsion[r_coset])
            r = affine_encode(r_point)
            for attempt in range(16):
                message = b"strict-residual-independent/" + bytes([public_coset, r_coset, attempt])
                k = challenge(public, r, message)
                residue = (r_coset + k * public_coset) % 8
                if not residue or not (public_coset in remaining_a or r_coset in remaining_r
                                       or residue in remaining_residual):
                    continue
                scalar = (7 + 5 * k) % L
                left = affine_mul(scalar, BASE)
                right = affine_add(r_point, affine_mul(k, a))
                assert left != right
                assert affine_mul(8, left) == affine_mul(8, right)
                assert affine_add(right, (-left[0] % P, left[1])) == torsion[residue]
                assert affine_mul(8, a) != IDENTITY and affine_mul(8, r_point) != IDENTITY
                selected.append((public + r + little(scalar) + message,
                                 public_coset, r_coset, residue))
                remaining_a.discard(public_coset)
                remaining_r.discard(r_coset)
                remaining_residual.discard(residue)
    assert not (remaining_a or remaining_r or remaining_residual)
    return tuple(selected)


def verify_step(raw, code=0, *, hashed=True):
    writes = list(VERIFY_WRITES)
    if hashed:
        writes += [(0, len(raw) - 32), (131168, 132576)]
    return {"module": "ed25519_verify", "raw": raw, "code": code,
            "output": OUTPUT, "writes": writes, "hashed": hashed}


def group_step(opcode, left, right, expected):
    return {"module": "ed25519_group", "raw": bytes([opcode]) + left + right,
            "code": 0, "output": expected + OUTPUT[32:],
            "writes": GROUP_WRITES, "hashed": False}


POINTER_WORKER = r"""
import base64, ctypes, fcntl, hashlib, json, os, resource, sys
request = json.load(sys.stdin)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
resource.setrlimit(resource.RLIMIT_AS, (512 << 20, 512 << 20))
resource.setrlimit(resource.RLIMIT_CPU, (55, 55))
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(4, 0, 0, 0, 0):
    raise OSError(ctypes.get_errno(), 'disable core dumps')
entries, libraries, captured_fds = {}, [], []
for name, artifact in request['artifacts'].items():
    with open(artifact['path'], 'rb') as stream:
        binary = stream.read()
    if hashlib.sha256(binary).hexdigest() != artifact['sha256']:
        raise ValueError('changed native artifact')
    fd = os.memfd_create('trnm-hia-ed25519-adversarial', os.MFD_ALLOW_SEALING)
    try:
        offset = 0
        while offset < len(binary):
            count = os.write(fd, binary[offset:])
            if count <= 0:
                raise OSError('short artifact capture')
            offset += count
        fcntl.fcntl(fd, getattr(fcntl, 'F_ADD_SEALS', 1033), 15)
        library = ctypes.CDLL('/proc/self/fd/' + str(fd))
    finally:
        # Keep distinct /proc/self/fd paths while both libraries are loaded;
        # immediate FD reuse could let dlopen reuse the first cached pathname.
        captured_fds.append(fd)
    libraries.append(library)
    entry = library.f0
    entry.argtypes = [ctypes.c_void_p, ctypes.c_uint64] * 3
    entry.restype = ctypes.c_uint64
    entries[name] = entry
for fd in captured_fds:
    os.close(fd)

def allocate(payload, residue):
    storage = ctypes.create_string_buffer(b'\x69' * (len(payload) + 48))
    begin = 16 + ((residue - ctypes.addressof(storage)) % 8)
    address = ctypes.addressof(storage) + begin
    ctypes.memmove(address, payload, len(payload))
    return storage, begin, len(payload), address, storage.raw

def contents(buffer):
    storage, begin, size, _, _ = buffer
    return storage.raw[begin:begin + size]

def guards(buffer):
    storage, begin, size, _, original = buffer
    return storage.raw[:begin] == original[:begin] and storage.raw[begin + size:] == original[begin + size:]

def outside_preserved(before, after, spans):
    begin = 0
    for left, right in sorted(spans):
        if before[begin:left] != after[begin:left]:
            return False
        begin = max(begin, right)
    return before[begin:] == after[begin:]

answers = []
for sequence in request['sequences']:
    residues = sequence['residues']
    initial = bytes((index * 113 + sequence['canary']) & 255 for index in range(140837))
    arena = allocate(initial, residues[2])
    steps = []
    for case in sequence['steps']:
        raw = base64.b64decode(case['input'], validate=True)
        source = allocate(raw, residues[0])
        output = allocate(b'\xa5' * 47, residues[1])
        before = contents(arena)
        args = []
        for buffer in (source, output, arena):
            args.extend((ctypes.c_void_p(buffer[3]), buffer[2]))
        result = entries[case['module']](*args)
        after = contents(arena)
        steps.append({
            'value': result & 0xffffffff, 'abi_status': result >> 32,
            'residues': [buffer[3] % 8 for buffer in (source, output, arena)],
            'guards': all(guards(buffer) for buffer in (source, output, arena)),
            'input_unchanged': contents(source) == raw,
            'output': contents(output).hex(),
            'outside_writes_unchanged': outside_preserved(before, after, case['writes']),
            'transcript': after[:len(raw) - 32] == raw[32:64] + raw[:32] + raw[96:] if case['hashed'] else None,
            'digest': after[131168:131232].hex(),
            'reduced_k': after[140032:140064].hex(),
        })
    answers.append(steps)
print(json.dumps({'sequences': answers,
                  'artifacts': {name: item['sha256'] for name, item in request['artifacts'].items()},
                  'compiler_modules_loaded': [name for name in sys.modules if name.startswith('hepta')]}))
"""


class Ed25519AdversarialNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules, cls.snapshots = {}, {}
        cls.shared_calls = cls.raw_pointer_calls = 0
        try:
            for name in ("ed25519_group", "ed25519_verify"):
                source = ROOT / "src/crypto" / (name + ".hepta")
                cls.snapshots[source] = source.read_bytes()
                cls.modules[name] = NativeModule(source, byte_exports=("f0",), backend="selfhost")
            sha = ROOT / "src/crypto/sha512_arena.hepta"
            cls.snapshots[sha] = sha.read_bytes()
        except BaseException:
            for module in cls.modules.values():
                module.close()
            raise

    @classmethod
    def tearDownClass(cls):
        try:
            print(json.dumps({
                "schema": "trnm.hia.ed25519-adversarial-observation.v1",
                "backend": "selfhost", "shared_runner_calls": cls.shared_calls,
                "additional_raw_pointer_calls": cls.raw_pointer_calls,
                "source_sha256": {path.name: hashlib.sha256(raw).hexdigest()
                                  for path, raw in cls.snapshots.items()},
                "sources_unchanged": all(path.read_bytes() == raw for path, raw in cls.snapshots.items()),
                "artifact_sha256": {name: module.artifact_sha256 for name, module in cls.modules.items()},
                "constant_time_qualified": False,
            }, sort_keys=True))
        finally:
            for module in cls.modules.values():
                module.close()

    def run_pointer_sequences(self, sequences):
        encoded = []
        for sequence in sequences:
            steps = [{"module": step["module"], "input": base64.b64encode(step["raw"]).decode(),
                      "writes": step["writes"], "hashed": step["hashed"]} for step in sequence["steps"]]
            encoded.append({"residues": sequence["residues"], "canary": sequence["canary"], "steps": steps})
        request = {"artifacts": {name: {"path": str(module.library), "sha256": module.artifact_sha256}
                                 for name, module in self.modules.items()}, "sequences": encoded}
        process = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", POINTER_WORKER],
                                 input=json.dumps(request), capture_output=True, text=True,
                                 timeout=60, check=True)
        self.assertEqual(process.stderr, "")
        observed = json.loads(process.stdout)
        self.assertEqual(observed["artifacts"], {name: module.artifact_sha256 for name, module in self.modules.items()})
        self.assertEqual(observed["compiler_modules_loaded"], [])
        self.assertEqual(len(observed["sequences"]), len(sequences))
        for sequence, answers in zip(sequences, observed["sequences"]):
            self.assertEqual(len(answers), len(sequence["steps"]))
            for step, answer in zip(sequence["steps"], answers):
                with self.subTest(module=step["module"], residues=sequence["residues"],
                                  input_sha256=hashlib.sha256(step["raw"]).hexdigest()):
                    self.assertEqual(answer["value"], step["code"])
                    self.assertEqual(answer["abi_status"], 0)
                    self.assertEqual(answer["residues"], sequence["residues"])
                    self.assertEqual(bytes.fromhex(answer["output"]), step["output"])
                    for key in ("guards", "input_unchanged", "outside_writes_unchanged"):
                        self.assertTrue(answer[key], key)
                    if step["hashed"]:
                        raw = step["raw"]
                        digest = hashlib.sha512(raw[32:64] + raw[:32] + raw[96:]).digest()
                        self.assertTrue(answer["transcript"])
                        self.assertEqual(bytes.fromhex(answer["digest"]), digest)
                        self.assertEqual(bytes.fromhex(answer["reduced_k"]), little(int.from_bytes(digest, "little") % L))
                    type(self).raw_pointer_calls += 1

    def test_nonzero_torsion_residuals_fail_without_cofactor_shortcut(self):
        vectors = cofactor_only_vectors()
        self.assertEqual({row[1] for row in vectors}, set(range(8)))
        self.assertEqual({row[2] for row in vectors}, set(range(8)))
        self.assertEqual({row[3] for row in vectors}, set(range(1, 8)))
        for start in range(0, len(vectors), 8):
            batch = vectors[start:start + 8]
            observed = self.modules["ed25519_verify"].call_many(
                [("f0", [raw, OUTPUT, b"\xc7" * (ARENA + 37)]) for raw, *_ in batch], timeout=60)
            self.assertEqual(len(observed), len(batch))
            for (raw, a_coset, r_coset, residual), observation in zip(batch, observed):
                with self.subTest(a_coset=a_coset, r_coset=r_coset, residual=residual):
                    result = observation.require_returned()
                    self.assertEqual(result.value, 5)
                    self.assertEqual(result.abi_status, 0)
                    self.assertEqual(result.arguments[0], raw)
                    self.assertEqual(result.arguments[1], OUTPUT)
                    self.assertEqual(result.arguments[2][140448:], b"\xc7" * (ARENA + 37 - 140448))
                    type(self).shared_calls += 1

    def test_true_unaligned_pointers_for_field_points_and_strict_verify(self):
        point = affine_encode(affine_add(BASE, torsion_points()[1]))
        valid = prime_order_vector(b"unaligned strict verification")
        invalid = cofactor_only_vectors()[0][0]
        for start in (0, 4):
            sequences = [{"residues": [residue, (residue + 3) % 8, (residue + 5) % 8],
                          "canary": 29 + residue, "steps": [
                              group_step(2, little(P - 1), little(P - 1), little(1)),
                              group_step(4, point, bytes(32), point),
                              verify_step(valid), verify_step(invalid, 5)]}
                         for residue in range(start, start + 4)]
            self.run_pointer_sequences(sequences)

    def test_same_arena_reuse_across_modules_lengths_and_early_rejection(self):
        long_message = bytes((index * 59 + 17) & 255 for index in range(131072))
        long_valid = prime_order_vector(long_message)
        small_valid = prime_order_vector(b"a")
        rejected = little(P) + small_valid[32:]
        point = affine_encode(BASE)
        sequence = {"residues": [7, 3, 1], "canary": 255, "steps": [
            verify_step(long_valid),
            group_step(3, little(P - 2), bytes(32), little(pow(P - 2, -1, P))),
            verify_step(rejected, 1, hashed=False),
            verify_step(small_valid),
            group_step(5, point, point, affine_encode(affine_add(BASE, BASE))),
            verify_step(prime_order_vector(b"")),
            verify_step(cofactor_only_vectors()[-1][0], 5),
            verify_step(small_valid),
        ]}
        self.run_pointer_sequences([sequence])

    def test_exact_sources_and_native_backend(self):
        for path, source in self.snapshots.items():
            self.assertEqual(path.read_bytes(), source)
        for module in self.modules.values():
            self.assertEqual(module.receipt["chain_migration"]["backend"], "selfhost")
            self.assertFalse(module.receipt["claims"]["python_emitter_used"])
            self.assertFalse(module.receipt["claims"]["fallback_used"])


if __name__ == "__main__":
    unittest.main()
