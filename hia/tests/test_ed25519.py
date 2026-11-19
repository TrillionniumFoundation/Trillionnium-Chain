"""Strict public Ed25519 verification, independent arithmetic and original Rust.

The HIA implementation follows the field/group equations of RFC 8032 sections
5.1.1--5.1.4 and the original project's stricter canonical/weak-point policy in
trnm-crypto-primitives/src/lib.rs. RFC 8032 section 7.1 supplies the first two
public known-answer vectors below: https://www.rfc-editor.org/rfc/rfc8032.html.
No private signing operation is exposed by the native HIA components. The
Python big-integer signer is solely a deterministic test-input generator;
CI also signs and verifies with the retained original Rust crate.

The arithmetic oracle uses Python integers modulo p, independently of the HIA
16-limb convolution/carry representation. Actual native artifacts are invoked
in isolated child processes. No host arithmetic supplies their returned result.
"""
from __future__ import annotations

from functools import lru_cache
import hashlib
import os
from pathlib import Path
import random
import subprocess
import unittest

from hia.tests.native_support import NativeModule

ROOT = Path(__file__).resolve().parents[1]
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, -1, P) % P
SQRT_I = pow(2, (P - 1) // 4, P)
BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202
BY = 4 * pow(5, -1, P) % P
B = (BX, BY, 1, BX * BY % P)
IDENTITY = (0, 1, 1, 0)
ARENA = 140800
MAX_MESSAGE = 131072
VECTOR1_PK = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
VECTOR1_SIG = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555"
                            "fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
VECTOR2_PK = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
VECTOR2_SIG = bytes.fromhex("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")


def little(n):
    return n.to_bytes(32, "little")


def add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * D * t1 * t2 % P
    d = 2 * z1 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return e * f % P, g * h % P, f * g % P, e * h % P


def multiply(scalar, point):
    # Right-to-left traversal differs from the native left-to-right traversal.
    answer = IDENTITY
    while scalar:
        if scalar & 1:
            answer = add(answer, point)
        point = add(point, point)
        scalar >>= 1
    return answer


def compress(point):
    x, y, z, _ = point
    inv = pow(z, -1, P)
    x, y = x * inv % P, y * inv % P
    return little(y | ((x & 1) << 255))


def decompress(raw):
    value = int.from_bytes(raw, "little")
    y, sign = value & ((1 << 255) - 1), value >> 255
    if y >= P or (sign and y in (1, P - 1)):
        return 1, None
    x_squared = (y * y - 1) * pow(D * y * y + 1, -1, P) % P
    x = pow(x_squared, (P + 3) // 8, P)
    if x * x % P != x_squared:
        x = x * SQRT_I % P
    if x * x % P != x_squared:
        return 2, None
    if x & 1 != sign:
        x = -x % P
    return 0, (x, y, 1, x * y % P)


def weak(point):
    return compress(multiply(8, point)) == little(1)


def sign(seed, message):
    digest = hashlib.sha512(seed).digest()
    scalar = (int.from_bytes(digest[:32], "little") & ((1 << 254) - 8)) | (1 << 254)
    public = compress(multiply(scalar, B))
    r = int.from_bytes(hashlib.sha512(digest[32:] + message).digest(), "little") % L
    r_bytes = compress(multiply(r, B))
    k = int.from_bytes(hashlib.sha512(r_bytes + public + message).digest(), "little") % L
    return public, r_bytes + little((r + k * scalar) % L)


def status(raw):
    if not 96 <= len(raw) <= 96 + MAX_MESSAGE:
        return 100
    code, a = decompress(raw[:32])
    if code:
        return code
    if weak(a):
        return 3
    code, r = decompress(raw[32:64])
    if code == 1:
        return 4
    if code or weak(r):
        return 5
    s = int.from_bytes(raw[64:96], "little")
    if s >= L:
        return 5
    k = int.from_bytes(hashlib.sha512(raw[32:64] + raw[:32] + raw[96:]).digest(), "little") % L
    return 0 if compress(multiply(s, B)) == compress(add(r, multiply(k, a))) else 5


@lru_cache(maxsize=1)
def torsion_generator():
    for y in range(2, 128):
        code, point = decompress(little(y))
        if not code:
            t = multiply(L, point)
            if compress(multiply(8, t)) == little(1) and compress(multiply(4, t)) != little(1):
                return t
    raise AssertionError("No deterministic order-eight test point")


@lru_cache(maxsize=1)
def mixed_order_signature():
    # Strict original dalek rejects small-order points, but does not require
    # every accepted point to be torsion-free. Preserve that exact distinction.
    t = torsion_generator()
    scalar = 123456789
    public_point = add(multiply(scalar, B), t)
    public = compress(public_point)
    message = b"nonweak mixed-order points preserve original strict semantics"
    for nonce in range(1, 64):
        for j in range(8):
            r = compress(add(multiply(nonce, B), multiply(j, t)))
            k = int.from_bytes(hashlib.sha512(r + public + message).digest(), "little") % L
            if (j + k) % 8 == 0:
                raw = public + r + little((nonce + k * scalar) % L) + message
                assert status(raw) == 0
                assert not weak(public_point)
                assert compress(multiply(L, public_point)) != little(1)
                return raw
    raise AssertionError("No deterministic mixed-order signature witness")


def malformed_vectors():
    good = VECTOR1_PK + VECTOR1_SIG
    cases = []
    for v in [P, P + 1, (1 << 255) - 1]:
        for sign_bit in [0, 1 << 255]:
            raw = little(v | sign_bit)
            cases.extend([raw + good[32:], good[:32] + raw + good[64:]])
    for v in [1 | (1 << 255), (P - 1) | (1 << 255)]:
        raw = little(v)
        cases.extend([raw + good[32:], good[:32] + raw + good[64:]])
    for j in range(8):
        raw = compress(multiply(j, torsion_generator()))
        cases.extend([raw + good[32:], good[:32] + raw + good[64:]])
    for s in [L, L + 1, 2 * L - 1, 1 << 255, (1 << 256) - 1]:
        cases.append(good[:64] + little(s))
    original_s = int.from_bytes(good[64:], "little")
    cases.append(good[:64] + little(original_s + L))
    # Every byte of public key/R/S is independently perturbed.
    for index in range(96):
        raw = bytearray(good)
        raw[index] ^= 1 << (index % 8)
        cases.append(bytes(raw))
    cases += [good + b"\0", good + b"message substitution"]
    return cases


class Ed25519NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules = {}
        try:
            for name in ["ed25519_group", "ed25519_verify"]:
                cls.modules[name] = NativeModule(ROOT / "src/crypto" / (name + ".hepta"), byte_exports=("f0",))
        except BaseException:
            for module in cls.modules.values():
                module.close()
            raise

    @classmethod
    def tearDownClass(cls):
        for module in cls.modules.values():
            module.close()

    def check_group(self, cases):
        rows = list(cases)
        for start in range(0, len(rows), 8):
            batch = rows[start:start + 8]
            calls = [("f0", [raw, b"\xa5" * 43, b"\x5a" * (ARENA + 19)]) for raw, _, _ in batch]
            observations = self.modules["ed25519_group"].call_many(calls, timeout=60)
            for (raw, code, output), got in zip(batch, observations):
                with self.subTest(op=raw[0], a=raw[1:33].hex(), b=raw[33:].hex()):
                    r = got.require_returned()
                    self.assertEqual(r.value, code)
                    self.assertEqual(r.arguments[0], raw)
                    self.assertEqual(r.arguments[1], output + b"\xa5" * 11 if code == 0 else b"\xa5" * 43)
                    self.assertEqual(r.arguments[2][ARENA:], b"\x5a" * 19)

    def check_verify(self, cases, *, module=None):
        rows = list(cases)
        module = module or self.modules["ed25519_verify"]
        results = []
        for start in range(0, len(rows), 8):
            batch = rows[start:start + 8]
            calls = [("f0", [raw, b"\xa5" * 7, b"\x5a" * (ARENA + 19)]) for raw in batch]
            observations = module.call_many(calls, timeout=60)
            for raw, got in zip(batch, observations):
                with self.subTest(input_sha=hashlib.sha256(raw).hexdigest()):
                    r = got.require_returned()
                    self.assertEqual(r.value, status(raw))
                    self.assertEqual(r.arguments[0], raw)
                    self.assertEqual(r.arguments[1], b"\xa5" * 7)
                    self.assertEqual(r.arguments[2][ARENA:], b"\x5a" * 19)
                    results.append(r.value)
        return results

    def test_field_full_carry_and_deterministic_random_arithmetic(self):
        rng = random.Random(8032)
        values = [0, 1, 2, 18, 19, 65535, 65536, P - 1, P - 2, P - 19,
                  int.from_bytes(b"\xaa" * 31 + b"\x2a", "little")]
        pairs = [(a, b) for a in values for b in values]
        pairs += [(rng.randrange(P), rng.randrange(P)) for _ in range(128)]
        cases = []
        for a, b in pairs:
            for op, answer in [(0, (a + b) % P), (1, (a - b) % P), (2, a * b % P)]:
                cases.append((bytes([op]) + little(a) + little(b), 0, little(answer)))
        self.check_group(cases)

    def test_field_inverse_and_noncanonical_inputs(self):
        rng = random.Random(25519)
        values = [1, 2, 19, 65536, P - 1, P - 2] + [rng.randrange(1, P) for _ in range(10)]
        cases = [(b"\3" + little(x) + little(0), 0, little(pow(x, -1, P))) for x in values]
        cases.append((b"\3" + little(0) + little(0), 3, b""))
        for a in [P, P + 1, 1 << 255, (1 << 256) - 1]:
            for op in range(4):
                cases.append((bytes([op]) + little(a) + little(1), 1, b""))
            for op in range(3):
                cases.append((bytes([op]) + little(1) + little(a), 1, b""))
        self.check_group(cases)

    def test_point_roundtrip_off_curve_canonical_and_torsion(self):
        encodings = [little(y | sign) for y in range(32) for sign in (0, 1 << 255)]
        encodings += [VECTOR1_PK, VECTOR2_PK, VECTOR1_SIG[:32], VECTOR2_SIG[:32], compress(B)]
        encodings += [compress(multiply(i, torsion_generator())) for i in range(8)]
        encodings += [little(y | sign) for y in (1, P - 1, P, P + 1, (1 << 255) - 1) for sign in (0, 1 << 255)]
        cases = []
        for raw in encodings:
            code, _ = decompress(raw)
            cases.append((b"\4" + raw + little(0), code, raw if code == 0 else b""))
        self.check_group(cases)

    def test_group_addition_and_all_scalar_bits(self):
        points = [IDENTITY, B, multiply(123456, B), torsion_generator(), add(B, torsion_generator())]
        cases = []
        for p in points:
            for q in points:
                cases.append((b"\5" + compress(p) + compress(q), 0, compress(add(p, q))))
        for scalar in [0, 1, 2, 7, 8, L - 1, L, L + 1, 1 << 255, (1 << 256) - 1]:
            for point in [B, torsion_generator(), add(B, torsion_generator())]:
                cases.append((b"\6" + compress(point) + little(scalar), 0, compress(multiply(scalar, point))))
        self.check_group(cases)

    def test_published_known_answers_and_independent_signatures(self):
        self.assertEqual(sign(bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"), b""),
                         (VECTOR1_PK, VECTOR1_SIG))
        self.assertEqual(sign(bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"), b"\x72"),
                         (VECTOR2_PK, VECTOR2_SIG))
        cases = [VECTOR1_PK + VECTOR1_SIG, VECTOR2_PK + VECTOR2_SIG + b"\x72"]
        for length in [0, 1, 2, 31, 32, 63, 64, 111, 112, 127, 128, 129, 255, 256, 1024, MAX_MESSAGE - 1, MAX_MESSAGE]:
            message = bytes((i * 73 + 19) & 255 for i in range(length))
            public, signature = sign(hashlib.sha256(str(length).encode()).digest(), message)
            cases.append(public + signature + message)
        self.assertEqual(self.check_verify(cases), [0] * len(cases))

    def test_weak_noncanonical_malleable_and_corrupted_signatures(self):
        cases = malformed_vectors()
        expected = self.check_verify(cases)
        self.assertTrue(all(code != 0 for code in expected))

    def test_nonweak_mixed_order_signature_preserves_original_contract(self):
        raw = mixed_order_signature()
        self.assertEqual(self.check_verify([raw]), [0])

    def test_error_precedence_and_capacity_are_explicit(self):
        # Bad public key is observed before malformed R or a noncanonical S.
        good = VECTOR1_PK + VECTOR1_SIG
        cases = [little(P) + little(P) + little(L), little(1) + little(P) + little(L),
                 good[:32] + little(P) + little(L), good[:64] + little(L)]
        self.assertEqual(self.check_verify(cases), [1, 3, 4, 5])
        raw_cases = [b"", good[:95], good + b"x" * (MAX_MESSAGE + 1)]
        for raw in raw_cases:
            result = self.modules["ed25519_verify"].call("f0", [raw, b"\xa5", b"\x5a" * ARENA]).require_returned()
            self.assertEqual(result.value, 100)
            self.assertEqual(result.arguments, [raw, b"\xa5", b"\x5a" * ARENA])
        for length in [0, 133120, ARENA - 1]:
            result = self.modules["ed25519_verify"].call("f0", [good, b"", b"\x5a" * length]).require_returned()
            self.assertEqual(result.value, 101)
            self.assertEqual(result.arguments, [good, b"", b"\x5a" * length])
        result = self.modules["ed25519_verify"].call("f0", [good, b"", b"\x5a" * ARENA]).require_returned()
        self.assertEqual(result.value, 0)
        self.assertEqual(result.arguments[1], b"")

    def test_distinct_native_backend_matches_selected_strict_cases(self):
        cases = [VECTOR1_PK + VECTOR1_SIG, VECTOR2_PK + VECTOR2_SIG + b"\x72", mixed_order_signature()]
        cases += malformed_vectors()[::17]
        with NativeModule(ROOT / "src/crypto/ed25519_verify.hepta", byte_exports=("f0",), backend="direct") as module:
            self.check_verify(cases, module=module)

    def test_original_rust_crate_differential_and_original_signing(self):
        executable = os.environ.get("TRNM_HIA_RUST_CRYPTO_REFERENCE")
        if not executable:
            self.skipTest("Original Rust crypto oracle is explicitly absent locally; required by CI")
        cases = [VECTOR1_PK + VECTOR1_SIG, VECTOR2_PK + VECTOR2_SIG + b"\x72", mixed_order_signature()]
        cases += malformed_vectors()
        good = VECTOR1_PK + VECTOR1_SIG
        cases += [little(P) + little(P) + little(L), little(1) + little(P) + little(L),
                  good[:32] + little(P) + little(L), good[:64] + little(L),
                  b"", good[:95], good + b"x" * (MAX_MESSAGE + 1)]
        requests = []
        for i, n in enumerate([0, 1, 63, 64, 112, 128, 129, 4096, MAX_MESSAGE]):
            seed = hashlib.sha256(b"original Rust signer" + little(i)).digest()
            message = bytes((j * 29 + i) & 255 for j in range(n))
            requests.append((seed, message))
        lines = ["S " + seed.hex() + " " + (message.hex() or "-") for seed, message in requests]
        observed = subprocess.run([executable], input="\n".join(lines) + "\n", text=True, capture_output=True,
                                  check=True, timeout=45).stdout.splitlines()
        self.assertEqual(len(observed), len(requests))
        for line, (seed, message) in zip(observed, requests):
            public, signature = [bytes.fromhex(word) for word in line.split()]
            self.assertEqual((public, signature), sign(seed, message))
            cases.append(public + signature + message)
        lines = ["V " + (raw.hex() or "-") for raw in cases]
        observed = subprocess.run([executable], input="\n".join(lines) + "\n", text=True, capture_output=True,
                                  check=True, timeout=45).stdout.splitlines()
        self.assertEqual([int(row) for row in observed], [status(raw) for raw in cases])
        self.assertEqual(self.check_verify(cases), [int(row) for row in observed])


if __name__ == "__main__":
    unittest.main()
