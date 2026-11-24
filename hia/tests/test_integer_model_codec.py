"""Byte-only M06 ILM2/ILM3 codec parity; no model execution or evidence."""
import hashlib
from pathlib import Path
import random
import struct
import subprocess
import tempfile
import tomllib
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_verification_challenge import ADAPTER as SHA_ADAPTER
from hia.tests.test_verification_profile_registry import ROOT, pick

SRC = ROOT / "hia/src/state/integer_model_codec.hepta"
LEGACY = ROOT / "trillionnium/crates/trnm-mvcc-fee/src/integer_factor_candidate_v2.rs"
PROTO = ROOT / "trillionnium/crates/trnm-protocol/src"
ADAPTER = Path(__file__).with_name("rust_integer_model_codec_reference.rs")
WORK, COEFFICIENTS = 9014, 3855
MARK, FILL = b"\xa5", b"\x49"
ZERO = bytes(32)
DIMENSIONS = struct.pack("<4H", 1024, 3, 257, 3)


def case(version, mode, family, raw, active=0):
    return bytes([version, mode, active, 0]) + family + raw


def frame(data):
    return b"IML1" + data


def values(data):
    return struct.pack("<" + "h" * len(data), *data)


def canonical(version, family, raw, active=0):
    return (f"ILM{version}".encode("ascii") + struct.pack("<H", version) + family + DIMENSIONS +
            (bytes([active, 0]) if version == 3 else b"") + raw)


def changed(data, at, replacement):
    return data[:at] + replacement + data[at + len(replacement):]


def build_reference(work):
    legacy = LEGACY.read_bytes()
    start = legacy.index(b"pub struct IntegerModelV2")
    stop = legacy.index(b"pub trait FactorState", start)
    model = legacy[legacy.rfind(b"#[derive", 0, start):stop]
    constants = [pick(legacy, rb"^pub const " + tag + rb":[^\n]+;\n") for tag in
                 (b"MODEL_BYTES", b"EVOLUTION_MODEL_BYTES", b"MAX_MODEL_BYTES")]
    factor = (PROTO / "integer_factor_v2.rs").read_bytes()
    geometry = [pick(factor, rb"^pub const " + tag + rb":[^\n]+;\n") for tag in (b"ROWS", b"COLUMNS")]
    protocol = (PROTO / "pon_wire.rs").read_bytes()
    frame_hash = pick(protocol, rb"^pub fn hash\([^\n]+\n.*?^}\n")
    hash_type = pick(protocol, rb"^pub type Hash = \[u8; 32\];\n")
    ensure = pick(legacy, rb"^fn ensure\([^\n]+\n.*?^}\n")
    sha = SHA_ADAPTER.read_bytes()
    sha = sha[sha.index(b"use std::io"):sha.index(b"fn array")]
    source = work / "original-model-codec.rs"
    source.write_bytes(sha + b"type Result<T> = std::result::Result<T, &'static str>;\n" +
                       b"".join(constants + geometry) + hash_type + frame_hash + ensure + model +
                       ADAPTER.read_bytes())
    pin = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    version = subprocess.run(["rustc", "--version"], check=True, capture_output=True,
                             timeout=10, text=True).stdout.split()
    if version[:2] != ["rustc", pin]:
        raise ValueError("original model codec requires pinned Rust")
    binary = work / "original-model"
    subprocess.run(["rustc", "--edition=2024", "-Dwarnings", source, "-o", binary],
                   check=True, timeout=30)
    return binary


class IntegerModelCodec(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        work = Path(cls.enterClassContext(tempfile.TemporaryDirectory(prefix="trnm-iml-")))
        cls.oracle = build_reference(work)
        cls.modules = {backend: cls.enterClassContext(NativeModule(
            SRC, backend=backend, byte_exports=("f0",))) for backend in ("direct", "selfhost")}
        if len({v.artifact_sha256 for v in cls.modules.values()}) != 2:
            raise ValueError("need independently emitted native artifacts")

    def original(self, cases):
        stream = b"".join(struct.pack("<I", len(args)) + args for args in cases)
        run = subprocess.run([self.oracle], input=stream, check=True, capture_output=True, timeout=45)
        self.assertEqual(run.stderr, b"")
        rest, results = run.stdout, []
        for data in cases:
            status = rest[0]
            size = 0 if status else 7788 + 2 * (data[0] == 3)
            results.append((status, rest[1:1 + size]))
            rest = rest[1 + size:]
        self.assertEqual(rest, b"")
        return results

    def emitted(self, raws, expected, sizes=None):
        if sizes is None:
            sizes = [(len(result) + 5, WORK + 9) for _, result in expected]
        requests = [("f0", [data, MARK * out, FILL * work])
                    for data, (out, work) in zip(raws, sizes, strict=True)]
        for backend, module in self.modules.items():
            for offset in range(0, len(requests), 25):
                batch = requests[offset:offset + 25]
                for i, (got, (_, args), (status, payload)) in enumerate(zip(
                        module.call_many(batch, timeout=40), batch,
                        expected[offset:offset + len(batch)], strict=True)):
                    with self.subTest(backend=backend, case=offset + i):
                        got.require_returned()
                        self.assertEqual(got.value, status)
                        self.assertEqual(got.arguments[0], args[0])
                        self.assertEqual(got.arguments[1], payload + args[1][len(payload):])
                        self.assertEqual(got.arguments[2][WORK:], args[2][WORK:])
                        if status:
                            self.assertEqual(got.arguments[2], args[2])

    def once(self, cases):
        result = self.original(cases)
        self.emitted([frame(args) for args in cases], result)
        return result

    def test_exact_round_trip_complete_content_id_for_v2_and_every_v3_expert_count(self):
        rng = random.Random(2461)
        all_cases, expected = [], []
        for version, act in [(2, 0), *((3, expert) for expert in range(1, 8))]:
            for family in (ZERO, bytes(range(32)), rng.randbytes(32), b"\xff" * 32):
                coefficients = [-32767, 32767, 0] + [rng.randint(-32767, 32767)
                                                       for _ in range(COEFFICIENTS - 4)] + [-1]
                raw = values(coefficients)
                model_bytes = canonical(version, family, raw, act)
                all_cases.extend((case(version, 0, family, raw, act), case(version, 1, family, model_bytes)))
                domain = f"integer-linear-model-artifact-v{version}".encode("ascii")
                content_id = hashlib.sha256(b"TRNM-PON1\0" + struct.pack("<H", len(domain)) + domain +
                                            struct.pack("<I", len(model_bytes)) + model_bytes).digest()
                expected.extend([(0, content_id + model_bytes)] * 2)
        self.assertEqual(self.once(all_cases), expected)

    def test_original_rejection_order_and_coeff_vector_ranges(self):
        f = bytes(range(32))
        coeffs = bytes(COEFFICIENTS * 2)
        rows, wanted = [], []
        for ver in (2, 3):
            active = 7 if ver == 3 else 0
            body_at = 48 if ver == 3 else 46
            normal = canonical(ver, f, coeffs, active)
            for i in list(range(46)) + ([47] if ver == 3 else []):
                bad = changed(normal, i, bytes([normal[i] ^ 0x80]))
                rows.append(case(ver, 1, f, bad))
                wanted.append(2 if i < 6 else 3)
            wrong_version = changed(normal, 0, b"X")
            wrong_context = changed(wrong_version, 6, b"X")
            range_error = changed(normal, body_at, b"\x00\x80")
            rows.extend([case(ver, 1, f, b""), case(ver, 1, f, wrong_context[:-1]),
                         case(ver, 1, f, wrong_context), case(ver, 1, f, changed(range_error, 6, b"X"))])
            wanted.extend((1, 1, 2, 3))
            for position in [0, 1, 257, COEFFICIENTS // 2, COEFFICIENTS - 1]:
                rows.extend([case(ver, 0, f, changed(coeffs, 2 * position, b"\x00\x80"), active),
                             case(ver, 1, f, changed(normal, body_at + 2 * position, b"\x00\x80"))])
                wanted.extend((5, 5))
            rows.append(case(ver, 0, f, coeffs[:-2], active)); wanted.append(1)
            if ver == 3:
                for k in range(256):
                    rows.append(case(3, 0, f, b"", k))
                    wanted.append(1 if 1 <= k <= 7 else 4)
                for k in (0, 8, 255):
                    rows.extend([case(3, 1, f, changed(range_error, 46, bytes([k]))),
                                 case(3, 1, f, changed(changed(range_error, 46, bytes([k])), 47, b"\x01"))])
                    wanted.extend((4, 3))
        self.assertEqual(self.once(rows), [(n, b"") for n in wanted])

    def test_local_capacity_extents_and_input_not_mutated(self):
        coeffs = bytes(COEFFICIENTS * 2)
        args = case(3, 0, ZERO, coeffs, 7)
        data = frame(args)
        expected = self.original([args])[0]
        need = len(expected[1])
        controls = [
            (b"", (100, b""), 17, WORK), (data[:39], (100, b""), 17, WORK),
            (changed(data, 0, b"X"), (100, b""), 17, WORK),
            (changed(data, 4, b"\x01"), (100, b""), 17, WORK), (changed(data, 5, b"\x02"), (100, b""), 17, WORK),
            (changed(data, 7, b"\x01"), (100, b""), 17, WORK),
            (frame(case(2, 0, ZERO, coeffs, 1)), (100, b""), 17, WORK),
            (frame(case(3, 1, ZERO, canonical(3, ZERO, coeffs, 1), 1)), (100, b""), 17, WORK),
            (data, (102, b""), need-1, WORK), (data, (102, b""), need, WORK-1),
            (data, expected, need, WORK),
        ]
        self.emitted([x[0] for x in controls], [x[1] for x in controls], [(x[2],x[3]) for x in controls])
