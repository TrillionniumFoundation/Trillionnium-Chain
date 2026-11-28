"""Pure per-record M11 lifecycle versus the unchanged original Rust methods."""
import hashlib
from pathlib import Path
import random
import struct
import subprocess
import tempfile
import tomllib
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_verification_profile_registry import HI, ROOT, RUST, ZERO, pick, word

SRC = ROOT / "hia/src/verification/challenge_record.hepta"
ADAPTER = Path(__file__).with_name("rust_verification_challenge_reference.rs")
OUT, WORK = 173, 1472
MARK, FILL = b"\xa5", b"\x49"
OPEN, EVIDENCE, BEGIN, RESPONSE, DECIDE, APPEAL, FINALIZE, WITHDRAW, EXPIRE = range(9)


def frame(op, data, *, height=0, argument=0, choice=0):
    return struct.pack("<4sBBHQQ", b"VCX1", op, choice, 0, height, argument) + data


def opening(ids=(word(7), word(8), word(9)), times=(5, 11, 17, 23, 29), window=5):
    return frame(OPEN, b"".join(ids) + struct.pack("<5Q", *times) + bytes(37), argument=window)


def reference(work):
    raw = RUST.read_bytes()
    first = raw.index(b"pub enum ChallengePhaseV1")
    last = raw.index(b"pub struct ChallengeBookV1", first)
    section = raw[raw.rfind(b"#[derive", 0, first):raw.rfind(b"#[derive", first, last)]
    start = raw.index(b"pub enum VerificationProfileErrorV1")
    end = raw.index(b"pub type VerificationProfileResultV1", start)
    errors = raw[raw.rfind(b"#[derive", 0, start):raw.index(b";", end) + 1]
    aliases = [pick(raw, rb"^pub type " + term + rb" = \[u8; 32\];\n")
               for term in (b"VerificationDigestV1", b"VerificationObjectIdV1", b"VerificationActorIdV1")]
    domain = pick(raw, rb"^const CHALLENGE_DOMAIN_V1:[^\n]+;\n")
    helpers = [pick(raw, rb"^fn " + term + rb"\([^\n]+\n.*?^}\n")
               for term in (b"require_nonzero", b"hash_frame")]
    source = work / "original.rs"
    source.write_bytes(b"use std::fmt;\n" + domain + b"".join(aliases) + errors + b"\n" +
                       section + b"".join(helpers) + b"\n" + ADAPTER.read_bytes())
    pin = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    version = subprocess.run(["rustc", "--version"], check=True, capture_output=True,
                             timeout=10, text=True).stdout.split()
    if version[:2] != ["rustc", pin]:
        raise ValueError("Original M11 challenge requires pinned Rust")
    binary = work / "original"
    subprocess.run(["rustc", "--edition=2024", "-Dwarnings", source, "-o", binary],
                   check=True, timeout=30)
    return binary


class VerificationChallenge(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        scope = Path(cls.enterClassContext(tempfile.TemporaryDirectory(prefix="trnm-vcx-")))
        cls.oracle = reference(scope)
        cls.modules = {backend: cls.enterClassContext(NativeModule(
            SRC, backend=backend, byte_exports=("f0",))) for backend in ("direct", "selfhost")}
        if len({mod.artifact_sha256 for mod in cls.modules.values()}) != 2:
            raise ValueError("expected independent native images")

    def rust(self, cases):
        got = subprocess.run([self.oracle], input=b"".join(cases),
                             check=True, capture_output=True, timeout=45)
        self.assertEqual(got.stderr, b"")
        raw = got.stdout
        results = []
        for frame_data in cases:
            self.assertTrue(raw)
            code = raw[0]
            body = raw[1:1 + OUT] if not code else b""
            if not code:
                self.assertEqual(len(body), OUT)
                self.assertEqual(body[139:141], bytes(2))
                fields = [b"trnm.g2c.challenge-record.v1\0",
                          body[:32], body[32:64], body[64:96], body[136:137]]
                fields.extend(body[i:i+8][::-1] for i in range(96, 136, 8))
                fields.extend((body[137:138], body[138:139]))
                digest = hashlib.sha256(b"".join(len(x).to_bytes(8, "big") + x for x in fields))
                self.assertEqual(body[141:], digest.digest())
            results.append((code, body))
            raw = raw[1 + len(body):]
        self.assertEqual(raw, b"")
        return results

    def once(self, cases, expected=None, sizes=None):
        expected = self.rust(cases) if expected is None else expected
        sizes = [(OUT + 11, WORK + 13)] * len(cases) if sizes is None else sizes
        calls = [("f0", [data, MARK * n, FILL * w]) for data, (n, w) in zip(cases, sizes, strict=True)]
        for backend, module in self.modules.items():
            for i, (result, (_, args), (code, payload)) in enumerate(zip(
                    module.call_many(calls, timeout=60), calls, expected, strict=True)):
                with self.subTest(backend=backend, i=i):
                    result.require_returned()
                    self.assertEqual(result.value, code)
                    self.assertEqual(result.arguments[0], args[0])
                    self.assertEqual(result.arguments[1], payload + args[1][len(payload):])
                    self.assertEqual(result.arguments[2][WORK:], args[2][WORK:])
                    if code:
                        # A failed frame/policy/capacity never begins hashing.
                        self.assertEqual(result.arguments[2], args[2])
        return expected

    def test_open_exact_bytes_order_and_deadline_edges(self):
        rng = random.Random(1171)
        good = [opening(), opening(times=(0,)*5, window=0), opening(times=(HI,)*5, window=HI)]
        for i in range(32):
            heights = tuple(sorted(rng.getrandbits(64) for _ in range(5)))
            data = tuple(rng.randbytes(32) for _ in range(3))
            good.append(opening(ids=data, times=heights, window=heights[0] + i % 2))
        bad = [opening(times=(6, 11, 17, 23, 29)),
               opening(times=(5, 4, 17, 23, 29)),
               opening(times=(5, 11, 10, 23, 29)),
               opening(times=(5, 11, 17, 16, 29)),
               opening(times=(5, 11, 17, 23, 22))]
        zero = [opening(ids=tuple(ZERO if j == i else word(j + 1) for j in range(3)),
                        times=(6, 11, 17, 23, 29)) for i in range(3)]
        rows = self.once(good + bad + zero)
        self.assertEqual([c for c, _ in rows], [0] * len(good) + [18] * len(bad) + [1] * len(zero))

    def lifecycle(self):
        rows = []
        code, record = self.once([opening()])[0]
        self.assertEqual((code, record[136]), (0, 0))
        rows.append(record)
        for op, height, arg, choice, phase in (
            (EVIDENCE, 11, 0, 0, 1), (BEGIN, 17, 0, 0, 2), (RESPONSE, 17, 0, 0, 3),
            (DECIDE, 23, 0, 1, 4), (APPEAL, 29, 31, 0, 6),
            (DECIDE, 31, 0, 2, 5), (FINALIZE, 32, 0, 0, 7),
        ):
            code, record = self.once([frame(op, record, height=height, argument=arg, choice=choice)])[0]
            self.assertEqual((code, record[136]), (0, phase))
            rows.append(record)
        self.assertEqual(rows[5][120:136], struct.pack("<QQ", 31, 31))
        self.assertEqual(rows[5][137:139], bytes([1, 0]))
        self.assertEqual(rows[-1][137:139], bytes([1, 2]))
        return rows

    def test_lawful_full_record_lifecycle_and_all_action_phase_edges(self):
        states = self.lifecycle()
        rejected_once = self.once([frame(DECIDE, states[3], height=23, choice=2)])[0][1]
        self.assertEqual(rejected_once[136:139], bytes([5, 0, 2]))
        appealed = self.once([frame(APPEAL, rejected_once, height=29, argument=29)])[0][1]
        self.assertEqual(appealed[136:139], bytes([6, 1, 0]))
        upheld_after_appeal = self.once([frame(DECIDE, appealed, height=29, choice=1)])[0][1]
        self.assertEqual(upheld_after_appeal[136:139], bytes([4, 1, 1]))
        cases = []
        for record in [*states, rejected_once, upheld_after_appeal]:
            for h in (0, 10, 11, 12, 17, 18, 23, 24, 29, 30, 31, 32, HI):
                cases.extend(frame(op, record, height=h, choice=(1 if op == DECIDE else 0),
                                   argument=(h if op == APPEAL else 0))
                             for op in range(EVIDENCE, EXPIRE + 1))
            cases.extend(frame(DECIDE, record, height=23, choice=i) for i in (2, 3, 4))
            cases.extend(frame(APPEAL, record, height=h, argument=h-1) for h in (1, 29, HI))
        max_record = self.once([opening(times=(HI,)*5, window=HI)])[0][1]
        cases.extend((frame(EXPIRE, max_record, height=HI), frame(EVIDENCE, max_record, height=HI)))
        rows = self.once(cases)
        self.assertEqual([code for code, _ in rows[-2:]], [18, 0])
        important = [
            (frame(APPEAL, states[-1], height=HI, argument=0), 19),
            (frame(FINALIZE, states[4], height=29), 17),
            (frame(EXPIRE, states[0], height=11), 18),
            (frame(DECIDE, states[3], height=HI, choice=3), 17),
            (frame(RESPONSE, states[0], height=HI), 17),
        ]
        self.assertEqual(self.once([x for x, _ in important]), [(c, b"") for _, c in important])
        terminal = self.once([frame(WITHDRAW, states[2]), frame(EXPIRE, states[3], height=24)])
        self.assertEqual([(code, record[136:139]) for code, record in terminal],
                         [(0, bytes([7, 0, 3])), (0, bytes([7, 0, 4]))])

    def test_private_frame_and_capacity_refuse_without_writes(self):
        valid = opening()
        code, record = self.once([valid], sizes=[(OUT, WORK)])[0]
        self.assertEqual(code, 0)
        step = frame(EVIDENCE, record, height=11)
        patch_byte = lambda data, i, b: data[:i] + bytes([b]) + data[i+1:]
        bad = [b"", valid[:-1], valid + b"\0", b"BAD!" + valid[4:],
               patch_byte(valid, 4, 9), patch_byte(valid, 6, 1),
               patch_byte(valid, 8, 1), patch_byte(valid, 165, 1),
               patch_byte(step, 5, 1), patch_byte(step, 160, 8),
               patch_byte(step, 161, 2), patch_byte(step, 162, 5),
               patch_byte(step, 163, 1), patch_byte(step, 164, 1),
               frame(DECIDE, record), frame(EVIDENCE, record, argument=1)]
        cases = bad + [valid, step, frame(RESPONSE, record, height=HI)]
        expectations = [(100, b"")] * len(bad) + [(102, b""), (102, b""), (17, b"")]
        sizes = [(OUT, WORK)] * len(bad) + [(OUT-1, WORK), (OUT, WORK-1), (0, 0)]
        self.once(cases, expectations, sizes)
