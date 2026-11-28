"""Native immutable ChallengeBook value parity with its unchanged Rust owner."""
from pathlib import Path
import random
import struct
import subprocess
import tempfile
import tomllib
import unittest

from hia.tests import test_verification_challenge as challenge
from hia.tests.native_support import NativeModule
from hia.tests.test_verification_profile_registry import HI, ROOT, RUST, ZERO, pick, word

SRC = ROOT / "hia/src/verification/challenge_book.hepta"
ADAPTER = Path(__file__).with_name("rust_verification_challenge_book_reference.rs")
REC, WORK, BOUND = challenge.OUT, challenge.WORK, 32
MARK, FILL = b"\xa5", b"\x49"


def query(result, *, height=0):
    metadata = challenge.opening(ids=(ZERO, result, ZERO), times=(0,) * 5, window=0)
    return metadata[:8] + struct.pack("<Q", height) + metadata[16:]


def apply(result, operation, *, height=0, argument=0, choice=0):
    return challenge.frame(operation, bytes(32) + result + bytes(109),
                           height=height, argument=argument, choice=choice)


def book_frame(metadata, operation, records=b""):
    assert len(metadata) == 197 and len(records) % REC == 0
    return metadata + struct.pack("<4sBBH", b"VCB1", operation, len(records) // REC, 0) + records


def opening(result, *, identifier=word(7), times=(5, 11, 17, 23, 29), window=5):
    return challenge.opening(ids=(identifier, result, word(9)), times=times, window=window)


def build_reference(work):
    raw = RUST.read_bytes()
    first = raw.index(b"pub enum ChallengePhaseV1")
    last = raw.index(b"fn require_nonzero", first)
    section = raw[raw.rfind(b"#[derive", 0, first):last]
    start = raw.index(b"pub enum VerificationProfileErrorV1")
    end = raw.index(b"pub type VerificationProfileResultV1", start)
    errors = raw[raw.rfind(b"#[derive", 0, start):raw.index(b";", end) + 1]
    aliases = [pick(raw, rb"^pub type " + name + rb" = \[u8; 32\];\n")
               for name in (b"VerificationDigestV1", b"VerificationObjectIdV1", b"VerificationActorIdV1")]
    domain = pick(raw, rb"^const CHALLENGE_DOMAIN_V1:[^\n]+;\n")
    helpers = [pick(raw, rb"^fn " + name + rb"\([^\n]+\n.*?^}\n")
               for name in (b"require_nonzero", b"hash_frame")]
    codec = challenge.ADAPTER.read_bytes().split(b"fn execute(", 1)[0]
    codec = codec[:codec.index(b"fn phase(")] + codec[codec.index(b"fn encode("):]
    source = work / "original-book.rs"
    source.write_bytes(b"use std::{collections::BTreeMap, fmt};\n" + domain + b"".join(aliases) +
                       errors + b"\n" + section + b"".join(helpers) + b"\n" + codec + ADAPTER.read_bytes())
    pin = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    version = subprocess.run(["rustc", "--version"], check=True, capture_output=True,
                             timeout=10, text=True).stdout.split()
    if version[:2] != ["rustc", pin]:
        raise ValueError("original ChallengeBook requires pinned Rust")
    binary = work / "original-book"
    subprocess.run(["rustc", "--edition=2024", "-Dwarnings", source, "-o", binary],
                   check=True, timeout=30)
    return binary


class VerificationChallengeBook(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        work = Path(cls.enterClassContext(tempfile.TemporaryDirectory(prefix="trnm-vcb-")))
        cls.oracle = build_reference(work)
        cls.modules = {backend: cls.enterClassContext(NativeModule(
            SRC, backend=backend, byte_exports=("f0",))) for backend in ("direct", "selfhost")}
        if len({mod.artifact_sha256 for mod in cls.modules.values()}) != 2:
            raise ValueError("expected two distinct native artifacts")

    def original(self, requests):
        wire = b"".join(book_frame(meta, op) for op, meta in requests)
        run = subprocess.run([self.oracle], input=wire, capture_output=True, check=True, timeout=40)
        self.assertEqual(run.stderr, b"")
        data, result = run.stdout, []
        for op, meta in requests:
            self.assertTrue(data)
            code = data[0]
            if code:
                result.append((code, b""))
                data = data[1:]
                continue
            n, index = data[1:3]
            self.assertLess(index, n)
            size = 8 + (n + 1) * REC
            payload, data = data[1:1 + size], data[1 + size:]
            self.assertEqual(len(payload), size)
            self.assertEqual(payload[2:8], bytes(6))
            self.assertEqual(payload[-REC:][32:64], meta[56:88])
            roster = [payload[8 + i * REC:8 + (i + 1) * REC] for i in range(n)]
            self.assertEqual(payload[-REC:], roster[index])
            self.assertEqual([r[32:64] for r in roster], sorted({r[32:64] for r in roster}))
            self.assertTrue(all(r[139:141] == bytes(2) for r in roster))
            result.append((0, payload))
        self.assertEqual(data, b"")
        return result

    def command(self, module, raw, expected, n, w):
        code, payload = expected
        sent = [raw, MARK * n, FILL * w]
        (got,) = module.call_many([("f0", sent)], timeout=20)
        got.require_returned()
        self.assertEqual(got.value, code)
        self.assertEqual(got.arguments[0], raw)
        self.assertEqual(got.arguments[1], payload + sent[1][len(payload):])
        self.assertEqual(got.arguments[2][WORK:], sent[2][WORK:])
        return got.arguments[1][:len(payload)]

    def trajectory(self, requests):
        expected = self.original(requests)
        for backend, module in self.modules.items():
            roster = b""
            for i, ((op, meta), row) in enumerate(zip(requests, expected, strict=True)):
                with self.subTest(backend=backend, i=i):
                    code, payload = row
                    n = len(payload) + 11 if not code else 173
                    result = self.command(module, book_frame(meta, op, roster), row, n, WORK + 13)
                    if not code:
                        if op == 1:
                            self.assertEqual(result[8:-REC], roster)
                        elif op == 2:
                            slot = result[1] * REC
                            self.assertEqual(result[8:8 + slot], roster[:slot])
                            self.assertEqual(result[8 + slot + REC:-REC], roster[slot + REC:])
                            self.assertEqual(result[8 + slot:8 + slot + REC], result[-REC:])
                        roster = result[8:-REC]
        return expected

    def test_complete_original_open_lookup_order_and_duplicate_priority(self):
        low = bytes([0] * 31 + [128])
        lower = bytes([0] * 31 + [127])
        high = bytes([255] * 32)
        mid = bytes([128] + [0] * 31)
        rows = [
            (1, query(ZERO)), (0, opening(low)), (0, opening(high)),
            (0, opening(lower)), (0, opening(mid)), (1, query(low)),
            (0, opening(low, identifier=ZERO, times=(6, 0, 0, 0, 0))),
            (0, opening(word(10), identifier=ZERO, times=(6, 0, 0, 0, 0))),
            (0, opening(word(11), times=(6, 0, 0, 0, 0))),
            (1, query(lower)), (1, query(mid)), (1, query(high)),
            (1, query(word(10))), (2, apply(low, challenge.EVIDENCE, height=11)), (1, query(low)),
        ]
        initial = self.trajectory(rows)
        self.assertEqual([c for c, _ in initial], [21,0,0,0,0,0,20,1,18,0,0,0,21,0,0])
        self.assertEqual(initial[14][1][-REC:][136], 1)
        self.assertEqual(initial[5][1][-REC:][136], 0)

    def test_one_call_transition_keeps_independent_book_members(self):
        a, b, c, d = word(16), word(19), word(17), word(15)
        open_a, open_b, open_c, open_d = [(0, opening(k)) for k in (a, b, c, d)]
        act = lambda result, operation, **kw: (2, apply(result, operation, **kw))
        rows = [
            open_a, open_b, open_c, open_d,
            act(ZERO, challenge.RESPONSE, height=HI),
            act(a, challenge.RESPONSE, height=HI),
            act(c, challenge.EVIDENCE, height=12),
            act(a, challenge.EVIDENCE, height=11),
            act(a, challenge.BEGIN, height=17),
            act(b, challenge.WITHDRAW),
            act(c, challenge.EXPIRE, height=11),
            act(c, challenge.EXPIRE, height=12),
            act(a, challenge.RESPONSE, height=17),
            act(a, challenge.DECIDE, height=HI, choice=3),
            act(a, challenge.DECIDE, height=23, choice=2),
            act(a, challenge.FINALIZE, height=29),
            (1, query(c)),
            act(a, challenge.APPEAL, height=29, argument=28),
            act(a, challenge.APPEAL, height=29, argument=31),
            act(a, challenge.APPEAL, height=HI, argument=1),
            act(a, challenge.DECIDE, height=31, choice=1),
            act(a, challenge.FINALIZE, height=32),
            act(d, challenge.EVIDENCE, height=0),
            (1, query(b)), (1, query(c)), (1, query(a)), (1, query(d)),
        ]
        expected = self.trajectory(rows)
        self.assertEqual([x[0] for x in expected],
                         [0,0,0,0,21,17,18,0,0,0,18,0,0,17,0,17,0,18,0,19,0,0,0,0,0,0,0])
        self.assertEqual([x[1][-REC:][136:139] for x in expected[-4:]],
                         [bytes([7,0,3]), bytes([7,0,4]), bytes([7,1,1]), bytes([1,0,0])])
        prior = expected[11][1][8:-REC]
        good = apply(a, challenge.RESPONSE, height=17)
        raw = book_frame(good, 2, prior)
        patch = lambda at,n: raw[:at] + bytes([n]) + raw[at+1:]
        n = len(expected[12][1])
        controls = [
            (raw, (102, b""), n-1, WORK), (raw, (102, b""), n, WORK-1),
            (patch(4, 0), (100, b""), n, WORK), (patch(4, 9), (100, b""), n, WORK),
            (patch(5, 3), (100, b""), n, WORK), (patch(7, 1), (100, b""), n, WORK),
            (patch(16, 1), (100, b""), n, WORK), (patch(24, 1), (100, b""), n, WORK),
            (patch(88, 1), (100, b""), n, WORK), (patch(196, 1), (100, b""), n, WORK),
            (book_frame(good, 1, prior), (100, b""), n, WORK),
            (book_frame(good, 3, prior), (100, b""), n, WORK),
            (patch(205 + 172, 1 ^ raw[205 + 172]), (101, b""), n, WORK),
            (raw, expected[12], n, WORK),
        ]
        for module in self.modules.values():
            for wire, row, output, scratch in controls:
                self.command(module, wire, row, output, scratch)

    def test_all_private_maximum_rows_and_exact_bounded_capacity(self):
        rng = random.Random(7490)
        keys = [rng.randbytes(32) for _ in range(BOUND)]
        into = [(0, opening(k, times=(HI,) * 5, window=HI)) for k in keys]
        requests = into + [(1, query(x)) for x in (min(keys), sorted(keys)[15], max(keys), ZERO)]
        proof = self.trajectory(requests)
        full = proof[BOUND - 1][1][8:-REC]
        self.assertEqual(len(full), REC * BOUND)
        for module in self.modules.values():
            checks = [
                (book_frame(opening(word(3)), 0, full), (104, b""), 173, WORK),
                (book_frame(opening(keys[0], identifier=ZERO), 0, full), (20, b""), 0, WORK),
                (book_frame(opening(word(4), identifier=ZERO), 0, full), (1, b""), 0, WORK),
                (book_frame(query(min(keys)), 1, full), proof[BOUND], len(proof[BOUND][1]), WORK),
                (book_frame(query(min(keys)), 1, full), (102, b""), len(proof[BOUND][1])-1, WORK),
            ]
            for wire, row, n, w in checks:
                self.command(module, wire, row, n, w)

    def test_canonical_snapshot_integrity_every_field_and_untouched_refusal(self):
        keys = word(7), word(8)
        expected = self.original([(0, opening(keys[0])), (0, opening(keys[1])), (1, query(keys[0]))])
        payload = expected[-1][1]
        records = payload[8:-REC]
        valid = book_frame(query(keys[0]), 1, records)
        corrupt = lambda pos: valid[:pos] + bytes([valid[pos] ^ 1]) + valid[pos+1:]
        controls = [(corrupt(205 + i), (101, b""), 31, WORK) for i in range(REC)]
        controls.extend((corrupt(205 + REC + i), (101, b""), 31, WORK)
                        for i in (0, 32, 64, 96, 136, 137, 138, 139, 140, 141, 172))
        controls.extend([
            (book_frame(query(keys[0]), 1, records[REC:] + records[:REC]), (101, b""), 0, WORK),
            (book_frame(query(keys[0]), 1, records[:REC] * 2), (101, b""), 0, WORK),
            (book_frame(opening(keys[0], identifier=ZERO), 0, records[:REC] * 2), (101, b""), 31, WORK),
            (valid[:-1], (100, b""), 31, WORK), (valid + b"x", (100, b""), 31, WORK),
            (corrupt(0), (100, b""), 31, WORK), (corrupt(197), (100, b""), 31, WORK),
            (corrupt(203), (100, b""), 31, WORK),
            (book_frame(query(keys[0]), 1, records[:REC] * 33), (100, b""), 31, WORK),
            (valid, (102, b""), 173, WORK - 1),
            (valid, expected[-1], len(payload), WORK),
        ])
        for backend, module in self.modules.items():
            asks = [("f0", [data, MARK * n, FILL * w]) for (data, _, n, w) in controls]
            for i, (got, (_, args), (_, (code, value), _, _)) in enumerate(zip(
                    module.call_many(asks, timeout=40), asks, controls, strict=True)):
                with self.subTest(backend=backend, i=i):
                    got.require_returned()
                    self.assertEqual(got.value, code)
                    self.assertEqual(got.arguments[0], args[0])
                    self.assertEqual(got.arguments[1], value + args[1][len(value):])
                    self.assertEqual(got.arguments[2][WORK:], args[2][WORK:])
