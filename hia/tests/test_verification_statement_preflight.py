"""Native statement constructor and exact original pre-provider boundary."""
from dataclasses import dataclass, replace
import hashlib
from pathlib import Path
import random
import struct
import subprocess
import tempfile
import tomllib
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_verification_profile_registry import (
    ADAPTER as REGISTRY_ADAPTER, DEFAULT, HI, ROOT, RUST, V32, ZERO, pick, word,
)

SRC = ROOT / "hia/src/verification/statement_preflight.hepta"
ADAPTER = Path(__file__).with_name("rust_verification_statement_preflight_reference.rs")
DOMAIN = b"trnm.g2c.verification-statement.v1\0"
MARK, FILL, WORK = b"\xa5", b"\x45", 1591


@dataclass(frozen=True)
class Statement:
    ids: tuple = (word(20), word(21), word(22))
    version: int = 1
    row: object = DEFAULT[0]
    artifacts: tuple = (word(23), word(24))
    lower: int = 8
    upper: int = 18
    submitted: int = 10

    def to_wire(self):
        return (b"".join(self.ids) + self.row.identity + struct.pack("<I", self.version)
                + self.row.digest + b"".join(self.artifacts)
                + struct.pack("<QQQ", self.lower, self.upper, self.submitted))

    def digest(self):
        fields = (DOMAIN, *self.ids, self.row.identity, struct.pack(">I", self.version),
                  self.row.digest, *self.artifacts, *(struct.pack(">Q", h)
                  for h in (self.lower, self.upper, self.submitted)))
        return hashlib.sha256(b"".join(len(p).to_bytes(8, "big") + p for p in fields)).digest()

    def evidence(self):
        return self.ids + self.artifacts + (word(25),)


def frame(statement, *, rows=None, height=10, claim=None, evidence=None):
    op = int(rows is not None)
    profiles = () if rows is None else rows
    head = b"VPS1" + struct.pack("<IQQ", op, len(profiles), height) + bytes(68)
    extra = b"" if not op else ((statement.digest() if claim is None else claim)
                                + b"".join(statement.evidence() if evidence is None else evidence))
    return head + b"".join(p.wire() for p in profiles) + statement.to_wire() + extra


def changed(items, index, value):
    return items[:index] + (value,) + items[index + 1:]


def reference(path):
    raw = RUST.read_bytes()
    first = raw.index(b"pub enum VerificationProfileKindV1")
    last = raw.index(b"pub enum ChallengePhaseV1", first)
    section = raw[raw.rfind(b"#[derive", 0, first):raw.rfind(b"#[derive", first, last)]
    aliases = [pick(raw, rb"^pub type " + n + rb" = \[u8; 32\];\n") for n in (
        b"VerificationDigestV1", b"VerificationProfileIdV1", b"VerificationObjectIdV1")]
    domains = [pick(raw, rb"^const " + n + rb":[^\n]+;\n")
               for n in (b"STATEMENT_DOMAIN_V1", b"DECISION_DOMAIN_V1")]
    methods = [pick(raw, rb"^fn " + n + rb"\([^\n]+\n.*?^}\n")
               for n in (b"require_nonzero", b"hash_frame")]
    old = REGISTRY_ADAPTER.read_bytes().split(b"\nfn main()", 1)[0]
    marker = b"        _ => panic!(\"unrelated original error: {err}\"),"
    if old.count(marker) != 1:
        raise ValueError("registry fixture error adapter changed")
    bridge = old.replace(marker, b"""        VerificationProfileErrorV1::MalformedStatement => 14,
        VerificationProfileErrorV1::EvidenceBindingMismatch => 15,
        VerificationProfileErrorV1::EvidenceWindowClosed => 16,
""" + marker)
    source = path / "statement-original.rs"
    source.write_bytes(b"use std::{collections::{BTreeMap,BTreeSet},fmt};\n" + b"".join(aliases + domains)
                       + section + b"".join(methods) + bridge + b"\n" + ADAPTER.read_bytes())
    pin = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    actual = subprocess.run(["rustc", "--version"], check=True, capture_output=True,
                            timeout=10, text=True).stdout.split()
    if actual[:2] != ["rustc", pin]:
        raise ValueError("Original M11 preflight requires the pinned Rust toolchain")
    binary = path / "original-preflight"
    subprocess.run(["rustc", "--edition=2024", "-Dwarnings",
                    source, "-o", binary], check=True, timeout=30)
    return binary


class VerificationStatementPreflight(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        work = Path(cls.enterClassContext(tempfile.TemporaryDirectory(prefix="trnm-vps-rust-")))
        cls.original = reference(work)
        cls.modules = {mode: cls.enterClassContext(NativeModule(SRC, backend=mode, byte_exports=("f0",)))
                       for mode in ("direct", "selfhost")}
        if cls.modules["direct"].artifact_sha256 == cls.modules["selfhost"].artifact_sha256:
            raise ValueError("Independent native images required")

    def once(self, rows, expected=None, sizes=None):
        frames = [r[0] for r in rows]
        if expected is None:
            run = subprocess.run([self.original], input=b"".join(frames), check=True, capture_output=True, timeout=45)
            self.assertEqual(run.stderr, b"")
            pending, expected = run.stdout, []
            for (wire, code) in rows:
                self.assertGreaterEqual(len(pending), 2)
                self.assertEqual(pending[0], code)
                self.assertEqual(pending[1], int(code == 0 and wire[4] == 1))
                extent = 0 if code else 129 if wire[4] else 32
                self.assertGreaterEqual(len(pending), 2 + extent)
                expected.append(pending[2:2 + extent])
                pending = pending[2 + extent:]
            self.assertEqual(pending, b"")
        sizes = [(136, WORK + 11)] * len(rows) if sizes is None else sizes
        asks = [("f0", [wire, MARK * out, FILL * work])
                for (wire, _), (out, work) in zip(rows, sizes, strict=True)]
        for mode, module in self.modules.items():
            for pos, (req, got, row, payload) in enumerate(zip(
                    asks, module.call_many(asks, timeout=40), rows, expected, strict=True)):
                with self.subTest(backend=mode, row=pos):
                    out = req[1][1]
                    got.require_returned()
                    self.assertEqual(got.value, row[1])
                    self.assertEqual(got.arguments[0], req[1][0])
                    self.assertEqual(got.arguments[1], payload + out[len(payload):])
                    self.assertEqual(got.arguments[2][WORK:], req[1][2][WORK:])

    def test_actual_constructor_bytes_and_original_shape(self):
        base = Statement()
        rng = random.Random(906)
        varied = [replace(base, version=rng.choice((1, V32)), lower=i, submitted=i, upper=HI,
                          ids=(rng.randbytes(32), base.ids[1], base.ids[2]))
                  for i in range(45)]
        good = [base, replace(base, lower=HI, upper=HI, submitted=HI), *varied]
        cases = [(frame(x), 0) for x in good]
        cases.extend((frame(x), error) for x, error in (
            (replace(base, version=0), 14), (replace(base, upper=9), 14),
            (replace(base, lower=10, upper=8), 14), (replace(base, submitted=6), 14),
            (replace(base, ids=(ZERO, *base.ids[1:]), version=0), 1),
            (replace(base, artifacts=(ZERO, base.artifacts[1])), 1),
        ))
        self.once(cases)

    def test_real_pre_provider_order_and_no_economic_effect(self):
        base = Statement()
        wrong = changed(base.evidence(), 0, word(50))
        zero_payload = changed(wrong, 5, ZERO)
        disabled = (replace(DEFAULT[0], enabled=False), *DEFAULT[1:])
        expired = (replace(DEFAULT[0], expires=9, revoked=9), *DEFAULT[1:])
        cases = [
            (frame(base, rows=DEFAULT), 0),
            (frame(base, rows=DEFAULT, height=8), 0),
            (frame(base, rows=DEFAULT, height=18), 0),
            (frame(base, rows=DEFAULT, height=19), 16),
            (frame(base, rows=DEFAULT, height=7), 16),
            (frame(base, rows=DEFAULT, evidence=wrong, height=19), 15),
            (frame(base, rows=DEFAULT, evidence=zero_payload, height=19), 1),
            (frame(base, rows=disabled, evidence=zero_payload, height=19, claim=ZERO), 14),
            (frame(base, rows=disabled, evidence=zero_payload, height=19), 9),
            (frame(base, rows=expired, evidence=wrong, height=19), 11),
            (frame(base, rows=expired, evidence=wrong, height=9), 12),
            (frame(base, rows=expired, height=8), 0),
            (frame(replace(base, version=2), rows=DEFAULT, evidence=zero_payload), 7),
            (frame(replace(base, row=replace(base.row, digest=word(54))), rows=DEFAULT), 8),
            (frame(base, rows=DEFAULT[:-1], claim=ZERO), 6),
        ]
        cases += [(frame(base, rows=DEFAULT, evidence=changed(base.evidence(), index, word(50))), 15)
                  for index in range(5)]
        cases += [(frame(base, rows=DEFAULT, evidence=changed(base.evidence(), index, ZERO)), 1)
                  for index in range(6)]
        bound = replace(base, lower=HI, upper=HI, submitted=HI)
        cases.append((frame(bound, rows=DEFAULT[::-1], height=HI), 0))
        self.once(cases)

    def test_private_capacity_and_no_partial_output(self):
        base = Statement()
        valid = frame(base, rows=DEFAULT)
        created = frame(base)
        rows = [(valid, 102), (created, 102), (created, 102), (valid[:-1], 100),
                (valid + b"x", 100), (b"", 100), (b"BAD!" + valid[4:], 100),
                (frame(base, rows=DEFAULT, evidence=changed(base.evidence(), 0, ZERO)), 1)]
        self.once(rows, expected=[b""] * len(rows), sizes=[
                  (128, WORK), (31, WORK), (136, WORK - 1), (136, WORK),
                  (136, WORK), (136, WORK), (136, WORK), (0, WORK)])


if __name__ == "__main__":
    unittest.main()
