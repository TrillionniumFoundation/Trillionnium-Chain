"""Exact original closed registry and height-sensitive profile lookup."""
from dataclasses import dataclass, replace
from itertools import permutations
from pathlib import Path
import random
import re
import struct
import subprocess
import tempfile
import tomllib
import unittest

from hia.tests.native_support import NativeModule

ROOT = Path(__file__).resolve().parents[2]
NATIVE = ROOT / "hia/src/verification/profile_registry.hepta"
RUST = ROOT / "trillionnium/crates/trnm-verification-profiles/src/lib.rs"
ADAPTER = Path(__file__).with_name("rust_verification_profile_registry_reference.rs")
HI = (1 << 64) - 1
V32 = (1 << 32) - 1
KINDS = (0, 1, 2, 3, 5, 6)
ZERO = bytes(32)
MARK = b"\xa5"
SCRATCH = b"unchanged-registry-scratch"


@dataclass(frozen=True)
class Row:
    kind: int
    identity: bytes
    digest: bytes
    version: int = 1
    active: int = 5
    expires: int | None = None
    revoked: int | None = None
    enabled: bool = True
    objective: bool = False

    def wire(self):
        return (self.identity + self.digest
                + struct.pack("<IQQQBBBBB", self.version, self.active,
                              self.expires if self.expires is not None else 0,
                              self.revoked if self.revoked is not None else 0,
                              self.kind, self.enabled, self.expires is not None,
                              self.revoked is not None, self.objective))


def word(n):
    return bytes([n]) * 32


DEFAULT = tuple(Row(k, word(k + 1), word(k + 11), objective=k != 6) for k in KINDS)


def frame(rows=DEFAULT, query=None):
    head = b"VPR1" + struct.pack("<IQ", int(query is not None), len(rows))
    if query is None:
        return head + bytes(76) + b"".join(r.wire() for r in rows)
    identity, version, digest, height = query
    return head + identity + struct.pack("<I", version) + digest + struct.pack("<Q", height) + b"".join(
        r.wire() for r in rows)


def ask(row=DEFAULT[0], height=5):
    return (row.identity, row.version, row.digest, height)


def first(row):
    return (row, *DEFAULT[1:])


def pick(raw, expr):
    items = re.findall(expr, raw, re.M | re.S)
    if len(items) != 1:
        raise ValueError("Original API ownership changed")
    return items[0]


def build_reference(path):
    raw = RUST.read_bytes()
    before = raw.index(b"pub enum VerificationProfileKindV1")
    after = raw.index(b"pub struct VerificationStatementV1", before)
    a = raw.rfind(b"#[derive", 0, before)
    b = raw.rfind(b"#[derive", a, after)
    aliases = [pick(raw, rb"^pub type " + n + rb" = \[u8; 32\];\n")
               for n in (b"VerificationDigestV1", b"VerificationProfileIdV1")]
    helper = pick(raw, rb"^fn require_nonzero\([^\n]+\n.*?^}\n")
    source = path / "registry-original.rs"
    source.write_bytes(b"use std::{collections::{BTreeMap,BTreeSet},fmt};\n"
                       + b"".join(aliases) + raw[a:b] + helper + ADAPTER.read_bytes())
    pin = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    version = subprocess.run(["rustc", "--version"], check=True, capture_output=True,
                             timeout=10, text=True).stdout.split()
    if version[:2] != ["rustc", pin]:
        raise ValueError("Original verification registry requires its pinned Rust")
    binary = path / "policy-reference"
    subprocess.run(["rustc", "--edition=2024", "-Dwarnings", str(source), "-o", str(binary)],
                   check=True, timeout=30)
    return binary


class VerificationProfileRegistry(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        work = Path(cls.enterClassContext(tempfile.TemporaryDirectory(prefix="trnm-vpr-rust-")))
        cls.original = build_reference(work)
        cls.backends = {name: cls.enterClassContext(
            NativeModule(NATIVE, backend=name, byte_exports=("f0",))) for name in ("direct", "selfhost")}
        if cls.backends["direct"].artifact_sha256 == cls.backends["selfhost"].artifact_sha256:
            raise ValueError("Independent native images are required")

    def rust(self, frames):
        run = subprocess.run([self.original], input=b"".join(frames), check=True, capture_output=True, timeout=45)
        self.assertEqual(run.stderr, b"")
        pending, output = run.stdout, []
        for wire in frames:
            self.assertTrue(pending)
            error = pending[0]
            extent = 0 if error else 101 if wire[4] else 4
            self.assertGreaterEqual(len(pending), 1 + extent)
            output.append((error, pending[1:1 + extent]))
            pending = pending[1 + extent:]
        self.assertEqual(pending, b"")
        return output

    def check(self, frames, original, *, sizes=None):
        if sizes is None:
            sizes = [112] * len(frames)
        for emitter, module in self.backends.items():
            for start in range(0, len(frames), 96):
                n = start + 96
                cases = [("f0", [f, MARK * k, SCRATCH]) for f, k in zip(frames[start:n], sizes[start:n], strict=True)]
                actual = module.call_many(cases, timeout=30)
                for i, (asked, answer, (code, output)) in enumerate(zip(cases, actual, original[start:n], strict=True)):
                    with self.subTest(emitter=emitter, row=start + i):
                        answer.require_returned()
                        before, canary, scratch = asked[1]
                        self.assertEqual(answer.value, code)
                        self.assertEqual(answer.arguments, [before, output + canary[len(output):], scratch])

    def test_first_registry_error_and_competing_lookup_errors(self):
        identity = DEFAULT[0]
        disabled = replace(identity, enabled=False, expires=7, revoked=7)
        frontier = replace(identity, expires=7, revoked=7)
        maxrow = replace(identity, version=V32, active=HI, expires=HI)
        tests = [
            (frame(()), 6), (frame(DEFAULT[:-1]), 6), (frame(), 0),
            (frame(first(replace(identity, identity=ZERO, version=0))), 1),
            (frame(first(replace(identity, digest=ZERO, version=0))), 1),
            (frame(first(replace(identity, version=0, expires=4))), 2),
            (frame(first(replace(identity, expires=4))), 3),
            (frame(first(replace(identity, revoked=4))), 3),
            (frame((*DEFAULT[:-1], replace(DEFAULT[-1], objective=True, revoked=4))), 3),
            (frame((*DEFAULT[:-1], replace(DEFAULT[-1], objective=True))), 13),
            (frame((*DEFAULT, replace(identity, version=0))), 2),
            (frame((*DEFAULT, identity)), 4),
            (frame((*DEFAULT, identity, replace(identity, version=0)) + DEFAULT * 8), 4),
            (frame((identity, replace(DEFAULT[1], identity=identity.identity), *DEFAULT[2:])), 5),
            (frame((identity, replace(DEFAULT[1], identity=identity.identity, version=2), *DEFAULT[2:]),
                   (identity.identity, 2, DEFAULT[1].digest, 5)), 0),
            (frame(DEFAULT, (ZERO, 0, ZERO, 0)), 7),
            (frame(DEFAULT, (identity.identity, 2, identity.digest, 5)), 7),
            (frame(first(disabled), (identity.identity, 1, ZERO, 4)), 8),
            (frame(first(disabled), ask(disabled, 4)), 9),
            (frame(first(frontier), ask(frontier, 4)), 10),
            (frame(first(frontier), ask(frontier, 5)), 0),
            (frame(first(frontier), ask(frontier, 7)), 12),
            (frame(first(frontier), ask(frontier, 8)), 11),
            (frame(first(replace(frontier, revoked=None)), ask(frontier, 7)), 0),
            (frame(first(maxrow), ask(maxrow, HI - 1)), 10),
            (frame(first(maxrow), ask(maxrow, HI)), 0),
            (frame(first(replace(identity, active=0, expires=0)), ask(identity, 0)), 0),
            (frame(first(replace(identity, active=0, expires=0)), ask(identity, 1)), 11),
            (frame(first(replace(identity, active=0, revoked=0)), ask(identity, 0)), 12),
            (frame(DEFAULT, ask(identity, HI)), 0),
            (frame(DEFAULT, ask(DEFAULT[-1], HI)), 0),
        ]
        frames, expected = zip(*tests, strict=True)
        original = self.rust(frames)
        self.assertEqual([r[0] for r in original], list(expected))
        self.check(frames, original)

    def test_all_six_kind_permutations_resolve_without_fallback(self):
        frames = [frame(rows, ask(DEFAULT[-1], HI)) for rows in permutations(DEFAULT)]
        rng = random.Random(0x8321)
        for _ in range(80):
            rows = list(DEFAULT)
            rng.shuffle(rows)
            selected = rows[rng.randrange(6)]
            candidate = replace(selected, enabled=bool(rng.getrandbits(1)), active=rng.choice((0, 2, HI)),
                                version=rng.choice((1, V32)), expires=rng.choice((None, 5, HI)),
                                revoked=rng.choice((None, 0, HI)))
            rows[rows.index(selected)] = candidate
            frames.append(frame(rows, ask(candidate, rng.choice((0, 4, HI)))))
        original = self.rust(frames)
        self.assertTrue(all((code, value) == (0, b"\x06\0\0\0" + DEFAULT[-1].wire())
                            for code, value in original[:720]))
        self.check(frames, original)

    def test_wire_shape_capacity_and_no_partial_publish(self):
        good = frame(DEFAULT, ask())
        closed = frame()
        malformed = bytearray(good)
        malformed[92 + 92] = 4
        invalid_flag = bytearray(good)
        invalid_flag[92 + 93] = 2
        inconsistent = bytearray(good)
        inconsistent[92 + 76] = 1
        frames = [good, closed, frame(first(replace(DEFAULT[0], version=0)), ask()),
                  b"", good[:-1], good + b"\0", b"bad!" + good[4:], good[:4] + b"\x02" + good[5:],
                  good[:10] + b"\x01" + good[11:], bytes(malformed), bytes(invalid_flag),
                  bytes(inconsistent), frame(DEFAULT * 11)]
        expected = [(n, b"") for n in (102, 102, 2, *([100] * 10))]
        self.check(frames, expected, sizes=[100, 3, 0] + [110] * 10)


if __name__ == "__main__":
    unittest.main()
