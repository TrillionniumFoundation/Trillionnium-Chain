"""Pure canonical M11 integer-linear context is identical to the original Rust API."""
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
from hia.tests.test_verification_profile_registry import ROOT, RUST

SRC = ROOT / "hia/src/verification/integer_linear_context.hepta"
ORIGINAL = RUST.with_name("exact_integer_linear_v1.rs")
ADAPTER = Path(__file__).with_name("rust_integer_linear_context_reference.rs")
FAMILY = bytes.fromhex("89b918183308ee94cc4e45575ac12f74d5de704d385289dbe2752daa13a47cef")
OUT, WORK = 469, 1632
MARK, FILL = b"\xa5", b"\x49"
DOMAIN = b"integer-linear-insertion-contract-v1"


def canonical(family, parent, slot):
    return (f'{{"columns":257,"delta_bound":32767,"factor_bound":32767,"family":"{family.hex()}",'
            '"numeric":"exact-BA-no-rounding-fixed-router-add-to-delta-v1",'
            f'"parent_artifact":"{parent.hex()}","rank_max":8,"rows":3,"scale":1024,'
            f'"schema":"pon-exact-integer-linear-insertion-v1","slot":{slot}}}').encode("ascii")


def typed(family, parent, slot):
    return family + parent + bytes([slot])


def frame(op, body):
    return b"ILC1" + struct.pack("<I", op) + body


def changed(raw, where, replacement):
    return raw[:where] + replacement + raw[where + len(replacement):]


def build_reference(work):
    original = ORIGINAL.read_bytes()
    opening = original.index(b"use sha2::{Digest, Sha256};")
    original = original[opening:].removeprefix(b"use sha2::{Digest, Sha256};\n")
    sha = SHA_ADAPTER.read_bytes()
    sha = sha[sha.index(b"use std::io"):sha.index(b"fn array")]
    source = work / "original-context.rs"
    source.write_bytes(sha + original + ADAPTER.read_bytes())
    pin = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    version = subprocess.run(["rustc", "--version"], check=True, capture_output=True,
                             timeout=10, text=True).stdout.split()
    if version[:2] != ["rustc", pin]:
        raise ValueError("original integer-linear context requires pinned Rust")
    binary = work / "original-context"
    subprocess.run(["rustc", "--edition=2024", "-Dwarnings", source, "-o", binary],
                   check=True, timeout=30)
    return binary


class IntegerLinearContext(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        scratch = Path(cls.enterClassContext(tempfile.TemporaryDirectory(prefix="trnm-ilc-")))
        cls.oracle = build_reference(scratch)
        cls.modules = {mode: cls.enterClassContext(NativeModule(
            SRC, backend=mode, byte_exports=("f0",))) for mode in ("direct", "selfhost")}
        if len({v.artifact_sha256 for v in cls.modules.values()}) != 2:
            raise ValueError("expected independently emitted native images")

    def original(self, cases):
        stream = b"".join(struct.pack("<BH", op, len(data)) + data for op, data in cases)
        got = subprocess.run([self.oracle], input=stream, capture_output=True, check=True, timeout=45)
        self.assertEqual(got.stderr, b"")
        data, result = got.stdout, []
        for _ in cases:
            self.assertTrue(data)
            status = data[0]
            extent = 0 if status else OUT
            result.append((status, data[1:1 + extent]))
            data = data[1 + extent:]
        self.assertEqual(data, b"")
        return result

    def emitted(self, wires, expected, sizes=None):
        sizes = [(OUT + 11, WORK + 9)] * len(wires) if sizes is None else sizes
        requests = [("f0", [wire, MARK * ks, FILL * ws])
                    for wire, (ks, ws) in zip(wires, sizes, strict=True)]
        for backend, mod in self.modules.items():
            for i, (got, (_, args), (status, result)) in enumerate(zip(
                    mod.call_many(requests, timeout=55), requests, expected, strict=True)):
                with self.subTest(backend=backend, row=i):
                    got.require_returned()
                    self.assertEqual(got.value, status)
                    self.assertEqual(got.arguments[0], args[0])
                    self.assertEqual(got.arguments[1], result + args[1][len(result):])
                    self.assertEqual(got.arguments[2][WORK:], args[2][WORK:])

    def once(self, cases):
        result = self.original(cases)
        self.emitted([frame(op, body) for op, body in cases], result)
        return result

    def test_exact_context_projection_and_pinned_identity_in_both_directions(self):
        rng = random.Random(724143)
        parents = [bytes(32), bytes([255]) * 32, bytes(range(32))]
        parents += [rng.randbytes(32) for _ in range(24)]
        cases = []
        payloads = []
        for parent in parents:
            for slot in range(3):
                data = canonical(FAMILY, parent, slot)
                self.assertEqual(len(data), 372)
                cases.extend(((0, typed(FAMILY, parent, slot)), (1, data)))
                digest = hashlib.sha256(b"TRNM-PON1\0" + struct.pack("<H", len(DOMAIN)) + DOMAIN +
                                        struct.pack("<I", len(data)) + data).digest()
                payloads.extend([(0, FAMILY + parent + bytes([slot]) + digest + data)] * 2)
        self.assertEqual(self.once(cases), payloads)

    def test_complete_u8_slots_syntax_and_original_error_precedence(self):
        parent = bytes(range(32))
        good = canonical(FAMILY, parent, 0)
        other = bytes([FAMILY[0] ^ 1]) + FAMILY[1:]
        bad_family = changed(good, 66, other.hex().encode())
        cases = [(0, typed(FAMILY, parent, n)) for n in range(256)]
        cases += [(0, typed(other, parent, 255)), (1, b""), (1, good[:-1]), (1, good + b"x"),
                  (1, changed(bad_family, 370, b"9")),
                  (1, changed(bad_family, 370, b"Z")),
                  (1, changed(bad_family, 285, b" ")),
                  (1, changed(bad_family, 213, b"A")),
                  (1, changed(good, 370, b"-1")), (1, changed(good, 370, b"00")),
                  (1, changed(good, 370, b"-0")), (1, changed(good, 370, b"9")),
                  (1, changed(good, 66, b"A")), (1, changed(good, 213, b"\\"))]
        result = self.once(cases)
        self.assertEqual([s for s, _ in result], [0] * 3 + [4] * 253 +
                         [3, 1, 1, 1, 3, 2, 2, 2, 2, 2, 2, 4, 2, 2])

    def test_every_json_byte_has_exact_original_error_and_local_bounds(self):
        good = canonical(FAMILY, bytes([0xa5]) * 32, 2)
        tests = [(1, changed(good, i, bytes([b ^ 0x80]))) for i, b in enumerate(good)]
        self.assertEqual(self.once(tests), [(2, b"")] * len(good))
        result = self.original([(1, good)])[0]
        valid = frame(1, good)
        encode = frame(0, typed(FAMILY, bytes([0xa5]) * 32, 2))
        runs = [
            (b"", (100, b""), OUT, WORK), (b"ILC", (100, b""), OUT, WORK),
            (b"bad!" + valid[4:], (100, b""), OUT, WORK),
            (changed(valid, 4, b"\x02"), (100, b""), OUT, WORK),
            (changed(valid, 6, b"\x01"), (100, b""), OUT, WORK),
            (valid[0:8], (1, b""), OUT, WORK),
            (encode[:-1], (100, b""), OUT, WORK), (encode+b"x", (100, b""), OUT, WORK),
            (valid, (102, b""), OUT-1, WORK), (valid, (102, b""), OUT, WORK-1),
            (encode, (102, b""), 0, WORK), (encode, result, OUT, WORK),
            (valid, result, OUT, WORK),
        ]
        self.emitted([r[0] for r in runs], [r[1] for r in runs], [(r[2],r[3]) for r in runs])
