"""Native external keys against actual retained public methods and independent SHA-256."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import random
import struct
import subprocess
import tempfile
import unittest

from hia.tests.native_support import NativeModule

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/research_protocol/external_key.hepta"
REFERENCE = ROOT / "hia/tests/rust_research_external_key_reference.rs"
ORIGINAL = ROOT / "trillionnium/crates/trnm-research-protocol"
UUID = b"01234567-89ab-cdef-0123-456789abcdef"
DOMAIN = b"TRNM_RESEARCH_EXTERNAL_KEY_V1\0"


def wire(op, namespace=b"", value=b""):
    return b"REK1" + bytes((op, 0)) + struct.pack("<H", len(namespace)) + namespace + value


def build_original(directory):
    before = {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in sorted(ORIGINAL.rglob("*.rs"))}
    before[str(ORIGINAL / "Cargo.toml")] = hashlib.sha256((ORIGINAL / "Cargo.toml").read_bytes()).hexdigest()
    result = subprocess.run(["cargo", "build", "--manifest-path", str(ROOT / "trillionnium/Cargo.toml"),
                             "--target-dir", str(Path(directory) / "original-target"),
                             "--locked", "--offline", "-p", "trnm-research-protocol", "--message-format=json"],
                            cwd=ROOT, capture_output=True, text=True, timeout=240, check=False)
    if result.returncode:
        raise AssertionError("Original Research crate build failed:\n" + result.stderr)
    artifacts = []
    dependencies = {}
    for line in result.stdout.splitlines():
        row = json.loads(line)
        if row.get("reason") != "compiler-artifact":
            continue
        paths = [Path(p) for p in row["filenames"] if p.endswith(".rlib")]
        for path in paths:
            dependencies[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
        if row["target"]["name"] == "trnm_research_protocol":
            artifacts.extend(paths)
    if len(artifacts) != 1:
        raise AssertionError("Ambiguous or absent actual original Research library")
    output = Path(directory) / "research-external-key-original"
    args = ["rustc", "--edition=2021", "--deny=warnings", str(REFERENCE), "-o", str(output),
            "--extern", "trnm_research_protocol=" + str(artifacts[0])]
    for directory in sorted({Path(p).parent for p in dependencies}):
        args += ["-L", "dependency=" + str(directory)]
    compiled = subprocess.run(args,
                              cwd=ROOT, capture_output=True, text=True, timeout=60, check=False)
    if compiled.returncode:
        raise AssertionError("Original Research public adapter compile failed:\n" + compiled.stderr)
    if any(hashlib.sha256(Path(p).read_bytes()).hexdigest() != value for p, value in before.items()):
        raise AssertionError("Original sources changed while constructing the reference")
    return output, {"sources": before, "crate_sha256": hashlib.sha256(artifacts[0].read_bytes()).hexdigest(),
                    "binary_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
                    "dependency_sha256": dependencies}


class ResearchExternalKeyNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="trnm-research-external-key-")
        try:
            cls.oracle, cls.original = build_original(cls.directory.name)
            cls.module = NativeModule(SOURCE, byte_exports=("f0",))
        except BaseException:
            cls.directory.cleanup()
            raise
        cls.compared = cls.independent = cls.refused = 0

    @classmethod
    def tearDownClass(cls):
        print(json.dumps({"schema": "trnm.hia.research-external-key-observation.v1",
                          "original_native_pairs": cls.compared, "independent_hashes": cls.independent,
                          "abi_controls": cls.refused, "original": cls.original,
                          "native": {"source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                                     "artifact_sha256": cls.module.artifact_sha256,
                                     "compiler_sha256": cls.module.receipt["compiler_sha256"]}}, sort_keys=True))
        cls.module.close()
        cls.directory.cleanup()

    def compare(self, raws):
        for start in range(0, len(raws), 96):
            batch = raws[start:start + 96]
            reference = subprocess.run([str(self.oracle)], input="".join(raw.hex() + "\n" for raw in batch),
                                       capture_output=True, text=True, timeout=30, check=True)
            lines = reference.stdout.splitlines()
            self.assertEqual(len(lines), len(batch))
            calls = [("f0", [raw, b"\xa5" * 147, b"\x5a" * 1241]) for raw in batch]
            observed = self.module.call_many(calls, timeout=60)
            for raw, line, actual in zip(batch, lines, observed):
                fields = line.split()
                code = int(fields[0])
                expected = bytes.fromhex(fields[1]) + b"\xa5" * 17 if code == 0 else b"\xa5" * 147
                actual.require_returned()
                with self.subTest(request=raw[:96].hex(), length=len(raw)):
                    self.assertEqual(actual.value, code)
                    self.assertEqual(actual.arguments[0], raw)
                    self.assertEqual(actual.arguments[1], expected)
                    self.assertEqual(actual.arguments[2][1208:], b"\x5a" * 33)
                    if code:
                        self.assertEqual(actual.arguments[2], b"\x5a" * 1241)
                    if not code and raw[4] in (1, 2):
                        n = int.from_bytes(raw[6:8], "little")
                        namespace, value = raw[8:8+n], raw[8+n:]
                        value = bytes.fromhex(value.decode().replace("-", "")) if raw[4] == 1 else value
                        independent = hashlib.sha256(DOMAIN + len(namespace).to_bytes(2, "big") + namespace
                                                     + raw[4:5] + len(value).to_bytes(2, "big") + value).digest()
                        self.assertEqual(actual.arguments[1][:32], independent)
                        type(self).independent += 1
                    type(self).compared += 1

    def test_namespace_characters_lengths_and_error_order(self):
        rows = [wire(op, bytes((byte,)), value) for byte in range(128)
                for op, value in ((1, UUID), (2, b"external-id"))]
        rows += [wire(op, namespace, value) for namespace in (b"", b"a" * 64, b"a" * 65,
                 b"a.b-c_d:019", b"a" * 65535, "研究".encode(), "é".encode())
                 for op, value in ((1, UUID), (1, b"bad-uuid"), (2, b""), (2, b"a\\b"))]
        self.compare(rows)

    def test_uuid_every_position_and_canonical_lowercase_rules(self):
        rows = [wire(1, b"research", UUID[:index] + bytes((value,)) + UUID[index + 1:])
                for index in range(36) for value in range(128)]
        rows += [wire(1, b"research", UUID[:n]) for n in range(36)]
        rows += [wire(1, b"research", value) for value in (
            UUID + b"0", b"00000000-0000-0000-0000-000000000000", b"ffffffff-ffff-ffff-ffff-ffffffffffff",
            UUID.upper(), UUID.replace(b"-", b""), "00000000-0000-0000-0000-00000000000é".encode())]
        self.compare(rows)

    def test_external_identifiers_visible_ascii_and_length_boundaries(self):
        rows = [wire(2, b"research", b"prefix" + bytes((value,)) + b"suffix") for value in range(128)]
        rows += [wire(2, b"research", value) for value in (b"", b"a", b"x" * 255, b"x" * 256,
            b"x" * 257, b" x", b"x ", b"a\\b", b"~!@#$%^&*()_+-={}[]:;\"'<>,.?/|", "é".encode(), "研究".encode())]
        self.compare(rows)

    def test_raw_key_all_bits_hex_display_and_cbor(self):
        values = [bytes(32), b"\xff" * 32, bytes(range(32))]
        values += [(1 << index).to_bytes(32, "little") for index in range(256)]
        randomizer = random.Random(0x4558544B4559)
        values += [randomizer.randbytes(32) for _ in range(96)]
        self.compare([wire(3, value=value) for value in values])

    def test_domain_namespace_and_identifier_kind_separation(self):
        namespaces = (b"a", b"a-b", b"a_b", b"a.b", b"a:b", b"0", b"x" * 64)
        rows = [wire(op, namespace, value) for namespace in namespaces
                for op, value in ((1, UUID), (2, UUID), (2, b"id"), (2, b"ID"), (2, b"x" * 256))]
        self.compare(rows)

    def test_abi_capacity_shape_and_no_partial_output(self):
        valid = wire(1, b"research", UUID)
        cases = [(raw, 130, 1208, 65) for raw in (b"", valid[:7], b"X" + valid[1:],
            valid[:5] + b"\x01" + valid[6:], wire(0), wire(4), wire(3, b"a", bytes(32)),
            wire(3, value=bytes(31)), wire(3, value=bytes(33)), b"REK1\x01\0\xff\xff")]
        cases += [(valid, size, 1208, 64) for size in (0, 1, 31, 32, 129)]
        cases += [(valid, 130, size, 64) for size in (0, 1, 1167, 1207)]
        cases += [(valid, 130, 1208, 0), (wire(3, value=bytes(32)), 130, 1208, 0)]
        cases += [(wire(1, b"\xff", UUID), 130, 1208, 1),
                  (wire(1, b"research", b"\xff" * 36), 130, 1208, 2),
                  (wire(2, b"research", b"\xff"), 130, 1208, 3)]
        for raw, out_size, scratch_size, wanted in cases:
            output, scratch = b"\xa5" * out_size, b"\x5a" * scratch_size
            got = self.module.call("f0", [raw, output, scratch]).require_returned()
            with self.subTest(size=(len(raw), out_size, scratch_size), wanted=wanted):
                self.assertEqual(got.value, wanted)
                self.assertEqual(got.arguments[0], raw)
                if wanted:
                    self.assertEqual(got.arguments[1:], [output, scratch])
                type(self).refused += 1


if __name__ == "__main__":
    unittest.main()
