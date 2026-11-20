"""Real native research CBOR primitives against the untouched original Rust.

The Python driver supplies borrowed inputs and records native results. The Rust
oracle includes the original module byte for byte, so decoder cursor advancement,
error order, UTF-8 validation and exact framing come from the retained methods.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import random
import struct
import subprocess
import tempfile
import unittest

from hia.tests.native_support import NativeModule

ROOT = Path(__file__).resolve().parents[2]
SOURCES = ROOT / "hia/src/research_protocol"
ORIGINAL = ROOT / "trillionnium/crates/trnm-research-protocol/src/canonical.rs"
REFERENCE = ROOT / "hia/tests/rust_research_canonical_reference.rs"
MAX = (1 << 64) - 1
EXTREMA = (0, 1, 22, 23, 24, 25, 254, 255, 256, 257, 65534, 65535,
           65536, 65537, (1 << 32) - 1, 1 << 32, (1 << 32) + 1, MAX)


def wire(op, payload=b"", *, argument=0, cursor=0):
    return struct.pack("<4sB3xQQ", b"RCB1", op, argument, cursor) + payload


def hash_wire(domain, message):
    return b"RCH1" + struct.pack("<I", len(domain)) + domain + message


def header(major, value):
    if value < 24:
        return bytes(((major << 5) | value,))
    for maximum, info, width in ((255, 24, 1), (65535, 25, 2),
                                  ((1 << 32) - 1, 26, 4), (MAX, 27, 8)):
        if value <= maximum:
            return bytes(((major << 5) | info,)) + value.to_bytes(width, "big")
    raise AssertionError(value)


def build_original(directory):
    """Build the retained workspace graph; select its exact dependency artifacts."""
    before = ORIGINAL.read_bytes()
    command = ["cargo", "build", "--manifest-path", str(ROOT / "trillionnium/Cargo.toml"),
               "--target-dir", str(Path(directory) / "original-target"),
               "--locked", "--offline", "-p", "trnm-research-protocol",
               "--message-format=json"]
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                            check=False, timeout=240)
    if result.returncode:
        raise AssertionError("Original research workspace build failed:\n" + result.stderr)
    dependencies = {}
    for line in result.stdout.splitlines():
        row = json.loads(line)
        if row.get("reason") != "compiler-artifact":
            continue
        name = row["target"]["name"]
        package = row["package_id"]
        if ((name == "sha2" and "0.10." in package)
                or (name == "thiserror" and "1.0." in package)):
            paths = [Path(p) for p in row["filenames"] if p.endswith(".rlib")]
            if len(paths) != 1:
                raise AssertionError("Ambiguous original dependency artifact")
            dependencies[name] = paths[0]
    if set(dependencies) != {"sha2", "thiserror"}:
        raise AssertionError("Missing original sha2/thiserror artifacts")
    output = Path(directory) / "research-canonical-original"
    args = ["rustc", "--edition=2021", "--deny=warnings", str(REFERENCE), "-o", str(output)]
    for name, path in sorted(dependencies.items()):
        args.extend(["--extern", name + "=" + str(path)])
    for path in sorted({p.parent for p in dependencies.values()}):
        args.extend(["-L", "dependency=" + str(path)])
    env = dict(os.environ, TRNM_RESEARCH_CANONICAL_SOURCE=str(ORIGINAL))
    subprocess.run(args, env=env, capture_output=True, text=True, check=True, timeout=60)
    if ORIGINAL.read_bytes() != before:
        raise AssertionError("Original module changed during native oracle construction")
    return output, {"source_sha256": hashlib.sha256(before).hexdigest(),
                    "binary_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
                    "dependency_sha256": {n: hashlib.sha256(p.read_bytes()).hexdigest()
                                          for n, p in dependencies.items()}}


class ResearchCanonicalNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="trnm-research-canonical-")
        cls.modules = {}
        try:
            cls.oracle, cls.original_identity = build_original(cls.temporary.name)
            for name in ("canonical", "hash"):
                cls.modules[name] = NativeModule(SOURCES / (name + ".hepta"), byte_exports=("f0",))
        except BaseException:
            for module in cls.modules.values():
                module.close()
            cls.temporary.cleanup()
            raise
        cls.observations = {"canonical": 0, "hash": 0, "adapter_refusals": 0}

    @classmethod
    def tearDownClass(cls):
        print(json.dumps({"schema": "trnm.hia.research-canonical-observation.v1",
            "backend": "selfhost", "counts": cls.observations,
            "original": cls.original_identity,
            "native": {name: {"source_sha256": hashlib.sha256(module.source.read_bytes()).hexdigest(),
                               "artifact_sha256": module.artifact_sha256,
                               "compiler_sha256": module.receipt["compiler_sha256"]}
                       for name, module in cls.modules.items()}}, sort_keys=True))
        for module in cls.modules.values():
            module.close()
        cls.temporary.cleanup()

    def compare(self, raws, *, module="canonical"):
        raws = list(raws)
        for start in range(0, len(raws), 96):
            batch = raws[start:start + 96]
            reference = subprocess.run([str(self.oracle)], input="".join(raw.hex() + "\n" for raw in batch),
                                       text=True, capture_output=True, check=True, timeout=30)
            lines = reference.stdout.splitlines()
            self.assertEqual(len(lines), len(batch))
            calls = []
            for raw in batch:
                capacity = max(64, len(raw) + 96)
                calls.append(("f0", [raw, b"\xa5" * capacity, b"\x5a" * (1241 if module == "hash" else 53)]))
            observed = self.modules[module].call_many(calls, timeout=60)
            for raw, (_, sent), actual, line in zip(batch, calls, observed, lines):
                fields = line.split()
                code, cursor, a, b, c = map(int, fields[:5])
                encoded = bytes.fromhex(fields[5]) if len(fields) > 5 else b""
                actual.require_returned()
                with self.subTest(module=module, prefix=raw[:33].hex(), size=len(raw)):
                    self.assertEqual(actual.value, code)
                    self.assertEqual(actual.arguments[0], raw)
                    self.assertEqual(actual.arguments[2][1208 if module == "hash" else 32:],
                                     sent[2][1208 if module == "hash" else 32:])
                    if module == "hash":
                        expected = encoded + sent[1][32:] if code == 0 else sent[1]
                    elif raw[4] < 7:
                        expected = (struct.pack("<4Q", cursor, a, b, c) + encoded
                                    + sent[1][32 + len(encoded):]) if code == 0 else sent[1]
                    else:
                        expected = struct.pack("<4Q", cursor, a, b, c) + sent[1][32:]
                    self.assertEqual(actual.arguments[1], expected)
                    self.observations[module] += 1

    def test_all_encoder_methods_and_shortest_integer_boundaries(self):
        rows = [wire(op, argument=value, cursor=cursor)
                for op in (0, 3) for value in EXTREMA for cursor in (0, 1, 7, 31)]
        for n in (0, 1, 2, 23, 24, 25, 255, 256, 257, 1024, 65535, 65536):
            payload = bytes((i * 73 + 19) % 256 for i in range(n))
            rows.extend(wire(1, payload, cursor=cursor) for cursor in (0, 3))
        for text in ("", "ASCII\0", "稻", "é", "a\u07ff\u0800\ud7ff\ue000\U0010ffff", "🌾" * 256):
            rows.append(wire(2, text.encode(), cursor=5))
        rows.extend((wire(4, argument=0), wire(4, argument=1), wire(5),
                     wire(6), wire(6, bytes(range(32)), argument=1)))
        self.compare(rows)

    def test_decoder_head_type_precedence_and_every_first_byte(self):
        rows = []
        for major in range(8):
            for value in EXTREMA:
                data = header(major, value)
                rows.extend(wire(op, data, argument=32) for op in (16, 17, 18, 19, 20, 21, 25))
        for first in range(256):
            for tail in (b"", b"\x00", b"\x00" * 8, b"\xff" * 8):
                rows.extend(wire(op, bytes((first,)) + tail, argument=32)
                            for op in (16, 17, 19, 21, 22, 23, 25))
        self.compare(rows)

    def test_nonminimal_reserved_truncated_and_u64_overflow_lengths(self):
        rows = []
        for major in range(8):
            for additional, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
                for value in (0, 1, 23, 24, 255):
                    if value >= 1 << (8 * width):
                        continue
                    raw = bytes(((major << 5) | additional,)) + value.to_bytes(width, "big")
                    rows.extend(wire(op, raw[:n], argument=32) for n in range(len(raw) + 1)
                                for op in (16, 18, 19, 20, 21, 25))
            rows.extend(wire(25, bytes(((major << 5) | info,))) for info in range(28, 32))
        for major in (2, 3, 4):
            for value in (MAX, MAX - 1, (1 << 63), 65536):
                for cursor in (0, 1, 7):
                    payload = b"\xa5" * cursor + header(major, value)
                    rows.extend(wire(op, payload, argument=MAX if op == 21 else 32, cursor=cursor)
                                for op in (17, 18, 19, 20, 21))
        self.compare(rows)

    def test_borrowed_spans_optional_digest_bounds_and_exact_cursor(self):
        rows = []
        for n in (0, 1, 2, 23, 24, 31, 32, 33, 255, 256, 1024):
            body = bytes((i * 13) % 256 for i in range(n))
            for cursor in (0, 3, 11):
                raw = b"P" * cursor + header(2, n) + body + b"TAIL"
                rows.extend(wire(op, raw, argument=expected, cursor=cursor)
                            for op in (19, 20, 23) for expected in (0, 1, 31, 32, 33, 256))
                rows.append(wire(24, raw, cursor=cursor + len(header(2, n)) + n))
                rows.append(wire(24, raw, cursor=len(raw)))
        rows.extend(wire(op, value, argument=1, cursor=cursor)
                    for op in (16, 19, 21, 22, 23, 24, 25)
                    for value in (b"", b"\xf4", b"\xf5", b"\xf6", b"\x00", b"\x80")
                    for cursor in (0, 1, MAX))
        self.compare(rows)

    def test_utf8_scalar_ranges_and_bound_before_missing_body(self):
        payloads = [bytes((i,)) for i in range(256)]
        for cp in (0, 0x7f, 0x80, 0x7ff, 0x800, 0xd7ff, 0xe000, 0xffff, 0x10000, 0x10ffff):
            raw = chr(cp).encode()
            payloads.extend((raw, b"a" + raw + b"z"))
            payloads.extend(raw[:n] for n in range(len(raw)))
        for lead in range(192, 256):
            for continuation in (0, 127, 128, 143, 144, 159, 160, 191, 192, 255):
                payloads.extend((bytes((lead, continuation)), bytes((lead, continuation, 128)),
                                 bytes((lead, continuation, 128, 128))))
        rows = [wire(21, header(3, len(raw)) + raw, argument=bound)
                for raw in payloads for bound in (0, 1, 3, 4, 32)]
        rows += [wire(21, header(3, length), argument=bound)
                 for length in (1, 24, 256, MAX) for bound in (0, 1, 32, MAX)]
        rows += [wire(2, raw) for raw in payloads]
        self.compare(rows)

    def test_random_decoder_inputs_match_original_errors_and_consumption(self):
        rng = random.Random(0x52434231)
        rows = []
        for _ in range(1600):
            raw = rng.randbytes(rng.randrange(42))
            op = rng.choice((16, 17, 18, 19, 20, 21, 22, 23, 24, 25))
            rows.append(wire(op, raw, argument=rng.choice((0, 1, 2, 8, 32, 256)),
                             cursor=rng.randrange(len(raw) + 2)))
        self.compare(rows)

    def test_hash_original_domain_and_message_framing(self):
        rows = [hash_wire(domain, message)
                for domain in (b"", b"a", b"ab", b"\x00", "中国🌾".encode(), b"x" * 256)
                for message in (b"", b"c", b"bc", bytes(range(256)), b"x" * 1024)]
        for n in (1, 23, 24, 31, 32, 55, 56, 63, 64, 65, 127, 128, 1023, 65536, 131136):
            rows.append(hash_wire(b"research/v1", bytes((i * 73 + 19) % 256 for i in range(n))))
        self.compare(rows, module="hash")
        for raw in rows:
            n = int.from_bytes(raw[4:8], "little")
            expected = hashlib.sha256(b"TRNM_RESEARCH_PROTOCOL_HASH_V1\0"
                + n.to_bytes(4, "big") + raw[8:8+n]
                + (len(raw)-8-n).to_bytes(8, "big") + raw[8+n:]).digest()
            got = self.modules["hash"].call("f0", [raw, b"\xa5" * 45, b"\x5a" * 1241]).require_returned()
            self.assertEqual(got.arguments[1][:32], expected)

    def test_adapter_refuses_invalid_buffers_frames_and_output_overflow(self):
        rows = []
        valid = wire(0, argument=MAX)
        rows.extend(("canonical", valid[:n], 80, 53, 65) for n in range(24))
        for position in (0, 1, 2, 3, 5, 6, 7):
            corrupt = bytearray(valid); corrupt[position] ^= 1
            rows.append(("canonical", bytes(corrupt), 80, 53, 65))
        rows += [("canonical", wire(op), 80, 53, 65) for op in (7, 15, 26, 255)]
        rows += [("canonical", valid, n, 53, 64) for n in (0, 1, 31, 32, 40)]
        rows += [("canonical", valid, 80, n, 64) for n in (0, 1, 31)]
        rows += [("canonical", wire(0, cursor=MAX), 80, 53, 64),
                 ("canonical", wire(1, b"hello", cursor=48), 80, 53, 64),
                 ("canonical", wire(0, b"unexpected"), 80, 53, 65),
                 ("canonical", wire(4, argument=2), 80, 53, 65),
                 ("canonical", wire(6, b"short", argument=1), 80, 53, 65)]
        good_hash = hash_wire(b"a", b"b")
        rows += [("hash", good_hash, 31, 1241, 64),
                 ("hash", good_hash, 40, 1207, 64),
                 ("hash", b"BAD!" + good_hash[4:], 40, 1241, 65),
                 ("hash", b"RCH1\xff\xff\xff\xff", 40, 1241, 65),
                 ("hash", hash_wire(b"\xc0\xaf", b"x"), 40, 1241, 5)]
        for module, raw, outlen, worklen, code in rows:
            output, scratch = b"\xa5" * outlen, b"\x5a" * worklen
            got = self.modules[module].call("f0", [raw, output, scratch]).require_returned()
            self.assertEqual(got.value, code, (module, raw.hex(), outlen, worklen))
            self.assertEqual(got.arguments[0], raw)
            self.assertEqual(got.arguments[1], output)
            self.assertEqual(got.arguments[2][1208 if module == "hash" else 32:],
                             scratch[1208 if module == "hash" else 32:])
            self.observations["adapter_refusals"] += 1


if __name__ == "__main__":
    unittest.main()
