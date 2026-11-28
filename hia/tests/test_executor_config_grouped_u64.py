"""Compare machine code with the unchanged Rust executor environment parser."""
from __future__ import annotations

import itertools
import os
from pathlib import Path
import random
import re
import subprocess
import tempfile
import unittest

from hia.tests.native_support import NativeModule

ROOT = Path(__file__).resolve().parents[2]
ORIGINAL = ROOT / "trillionnium/crates/trnm-executor/src/env_config.rs"
ACTIVE = ORIGINAL.with_name("lib.rs")
REFERENCE = ROOT / "hia/tests/rust_executor_config_grouped_u64_reference.rs"
NATIVE = ROOT / "hia/src/executor/config_grouped_u64.hepta"
MAX_U64 = 2**64 - 1
OUTPUT = b"\xa5" * 13
SCRATCH = b"\xbc" * 11
WHITE_SPACE = "\t\n\v\f\r \u0085\u00a0\u1680" + "".join(
    chr(codepoint) for codepoint in range(0x2000, 0x200B)
) + "\u2028\u2029\u202f\u205f\u3000"
FIXED = {
    b"": None, b"+": None, b"___": None, b",": None, b"  ": None,
    b"0": 0, b" 0 ": 0, b"' '": None, b"+0": 0, b"++0": 0,
    b"+_+_42": 42, b"+++1": None, b"++1,234": None,
    b"0_0,0_0_1": 1, b"1234,567": 1234567,
    b"1,1": None, b"1,02": None, b"1,008": 1008, b"1,0000": None,
    b",123": None, b"1,": None, b"1,,234": None, b"1,234,": None,
    b"1,234,005": 1234005, b"+,000": None, b"1,+000": None,
    b"' +1,234 '": 1234, b'" +1,234 "': 1234, b"'1\"": None,
    b"'1": None, b"''1''": None, b"+ 1": None, b"'_ 1'": None,
    b"18446744073709551615": MAX_U64, b"18446744073709551616": None,
    b"+018446744073709551615": MAX_U64, b"18,446,744,073,709,551,615": MAX_U64,
    b"18,446,744,073,709,551,616": None, b"99,999,999,999,999,999,999": None,
    b"00000000000000000000000000000": 0,
    b"\xff1": None, b"1\xe2\x80": None, b"\xc2\x851\x85": None,
}


def active_function(source):
    """Copy the exact production function, without exposing it on the crate ABI."""
    signature = rb"^fn parse_grouped_env_usize\(name: &str\) -> Option<usize> \{\n"
    blocks = re.findall(signature + rb".*?^\}\n", source, re.MULTILINE | re.DOTALL)
    if len(blocks) != 1 or len(re.findall(rb"^fn parse_grouped_env_usize\b", source,
                                        re.MULTILINE)) != 1:
        raise ValueError("Expected one unchanged-signature top-level executor parser")
    return blocks[0]


class ExecutorGroupedU64SourceTests(unittest.TestCase):
    def test_retains_exact_active_bytes_and_refuses_ambiguous_source(self):
        active = active_function(ACTIVE.read_bytes())
        self.assertEqual(active_function(b"// prefix\n" + active + b"// suffix\n"), active)
        for source in (b"", active + active, active.replace(b"&str", b"&String", 1)):
            with self.subTest(source=source[:65]):
                with self.assertRaisesRegex(ValueError, "one unchanged-signature"):
                    active_function(source)


class ExecutorGroupedU64Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        version = subprocess.run(
            ["rustc", "--version"], check=True, capture_output=True, text=True, timeout=10,
        ).stdout.split()
        if version[:2] != ["rustc", "1.95.0"]:
            raise ValueError("Chain's pinned rustc 1.95.0 is required")
        temp = tempfile.TemporaryDirectory(prefix="trnm-grouped-u64-reference-")
        cls.addClassCleanup(temp.cleanup)
        cls.reference = Path(temp.name) / "reference"
        active = Path(temp.name) / "active.rs"
        active.write_bytes(active_function(ACTIVE.read_bytes()))
        build = subprocess.run(
            ["rustc", "--edition=2021", "-C", "overflow-checks=yes", "-A", "dead_code",
             str(REFERENCE), "-o", str(cls.reference)],
            env={**os.environ, "TRNM_ORIGINAL_EXECUTOR_ENV_CONFIG": str(ORIGINAL),
                 "TRNM_ACTIVE_EXECUTOR_GROUPED_FUNCTION": str(active)},
            capture_output=True, text=True, timeout=30,
        )
        if build.returncode:
            raise RuntimeError(build.stderr)
        cls.backends = {}
        for backend in ("selfhost", "direct"):
            native = NativeModule(NATIVE, backend=backend, byte_exports=("f0",))
            cls.addClassCleanup(native.close)
            cls.backends[backend] = native

    def original(self, inputs):
        result = subprocess.run(
            [str(self.reference)], input="".join(raw.hex() + "\n" for raw in inputs),
            check=True, capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(result.stderr, "")
        values = [None if value == "-" else int(value) for value in result.stdout.splitlines()]
        self.assertEqual(len(values), len(inputs))
        return values

    def native(self, cases):
        for backend, native in self.backends.items():
            self.assertEqual(native.exports, frozenset({"f0"}))
            for pos in range(0, len(cases), 128):
                batch = cases[pos:pos + 128]
                results = native.call_many([("f0", (raw, output, SCRATCH))
                                            for raw, output, _ in batch])
                for actual, (raw, output, value) in zip(results, batch, strict=True):
                    actual.require_returned()
                    status = 1 if value is None else (2 if len(output) < 8 else 0)
                    expected = output if status else value.to_bytes(8, "little") + output[8:]
                    self.assertEqual((actual.value, actual.arguments),
                                     (status, [raw, expected, SCRATCH]), (backend, raw[:96]))

    def compare(self, inputs):
        values = self.original(inputs)
        self.native([(raw, OUTPUT, value) for raw, value in zip(inputs, values, strict=True)])
        return values

    def test_grouping_signs_and_overflow(self):
        self.assertEqual(self.compare(list(FIXED)), list(FIXED.values()))

    def test_rust_whitespace_inside_quotes_and_near_misses(self):
        inputs = [f"{ws}'{ws}+1_2,3_4_5{ws}'{ws}".encode() for ws in WHITE_SPACE]
        inputs += [f"{ws}0{ws}".encode() for ws in WHITE_SPACE]
        inputs += [f"1{ws}2".encode() for ws in WHITE_SPACE]
        untrimmed = "\u001c\u001d\u001e\u001f\u180e\u200b\u2060\ufeff\uff10"
        inputs += [f"{ws}1{ws}".encode() for ws in untrimmed]
        expected = ([12345] * len(WHITE_SPACE) + [0] * len(WHITE_SPACE)
                    + [None] * (len(WHITE_SPACE) + len(untrimmed)))
        self.assertEqual(self.compare(inputs), expected)

    def test_deterministic_differential_corpus(self):
        rng = random.Random(0xA80F396)
        inputs = [bytes(parts) for size in range(4)
                  for parts in itertools.product(b"0+, _'\"", repeat=size)]
        for _ in range(240):
            n = rng.randrange(1 << 64)
            plain, grouped = str(n), format(n, ",")
            inputs.extend((plain.encode(), grouped.encode(),
                           (rng.choice(("+", "++", "'")) + plain).encode()))
            template = rng.choice((plain, grouped))
            decorated = "".join(c + "_" * rng.randrange(3) for c in template)
            quote = rng.choice(("", '"', "'"))
            ws = rng.choice(WHITE_SPACE)
            inputs.append(f"{ws}{quote}{ws}+{decorated}{ws}{quote}{ws}".encode()
                          if quote else f"{ws}+{decorated}{ws}".encode())
            inputs.append(bytes(rng.randrange(1, 256) for _ in range(rng.randrange(1, 25))))
        self.compare(inputs)

    def test_output_capacity_and_atomic_failure(self):
        inputs = (b"0", b"18446744073709551615", b"1,2", b"1\0", b"\0")
        expected = [*self.original(inputs[:3]), None, None]
        self.native([(raw, OUTPUT[:size], value)
                     for raw, value in zip(inputs, expected, strict=True)
                     for size in (0, 1, 7, 8, 9, len(OUTPUT))])


if __name__ == "__main__":
    unittest.main()
