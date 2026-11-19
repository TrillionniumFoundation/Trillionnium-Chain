"""Emitted HIA implements the complete original pure M02 consensus closure.

Python integers form an independent oracle; they never supply a runtime verdict,
limb, quotient or sorted window to the native program. The mandatory Rust test
compiles the exact original Node module and calls its actual functions.
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
SOURCE = ROOT / "hia/src/consensus/work.hepta"
ORIGINAL = ROOT / "trillionnium/crates/trnm-pon-node/src/consensus.rs"
REFERENCE = ROOT / "hia/tests/rust_consensus_reference.rs"
VECTORS = ROOT / "formal/pon-nakamoto-v1/vectors"
U64 = (1 << 64) - 1
U256 = (1 << 256) - 1
U512 = (1 << 512) - 1
MAGIC = b"NCWV0001"
SCRATCH = 768
ERRORS = {"CHAINWORK_OVERFLOW": 16, "CHAINWORK_UNDERFLOW": 17,
          "DIVISION_BY_ZERO": 18, "TARGET_OVERFLOW": 19, "TARGET": 20,
          "TARGET_PARAMETERS": 21, "HEIGHT": 22, "UNKNOWN_PARENT": 23,
          "TIME": 24, "TIME_DEFERRED": 25}


def u64(value):
    return struct.pack("<Q", value)


def bigint(value, size=64):
    return value.to_bytes(size, "big")


def wire(op, *values):
    prefix = MAGIC + u64(op)
    if op in (0, 1, 3, 7):
        return prefix + bigint(values[0]) + bigint(values[1])
    if op == 2:
        return prefix + bigint(values[0]) + u64(values[1])
    if op in (4, 8):
        return prefix + bigint(values[0], 32)
    if op == 6:
        return prefix + bigint(values[0])
    if op == 5:
        parent, first, last, interval, spacing, limit = values
        return (prefix + bigint(parent, 32) + bigint(limit, 32)
                + struct.pack("<4Q", first, last, interval, spacing))
    if op == 9:
        height, interval, recent = values
        return (prefix + struct.pack("<3Q", height, interval, len(recent))
                + b"".join(u64(time) + bigint(target, 32) for time, target in recent))
    if op == 10:
        candidate, ancestors, now, skew = values
        return prefix + struct.pack("<4Q", candidate, now, skew, len(ancestors)) + b"".join(map(u64, ancestors))
    raise ValueError(op)


def expected(op, *values):
    """Independent mathematical definition, without limb arithmetic."""
    if op in (0, 1, 2, 3):
        left, right = values
        if op == 0:
            result = left + right
        elif op == 1:
            if left < right:
                return 17, b""
            result = left - right
        elif op == 2:
            result = left * right
        else:
            if right == 0:
                return 18, b""
            result = left // right
        return (16, b"") if result > U512 else (0, bigint(result))
    if op == 4:
        target, = values
        return (20, b"") if target == 0 else (0, bigint((1 << 256) // (target + 1)))
    if op == 5:
        parent, first, last, interval, spacing, limit = values
        if interval < 16 or spacing == 0 or parent == 0 or parent > limit:
            return 21, b""
        desired = (interval - 1) * spacing
        if desired > U64 or desired * 4 > U64:
            return 21, b""
        observed = min(max(max(0, last - first), 1, (desired + 3) // 4), 4 * desired)
        adjusted = min(max(parent * observed // desired, 1), limit)
        return 0, bigint(adjusted, 32)
    if op == 6:
        return (19, b"") if values[0] > U256 else (0, bigint(values[0], 32))
    if op == 7:
        return 0, u64(0 if values[0] < values[1] else 1 if values[0] == values[1] else 2)
    if op == 8:
        return 0, bigint(values[0])
    if op == 9:
        height, interval, recent = values
        if height == U64:
            return 22, b""
        if not recent:
            return 23, b""
        last, target = recent[0]
        if interval == 0:
            return 21, b""
        if (height + 1) % interval:
            return 0, u64(0) + bigint(target, 32) + u64(0) + u64(0)
        if len(recent) < interval:
            return 23, b""
        return 0, u64(1) + bigint(target, 32) + u64(recent[interval - 1][0]) + u64(last)
    if op == 10:
        candidate, ancestors, now, skew = values
        if not ancestors:
            return 23, b""
        recent = sorted(ancestors[:11])
        if candidate <= recent[len(recent) // 2]:
            return 24, b""
        if candidate > now + skew:
            return 25, b""
        return 0, b""
    raise ValueError(op)


def retained_vector_cases():
    cases = []
    for name in ("consensus-arithmetic-v1.json", "consensus-domain-v2.json"):
        rows = json.loads((VECTORS / name).read_text())["rows"]
        for row in rows:
            op = {"add": 0, "subtract": 1, "multiply": 2,
                  "divide": 3, "required_work": 4, "retarget": 5}[row["operation"]]
            if op in (0, 1, 3):
                values = (int(row["left"], 16), int(row["right"], 16))
            elif op == 2:
                values = (int(row["left"], 16), row["factor"])
            elif op == 4:
                values = (int(row["target"], 16),)
            else:
                values = (int(row["target"], 16), row["first"], row["last"],
                          row["interval"], row["spacing"], int(row["pow_limit"], 16))
            actual = expected(op, *values)
            if "error" in row:
                committed = (ERRORS[row["error"]], b"")
            else:
                answer = bytes.fromhex(row["expected"])
                committed = (0, answer[-32:] if op == 5 else answer)
            if actual != committed:
                raise AssertionError((name, row, actual, committed))
            cases.append((op, *values))
    return cases


def arithmetic_cases():
    rng = random.Random(0x51220261116)
    edges = [0, 1, 2, 3, U64, U256, U512]
    for bit in (31, 32, 63, 64, 127, 128, 255, 256, 287, 319, 383, 447, 479, 510, 511):
        edges.extend([(1 << bit) - 1, 1 << bit, (1 << bit) + 1])
    cases = []
    for x in edges:
        for y in (0, 1, U512, x, max(0, x - 1)):
            cases.extend((op, x, y) for op in (0, 1, 3, 7))
        cases.extend((2, x, multiplier) for multiplier in (0, 1, 2, (1 << 32) - 1, 1 << 32, U64))
        cases.append((6, x))
    # Every quotient position, including all original 512-bit alignment shifts.
    for bit in range(512):
        cases.append((3, U512, 1 << bit))
        cases.append((3, 1 << bit, (1 << bit) + 1))
    for _ in range(320):
        x = rng.getrandbits(rng.randint(0, 512))
        y = rng.getrandbits(rng.randint(0, 512))
        cases.extend((op, x, y) for op in (0, 1, 3, 7))
        cases.append((2, x, rng.getrandbits(64)))
    for x in (0, 1, 2, 3, (1 << 128) - 1, 1 << 128, 1 << 255, U256 - 1, U256):
        cases.extend([(4, x), (8, x)])
    for _ in range(80):
        x = rng.getrandbits(256)
        cases.extend([(4, x), (8, x)])
    return cases


def policy_cases():
    rng = random.Random(0xDDA20261116)
    cases = []
    for parent in (0, 1, 2, 1000, 1 << 255, U256):
        for interval, spacing in ((0, 1), (15, 1), (16, 0), (16, 1),
                                  (16, 3), (17, 7), (U64, 1), (16, U64),
                                  (16, U64 // 60), (16, U64 // 60 + 1)):
            for first, last in ((0, 0), (100, 99), (0, 1), (0, U64)):
                cases.append((5, parent, first, last, interval, spacing, U256))
        cases.append((5, parent, 0, 1, 16, 1, max(0, parent - 1)))
    for _ in range(220):
        limit = max(1, rng.getrandbits(256))
        parent = rng.randrange(1, limit + 1)
        cases.append((5, parent, rng.getrandbits(64), rng.getrandbits(64),
                      rng.randrange(16, 512), rng.randrange(1, 100000), limit))
    recent = [(1000 - 10 * i, (37 if i == 0 else 9)) for i in range(25)]
    for height in (0, 14, 15, 16, 30, 31, U64 - 16, U64 - 1, U64):
        for interval in (0, 1, 2, 16, 17, U64):
            for count in (0, 1, 2, 15, 16, 17, 25):
                cases.append((9, height, interval, recent[:count]))
    for n in range(25):
        ancestors = [rng.getrandbits(64) for _ in range(n)]
        for candidate, now, skew in ((0, 0, 0), (U64, U64, U64),
                                     (1, 0, 0), (U64, U64 - 1, 1),
                                     (U64, U64 - 1, 0)):
            cases.append((10, candidate, ancestors, now, skew))
    # Odd/even upper median, first-eleven restriction and original error ordering.
    cases.extend([
        (10, 2, [1, 2], 0, 0), (10, 3, [2, 1], 2, 0),
        (10, 3, [2, 1], 2, 1), (10, U64, [0], U64, 1),
        (10, U64, [0], 1 << 63, 1 << 63),
        (10, U64, [0], (1 << 63) - 1, 1 << 63),
        (10, 1, [0] * 11 + [U64] * 100, 0, 1),
        (10, 1, [0] * 10 + [U64] * 100, 0, 1),
        (9, U64, 0, []), (9, 0, 0, []), (9, 0, 0, [(0, 0)]),
    ])
    return cases


class ConsensusWork(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = NativeModule(SOURCE, byte_exports=("f0",))

    @classmethod
    def tearDownClass(cls):
        cls.native.close()

    def check_rows(self, rows, *, output_size=80, scratch_size=SCRATCH + 23):
        total = 0
        for start in range(0, len(rows), 96):
            batch = rows[start:start + 96]
            requests = [("f0", [wire(*row), b"\xa5" * output_size,
                                  b"\x6d" * scratch_size]) for row in batch]
            actual = self.native.call_many(requests, timeout=60)
            for row, result in zip(batch, actual):
                status, answer = expected(*row)
                if scratch_size < SCRATCH:
                    status, answer = 3, b""
                elif status == 0 and output_size < len(answer):
                    status, answer = 2, b""
                observed = result.require_returned()
                self.assertEqual(observed.value, status, row)
                self.assertEqual(observed.arguments[0], wire(*row), row)
                self.assertEqual(observed.arguments[1],
                                 answer + b"\xa5" * (output_size - len(answer))
                                 if status == 0 else b"\xa5" * output_size, row)
                if scratch_size >= SCRATCH:
                    self.assertEqual(observed.arguments[2][SCRATCH:], b"\x6d" * (scratch_size - SCRATCH), row)
                else:
                    self.assertEqual(observed.arguments[2], b"\x6d" * scratch_size, row)
                total += 1
        return total

    def test_retained_independent_integer_vectors(self):
        rows = retained_vector_cases()
        self.assertEqual(len(rows), 158)
        self.check_rows(rows)

    def test_complete_512_bit_arithmetic_and_conversion(self):
        self.check_rows(arithmetic_cases())

    def test_retarget_parent_window_and_time_policy(self):
        self.check_rows(policy_cases())

    def test_output_commit_and_scratch_boundaries(self):
        rows = [(0, 1, 2), (1, 2, 1), (2, 7, U64), (3, U512, 17),
                (4, 1), (5, 12345, 0, 100, 16, 1, U256), (6, U256),
                (7, U512, 1), (8, U256), (9, 15, 16, [(i, 7) for i in range(16)]),
                (10, 1, [0], 1, 0),
                (0, U512, 1), (1, 0, 1), (2, U512, 2), (3, 1, 0),
                (4, 0), (5, 0, 0, 0, 0, 0, 0), (6, U512),
                (9, U64, 0, []), (10, 0, [0], 0, 0)]
        for size in (0, 7, 8, 31, 32, 55, 56, 63, 64, 80):
            self.check_rows(rows, output_size=size, scratch_size=SCRATCH)
        for size in (0, 767, 768, 769):
            self.check_rows(rows, scratch_size=size)

    def test_frame_refusal_has_no_effects(self):
        samples = [wire(0, 1, 2), wire(2, 1, 2), wire(4, 1),
                   wire(5, 1, 0, 1, 16, 1, U256), wire(6, 1), wire(8, 1),
                   wire(9, 0, 16, [(1, 1)]), wire(10, 2, [1], 2, 0)]
        bad = [b"", MAGIC, MAGIC + u64(11), MAGIC + u64(U64)]
        for sample in samples:
            bad.extend(sample[:i] for i in range(len(sample)))
            bad.extend([sample + b"\0", bytes([sample[0] ^ 1]) + sample[1:]])
        for sample, offset in ((samples[-2], 32), (samples[-1], 40)):
            bad.extend(sample[:offset] + u64(n) + sample[offset + 8:]
                       for n in (0, 2, 1 << 63, U64))
        for start in range(0, len(bad), 96):
            requests = [("f0", [raw, b"\xa5" * 80, b"\x6d" * (SCRATCH + 23)])
                        for raw in bad[start:start + 96]]
            for raw, result in zip(bad[start:start + 96], self.native.call_many(requests)):
                observed = result.require_returned()
                self.assertEqual(observed.value, 1, raw.hex())
                self.assertEqual(observed.arguments, [raw, b"\xa5" * 80, b"\x6d" * (SCRATCH + 23)])

    def test_actual_original_consensus_module(self):
        # Mandatory original execution, including original private division and
        # window policy. Missing rustc is a failure, never skip or fake parity.
        raw = ORIGINAL.read_bytes()
        template = REFERENCE.read_bytes()
        marker = b"// TRNM_ORIGINAL_CONSENSUS_SOURCE\n"
        self.assertEqual(template.count(marker), 1)
        assembled = template.replace(marker, raw + b"\n")
        self.assertIn(raw, assembled)
        source_hash = hashlib.sha256(raw).hexdigest()
        rows = retained_vector_cases() + arithmetic_cases() + policy_cases()
        with tempfile.TemporaryDirectory(prefix="trnm-hia-consensus-original-") as temporary:
            path = Path(temporary)
            source, executable = path / "reference.rs", path / "reference"
            source.write_bytes(assembled)
            environment = dict(os.environ, TRNM_CONSENSUS_SOURCE_SHA256=source_hash)
            built = subprocess.run(["rustc", "--edition=2021", "-O", str(source), "-o", str(executable)],
                                   env=environment, capture_output=True, text=True,
                                   timeout=60, check=False)
            self.assertEqual(built.returncode, 0, built.stderr)
            request = "".join(wire(*row).hex() + "\n" for row in rows)
            original = subprocess.run([str(executable)], input=request, capture_output=True,
                                      text=True, timeout=60, check=False)
            self.assertEqual(original.returncode, 0, original.stderr)
        lines = original.stdout.splitlines()
        self.assertEqual(lines[0], "SOURCE_SHA256 " + source_hash)
        self.assertEqual(len(lines), len(rows) + 1)
        for index, (line, row) in enumerate(zip(lines[1:], rows)):
            if line.startswith("OK "):
                actual = (0, bytes.fromhex(line[3:]))
            elif line.startswith("ERR "):
                self.assertIn(line[4:], ERRORS, (index, row, line))
                actual = (ERRORS[line[4:]], b"")
            else:
                self.fail((index, row, line))
            self.assertEqual(actual, expected(*row), (index, row))
        self.assertEqual(ORIGINAL.read_bytes(), raw)
        self.assertEqual(REFERENCE.read_bytes(), template)
        self.check_rows(rows)


if __name__ == "__main__":
    unittest.main()
