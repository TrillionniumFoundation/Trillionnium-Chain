"""Native M05 quota/fairness predicates with actual original Rust module comparison.

This is not a mempool or a Node admission owner. Every decision in the tested
HIA path executes emitted machine code; Python constructs borrowed wire cases.
The Rust adapter includes the untouched original lane_quota and lane_fairness.
"""
from __future__ import annotations

import random
import struct
import subprocess
import tempfile
from pathlib import Path
import unittest

from hia.tests.native_support import NativeModule

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/mempool/lane_quota.hepta"
RUST = ROOT / "hia/tests/rust_mempool_quota_reference.rs"
MAX = (1 << 64) - 1


def wire(op: int, total: int, reserve: int, normal: int,
         critical: int, streak: int, burst: int) -> bytes:
    return struct.pack("<4sBBBB6Q", b"LQV1", op, 0, 0, 0,
                       total, reserve, normal, critical, streak, burst)


def expected(op: int, total: int, requested: int, normal: int,
             critical: int, streak: int, burst: int) -> int:
    reserve = min(total, requested)
    normal_capacity = total - reserve
    free = max(0, reserve - critical)
    if op == 0:
        return int(normal + critical < total)
    if op == 1:
        return free
    if op == 2:
        return int(normal < normal_capacity)
    if op == 3:
        return int(free > 0 and (normal_capacity == 0 or free > 1
                                 or (critical == 0 and free == 1)))
    if op == 4:
        return int(normal_capacity > 0 and streak >= burst and normal > 0)
    if op == 5:
        return min(streak + 1, burst) if normal_capacity > 0 else 0
    if op == 6:
        return max(0, burst - 1) if normal_capacity > 0 and normal > 0 and critical > 0 else 0
    if 7 <= op <= 12:
        # Each pair is one actual original AdmitOutcome; the low bit is
        # normal_was_empty. Only accepted warmups can modify the streak.
        outcome = (op - 7) // 2
        normal_was_empty = bool((op - 7) % 2)
        if outcome == 0 and normal_was_empty and normal_capacity > 0 and normal > 0 and critical > 0:
            return burst
        return streak
    raise AssertionError("Unknown test mode")


def finite_cases():
    rng = random.Random(0x4D30352D)
    for total, reserve, normal, critical, streak, burst in [
        (0, 0, 0, 0, 0, 0), (3, 1, 2, 0, 0, 2),
        (3, 1, 2, 1, 2, 2), (3, 3, 0, 2, 0, 6),
        (MAX, MAX, MAX, MAX, MAX, MAX),
        (MAX, 1, MAX, MAX, MAX, 0),
        (MAX, MAX - 1, 1, 0, 1, MAX),
        (1, MAX, 0, 1, 0, 0),
        (2, MAX, 0, 1, MAX, MAX),
    ]:
        for op in range(13):
            yield op, total, reserve, normal, critical, streak, burst
    values = [0, 1, 2, 3, 4, 7, 8, 15, 16, 32, 63,
              MAX // 2, MAX - 2, MAX - 1, MAX]
    for _ in range(1800):
        yield (rng.randrange(13), *(rng.choice(values) for _ in range(6)))


class NativeMempoolQuotaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = NativeModule(SOURCE, byte_exports=("f0",))

    @classmethod
    def tearDownClass(cls):
        cls.native.close()

    def check_cases(self, records):
        for start in range(0, len(records), 96):
            batch = records[start:start + 96]
            arguments = [[wire(*row), b"\xa5" * 16, b"\x5a" * 19] for row in batch]
            observed = self.native.call_many([("f0", row) for row in arguments], timeout=60)
            self.assertEqual(len(observed), len(batch))
            for state, sent, actual in zip(batch, arguments, observed):
                actual.require_returned()
                self.assertEqual(actual.value, 0, state)
                result = struct.pack("<Q", expected(*state))
                self.assertEqual(actual.arguments[0], sent[0])
                self.assertEqual(actual.arguments[1], result + sent[1][8:], state)
                self.assertEqual(actual.arguments[2], sent[2])

    def test_native_full_u64_and_reserve_boundaries(self):
        self.check_cases(list(finite_cases()))

    def test_malformed_frames_do_not_publish_an_output(self):
        valid = wire(0, 3, 1, 1, 1, 1, 2)
        wrong_magic = b"BAD!" + valid[4:]
        wrong_reserved = valid[:6] + b"\x01" + valid[7:]
        bad_opcode = valid[:4] + b"\xff" + valid[5:]
        next_unimplemented = valid[:4] + b"\x0d" + valid[5:]
        cases = [(valid[:-1], 16, 1), (valid + b"\x00", 16, 1),
                 (valid, 7, 2), (wrong_magic, 16, 3),
                 (wrong_reserved, 16, 3), (bad_opcode, 16, 4),
                 (next_unimplemented, 16, 4),
                 (wrong_magic, 0, 2)]
        sent = [[data, b"\xa5" * length, b"\x5a" * 13]
                for data, length, _ in cases]
        observed = self.native.call_many([("f0", row) for row in sent])
        for (_, _, code), args, actual in zip(cases, sent, observed):
            actual.require_returned()
            self.assertEqual(actual.value, code)
            self.assertEqual(actual.arguments, args)

    def test_actual_original_lane_modules(self):
        # Compile the repository's actual Rust methods rather than a Python
        # reimplementation or a copied reference formula. A missing Rust
        # compiler, source, compile or runtime failure is a test failure.
        rng = random.Random(0xC17E)
        rows = []
        for op in range(13):
            for total in range(7):
                for reserve in range(9):
                    for _ in range(5):
                        rows.append((op, total, reserve, rng.randrange(9),
                                     rng.randrange(9), rng.randrange(10),
                                     rng.randrange(10)))
        # The original Rust oracle must cover usize::MAX boundaries, not
        # merely the Python arithmetic model or small-capacity Rust cases.
        # Queue lengths stay physically small (the original adapter allocates
        # the corresponding Vecs); capacity/streak/burst retain full u64 width.
        capacity_edges = (
            (0, 0), (0, MAX), (1, MAX), (MAX - 1, MAX),
            (MAX, 0), (MAX, 1), (MAX, MAX - 1), (MAX, MAX),
        )
        fairness_edges = (
            (0, 0), (1, 0), (MAX - 1, MAX), (MAX, MAX - 1),
            (MAX, MAX),
        )
        for op in range(13):
            for total, reserve in capacity_edges:
                for streak, burst in fairness_edges:
                    for normal, critical in (
                        (0, 0), (0, 1), (1, 0), (1, 1), (32, 32),
                    ):
                        rows.append((op, total, reserve, normal, critical,
                                     streak, burst))
        with tempfile.TemporaryDirectory(prefix="trnm-hia-quota-rust-") as tmp:
            executable = Path(tmp) / "original-quota"
            built = subprocess.run(["rustc", "--edition=2021", "-O",
                                    str(RUST), "-o", str(executable)],
                                   cwd=ROOT, capture_output=True, text=True,
                                   timeout=120, check=False)
            self.assertEqual(built.returncode, 0, built.stderr)
            request = "".join(" ".join(str(n) for n in row) + "\n" for row in rows)
            reference = subprocess.run([str(executable)], input=request,
                                       capture_output=True, text=True,
                                       timeout=30, check=False)
            self.assertEqual(reference.returncode, 0, reference.stderr)
            answers = [int(row) for row in reference.stdout.splitlines()]
            self.assertEqual(len(answers), len(rows))
        self.assertEqual(answers, [expected(*row) for row in rows])
        self.check_cases(rows)


if __name__ == "__main__":
    unittest.main()
