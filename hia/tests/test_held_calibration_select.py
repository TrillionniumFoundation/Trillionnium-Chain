"""Exact original numeric frozen calibration selection on inert held values."""
from collections import Counter
import json
from pathlib import Path
import random
import struct
import subprocess
import sys
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_paired_evaluation_score import ERROR, PINS, ROOT, frame, pins, sha

SOURCE = ROOT / "hia/src/model/held_calibration_select.hepta"
NAMES = ("current", "best_single", "mean_merge", "pooled")
OUT = bytes([233]) * 97
SCRATCH = b"untouched calibration work loan"
ORIGINAL = """
import json, pathlib, sys, types
root = pathlib.Path(sys.argv[1])
for name in ('contract_wire', 'evaluation'):
    source = root / 'formal/pon-nakamoto-v1' / (name + '.py')
    module = types.ModuleType(name)
    module.__file__ = str(source)
    sys.modules[name] = module
    exec(compile(source.read_bytes(), str(source), 'exec'), module.__dict__)
evaluation = sys.modules['evaluation']
for rows, controls in json.load(sys.stdin):
    try:
        selected, _ = evaluation.select_reference(rows, controls)
        fractions = [evaluation.macro_accuracy(rows, controls[name]) for name in evaluation.CONTROL_ORDER]
        result = [selected, [[v.numerator, v.denominator] for v in fractions]]
    except ValueError as err:
        result = {'error': str(err)}
    print(json.dumps(result, separators=(',', ':')))
"""


def wire(rows, controls):
    if set(controls) != set(NAMES):
        mask = sum(1 << i for i, key in enumerate(NAMES) if key in controls)
        if set(controls) - set(NAMES):
            mask |= 16
        return b"CAL1" + bytes((len(rows), mask, 0, 0, 0))
    # Reuse only the private EAS1 row encoding (not an EAS1 result).
    body = frame(rows, controls[NAMES[0]], controls[NAMES[1]], 4, 20, False)[9:]
    side = bytes(c for pair in zip(controls[NAMES[2]], controls[NAMES[3]], strict=True) for c in pair)
    return b"CAL1" + bytes((len(rows), 15, 0, 0, 0)) + body + side


def fixture(groups, correct):
    rows = []
    for g, size in enumerate(groups):
        for i in range(size):
            key = f"group {g}"
            row = dict(id=f"held {g} item {i}", label=(i + g) % 3)
            if i % 3 != 1: row["source_group"] = key
            if i % 3 != 0: row["file"] = key
            rows.append(row)
    controls = {
        name: [row["label"] if flag else (row["label"] + 1 + offset % 2) % 3
               for row, flag in zip(rows, flags, strict=True)]
        for offset, (name, flags) in enumerate(zip(NAMES, correct, strict=True))
    }
    return rows, controls


def cases():
    # Sweep every four-way tie subset on multiple row/group extents, including
    # the maximum rows, single largest group, and product-bound group sizes.
    for sizes in ([1], [1] * 64, [64], [3] * 21 + [1], [1, 2, 4, 11, 17, 29]):
        count = sum(sizes)
        for bits in range(16):
            yield fixture(sizes, [[bool(bits & (1 << j))] * count for j in range(4)])
    # A large group with many correct rows loses to two correct small groups.
    yield fixture([62, 1, 1], [[True] * 62 + [False, False], [False] * 62 + [True, True],
                              [False] * 63 + [True], [True] * 32 + [False] * 32])
    # Equal numeric score with unequal numbers of rows/group and exact rational ties.
    yield fixture([3, 5], [[True] * 3 + [False] * 5, [False] * 3 + [True] * 5,
                            [False] * 7 + [True], [True] + [False] * 7])
    rng = random.Random(2389)
    for _ in range(120):
        final = rng.randint(1, 64)
        sizes = []
        while final > 0:
            s = rng.randint(1, min(11, final))
            final -= s
            sizes.append(s)
        n = sum(sizes)
        rows, controls = fixture(sizes, [[rng.randrange(2) for _ in range(n)] for _ in range(4)])
        order = list(range(n))
        rng.shuffle(order)
        yield [rows[i] for i in order], {name: [controls[name][i] for i in order] for name in NAMES}
    r, c = fixture([1, 1], [[True, True]] * 4)
    yield r, dict(reversed(list(c.items())))
    yield [], {name: [] for name in NAMES}
    yield [], {}
    yield r, {k: c[k] for k in NAMES[:-1]}
    yield r, dict(c, fifth=[0, 1])
    for j, v in enumerate(NAMES):
        yield r, dict(c, **{v: [3 + j, 1]})
        # First row's control error is prior to the next row's label error.
        yield [r[0], dict(r[1], label=7)], dict(c, **{v: [3 + j, 1]})
    yield [dict(r[0], id=""), r[1]], c
    yield [r[0], dict(r[0], label=7)], c
    yield [dict(r[0], label=7), r[1]], c
    yield [dict(r[0], source_group=""), r[1]], c
    yield [dict(r[0], file="another group"), r[1]], c
    e = "K" * 32
    yield [dict(r[0], id=e, source_group=e, file=e), r[1]], c


class HeldCalibrationSelect(unittest.TestCase):
    def test_frozen_select_reference_and_macro_accuracy_both_stock(self):
        inputs = list(cases())
        request = json.dumps(inputs, separators=(",", ":")).encode()
        self.assertEqual(pins(), PINS)
        result = subprocess.run([sys.executable, "-IB", "-c", ORIGINAL, str(ROOT)],
                                cwd=ROOT, input=request, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, check=True, timeout=30)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(pins(), PINS)
        original = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(len(original), len(inputs))
        errors = {r["error"] for r in original if isinstance(r, dict)}
        self.assertEqual(errors, {k for k, v in ERROR.items() if v >= 4} | {"CONTROL_SET"})
        winner_counts = Counter(r[0] for r in original if isinstance(r, list))
        self.assertEqual(set(winner_counts), set(NAMES))
        self.assertEqual(original[80], ["best_single", [[1, 3], [2, 3], [1, 3], [16, 93]]])
        payloads = []
        for item, want in zip(inputs, original, strict=True):
            raw = wire(*item)
            if isinstance(want, dict):
                code = 11 if want["error"] == "CONTROL_SET" else ERROR[want["error"]]
                payloads.append((raw, OUT, code, b""))
            else:
                name, fractions = want
                encoded = struct.pack("<16s8Q", name.encode(), *(part for pair in fractions for part in pair))
                payloads.append((raw, OUT, 0, encoded))
        normal, _, _, expected = payloads[0]
        private = [
            (b"", OUT, 100, b""), (normal[:8], OUT, 100, b""),
            (b"EAS1" + normal[4:], OUT, 100, b""), (normal[:-1], OUT, 100, b""),
            (normal + b"\x00", OUT, 100, b""),
            (normal[:6] + b"\x01" + normal[7:], OUT, 100, b""),
            (normal[:4] + b"A" + normal[5:], OUT, 4, b""),
            (normal[:9] + b"\x91" + normal[10:], OUT, 100, b""),
            (normal[:110] + b"\x01" + normal[111:], OUT, 100, b""),
            (normal[:11] + b"\x00x" + normal[13:], OUT, 100, b""),
            (normal, OUT[:79], 102, b""), (normal, b"", 102, b""),
            (normal, OUT[:80], 0, expected),
            (normal[:5] + b"\x07" + normal[6:], b"", 11, b""),
        ]
        print(json.dumps(dict(oracle="unchanged evaluation.select_reference and macro_accuracy",
                              source_sha256=PINS, input_sha256=sha(request), stdout_sha256=sha(result.stdout),
                              statuses=Counter(v[2] for v in payloads), winners=winner_counts),
                         sort_keys=True), flush=True)
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",), backend=backend) as native:
                all_cases = payloads + private
                for start in range(0, len(all_cases), 60):
                    batch = all_cases[start:start + 60]
                    replies = native.call_many([("f0", [r, o, SCRATCH]) for r, o, _, _ in batch], timeout=20)
                    for i, ((raw, out, code, expected), reply) in enumerate(zip(batch, replies, strict=True)):
                        self.assertEqual(reply.require_returned().value, code, (backend, start + i))
                        self.assertEqual(reply.arguments, [raw, expected + out[len(expected):], SCRATCH],
                                         (backend, start + i))
                print(json.dumps(dict(backend=backend, native_elf=native.artifact_sha256,
                                      original_matches=len(payloads), private_abi_controls=len(private)),
                                 sort_keys=True), flush=True)
