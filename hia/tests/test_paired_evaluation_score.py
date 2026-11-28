"""Differential tests of the original isolated formal paired held-row assessor."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import random
import struct
import subprocess
import sys
import unittest

from hia.tests.native_support import NativeModule

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/model/paired_evaluation_score.hepta"
PINS = {
    "formal/pon-nakamoto-v1/evaluation.py": "64abdc175b20a446421371380e244f401f658662a55e925f4bfb76c956f87842",
    "formal/pon-nakamoto-v1/contract_wire.py": "cbe45d72ad20ed5683d50dceaa97b93bc74cdafced7d0896386edf9cbe9f98f6",
    "config/pon/ledger-v1.json": "6755e36aab0ab9f4743da331a8dcd3374d657ff80f027ecf28db922e6d5ea39a",
    "config/pon/work-profile-v1.json": "03f7537b2fc3fa0c2f7036dd73d7088ba1ce50eafe6f2c907087d30385320880",
    "config/pon/model-family-v1.json": "30b250db074e7fbb5776c1474371258a6110cc1742e0e9970232a799ab790ca1",
}
ORIGINAL = """
import json, pathlib, sys, types
root = pathlib.Path(sys.argv[1])
# Execute exact source bytes, never an existing Python bytecode cache.
for name in ('contract_wire', 'evaluation'):
    source = root / 'formal/pon-nakamoto-v1' / (name + '.py')
    module = types.ModuleType(name)
    module.__file__ = str(source)
    sys.modules[name] = module
    exec(compile(source.read_bytes(), str(source), 'exec'), module.__dict__)
evaluation = sys.modules['evaluation']
for rows, candidate, reference, comparisons, minimum_clusters, future_window in json.load(sys.stdin):
    try:
        result = evaluation.assess(rows, candidate, reference, comparisons=comparisons,
                                  minimum_clusters=minimum_clusters, future_window=future_window)
    except ValueError as err:
        result = {'error': str(err)}
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
"""
ERROR = {
    "MULTIPLICITY": 1, "MINIMUM_CLUSTERS": 2, "TIME_OBSERVATION": 3, "EVALUATION_LIMIT": 4,
    "TASK_ID": 5, "DUPLICATE_TASK": 6, "LABEL": 7, "SOURCE_GROUP": 8,
    "SOURCE_GROUP_BINDING": 9, "PREDICTION": 10,
}
FIELDS = ("clusters", "wins", "losses", "comparisons", "cluster_gate", "mean_gain_numerator",
          "mean_gain_denominator", "exploratory_score", "future_window_observed",
          "caller_future_window_claim", "public_reward_eligible")
REASON = "independent time/source-owner receipts must be verified by the accepting owner"
OUT = bytes([173]) * 96
SCRATCH = b"unused scorer work loan"


def frame(rows, candidate, reference, comparisons, minimum, future):
    def field(row, key):
        raw = row.get(key, "").encode("ascii")
        assert len(raw) <= 32 and all(32 <= b <= 126 for b in raw)
        return raw.ljust(32, b"\0")
    assert len(rows) == len(candidate) == len(reference)
    header = struct.pack("<4sBBBH", b"EAS1", len(rows), future, comparisons, minimum)
    return header + b"".join(field(row, "id") + field(row, "source_group") + field(row, "file")
                             + bytes((row["label"], c, r, "source_group" in row, "file" in row, 0, 0, 0))
                             for row, c, r in zip(rows, candidate, reference, strict=True))


def fixture(sizes, outcomes, *, comparisons=4, minimum=20, future=False):
    """Each held row decides between two already supplied inert predictions."""
    rows, candidate, reference = [], [], []
    for g, (count, signs) in enumerate(zip(sizes, outcomes, strict=True)):
        assert count == len(signs)
        for index, sign in enumerate(signs):
            group = f"synthetic group {g}"
            row = {"id": f"member {g} of {index}", "label": (g + index) % 3}
            if index % 3 != 1:
                row["source_group"] = group
            if index % 3 != 0:
                row["file"] = group
            rows.append(row)
            wrong = (row["label"] + 1) % 3
            candidate.append(row["label"] if sign >= 0 else wrong)
            reference.append(row["label"] if sign <= 0 else wrong)
    return rows, candidate, reference, comparisons, minimum, future


def matrix():
    # Exhaustively sweep decision edge for each number of wins across the 64th
    # decisive observation, at both extrema of the comparison-count profile.
    for count in (19, 20, 21, 31, 32, 63, 64):
        for wins in range(count + 1):
            for compare in (4, 64):
                yield fixture([1] * count, [(1,)] * wins + [(-1,)] * (count - wins),
                              comparisons=compare, future=(wins % 2 == 0))
    yield fixture([1] * 64, [(1,)] * 64, minimum=64, future=True)
    yield fixture([1] * 64, [(1,)] * 64, minimum=65)
    yield fixture([1] * 64, [(1,)] * 64, minimum=4096)
    yield fixture([1] * 64, [(0,)] * 64)
    # Majority of diluted wins but negative group mean, and the mirror case.
    for sign in (-1, 1):
        yield fixture([2] * 21 + [1] * 11, [(sign, 0)] * 21 + [(-sign,)] * 11)
    # Product/rational chain closer to its proven bound, true zero mean and
    # signed fractions on unequal group sizes, plus noncontiguous members.
    for sign in (-1, 1):
        yield fixture([3] * 21 + [1], [(sign, 0, 0)] * 21 + [(0,)])
    yield fixture([2, 1], [(1, 1), (-1,)])
    yield fixture([64], [(1,) * 64])
    rng = random.Random(89)
    for _ in range(80):
        sizes = []
        remaining = rng.randint(1, 64)
        while remaining:
            take = rng.randint(1, min(remaining, rng.randint(1, 8)))
            sizes.append(take)
            remaining -= take
        groups = [[rng.choice((-1, -1, 0, 0, 1, 1)) for _ in range(n)] for n in sizes]
        rows, cs, rs, comp, minimum, future = fixture(sizes, groups, comparisons=rng.randint(4, 64))
        shuffled = list(zip(rows, cs, rs, strict=True))
        rng.shuffle(shuffled)
        a, b, c = zip(*shuffled, strict=True)
        yield list(a), list(b), list(c), comp, minimum, future
    edge = "x" * 32
    yield [{"id": edge, "label": 2, "source_group": edge, "file": edge}], [2], [1], 4, 20, False
    yield [], [], [], 4, 20, False
    yield [], [], [], 3, 19, 2  # Original configuration validation precedence.
    yield [], [], [], 65, 4097, 2
    yield [], [], [], 4, 19, 2
    yield [], [], [], 4, 4097, 2
    yield [], [], [], 4, 20, 2
    for raw, pred, ref in (
        ({"id": "", "label": 9}, 9, 9),
        ({"id": "bad", "label": 3}, 9, 9),
        ({"id": "bad", "label": 0}, 9, 9),
        ({"id": "bad", "label": 0, "source_group": "", "file": "nonempty"}, 9, 9),
        ({"id": "bad", "label": 0, "source_group": "x", "file": ""}, 9, 9),
        ({"id": "bad", "label": 0, "source_group": "x", "file": "y"}, 9, 9),
        ({"id": "bad", "label": 0, "file": "x"}, 3, 0),
        ({"id": "bad", "label": 0, "source_group": "x"}, 0, 3),
    ):
        yield [raw], [pred], [ref], 4, 20, False
    same = {"id": "identical", "label": 0, "source_group": "a"}
    yield [same, dict(same, label=3)], [0, 3], [0, 3], 4, 20, False


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pins():
    return {name: sha((ROOT / name).read_bytes()) for name in PINS}


class PairedEvaluationScore(unittest.TestCase):
    def test_frozen_formal_held_scorer_both_stock(self):
        combined = list(matrix())
        original_args = json.dumps(combined, ensure_ascii=True, separators=(",", ":")).encode()
        self.assertEqual(pins(), PINS)
        original = subprocess.run([sys.executable, "-IB", "-c", ORIGINAL, str(ROOT)],
                                  input=original_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  timeout=30, check=True, cwd=ROOT)
        self.assertEqual(original.stderr, b"")
        self.assertEqual(pins(), PINS)
        parsed = [json.loads(line) for line in original.stdout.splitlines()]
        self.assertEqual(len(parsed), len(combined))
        self.assertTrue(any(d.get("cluster_gate") for d in parsed))
        self.assertEqual({value["error"] for value in parsed if "error" in value}, set(ERROR))
        normal = []
        for case, want in zip(combined, parsed, strict=True):
            raw = frame(*case)
            if "error" in want:
                normal.append((raw, OUT, ERROR[want["error"]], b""))
                continue
            self.assertEqual(want["reason"], REASON)
            self.assertIs(want["future_window_observed"], False)
            self.assertIs(want["public_reward_eligible"], False)
            score = struct.pack("<QQQQQqQQQQQ", *(want[name] for name in FIELDS))
            normal.append((raw, OUT, 0, score))
        prior, _, _, result = normal[0]
        control = [
            (b"", OUT, 100, b""), (prior[:8], OUT, 100, b""),
            (b"FAKE" + prior[4:], OUT, 100, b""), (prior[:-1], OUT, 100, b""),
            (prior + b"x", OUT, 100, b""), (prior[:4] + b"A" + prior[5:], OUT, 4, b""),
            (prior[:9] + b"\x91" + prior[10:], OUT, 100, b""),
            (prior[:110] + b"\x01" + prior[111:], OUT, 100, b""),
            (prior[:11] + b"\x00x" + prior[13:], OUT, 100, b""),
            (prior, OUT[:87], 102, b""), (prior, b"", 102, b""), (prior, OUT[:88], 0, result),
            (prior[:6] + b"\x03" + prior[7:], b"", 1, b""),
        ]
        print(json.dumps(dict(oracle="unchanged evaluation.assess", source_sha256=PINS,
                              inputs_sha256=sha(original_args), stdout_sha256=sha(original.stdout),
                              actual_counts=Counter(code for _, _, code, _ in normal),
                              positives=sum(d.get("cluster_gate", False) for d in parsed)), sort_keys=True), flush=True)
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",), backend=backend) as native:
                cases = normal + control
                for start in range(0, len(cases), 80):
                    cohort = cases[start:start + 80]
                    actuals = native.call_many([("f0", [raw, out, SCRATCH]) for raw, out, _, _ in cohort], timeout=20)
                    for index, ((raw, out, status, result), actual) in enumerate(zip(cohort, actuals, strict=True)):
                        self.assertEqual(actual.require_returned().value, status, (backend, start + index))
                        self.assertEqual(actual.arguments, [raw, result + out[len(result):], SCRATCH],
                                         (backend, start + index))
                print(json.dumps(dict(backend=backend, elf=native.artifact_sha256,
                                      original_matches=len(normal), private_controls=len(control)),
                                 sort_keys=True), flush=True)
