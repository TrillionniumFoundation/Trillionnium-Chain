"""One native call: held numeric CAL1 winner selects the held EAS1 reference."""
from collections import Counter
import json
import random
import struct
import subprocess
import sys
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_held_calibration_select import NAMES, ORIGINAL, fixture, wire
from hia.tests.test_paired_evaluation_score import ERROR, FIELDS, PINS, REASON, ROOT, frame, pins, sha

SOURCE = ROOT / "hia/src/model/calibrated_paired_evaluation.hepta"
OUT = bytes([182]) * 181
SCRATCH = b"unused combined work span"
ORACLE = ORIGINAL.split("for rows, controls in json.load(sys.stdin):", 1)[0] + """
for cal, controls, rows, candidate, evaluation_controls, comp, minimum, future in json.load(sys.stdin):
    try:
        winner, _ = evaluation.select_reference(cal, controls)
        scores = [evaluation.macro_accuracy(cal, controls[key]) for key in evaluation.CONTROL_ORDER]
        score = evaluation.assess(rows, candidate, evaluation_controls[winner],
                                  comparisons=comp, minimum_clusters=minimum, future_window=future)
        result = [winner, [[s.numerator,s.denominator] for s in scores], score]
    except ValueError as err:
        result = {'error': str(err)}
    print(json.dumps(result, separators=(',', ':')))
"""


def labeled(rows, section):
    return [{key: section + value if key in {"id", "source_group", "file"} else value
             for key, value in row.items()} for row in rows]


def bind(cal, controls, rows, candidate, eval_controls, comp, minimum, future):
    cal_raw = wire(cal, controls)
    head = struct.pack("<4sBBBBHB", b"CAE1", len(cal), len(rows), cal_raw[5], comp, minimum, future)
    primary = frame(rows, candidate, eval_controls[NAMES[0]], 4, 20, False)[9:]
    side = bytes(x for item in zip(*(eval_controls[n] for n in NAMES[1:]), strict=True) for x in item)
    return head + cal_raw[9:] + primary + side


def case(cals, calbits, evals, evalbits, **policy):
    cal, controls = fixture(cals, calbits)
    rows, ev = fixture(evals, evalbits[1:])
    candidate = [r["label"] if hit else (r["label"] + 1) % 3
                 for r, hit in zip(rows, evalbits[0], strict=True)]
    return (labeled(cal, "C/"), controls, labeled(rows, "E/"), candidate, ev,
            policy.get("comp", 4), policy.get("minimum", 20), policy.get("future", False))


def examples():
    # Ties and permutations select only from calibration. For each selected
    # column the evaluation outcome varies, including opposite-sign controls.
    for sizes in ([1], [1] * 64, [3] * 21 + [1]):
        n = sum(sizes)
        for bits in range(16):
            for mismatch in (False, True):
                ev_cols = [[True] * 64] + [[(i + j + mismatch) % (j + 2) == 0 for i in range(64)]
                                            for j in range(4)]
                yield case(sizes, [[bool(bits & (1 << j))] * n for j in range(4)],
                           [1, 2, 4, 11, 17, 29], ev_cols, future=mismatch)
    # Exact 64-decisive binomial path; rotate which native-selected reference
    # is all wrong, while every unselected reference is completely correct.
    for selected in range(4):
        calbits = [[j == selected] * 64 for j in range(4)]
        ev_cols = [[True] * 64] + [[j != selected] * 64 for j in range(4)]
        yield case([1] * 64, calbits, [1] * 64, ev_cols, comp=64, minimum=64, future=True)
        ev_cols = [[False] * 64] + [[j == selected] * 64 for j in range(4)]
        yield case([1] * 64, calbits, [1] * 64, ev_cols)
    rng = random.Random(242)
    for _ in range(96):
        groups = []
        for total in (rng.randint(1, 64), rng.randint(1, 64)):
            sizes = []
            while total:
                width = rng.randint(1, min(10, total))
                sizes.append(width)
                total -= width
            groups.append(sizes)
        cal, controls, ev, pred, candidates, *_ = case(
            groups[0], [[bool(rng.getrandbits(1)) for _ in range(sum(groups[0]))] for _ in range(4)],
            groups[1], [[bool(rng.getrandbits(1)) for _ in range(sum(groups[1]))] for _ in range(5)])
        ai, bi = list(range(len(cal))), list(range(len(ev)))
        rng.shuffle(ai)
        rng.shuffle(bi)
        yield ([cal[i] for i in ai], {k: [v[i] for i in ai] for k, v in controls.items()},
               [ev[i] for i in bi], [pred[i] for i in bi], {k: [v[i] for i in bi] for k, v in candidates.items()},
               rng.randint(4, 64), rng.randint(20, 65), False)
    base = list(case([1], [[False], [False], [True], [False]],
                     [1, 1], [[True, False]] * 5))
    replacements = [
        {1: {}}, {0: [], 1: {n: [] for n in NAMES}},
        {0: [dict(base[0][0], label=7)], 5: 3},
        {5: 3, 6: 19, 7: 2}, {6: 19, 7: 2}, {7: 2},
        {2: [dict(base[2][0], id=""), base[2][1]]},
        {2: [base[2][0], dict(base[2][1], id=base[2][0]["id"], label=9)]},
        {2: [dict(base[2][0], label=7), base[2][1]]},
        {2: [dict(base[2][0], source_group=""), base[2][1]]},
        {2: [dict(base[2][0], file="E/not the group"), base[2][1]]},
        {3: [7, 0]}, {4: dict(base[4], mean_merge=[7, 0])},
    ]
    for changes in replacements:
        item = base.copy()
        for i, value in changes.items():
            item[i] = value
        yield tuple(item)


class CalibratedPairedEvaluation(unittest.TestCase):
    def test_original_select_then_assess_with_bound_native_winner(self):
        inputs = list(examples())
        request = json.dumps(inputs, separators=(",", ":")).encode()
        self.assertEqual(pins(), PINS)
        process = subprocess.run([sys.executable, "-IB", "-c", ORACLE, str(ROOT)],
                                 cwd=ROOT, input=request, capture_output=True, check=True, timeout=30)
        self.assertEqual(pins(), PINS)
        self.assertEqual(process.stderr, b"")
        expected = [json.loads(x) for x in process.stdout.splitlines()]
        self.assertEqual(len(expected), len(inputs))
        winners = Counter(v[0] for v in expected if isinstance(v, list))
        self.assertEqual(set(winners), set(NAMES))
        self.assertEqual({v["error"] for v in expected if isinstance(v, dict)}, set(ERROR) | {"CONTROL_SET"})
        gate_positives = Counter(v[0] for v in expected if isinstance(v, list) and v[2]["cluster_gate"])
        self.assertEqual(set(gate_positives), set(NAMES))
        normal = []
        for case, want in zip(inputs, expected, strict=True):
            raw = bind(*case)
            if isinstance(want, dict):
                code = 11 if want["error"] == "CONTROL_SET" else ERROR[want["error"]]
                normal.append((raw, OUT, code, b""))
                continue
            name, fractions, assessment = want
            self.assertEqual(assessment["reason"], REASON)
            self.assertIs(assessment["future_window_observed"], False)
            self.assertIs(assessment["public_reward_eligible"], False)
            projected = struct.pack("<QQQQQqQQQQQ", *(assessment[k] for k in FIELDS))
            calibrated = struct.pack("<16s8Q", name.encode(), *(i for pair in fractions for i in pair))
            normal.append((raw, OUT, 0, projected + calibrated))
        raw, _, _, value = normal[0]
        # These are private frame and alignment controls, not original policy
        # outcomes. Require all four held evaluation predictions to be typed,
        # even a malformed nonselected cell that assess alone never reads.
        def alter(at, value):
            return raw[:at] + bytes([value]) + raw[at + 1:]
        evaluation_start = 11 + 106 * raw[4]
        extras = evaluation_start + 104 * raw[5]
        controls = [(b"", OUT, 100, b""), (raw[:10], OUT, 100, b""),
                    (b"CAL1" + raw[4:], OUT, 100, b""), (raw[:-1], OUT, 100, b""),
                    (raw + b"\0", OUT, 100, b""), (alter(4, 65), OUT, 4, b""),
                    (alter(5, 65), OUT, 4, b""), (alter(5, 0), OUT, 4, b""),
                    (alter(6, 7), OUT, 11, b""), (alter(11 + 101, 1), OUT, 100, b""),
                    (alter(evaluation_start + 97, 3), OUT, 10, b""),
                    (alter(evaluation_start + 98, 3), OUT, 10, b""),
                    (alter(extras, 3), OUT, 10, b""),
                    (alter(extras + 1, 3), OUT, 10, b""),
                    (alter(extras + 2, 3), OUT, 10, b""),
                    (alter(extras + 3 + 2, 3), OUT, 10, b""),
                    (raw, OUT[:167], 102, b""), (raw, b"", 102, b""),
                    (raw, OUT[:168], 0, value)]
        print(json.dumps(dict(oracle="unchanged select_reference, macro_accuracy and assess",
                              source_sha256=PINS, input_sha256=sha(request), stdout_sha256=sha(process.stdout),
                              statuses=Counter(r[2] for r in normal), winners=winners,
                              gate_positives=gate_positives), sort_keys=True), flush=True)
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",), backend=backend) as n:
                all_cases = normal + controls
                for base in range(0, len(all_cases), 50):
                    tests = all_cases[base:base + 50]
                    got = n.call_many([("f0", [wire, out, SCRATCH]) for wire, out, _, _ in tests], timeout=20)
                    for i, ((wire, out, status, payload), reply) in enumerate(zip(tests, got, strict=True)):
                        self.assertEqual(reply.require_returned().value, status, (backend, base + i))
                        self.assertEqual(reply.arguments, [wire, payload + out[len(payload):], SCRATCH],
                                         (backend, base + i))
                print(json.dumps(dict(backend=backend, elf=n.artifact_sha256, original_matches=len(normal),
                                      private_abi_controls=len(controls)), sort_keys=True), flush=True)
