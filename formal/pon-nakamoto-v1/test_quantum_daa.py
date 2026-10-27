#!/usr/bin/env python3
"""Source-bound native arithmetic parity and conditional-model counterexamples."""
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import tempfile
import unittest

import quantum_daa as q

NATIVE_BLOB = "2f63dd18dc5893e3020bb00b18f7dcb90bae41ae"


def observed(call, width=0):
    try:
        value = call()
        return "ok:" + (format(value, f"0{width}x") if width else "")
    except q.Reject as error:
        return "err:" + str(error)


class NativeArithmeticParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rustc = os.environ.get("RUSTC") or shutil.which("rustc")
        if rustc is None:
            raise unittest.SkipTest("real Rust compiler unavailable; native parity NOT run")
        source = q.ROOT / "trillionnium/crates/trnm-pon-node/src/consensus.rs"
        raw = source.read_bytes()
        blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        if blob != NATIVE_BLOB:
            raise RuntimeError("native source changed: review and rebind this conditional experiment")
        cls.directory = tempfile.TemporaryDirectory(prefix="pon-quantum-daa-")
        cls.binary = Path(cls.directory.name) / "native-daa"
        subprocess.run([rustc, "--edition=2021", "-D", "warnings", "-C", "opt-level=2",
                        str(Path(__file__).with_name("quantum_daa_native.rs")),
                        "-o", str(cls.binary)], check=True, capture_output=True, text=True)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def parity(self, rows):
        result = subprocess.run([str(self.binary)], input="\n".join(r[0] for r in rows) + "\n",
                                check=True, capture_output=True, text=True)
        actual = result.stdout.splitlines()
        self.assertEqual(len(actual), len(rows))
        for (request, expected), got in zip(rows, actual):
            self.assertEqual(got, expected, request)

    def test_required_work_boundaries_and_512_bit_overflow(self):
        rng = random.Random(204203)
        targets = [0, 1, 2, q.TARGET_MAX, q.TARGET_MAX // 2]
        targets += [rng.getrandbits(256) for _ in range(256)]
        self.parity([(f"work {t:064x}", observed(lambda t=t: q.required_work(t), 128))
                     for t in targets])
        pairs = [(0, 0), (q.WORK_MAX, 0), (q.WORK_MAX, 1),
                 (1 << 511, 1 << 511), ((1 << 511) - 1, 1 << 511)]
        self.parity([(f"add {a:0128x} {b:0128x}", observed(lambda a=a, b=b: q.add_work(a, b), 128))
                     for a, b in pairs])

    def test_retarget_exact_rounding_clamps_and_saturating_timestamp_delta(self):
        rng = random.Random(498495)
        rows = []
        for i in range(600):
            parent = rng.randrange(1, q.TARGET_MAX)
            interval = rng.choice([16, 17, 32, 2016])
            spacing = rng.choice([1, 3, 10, 600])
            desired = (interval - 1) * spacing
            first = rng.randrange(100_000)
            delta = rng.choice([-100, 0, 1, desired // 4, desired // 4 + 1,
                                desired, desired * 4, desired * 4 + 1])
            last = max(0, first + delta)
            args = parent, first, last, interval, spacing, q.TARGET_MAX
            line = f"retarget {parent:064x} {first} {last} {interval} {spacing} {q.TARGET_MAX:064x}"
            rows.append((line, observed(lambda args=args: q.retarget(*args), 64)))
        for args in [(0, 0, 1, 16, 10, q.TARGET_MAX),
                     (2, 0, 1, 16, 10, 1), (1, 0, 1, 15, 10, 2),
                     (1, 0, 1, 16, 0, 2), (1, 0, 1, q.U64_MAX, q.U64_MAX, 2),
                     (1, 0, 1, 16, q.U64_MAX // 30, 2)]:
            p, f, last, interval, spacing, limit = args
            rows.append((f"retarget {p:064x} {f} {last} {interval} {spacing} {limit:064x}",
                         observed(lambda args=args: q.retarget(*args), 64)))
        self.parity(rows)

    def test_median_time_uses_parent_first_11_and_u128_future_bound(self):
        cases = [(10, [], 10, 120), (10, [10], 10, 120), (11, [10], 10, 120),
                 (131, [10], 10, 120), (130, [10], 10, 120),
                 (q.U64_MAX, [1], q.U64_MAX, 120),
                 (7, list(range(11, 0, -1)) + [1000] * 8, 7, 0)]
        rng = random.Random(1011)
        for _ in range(200):
            ancestors = [rng.randrange(500) for _ in range(rng.randrange(1, 21))]
            cases.append((rng.randrange(600), ancestors, rng.randrange(600), rng.randrange(121)))
        rows = [(f"time {c} {now} {skew} " + " ".join(map(str, a)),
                 observed(lambda c=c, a=a, now=now, skew=skew: q.check_time(c, a, now, skew)))
                for c, a, now, skew in cases]
        self.parity(rows)


class ConditionalSchedules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parameters = q.Parameters.load(q.ROOT / "config/pon/devnet-v1.json")
        cls.output = q.report(cls.parameters)

    def test_valid_timestamp_difficulty_ramp_is_conditional_quantum_counterexample(self):
        classical, quantum, caught_up, fixed = self.output["cases"]
        self.assertFalse(classical["private_heavier"])
        self.assertTrue(quantum["private_heavier"])
        self.assertTrue(caught_up["private_heavier"])
        self.assertLess(Decimal(caught_up["tip_age_seconds"]), Decimal(quantum["tip_age_seconds"]))
        self.assertFalse(fixed["private_heavier"])
        self.assertFalse(fixed["native_retarget_rule_used"])
        self.assertTrue(quantum["native_retarget_rule_used"])
        for case in self.output["cases"]:
            self.assertFalse(case["valid_w1_generated_or_verified"])
            self.assertIsNone(case["quantum_resource_estimate"])
            self.assertFalse(case["quantum_pon_hardness_qualified"])

    def test_target_and_time_recomputed_from_this_branch(self):
        branch = q.Branch(self.parameters)
        before = list(branch.headers)
        with self.assertRaisesRegex(q.Reject, "TARGET"):
            branch.append(self.parameters.genesis_time + 10, self.parameters.genesis_time + 10,
                          alleged_target=self.parameters.initial - 1)
        self.assertEqual(branch.headers, before)
        with self.assertRaisesRegex(q.Reject, "TIME"):
            branch.append(self.parameters.genesis_time, self.parameters.genesis_time)
        self.assertEqual(branch.headers, before)

    def test_runtime_cost_and_fixed_fresh_work_assumptions_remain_explicit(self):
        p = self.parameters
        base = q.expected_attempt_seconds(p, p.initial, Decimal("0.25"), "quantum_query_cost_assumption")
        costed = q.expected_attempt_seconds(p, p.initial, Decimal("0.25"), "quantum_query_cost_assumption", Decimal(7))
        self.assertEqual(costed - base, 7)
        for bad in [Decimal(0), Decimal(-1), Decimal("NaN"), Decimal("Infinity")]:
            with self.assertRaises(q.Reject):
                q.expected_attempt_seconds(p, p.initial, bad, "quantum_query_cost_assumption")
        sensitivity = self.output["fixed_probability_fresh_work"]
        self.assertIn("unproven", sensitivity["status"])
        self.assertEqual(sensitivity["rows"][-1]["assumed_linear_oracle_relative_weight_rate"], 1)
        self.assertEqual(Decimal(sensitivity["rows"][-1]["assumed_sqrt_oracle_relative_weight_rate"]), 16)
        self.assertFalse(sensitivity["production_activation"])

    def test_profile_refuses_activation_and_other_time_rules(self):
        source = q.ROOT / "config/pon/devnet-v1.json"
        data = json.loads(source.read_text())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "parameters.json"
            for key, value in [("production_activation", True), ("median_time_width", 13),
                               ("retarget_factor", 2), ("not_mainnet", False)]:
                altered = dict(data, **{key: value})
                path.write_text(json.dumps(altered))
                with self.assertRaises(q.Reject):
                    q.Parameters.load(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
