#!/usr/bin/env python3
"""Adversarial evidence-reader tests; fixtures are not measured evidence."""
import copy
import itertools
import unittest
import hashlib
import tempfile
from pathlib import Path
from check_pure_pon_cost_campaign import ARMS, ARMS_V1, GENERAL_ARMS, MATERIALS, SCHEMA, SCHEMA_V1, check


def fixture():
    native = "7f" + "ff" * 31
    rows = [{"kind": "begin", "hardness_proved": False, "rounds": 1,
             "max_horizon": 1, "attempt_budget": 4, "native_target": native,
             "compiled_source_sha256": {name: "aa" * 32 for name in
                ("campaign_driver", "canonical_w1", "low_rank_prefix", "cargo_lock")}}]
    rows += [{"kind": "material", "name": name} for name in sorted(MATERIALS)]
    for material, arm, reuse, target in itertools.product(sorted(MATERIALS), sorted(ARMS),
                                                         (False, True), (native, "07" + "ff" * 31)):
        row = {"kind": "cohort", "material": material, "strategy": arm,
               "reuse": reuse, "horizon": 1, "round": 0, "target": target,
               "setup_wall_ns": 3, "setup_cpu_ns": 2, "setup_count": 1,
               "attempts": 0, "winners": 0, "status": "unsupported"}
        if arm in GENERAL_ARMS:
            row.update(status="complete", attempts=4, winners=0, exhausted=1,
                       search_wall_ns=10, total_producer_wall_ns=13,
                       search_cpu_ns=8, total_producer_cpu_ns=10,
                       native_accepted_calls=0, stream_sha256="aa" * 32,
                       searches=[{"search": 0, "attempts": 4, "winner": False,
                                  "search_wall_ns": 10, "search_cpu_ns": 8,
                                  "last_ticket": "ff" * 32}])
        rows.append(row)
    rows.append({"kind": "late_product_rejection", "cases": 64})
    rows.append({"kind": "terminal", "status": "complete", "hardness_proved": False,
                 "production_qualified": False, "cohorts": len(MATERIALS) * len(ARMS) * 2 * 2})
    for row in rows:
        row["schema"] = SCHEMA
    return rows


class EvidenceReaderTests(unittest.TestCase):
    def setUp(self):
        self.rows = fixture()
        self.first = next(row for row in self.rows if row.get("status") == "complete"
                          and row["kind"] == "cohort")

    def test_complete_finite_fixture_and_unknown_cpu_propagation(self):
        report = check(self.rows)
        self.assertGreater(report["exhausted_searches"], 0)
        self.assertFalse(report["hardness_proved"])
        self.first["searches"][0]["search_cpu_ns"] = None
        self.first["search_cpu_ns"] = None
        self.first["total_producer_cpu_ns"] = None
        check(self.rows)

    def test_historical_v1_keeps_its_original_twelve_strategy_roster(self):
        rows = [row for row in self.rows if row.get("kind") != "cohort" or row["strategy"] in ARMS_V1]
        for row in rows:
            row["schema"] = SCHEMA_V1
        rows[-1]["cohorts"] = len(MATERIALS) * len(ARMS_V1) * 2 * 2
        rows[0].pop("compiled_source_sha256")
        self.assertEqual(check(rows)["input_schema"], SCHEMA_V1)

    def test_v2_requires_all_compiled_source_digests(self):
        self.rows[0]["compiled_source_sha256"].pop("low_rank_prefix")
        with self.assertRaisesRegex(ValueError, "compiled source digests"):
            check(self.rows)

    def test_v2_cannot_drop_an_unsupported_low_rank_arm(self):
        row = next(r for r in self.rows if r.get("strategy") == "low-rank-prefix-paired")
        self.rows.remove(row)
        self.rows[-1]["cohorts"] -= 1
        with self.assertRaisesRegex(ValueError, "missing offered cohort"):
            check(self.rows)

    def test_explicit_source_readback_rejects_changed_solver_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            names = {
                "campaign_driver": "trillionnium/crates/trnm-pon-node/examples/pon_pure_cost_campaign.rs",
                "canonical_w1": "trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs",
                "low_rank_prefix": "trillionnium/crates/trnm-crypto-primitives/src/pon_work/low_rank_prefix.rs",
                "cargo_lock": "trillionnium/Cargo.lock",
            }
            for key, name in names.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                content = (key + " synthetic parser fixture").encode()
                path.write_bytes(content)
                self.rows[0]["compiled_source_sha256"][key] = hashlib.sha256(content).hexdigest()
            self.assertTrue(check(self.rows, root)["compiled_source_bytes_matched"])
            (root / names["low_rank_prefix"]).write_text("changed")
            with self.assertRaisesRegex(ValueError, "compiled source bytes differ"):
                check(self.rows, root)

    def test_dropped_failed_attempts_cannot_reduce_denominator(self):
        self.first["searches"][0]["attempts"] = 1
        self.first["attempts"] = 1
        with self.assertRaisesRegex(ValueError, "dropped failed attempts"):
            check(self.rows)

    def test_missing_offered_arm_is_not_tolerated(self):
        self.rows.remove(self.first)
        self.rows[-1]["cohorts"] -= 1
        with self.assertRaisesRegex(ValueError, "missing offered cohort"):
            check(self.rows)

    def test_unknown_cpu_cannot_be_forged_to_zero(self):
        self.first["setup_cpu_ns"] = None
        self.first["total_producer_cpu_ns"] = 8
        with self.assertRaisesRegex(ValueError, "unknown CPU"):
            check(self.rows)

    def test_mismatched_stream_is_not_a_paired_comparison(self):
        self.first["stream_sha256"] = "bb" * 32
        with self.assertRaisesRegex(ValueError, "unpaired proof streams"):
            check(self.rows)

    def test_primitive_target_wins_cannot_be_promoted_to_native_acceptance(self):
        self.first["native_accepted_calls"] = 1
        with self.assertRaisesRegex(ValueError, "native admission scope"):
            check(self.rows)

    def test_false_winner_or_incomplete_terminal_never_qualifies(self):
        for mutate in (lambda rows: rows[-1].update(status="failed"),
                       lambda rows: rows[-1].update(hardness_proved=True),
                       lambda rows: next(r for r in rows if r.get("searches"))["searches"][0].update(winner=True)):
            rows = copy.deepcopy(self.rows)
            mutate(rows)
            with self.assertRaises(ValueError):
                check(rows)


if __name__ == "__main__":
    unittest.main()
