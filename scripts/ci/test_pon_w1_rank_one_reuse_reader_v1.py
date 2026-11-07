#!/usr/bin/env python3
"""Synthetic reader controls. Invented traces/timings are NOT native evidence."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pon_w1_rank_one_reuse_reader_v1 as reader


def stamp(value):
    return dict(cpu_ns=value, wall_ns=value)


def row(kind, **values):
    return dict(schema=reader.SCHEMA, kind=kind, **values)


def fixture(target_index=3, horizon=1, name="rank-one-field"):
    left, right, task, prefix = reader.material(name)
    target = bytes.fromhex(reader.TARGETS[target_index])
    limit = reader.LIMIT if target_index < 2 else 3
    result = [row("campaign", selector=reader.SELECTOR, **{"class":name}, target_index=target_index,
        target=target.hex(), reuse_searches=horizon, samples=reader.SAMPLES, attempt_budget=limit,
        purpose=reader.PURPOSES[target_index], classes=list(reader.CLASSES), horizons=list(reader.HORIZONS),
        arms=list(reader.ARMS), preparations=list(reader.PREPARATIONS), lifetimes=list(reader.LIFETIMES),
        paths=list(reader.PATHS), cases=list(reader.CASES), arithmetic="full-limb", materialization="target-hit",
        clock="thread-cpu-and-monotonic-wall-ns", producer_timing_scope=reader.PRODUCER_SCOPE,
        attempt_timing_scope=reader.ATTEMPT_SCOPE, verifier_timing_scope=reader.VERIFY_SCOPE,
        cross_horizon_challenges="same-prefix-not-independent", proof_bytes_encoding="shared-exact-prefix-plus-32-byte-trace",
        material_timing=stamp(100), **dict.fromkeys(reader.FALSE_FLAGS, False)),
        row("material", **{"class":name}, task=task.hex(), a_hex=left.hex(), b_hex=right.hex(),
            source="deterministic-synthetic-rank-one-v1", provenance_verified=False),
        row("proof_prefix", bytes_hex=prefix.hex(), sha256=reader.sha(prefix))]
    for sample in range(reader.SAMPLES):
        searches = []
        for index in range(horizon):
            trials = []
            for nonce in range(limit):
                context = reader.challenge(task, target, sample, index, nonce)
                trace = reader.pon_hash(b"SYNTHETIC-NOT-W1-NATIVE-EVIDENCE", context)
                ticket = reader.pon_hash(b"ticket", context, trace)
                hit = ticket <= target
                trials.append(dict(nonce=nonce, challenge=context.hex(), trace=trace.hex(), ticket=ticket.hex(),
                    hit=hit, proof_materialized=hit, complete_proof_sha256=reader.sha(prefix+trace), timing=stamp(10)))
                if hit:
                    break
            searches.append(trials)
        for order in range(len(reader.ARMS)):
            arm_index = (sample + order) % len(reader.ARMS)
            arm = reader.ARMS[arm_index]
            warm = arm_index % 2 == 1
            setup = [dict(search_index=index, timing=stamp(40)) for index in ([0] if warm else range(horizon))]
            destruction = [dict(search_index=index, timing=stamp(5)) for index in ([horizon-1] if warm else range(horizon))]
            search_total = sum(len(trials)*10+20 for trials in searches)
            result.append(row("cohort", sample=sample, arm=arm, invocation_order=order,
                preparation=reader.PREPARATIONS[arm_index//2], lifetime=reader.LIFETIMES[arm_index%2],
                prefix_sha256=reader.sha(prefix), searches=horizon, setups=setup, destructions=destruction,
                timing=stamp(100+len(setup)*40+len(destruction)*5+search_total)))
            for index, trials in enumerate(searches):
                last = trials[-1]
                proof = prefix + bytes.fromhex(last["trace"]) if last["hit"] else None
                checks = []
                if proof is not None:
                    for case, candidate in enumerate(reader.expected_cases(proof)):
                        outcome = dict(result="Accepted", challenge=last["challenge"], task=task.hex(),
                            ticket=last["ticket"], product_sha256=reader.sha(proof[4+2*reader.CELLS*4:-32])) if case == 0 else {
                                "result":"Product" if case == 1 else "Transcript"}
                        checks.append(dict(case=reader.CASES[case], target=reader.TARGETS[3] if case==2 else target.hex(),
                            proof_sha256=reader.sha(candidate), mutation_timing=None if case==0 else stamp(5),
                            verifiers=[dict(path=reader.PATHS[(sample+order+index+verify_order)%len(reader.PATHS)],
                                invocation_order=verify_order, timing=stamp(30), outcome=copy.deepcopy(outcome))
                                for verify_order in range(len(reader.PATHS))]))
                result.append(row("search", sample=sample, arm=arm, search_index=index,
                    timing=stamp(len(trials)*10+20), attempts=copy.deepcopy(trials),
                    winner={"proof_sha256":reader.sha(proof)} if proof else None,
                    status="target-hit-unverified" if proof else "exhausted", evidence_timing=stamp(20), checks=checks))
    result.append(row("end", cohort_count=reader.SAMPLES*len(reader.ARMS),
        search_count=reader.SAMPLES*len(reader.ARMS)*horizon, semantic_failures=0, complete=True))
    return result


class RankOneReuseReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hit = fixture()
        cls.exhausted = fixture(2)
        cls.warm = fixture(0, 8)

    def reject(self, records):
        with self.assertRaises(ValueError):
            reader.analyze_records(records)

    def test_full_first_hit_controls_keep_all_six_paid_arms(self):
        report = reader.analyze_records(copy.deepcopy(self.hit))
        self.assertTrue(report["native_semantics_pass"])
        self.assertTrue(report["control_expected_outcome_observed"])
        self.assertEqual(report["qualification_status"], "HOLD")
        for paid in report["per_arm_paid_totals"].values():
            self.assertEqual(paid["counts"]["attempts"], reader.SAMPLES)
            self.assertEqual(paid["counts"]["verifier_calls"], reader.SAMPLES*6)
        self.assertFalse(report["boundaries"]["reader_cryptographically_replays_transcript"])

    def test_warm_and_per_search_pay_their_real_setup_and_destruction_counts(self):
        report = reader.analyze_records(copy.deepcopy(self.warm))
        for index, paid in enumerate(report["per_arm_paid_totals"].values()):
            expected = reader.SAMPLES*(1 if index%2 else 8)
            self.assertEqual(paid["counts"]["actual_setup_calls"], expected)
            self.assertEqual(paid["counts"]["actual_destructions"], expected)
            self.assertEqual(paid["counts"]["actual_searches"], reader.SAMPLES*8)

    def test_exhaustion_keeps_all_three_misses_without_invented_winners(self):
        report = reader.analyze_records(copy.deepcopy(self.exhausted))
        self.assertTrue(report["control_expected_outcome_observed"])
        for paid in report["per_arm_paid_totals"].values():
            self.assertEqual(paid["counts"]["misses"], reader.SAMPLES*3)
            self.assertEqual(paid["counts"]["target_hits"], 0)
            self.assertEqual(paid["counts"]["verifier_calls"], 0)

    def test_missing_or_reordered_miss_is_rejected(self):
        for mutate in (lambda v: v.pop(0), lambda v: v.pop(), lambda v: v.reverse()):
            records = copy.deepcopy(self.exhausted)
            mutate(next(r for r in records if r["kind"]=="search")["attempts"])
            self.reject(records)

    def test_warm_horizon_cannot_be_charged_as_no_setup(self):
        records = copy.deepcopy(self.warm)
        next(r for r in records if r["kind"]=="cohort" and r["lifetime"]=="warm-horizon")["setups"] = []
        self.reject(records)

    def test_per_search_cannot_borrow_a_warm_setup_count(self):
        records = copy.deepcopy(self.warm)
        next(r for r in records if r["kind"]=="cohort" and r["lifetime"]=="per-search")["setups"].pop()
        self.reject(records)

    def test_retained_task_destruction_is_required(self):
        records = copy.deepcopy(self.warm)
        next(r for r in records if r["kind"]=="cohort")["destructions"].pop()
        self.reject(records)

    def test_rank_one_label_cannot_substitute_dense_preparation(self):
        records = copy.deepcopy(self.hit)
        next(r for r in records if r["kind"]=="cohort" and r["arm"].startswith("rank-one"))["preparation"] = "dense"
        self.reject(records)

    def test_independent_product_prefix_is_required(self):
        records = copy.deepcopy(self.hit)
        changed = bytearray.fromhex(records[2]["bytes_hex"])
        changed[-1] ^= 1
        records[2]["bytes_hex"] = changed.hex()
        records[2]["sha256"] = reader.sha(bytes.fromhex(records[2]["bytes_hex"]))
        self.reject(records)

    def test_missing_scalar_verifier_is_rejected(self):
        records = copy.deepcopy(self.hit)
        next(r for r in records if r["kind"]=="search")["checks"][0]["verifiers"].pop()
        self.reject(records)

    def test_wrong_transcript_control_target_is_not_hidden(self):
        records = copy.deepcopy(self.warm)
        next(r for r in records if r["kind"]=="search")["checks"][2]["target"] = reader.TARGETS[0]
        self.reject(records)

    def test_always_reject_verifier_preserves_semantic_failure(self):
        records = copy.deepcopy(self.hit)
        failures = 0
        for row in records:
            if row["kind"] == "search":
                for verifier in row["checks"][0]["verifiers"]:
                    verifier["outcome"] = {"result":"Transcript"}
                    failures += 1
        records[-1]["semantic_failures"] = failures
        report = reader.analyze_records(records)
        self.assertFalse(report["native_semantics_pass"])
        self.assertEqual(report["semantic_failures"], failures)
        records[-1]["semantic_failures"] = 0
        self.reject(records)

    def test_accepted_negative_controls_are_retained_as_failures(self):
        records = copy.deepcopy(self.hit)
        searched = next(r for r in records if r["kind"]=="search")
        searched["checks"][1]["verifiers"][0]["outcome"] = copy.deepcopy(searched["checks"][0]["verifiers"][0]["outcome"])
        records[-1]["semantic_failures"] = 1
        self.assertFalse(reader.analyze_records(records)["native_semantics_pass"])

    def test_timing_subtotals_cannot_exceed_paid_total(self):
        records = copy.deepcopy(self.hit)
        next(r for r in records if r["kind"]=="cohort")["timing"] = stamp(1)
        self.reject(records)

    def test_unknown_cpu_remains_unknown_in_sums_and_ratios(self):
        records = copy.deepcopy(self.hit)
        def erase(value):
            if type(value) is dict:
                if set(value)=={"cpu_ns","wall_ns"}:
                    value["cpu_ns"] = None
                else:
                    for item in value.values(): erase(item)
            elif type(value) is list:
                for item in value: erase(item)
        erase(records)
        report = reader.analyze_records(records)
        for paid in report["per_arm_paid_totals"].values():
            self.assertIsNone(paid["producer_total"]["cpu_ns"])
            self.assertIsNotNone(paid["producer_total"]["wall_ns"])
        for ratio in report["warm_over_per_search_paid_ratios"].values():
            self.assertIsNone(ratio["cpu_ns"])

    def test_booleans_are_not_integer_declarations_or_clocks(self):
        records = copy.deepcopy(self.hit)
        records[0]["horizons"][0] = True
        self.reject(records)
        records = copy.deepcopy(self.hit)
        records[0]["material_timing"]["cpu_ns"] = True
        self.reject(records)

    def test_incomplete_or_extra_records_are_rejected(self):
        self.reject(copy.deepcopy(self.hit[:-1]))
        self.reject(copy.deepcopy(self.hit + [self.hit[-1]]))

    def test_duplicate_json_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/"duplicate.jsonl"
            path.write_text('{"schema":"a","schema":"b"}\n')
            with self.assertRaises(ValueError):
                list(reader.rows(path))

    def test_partial_grid_is_explicit_and_required_grid_refuses_it(self):
        report = reader.analyze_records(copy.deepcopy(self.hit))
        with patch.object(reader, "analyze_shard", return_value=report):
            result = reader.analyze(["synthetic"])
            self.assertFalse(result["cost_grid_complete"])
            self.assertFalse(result["separate_controls_complete"])
            with self.assertRaises(ValueError):
                reader.analyze(["synthetic"], require_grid=True)
            with self.assertRaises(ValueError):
                reader.analyze(["synthetic", "synthetic"])

    def test_shared_horizon_prefixes_must_match(self):
        short = reader.analyze_records(fixture(0))
        longer = reader.analyze_records(copy.deepcopy(self.warm))
        with patch.object(reader, "analyze_shard", side_effect=[short, longer]):
            reader.analyze(["short", "longer"])
        longer["canonical_search_stream_sha256"]["0/0"] = "00"*32
        with patch.object(reader, "analyze_shard", side_effect=[short, longer]):
            with self.assertRaises(ValueError):
                reader.analyze(["short", "longer"])


if __name__ == "__main__":
    unittest.main()
