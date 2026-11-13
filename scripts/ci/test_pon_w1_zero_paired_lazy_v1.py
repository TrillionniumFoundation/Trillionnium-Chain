#!/usr/bin/env python3
"""Synthetic grammar/forgery controls, never native W1 or timing evidence.

The traces below are deliberately hash-only parser fixtures. Accepting their
journal grammar must retain every execution/replay/qualification flag as false.
Real native source, executable, process and full-relation receipts are separate.
"""
import copy
from functools import lru_cache
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pon_w1_zero_paired_lazy_v1 as reader


def tm(n):
    return {"cpu_ns": n, "wall_ns": n + 1}


def encode(rows):
    return b"".join(json.dumps({**row, "schema": reader.SCHEMA, "seq": seq},
                              separators=(",", ":")).encode() + b"\n"
                    for seq, row in enumerate(rows))


@lru_cache(maxsize=10000)
def synthetic_trial(target_index, sample, search, nonce, hit):
    """Find a fake trace with the intended cheap-ticket outcome; no W1 occurs."""
    target = reader.TARGETS[target_index]
    context = reader.challenge(target, sample, search, nonce)
    for counter in range(10000):
        trace = hashlib.sha256(b"SYNTHETIC-NOT-W1:" + context + counter.to_bytes(8, "little")).digest()
        ticket = reader.common.pon_hash(b"ticket", context, trace)
        if (ticket <= bytes.fromhex(target)) == hit:
            return {"nonce": nonce, "challenge": context.hex(), "trace": trace.hex(),
                "ticket": ticket.hex(), "proof_sha256": reader.common.sha(reader.PREFIX + trace), "hit": hit}
    raise AssertionError("bounded synthetic ticket fixture exhausted")


def synthetic_rows(target_index=3, horizon=1, *, changed_trace=None):
    """A complete declared grammar fixture, not a claimed native measurement."""
    rows = [{"event": "header", **copy.deepcopy(reader.STATIC), "target_index": target_index,
        "target": reader.TARGETS[target_index], "horizon": horizon,
        "max_attempts": reader.LIMIT if target_index < 2 else 3,
        "material_timing": tm(11),
        "ideal_uniform_ticket_assumption": ("1/2", "1/32", None, None)[target_index]}]
    counts = dict.fromkeys(reader.COUNTERS, 0)
    for sample in range(reader.SAMPLES):
        for position in range(len(reader.ARMS)):
            arm = (sample + position) % len(reader.ARMS)
            c = {"sample": sample, "arm": arm}
            rows.append({"event": "cohort_begin", **c, "position": position})
            rows.append({"event": "setup_finish", **c, "timing": tm(7), "setup_calls": 1})
            counts["cohorts"] += 1
            counts["setup_calls"] += 1
            for search in range(horizon):
                s = {**c, "search": search}
                rows.append({"event": "search_begin", **s})
                trials = []
                count = 1 if target_index == 3 else 3
                for nonce in range(count):
                    hit = target_index != 2 and nonce == count - 1
                    trial = dict(synthetic_trial(target_index, sample, search, nonce, hit))
                    if changed_trace and changed_trace == (sample, arm, search, nonce):
                        context = bytes.fromhex(trial["challenge"])
                        for counter in range(10000):
                            trace = hashlib.sha256(b"ALTERNATE-SYNTHETIC:" + counter.to_bytes(8, "little")).digest()
                            ticket = reader.common.pon_hash(b"ticket", context, trace)
                            if (ticket <= bytes.fromhex(reader.TARGETS[target_index])) == hit:
                                trial.update(trace=trace.hex(), ticket=ticket.hex(),
                                             proof_sha256=reader.common.sha(reader.PREFIX + trace))
                                break
                    rows.append({"event": "attempt_begin", **s, "nonce": nonce})
                    materialized = arm in (0, 2, 3) or hit
                    rows.append({"event": "attempt_finish", **s, **trial, "materialized": materialized,
                        "producer": tm(10), "evidence": tm(3), "disposal": tm(1)})
                    trials.append(trial)
                    counts["attempts"] += 1
                    counts["hits" if hit else "misses"] += 1
                    counts["materialized"] += int(materialized)
                first = None if target_index == 2 else count - 1
                rows.append({"event": "search_finish", **s, "attempts": count,
                    "first_hit_nonce": first, "timing": tm(100 + count * 20)})
                counts["searches"] += 1
                counts["exhausted"] += int(first is None)
                verification = ([(trial, "exhausted-replay") for trial in trials] if first is None else
                                [(trials[-1], kind) for kind in ("winner", "product-last")])
                for trial, kind in verification:
                    proof = reader.PREFIX + bytes.fromhex(trial["trace"])
                    if kind == "product-last":
                        proof = bytearray(proof)
                        proof[4 + 3 * reader.common.CELLS * 4 - 4] = 1
                    for verifier in ("production", "reference"):
                        v = {**s, "nonce": trial["nonce"], "kind": kind, "verifier": verifier,
                            "target": reader.TARGETS[3] if kind == "exhausted-replay" else reader.TARGETS[target_index],
                            "proof_sha256": reader.common.sha(proof)}
                        rows.append({"event": "verify_begin", **v})
                        rows.append({"event": "verify_finish", **v, "accepted": kind != "product-last",
                            "error": "Product" if kind == "product-last" else None, "timing": tm(5)})
                        counts["verification_calls"] += 1
                rows.append({"event": "cleanup_begin", **s})
                rows.append({"event": "cleanup_finish", **s, "timing": tm(2)})
            rows.append({"event": "cohort_end", **c, "teardown": tm(1), "total": tm(1_000_000)})
    rows.append({"event": "footer", "counts": counts, "complete": True,
        "consensus_credit": 0, "production_activation": False, "cheapest_strategy_proven": False})
    return rows


def read(rows, code=0):
    return reader.read_stream(io.BytesIO(encode(rows)), process_exit_code=code)


class SyntheticReadback(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.first = synthetic_rows()
        cls.exhaustion = synthetic_rows(2)
        cls.cost = synthetic_rows(0)

    def assert_invalid(self, rows):
        result = read(rows)
        self.assertEqual(result["status"], "INVALID", result)
        self.assertEqual(result["exit_code"], 2)
        self.assertFalse(result["source_execution_authenticated"])
        self.assertIsNone(result["unfinished_resource_cost"])
        return result

    def test_complete_synthetic_grammar_never_claims_execution_or_replay(self):
        result = read(self.first)
        self.assertEqual(result["status"], "COMPONENT_OBSERVATION", result)
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["counts"], self.first[-1]["counts"])
        for flag in reader.FALSE_FLAGS:
            self.assertIs(result[flag], False)
        self.assertFalse(result["process_exit_authenticated"])
        self.assertEqual(result["consensus_credit"], 0)

    def test_unknown_or_failed_process_exit_cannot_complete(self):
        for code in (None, 1, 124, -15):
            with self.subTest(code=code):
                result = read(self.first, code)
                self.assertEqual(result["status"], "INCOMPLETE")
                self.assertEqual(result["exit_code"], 3)
                self.assertTrue(result["footer_observed"])
                self.assertTrue(all(row["cost_per_accepted_winner"]["cpu_ns"] is None for row in result["arms"]))
        self.assertEqual(read(self.first, False)["status"], "INVALID")

    def test_every_first_cohort_prefix_retains_unknown_incomplete_cost(self):
        end = next(i for i, row in enumerate(self.cost) if row["event"] == "cohort_end")
        for n in range(end + 2):
            result = read(self.cost[:n])
            self.assertEqual(result["status"], "INCOMPLETE", (n, result))
            self.assertIsNone(result["unfinished_resource_cost"])
        result = read(self.first[:-1])
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertEqual(result["counts"]["cohorts"], 40)

    def test_partial_line_and_failure_record_preserve_uncertainty(self):
        at = next(i for i, row in enumerate(self.cost) if row["event"] == "attempt_begin")
        raw = encode(self.cost[:at + 2])[:-17]
        result = reader.read_stream(io.BytesIO(raw), process_exit_code=-15)
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertGreater(result["trailing_partial_bytes"], 0)
        self.assertEqual(result["unfinished_search"], {"sample": 0, "arm": 0, "search": 0})
        rows = self.cost[:at + 1] + [{"event": "failure", "error": "GENERATION_CANCELLED"}]
        result = read(rows, 1)
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertEqual(result["failure"], "GENERATION_CANCELLED")
        self.assertIsNone(result["unfinished_resource_cost"])

    def test_fixed_roster_and_no_credit_cannot_be_relabelled(self):
        mutations = {"arms": list(reversed(reader.ARMS)), "samples": 7, "material": "maintenance",
            "consensus_credit": 1, "production_activation": True, "cheapest_strategy_proven": True,
            "clock": "changed", "rotation": "post-hoc-fastest", "proof_bytes": 49187,
            "max_attempts": 2, "target_index": True, "horizon": True,
            "a_sha256": "00" * 32, "prefix_sha256": "00" * 32}
        for key, value in mutations.items():
            with self.subTest(field=key):
                rows = copy.deepcopy(self.first[:1])
                rows[0][key] = value
                self.assert_invalid(rows)

    def test_deleted_duplicated_and_reordered_events_cannot_close(self):
        for event in ("setup_finish", "attempt_begin", "attempt_finish", "verify_begin", "verify_finish", "cleanup_finish"):
            pos = next(i for i, row in enumerate(self.first) if row["event"] == event)
            with self.subTest(deleted=event):
                self.assert_invalid(self.first[:pos] + self.first[pos + 1:])
            with self.subTest(duplicated=event):
                self.assert_invalid(self.first[:pos] + [self.first[pos]] + self.first[pos:])
        rows = copy.deepcopy(self.first)
        rows[1]["position"] = 1
        self.assert_invalid(rows)
        rows = copy.deepcopy(self.first)
        rows[1]["arm"] = 1
        self.assert_invalid(rows)

    def test_sequence_types_duplicate_keys_and_noninteger_numbers(self):
        raw = encode(self.first[:1])
        for forged in (raw.replace(b'"seq":0', b'"seq":false'),
                       raw.replace(b'"seq":0', b'"seq":0,"seq":0'),
                       raw.replace(b'"seq":0', b'"seq":1'),
                       raw.replace(b'"samples":8', b'"samples":8.0'),
                       raw.replace(b'"cpu_ns":11', b'"cpu_ns":NaN')):
            result = reader.read_stream(io.BytesIO(forged), process_exit_code=0)
            self.assertEqual(result["status"], "INVALID", result)

    def test_actual_misses_and_complete_proof_identity_are_checked(self):
        first_attempt = next(i for i, row in enumerate(self.cost) if row["event"] == "attempt_finish")
        for field, value in (("nonce", 1), ("challenge", "00" * 32), ("ticket", "00" * 32),
                             ("proof_sha256", "00" * 32), ("hit", True), ("materialized", False)):
            with self.subTest(field=field):
                rows = copy.deepcopy(self.cost[:first_attempt + 1])
                rows[-1][field] = value
                self.assert_invalid(rows)
        lazy = next(i for i, row in enumerate(self.cost) if row["event"] == "attempt_finish" and row["arm"] == 1 and not row["hit"])
        rows = copy.deepcopy(self.cost[:lazy + 1])
        rows[-1]["materialized"] = True
        self.assert_invalid(rows)

    def test_self_consistent_changed_trace_still_breaks_matched_arm_stream(self):
        result = read(synthetic_rows(0, changed_trace=(0, 1, 0, 1)))
        self.assertEqual(result["status"], "INVALID")
        self.assertIn("matched arm", result["error"])

    def test_cannot_omit_misses_or_continue_after_first_hit(self):
        pos = next(i for i, row in enumerate(self.cost) if row["event"] == "attempt_finish")
        rows = copy.deepcopy(self.cost[:pos + 1])
        rows.append({"event": "search_finish", "sample": 0, "arm": 0, "search": 0,
                     "attempts": 1, "first_hit_nonce": None, "timing": tm(100)})
        self.assert_invalid(rows)
        pos = next(i for i, row in enumerate(self.first) if row["event"] == "attempt_finish")
        rows = copy.deepcopy(self.first[:pos + 1])
        rows.append({"event": "attempt_begin", "sample": 0, "arm": 0, "search": 0, "nonce": 1})
        self.assert_invalid(rows)

    def test_verifiers_bind_original_target_and_exact_mutant_bytes(self):
        for event, kind in (("verify_begin", "winner"), ("verify_finish", "product-last")):
            pos = next(i for i, row in enumerate(self.cost) if row["event"] == event and row["kind"] == kind)
            for key, value in (("target", reader.TARGETS[3]), ("proof_sha256", "00" * 32), ("verifier", "cached")):
                with self.subTest(event=event, field=key):
                    rows = copy.deepcopy(self.cost[:pos + 1])
                    rows[-1][key] = value
                    self.assert_invalid(rows)

    def test_real_verifier_failure_is_retained_and_cannot_be_promoted(self):
        pos = next(i for i, row in enumerate(self.first) if row["event"] == "verify_finish")
        rows = copy.deepcopy(self.first[:pos + 1])
        rows[-1].update(accepted=False, error="Transcript")
        result = read(rows + [{"event": "failure", "error": "COMPLETE_VERIFIER_DISAGREEMENT"}], 1)
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertEqual(len(result["semantic_failures"]), 1)
        self.assertEqual(result["counts"]["verification_calls"], 1)
        self.assert_invalid(rows + [self.first[-1]])
        rows[-1].update(accepted=True, error="Transcript")
        self.assert_invalid(rows)

    def test_exhaustion_replay_does_not_create_winners_or_cost_ratios(self):
        result = read(self.exhaustion)
        self.assertEqual(result["status"], "COMPONENT_OBSERVATION", result)
        self.assertEqual(result["counts"]["verification_calls"], 40 * 3 * 2)
        self.assertEqual(result["counts"]["hits"], 0)
        self.assertEqual(result["counts"]["exhausted"], 40)
        for arm in result["arms"]:
            self.assertEqual(arm["accepted_winners"], 0)
            self.assertIsNone(arm["cost_per_accepted_winner"]["cpu_ns"])
        pos = next(i for i, row in enumerate(self.exhaustion) if row["event"] == "verify_begin")
        rows = copy.deepcopy(self.exhaustion[:pos + 1])
        rows[-1]["target"] = reader.TARGETS[2]
        self.assert_invalid(rows)

    def test_disposal_and_setup_remain_in_cost_with_correct_denominator(self):
        result = read(self.cost)
        self.assertEqual(result["status"], "COMPONENT_OBSERVATION", result)
        expected = 8 * (7 + 3 * (10 + 1) + 2 + 1)
        for arm in result["arms"]:
            self.assertEqual(arm["producer_total"]["cpu_ns"], expected)
            self.assertEqual(arm["cost_per_accepted_winner"]["cpu_ns"], {"numerator": expected, "denominator": 8})
            self.assertEqual(arm["evidence_total"]["cpu_ns"], 8 * 3 * 3)
            self.assertEqual(arm["verification_total"]["cpu_ns"], 8 * 4 * 5)
        self.assertEqual([arm["materialized"] for arm in result["arms"]], [24, 8, 24, 24, 8])

    def test_unknown_clock_propagates_and_overlapping_timer_fraud_is_rejected(self):
        rows = copy.deepcopy(self.cost)
        pos = next(i for i, row in enumerate(rows) if row["event"] == "attempt_finish")
        rows[pos]["producer"]["cpu_ns"] = None
        result = read(rows)
        self.assertEqual(result["status"], "COMPONENT_OBSERVATION")
        self.assertIsNone(result["arms"][0]["producer_total"]["cpu_ns"])
        self.assertIsNone(result["arms"][0]["cost_per_accepted_winner"]["cpu_ns"])
        for event, field in (("search_finish", "timing"), ("cohort_end", "total")):
            rows = copy.deepcopy(self.cost)
            pos = next(i for i, row in enumerate(rows) if row["event"] == event)
            rows[pos][field] = tm(1)
            self.assert_invalid(rows)

    def test_footer_counters_and_terminal_order_are_checked(self):
        for key in reader.COUNTERS:
            rows = copy.deepcopy(self.first)
            rows[-1]["counts"][key] += 1
            self.assert_invalid(rows)
        self.assert_invalid(self.first + [{"event": "failure", "error": "after footer"}])
        self.assert_invalid(self.first[:6] + [self.first[-1]])

    def test_invalid_tail_after_complete_footer_cannot_keep_comparative_rates(self):
        report = self.assert_invalid(self.first + [{"event": "failure", "error": "invalid suffix"}])
        self.assertTrue(report["footer_observed"])
        self.assertEqual(report["counts"]["hits"], 40)
        for arm in report["arms"]:
            self.assertIsNone(arm["cost_per_accepted_winner"]["cpu_ns"])
            self.assertIsNone(arm["cost_per_accepted_winner"]["wall_ns"])

    def test_campaign_rejects_stripped_or_contradictory_complete_summaries(self):
        minimal = [{"schema": reader.SCHEMA + "-readback", "status": "COMPONENT_OBSERVATION",
                    "target_index": target, "horizon": horizon, "logical_prefix_sha256": {},
                    **reader.FALSE_FLAGS} for target, horizon in reader.grid()]
        self.assertEqual(reader.campaign(minimal)["status"], "INVALID")
        baseline = read(self.first)
        mutations = [
            ("native_process_exit_code", None), ("native_process_exit_code", False),
            ("footer_observed", False), ("error", "bad"), ("failure", "failed"),
            ("semantic_failures", ["failed"]), ("trailing_partial_bytes", 1),
            ("logical_prefix_sha256", {}), ("arms", []), ("records_checked", 0),
        ]
        for key, value in mutations:
            with self.subTest(field=key, value=value):
                changed = copy.deepcopy(baseline)
                changed[key] = value
                self.assertEqual(reader.campaign([changed])["status"], "INVALID")
        for key in ("cohorts", "setup_calls", "searches", "attempts", "hits", "misses"):
            changed = copy.deepcopy(baseline)
            changed["counts"][key] += 1
            self.assertEqual(reader.campaign([changed])["status"], "INVALID", key)
        for mutation in ("missing-prefix", "bad-hash", "cross-arm", "missing-sample", "sample-identity"):
            changed = copy.deepcopy(baseline)
            if mutation == "missing-prefix":
                del changed["logical_prefix_sha256"]["0:0:0"]
            elif mutation == "bad-hash":
                changed["logical_prefix_sha256"]["0:0:0"] = "not-sha256"
            elif mutation == "cross-arm":
                changed["logical_prefix_sha256"]["0:1:0"] = "00" * 32
            elif mutation == "missing-sample":
                changed["arms"][0]["samples"].pop()
            else:
                changed["arms"][0]["samples"][0]["sample"] = 1
            self.assertEqual(reader.campaign([changed])["status"], "INVALID", mutation)

    def test_six_shard_campaign_requires_exact_grid_and_correlated_prefixes(self):
        reports = [read(synthetic_rows(target, horizon)) for target, horizon in reader.grid()]
        self.assertTrue(all(report["status"] == "COMPONENT_OBSERVATION" for report in reports))
        result = reader.campaign(reports)
        self.assertEqual(result["status"], "COMPONENT_OBSERVATION", result)
        self.assertEqual(reader.campaign(reports[:-1])["status"], "INCOMPLETE")
        self.assertEqual(reader.campaign(reports + [reports[0]])["status"], "INVALID")
        changed = copy.deepcopy(reports)
        changed[1]["logical_prefix_sha256"]["0:0:0"] = "00" * 32
        self.assertEqual(reader.campaign(changed)["status"], "INVALID")
        changed = copy.deepcopy(reports)
        changed[0]["status"] = "INCOMPLETE"
        self.assertEqual(reader.campaign(changed)["status"], "INCOMPLETE")

    def test_campaign_cost_ratio_rejects_equal_float_and_boolean_integers(self):
        # A synthetic summary-only type fixture: one winner and seven exhausted
        # searches per arm. No native execution or W1 trace is claimed. Integer
        # zero CPU costs allow False == 0 to exercise the actual nested-dict bug;
        # a denominator of one likewise exercises True == 1.
        report = read(self.cost)
        attempts = 7 * reader.LIMIT + 3
        for arm in report["arms"]:
            arm.update(accepted_winners=1, attempts=attempts, misses=attempts - 1,
                       exhausted=7, materialized=attempts if arm["arm"] in (0, 2, 3) else 1)
            arm["producer_total"]["cpu_ns"] = 0
            arm["paid_setup"]["cpu_ns"] = 0
            for sample in arm["samples"]:
                sample["accepted_winners"] = int(sample["sample"] == 0)
                sample["producer_total"]["cpu_ns"] = 0
            for axis in reader.AXES:
                arm["cost_per_accepted_winner"][axis] = {
                    "numerator": arm["producer_total"][axis], "denominator": 1}
        report["counts"].update(attempts=5 * attempts, hits=5, misses=5 * (attempts - 1),
                                exhausted=35, materialized=3 * attempts + 2, verification_calls=20)
        report["records_checked"] = 2 + 3 * 40 + 4 * 40 + 2 * 5 * attempts + 2 * 20
        # The one valid-structure shard is incomplete only because the other
        # five campaign shards are absent; type mutation must make it INVALID.
        self.assertEqual(reader.campaign([report])["status"], "INCOMPLETE")
        for field, value in (("numerator", 0.0), ("numerator", False),
                             ("denominator", 1.0), ("denominator", True)):
            with self.subTest(field=field, type=type(value).__name__):
                changed = copy.deepcopy(report)
                changed["arms"][0]["cost_per_accepted_winner"]["cpu_ns"][field] = value
                result = reader.campaign([changed])
                self.assertEqual(result["status"], "INVALID", result)
                self.assertIn("cost ratio." + field, result["error"])
                self.assertFalse(result["source_execution_authenticated"])

    def test_cli_exit_codes_and_missing_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.jsonl"
            for rows, supplied, expected in ((self.first, 0, 0), (self.first[:-1], 0, 3),
                                              (self.first, 1, 3), (self.first[1:], 0, 2)):
                path.write_bytes(encode(rows))
                process = subprocess.run([sys.executable, reader.__file__, str(path),
                    "--process-exit-code", str(supplied)], capture_output=True, check=False)
                self.assertEqual(process.returncode, expected, process.stderr)
                report = json.loads(process.stdout)
                self.assertEqual(report["exit_code"], expected)
                self.assertFalse(report["independent_w1_replay"])
            missing = reader.analyze(Path(directory) / "absent", 0)
            self.assertEqual(missing["status"], "INCOMPLETE")
            self.assertIn("input_error", missing)


if __name__ == "__main__":
    unittest.main()
