#!/usr/bin/env python3
"""Mutation tests with independently generated complete certificates.

The tiny synthetic ledger timestamps below test accounting logic only. They are
not measured mining costs or native-execution receipts. Real Rust tiny outputs
are exercised separately by integration; no large raw fixture is committed.
"""
from __future__ import annotations

import copy
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "scripts"))
import w1_joint_challenge_reader as reader


@lru_cache(maxsize=32)
def certificate(header_bytes):
    challenge = reader.H("challenge", header_bytes)
    # Scalar Python generation and scalar replay are functional controls, not
    # evidence that this fixture's invented CPU values occurred on a machine.
    return reader.work_oracle.prove(challenge, [0] * reader.CELLS, [0] * reader.CELLS)


def fixture(*, producer="avx2-joint", mode="hot", width=2, attempts=3,
            nonce_space=2, budget=None, target=None):
    options = dict(producer=producer, family="zero", mode=mode, attempts=attempts,
                   width=width, seed=117, sample=3, target=target or [255] * 32,
                   cpu_budget_ns=budget, nonce_space=nonce_space)
    rows = []

    def add(kind, **fields):
        row = dict(schema=reader.SCHEMA, kind=kind, **fields)
        rows.append(row)
        return row

    add("start", options=options, avx2_available=True,
        simd_lanes=4 if producer == "avx2-joint" else 1, **reader.START_FIXED)
    core_cpu = core_wall = charges = 0

    def charge(stage, batch, cpu, wall):
        nonlocal core_cpu, core_wall, charges
        core_cpu += cpu
        core_wall += wall
        add("charge", seq=charges, stage=stage, batch_index=batch, cpu_ns=cpu, wall_ns=wall,
            cumulative_charged_cpu_ns=core_cpu, cumulative_charged_wall_ns=core_wall)
        charges += 1

    charge("material", None, 10, 20)
    matrix = bytes(reader.CELLS * 4)
    task = reader.H("task", matrix, matrix)
    add("material", family="zero", source="synthetic-fixture", task=task.hex(),
        a_hex=matrix.hex(), b_hex=matrix.hex(), setup_complete_elapsed_cpu_ns=20,
        setup_complete_inclusive_cpu_ns=20, material_cpu_ns=10, material_wall_ns=20)
    elapsed, wall = 20, 30
    observer_cpu = observer_wall = done = batches = hits = unique_hits = in_budget = budget_hits = 0
    seen = set()

    def can_start():
        return budget is None or elapsed - observer_cpu < budget

    if mode == "hot" and can_start():
        charge("prepare", None, 30, 40)
        elapsed += 35
        wall += 45
    while done < attempts and can_start():
        if mode == "cold":
            charge("prepare", batches, 30, 40)
            elapsed += 35
            wall += 45
            if not can_start():
                break
        count = min(width, attempts - done)
        begin = done
        charge("generate", batches, 50, 60)
        elapsed += 65
        wall += 75
        complete_cpu, complete_wall = elapsed, wall
        inclusive = complete_cpu - observer_cpu
        within = budget is None or inclusive <= budget
        add("batch", batch_index=batches, attempt_start=done, active_lanes=count,
            padded_lanes=4 - count if producer == "avx2-joint" else 0,
            completion_elapsed_cpu_ns=complete_cpu, completion_elapsed_wall_ns=complete_wall,
            observer_before_cpu_ns=observer_cpu, inclusive_producer_cpu_ns=inclusive,
            inclusive_within_cpu_budget=within, cumulative_charged_cpu_ns=core_cpu)
        for lane in range(count):
            index = begin + lane
            header = reader.header_encode(reader.expected_header(options, task, index))
            proof = certificate(header)
            challenge = reader.H("challenge", header)
            trace = proof[-32:]
            ticket = reader.H("ticket", challenge, trace)
            semantic = reader.H("w1-cost-game-semantic-ticket-v1", task, challenge, ticket)
            unique = semantic not in seen
            hit = bytes(options["target"]) != bytes(32) and ticket <= bytes(options["target"])
            seen.add(semantic)
            duration_cpu, duration_wall = 7 + lane, 9 + lane
            observer_cpu += duration_cpu
            observer_wall += duration_wall
            elapsed += duration_cpu + 10
            wall += duration_wall + 12
            add("attempt", index=index, batch_index=batches, lane=lane, header_hex=header.hex(),
                challenge=challenge.hex(), task=task.hex(), target=bytes(options["target"]).hex(),
                trace=trace.hex(), ticket=ticket.hex(), block_id=reader.H("block", header, trace).hex(),
                semantic_id=semantic.hex(), proof_hex=proof.hex(), proof_sha256=hashlib.sha256(proof).hexdigest(),
                proof_bytes=len(proof), target_hit=hit, unique=unique,
                qualification_level="relation-valid", native_admitted=False,
                production_full_verify=True, reference_full_verify=True,
                relation_verification_target="ff" * 32,
                observer_cpu_ns=duration_cpu, observer_wall_ns=duration_wall,
                cumulative_observer_cpu_ns=observer_cpu,
                completion_elapsed_cpu_ns=complete_cpu, inclusive_producer_cpu_ns=inclusive,
                inclusive_within_cpu_budget=within)
            done += 1
            hits += int(hit)
            unique_hits += int(unique and hit)
            in_budget += int(unique and within)
            budget_hits += int(unique and hit and within)
        batches += 1
    elapsed += 15
    wall += 20
    inclusive = elapsed - observer_cpu
    add("end", status="attempt-cap-complete" if done == attempts else "inclusive-cpu-budget-exhausted",
        complete=True, attempts=done, batches=batches, charges=charges, target_hits=hits,
        target_misses=done - hits, unique_opportunities=len(seen), unique_target_hits=unique_hits,
        inclusive_budget_unique_opportunities=in_budget,
        inclusive_budget_unique_target_hits=budget_hits,
        native_admitted=0, production_full_verified=done, reference_full_verified=done,
        charged_core_cpu_ns=core_cpu, charged_core_wall_ns=core_wall,
        observer_cpu_ns=observer_cpu, observer_wall_ns=observer_wall,
        elapsed_cpu_ns=elapsed, elapsed_wall_ns=wall, inclusive_producer_cpu_ns=inclusive,
        inclusive_noncore_cpu_ns=inclusive - core_cpu,
        budget_stop=reader.START_FIXED["budget_stop"], overrun_cost_refunded=False,
        cache_and_material_teardown_included=True, final_end_emission_included=False)
    return rows


class JointReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = fixture()

    def read(self, rows, expected_options=None):
        with tempfile.TemporaryDirectory(prefix="w1-joint-reader-test-") as folder:
            path = Path(folder) / "raw.jsonl"
            path.write_text("".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows))
            return reader.read_joint(path, expected_options=expected_options)

    def reject(self, change, pattern=None, rows=None):
        altered = copy.deepcopy(self.base if rows is None else rows)
        change(altered)
        with self.assertRaisesRegex(ValueError, pattern or ".+"):
            self.read(altered)

    def test_complete_proofs_duplicates_and_partial_width_are_independently_replayed(self):
        result = self.read(self.base, expected_options=self.base[0]["options"])
        self.assertEqual(result["all_completed_proofs_python_replayed"], 3)
        self.assertEqual(result["end"]["unique_opportunities"], 2)
        self.assertEqual(result["end"]["unique_target_hits"], 2)
        self.assertEqual([v["unique"] for v in result["attempts"]], [True, True, False])
        self.assertNotIn("proof_hex", result["attempts"][0])
        self.assertFalse(result["native_admitted"])
        self.assertFalse(result["hardware_attested"])

    def test_both_producers_and_preparation_modes_match_the_same_header_stream(self):
        outputs = []
        for producer in ("avx2-joint", "prepared-sequential"):
            for mode in ("cold", "hot"):
                result = self.read(fixture(producer=producer, mode=mode, width=1))
                outputs.append([v["challenge"] for v in result["attempts"]])
                self.assertEqual(result["prepare_count"], 3 if mode == "cold" else 1)
        self.assertTrue(all(value == outputs[0] for value in outputs))

    def test_zero_target_still_replays_every_complete_miss(self):
        result = self.read(fixture(target=[0] * 32))
        self.assertEqual(result["all_completed_proofs_python_replayed"], 3)
        self.assertEqual(result["end"]["target_hits"], 0)
        self.assertEqual(result["end"]["inclusive_budget_unique_opportunities"], 2)

    def test_exact_budget_endpoint_counts_and_completed_overrun_does_not(self):
        at = self.read(fixture(budget=120))
        below = self.read(fixture(budget=119))
        self.assertEqual(at["end"]["attempts"], 2)
        self.assertEqual(at["end"]["inclusive_budget_unique_opportunities"], 2)
        self.assertEqual(below["end"]["attempts"], 2)
        self.assertEqual(below["end"]["inclusive_budget_unique_opportunities"], 0)
        self.assertEqual(at["end"]["charged_core_cpu_ns"], below["end"]["charged_core_cpu_ns"])
        self.assertGreater(below["end"]["inclusive_producer_cpu_ns"], 119)

    def test_zero_budget_and_prepare_overrun_finish_without_claiming_proofs(self):
        for budget in (0, 1, 40):
            result = self.read(fixture(budget=budget))
            self.assertEqual(result["all_completed_proofs_python_replayed"], 0)
            self.assertEqual(result["end"]["inclusive_budget_unique_target_hits"], 0)
            self.assertEqual(result["end"]["status"], "inclusive-cpu-budget-exhausted")
        self.assertEqual(self.read(fixture(budget=40))["prepare_count"], 1)

    def test_missing_end_missing_attempt_and_duplicate_attempt_are_rejected(self):
        self.reject(lambda rows: rows.pop(), "MISSING_COMPLETE_END")
        self.reject(lambda rows: rows.pop(next(i for i, r in enumerate(rows) if r["kind"] == "attempt")))
        self.reject(lambda rows: rows.insert(6, copy.deepcopy(next(r for r in rows if r["kind"] == "attempt"))))

    def test_unknown_fields_and_unknown_or_failure_rows_are_rejected(self):
        for kind in reader.ROW_FIELDS:
            with self.subTest(kind=kind):
                self.reject(lambda rows, kind=kind: next(r for r in rows if r["kind"] == kind).update(invented=1), "ROW_FIELDS")
        self.reject(lambda rows: rows.insert(1, {"schema": reader.SCHEMA, "kind": "failure"}), "UNKNOWN_ROW_KIND")
        self.reject(lambda rows: rows.append(copy.deepcopy(rows[-1])), "ROWS_AFTER_END")

    def test_duplicate_json_keys_nonfinite_numbers_and_truncated_last_line_reject(self):
        serialized = "".join(json.dumps(row) + "\n" for row in self.base)
        cases = [
            serialized.replace('"seed": 117', '"seed": 117, "seed": 117', 1),
            serialized.replace('"seed": 117', '"seed": NaN', 1),
            serialized.rstrip("\n"),
        ]
        for data in cases:
            with self.subTest():
                with tempfile.TemporaryDirectory(prefix="w1-joint-json-test-") as folder:
                    path = Path(folder) / "raw.jsonl"
                    path.write_text(data)
                    with self.assertRaises(ValueError):
                        reader.read_joint(path)

    def test_line_limit_rejects_without_loading_unbounded_output(self):
        with tempfile.TemporaryDirectory(prefix="w1-joint-limit-test-") as folder:
            path = Path(folder) / "raw.jsonl"
            path.write_bytes(b" " * (reader.MAX_LINE_BYTES + 1) + b"\n")
            with self.assertRaisesRegex(ValueError, "RAW_LIMIT"):
                reader.read_joint(path)

    def test_source_options_material_and_native_promotion_are_rejected(self):
        expected = copy.deepcopy(self.base[0]["options"])
        expected["seed"] += 1
        with self.assertRaisesRegex(ValueError, "EXPECTED_OPTIONS"):
            self.read(self.base, expected_options=expected)
        self.reject(lambda rows: rows[0].update(hardware_attested=True), "START_BOUNDARY")
        self.reject(lambda rows: rows[0].update(avx2_available=False), "UNSUPPORTED_AVX2")
        self.reject(lambda rows: next(r for r in rows if r["kind"] == "attempt").update(native_admitted=True), "ATTEMPT_BOUNDARY")
        self.reject(lambda rows: next(r for r in rows if r["kind"] == "material").update(a_hex="01" + "00" * (reader.CELLS * 4 - 1)), "MATERIAL_RECIPE")

    def test_header_context_nonce_and_target_cannot_be_substituted(self):
        def mutate(rows, field):
            row = next(r for r in rows if r["kind"] == "attempt")
            header = reader.header_decode(bytes.fromhex(row["header_hex"]))
            header[field] = header[field] + 1 if field in ("nonce", "timestamp") else bytes(32)
            row["header_hex"] = reader.header_encode(header).hex()
        for field in ("nonce", "timestamp", "parent", "target"):
            with self.subTest(field=field):
                self.reject(lambda rows, field=field: mutate(rows, field), "DIAGNOSTIC_HEADER_BINDING")
        self.reject(lambda rows: next(r for r in rows if r["kind"] == "attempt").update(target="00" * 32), "LITERAL_TARGET")

    def test_corrupt_product_with_consistent_hash_still_requires_full_python_replay(self):
        def change(rows):
            row = next(r for r in rows if r["kind"] == "attempt")
            proof = bytearray.fromhex(row["proof_hex"])
            proof[4 + reader.CELLS * 8] = 1
            row["proof_hex"] = proof.hex()
            row["proof_sha256"] = hashlib.sha256(proof).hexdigest()
        self.reject(change, "PRODUCT")

    def test_forged_trace_passing_max_target_is_not_valid_cost_work(self):
        def change(rows):
            row = next(r for r in rows if r["kind"] == "attempt")
            proof = bytearray.fromhex(row["proof_hex"])
            proof[-1] ^= 1
            trace = bytes(proof[-32:])
            challenge, task, header = (bytes.fromhex(row[key]) for key in ("challenge", "task", "header_hex"))
            ticket = reader.H("ticket", challenge, trace)
            row.update(proof_hex=proof.hex(), proof_sha256=hashlib.sha256(proof).hexdigest(),
                       trace=trace.hex(), ticket=ticket.hex(),
                       semantic_id=reader.H("w1-cost-game-semantic-ticket-v1", task, challenge, ticket).hex(),
                       block_id=reader.H("block", header, trace).hex())
        self.reject(change, "TRANSCRIPT")

    def test_same_semantic_ticket_cannot_gain_new_credit_or_early_lane_delivery(self):
        def duplicate_credit(rows):
            repeated = [r for r in rows if r["kind"] == "attempt"][-1]
            repeated["unique"] = True
            rows[-1]["unique_opportunities"] += 1
        self.reject(duplicate_credit, "SEMANTIC_DUPLICATION")
        self.reject(lambda rows: next(r for r in rows if r["kind"] == "attempt").update(
            inclusive_producer_cpu_ns=119), "ATTEMPT_COMPLETION_FENCE")

    def test_known_budget_fence_blocks_a_later_batch_even_if_final_sums_fit(self):
        def change(rows):
            rows[0]["options"]["cpu_budget_ns"] = 120
            for row in rows:
                if row["kind"] in ("batch", "attempt"):
                    row["inclusive_within_cpu_budget"] = row["inclusive_producer_cpu_ns"] <= 120
            rows[-1]["inclusive_budget_unique_opportunities"] = 2
            rows[-1]["inclusive_budget_unique_target_hits"] = 2
        self.reject(change, "START_AFTER_KNOWN_BUDGET_FENCE")

    def test_prepare_core_cost_alone_cannot_cross_budget_then_start_generation(self):
        def change(rows):
            rows[0]["options"]["cpu_budget_ns"] = 40
            # The material completion is below 40, but the recorded preparation
            # makes accumulated producer core cost exactly 40 before generation.
            for row in rows:
                if row["kind"] in ("batch", "attempt"):
                    row["inclusive_within_cpu_budget"] = False
            rows[-1]["inclusive_budget_unique_opportunities"] = 0
            rows[-1]["inclusive_budget_unique_target_hits"] = 0
        self.reject(change, "START_AFTER_KNOWN_BUDGET_FENCE")

    def test_overrun_cannot_be_refunded_or_relabelled_in_budget(self):
        rows = fixture(budget=119)
        def change(values):
            for row in values:
                if row["kind"] in ("batch", "attempt"):
                    row["inclusive_within_cpu_budget"] = True
            values[-1]["inclusive_budget_unique_opportunities"] = 2
            values[-1]["inclusive_budget_unique_target_hits"] = 2
        self.reject(change, "BATCH_BUDGET", rows)
        self.reject(lambda values: values[-1].update(overrun_cost_refunded=True), "END_BOUNDARY", rows)

    def test_observer_scope_and_completion_cost_cannot_be_silently_changed(self):
        def observer_change(rows):
            batches = [r for r in rows if r["kind"] == "batch"]
            batches[-1]["observer_before_cpu_ns"] = 0
        self.reject(observer_change, "BATCH_OBSERVER_FENCE")
        self.reject(lambda rows: rows[-1].update(observer_cpu_ns=0), "END_RECONCILIATION")
        self.reject(lambda rows: rows[-1].update(cache_and_material_teardown_included=False), "END_BOUNDARY")
        self.reject(lambda rows: rows[-1].update(final_end_emission_included=True), "END_BOUNDARY")
        self.reject(lambda rows: rows[-1].update(inclusive_noncore_cpu_ns=0), "END_NONCORE")

    def test_wrong_charge_sequence_batch_count_or_padding_rejects(self):
        self.reject(lambda rows: next(r for r in rows if r["kind"] == "charge").update(seq=1), "CHARGE_SEQUENCE")
        self.reject(lambda rows: next(r for r in rows if r["kind"] == "charge").update(cumulative_charged_cpu_ns=0), "CHARGED_CPU_SUM")
        self.reject(lambda rows: next(r for r in rows if r["kind"] == "batch").update(active_lanes=1), "ACTIVE_LANES")
        self.reject(lambda rows: next(r for r in rows if r["kind"] == "batch").update(padded_lanes=0), "PADDED_LANES")
        self.reject(lambda rows: rows[-1].update(attempts=4), "END_RECONCILIATION")

    def test_noninteger_ledger_fields_and_false_verifier_claims_reject(self):
        self.reject(lambda rows: rows[-1].update(attempts=True), "END_RECONCILIATION")
        self.reject(lambda rows: next(r for r in rows if r["kind"] == "charge").update(cpu_ns=10.0), "CHARGE_CPU")
        self.reject(lambda rows: next(r for r in rows if r["kind"] == "attempt").update(reference_full_verify=False), "ATTEMPT_BOUNDARY")
        self.reject(lambda rows: next(r for r in rows if r["kind"] == "attempt").update(target_hit=False), "TARGET_PREDICATE")

    def test_missing_preparation_and_premature_or_mislabelled_end_reject(self):
        self.reject(lambda rows: rows.pop(next(i for i, row in enumerate(rows) if row["kind"] == "charge" and row["stage"] == "prepare")))
        self.reject(lambda rows: rows[-1].update(status="inclusive-cpu-budget-exhausted"), "END_CAP_STATUS")
        self.reject(lambda rows: rows[-1].update(complete=False), "END_BOUNDARY")

    def test_options_match_defaults_u64_grammar_and_duplicate_rejection(self):
        options = reader.options_from_args([])
        self.assertEqual(options["attempts"], 4)
        self.assertEqual(options["width"], 4)
        self.assertEqual(options["nonce_space"], 4)
        self.assertEqual(reader.options_from_args(["--seed", "+0003"])["seed"], 3)
        for args in [
            ["--width", "0"], ["--width", "5"], ["--nonce-space", "0"],
            ["--attempts", "4097"], ["--seed", str(1 << 64)],
            ["--seed", "1_000"], ["--seed", "-1"], ["--seed", " 1"],
            ["--width", "1", "--width", "2"], ["--family", "unknown"],
            ["--target", "ff"], ["--unbounded", "1"], ["--seed"],
            ["--nonce_space", "2"],
        ]:
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    reader.options_from_args(args)


if __name__ == "__main__":
    unittest.main(verbosity=2)
