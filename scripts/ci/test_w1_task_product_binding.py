#!/usr/bin/env python3
"""Synthetic 100-row grammar controls; no native execution or timing evidence.

Only verify_case is mocked, because full scalar relations have separate controls.
The fake proof string is deliberately not hexadecimal, preventing this grammar
fixture from ever passing the real scalar reader without its explicit mock.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import read_w1_task_product_research as reader

FAMILIES = ("zero", "identity", "rank1", "sparse", "near_q", "dense")
TARGET = "ff" * 32


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def synthetic_case(row, seed, group, family, ordinal):
    expected = dict(type="case", id=f"{group}-{ordinal}", group=group, family=family,
                    ordinal=ordinal, proof_hex="SYNTHETIC_NO_NATIVE_PROOF")
    if row != expected or type(row["ordinal"]) is not int:
        raise ValueError("SYNTHETIC_CASE_ORDER")
    return dict(id=row["id"], group=group, family=family, ordinal=ordinal,
                challenge=sha(f"challenge:{seed}:{group}:{ordinal}"), task=sha("task:" + family),
                proof_sha256=sha("no-proof:" + row["id"]), ticket=sha("ticket:" + row["id"]),
                product_sha256=sha("product:" + family), noise_calls=256,
                material_wall_ns=1, prove_wall_ns=1, reference_wall_ns=1)


def fixture(seed):
    rows = [dict(type="start", schema="pon-w1-task-product-facts-research-v1", seed=seed,
                 profile="pon-matmul-transcript-64-v1", target=TARGET, proof_bytes=49188,
                 timing_scope="Instant-wall-per-operation-not-process-CPU",
                 reference_before_measurement=True,
                 whole_process_includes_material_proof_reference_output=True,
                 source_claim=False, production_activation=False, mining_opportunity_claim=False)]
    schedule = [("main-" + family, [family] * 4, 2, [False, True, True, True])
                for family in FAMILIES]
    schedule.append(("eviction", ["zero", "identity", "zero", "zero"], 1,
                     [False, False, False, True]))
    for group, families, capacity, warm_flags in schedule:
        rows.append(dict(type="group", group=group, families=families, cache_capacity=capacity,
                         cache_software_bytes=capacity * 49156 + 64, cache_create_wall_ns=1))
        for ordinal, (family, warm) in enumerate(zip(families, warm_flags)):
            row = dict(type="case", id=f"{group}-{ordinal}", group=group, family=family,
                       ordinal=ordinal, proof_hex="SYNTHETIC_NO_NATIVE_PROOF")
            case = synthetic_case(row, seed, group, family, ordinal)
            rows.append(row)
            for order, arm in enumerate(("raw", "facts") if seed == 8101 else ("facts", "raw")):
                reused = warm and arm == "facts"
                observation = None
                if arm == "facts":
                    observation = dict(lookup_probes=1 if warm else capacity, lookup_contended=False,
                                       exact_inputs_found=warm, product_reused=warm,
                                       transcript_entered=True, transcript_completed=True,
                                       product_reconstruction_entered=not warm,
                                       product_reconstruction_completed=not warm,
                                       publication_probes=0 if warm else capacity,
                                       publication="none" if warm else "stored")
                rows.append(dict(type="verify", case_id=case["id"], arm=arm, order=order,
                                 wall_ns=2 if arm == "raw" else 1, ticket=case["ticket"],
                                 product_sha256=case["product_sha256"],
                                 progress=dict(before_replay=1, noise=256, matrix_rows_before_product=128,
                                               transcript_tiles=512, before_product=1,
                                               matrix_rows_after_product=0 if reused else 200,
                                               before_verified_work=1), observation=observation))
        rows.append(dict(type="group_end", group=group, cache_drop_wall_ns=1))
    rows.append(dict(type="end", schema="pon-w1-task-product-facts-research-v1", status="PASS",
                     cases=28, verifications=56, observed_wall_before_final_output_ns=1000,
                     source_claim=False, production_activation=False, mining_opportunity_claim=False))
    assert len(rows) == 100
    return rows


class CompleteGrammarControls(unittest.TestCase):
    def read(self, rows, seed=8101):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.stdout"
            path.write_text("".join(json.dumps(row, allow_nan=False) + "\n" for row in rows))
            with patch.object(reader, "verify_case", side_effect=synthetic_case):
                return reader.read_raw(path, seed)

    def reject(self, rows, pattern, seed=8101):
        with self.assertRaisesRegex(ValueError, pattern):
            self.read(rows, seed)

    def test_both_registered_orders_complete_exactly_and_preserve_distinct_scopes(self):
        for seed in (8101, 8102):
            result = self.read(fixture(seed), seed)
            self.assertEqual(result["proof_records_replayed"], 28)
            self.assertEqual(result["accepted_verifier_calls"], 56)
            self.assertEqual(result["totals"]["cold"]["cases"], 9)
            self.assertEqual(result["totals"]["warm"]["cases"], 19)
            self.assertEqual(result["accounted_operation_wall_ns"], 182)
            self.assertEqual(result["unallocated_native_wall_ns"], 818)
            self.assertFalse(result["wall_ratio_is_cpu_ratio"])
            self.assertFalse(result["verifier_calls_are_mining_tickets"])
            self.assertEqual(result["node_admissions"], 0)

    def test_missing_or_extra_records_never_get_a_success_summary(self):
        for index in (0, 1, 2, 3, 13, 98, 99):
            rows = fixture(8101)
            rows.pop(index)
            self.reject(rows, "COMPLETE_ROW_SET")
            rows = fixture(8101)
            rows.insert(index, copy.deepcopy(rows[index]))
            self.reject(rows, "COMPLETE_ROW_SET")

    def test_same_length_duplicate_case_or_wrong_case_order_rejected(self):
        rows = fixture(8101)
        rows[5] = copy.deepcopy(rows[2])
        self.reject(rows, "SYNTHETIC_CASE_ORDER")
        rows = fixture(8101)
        rows[2:5], rows[5:8] = rows[5:8], rows[2:5]
        self.reject(rows, "SYNTHETIC_CASE_ORDER")

    def test_arm_order_cannot_be_swapped_or_relabelled(self):
        rows = fixture(8101)
        rows[3], rows[4] = rows[4], rows[3]
        self.reject(rows, "VERIFY_ORDER")
        rows = fixture(8101)
        rows[3]["arm"] = "facts"
        self.reject(rows, "VERIFY_ORDER")
        rows = fixture(8101)
        rows[4]["order"] = True
        self.reject(rows, "VERIFY_ORDER")

    def test_group_identity_capacity_and_closure_are_not_aliases(self):
        for field, value in (("cache_capacity", True), ("cache_capacity", 1),
                             ("group", "eviction"), ("families", ["identity"] * 4)):
            rows = fixture(8101)
            rows[1][field] = value
            self.reject(rows, "GROUP_IDENTITY")
        rows = fixture(8101)
        rows[14]["group"] = "main-identity"
        self.reject(rows, "GROUP_END")

    def test_eviction_misses_must_not_masquerade_as_warm_hits(self):
        rows = fixture(8101)
        call = next(row for row in rows if row.get("type") == "verify" and
                    row.get("case_id") == "eviction-2" and row.get("arm") == "facts")
        call["observation"].update(exact_inputs_found=True, product_reused=True,
                                   product_reconstruction_entered=False,
                                   product_reconstruction_completed=False,
                                   publication_probes=0, publication="none")
        call["progress"]["matrix_rows_after_product"] = 0
        self.reject(rows, "COMPLETE_FRESH_TRANSCRIPT|EXACT_CACHE_PATH")

    def test_warm_product_reuse_never_excuses_fresh_transcript_or_canonical_order(self):
        for field, value in (("transcript_tiles", 0), ("matrix_rows_before_product", 0),
                             ("before_replay", True), ("matrix_rows_after_product", 200)):
            rows = fixture(8101)
            call = next(row for row in rows if row.get("type") == "verify" and
                        row.get("case_id") == "main-zero-1" and row.get("arm") == "facts")
            call["progress"][field] = value
            self.reject(rows, "COMPLETE_FRESH_TRANSCRIPT")

    def test_negative_unallocated_wall_time_is_refused_not_clamped(self):
        rows = fixture(8101)
        rows[-1]["observed_wall_before_final_output_ns"] = 181
        self.reject(rows, "OVERLAPPING_OR_INCONSISTENT_WALL_SCOPES")
        rows = fixture(8101)
        rows[-1]["observed_wall_before_final_output_ns"] = 182
        self.assertEqual(self.read(rows)["unallocated_native_wall_ns"], 0)

    def test_success_summary_does_not_excuse_false_counts_or_activation(self):
        for field, value in (("cases", 27), ("verifications", 55), ("source_claim", True),
                             ("production_activation", True), ("mining_opportunity_claim", True)):
            rows = fixture(8101)
            rows[-1][field] = value
            self.reject(rows, "END_CONTRACT")

    def test_key_duplicate_and_trailing_bytes_are_not_accepted(self):
        rows = fixture(8101)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.stdout"
            text = "".join(json.dumps(row) + "\n" for row in rows)
            text = text.replace('"seed": 8101', '"seed": 8101, "seed": 8101', 1)
            path.write_text(text)
            with patch.object(reader, "verify_case", side_effect=synthetic_case):
                with self.assertRaisesRegex(ValueError, "DUPLICATE_JSON_KEY"):
                    reader.read_raw(path, 8101)
            path.write_text("".join(json.dumps(row) + "\n" for row in rows) + "{}\n")
            with patch.object(reader, "verify_case", side_effect=synthetic_case):
                with self.assertRaisesRegex(ValueError, "COMPLETE_ROW_SET"):
                    reader.read_raw(path, 8101)


if __name__ == "__main__":
    unittest.main()
