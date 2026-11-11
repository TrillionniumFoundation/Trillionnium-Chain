#!/usr/bin/env python3
"""Lifetime accounting negatives and source-survey boundaries, not proof tests."""
from __future__ import annotations

from copy import deepcopy
from fractions import Fraction
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "scripts/w1_lifetime_ledger.py"
SPEC = importlib.util.spec_from_file_location("tested_w1_lifetime_ledger", MODULE)
ledger = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ledger)


def fraction(numerator, denominator=1):
    return {"numerator": numerator, "denominator": denominator}


def git_blob(commit, path):
    """Read an existing exact Git object; never fetch or trust replacement refs."""
    return subprocess.check_output(
        ["git", "--no-replace-objects", "show", commit + ":" + path],
        cwd=ROOT, env=dict(os.environ, GIT_NO_LAZY_FETCH="1"), timeout=15)


def hypothetical():
    raw = ledger.template()
    raw["input_kind"] = "hypothetical"
    raw["lifetime"] = dict.fromkeys(ledger.LIFETIME_FIELDS, 0)
    raw["lifetime"].update(online_seconds=1, processors_max=1)
    raw["lifetime_bound_reference"] = "TEST ONLY: explicit hypothetical count assumptions."
    for item in raw["groups"].values():
        item["queries_per_occurrence_upper"] = dict.fromkeys(ledger.PHASES, 0)
        item["additional_reduction_queries_upper"] = dict.fromkeys(ledger.OVERHEADS, 0)
        item["online_mass_upper"] = {key: fraction(0) for key in ledger.MASSES}
        item["query_bound_reference"] = "TEST ONLY: assumed abstract oracle upper envelope."
    for item in raw["uniform_event_bounds"].values():
        item.update(opportunities_max=0, error_per_opportunity_upper=fraction(0),
                    assumed_bound_valid_up_to_joint_queries=1 << 128,
                    bound_reference="TEST ONLY: assumed uniform conditional bound, not a theorem.")
    raw["total_target_error"] = fraction(1, 256)
    return raw


class LifetimeLedgerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources = {path: (ROOT / path).read_bytes() for path in ledger.SOURCE_PINS}
        cls.survey = ledger.source_survey(cls.sources)

    def test_project_unknowns_do_not_produce_a_target_or_qualification(self):
        result = ledger.make_report(ledger.template(), ROOT)
        # This is an independently fixed successor, not an expected value read
        # from the implementation under test. The M8 observation stays intact.
        historical = ROOT / "evidence/pon-w1-lifetime-current-20261109/project-report.json"
        self.assertEqual(hashlib.sha256(historical.read_bytes()).hexdigest(),
                         "8ee20462d669a0e21b0fe964585f85fa2a49e7e58273459ab2501b4a2e39dfc0")
        fixture = ROOT / "evidence/pon-w1-lifetime-account-boundary-20261110/project-report.json"
        # Permit exactly the seven reviewed source-observation changes. Every
        # other historical report field is still compared in full; expected
        # values must not be populated from ledger.SOURCE_BASE/SOURCE_PINS.
        expected = json.loads(historical.read_bytes())
        survey = expected["selected_source_survey"]
        survey["base_commit"] = "077ac4f33206de00a178553d9a0c729a20685088"
        survey["observations"]["cumulative_weight"]["anchor_line"] = "5157"
        survey["observations"]["cumulative_weight"]["sha256"] = (
            "d4623d65b74a5f7d875037dceeb1a9c3d2a4d957791d4b39514a14eb3a2b90ca")
        survey["observations"]["native_work_verifier"]["anchor_line"] = "1124"
        survey["observations"]["native_work_verifier"]["sha256"] = (
            "d4623d65b74a5f7d875037dceeb1a9c3d2a4d957791d4b39514a14eb3a2b90ca")
        survey["sources"][7]["bytes"] = "383977"
        survey["sources"][7]["sha256"] = (
            "d4623d65b74a5f7d875037dceeb1a9c3d2a4d957791d4b39514a14eb3a2b90ca")
        self.assertEqual((json.dumps(expected, indent=2, sort_keys=True, allow_nan=False)
                          + "\n").encode(), fixture.read_bytes())
        self.assertEqual((json.dumps(result, indent=2, sort_keys=True, allow_nan=False)
                          + "\n").encode(), fixture.read_bytes())
        self.assertNotEqual(fixture.read_bytes(), historical.read_bytes())
        budget = result["lifetime_ledger"]
        self.assertIsNone(budget["sum_of_group_adversary_query_envelopes"])
        self.assertIsNone(budget["conditional_union"]["hypothetical_expression_meets_target"])
        self.assertIsNone(budget["conditional_union"]["project_total_error_upper"])
        self.assertIsNone(budget["conditional_union"]["project_target_met"])
        self.assertFalse(budget["coverage_exhaustiveness_proved"])
        for line in result["independent_acceptance"]["lines"].values():
            self.assertFalse(line["qualified"])
            self.assertIsNone(line["security_bits"])
            self.assertFalse(line["qualification_inferred_from_another_line"])
        self.assertFalse(result["independent_acceptance"]["all_three_qualified"])

    def test_processors_failed_roots_and_recursive_nodes_are_all_charged(self):
        raw = hypothetical()
        raw["lifetime"].update(processors_max=3,
                               accepted_root_attempts_per_processor_max=2,
                               failed_aborted_root_attempts_per_processor_max=5,
                               recursive_nodes_per_root_attempt_max=7)
        raw["groups"]["poseidon2_shared"]["queries_per_occurrence_upper"]["recursive_subproof_nodes"] = 11
        raw["uniform_event_bounds"]["complete_relation_verification_opportunities"]["opportunities_max"] = 21
        result = ledger.evaluate(raw)
        self.assertEqual(result["occurrences_all_processors_upper"]["recursive_subproof_nodes"], 147)
        self.assertEqual(result["groups"]["poseidon2_shared"]["adversary_queries_upper"], 1617)
        self.assertEqual(result["sum_of_group_adversary_query_envelopes"], 1617)

    def test_complete_relation_event_count_cannot_drop_failed_attempts(self):
        raw = hypothetical()
        raw["lifetime"].update(accepted_root_attempts_per_processor_max=2,
                               failed_aborted_root_attempts_per_processor_max=3)
        raw["uniform_event_bounds"]["complete_relation_verification_opportunities"]["opportunities_max"] = 2
        with self.assertRaisesRegex(ledger.LedgerError, "omits"):
            ledger.evaluate(raw)

    def test_offline_adaptive_delegated_and_unclassified_queries_accumulate(self):
        raw = hypothetical()
        raw["lifetime"].update(processors_max=2, offline_batches_per_processor_max=3,
                               adaptive_restart_batches_per_processor_max=5,
                               delegated_service_batches_per_processor_max=7,
                               cross_protocol_batches_per_processor_max=11)
        phase = raw["groups"]["sha256_shared"]["queries_per_occurrence_upper"]
        phase.update(offline_preprocessing=13, adaptive_restart_batches=17,
                     delegated_service_batches=19, cross_protocol_unclassified_batches=23)
        expected = 2 * (3 * 13 + 5 * 17 + 7 * 19 + 11 * 23)
        self.assertEqual(ledger.evaluate(raw)["sum_of_group_adversary_query_envelopes"], expected)

    def test_missing_phase_group_or_unknown_field_is_not_a_free_zero(self):
        for missing in ("offline_preprocessing", "failed_aborted_root_attempts",
                        "recursive_subproof_nodes", "cross_protocol_unclassified_batches"):
            raw = hypothetical()
            del raw["groups"]["poseidon2_shared"]["queries_per_occurrence_upper"][missing]
            with self.subTest(missing=missing), self.assertRaises(ledger.LedgerError):
                ledger.evaluate(raw)
        raw = hypothetical()
        del raw["groups"]["other_unmapped"]
        with self.assertRaises(ledger.LedgerError):
            ledger.evaluate(raw)
        raw = hypothetical()
        raw["groups"]["poseidon2_merkle_independent_oracle"] = deepcopy(raw["groups"]["poseidon2_shared"])
        with self.assertRaises(ledger.LedgerError):
            ledger.evaluate(raw)

    def test_unknown_factor_survives_known_zero(self):
        raw = hypothetical()
        raw["groups"]["poseidon2_shared"]["queries_per_occurrence_upper"]["offline_preprocessing"] = None
        result = ledger.evaluate(raw)
        self.assertIsNone(result["groups"]["poseidon2_shared"]["adversary_queries_upper"])
        self.assertIsNone(result["conditional_union"]["hypothetical_expression_meets_target"])
        raw = hypothetical()
        raw["lifetime"]["recursive_nodes_per_root_attempt_max"] = None
        self.assertIsNone(ledger.evaluate(raw)["occurrences_all_processors_upper"]["recursive_subproof_nodes"])

    def test_scope_cannot_reset_by_identity_upgrade_or_reorganization(self):
        for key in ("pre_deployment_queries_included",
                    "all_identities_processors_and_reorganizations_share_budget",
                    "protocol_upgrades_do_not_reset_budget"):
            for value in (False, 1):
                raw = hypothetical()
                raw["scope"][key] = value
                with self.subTest(key=key, value=value), self.assertRaises(ledger.LedgerError):
                    ledger.evaluate(raw)
        raw = hypothetical()
        raw["scope"]["coverage"] = "all_hash_uses_proved_complete"
        with self.assertRaises(ledger.LedgerError):
            ledger.evaluate(raw)

    def test_native_permutation_count_cannot_be_the_query_unit(self):
        raw = hypothetical()
        raw["scope"]["query_unit"] = "32_native_rng_permutations_per_saved_receipt"
        with self.assertRaises(ledger.LedgerError):
            ledger.evaluate(raw)

    def test_mass_and_reduction_overheads_are_independent_inputs(self):
        raw = hypothetical()
        group = raw["groups"]["poseidon2_shared"]
        group["online_mass_upper"]["fiat_shamir_online"] = None
        result = ledger.evaluate(raw)
        self.assertEqual(result["groups"]["poseidon2_shared"]["adversary_queries_upper"], 0)
        self.assertIsNone(result["conditional_union"]["hypothetical_expression_meets_target"])
        group["online_mass_upper"]["fiat_shamir_online"] = fraction(1)
        with self.assertRaisesRegex(ledger.LedgerError, "mass exceeds"):
            ledger.evaluate(raw)
        group["online_mass_upper"]["fiat_shamir_online"] = fraction(0)
        group["additional_reduction_queries_upper"]["extractor"] = None
        result = ledger.evaluate(raw)
        self.assertIsNone(result["sum_with_declared_additional_reduction_queries"])
        self.assertFalse(result["groups"]["poseidon2_shared"]["mapped_to_cdhz_t_or_w"])

    def test_numeric_inputs_need_explicit_unverified_references(self):
        raw = hypothetical()
        raw["lifetime_bound_reference"] = None
        with self.assertRaises(ledger.LedgerError):
            ledger.evaluate(raw)
        raw = hypothetical()
        raw["groups"]["mldsa_xof"]["query_bound_reference"] = None
        with self.assertRaises(ledger.LedgerError):
            ledger.evaluate(raw)
        raw = hypothetical()
        raw["uniform_event_bounds"][ledger.EVENTS[0]]["bound_reference"] = None
        with self.assertRaises(ledger.LedgerError):
            ledger.evaluate(raw)

    def test_conditional_union_is_exact_and_does_not_require_independence(self):
        raw = hypothetical()
        a = raw["uniform_event_bounds"][ledger.EVENTS[0]]
        b = raw["uniform_event_bounds"][ledger.EVENTS[1]]
        a.update(opportunities_max=3, error_per_opportunity_upper=fraction(1, 1024))
        b.update(opportunities_max=1, error_per_opportunity_upper=fraction(1, 2048))
        result = ledger.evaluate(raw)["conditional_union"]
        self.assertEqual(result["unclipped_expression"], Fraction(7, 2048))
        self.assertTrue(result["hypothetical_expression_meets_target"])
        self.assertIsNone(result["project_target_met"])
        self.assertFalse(result["uniform_conditional_premises_verified"])
        raw["input_kind"] = "project_unqualified"
        self.assertIsNone(ledger.evaluate(raw)["conditional_union"]["hypothetical_expression_meets_target"])

    def test_marginal_or_accepted_only_error_bound_is_refused(self):
        for conditioning in ("fixed_statement_marginal", "fresh_oracle_per_block",
                             "conditional_only_on_successful_receipts"):
            raw = hypothetical()
            raw["uniform_event_bounds"][ledger.EVENTS[1]]["conditioning"] = conditioning
            with self.subTest(conditioning=conditioning), self.assertRaises(ledger.LedgerError):
                ledger.evaluate(raw)
        example = ledger.counterexamples()["adaptive_statement_selection"]
        self.assertEqual(example["failure_for_fixed_statement_zero"], Fraction(1, 16))
        self.assertEqual(example["failure_for_adaptively_selected_statement_R"], 1)

    def test_bound_domain_cannot_be_extrapolated_to_larger_lifetime_queries(self):
        raw = hypothetical()
        raw["lifetime"]["offline_batches_per_processor_max"] = 10
        raw["groups"]["sha256_shared"]["queries_per_occurrence_upper"]["offline_preprocessing"] = 20
        bound = raw["uniform_event_bounds"][ledger.EVENTS[1]]
        bound["assumed_bound_valid_up_to_joint_queries"] = 199
        with self.assertRaisesRegex(ledger.LedgerError, "query domain"):
            ledger.evaluate(raw)
        bound["assumed_bound_valid_up_to_joint_queries"] = 200
        self.assertTrue(ledger.evaluate(raw)["conditional_union"]["hypothetical_expression_meets_target"])
        raw["groups"]["sha256_shared"]["additional_reduction_queries_upper"]["extractor"] = 1
        with self.assertRaisesRegex(ledger.LedgerError, "query domain"):
            ledger.evaluate(raw)
        bound["assumed_bound_valid_up_to_joint_queries"] = None
        self.assertIsNone(ledger.evaluate(raw)["conditional_union"]["hypothetical_expression_meets_target"])

    def test_lifetime_reset_and_per_event_target_counterexamples(self):
        example = ledger.counterexamples()
        cubic = example["query_reset"]["powers"]["3"]
        self.assertEqual(cubic["shared_total_power"], 8000)
        self.assertEqual(cubic["incorrect_sum_of_reset_powers"], 2000)
        self.assertEqual(cubic["understatement_factor"], 4)
        self.assertEqual(example["per_event_target"]["union_expression"], Fraction(1, 1 << 122))
        self.assertFalse(example["per_event_target"]["meets_whole_lifetime_target"])

    def test_exact_lottery_rounding_and_weight_cost_counterexample(self):
        for bits in range(2, 9):
            for target in range(1, 1 << bits):
                row = ledger.work_lottery(target, bits)
                expected = Fraction((target + 1) * ((1 << bits) // (target + 1)), 1 << bits)
                self.assertEqual(row["ideal_expected_credit_per_distinct_classical_first_query"], expected)
                self.assertLessEqual(expected, 1)
        self.assertEqual(ledger.work_lottery(5, 4)["ideal_expected_credit_per_distinct_classical_first_query"],
                         Fraction(3, 4))
        example = ledger.counterexamples()["difficulty_weight_cost"]
        self.assertEqual(example["weight_ratio"], 16)
        self.assertEqual(example["hypothetical_weight_per_cost_advantage"], 4)

    def test_source_mutation_missing_source_and_symlink_are_refused(self):
        key = "trillionnium/crates/trnm-crypto-primitives/src/pq_auth.rs"
        lock = "trillionnium/Cargo.lock"
        store = "trillionnium/crates/trnm-pon-node/src/store.rs"
        for changed in (key, lock, store):
            sources = dict(self.sources)
            sources[changed] += b"\n"
            with self.subTest(changed=changed), self.assertRaisesRegex(
                    ledger.LedgerError, "source identity"):
                ledger.source_survey(sources)
            del sources[changed]
            with self.subTest(missing=changed), self.assertRaises(ledger.LedgerError):
                ledger.source_survey(sources)
        # This is the actual earlier lock from M7, not a fabricated invalid TOML.
        # It remains a rejected source even though it was a real prior candidate.
        historical_lock = git_blob("7ddfe2bfa480d1ebd91c07d03d56a963fff038c5", lock)
        self.assertEqual(hashlib.sha256(historical_lock).hexdigest(),
                         "f9e57d73899c5d9fabd4f5b4fedf45256b8db4efb448d15680d070bbcfcb30bd")
        sources = dict(self.sources)
        sources[lock] = historical_lock
        with self.assertRaises(ledger.LedgerError) as refused:
            ledger.source_survey(sources)
        self.assertEqual(str(refused.exception), "source identity mismatch: " + lock)
        # Reuse the M7 revision already required above; the closure checkout has
        # fetch-depth: 0. No new M8 history dependency or lazy fetch is added.
        # These actual pre-boundary store bytes remain invalid current source.
        historical_store = git_blob("7ddfe2bfa480d1ebd91c07d03d56a963fff038c5", store)
        self.assertEqual(hashlib.sha256(historical_store).hexdigest(),
                         "108621f304255841ea2e1a7353858c3f0f5d8cb70a235f6a4aef6d57ebe0c554")
        sources = dict(self.sources)
        sources[store] = historical_store
        with self.assertRaises(ledger.LedgerError) as refused:
            ledger.source_survey(sources)
        self.assertEqual(str(refused.exception), "source identity mismatch: " + store)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "trillionnium").symlink_to(ROOT / "trillionnium", target_is_directory=True)
            with self.assertRaisesRegex(ledger.LedgerError, "symlink"):
                ledger.bounded_source(root, key)

    def test_source_lines_remain_independent_of_existing_qualification_labels(self):
        survey = self.survey
        reviewed_base = "077ac4f33206de00a178553d9a0c729a20685088"
        reviewed_store = "d4623d65b74a5f7d875037dceeb1a9c3d2a4d957791d4b39514a14eb3a2b90ca"
        self.assertEqual(ledger.SOURCE_BASE, reviewed_base)
        self.assertEqual(survey["base_commit"], reviewed_base)
        self.assertEqual(ledger.SOURCE_PINS["trillionnium/crates/trnm-pon-node/src/store.rs"],
                         reviewed_store)
        for path, expected in ledger.SOURCE_PINS.items():
            with self.subTest(source_path=path):
                original = git_blob(ledger.SOURCE_BASE, path)
                self.assertEqual(hashlib.sha256(original).hexdigest(), expected)
                self.assertEqual(original, self.sources[path])
        self.assertEqual(survey["canonical_signature"]["algorithm"], "ML-DSA-65")
        self.assertEqual(survey["canonical_signature"]["crate_version"], "0.1.1")
        self.assertIn("constructive_quantum_oracle", survey["observations"])
        self.assertIn("restricted_quantum_strategy", survey["observations"])
        self.assertIn("native_work_verifier", survey["observations"])
        gates = ledger.independent_acceptance_lines(survey)
        self.assertEqual(set(gates["lines"]), {"pq_authorization", "complete_computation_relation",
                                              "quantum_work_and_chain_weight"})
        self.assertTrue(all(not row["qualified"] for row in gates["lines"].values()))
        self.assertFalse(gates["whole_chain_post_quantum_qualified"])
        self.assertFalse(survey["whole_repository_build_or_behavior_verified"])
        math = survey["native_development_arithmetic"]
        self.assertEqual((math["desired_span_seconds"], math["clamp_lower_seconds"],
                          math["clamp_upper_seconds"]), (150, 38, 600))

    def test_nonexact_numbers_duplicate_json_and_qualification_injection_are_refused(self):
        for value in (True, -1, 1.0, "01", "1e6", 1 << 513):
            raw = hypothetical()
            raw["lifetime"]["offline_batches_per_processor_max"] = value
            with self.subTest(value=str(value)[:30]), self.assertRaises(ledger.LedgerError):
                ledger.evaluate(raw)
        for data in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1.5}', b'{"a":Infinity}'):
            with self.assertRaises(ledger.LedgerError):
                ledger.strict_json(data)
        raw = hypothetical()
        raw["whole_chain_post_quantum_qualified"] = True
        with self.assertRaises(ledger.LedgerError):
            ledger.evaluate(raw)

    def test_cli_rejects_malformed_input_without_emitting_a_report(self):
        process = subprocess.run([sys.executable, str(MODULE), "--input", "-"],
                                 input=b'{"schema":"a","schema":"b"}', capture_output=True,
                                 cwd=ROOT, timeout=15, check=False)
        self.assertEqual(process.returncode, 2)
        self.assertEqual(process.stdout, b"")
        self.assertEqual(json.loads(process.stderr)["status"], "REFUSED")


if __name__ == "__main__":
    unittest.main()
