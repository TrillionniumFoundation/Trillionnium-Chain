"""Independent controls for literal candidate sets, binding and paid measurements."""
from __future__ import annotations

import copy
from dataclasses import replace
from fractions import Fraction
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "experiments"))

import w1_marked_domain_campaign as campaign
from quantum_adversarial_search import TrialCosts
from w1_marked_domain import (
    compare_domains, enumerate_domain, evaluate_nonce, replay_domain,
    simulate_measurements,
)
from w1_quantum_oracle import OracleProgram, canonical, h_bytes


class LiteralDomainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = campaign.with_parameters(campaign.retained.retained_template(), 2)
        cls.native_record = enumerate_domain(cls.native)
        cls.reduced = campaign.with_parameters(campaign.retained.reduced_template(), 8)
        cls.reduced_record = enumerate_domain(cls.reduced)
        cls.empty = campaign.with_parameters(cls.reduced, 2, target=1)
        cls.empty_record = enumerate_domain(cls.empty)
        cls.other_empty = campaign.with_parameters(cls.empty, 2, profile="PGH2")
        cls.other_empty_record = enumerate_domain(cls.other_empty)
        cls.costs = TrialCosts(1, 2, 3, 5, 7, 11, "upward")

    def test_native_fixed_vector_ticket(self):
        row = self.native_record["outcomes"][0]
        self.assertEqual(row["ticket"], "1206f6f3e2ae2c8eda4b71ec0a91afe03396e70924582475ee41aa5a00c34f62")
        self.assertTrue(row["winner"])
        self.assertTrue(row["complete_PNW1_scalar_verified"])

    def test_pgh2_native_ticket_is_bound_to_witness_and_domain(self):
        template = campaign.with_parameters(self.native, 2, profile="PGH2")
        row = evaluate_nonce(template, 0)
        self.assertEqual(row["ticket"], "fb5974b542ede610124bd243af840b8159faeed4aa8555155a2d8688c5068ad1")
        self.assertFalse(row["winner"])
        self.assertNotEqual(row["challenge"], self.native_record["outcomes"][0]["challenge"])

    def test_nonce_bytes_are_actual_little_endian_header_field(self):
        nonce = 3
        header = self.native.header_for(nonce)
        self.assertEqual(header[310:318], nonce.to_bytes(8, "little"))
        challenge = hashlib.sha256(h_bytes(b"challenge", header)).hexdigest()
        self.assertEqual(evaluate_nonce(self.native, nonce)["challenge"], challenge)

    def test_all_native_winners_verified_and_public_product_precomputed_once(self):
        record = self.native_record
        self.assertEqual(record["public_AB_products_computed"], 1)
        self.assertEqual(record["native_winning_proofs_verified"], record["marked_count"])
        self.assertTrue(all(row["complete_PNW1_scalar_verified"] is row["winner"] for row in record["outcomes"]))
        self.assertTrue(all((row["proof_sha256"] is not None) is row["winner"] for row in record["outcomes"]))

    def test_native_census_is_a_subspace_and_not_full_nonce64(self):
        record = self.native_record
        self.assertEqual(record["domain_size"], 4)
        self.assertEqual(record["unsearched_nonce_bits"], 62)
        self.assertFalse(record["assertions"]["unsearched_nonce64_space_characterized"])
        self.assertFalse(record["assertions"]["native_task_parent_time_target_admission_checked"])

    def test_reduced_control_has_no_native_proof_claim(self):
        record = self.reduced_record
        self.assertFalse(record["native_shape"])
        self.assertEqual(record["native_winning_proofs_verified"], 0)
        self.assertEqual(record["public_AB_products_computed"], 0)
        self.assertIsNone(record["public_AB_sha256"])
        self.assertTrue(all(row["proof_sha256"] is None for row in record["outcomes"]))

    def test_actual_bounded_noise_exhaustion_is_unmarked(self):
        row = self.reduced_record["outcomes"][78]
        self.assertEqual(row["refusal"], "NOISE_BUDGET")
        self.assertFalse(row["winner"])
        self.assertIsNone(row["trace"])
        self.assertIsNone(row["ticket"])
        self.assertFalse(all(row["noise_complete"]))

    def test_scalar_and_existing_macro_predicate_agree(self):
        program = OracleProgram(self.reduced)
        for nonce in (0, 1, 78):
            with self.subTest(nonce=nonce):
                expected = self.reduced_record["outcomes"][nonce]
                actual = program.execute(nonce)
                self.assertEqual(expected["challenge"], actual["challenge"])
                self.assertEqual(expected["noise_complete"], actual["noise_complete"])
                self.assertEqual(expected["winner"], actual["winner"])
                if all(expected["noise_complete"]):
                    self.assertEqual(expected["trace"], actual["trace"])
                    self.assertEqual(expected["ticket"], actual["ticket"])
                self.assertTrue(actual["clean_ancillas"])

    def test_prefix_membership_checks_first_raw_words_before_rejection(self):
        for nonce in (0, 1, 78):
            row = self.reduced_record["outcomes"][nonce]
            challenge = bytes.fromhex(row["challenge"])
            expected = []
            for label in range(4):
                raw = hashlib.sha256(h_bytes(b"noise", challenge, bytes([label]), bytes(4))).digest()
                expected.append((int.from_bytes(raw[:4], "little") & 15) < 11)
            self.assertEqual(row["prefix_all_accepted_by_label"], expected)
            self.assertEqual(row["prefix_all_accepted"], all(expected))

    def test_prefix_restricted_winners_are_subset_of_full_winners(self):
        record = self.reduced_record
        actual = sum(row["prefix_all_accepted"] and row["winner"] for row in record["outcomes"])
        self.assertEqual(record["prefix_restricted_marked_count"], actual)
        self.assertLess(record["prefix_restricted_marked_count"], record["marked_count"])
        self.assertLess(record["prefix_all_accepted_count"], record["domain_size"])

    def test_changing_target_changes_the_challenge_and_ticket(self):
        left = evaluate_nonce(self.reduced, 0)
        right = evaluate_nonce(self.empty, 0)
        self.assertNotEqual(left["challenge"], right["challenge"])
        self.assertNotEqual(left["ticket"], right["ticket"])

    def test_rethresholded_old_ticket_table_is_rejected(self):
        changed = copy.deepcopy(self.empty_record)
        changed["outcomes"][0]["challenge"] = self.reduced_record["outcomes"][0]["challenge"]
        changed["outcomes"][0]["trace"] = self.reduced_record["outcomes"][0]["trace"]
        changed["outcomes"][0]["ticket"] = self.reduced_record["outcomes"][0]["ticket"]
        with self.assertRaisesRegex(ValueError, "CENSUS_REPLAY_MISMATCH"):
            replay_domain(changed)

    def test_same_template_replay_has_identical_marked_set(self):
        replayed = replay_domain(self.empty_record)
        self.assertEqual(canonical(replayed), canonical(self.empty_record))
        self.assertTrue(replayed["no_solution"])

    def test_changing_nonce_subspace_does_not_imply_independent_tickets(self):
        small = enumerate_domain(campaign.with_parameters(self.reduced, 2))
        compared = compare_domains(self.reduced_record, small)
        self.assertFalse(compared["same_template"])
        self.assertEqual(compared["matching_challenges"], 4)
        self.assertEqual(compared["matching_complete_tickets"], 4)
        self.assertFalse(compared["ticket_independence_inferred"])

    def test_unsupported_native_census_size_refuses_before_enumeration(self):
        template = campaign.with_parameters(self.native, 64)
        with self.assertRaisesRegex(ValueError, "CENSUS_NONCE_BITS_BOUND"):
            enumerate_domain(template)

    def test_directly_forged_template_metadata_is_rejected(self):
        for forged in (replace(self.native, target=1), replace(self.native, nonce_offset=0),
                       replace(self.native, profile="fake"), replace(self.native, challenge_tag=b"fake"),
                       replace(self.empty, target=True)):
            with self.subTest(forged=forged.profile, target=forged.target):
                with self.assertRaisesRegex(ValueError, "NONCANONICAL_FIXED_TEMPLATE"):
                    evaluate_nonce(forged, 0)

    def test_wrong_nonce_and_bool_nonce_rejected(self):
        for nonce in (-1, 4, True, 0.0):
            with self.subTest(nonce=nonce):
                with self.assertRaises(ValueError):
                    evaluate_nonce(self.native, nonce)

    def test_census_counts_scope_and_ticket_mutations_are_rejected(self):
        mutators = (
            lambda x: x.update(marked_count=1),
            lambda x: x.update(native_shape=True),
            lambda x: x.update(domain_sha256="0" * 64),
            lambda x: x["assertions"].update(consensus_security_theorem=True),
            lambda x: x["outcomes"][0].update(winner=True),
            lambda x: x["outcomes"][0].update(prefix_all_accepted=not x["outcomes"][0]["prefix_all_accepted"]),
            lambda x: x["outcomes"][0].update(complete_PNW1_scalar_verified=True),
        )
        for mutation in mutators:
            altered = copy.deepcopy(self.empty_record)
            mutation(altered)
            with self.assertRaisesRegex(ValueError, "CENSUS_REPLAY_MISMATCH"):
                replay_domain(altered)

    def test_native_proof_hash_mutation_is_rejected(self):
        changed = copy.deepcopy(self.native_record)
        changed["outcomes"][0]["proof_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "CENSUS_REPLAY_MISMATCH"):
            replay_domain(changed)

    def test_same_empty_domain_persists_across_parallel_measurements_and_retries(self):
        result = simulate_measurements((self.empty_record,), ((0, 0), (0, 1), (0, 100)), 4, 5, self.costs)
        self.assertFalse(result["success"])
        self.assertEqual(result["domain_setup_charges"], 1)
        self.assertEqual(len(result["trials"]), 3)
        self.assertTrue(all(row["evaluator_marked_count"] == 0 for row in result["trials"]))
        self.assertTrue(all(not measurement["winner"] for row in result["trials"] for measurement in row["measurements"]))
        self.assertEqual({row["domain_sha256"] for row in result["trials"]}, {self.empty_record["domain_sha256"]})
        self.assertFalse(result["independent_ticket_prior_used"])
        self.assertFalse(result["strategy_reads_marked_count"])

    def test_aliasing_one_template_in_input_does_not_refill_it(self):
        result = simulate_measurements((self.empty_record, copy.deepcopy(self.empty_record)),
                                       ((0, 0), (1, 3), (0, 7)), 2, 17, self.costs)
        self.assertEqual(result["domain_setup_charges"], 1)
        self.assertFalse(result["success"])

    def test_different_templates_pay_refresh_and_revisit_pays_single_resident_setup(self):
        result = simulate_measurements((self.empty_record, self.other_empty_record),
                                       ((0, 0), (0, 1), (1, 2), (1, 3), (0, 4)), 2, 19, self.costs)
        self.assertEqual(result["domain_setup_charges"], 3)
        self.assertEqual([row["domain_setup_charged"] for row in result["trials"]], [True, False, True, False, True])
        self.assertFalse(result["success"])

    def test_failed_zero_iteration_measurements_still_pay_every_candidate_check(self):
        result = simulate_measurements((self.empty_record,), ((0, 0), (0, 1)), 4, 7, self.costs)
        self.assertEqual(result["elapsed_assumed_seconds_exact"], {"numerator": 61, "denominator": 1})
        self.assertEqual(result["coherent_processor_seconds_exact"], {"numerator": 40, "denominator": 1})
        self.assertEqual(result["elapsed_assumed_seconds_upper_float"], 61.0)

    def test_all_marked_measurements_stop_after_one_paid_winning_batch(self):
        all_marked = enumerate_domain(campaign.with_parameters(self.reduced, 1))
        self.assertEqual(all_marked["marked_count"], all_marked["domain_size"])
        result = simulate_measurements((all_marked,), ((0, 0), (0, 1), (0, 3)), 4, 11, self.costs)
        self.assertTrue(result["success"])
        self.assertEqual(len(result["trials"]), 1)
        self.assertEqual(result["unused_predeclared_trials"], 2)
        self.assertEqual(result["elapsed_assumed_seconds_exact"], {"numerator": 42, "denominator": 1})
        self.assertEqual(result["native_blocks_admitted"], 0)
        self.assertTrue(all(x["winner"] for x in result["trials"][0]["measurements"]))

    def test_saved_domain_is_rechecked_before_measurement(self):
        altered = copy.deepcopy(self.empty_record)
        altered["marked_nonces"] = [0]
        with self.assertRaisesRegex(ValueError, "CENSUS_REPLAY_MISMATCH"):
            simulate_measurements((altered,), ((0, 0),), 1, 0, self.costs)

    def test_measurement_input_bounds_are_strict(self):
        cases = (
            ((self.empty_record,), ((0, True),), 1, 0, self.costs),
            ((self.empty_record,), ((1, 0),), 1, 0, self.costs),
            ((self.empty_record,), ((0, 0),), True, 0, self.costs),
            ((self.empty_record,), ((0, 0),), 1, True, self.costs),
            ((self.empty_record,), ((0, 0),), 1, 0, replace(self.costs, candidate_check_seconds=0)),
            ((self.empty_record,), ((0, 0),), 1, 0, replace(self.costs, iteration_seconds=float("nan"))),
        )
        for args in cases:
            with self.assertRaises(ValueError):
                simulate_measurements(*args)

    def test_binary_rational_clocks_never_round_total_down(self):
        costs = TrialCosts(.1, .1, .1, .1, .1, .1, "nearest")
        result = simulate_measurements((self.empty_record,), ((0, 3), (0, 5)), 3, 31, costs)
        exact = Fraction(**result["elapsed_assumed_seconds_exact"])
        self.assertGreaterEqual(Fraction.from_float(result["elapsed_assumed_seconds_upper_float"]), exact)


class CampaignBoundaryTests(unittest.TestCase):
    def test_largest_reduced_census_roundtrips_beyond_old_two_megabyte_limit(self):
        template = campaign.with_parameters(campaign.retained.reduced_template(), 12)
        census = enumerate_domain(template)
        raw = canonical(census) + b"\n"
        self.assertGreater(len(raw), 2_000_000)
        self.assertLess(len(raw), campaign.MAX_REPORT_BYTES)
        with tempfile.TemporaryDirectory(prefix="w1-domain-bound-") as directory:
            path = Path(directory) / "largest-reduced-census.json"
            campaign.write_report(path, raw)
            loaded = campaign.strict_load(campaign.read_report(path))
            self.assertEqual(loaded, census)
            with self.assertRaisesRegex(ValueError, "OUTPUT_ALREADY_EXISTS"):
                campaign.write_report(path, b"{}")
            self.assertEqual(path.read_bytes(), raw)

    def test_report_io_refuses_over_cap_without_fallback(self):
        raw = b" " * (campaign.MAX_REPORT_BYTES + 1)
        with self.assertRaisesRegex(ValueError, "JSON_BOUND"):
            campaign.strict_load(raw)
        with tempfile.TemporaryDirectory(prefix="w1-domain-cap-") as directory:
            path = Path(directory) / "too-large.json"
            with self.assertRaisesRegex(ValueError, "OUTPUT_BOUND"):
                campaign.write_report(path, raw)
            self.assertFalse(path.exists())
            # Sparse file verifies stat-based refusal without a large disk write.
            with path.open("wb") as stream:
                stream.truncate(len(raw))
            with self.assertRaisesRegex(ValueError, "INPUT_FILE_BOUND"):
                campaign.read_report(path)

    def test_duplicate_json_keys_and_nonfinite_values_rejected(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1e999}'):
            with self.assertRaises(ValueError):
                campaign.strict_load(raw)

    def test_exact_uniform_denominator_survives_json(self):
        value = {"denominator": 1 << 256}
        self.assertEqual(campaign.strict_load(canonical(value)), value)

    def test_source_record_rejects_fake_committed_claim(self):
        record = campaign.source_record()
        campaign.validate_source(record)
        record["all_sources_committed_at_head"] = not record["all_sources_committed_at_head"]
        with self.assertRaisesRegex(ValueError, "SOURCE_COMMITMENT_CLAIM"):
            campaign.validate_source(record)

    def test_source_hash_mutation_rejected(self):
        record = campaign.source_record()
        key = next(iter(record["source_sha256"]))
        record["source_sha256"][key] = "0" * 64
        with self.assertRaisesRegex(ValueError, "SOURCE_HASH"):
            campaign.validate_source(record)

    def test_case_definitions_keep_native_and_reduced_bounds(self):
        definitions = campaign.case_definitions(1, 2)
        self.assertEqual(len(definitions), 6)
        self.assertEqual(sum(template.shape.native for _, template in definitions), 3)
        self.assertTrue(all(template.nonce_bits == (1 if template.shape.native else 2)
                            for _, template in definitions))
        for native_bits, reduced_bits in ((True, 2), (7, 2), (1, 13), (0, 2)):
            with self.assertRaises(ValueError):
                campaign.case_definitions(native_bits, reduced_bits)


if __name__ == "__main__":
    unittest.main()
