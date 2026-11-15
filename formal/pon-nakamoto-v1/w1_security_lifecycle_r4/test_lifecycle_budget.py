"""Falsifying controls for arithmetic, adaptive scope and source admission."""

from fractions import Fraction
import hashlib
import itertools
import json
from pathlib import Path
import tempfile
import unittest

import lifecycle_budget as audit


def literal_duplex(operations, rate=4):
    pending = outputs = calls = observed = sampled = 0
    for operation in operations:
        for _ in range(operation["fields"]):
            if operation["kind"] == "absorb":
                outputs = 0
                observed += 1
                pending += 1
                if pending == rate:
                    pending = 0
                    outputs = rate
                    calls += 1
            else:
                sampled += 1
                if pending or outputs == 0:
                    calls += 1
                    pending = 0
                    outputs = rate
                outputs -= 1
    return {"permutation_evaluations": calls, "absorbed_base_fields": observed,
            "sampled_base_fields": sampled, "pending_inputs": pending,
            "buffered_outputs": outputs}


def synthetic_receipts():
    # Counts are deliberately synthetic test data, never delivered as native observations.
    return {"test-sha1": {"measurements": {
        "config_initialization": {"leaf_sponge": 0, "branch_compressor": 0, "transcript": 3},
        "independent_preprocessing": {"leaf_sponge": 7, "branch_compressor": 11, "transcript": 0},
        "one_verification": {"leaf_sponge": 5, "branch_compressor": 13, "transcript": 17},
    }}}


def scenario():
    return {"schema": "trnm-w1-lifetime-scenario-v1", "name": "synthetic test",
            "epochs": [{"label": "first", "runs": [{"receipt": "test-sha1",
            "config_initializations": 1, "preprocessing_builds": 1, "verification_calls": 2}],
            "offline_forward_queries": 19, "offline_inverse_queries": 23,
            "other_honest_evaluations": 29}],
            "abstract_conditional_opportunities": [{"count": 5,
            "error_numerator": 1, "error_denominator": 1 << 63}]}


class TranscriptCounts(unittest.TestCase):
    def test_exhaustive_buffer_boundaries_against_literal_calls(self):
        alphabet = [(kind, n) for kind in ("absorb", "squeeze") for n in range(6)]
        for sequence in itertools.product(alphabet, repeat=3):
            ops = [{"kind": kind, "fields": n} for kind, n in sequence]
            self.assertEqual(audit.replay_duplex(ops), literal_duplex(ops), sequence)

    def test_one_squeeze_can_reuse_a_full_absorption_output(self):
        ops = [{"kind": "absorb", "fields": 4}, {"kind": "squeeze", "fields": 2}]
        self.assertEqual(audit.replay_duplex(ops)["permutation_evaluations"], 1)
        # Counting every squeeze as a fresh permutation would be wrong here.

    def test_observation_discards_unused_outputs(self):
        ops = [{"kind": "absorb", "fields": 4}, {"kind": "squeeze", "fields": 1},
               {"kind": "absorb", "fields": 1}, {"kind": "squeeze", "fields": 1}]
        self.assertEqual(audit.replay_duplex(ops)["permutation_evaluations"], 2)

    def test_replay_rejects_unknown_operation_and_fake_counts(self):
        for operation in ({"kind": "duplex", "fields": 1}, {"kind": "absorb", "fields": True},
                          {"kind": "squeeze", "fields": -1}, {"kind": "squeeze", "fields": 1.0}):
            with self.assertRaises(audit.Refusal):
                audit.replay_duplex([operation])


class ProbabilityScope(unittest.TestCase):
    def test_goldilocks_law_is_normalized_and_not_uniform(self):
        for bits in (15, 16, 19):
            law = audit.query_law(bits)
            decode = lambda x: Fraction(int(x["numerator"]), int(x["denominator"]))
            p0 = decode(law["probability_zero"])
            p1 = decode(law["probability_each_nonzero"])
            size = 1 << bits
            self.assertEqual(p0 + (size - 1) * p1, 1)
            self.assertGreater(p0, Fraction(1, size))
            self.assertEqual(p0 - p1, Fraction(1, audit.P))
            self.assertEqual(decode(law["total_variation_from_uniform"]), p0 - Fraction(1, size))

    def test_union_handles_perfect_correlation_without_independence(self):
        event = {0}
        actual = Fraction(len(event | event), 16)
        upper = audit.adaptive_bad_event_bound([(2, Fraction(1, 16))])
        self.assertLessEqual(actual, upper)
        self.assertGreater(actual, Fraction(1, 16) ** 2)

    def test_disjoint_events_make_union_tight(self):
        events = [{i} for i in range(5)]
        actual = Fraction(len(set().union(*events)), 16)
        self.assertEqual(actual, audit.adaptive_bad_event_bound([(5, Fraction(1, 16))]))

    def test_marginal_probability_does_not_supply_conditional_hypothesis(self):
        # Let public history reveal uniform Z. Choose E_Z after seeing it.
        # Every fixed E_i=(Z=i) has marginal probability 1/16, while E_Z holds surely.
        fixed_marginal = Fraction(1, 16)
        adaptive_success = Fraction(sum(z == z for z in range(16)), 16)
        self.assertEqual(adaptive_success, 1)
        self.assertGreater(adaptive_success, audit.adaptive_bad_event_bound([(1, fixed_marginal)]))

    def test_saturation_and_exact_very_small_probabilities(self):
        self.assertEqual(audit.adaptive_bad_event_bound([(1 << 100, Fraction(1, 1 << 63))]), 1)
        self.assertEqual(audit.adaptive_bad_event_bound([(3, Fraction(1, 1 << 2000))]), Fraction(3, 1 << 2000))
        for invalid in (Fraction(-1), Fraction(2)):
            with self.assertRaises(audit.Refusal):
                audit.adaptive_bad_event_bound([(1, invalid)])

    def test_restricted_leaf_bound_zero_queries_and_saturation(self):
        # With no oracle query, two fixed different messages collide with
        # exact probability 1/(N+1); the upper bound is slightly conservative.
        for n in range(2, 20):
            self.assertGreaterEqual(audit.restricted_leaf_collision_bound(0, n), Fraction(1, n + 1))
            self.assertEqual(audit.restricted_leaf_collision_bound(n * n - 2, n), 1)
            self.assertEqual(audit.restricted_leaf_collision_bound(n * n, n), 1)
        self.assertLess(audit.restricted_leaf_collision_bound(1 << 64), Fraction(1, 1 << 128))
        self.assertGreater(audit.restricted_leaf_collision_bound(1 << 128), Fraction(1, 4))

    def test_exhaustive_inverse_collision_does_not_automatically_enter_leaf_domain(self):
        # N=2, Pi on four points; pair coding is 2*left+right. Query inverse
        # at (0,0) and (0,1): arbitrary compressor collision always succeeds.
        # Both inputs belong to m||0 only in 4 of the 24 permutations.
        raw = restricted = 0
        for permutation in itertools.permutations(range(4)):
            inverse = [permutation.index(y) for y in range(4)]
            x, y = inverse[0], inverse[1]
            self.assertNotEqual(x, y)
            self.assertEqual(permutation[x] // 2, permutation[y] // 2)
            raw += 1
            if x % 2 == 0 and y % 2 == 0:
                restricted += 1
        self.assertEqual(raw, 24)
        self.assertEqual(Fraction(restricted, raw), Fraction(1, 6))

    def test_restricted_leaf_bound_cannot_be_reused_for_raw_compression(self):
        # The raw compressor's two inverse-query attack succeeds for EVERY
        # permutation; pretending its inputs have the zero-capacity restriction
        # would yield a contradiction, even in the ideal-permutation model.
        self.assertLess(audit.restricted_leaf_collision_bound(2, 16), 1)
        self.assertEqual(Fraction(1), 1)  # raw attack's model-independent success


class LifetimeAdmission(unittest.TestCase):
    def test_same_primitive_roles_and_epochs_merge_before_squaring(self):
        s = scenario()
        first = s["epochs"][0]
        second = json.loads(json.dumps(first))
        second["label"] = "next protocol version, same permutation"
        s["epochs"].append(second)
        result = audit.merge_lifetime(synthetic_receipts(), s)
        expected = 2 * (3 + 7 + 11 + 2 * (5 + 13 + 17) + 19 + 23 + 29)
        self.assertEqual(result["merged_total_evaluations_and_queries"], expected)
        self.assertEqual(int(result["quadratic_accounting_only"]["merged_square"]), expected ** 2)
        self.assertGreater(int(result["quadratic_accounting_only"]["omitted_cross_terms"]), 0)
        self.assertIsNone(result["actual_w1_noninteractive_bits"])
        self.assertIsNone(result["actual_w1_quantum_bits"])
        self.assertFalse(result["pq128"])

    def test_missing_offline_budget_is_refused_not_assumed_zero(self):
        s = scenario()
        del s["epochs"][0]["offline_inverse_queries"]
        with self.assertRaises(audit.Refusal):
            audit.merge_lifetime(synthetic_receipts(), s)

    def test_domain_version_cannot_reset_the_permutation(self):
        s = scenario()
        s["epochs"][0]["new_independent_primitive"] = True
        with self.assertRaises(audit.Refusal):
            audit.merge_lifetime(synthetic_receipts(), s)

    def test_assumption_checkboxes_cannot_create_ni_or_pq_bound(self):
        for key, value in (("pq128", True), ("hash_collision_bits", 128),
                           ("fs_theorem_verified", True), ("mode", "quantum")):
            s = scenario()
            s[key] = value
            with self.assertRaises(audit.Refusal):
                audit.merge_lifetime(synthetic_receipts(), s)

    def test_lifetime_does_not_silently_replace_queries_with_proof_count(self):
        s = scenario()
        result = audit.merge_lifetime(synthetic_receipts(), s)
        self.assertEqual(result["declared_offline_forward_queries"], 19)
        self.assertEqual(result["declared_offline_inverse_queries"], 23)
        self.assertEqual(result["abstract_adaptive_bad_event_lemma"]["conditional_failure_upper_bound"]["numerator"], "5")
        self.assertTrue(result["abstract_adaptive_bad_event_lemma"]["opportunities_not_inferred_from_proof_count"])

    def test_unknown_profile_and_numeric_coercion_are_refused(self):
        for field, value in (("receipt", "unmeasured-profile"), ("receipt", True), ("verification_calls", "2")):
            s = scenario()
            s["epochs"][0]["runs"][0][field] = value
            with self.assertRaises(audit.Refusal):
                audit.merge_lifetime(synthetic_receipts(), s)

    def test_source_byte_change_and_missing_file_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.rs"
            source.write_bytes(b"pinned source\n")
            manifest = {"base": audit.BASE, "files": [{"root": "repo", "revision": None, "path": "source.rs",
                "sha256": hashlib.sha256(source.read_bytes()).hexdigest()}]}
            self.assertTrue(audit.source_check(manifest, root, root)["ok"])
            source.write_bytes(b"changed source\n")
            self.assertFalse(audit.source_check(manifest, root, root)["ok"])
            source.unlink()
            self.assertFalse(audit.source_check(manifest, root, root)["ok"])

    def test_empty_source_contract_is_not_success(self):
        with self.assertRaises(audit.Refusal):
            audit.source_check({"base": audit.BASE, "files": []}, Path("."), Path("."))


class RetainedEvidence(unittest.TestCase):
    root = Path(__file__).resolve().parent

    def manifest(self):
        return audit.admit_manifest((self.root / "source_contract.json").read_bytes())

    def test_real_native_receipts_replay_at_their_own_source_revisions(self):
        manifest = self.manifest()
        receipts = {}
        for key, pin in manifest["native_receipts"].items():
            found, receipt = audit.admit_receipt((self.root / pin["path"]).read_bytes(), manifest)
            self.assertEqual(found, key)
            receipts[key] = receipt
        self.assertEqual(receipts["r3-sha1"]["source_base"], audit.BASE)
        self.assertEqual(receipts["r4-sha5"]["source_base"], audit.PROFILE5_BASE)
        self.assertEqual(receipts["r3-packed4"]["measurements"], receipts["r4-packed4"]["measurements"])
        for scenario_input in json.loads((self.root / "scenarios.json").read_text()):
            report = audit.merge_lifetime(receipts, scenario_input)
            self.assertIsNone(report["actual_w1_lifetime_failure_probability"])
            self.assertIsNone(report["actual_w1_noninteractive_bits"])
            self.assertIsNone(report["actual_w1_quantum_bits"])
            self.assertFalse(report["pq128"])
            self.assertFalse(report["complete_experiment_query_budget_established"])

    def test_modified_manifest_and_observation_bytes_are_refused(self):
        raw = (self.root / "source_contract.json").read_bytes()
        with self.assertRaises(audit.Refusal):
            audit.admit_manifest(raw + b" ")
        manifest = self.manifest()
        receipt = (self.root / manifest["native_receipts"]["r4-sha5"]["path"]).read_bytes()
        with self.assertRaises(audit.Refusal):
            audit.admit_receipt(receipt + b" ", manifest)

    def test_probe_sources_match_the_native_run_attribution(self):
        manifest = self.manifest()
        for pin in manifest["probe_sources"].values():
            self.assertEqual(hashlib.sha256((self.root / pin["path"]).read_bytes()).hexdigest(), pin["sha256"])
        old = json.loads((self.root / "artifacts/native-run-v1.json").read_text())
        self.assertEqual(old["source_sha256"], manifest["probe_sources"]["historical_r3"]["sha256"])
        new = json.loads((self.root / "artifacts/native-run-v2-profile5.json").read_text())
        self.assertTrue(new["inputs_unchanged"])
        self.assertEqual(new["inputs_before"], new["inputs_after"])
        probe_pins = [item for item in new["inputs_before"] if item["path"].endswith("r4_lifecycle_probe.rs")]
        self.assertEqual(len(probe_pins), 1)
        self.assertEqual(probe_pins[0]["sha256"], manifest["probe_sources"]["profile5"]["sha256"])

    def test_receipt_semantics_reject_wrong_count_and_dropped_negative_control(self):
        manifest = self.manifest()
        receipt = json.loads((self.root / manifest["native_receipts"]["r4-sha5"]["path"]).read_text())
        bad = json.loads(json.dumps(receipt))
        bad["transcript_including_initialization"]["observed_base_fields"] += 1
        with self.assertRaises(audit.Refusal):
            audit.validate_receipt(bad)
        bad = json.loads(json.dumps(receipt))
        bad["negative_controls"].pop()
        with self.assertRaises(audit.Refusal):
            audit.validate_receipt(bad)
        bad = json.loads(json.dumps(receipt))
        bad["source_base"] = audit.BASE
        with self.assertRaises(audit.Refusal):
            audit.validate_receipt(bad)


if __name__ == "__main__":
    unittest.main()
