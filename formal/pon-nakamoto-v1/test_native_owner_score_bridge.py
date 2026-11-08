"""Controls against a fresh actual native owner run; no fixture fallback."""
from copy import deepcopy
import os
from pathlib import Path
import tempfile
import unittest

from native_owner_score_bridge import (
    CertificateError, check_census, check_confirmation, check_run,
    local_commitment, observe_native, read_run, strict_json,
)


class ActualOwnerBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        binary = os.environ.get("TRNM_NATIVE_OWNER_OBSERVATION")
        if not binary:
            raise RuntimeError("TRNM_NATIVE_OWNER_OBSERVATION_REQUIRED_NO_FALLBACK")
        retained = os.environ.get("TRNM_NATIVE_OWNER_RECORD_DIR")
        cls.temporary = None
        if retained:
            cls.output = Path(retained)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix="pon-actual-owner-bridge-")
            cls.output = Path(cls.temporary.name) / "run"
        cls.result = observe_native(Path(binary), cls.output)
        cls.document = read_run(cls.output / "native.json")
        cls.snapshots = {entry["name"]: entry["census"] for entry in cls.document["snapshots"]}

    @classmethod
    def tearDownClass(cls):
        if cls.temporary is not None:
            cls.temporary.cleanup()

    def changed(self, name="alice_confirmed_a7"):
        return deepcopy(self.snapshots[name])

    def refuse(self, census, pattern):
        with self.assertRaisesRegex(CertificateError, pattern):
            check_census(census)

    def test_fresh_native_run_has_bounded_local_scope(self):
        self.assertTrue(self.result["exported_arithmetic_and_local_witnesses_checked"])
        self.assertEqual(self.result["owner_count"], 2)
        self.assertGreaterEqual(self.result["snapshot_count"], 10)
        self.assertFalse(self.result["native_execution_independently_attested"])
        self.assertFalse(self.result["world_coverage_attested"])
        self.assertFalse(self.result["six_successor_risk_qualified"])
        self.assertIsNone(self.result["failure_probability"])

    def test_actual_six_successors_and_reorganization(self):
        first, later = self.result["observations"]
        self.assertTrue(first["confirmed"])
        self.assertEqual(first["depth"], 6)
        self.assertEqual(first["work_delta"], first["required_work_delta"])
        self.assertEqual(first["inclusive_K"], 14)
        self.assertFalse(later["confirmed"])
        self.assertFalse(later["included"])

    def test_early_unseen_view_pays_whole_reference_deficit(self):
        row = self.result["comparisons"][0]
        self.assertEqual(row["availability_score_deficit"], 14)
        self.assertEqual(row["selection_score_deficit"], 0)
        self.assertEqual(row["whole_competing_suffix_weight"], 0)
        self.assertIsNone(row["known_b_chain_witness"])
        self.assertIsNone(row["new_adversarial_work_lower_bound"])

    def test_known_heavier_chain_exposes_native_selection_lag(self):
        row = self.result["comparisons"][1]
        self.assertEqual((row["eligible_view_maximum"], row["selected_score"]), (18, 16))
        self.assertEqual(row["raw_selection_score_deficit"], 2)
        self.assertEqual(row["selection_score_deficit"], 0)
        self.assertEqual(row["known_b_chain_witness"]["g_minus_q"], 16)

    def test_future_ancestry_maturity_changes_eligible_maximum(self):
        deferred = check_census(self.snapshots["alice_future_ancestor_deferred"])
        mature = check_census(self.snapshots["alice_future_mature_pending"])
        refs = self.document["references"]
        self.assertNotIn(refs["future_ancestor"], deferred.eligible)
        self.assertNotIn(refs["current_time_child"], deferred.eligible)
        self.assertIn(refs["current_time_child"], mature.eligible)
        self.assertEqual(mature.raw["eligible_max_score_hex"], f"{22:0128x}")
        self.assertEqual(mature.raw["raw_selection_deficit_hex"], f"{6:0128x}")

    def test_real_hidden_branch_does_not_change_alice_view_commitment(self):
        before = self.snapshots["alice_before_hidden_branch"]
        after = self.snapshots["alice_after_hidden_branch"]
        self.assertEqual(before["local_view_commitment"], after["local_view_commitment"])
        self.assertGreater(after["owner_attempt"], before["owner_attempt"])
        bob = self.snapshots["bob_hidden_b8"]
        self.assertEqual(int(bob["active_score_hex"], 16), 16)
        self.assertNotEqual(bob["active_tip"], before["active_tip"])

    def test_actual_cancellation_budget_and_bad_product_are_refusals(self):
        rejected = [entry for entry in self.document["operations"] if not entry["result"]["accepted"]]
        errors = [entry["result"]["error"] for entry in rejected]
        self.assertTrue(any(error.startswith("WORK:") for error in errors))
        self.assertTrue(any("TIME_DEFERRED" in error for error in errors))
        self.assertTrue(any("OWNER_CENSUS_BLOCK_BUDGET" in error for error in errors))
        self.assertTrue(any("DEADLINE" in error for error in errors))

    def test_256_bit_work_encoding_is_rejected(self):
        census = self.changed()
        census["rows"][-1]["chainwork_hex"] = "00" * 32
        self.refuse(census, "WORK_ENCODING")

    def test_chainwork_sum_is_recomputed(self):
        census = self.changed()
        census["rows"][-1]["chainwork_hex"] = f"{100:0128x}"
        self.refuse(census, "CHAINWORK_SUM")

    def test_native_target_cost_is_recomputed(self):
        census = self.changed()
        census["rows"][-1]["target"] = "ff" * 32
        self.refuse(census, "REQUIRED_WORK")

    def test_zero_target_is_not_an_allowed_free_block(self):
        census = self.changed()
        census["rows"][-1]["target"] = "00" * 32
        self.refuse(census, "REQUIRED_WORK")

    def test_missing_parent_refuses_a_partial_view(self):
        census = self.changed()
        del census["rows"][2]
        self.refuse(census, "MISSING_OR_UNORDERED_PARENT")

    def test_duplicate_block_identity_is_rejected(self):
        census = self.changed()
        census["rows"].append(deepcopy(census["rows"][-1]))
        self.refuse(census, "DUPLICATE_BLOCK")

    def test_child_eligibility_cannot_ignore_its_future_ancestor(self):
        census = self.changed("alice_future_ancestor_deferred")
        child = self.document["references"]["current_time_child"]
        next(row for row in census["rows"] if row["id"] == child)["ancestry_time_eligible"] = True
        self.refuse(census, "ANCESTRY_TIME_ELIGIBILITY")

    def test_caller_clock_is_rechecked_not_reused(self):
        census = self.changed("alice_future_mature_pending")
        census["observed_now"] = 100
        self.refuse(census, "ANCESTRY_TIME_ELIGIBILITY")

    def test_active_path_is_recomputed(self):
        census = self.changed()
        census["rows"][1]["active_chain_member"] = False
        self.refuse(census, "ACTIVE_PATH")

    def test_view_maximum_is_recomputed(self):
        census = self.changed("alice_a9_admitted_not_active")
        census["eligible_max_score_hex"] = f"{7:0128x}"
        self.refuse(census, "ELIGIBLE_MAX_SCORE")

    def test_maximum_id_list_must_be_complete(self):
        census = self.changed()
        census["eligible_max_ids"] = []
        self.refuse(census, "ELIGIBLE_MAX_IDS")

    def test_selection_deficit_cannot_be_dropped(self):
        census = self.changed("alice_a9_admitted_not_active")
        census["raw_selection_deficit_hex"] = f"{0:0128x}"
        self.refuse(census, "RAW_SELECTION_DEFICIT")

    def test_incomplete_or_unauthenticated_scope_cannot_escalate(self):
        for key, value, expected in (
            ("complete_for_all_admitted_rows_in_snapshot", False, "INCOMPLETE_CENSUS"),
            ("world_coverage_attested", True, "UNSUPPORTED_QUALIFICATION"),
            ("physical_clock_authenticated", True, "UNSUPPORTED_QUALIFICATION"),
            ("six_successor_risk_qualified", True, "UNSUPPORTED_QUALIFICATION"),
        ):
            with self.subTest(key=key):
                census = self.changed()
                census[key] = value
                self.refuse(census, expected)

    def test_local_commitment_changes_after_export_mutation(self):
        census = self.changed()
        census["active_generation"] += 1
        self.refuse(census, "LOCAL_VIEW_COMMITMENT")

    def test_boolean_cannot_substitute_for_integer_clock(self):
        census = self.changed()
        census["observed_now"] = True
        self.refuse(census, "CENSUS_OBSERVED_NOW")

    def test_confirmation_generation_must_bind_same_snapshot(self):
        census = check_census(self.changed())
        observation = deepcopy(self.document["confirmations"][0])
        observation["active_generation"] += 1
        with self.assertRaisesRegex(CertificateError, "OBSERVATION_BINDING"):
            check_confirmation(observation, census)

    def test_boolean_cannot_substitute_for_observed_height(self):
        census = check_census(self.changed())
        observation = deepcopy(self.document["confirmations"][0])
        observation["included_height"] = True
        with self.assertRaisesRegex(CertificateError, "OBSERVATION_HEIGHT_TYPE"):
            check_confirmation(observation, census)

    def test_confirmation_weight_gate_is_not_inferred_from_depth(self):
        census = check_census(self.changed())
        observation = deepcopy(self.document["confirmations"][0])
        observation["required_work_delta"] = f"{0:0128x}"
        with self.assertRaisesRegex(CertificateError, "CONFIRMATION_THRESHOLD"):
            check_confirmation(observation, census)

    def test_reorged_confirmation_cannot_be_relabelled_confirmed(self):
        census = check_census(self.changed("alice_after_strict_reorg_b8"))
        observation = deepcopy(self.document["confirmations"][1])
        observation["confirmed"] = True
        with self.assertRaisesRegex(CertificateError, "CONFIRMATION_AND"):
            check_confirmation(observation, census)

    def test_safety_claim_cannot_be_added_to_native_run(self):
        document = deepcopy(self.document)
        document["probability_bound"] = 1e-9
        with self.assertRaisesRegex(CertificateError, "UNSUPPORTED_RISK_BOUND"):
            check_run(document, self.output)

    def test_packet_hash_is_not_a_replaceable_label(self):
        document = deepcopy(self.document)
        row = document["packet_artifacts"][0]
        row["bytes"] += 1
        with self.assertRaisesRegex(CertificateError, "ARTIFACT_SIZE"):
            check_run(document, self.output)

    def test_owner_attempt_cannot_rewind_after_reorg(self):
        document = deepcopy(self.document)
        snapshot = next(row for row in document["snapshots"] if row["name"] == "alice_after_strict_reorg_b8")
        snapshot["census"]["owner_attempt"] = 1
        with self.assertRaisesRegex(CertificateError, "OWNER_LIFECYCLE_ORDER"):
            check_run(document, self.output)

    def test_coherent_plaintext_rewrite_is_not_independent_attestation(self):
        # A public digest cannot prevent a complete, coherent rewritten export.
        # This explicitly proves a reader limitation rather than suppressing it.
        census = self.changed()
        census["owner_process_id"] += 1
        census["active_generation"] += 1
        census["local_view_commitment"] = local_commitment(census)
        rewritten = check_census(census)
        self.assertFalse(rewritten.raw["exported_artifact_authenticated"])
        self.assertFalse(rewritten.raw["world_coverage_attested"])

    def test_duplicate_json_keys_are_rejected(self):
        with self.assertRaisesRegex(CertificateError, "DUPLICATE_JSON_KEY"):
            strict_json('{"score":1,"score":2}')

    def test_nonfinite_json_is_rejected(self):
        with self.assertRaisesRegex(CertificateError, "NONFINITE_JSON"):
            strict_json('{"score":NaN}')


if __name__ == "__main__":
    unittest.main()
