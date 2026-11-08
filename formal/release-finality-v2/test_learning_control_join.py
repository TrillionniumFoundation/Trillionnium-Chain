"""Join real V3 signature verification with synthetic role-control materials.

These are algorithmic controls, not independent operators or native adoption.
The role-control fixture is independent synthetic material; it is not an
original-owner mapping of the signed V3 learning actors. A shared campaign and
source pair cannot establish that missing actor-to-control association.
"""
import copy
import unittest

from campaign_gate import review_learning_control_material, verify_learning_packet
from protocol import Refusal, canonical
import test_model_generation_sequence_parent as parent_fixtures
import test_control_separation as control_fixtures


class LearningControlJoinTests(unittest.TestCase):
    def setUp(self):
        self.owner = parent_fixtures.ParentBoundGenerationSequenceTests()
        self.owner.setUp()
        self.manifest, self.policy, self.control = control_fixtures.fixture()

    def packet(self, decisions=("adopted", "no_update", "adopted")):
        case = self.owner.case(decisions)
        raw, pin, generations, receipts, attestations = self.owner.owner.args(case)
        packet = dict(pair=copy.deepcopy(self.control["expected_pair"]),
            campaign=self.control["expected_campaign"], history_hex=raw.hex(),
            generations=generations, receipts=receipts, attestations=attestations,
            run_plans=case["plans"], contexts=case["contexts"])
        trusted = dict(pair=copy.deepcopy(packet["pair"]), campaign=packet["campaign"],
                       history=pin, initial_model=case["initial"])
        return packet, trusted

    def review(self, packet, trusted):
        controls = dict(manifest=self.control["expected_manifest"],
                        policy=self.control["expected_policy"],
                        revision=self.control["expected_revision"],
                        bindings=self.control["expected_bindings"])
        return review_learning_control_material(
            packet, trusted, canonical(self.manifest), canonical(self.policy),
            controls, now=self.control["now"])

    def test_actual_signed_v3_and_legitimate_no_update_keep_original_results(self):
        for decisions in (("adopted",) * 3, ("adopted", "no_update", "adopted"),
                          ("no_update",) * 3):
            packet, trusted = self.packet(decisions)
            before = copy.deepcopy((packet, trusted, self.manifest, self.policy, self.control))
            result = self.review(packet, trusted)
            self.assertEqual(result["learning_input_review"], verify_learning_packet(packet, trusted))
            self.assertEqual(result["control_material_review"]["status"], "MATERIAL_REVIEW_COMPLETE")
            self.assertEqual(result["qualification"], "HOLD_NO_GO")
            for name in ("independent_control_accepted", "learning_actor_control_binding_verified",
                         "physical_installation_accepted",
                         "prospective_neural_gain_accepted", "hepta_final_use", "production_activation"):
                self.assertIs(result[name], False)
            self.assertIn("original learning actor-to-control binding", result["missing_external_acceptance"])
            self.assertEqual((packet, trusted, self.manifest, self.policy, self.control), before)

    def test_complete_materials_do_not_assert_control_bindings_for_signed_learning_actors(self):
        packet, trusted = self.packet()
        result = self.review(packet, trusted)
        self.assertEqual(result["control_material_review"]["status"], "MATERIAL_REVIEW_COMPLETE")
        self.assertIs(result["learning_actor_control_binding_verified"], False)
        self.assertEqual(result["missing_external_acceptance"],
                         verify_learning_packet(packet, trusted)["missing_external_acceptance"] +
                         ["original learning actor-to-control binding"])
        self.assertEqual(result["qualification"], "HOLD_NO_GO")
        self.assertIs(result["hepta_final_use"], False)

    def test_seven_role_materials_do_not_waive_a_wrong_parent_or_bad_signature(self):
        packet, trusted = self.packet()
        packet["run_plans"][0]["controls"][0]["artifact"] = "f" * 64
        with self.assertRaises(ValueError):
            self.review(packet, trusted)
        packet, trusted = self.packet()
        packet["attestations"][1]["consumer_signature"] = "00" * 64
        with self.assertRaises(ValueError):
            self.review(packet, trusted)

    def test_valid_learning_cannot_hide_colluding_trainer_and_evaluator(self):
        actors = {row["role"]: row["controller_id"] for row in self.manifest["bindings"]}
        self.manifest["common_control"].append(dict(
            controllers=sorted((actors["trainer"], actors["evaluator"])), kind="same_operator"))
        self.control = control_fixtures.refresh(self.manifest, self.policy)
        packet, trusted = self.packet()
        result = self.review(packet, trusted)
        self.assertEqual(result["control_material_review"]["status"], "CONFLICT")
        self.assertTrue(result["control_material_review"]["conflicts"])
        self.assertIs(result["independent_control_accepted"], False)

    def test_signed_learning_cannot_replace_missing_independence_material(self):
        self.manifest["separation_reviews"] = []
        self.control = control_fixtures.refresh(self.manifest, self.policy)
        packet, trusted = self.packet()
        result = self.review(packet, trusted)
        self.assertEqual(result["control_material_review"]["status"], "UNRESOLVED")
        self.assertIs(result["hepta_final_use"], False)

    def test_control_report_from_a_different_campaign_cannot_be_spliced_in(self):
        packet, trusted = self.packet()
        # V3 is still valid; this separate campaign boundary belongs to the
        # qualification owner, not the candidate's list of control documents.
        packet["campaign"] = trusted["campaign"] = "e" * 64
        verify_learning_packet(packet, trusted)
        with self.assertRaisesRegex(Refusal, "CONTROL_CAMPAIGN"):
            self.review(packet, trusted)


if __name__ == "__main__":
    unittest.main()
