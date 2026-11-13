"""Adversarial four-domain controls; all participants and documents are synthetic."""
import copy
import hashlib
import unittest

from protocol import Refusal, canonical
from control_domains import (
    AXES, MAX_DOCUMENT_BYTES, SCHEMA, document_statement,
    domains_manifest_digest, review_control_domains,
)
from control_separation import review_control_separation
import test_control_separation as fixtures


def domain_fixture(manifest, trusted):
    result = dict(schema=SCHEMA, pair=copy.deepcopy(manifest["pair"]),
        campaign=manifest["campaign"], control_manifest=trusted["expected_manifest"],
        control_policy=trusted["expected_policy"], revision=manifest["revision"],
        valid_from=manifest["valid_from"], valid_until=manifest["valid_until"], inventories=[])
    for row in manifest["inventories"]:
        actor = row["controller_id"]
        result["inventories"].append(dict(controller_id=actor,
            domains={axis: [axis + ":" + actor] for axis in AXES},
            observed_at=950, valid_until=1400, document_sha256="0" * 64))
    return result


def repin(manifest):
    """Re-pin test-only material, never an acceptance source for real subjects."""
    documents = {}
    for row in manifest["inventories"]:
        raw = canonical(document_statement(manifest, row))
        row["document_sha256"] = hashlib.sha256(raw).hexdigest()
        documents[row["document_sha256"]] = raw
    return documents, domains_manifest_digest(canonical(manifest))


class ControlDomainsTests(unittest.TestCase):
    def setUp(self):
        self.manifest, self.policy, self.trusted = fixtures.fixture()
        self.domains = domain_fixture(self.manifest, self.trusted)
        self.documents, self.pin = repin(self.domains)

    def review(self):
        return review_control_domains(canonical(self.manifest), canonical(self.policy),
            canonical(self.domains), self.documents, expected_domains=self.pin, **self.trusted)

    def refresh(self):
        self.documents, self.pin = repin(self.domains)

    def actor(self, role):
        return next(row["controller_id"] for row in self.manifest["bindings"] if row["role"] == role)

    def row(self, actor):
        return next(row for row in self.domains["inventories"] if row["controller_id"] == actor)

    def share(self, a, b, axis):
        self.row(a)["domains"][axis] = ["declared-shared-principal"]
        self.row(b)["domains"][axis] = ["declared-shared-principal"]
        self.refresh()

    def test_complete_documents_keep_original_review_and_all_authority_false(self):
        before = copy.deepcopy((self.manifest, self.policy, self.trusted, self.domains, self.documents))
        report = self.review()
        self.assertEqual(report["status"], "MATERIAL_REVIEW_COMPLETE")
        self.assertEqual(report["original_control_material_review"], review_control_separation(
            canonical(self.manifest), canonical(self.policy), **self.trusted))
        self.assertEqual(report["checked_document_bytes"], sum(map(len, self.documents.values())))
        self.assertEqual(report["checked_document_digests"], sorted(self.documents))
        self.assertIsNone(report["joint_independent_operator_count"])
        for name in ("source_documents_authenticated", "hidden_control_excluded",
                     "independent_control_accepted", "physical_installation_accepted",
                     "hepta_final_use", "production_activation"):
            self.assertIs(report[name], False)
        self.assertEqual(before, (self.manifest, self.policy, self.trusted, self.domains, self.documents))
        self.assertEqual(report, self.review())

    def test_each_axis_catches_shared_dependency_on_same_required_pair(self):
        for axis in AXES:
            with self.subTest(axis=axis):
                self.setUp()
                self.share(self.actor("trainer"), self.actor("evaluator"), axis)
                report = self.review()
                self.assertEqual(report["status"], "CONFLICT")
                code = "DOMAINS_REQUIRED_COMMON_FAILURE" if axis == "failure" else "DOMAINS_REQUIRED_COMMON_AUTHORITY"
                self.assertTrue(any(row["code"] == code for row in report["conflicts"]))

    def test_transitive_cross_axis_authority_is_not_three_independent_ids(self):
        a, b, middle = self.actor("trainer"), self.actor("evaluator"), self.actor("storage")
        self.row(a)["domains"]["funding"] = ["funding-principal"]
        self.row(middle)["domains"]["administration"] = ["funding-principal"]
        self.row(middle)["domains"]["key_custody"] = ["custody-principal"]
        self.row(b)["domains"]["funding"] = ["custody-principal"]
        self.refresh()
        report = self.review()
        self.assertTrue(any(row["code"] == "DOMAINS_REQUIRED_COMMON_AUTHORITY" and
            set(row["controllers"]) == {a, b} for row in report["conflicts"]))

    def test_domain_identifying_an_existing_controller_joins_that_controller(self):
        self.row(self.actor("trainer"))["domains"]["funding"] = [self.actor("evaluator")]
        self.refresh()
        self.assertEqual(self.review()["status"], "CONFLICT")

    def test_shared_failure_domain_does_not_invent_authority_over_other_party(self):
        self.share(self.actor("trainer"), self.actor("evaluator"), "failure")
        report = self.review()
        self.assertTrue(any(row["code"] == "DOMAINS_REQUIRED_COMMON_FAILURE" for row in report["conflicts"]))
        self.assertFalse(any(row["code"] == "DOMAINS_REQUIRED_COMMON_AUTHORITY" for row in report["conflicts"]))

    def test_funded_reviewer_is_removed_after_original_review(self):
        reviewer = self.policy["reviewers"][0]["controller_id"]
        self.share(reviewer, self.actor("trainer"), "funding")
        report = self.review()
        self.assertEqual(report["original_control_material_review"]["status"], "MATERIAL_REVIEW_COMPLETE")
        self.assertEqual(report["status"], "UNRESOLVED")
        affected = [row for row in report["separation_observations"] if "trainer" in row["roles"]]
        self.assertTrue(all(row["known_reviewer_components"] == 0 for row in affected))

    def test_empty_domains_are_unknown_instead_of_independent(self):
        for axis in AXES:
            with self.subTest(axis=axis):
                self.setUp()
                self.row(self.actor("trainer"))["domains"][axis] = []
                self.refresh()
                report = self.review()
                self.assertEqual(report["status"], "UNRESOLVED")
                self.assertTrue(any(row["code"] == "DOMAINS_AXIS_UNKNOWN" and row["axis"] == axis
                                    for row in report["unresolved"]))

    def test_missing_controller_and_reviewer_inventories_remain_unresolved(self):
        for actor in (self.actor("trainer"), self.policy["reviewers"][0]["controller_id"]):
            with self.subTest(actor=actor):
                self.setUp()
                self.domains["inventories"] = [row for row in self.domains["inventories"]
                                                if row["controller_id"] != actor]
                self.refresh()
                self.assertEqual(self.review()["status"], "UNRESOLVED")

    def test_missing_actual_document_is_not_a_hash_only_pass(self):
        self.documents.pop(self.row(self.actor("trainer"))["document_sha256"])
        report = self.review()
        self.assertEqual(report["status"], "UNRESOLVED")
        self.assertTrue(any(row["code"] == "DOMAINS_DOCUMENT_MISSING" for row in report["unresolved"]))

    def test_missing_document_cannot_erase_a_known_adverse_declaration(self):
        self.share(self.actor("trainer"), self.actor("evaluator"), "funding")
        self.documents.pop(self.row(self.actor("trainer"))["document_sha256"])
        report = self.review()
        self.assertEqual(report["status"], "CONFLICT")
        self.assertTrue(report["unresolved"])

    def test_actual_bytes_with_wrong_digest_are_refused(self):
        key = next(iter(self.documents))
        self.documents[key] += b" "
        with self.assertRaisesRegex(Refusal, "DOMAINS_DOCUMENT_DIGEST"):
            self.review()

    def test_rehashed_document_cannot_change_bound_statement(self):
        row = self.row(self.actor("trainer"))
        self.documents.pop(row["document_sha256"])
        wrong = document_statement(self.domains, row)
        wrong["inventory"]["domains"] = {axis: ["substituted-claim"] for axis in AXES}
        raw = canonical(wrong)
        row["document_sha256"] = hashlib.sha256(raw).hexdigest()
        self.documents[row["document_sha256"]] = raw
        self.pin = domains_manifest_digest(canonical(self.domains))
        with self.assertRaisesRegex(Refusal, "DOMAINS_DOCUMENT_STATEMENT"):
            self.review()

    def test_duplicate_controller_and_domains_are_refused(self):
        self.domains["inventories"].append(copy.deepcopy(self.domains["inventories"][-1]))
        self.refresh()
        with self.assertRaisesRegex(Refusal, "DOMAINS_INVENTORY_ORDER_OR_DUPLICATE"):
            self.review()
        self.setUp()
        row = self.row(self.actor("trainer"))
        row["domains"]["funding"] *= 2
        self.refresh()
        with self.assertRaisesRegex(Refusal, "DOMAINS_IDENTITIES"):
            self.review()

    def test_extra_supplied_document_is_not_silently_omitted(self):
        raw = b"unreferenced"
        self.documents[hashlib.sha256(raw).hexdigest()] = raw
        with self.assertRaisesRegex(Refusal, "DOMAINS_UNREFERENCED_DOCUMENT"):
            self.review()

    def test_declared_document_byte_limit_is_checked_before_v1_review(self):
        key = next(iter(self.documents))
        self.documents[key] = b"x" * (MAX_DOCUMENT_BYTES + 1)
        self.manifest["schema"] = "wrong-schema"
        with self.assertRaisesRegex(Refusal, "DOMAINS_DOCUMENT_LIMIT"):
            self.review()

    def test_current_time_expiry_and_original_pins_are_enforced(self):
        self.trusted["now"] = 1400
        with self.assertRaisesRegex(Refusal, "CONTROL_EVIDENCE_TIME|DOMAINS_OBSERVATION_TIME"):
            self.review()
        self.setUp()
        self.domains["control_manifest"] = "a" * 64
        self.refresh()
        with self.assertRaisesRegex(Refusal, "DOMAINS_CONTROL_BINDING"):
            self.review()

    def test_repinning_wrong_campaign_pair_or_revision_does_not_bypass_owner(self):
        mutations = (("campaign", "a" * 64, "DOMAINS_CAMPAIGN"),
                     ("revision", 4, "DOMAINS_REVISION"),
                     ("pair", {key: "a" * 40 for key in self.domains["pair"]}, "DOMAINS_SOURCE_PAIR"))
        for key, value, error in mutations:
            with self.subTest(key=key):
                self.setUp()
                self.domains[key] = value
                self.refresh()
                with self.assertRaisesRegex(Refusal, error):
                    self.review()

    def test_unknown_axis_noncanonical_bytes_and_candidate_pin_fail(self):
        self.row(self.actor("trainer"))["domains"]["independent"] = True
        self.refresh()
        with self.assertRaisesRegex(Refusal, "DOMAINS_AXES"):
            self.review()
        self.setUp()
        raw = canonical(self.domains) + b" "
        with self.assertRaisesRegex(Refusal, "NONCANONICAL"):
            review_control_domains(canonical(self.manifest), canonical(self.policy), raw,
                self.documents, expected_domains=domains_manifest_digest(raw), **self.trusted)
        self.pin = "f" * 64
        with self.assertRaisesRegex(Refusal, "DOMAINS_PIN"):
            self.review()

    def test_storage_pair_with_separate_keys_but_shared_fault_or_funding_is_not_independent(self):
        actors = [row["controller_id"] for row in self.manifest["bindings"] if row["role"] == "storage"]
        for axis in ("funding", "failure"):
            with self.subTest(axis=axis):
                self.setUp()
                self.share(*actors, axis)
                report = self.review()
                self.assertEqual(report["status"], "CONFLICT")
                self.assertIsNone(report["joint_independent_operator_count"])


class LearningDomainJoinTests(unittest.TestCase):
    def test_real_v3_no_update_and_fault_domain_conflict_are_both_retained(self):
        from campaign_gate import review_learning_control_domains, verify_learning_packet
        from test_learning_control_join import LearningControlJoinTests
        original = LearningControlJoinTests()
        original.setUp()
        packet, trusted = original.packet()
        domains = domain_fixture(original.manifest, original.control)
        storage = {row["controller_id"] for row in original.manifest["bindings"] if row["role"] == "storage"}
        for row in domains["inventories"]:
            if row["controller_id"] in storage:
                row["domains"]["failure"] = ["one-shared-failure-domain"]
        documents, pin = repin(domains)
        controls = dict(manifest=original.control["expected_manifest"],
                        policy=original.control["expected_policy"],
                        revision=original.control["expected_revision"],
                        bindings=original.control["expected_bindings"])
        result = review_learning_control_domains(packet, trusted, canonical(original.manifest),
            canonical(original.policy), controls, canonical(domains), documents,
            expected_domains=pin, now=original.control["now"])
        self.assertEqual(result["learning_input_review"], verify_learning_packet(packet, trusted))
        self.assertEqual(result["control_domain_material_review"]["status"], "CONFLICT")
        self.assertEqual(result["qualification"], "HOLD_NO_GO")
        self.assertIs(result["learning_actor_control_binding_verified"], False)
        packet["attestations"][1]["consumer_signature"] = "00" * 64
        with self.assertRaises(ValueError):
            review_learning_control_domains(packet, trusted, canonical(original.manifest),
                canonical(original.policy), controls, canonical(domains), documents,
                expected_domains=pin, now=original.control["now"])


if __name__ == "__main__":
    unittest.main()
