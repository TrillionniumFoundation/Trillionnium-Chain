"""Synthetic material controls; no independent operator or native use evidence."""
import copy
import hashlib
import unittest
from itertools import combinations, product

from protocol import Refusal, canonical
from control_separation import (
    COMMON_CONTROL_DOMAIN, INVENTORY_DOMAIN, MANIFEST_SCHEMA, MAX_BYTES, MINIMUM_REQUIRED_SEPARATIONS,
    POLICY_SCHEMA, ROLES, SEPARATION_DOMAIN, evidence_statement_digest,
    manifest_digest, policy_digest, review_control_separation,
)


def h(label):
    return hashlib.sha256(label.encode()).hexdigest()


def evidence(domain, statement, manifest, authority=None):
    return dict(domain=domain, authority=authority or h("reviewer-key"),
        document_sha256=h("synthetic-document:" + domain + canonical(statement).decode()),
        statement_sha256=evidence_statement_digest(domain, manifest["campaign"],
            manifest["policy"], manifest["revision"], statement),
        observed_at=950, valid_until=1400)


def refresh(manifest, policy):
    """Explicitly re-pin synthetic edits; never a production trust operation."""
    manifest["policy"] = policy_digest(canonical(policy))
    for name, domain in (("inventories", INVENTORY_DOMAIN), ("common_control", COMMON_CONTROL_DOMAIN),
                         ("separation_reviews", SEPARATION_DOMAIN)):
        for row in manifest[name]:
            statement = {k: v for k, v in row.items() if k != "evidence"}
            if "evidence" not in row:
                row["evidence"] = evidence(domain, statement, manifest)
            else:
                row["evidence"]["statement_sha256"] = evidence_statement_digest(
                    domain, manifest["campaign"], manifest["policy"], manifest["revision"], statement)
    manifest["bindings"].sort(key=lambda row: (row["role"], row["signer"]))
    manifest["inventories"].sort(key=lambda row: row["controller_id"])
    manifest["common_control"].sort(key=lambda row: (*row["controllers"], row["kind"]))
    manifest["separation_reviews"].sort(key=lambda row: (*row["controllers"], row["evidence"]["authority"]))
    return dict(expected_manifest=manifest_digest(canonical(manifest)),
                expected_policy=policy_digest(canonical(policy)),
                expected_campaign=manifest["campaign"], expected_pair=copy.deepcopy(manifest["pair"]),
                expected_revision=manifest["revision"],
                expected_bindings=copy.deepcopy(manifest["bindings"]), now=1000)


def fixture():
    """Return (manifest dict, policy dict, trusted keyword args), all synthetic."""
    pair = {key: hashlib.sha1(key.encode()).hexdigest()
            for key in ("chain_source", "chain_tree", "hepta_source", "hepta_tree")}
    roles = {role: [h("controller:" + role)] for role in ROLES}
    roles["storage"].append(h("controller:second-storage"))
    required = sorted([sorted(p) for p in (
        ("trainer", "evaluator"), ("task_publisher", "evaluator"),
        ("trainer", "version_selector"), ("evaluator", "version_selector"),
        ("trainer", "release_key_custodian"), ("trainer", "consumer"),
        ("version_selector", "consumer"), ("storage", "storage"))])
    policy = dict(schema=POLICY_SCHEMA, pair=pair, campaign=h("campaign"), revision=3,
        valid_from=100, valid_until=2000, maximum_evidence_age_seconds=1000,
        minimum_role_components={role: 2 if role == "storage" else 1 for role in ROLES},
        required_separations=required, minimum_reviewer_components=1,
        reviewers=[dict(authority=h("reviewer-key"), controller_id=h("reviewer-controller"))])
    manifest = dict(schema=MANIFEST_SCHEMA, pair=copy.deepcopy(pair), campaign=policy["campaign"],
        policy=policy_digest(canonical(policy)), revision=3, valid_from=900, valid_until=1500,
        bindings=[], inventories=[], common_control=[], separation_reviews=[])
    controllers = {h("reviewer-controller")}
    for role, actors in roles.items():
        for actor in actors:
            manifest["bindings"].append(dict(role=role, signer=h("signer:" + actor),
                controller_id=actor, owner_digest=h("original-owner:" + role + actor)))
            controllers.add(actor)
    for actor in sorted(controllers):
        manifest["inventories"].append(dict(controller_id=actor, administrators=[], key_custodians=[]))
    pairs = set()
    for a_role, b_role in required:
        selected = (combinations(roles[a_role], 2) if a_role == b_role
                    else product(roles[a_role], roles[b_role]))
        pairs.update(tuple(sorted(pair)) for pair in selected)
    for pair_actors in sorted(pairs):
        manifest["separation_reviews"].append(dict(controllers=list(pair_actors)))
    return manifest, policy, refresh(manifest, policy)


class ControlSeparationTests(unittest.TestCase):
    def setUp(self):
        self.manifest, self.policy, self.trusted = fixture()

    def review(self):
        return review_control_separation(canonical(self.manifest), canonical(self.policy), **self.trusted)

    def repin(self):
        self.trusted = refresh(self.manifest, self.policy)

    def controller(self, role):
        return next(row["controller_id"] for row in self.manifest["bindings"] if row["role"] == role)

    def add_inventory(self, controller):
        self.manifest["inventories"].append(dict(controller_id=controller, administrators=[], key_custodians=[]))

    def add_link(self, a, b, kind="same_operator"):
        self.manifest["common_control"].append(dict(controllers=sorted([a, b]), kind=kind))

    def assert_no_authority(self, report):
        for field in ("source_documents_authenticated", "hidden_control_excluded",
                      "independent_control_accepted", "physical_installation_accepted",
                      "hepta_final_use", "production_activation"):
            self.assertIs(report[field], False)

    def test_complete_pinned_materials_never_grant_native_or_independent_authority(self):
        before = copy.deepcopy((self.manifest, self.policy, self.trusted))
        result = self.review()
        self.assertEqual(result["status"], "MATERIAL_REVIEW_COMPLETE")
        self.assertEqual(result["conflicts"], [])
        self.assertEqual(result["unresolved"], [])
        self.assertEqual(result, self.review())
        self.assertEqual(before, (self.manifest, self.policy, self.trusted))
        self.assertEqual(len(result["role_observations"]), 7)
        self.assert_no_authority(result)

    def test_one_actual_controller_with_many_role_keys_conflicts(self):
        controller = self.controller("trainer")
        for row in self.manifest["bindings"]:
            row["controller_id"] = controller
        self.repin()
        result = self.review()
        self.assertEqual(result["status"], "CONFLICT")
        self.assertTrue(any(row["code"] == "CONTROL_REQUIRED_SHARED_COMPONENT" for row in result["conflicts"]))
        self.assertTrue(all(row["known_control_component_count"] == 1 for row in result["role_observations"]))
        self.assert_no_authority(result)

    def test_key_rotation_does_not_add_control_components(self):
        old = next(row for row in self.manifest["bindings"] if row["role"] == "trainer")
        self.manifest["bindings"].append(dict(old, signer=h("rotated-trainer-key")))
        self.repin()
        trainer = next(row for row in self.review()["role_observations"] if row["role"] == "trainer")
        self.assertEqual(trainer["signer_count"], 2)
        self.assertEqual(trainer["known_control_component_count"], 1)

    def test_original_owner_controller_mapping_cannot_be_relabelled(self):
        self.manifest["bindings"][0]["controller_id"] = h("self-chosen-controller")
        self.trusted["expected_manifest"] = manifest_digest(canonical(self.manifest))
        with self.assertRaisesRegex(Refusal, "CONTROL_ORIGINAL_OWNER_BINDINGS"):
            self.review()

    def test_original_owner_record_cannot_be_substituted(self):
        self.manifest["bindings"][0]["owner_digest"] = h("another-owner-record")
        self.trusted["expected_manifest"] = manifest_digest(canonical(self.manifest))
        with self.assertRaisesRegex(Refusal, "CONTROL_ORIGINAL_OWNER_BINDINGS"):
            self.review()

    def test_one_signer_cannot_claim_two_controllers(self):
        self.manifest["bindings"][1]["signer"] = self.manifest["bindings"][0]["signer"]
        self.repin()
        with self.assertRaisesRegex(Refusal, "CONTROL_SIGNER_CONTROLLER_ALIAS"):
            self.review()

    def test_transitive_common_control_through_intermediate_administrator(self):
        middle = h("intermediate-administrator")
        self.add_inventory(middle)
        self.add_link(self.controller("trainer"), middle, "shared_administrator")
        self.add_link(middle, self.controller("evaluator"), "declared_control")
        self.repin()
        result = self.review()
        self.assertEqual(result["status"], "CONFLICT")
        self.assertTrue(any(row.get("roles") == ["evaluator", "trainer"] for row in result["conflicts"]))

    def test_shared_administrator_is_discovered_without_explicit_link(self):
        shared = h("shared-root-administrator")
        self.add_inventory(shared)
        parties = {self.controller("trainer"), self.controller("evaluator")}
        for row in self.manifest["inventories"]:
            if row["controller_id"] in parties:
                row["administrators"] = [shared]
        self.repin()
        self.assertEqual(self.review()["status"], "CONFLICT")

    def test_shared_release_custodian_merges_storage_replicas(self):
        shared = h("shared-release-key-custodian")
        self.add_inventory(shared)
        parties = {row["controller_id"] for row in self.manifest["bindings"] if row["role"] == "storage"}
        for row in self.manifest["inventories"]:
            if row["controller_id"] in parties:
                row["key_custodians"] = [shared]
        self.repin()
        result = self.review()
        self.assertEqual(result["status"], "CONFLICT")
        self.assertTrue(any(row["code"] == "CONTROL_ROLE_COMMON_CONTROL" for row in result["conflicts"]))

    def test_admin_and_custody_identifiers_share_the_same_control_graph(self):
        shared = h("same-person-in-different-functions")
        self.add_inventory(shared)
        for row in self.manifest["inventories"]:
            if row["controller_id"] == self.controller("trainer"):
                row["administrators"] = [shared]
            if row["controller_id"] == self.controller("evaluator"):
                row["key_custodians"] = [shared]
        self.repin()
        self.assertEqual(self.review()["status"], "CONFLICT")

    def test_missing_each_of_the_seven_roles_remains_unresolved(self):
        for role in ROLES:
            self.manifest, self.policy, self.trusted = fixture()
            self.manifest["bindings"] = [row for row in self.manifest["bindings"] if row["role"] != role]
            self.repin()
            with self.subTest(role=role):
                result = self.review()
                self.assertEqual(result["status"], "UNRESOLVED")
                self.assertIn(dict(code="CONTROL_ROLE_MISSING", role=role), result["unresolved"])

    def test_absent_inventory_does_not_assert_unknown_control_is_independent(self):
        missing = self.manifest["inventories"].pop()
        self.repin()
        result = self.review()
        self.assertEqual(result["status"], "UNRESOLVED")
        self.assertIn(dict(code="CONTROL_INVENTORY_MISSING", controller_id=missing["controller_id"]), result["unresolved"])

    def test_new_administrator_without_its_inventory_remains_unresolved(self):
        missing = h("unreviewed-administrator")
        self.manifest["inventories"][0]["administrators"] = [missing]
        self.repin()
        self.assertIn(dict(code="CONTROL_INVENTORY_MISSING", controller_id=missing), self.review()["unresolved"])

    def test_distinct_controller_labels_without_pair_reviews_remain_unknown(self):
        self.manifest["separation_reviews"] = []
        self.repin()
        result = self.review()
        self.assertEqual(result["status"], "UNRESOLVED")
        self.assertEqual(len(result["unresolved"]), len(self.policy["required_separations"]))
        self.assert_no_authority(result)

    def test_missing_replica_cannot_satisfy_separation_vacuously(self):
        removed = False
        bindings = []
        for row in self.manifest["bindings"]:
            if row["role"] == "storage" and not removed:
                removed = True
            else:
                bindings.append(row)
        self.manifest["bindings"] = bindings
        self.repin()
        self.assertTrue(any(row["code"] == "CONTROL_ROLE_ROSTER_INCOMPLETE" for row in self.review()["unresolved"]))

    def test_self_controlled_reviewer_does_not_establish_separation(self):
        self.add_link(h("reviewer-controller"), self.controller("trainer"), "shared_administrator")
        self.repin()
        result = self.review()
        self.assertEqual(result["status"], "UNRESOLVED")
        rows = [row for row in result["separation_observations"] if "trainer" in row["roles"]]
        self.assertTrue(all(row["reviewer_components"] == 0 for row in rows))
        self.assertTrue(all(row["rejected_self_controlled_reviewers"] for row in rows))

    def test_role_signing_key_cannot_acquire_another_controller_as_reviewer(self):
        trainer = next(row for row in self.manifest["bindings"] if row["role"] == "trainer")
        previous = self.policy["reviewers"][0]["authority"]
        self.policy["reviewers"][0]["authority"] = trainer["signer"]
        # Deliberately retain the different reviewer controller. Re-pinning this
        # inconsistent policy must not override the original role-owner mapping.
        for section in ("inventories", "common_control", "separation_reviews"):
            for row in self.manifest[section]:
                if row["evidence"]["authority"] == previous:
                    row["evidence"]["authority"] = trainer["signer"]
        self.repin()
        with self.assertRaisesRegex(Refusal, "CONTROL_REVIEWER_SIGNER_CONTROLLER_ALIAS"):
            self.review()

    def test_same_role_key_and_controller_are_excluded_from_self_review(self):
        trainer = next(row for row in self.manifest["bindings"] if row["role"] == "trainer")
        previous = self.policy["reviewers"][0]["authority"]
        self.policy["reviewers"][0].update(authority=trainer["signer"],
                                          controller_id=trainer["controller_id"])
        for section in ("inventories", "common_control", "separation_reviews"):
            for row in self.manifest[section]:
                if row["evidence"]["authority"] == previous:
                    row["evidence"]["authority"] = trainer["signer"]
        self.repin()
        result = self.review()
        self.assertEqual(result["status"], "UNRESOLVED")
        rows = [row for row in result["separation_observations"] if "trainer" in row["roles"]]
        self.assertTrue(rows)
        self.assertTrue(all(row["reviewer_components"] == 0 for row in rows))
        self.assertTrue(all(row["rejected_self_controlled_reviewers"] == [trainer["signer"]]
                            for row in rows))
        self.assert_no_authority(result)

    def test_two_reviewer_keys_owned_by_one_controller_count_once(self):
        second = h("rotated-reviewer-key")
        self.policy["minimum_reviewer_components"] = 2
        self.policy["reviewers"].append(dict(authority=second, controller_id=h("reviewer-controller")))
        self.policy["reviewers"].sort(key=lambda row: row["authority"])
        for row in list(self.manifest["separation_reviews"]):
            other = copy.deepcopy(row)
            other["evidence"]["authority"] = second
            self.manifest["separation_reviews"].append(other)
        self.repin()
        result = self.review()
        self.assertEqual(result["status"], "UNRESOLVED")
        self.assertTrue(all(row["reviewer_components"] == 1 for row in result["separation_observations"]))

    def test_known_conflict_survives_a_contradictory_separation_review(self):
        self.add_link(self.controller("trainer"), self.controller("evaluator"))
        self.repin()
        result = self.review()
        self.assertEqual(result["status"], "CONFLICT")
        self.assertTrue(any(row["result"] == "CONFLICT" for row in result["separation_observations"]))

    def test_conflicts_do_not_erase_other_unresolved_materials(self):
        self.add_link(self.controller("trainer"), self.controller("evaluator"))
        self.manifest["inventories"].pop()
        self.manifest["separation_reviews"] = []
        self.repin()
        result = self.review()
        self.assertTrue(result["conflicts"])
        self.assertTrue(result["unresolved"])

    def test_changed_manifest_cannot_keep_its_external_pin(self):
        self.manifest["valid_until"] -= 1
        with self.assertRaisesRegex(Refusal, "CONTROL_MANIFEST_PIN"):
            self.review()

    def test_changed_policy_cannot_keep_its_external_pin(self):
        self.policy["minimum_reviewer_components"] = 2
        with self.assertRaisesRegex(Refusal, "CONTROL_POLICY_PIN"):
            self.review()

    def test_campaign_source_pair_revision_and_owner_bindings_are_independent_inputs(self):
        changes = (
            ("expected_campaign", h("other-campaign"), "CONTROL_CAMPAIGN"),
            ("expected_revision", 4, "CONTROL_POLICY_REVISION"),
            ("expected_pair", {key: "a" * 40 for key in self.trusted["expected_pair"]}, "CONTROL_SOURCE_PAIR"),
            ("expected_bindings", [], "CONTROL_ORIGINAL_OWNER_BINDINGS"),
        )
        for key, value, error in changes:
            self.manifest, self.policy, self.trusted = fixture()
            self.trusted[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(Refusal, error):
                self.review()

    def test_old_policy_cannot_be_resubmitted_as_current_revision(self):
        self.trusted["expected_revision"] += 1
        with self.assertRaisesRegex(Refusal, "CONTROL_POLICY_REVISION"):
            self.review()

    def test_manifest_uses_the_exact_policy_digest(self):
        self.manifest["policy"] = h("another-policy")
        self.trusted["expected_manifest"] = manifest_digest(canonical(self.manifest))
        with self.assertRaisesRegex(Refusal, "CONTROL_POLICY_BINDING"):
            self.review()

    def test_evidence_domain_cannot_be_reused_for_another_kind(self):
        row = self.manifest["separation_reviews"][0]
        row["evidence"]["domain"] = INVENTORY_DOMAIN
        self.trusted["expected_manifest"] = manifest_digest(canonical(self.manifest))
        with self.assertRaisesRegex(Refusal, "CONTROL_EVIDENCE_DOMAIN"):
            self.review()

    def test_evidence_is_bound_to_exact_controller_pair(self):
        row = self.manifest["separation_reviews"][0]
        row["controllers"] = sorted([h("substituted-one"), h("substituted-two")])
        self.trusted["expected_manifest"] = manifest_digest(canonical(self.manifest))
        with self.assertRaisesRegex(Refusal, "CONTROL_EVIDENCE_STATEMENT"):
            self.review()

    def test_evidence_cannot_be_moved_between_campaigns_or_policy_revisions(self):
        for key, value in (("campaign", h("new-campaign")), ("revision", 4)):
            self.manifest, self.policy, self.trusted = fixture()
            self.manifest[key] = self.policy[key] = value
            self.manifest["policy"] = policy_digest(canonical(self.policy))
            self.trusted["expected_policy"] = self.manifest["policy"]
            self.trusted["expected_manifest"] = manifest_digest(canonical(self.manifest))
            self.trusted["expected_campaign" if key == "campaign" else "expected_revision"] = value
            with self.subTest(key=key), self.assertRaisesRegex(Refusal, "CONTROL_EVIDENCE_STATEMENT"):
                self.review()

    def test_unlisted_evidence_authority_cannot_self_authorize(self):
        self.manifest["inventories"][0]["evidence"]["authority"] = h("attacker-authority")
        self.trusted["expected_manifest"] = manifest_digest(canonical(self.manifest))
        with self.assertRaisesRegex(Refusal, "CONTROL_EVIDENCE_AUTHORITY"):
            self.review()

    def test_expiry_is_exclusive_and_future_evidence_is_rejected(self):
        for field, value in (("valid_until", 1000), ("observed_at", 1001), ("observed_at", 99)):
            self.manifest, self.policy, self.trusted = fixture()
            self.manifest["inventories"][0]["evidence"][field] = value
            self.trusted["expected_manifest"] = manifest_digest(canonical(self.manifest))
            with self.subTest(field=field, value=value), self.assertRaisesRegex(Refusal, "CONTROL_EVIDENCE_TIME"):
                self.review()

    def test_current_time_is_not_taken_from_the_candidate_packet(self):
        self.trusted["now"] = 1500
        with self.assertRaisesRegex(Refusal, "CONTROL_MANIFEST_TIME"):
            self.review()
        self.trusted["now"] = 2000
        with self.assertRaisesRegex(Refusal, "CONTROL_POLICY_TIME"):
            self.review()

    def test_evidence_maximum_age_is_enforced(self):
        self.policy["maximum_evidence_age_seconds"] = 49
        self.repin()
        with self.assertRaisesRegex(Refusal, "CONTROL_EVIDENCE_AGE"):
            self.review()

    def test_bool_float_and_negative_time_do_not_alias_integers(self):
        for key in ("now", "expected_revision"):
            for value in (True, 1.0, -1):
                self.manifest, self.policy, self.trusted = fixture()
                self.trusted[key] = value
                with self.subTest(key=key, value=value), self.assertRaisesRegex(Refusal, "INTEGER"):
                    self.review()

    def test_duplicate_or_unknown_fields_are_refused(self):
        self.manifest["independent_control_accepted"] = True
        self.trusted["expected_manifest"] = manifest_digest(canonical(self.manifest))
        with self.assertRaisesRegex(Refusal, "CONTROL_MANIFEST_FIELDS"):
            self.review()
        self.manifest, self.policy, self.trusted = fixture()
        raw = canonical(self.manifest)
        raw = b'{"schema":"ignored",' + raw[1:]
        self.trusted["expected_manifest"] = manifest_digest(raw)
        with self.assertRaisesRegex(Refusal, "DUPLICATE_KEY"):
            review_control_separation(raw, canonical(self.policy), **self.trusted)

    def test_noncanonical_json_and_oversized_wire_are_refused(self):
        raw = canonical(self.manifest) + b"\n"
        self.trusted["expected_manifest"] = manifest_digest(raw)
        with self.assertRaisesRegex(Refusal, "NONCANONICAL"):
            review_control_separation(raw, canonical(self.policy), **self.trusted)
        with self.assertRaisesRegex(Refusal, "CONTROL_WIRE_LIMIT"):
            manifest_digest(b"x" * (MAX_BYTES + 1))

    def test_duplicate_review_cannot_be_counted_again(self):
        self.manifest["separation_reviews"].append(copy.deepcopy(self.manifest["separation_reviews"][0]))
        self.repin()
        with self.assertRaisesRegex(Refusal, "CONTROL_REVIEW_ORDER_OR_DUPLICATE"):
            self.review()

    def test_unknown_role_and_wrong_field_types_are_refused(self):
        self.manifest["bindings"][0]["role"] = "node-process"
        self.repin()
        with self.assertRaisesRegex(Refusal, "CONTROL_ROLE"):
            self.review()
        self.manifest, self.policy, self.trusted = fixture()
        self.manifest["inventories"][0]["administrators"] = None
        self.trusted["expected_manifest"] = manifest_digest(canonical(self.manifest))
        with self.assertRaisesRegex(Refusal, "CONTROL_ADMINISTRATORS"):
            self.review()

    def test_independence_counts_require_explicit_same_role_pair_review(self):
        self.policy["required_separations"].remove(["storage", "storage"])
        self.repin()
        with self.assertRaisesRegex(Refusal, "CONTROL_POLICY_REQUIRED_SEPARATION_MISSING"):
            self.review()

    def test_each_minimum_safety_pair_cannot_be_removed_even_with_a_new_policy_pin(self):
        for pair in MINIMUM_REQUIRED_SEPARATIONS:
            self.manifest, self.policy, self.trusted = fixture()
            self.policy["required_separations"].remove(list(pair))
            self.repin()
            with self.subTest(pair=pair), self.assertRaisesRegex(Refusal, "CONTROL_POLICY_REQUIRED_SEPARATION_MISSING"):
                self.review()

    def test_original_hepta_stable_id_is_preserved_without_digest_reinterpretation(self):
        old = self.controller("trainer")
        current = "authority:Trainer-Alpha_1.Origin"
        for row in self.manifest["bindings"]:
            if row["controller_id"] == old:
                row["controller_id"] = current
        for row in self.manifest["inventories"]:
            if row["controller_id"] == old:
                row["controller_id"] = current
        for row in self.manifest["separation_reviews"]:
            row["controllers"] = sorted(current if value == old else value for value in row["controllers"])
        self.repin()
        result = self.review()
        self.assertEqual(result["status"], "MATERIAL_REVIEW_COMPLETE")
        trainer = next(row for row in result["role_observations"] if row["role"] == "trainer")
        self.assertEqual(trainer["controller_ids"], [current])

    def test_stable_controller_grammar_refuses_ambiguous_or_oversized_identifiers(self):
        for value in ("", "name space", "name/space", "é", "x" * 129, None, True):
            self.manifest, self.policy, self.trusted = fixture()
            self.trusted["expected_bindings"][0]["controller_id"] = value
            with self.subTest(value=value), self.assertRaisesRegex(Refusal, "CONTROL_CONTROLLER_ID"):
                self.review()

    def test_sharing_outside_required_pairs_is_still_reported(self):
        self.add_link(self.controller("task_publisher"), self.controller("release_key_custodian"))
        self.repin()
        result = self.review()
        self.assertEqual(result["status"], "MATERIAL_REVIEW_COMPLETE")
        self.assertTrue(any(row["roles"] == ["release_key_custodian", "task_publisher"]
                            for row in result["observed_role_control_overlaps"]))
        self.assert_no_authority(result)

    def test_empty_policy_cannot_pass_by_omitting_all_separation_requirements(self):
        self.policy["required_separations"] = []
        self.repin()
        with self.assertRaisesRegex(Refusal, "CONTROL_POLICY_NO_SEPARATIONS"):
            self.review()

    def test_many_documents_from_one_reviewer_do_not_create_independence(self):
        self.policy["minimum_reviewer_components"] = 2
        self.repin()
        result = self.review()
        self.assertEqual(result["status"], "UNRESOLVED")
        self.assertTrue(all(row["reviewer_components"] == 1 for row in result["separation_observations"]))
        self.assert_no_authority(result)

    def test_policy_and_manifest_hashes_are_domain_separated(self):
        raw = canonical(self.manifest)
        self.assertNotEqual(manifest_digest(raw), policy_digest(raw))


if __name__ == "__main__":
    unittest.main()
