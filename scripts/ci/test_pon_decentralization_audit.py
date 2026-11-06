#!/usr/bin/env python3
"""Independent adversarial controls; synthetic claims never establish independence."""
from __future__ import annotations

import copy
import hashlib
import itertools
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import pon_decentralization_audit as D

START = 1_800_000_000_000
END = START + 72 * 3600 * 1000
CONTEXT = {"chain_source_sha256": "1" * 64, "profile_sha256": "2" * 64}


def sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


def add_evidence(registry, label, status="current", start=START, end=END):
    identity = sha("synthetic evidence:" + label)
    registry["evidence"].append(dict(sha256=identity, valid_from_unix_ms=start,
                                   valid_until_unix_ms=end, status=status))
    return identity


def seal_subjects(registry):
    registry["subjects_sha256"] = D.canonical_sha256(registry["subjects"])
    return registry


def registry_fixture(count=3):
    registry = dict(schema="trnm-control-registry-v1", context=dict(CONTEXT),
                    valid_from_unix_ms=START, valid_until_unix_ms=END,
                    subjects_sha256="0" * 64, controllers=[], aliases=[], subjects=[], evidence=[])
    for index in range(count):
        evidence = add_evidence(registry, str(index))
        registry["controllers"].append(dict(id=f"controller-{index}", parents=[], evidence_sha256=evidence))
        registry["subjects"].append(dict(id=f"subject-{index}", controller=f"controller-{index}",
                                        key_sha256=sha(f"synthetic key:{index}"), evidence_sha256=evidence))
    return seal_subjects(registry)


def mapped(registry, *, expected_sha256=None, expected_context=None, start=START, end=END):
    return D.ControlMap(registry,
        expected_sha256=expected_sha256 or D.canonical_sha256(registry),
        expected_context=dict(CONTEXT) if expected_context is None else expected_context,
        start_unix_ms=start, end_unix_ms=end)


def brute_coalition(weights, threshold):
    """Independent exhaustive small-case oracle; does not use implementation helpers."""
    for size in range(1, len(weights) + 1):
        for group in itertools.combinations(weights, size):
            if sum(group) >= threshold:
                return size
    return None


def weighted_registry(weights):
    registry = registry_fixture(len(weights))
    registry["subjects"] = []
    for controller, weight in enumerate(weights):
        for voter in range(weight):
            identity = f"voter-{controller}-{voter}"
            registry["subjects"].append(dict(
                id=identity, controller=f"controller-{controller}", key_sha256=sha(identity),
                evidence_sha256=registry["evidence"][controller]["sha256"]))
    return seal_subjects(registry)


FIXTURE_PATH = ROOT / "scripts/ci/fixtures/pon_decentralization_v1.json"


def audit_fixture():
    # File references are explicitly synthetic; the expected results below are
    # fixed arithmetic facts, never assertions about real-world operators.
    return json.loads(FIXTURE_PATH.read_text())


def seal_fixture(value):
    seal_subjects(value["registry"])
    value["audit"]["control_registry_sha256"] = D.canonical_sha256(value["registry"])


def seal_roster(value):
    value["roster_sha256"] = D.canonical_sha256(value["roster"])


def audited(value):
    return D.evaluate(value["audit"], value["registry"])


def bind_alias(value, left, right):
    value["registry"]["aliases"].append(dict(left=left, right=right,
        evidence_sha256=value["registry"]["controllers"][0]["evidence_sha256"]))
    seal_fixture(value)


def evidence_row(value, identity):
    return next(row for row in value["registry"]["evidence"] if row["sha256"] == identity)


def finding_codes(report):
    return {finding["code"] for finding in report["findings"]}


class ControlDomains(unittest.TestCase):
    def test_distinct_synthetic_controllers_are_only_declared_groups(self):
        registry = registry_fixture()
        control = mapped(registry)
        self.assertEqual(len({control.group_for(s["id"]) for s in registry["subjects"]}), 3)
        self.assertNotIn(None, [control.group_for(s["id"]) for s in registry["subjects"]])

    def test_one_controller_cannot_multiply_nodes_keys_or_witnesses(self):
        registry = registry_fixture(1)
        prototype = registry["subjects"][0]
        for role in ("node", "ip", "evaluator", "provider", "witness"):
            for index in range(20):
                registry["subjects"].append(dict(prototype, id=f"{role}-{index}",
                                                key_sha256=sha(f"{role}-key-{index}")))
        seal_subjects(registry)
        control = mapped(registry)
        self.assertEqual(len({control.group_for(s["id"]) for s in registry["subjects"]}), 1)

    def test_common_parent_and_transitive_aliases_collapse(self):
        registry = registry_fixture(4)
        registry["controllers"][0]["parents"] = ["controller-1"]
        registry["controllers"][1]["parents"] = ["controller-2"]
        registry["aliases"] = [dict(left="controller-2", right="controller-3",
                                    evidence_sha256=registry["evidence"][0]["sha256"])]
        control = mapped(registry)
        self.assertEqual(len({control.group_for(s["id"]) for s in registry["subjects"]}), 1)
        self.assertTrue(control.related("subject-0", "subject-3"))

    def test_common_control_cycle_is_not_three_independent_roots(self):
        registry = registry_fixture()
        for index in range(3):
            registry["controllers"][index]["parents"] = [f"controller-{(index + 1) % 3}"]
        control = mapped(registry)
        self.assertEqual(len({control.group_for(s["id"]) for s in registry["subjects"]}), 1)

    def test_graph_order_changes_neither_partition_nor_reported_relationships(self):
        registry = registry_fixture(5)
        registry["aliases"] = [dict(left="controller-0", right="controller-1",
                                    evidence_sha256=registry["evidence"][0]["sha256"]),
                               dict(left="controller-1", right="controller-2",
                                    evidence_sha256=registry["evidence"][1]["sha256"])]
        original = mapped(registry)
        permuted = copy.deepcopy(registry)
        for field in ("controllers", "aliases", "subjects", "evidence"):
            permuted[field].reverse()
        seal_subjects(permuted)
        changed = mapped(permuted)
        for a, b in itertools.product([s["id"] for s in registry["subjects"]], repeat=2):
            self.assertEqual(original.related(a, b), changed.related(a, b))

    def test_same_public_key_under_distinct_ids_collapses_controller_claims(self):
        registry = registry_fixture()
        registry["subjects"][1]["key_sha256"] = registry["subjects"][0]["key_sha256"]
        seal_subjects(registry)
        control = mapped(registry)
        self.assertTrue(control.related("subject-0", "subject-1"))
        with self.assertRaises(ValueError):
            control.quorum(["subject-0", "subject-1", "subject-2"], 2)

    def test_same_key_is_related_even_when_owner_is_unknown(self):
        for unknown in ((0,), (0, 1)):
            registry = registry_fixture()
            registry["subjects"][1]["key_sha256"] = registry["subjects"][0]["key_sha256"]
            for index in unknown:
                registry["subjects"][index]["controller"] = None
                registry["subjects"][index]["evidence_sha256"] = None
            seal_subjects(registry)
            control = mapped(registry)
            with self.subTest(unknown=unknown):
                self.assertTrue(control.related("subject-0", "subject-1"))
                for index in unknown:
                    self.assertIsNone(control.group_for(f"subject-{index}"))

    def test_unknown_owner_does_not_contribute_one_independent_group(self):
        registry = registry_fixture()
        registry["subjects"][0]["controller"] = None
        registry["subjects"][0]["evidence_sha256"] = None
        seal_subjects(registry)
        self.assertIsNone(mapped(registry).group_for("subject-0"))

    def test_revoked_unknown_and_expired_evidence_does_not_count(self):
        for mode in ("revoked", "unknown", "expired", "future"):
            with self.subTest(mode=mode):
                registry = registry_fixture()
                evidence = registry["evidence"][0]
                if mode in ("revoked", "unknown"):
                    evidence["status"] = mode
                elif mode == "expired":
                    evidence["valid_until_unix_ms"] = END - 1
                else:
                    evidence["valid_from_unix_ms"] = START + 1
                self.assertIsNone(mapped(registry).group_for("subject-0"))

    def test_invalid_alias_evidence_cannot_erase_known_common_control(self):
        for mode in ("revoked", "unknown", "expired"):
            with self.subTest(mode=mode):
                registry = registry_fixture()
                evidence = add_evidence(registry, "alias", status=mode if mode != "expired" else "current",
                                        end=END - 1 if mode == "expired" else END)
                registry["aliases"] = [dict(left="controller-0", right="controller-1", evidence_sha256=evidence)]
                control = mapped(registry)
                self.assertTrue(control.related("subject-0", "subject-1"))
                self.assertEqual(control.declared_group_for("subject-0"), control.declared_group_for("subject-1"))
                self.assertIsNone(control.group_for("subject-0"))
                self.assertIsNone(control.group_for("subject-1"))

    def test_verified_map_is_a_snapshot_not_mutable_registry_aliases(self):
        registry = registry_fixture()
        control = mapped(registry)
        subjects = [s["id"] for s in registry["subjects"]]
        before = control.quorum(subjects, 2)
        original_pin = D.canonical_sha256(registry)
        registry["subjects"][0]["controller"] = "controller-1"
        registry["subjects"][0]["key_sha256"] = registry["subjects"][1]["key_sha256"]
        registry["controllers"][0]["parents"].append("controller-1")
        registry["evidence"][2]["status"] = "revoked"
        self.assertEqual(control.quorum(subjects, 2), before)
        self.assertFalse(control.related("subject-0", "subject-1"))
        self.assertEqual(control.sha256, original_pin)

    def test_external_context_and_registry_digest_pins_reject_substitution(self):
        registry = registry_fixture()
        original_digest = D.canonical_sha256(registry)
        modified = copy.deepcopy(registry)
        modified["context"]["chain_source_sha256"] = "e" * 64
        with self.assertRaises(ValueError):
            mapped(modified, expected_sha256=original_digest)
        with self.assertRaises(ValueError):
            mapped(modified)
        with self.assertRaises(ValueError):
            mapped(registry, expected_sha256="f" * 64)

    def test_roster_digest_detects_omission_or_reassignment(self):
        registry = registry_fixture()
        for mode in ("omit", "reassign"):
            modified = copy.deepcopy(registry)
            if mode == "omit":
                modified["subjects"].pop()
            else:
                modified["subjects"][0]["controller"] = "controller-1"
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                mapped(modified)

    def test_unknown_graph_or_subject_references_reject(self):
        registry = registry_fixture()
        for mode in ("parent", "controller", "alias", "evidence"):
            modified = copy.deepcopy(registry)
            if mode == "parent":
                modified["controllers"][0]["parents"] = ["absent"]
            elif mode == "controller":
                modified["subjects"][0]["controller"] = "absent"
                seal_subjects(modified)
            elif mode == "alias":
                modified["aliases"] = [dict(left="controller-0", right="absent",
                                           evidence_sha256=registry["evidence"][0]["sha256"])]
            else:
                modified["subjects"][0]["evidence_sha256"] = "f" * 64
                seal_subjects(modified)
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                mapped(modified)
        with self.assertRaises(ValueError):
            mapped(registry).group_for("absent")

    def test_duplicate_identities_and_undeclared_fields_reject(self):
        for field in ("controllers", "subjects", "evidence"):
            registry = registry_fixture()
            registry[field].append(copy.deepcopy(registry[field][0]))
            seal_subjects(registry)
            with self.subTest(field=field), self.assertRaises(ValueError):
                mapped(registry)
        for field in ("verified_independent", "production_activation", "independent_accepted"):
            registry = registry_fixture()
            registry[field] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                mapped(registry)

    def test_wrong_types_and_noncanonical_identifiers_reject(self):
        for value in (True, False, -1, 1.5, "1800000000000"):
            registry = registry_fixture()
            registry["valid_from_unix_ms"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                mapped(registry)
        for value in ("", " subject-0", "subject-0 ", "line\nbreak"):
            registry = registry_fixture()
            registry["subjects"][0]["id"] = value
            seal_subjects(registry)
            with self.subTest(value=value), self.assertRaises(ValueError):
                mapped(registry)

    def test_duplicate_json_nonfinite_and_malformed_root_reject(self):
        for raw in (b'{"a":1,"a":2}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                D.parse_json(raw)
        for raw in ([], None, "registry", 42):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                D.ControlMap(raw, expected_sha256="f" * 64, expected_context=CONTEXT,
                             start_unix_ms=START, end_unix_ms=END)

    def test_quorum_rejects_duplicate_subjects_bad_threshold_and_unknown_subject(self):
        control = mapped(registry_fixture())
        for roster, threshold in ((["subject-0", "subject-0"], 1), (["subject-0"], 0),
                                  (["subject-0"], 2), (["subject-0"], True), (["absent"], 1)):
            with self.subTest(roster=roster, threshold=threshold), self.assertRaises(ValueError):
                control.quorum(roster, threshold)


class QuorumCoalitions(unittest.TestCase):
    def test_three_keys_can_require_one_or_two_controllers(self):
        for weights, expected in (([1, 1, 1], 2), ([2, 1], 1), ([3], 1)):
            registry = weighted_registry(weights)
            report = mapped(registry).quorum([s["id"] for s in registry["subjects"]], 2)
            with self.subTest(weights=weights):
                self.assertEqual(report["minimum_approving_groups"], expected)
                self.assertEqual(report["minimum_blocking_groups"], expected)

    def test_coefficients_match_exhaustive_coalitions_for_every_small_threshold(self):
        for weights in ([1], [1, 1], [1, 1, 1], [2, 1], [3, 1], [2, 2],
                        [4, 1, 1], [2, 3, 1], [1, 2, 1, 2], [3, 3, 2, 1]):
            registry = weighted_registry(weights)
            control = mapped(registry)
            subjects = [s["id"] for s in registry["subjects"]]
            for threshold in range(1, sum(weights) + 1):
                report = control.quorum(subjects, threshold)
                with self.subTest(weights=weights, threshold=threshold):
                    self.assertEqual(report["minimum_approving_groups"],
                                     brute_coalition(weights, threshold))
                    self.assertEqual(report["minimum_blocking_groups"],
                                     brute_coalition(weights, sum(weights) - threshold + 1))

    def test_missing_keys_preserve_frozen_threshold_and_do_not_invent_minima(self):
        registry = registry_fixture()
        control = mapped(registry)
        for subjects, slots, threshold in (([], 3, 2), (["subject-0"], 3, 2),
                                           (["subject-0", "subject-1"], 3, 2)):
            report = control.quorum(subjects, threshold, total_key_slots=slots)
            with self.subTest(subjects=subjects):
                self.assertIsNone(report["minimum_approving_groups"])
                self.assertIsNone(report["minimum_blocking_groups"])

    def test_unknown_owner_or_key_prevents_claimed_global_minimum(self):
        for field in ("controller", "key_sha256", "evidence_sha256"):
            registry = registry_fixture()
            registry["subjects"][0][field] = None
            if field == "controller":
                registry["subjects"][0]["evidence_sha256"] = None
            seal_subjects(registry)
            report = mapped(registry).quorum([s["id"] for s in registry["subjects"]], 2)
            with self.subTest(field=field):
                self.assertIsNone(report["minimum_approving_groups"])
                self.assertIsNone(report["minimum_blocking_groups"])

    def test_stale_controller_cannot_turn_partial_known_groups_into_exact_minimum(self):
        registry = weighted_registry([2, 1, 1])
        registry["evidence"][0]["valid_until_unix_ms"] = END - 1
        report = mapped(registry).quorum([s["id"] for s in registry["subjects"]], 2)
        self.assertIsNone(report["minimum_approving_groups"])
        self.assertIsNone(report["minimum_blocking_groups"])

    def test_aliases_change_actual_coalitions_even_with_unique_key_fingerprints(self):
        registry = weighted_registry([1, 1, 1, 1, 1])
        registry["aliases"] = [dict(left=f"controller-{i}", right=f"controller-{i+1}",
                                     evidence_sha256=registry["evidence"][i]["sha256"])
                               for i in range(3)]
        report = mapped(registry).quorum([s["id"] for s in registry["subjects"]], 3)
        self.assertEqual(report["minimum_approving_groups"], 1)
        self.assertEqual(report["minimum_blocking_groups"], 1)

    def test_invalid_declared_roster_size_never_rescales_threshold(self):
        control = mapped(registry_fixture())
        for slots in (True, False, 0, -1, 1.5, "3", 2):
            with self.subTest(slots=slots), self.assertRaises(ValueError):
                control.quorum(["subject-0", "subject-1", "subject-2"], 2, total_key_slots=slots)


class StrictRegistry(unittest.TestCase):
    def test_unknown_fields_are_rejected_at_each_trust_bearing_layer(self):
        for collection in ("controllers", "subjects", "evidence", "aliases"):
            registry = registry_fixture()
            if collection == "aliases":
                registry["aliases"].append(dict(left="controller-0", right="controller-1",
                                              evidence_sha256=registry["evidence"][0]["sha256"]))
            registry[collection][0]["externally_verified"] = True
            seal_subjects(registry)
            with self.subTest(collection=collection), self.assertRaises(ValueError):
                mapped(registry)
        registry = registry_fixture()
        registry["context"]["independent_accepted"] = True
        with self.assertRaises(ValueError):
            mapped(registry, expected_context=registry["context"])

    def test_context_cannot_drop_mandatory_identity_fields(self):
        for key in ("chain_source_sha256", "profile_sha256"):
            registry = registry_fixture()
            del registry["context"][key]
            with self.subTest(key=key), self.assertRaises(ValueError):
                mapped(registry, expected_context=registry["context"])

    def test_fingerprints_are_full_canonical_sha256_not_labels(self):
        for value in ("", "a" * 63, "a" * 65, "g" * 64, "A" * 64, True, 1):
            registry = registry_fixture()
            registry["subjects"][0]["key_sha256"] = value
            seal_subjects(registry)
            with self.subTest(value=value), self.assertRaises(ValueError):
                mapped(registry)

    def test_empty_registry_is_honest_unresolved_input(self):
        control = mapped(registry_fixture(0))
        report = control.quorum([], 2, total_key_slots=3)
        self.assertIsNone(report["minimum_approving_groups"])
        self.assertIsNone(report["minimum_blocking_groups"])

    def test_integer_boundaries_and_reversed_evidence_windows_reject(self):
        for field, value in (("valid_from_unix_ms", -1), ("valid_until_unix_ms", True),
                             ("valid_from_unix_ms", END + 1), ("valid_until_unix_ms", START - 1),
                             ("valid_until_unix_ms", 2 ** 64)):
            registry = registry_fixture()
            registry["evidence"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                mapped(registry)

    def test_direct_constructor_obeys_same_byte_limit_as_cli(self):
        registry = registry_fixture(0)
        evidence = add_evidence(registry, "oversize-valid-graph")
        identities = [f"control-{index:04d}-".ljust(128, "a") for index in range(600)]
        registry["controllers"] = [dict(id=identity,
            parents=[identities[(index + step) % len(identities)] for step in range(1, 61)],
            evidence_sha256=evidence) for index, identity in enumerate(identities)]
        self.assertGreater(len(json.dumps(registry, separators=(",", ":")).encode()), D.MAX_BYTES)
        with self.assertRaises(ValueError):
            mapped(registry)

    def test_duplicate_keys_after_unicode_unescaping_and_nested_json_reject(self):
        for raw in (b'{"a":0,"\\u0061":1}', b'{"outer":{"x":1,"x":2}}',
                    b'{"rows":[{"x":NaN}]}', b'{"ok":true} {"extra":true}', b'\xff'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                D.parse_json(raw)


class FiveAxisReports(unittest.TestCase):
    def test_synthetic_success_remains_hold_with_every_external_flag_false(self):
        value = audit_fixture()
        before = copy.deepcopy(value)
        report = audited(value)
        self.assertEqual(value, before)
        self.assertEqual(report["status"], "HOLD")
        self.assertEqual(set(report["axes"]),
                         {"work_production", "data_distribution", "evaluation", "authority", "resources"})
        self.assertIn("EXTERNAL_INDEPENDENCE_ACCEPTANCE_NOT_PERFORMED", finding_codes(report))
        flags = []
        def inspect(item):
            if isinstance(item, dict):
                for key, value in item.items():
                    if key.endswith(("_verified", "_accepted", "_ready", "_activation", "_authenticated")):
                        flags.append(key)
                        self.assertIs(value, False, key)
                    inspect(value)
            elif isinstance(item, list):
                for value in item:
                    inspect(value)
        inspect(report)
        self.assertGreater(len(flags), 10)
        self.assertEqual(report["axes"]["evaluation"]["key_threshold"], 2)
        self.assertEqual(report["axes"]["evaluation"]["total_key_slots"], 3)

    def test_report_source_context_cannot_change_after_return(self):
        value = audit_fixture()
        report = audited(value)
        before = copy.deepcopy(report)
        value["audit"]["context"]["chain_source_sha256"] = "f" * 64
        value["audit"]["window"]["end_unix_ms"] += 1
        self.assertEqual(report, before)

    def test_open_work_rule_does_not_substitute_for_other_access_facets(self):
        value = audit_fixture()
        facets = {row["id"]: row for row in value["audit"]["work_production"]["facets"]}
        facets["task_admission"]["status"] = "restricted"
        facets["network_service"].update(status="unknown", evidence_sha256=None)
        report = audited(value)
        codes = finding_codes(report)
        self.assertIn("TASK_ADMISSION_NOT_ESTABLISHED_OPEN", codes)
        self.assertIn("NETWORK_SERVICE_NOT_ESTABLISHED_OPEN", codes)
        self.assertEqual(report["axes"]["work_production"]["facets"]["work_rule"]["declared_status"], "open")
        self.assertIs(report["permissionless_utility_accepted"], False)

    def test_data_roles_under_common_controller_collapse_independently(self):
        value = audit_fixture()
        bind_alias(value, "operator-a", "operator-b")
        bind_alias(value, "operator-b", "operator-c")
        report = audited(value)["axes"]["data_distribution"]
        for role in ("providers", "discovery", "replicas"):
            self.assertEqual(report[role]["subject_count"], 3)
            self.assertEqual(report[role]["declared_group_count"], 1)
            self.assertIs(report[role]["independent_administration_verified"], False)

    def test_transitive_author_control_exclusion_preserves_original_threshold(self):
        value = audit_fixture()
        bind_alias(value, "author-owner", "operator-a")
        bind_alias(value, "operator-a", "operator-b")
        report = audited(value)
        evaluation = report["axes"]["evaluation"]
        self.assertEqual(evaluation["author_related_subjects"], ["eval-a", "eval-b"])
        self.assertEqual(evaluation["author_separated_candidate_key_count"], 1)
        self.assertEqual(evaluation["key_threshold"], 2)
        self.assertEqual(evaluation["total_key_slots"], 3)
        self.assertIs(evaluation["author_separated_candidate_key_threshold_met"], False)
        self.assertIn("AUTHOR_COMMON_CONTROL", finding_codes(report))

    def test_unknown_author_key_alias_retains_transitive_conflict_without_credit(self):
        value = audit_fixture()
        subjects = {row["id"]: row for row in value["registry"]["subjects"]}
        subjects["author"].update(controller=None, evidence_sha256=None,
                                  key_sha256=subjects["provider-a"]["key_sha256"])
        # Providers may be non-key endpoints; establish an explicit shared key
        # while keeping the evaluator's distinct key in the same control group.
        subjects["provider-a"]["key_sha256"] = sha("author-provider shared key")
        subjects["author"]["key_sha256"] = subjects["provider-a"]["key_sha256"]
        seal_fixture(value)
        evaluation = audited(value)["axes"]["evaluation"]
        self.assertIn("eval-a", evaluation["author_related_subjects"])
        self.assertIs(evaluation["author_control_unresolved"], True)
        self.assertEqual(evaluation["author_separated_candidate_key_count"], 0)
        self.assertIs(evaluation["author_separated_candidate_key_threshold_met"], False)

    def test_unknown_author_inventory_does_not_create_empty_conflict_free_set(self):
        value = audit_fixture()
        value["audit"]["evaluation"].update(authors=[], authors_complete=False)
        evaluation = audited(value)["axes"]["evaluation"]
        self.assertIs(evaluation["author_control_unresolved"], True)
        self.assertEqual(evaluation["author_separated_candidate_key_count"], 0)
        value["audit"]["evaluation"]["authors_complete"] = True
        with self.assertRaises(ValueError):
            audited(value)

    def test_author_inventory_requires_a_json_array_not_scalar_or_mapping(self):
        for authors in (None, True, False, 1, "author", {"author": {"ignored": True}}):
            value = audit_fixture()
            value["audit"]["evaluation"]["authors"] = authors
            with self.subTest(authors=authors), self.assertRaises(ValueError):
                audited(value)

    def test_honest_three_slot_development_declaration_without_real_keys_stays_unknown(self):
        value = audit_fixture()
        row = value["audit"]["evaluation"]
        row.update(roster=[], inventory_complete=False, authors=[], authors_complete=False)
        seal_roster(row)
        report = audited(value)["axes"]["evaluation"]
        self.assertEqual(report["total_key_slots"], 3)
        self.assertEqual(report["key_threshold"], 2)
        self.assertEqual(report["unidentified_key_slots"], 3)
        self.assertEqual(report["unresolved_control_key_slots"], 3)
        self.assertIsNone(report["minimum_approving_groups"])
        self.assertIsNone(report["minimum_blocking_groups"])

    def test_emergency_release_or_recovery_route_cannot_hide_behind_normal_multisig(self):
        for role in ("release", "recovery"):
            value = audit_fixture()
            route = copy.deepcopy(value["audit"]["authority"]["routes"][0])
            route.update(id="emergency-" + role, role=role, roster=["eval-a"], total_key_slots=1, threshold=1)
            seal_roster(route)
            value["audit"]["authority"]["routes"].append(route)
            report = audited(value)
            routes = {item["id"]: item for item in report["axes"]["authority"]["routes"]}
            with self.subTest(role=role):
                self.assertEqual(routes["root-route"]["minimum_approving_groups"], 2)
                self.assertEqual(routes[route["id"]]["minimum_approving_groups"], 1)
                self.assertEqual(routes[route["id"]]["minimum_blocking_groups"], 1)
                self.assertIn("SINGLE_DECLARED_CONTROLLER_ROUTE:" + route["id"], finding_codes(report))
                self.assertEqual(len(routes), 6)

    def test_missing_or_revoked_authority_remains_visible(self):
        value = audit_fixture()
        value["audit"]["authority"]["routes"] = [row for row in value["audit"]["authority"]["routes"]
                                                   if row["role"] != "recovery"]
        report = audited(value)
        self.assertIn("recovery", report["axes"]["authority"]["missing_roles"])
        self.assertIn("MISSING_AUTHORITY_ROLE:recovery", finding_codes(report))
        value = audit_fixture()
        route = value["audit"]["authority"]["routes"][0]
        evidence_row(value, route["evidence_sha256"])["status"] = "revoked"
        seal_fixture(value)
        report = audited(value)
        self.assertIn("AUTHORITY_ROUTE_UNRESOLVED:" + route["id"], finding_codes(report))
        self.assertEqual(len(report["axes"]["authority"]["routes"]), 5)

    def test_distinct_role_keys_cannot_hide_cross_role_control_even_when_stale(self):
        value = audit_fixture()
        route = value["audit"]["authority"]["routes"][0]
        route.update(roster=["provider-a", "provider-b", "provider-c"])
        for row in value["registry"]["subjects"]:
            if row["id"].startswith("provider-"):
                row["key_sha256"] = sha("distinct authority key:" + row["id"])
        seal_roster(route)
        controller = next(row for row in value["registry"]["controllers"] if row["id"] == "operator-a")
        evidence_row(value, controller["evidence_sha256"])["status"] = "revoked"
        seal_fixture(value)
        report = audited(value)["axes"]["authority"]
        self.assertIn("root", report["cross_role_control_groups"]["operator-a"]["roles"])
        self.assertIn("witness", report["cross_role_control_groups"]["operator-a"]["roles"])
        overlap = next(row for row in report["evaluation_authority_control_overlap"] if row["group"] == "operator-a")
        self.assertIn("eval-a", overlap["evaluation_subjects"])
        self.assertIn("root-route", overlap["authority_routes"])

    def test_unknown_funding_stays_in_original_denominator(self):
        value = audit_fixture()
        funding = value["audit"]["resources"]["funding"]
        funding["allocations"] = funding["allocations"][:2]
        funding["allocations"][0]["units"] = 40
        funding["allocations"][1]["units"] = 10
        funding.update(total_units=100, unknown_units=50)
        report = audited(value)["axes"]["resources"]["funding"]
        self.assertEqual(report["largest_declared_group_share_ppm"], 400_000)
        self.assertEqual(report["unknown_owner_share_ppm"], 500_000)
        self.assertEqual(sum(report["declared_group_share_ppm"].values()), 500_000)
        self.assertIsNone(report["known_groups_sufficient_for_majority"])
        self.assertEqual((report["total_units"], report["listed_units"]), (100, 50))

    def test_half_known_funding_is_not_majority_after_unknown_share_is_dropped(self):
        report = audited(audit_fixture())["axes"]["resources"]["funding"]
        self.assertEqual(report["largest_declared_group_share_ppm"], 500_000)
        self.assertEqual(report["known_groups_sufficient_for_majority"], 2)
        self.assertEqual(report["unknown_owner_share_ppm"], 100_000)

    def test_unattributed_or_stale_resources_remain_in_budget_as_unknown(self):
        for mode in ("unknown-owner", "stale-receipt"):
            value = audit_fixture()
            allocation = value["audit"]["resources"]["funding"]["allocations"][0]
            if mode == "unknown-owner":
                allocation["subject"] = "unknown"
            else:
                evidence_row(value, allocation["evidence_sha256"])["valid_until_unix_ms"] = value["audit"]["window"]["end_unix_ms"] - 1
            seal_fixture(value)
            report = audited(value)["axes"]["resources"]["funding"]
            with self.subTest(mode=mode):
                self.assertEqual((report["total_units"], report["listed_units"]), (1000, 900))
                self.assertEqual(report["unresolved_listed_units"], 500)
                self.assertEqual(report["unknown_owner_units"], 600)
                self.assertEqual(report["unknown_owner_share_ppm"], 600_000)
                self.assertEqual(report["largest_declared_group_share_ppm"], 300_000)

    def test_missing_denominator_and_missing_unit_never_get_invented_percentages(self):
        for mode in ("denominator", "unit"):
            value = audit_fixture()
            funding = value["audit"]["resources"]["funding"]
            if mode == "denominator":
                funding.update(total_units=None, unknown_units=None)
            else:
                funding["unit_definition_sha256"] = None
            report = audited(value)["axes"]["resources"]["funding"]
            with self.subTest(mode=mode):
                self.assertIsNone(report["declared_group_share_ppm"])
                self.assertIsNone(report["largest_declared_group_share_ppm"])
                self.assertIsNone(report["unknown_owner_share_ppm"])
                self.assertIsNone(report["known_groups_sufficient_for_majority"])
                self.assertEqual(report["listed_units"], 900)

    def test_same_controller_resource_assets_aggregate_but_hardware_keeps_own_unit(self):
        value = audit_fixture()
        bind_alias(value, "operator-a", "operator-b")
        reports = audited(value)["axes"]["resources"]
        self.assertEqual(reports["funding"]["largest_declared_group_share_ppm"], 800_000)
        self.assertEqual(reports["hardware"]["largest_declared_group_share_ppm"], 700_000)
        self.assertEqual((reports["funding"]["total_units"], reports["hardware"]["total_units"]), (1000, 10))
        self.assertNotEqual(reports["funding"]["unit"], reports["hardware"]["unit"])

    def test_duplicate_assets_receipts_and_invalid_resource_denominators_reject(self):
        for mode in ("asset", "receipt", "unknown-negative", "boolean", "overflow", "mismatch", "mixed-unit"):
            value = audit_fixture()
            funding = value["audit"]["resources"]["funding"]
            first, second = funding["allocations"][:2]
            if mode == "asset":
                second["asset_sha256"] = first["asset_sha256"]
            elif mode == "receipt":
                second["evidence_sha256"] = first["evidence_sha256"]
            elif mode == "unknown-negative":
                funding["unknown_units"] = -1
            elif mode == "boolean":
                first["units"] = True
            elif mode == "overflow":
                first["units"] = 2 ** 64 - 1
            elif mode == "mismatch":
                funding["total_units"] += 1
            else:
                first["unit"] = "different-unit"
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                audited(value)

    def test_frozen_roster_authority_inventory_and_policy_commitments_reject_substitution(self):
        for mode in ("evaluation-roster", "authority-roster", "duplicate-route", "policy"):
            value = audit_fixture()
            if mode == "evaluation-roster":
                value["audit"]["evaluation"]["roster"].pop()
            elif mode == "authority-roster":
                value["audit"]["authority"]["routes"][0]["roster"].pop()
            elif mode == "duplicate-route":
                value["audit"]["authority"]["routes"].append(copy.deepcopy(value["audit"]["authority"]["routes"][0]))
            else:
                value["audit"]["policy_sha256"] = "f" * 64
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                audited(value)

    def test_callers_cannot_promote_external_acceptance_with_extra_fields(self):
        for field in ("independent_administration_verified", "permissionless_utility_accepted",
                      "public_network_ready", "production_activation"):
            value = audit_fixture()
            value["audit"][field] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                audited(value)


class CommandLine(unittest.TestCase):
    def invoke(self, *args):
        return subprocess.run([sys.executable, str(Path(D.__file__).resolve()), *map(str, args)],
                              capture_output=True, text=True, timeout=15)

    def test_valid_cli_report_is_bound_and_hold(self):
        value = audit_fixture()
        with tempfile.TemporaryDirectory(prefix="control-audit-") as directory:
            path = Path(directory) / "input.json"
            raw = json.dumps(value).encode()
            path.write_bytes(raw)
            result = self.invoke("--input", path)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report, audited(value))
            self.assertEqual(report["status"], "HOLD")
            self.assertEqual(path.read_bytes(), raw)
            output = Path(directory) / "report.json"
            result = self.invoke("--input", path, "--output", output)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(output.read_text()), report)
            self.assertEqual(result.stdout, "")

    def test_existing_output_and_input_evidence_are_never_overwritten(self):
        with tempfile.TemporaryDirectory(prefix="control-audit-") as directory:
            path = Path(directory) / "input.json"
            path.write_text(json.dumps(audit_fixture()))
            output = Path(directory) / "prior-evidence.json"
            output.write_text("original failed observation\n")
            link = Path(directory) / "output-link.json"
            link.symlink_to(output)
            for target in (output, link, path):
                before = target.read_bytes()
                result = self.invoke("--input", path, "--output", target)
                with self.subTest(target=target.name):
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(target.read_bytes(), before)

    def test_cli_rejects_duplicate_json_nonfinite_bad_policy_and_oversize(self):
        value = audit_fixture()
        invalid_policy = copy.deepcopy(value)
        invalid_policy["audit"]["policy_sha256"] = "0" * 64
        cases = (b'{"registry":null,"registry":null,"audit":null}',
                 b'{"registry":NaN,"audit":null}', json.dumps(invalid_policy).encode(),
                 b" " * (D.MAX_BYTES + 1) + b"{}")
        with tempfile.TemporaryDirectory(prefix="control-audit-") as directory:
            path = Path(directory) / "input.json"
            output = Path(directory) / "report.json"
            for raw in cases:
                path.write_bytes(raw)
                result = self.invoke("--input", path, "--output", output)
                with self.subTest(size=len(raw)):
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, "")
                    self.assertFalse(output.exists())
                    self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
