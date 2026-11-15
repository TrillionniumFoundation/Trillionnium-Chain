"""Defensive contract checks for migration material review, not migration tests.

The artifact contents below are explicitly synthetic and are not signatures,
proofs, independent anchor receipts or real provider outcomes. Passing their
byte checks must never produce an authority or security qualification claim.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pq_root_migration_review_v1 as review


ROOT = Path(__file__).resolve().parents[2]


def identity(number, size=128):
    return format(number, "0" + str(size) + "x")


def families(suites):
    return [{"suite": suite, "quorum": 2, "roster_size": 3, "possession_required": 3}
            for suite in suites]


def key_rows(start, role, generation, suites):
    return [{"key_id": identity(start + index), "role": role,
             "generation": str(generation), "suite": suite}
            for index, suite in enumerate(suites * 3)]


def rebind(data):
    proposal = data["proposal"]
    transition = proposal["transition"]
    transition["current_profile_sha512"] = review.digest(proposal["current_profile"])
    transition["successor_profile_sha512"] = review.digest(proposal["successor_profile"])
    transition["scope_sha512"] = review.digest(proposal["scope"])
    binding = review.digest({key: value for key, value in proposal.items() if key != "evidence"})
    for row in proposal["evidence"].values():
        row["proposal_sha512"] = binding


def fixture():
    before = {"id": "root-native-v3", "source_revision": identity(1, 40),
              "policy_commitment": identity(2), "roster_commitment": identity(3),
              "generation": "7", "combiner": "AND", "families": families(review.CURRENT_SUITES),
              "primitive_ids": sorted(review.PRIMITIVES)}
    after = {"id": "synthetic-unimplemented-successor", "source_revision": identity(4, 40),
             "policy_commitment": identity(5), "roster_commitment": identity(6),
             "generation": "8", "combiner": "AND",
             "families": families(["Example-Family-A", "Example-Family-B"]),
             "primitive_ids": ["Example/Unimplemented-Hash"]}
    state = {"lifetime_id": identity(30),
             "key_epochs": key_rows(100, "root-approval", 7, review.CURRENT_SUITES)
                           + key_rows(200, "anchor-writer", 7, review.CURRENT_SUITES)
                           + key_rows(300, "anchor-response", 7, review.CURRENT_SUITES)
                           + key_rows(400, "effect-provider", 7, review.CURRENT_SUITES),
             "consumed_nonces": [identity(500, 64)], "revoked_keys": [identity(501)],
             "retained_effects": [{"operation_id": identity(600), "intent_sha512": identity(601),
                                    "owner_id": identity(602), "orphan_epoch": "3",
                                    "outcome": "unknown", "liability_sha512": identity(603)}],
             "primitives": [{"public_parameter_id": name, "prior_scope_id": identity(700 + i),
                              "observed_queries": "17", "adversary_query_bound": None,
                              "initial_advice_bound": None, "coverage": review.QUERY_COVERAGE.copy()}
                             for i, name in enumerate(sorted(review.PRIMITIVES))]}
    successor = deepcopy(state)
    successor["key_epochs"] += key_rows(800, "root-approval", 8,
                                        ["Example-Family-A", "Example-Family-B"])
    successor["key_epochs"] += key_rows(800, "successor-possession", 8,
                                        ["Example-Family-A", "Example-Family-B"])
    successor["consumed_nonces"].append(identity(900, 64))
    successor["primitives"].append({"public_parameter_id": "Example/Unimplemented-Hash",
                                    "prior_scope_id": identity(750), "observed_queries": "1",
                                    "adversary_query_bound": None, "initial_advice_bound": None,
                                    "coverage": review.QUERY_COVERAGE.copy()})
    materials = {kind: ("SYNTHETIC UNVERIFIED MATERIAL: " + kind + "\n").encode()
                 for kind in review.EVIDENCE_KINDS}
    proposal = {
        "scope": {"network": identity(10, 64), "genesis": identity(11, 64), "owner": identity(12, 64)},
        "current_profile": before, "successor_profile": after,
        "transition": {"operation_id": identity(20), "predecessor_head": identity(21),
                       "next_head": identity(22), "before_sequence": "8", "after_sequence": "9",
                       "nonce": identity(900, 64),
                       "statement_sha512": hashlib.sha512(materials["transition-statement"]).hexdigest(),
                       "current_profile_sha512": identity(23), "successor_profile_sha512": identity(24),
                       "scope_sha512": identity(25)},
        "continuity": {"lifetime_id": identity(30), "before": state, "after": successor},
        "evidence": {kind: {"schema": review.EVIDENCE_SCHEMA, "kind": kind,
                            "proposal_sha512": identity(40),
                            "material": {"path": "material/" + kind + ".bin",
                                         "sha512": hashlib.sha512(content).hexdigest(),
                                         "bytes": str(len(content))}}
                     for kind, content in materials.items()},
    }
    data = {"schema": review.SCHEMA, "purpose": "read-only-migration-review", "proposal": proposal}
    rebind(data)
    return data, materials


class ReviewAssertions:
    def setUp(self):
        self.data, self.materials = fixture()

    def refused(self, mutate, expected=None, bind=True):
        data = deepcopy(self.data)
        mutate(data["proposal"])
        if bind:
            rebind(data)
        context = self.assertRaisesRegex(review.MigrationReviewError, expected) if expected else (
            self.assertRaises(review.MigrationReviewError))
        with context:
            review.evaluate(data)

    def unqualified(self, result):
        self.assertEqual(result["status"], "HOLD")
        self.assertIsNone(result["actual_lifetime_failure_bound"])
        for name in ("migration_authorized", "migration_implementation_verified",
                     "cryptographic_verification_performed", "theorem_applicability_verified",
                     "independent_custody_verified", "anchor_independence_verified",
                     "actual_external_effects_verified", "whole_chain_pq_qualified",
                     "composition_coverage_proved", "production_activation",
                     "complete_key_epoch_population_verified", "observed_query_counts_bound_adversary"):
            self.assertIs(result[name], False, name)


class ContractTests(ReviewAssertions, unittest.TestCase):
    def test_no_proposal_stays_hold_and_lists_missing_implementation(self):
        result = review.inspect(ROOT)
        self.assertIs(result["proposal_present"], False)
        self.assertIs(result["review_material_complete"], False)
        self.assertIn("explicit-versioned-migration-implementation", result["open_obligations"])
        self.unqualified(result)

    def test_structural_review_is_not_material_readback_or_authorization(self):
        result = review.evaluate(self.data)
        self.assertIs(result["declared_continuity_checked"], True)
        self.assertIs(result["material_bytes_checked"], False)
        self.assertIs(result["review_material_complete"], False)
        self.assertEqual(result["declared_inventory"]["retained_key_epoch_records"], 36)
        self.assertEqual(len(result["declared_inventory"]["shared_primitive_ids"]), 5)
        self.unqualified(result)

    def test_current_profile_requires_both_exact_existing_families(self):
        self.refused(lambda p: p["current_profile"]["families"][0].update(suite="ML-DSA-65"))
        self.refused(lambda p: p["current_profile"].update(combiner="OR"))
        self.refused(lambda p: p["current_profile"]["families"].pop())

    def test_target_cannot_rename_quorum_weakening_as_agility(self):
        for field, value in (("quorum", 1), ("roster_size", 2), ("possession_required", 2),
                             ("quorum", True), ("roster_size", "3")):
            with self.subTest(field=field, value=value):
                self.refused(lambda p: p["successor_profile"]["families"][0].update({field: value}))
        self.refused(lambda p: p["successor_profile"].update(combiner="OR"))

    def test_a_profile_name_does_not_replace_a_new_implementation(self):
        for field in ("id", "source_revision", "policy_commitment", "roster_commitment"):
            self.refused(lambda p: p["successor_profile"].update({field: p["current_profile"][field]}))

    def test_generation_and_sequence_must_advance_exactly_once(self):
        for number in ("0", "7", "9", "18446744073709551616", 8, True):
            self.refused(lambda p: p["successor_profile"].update(generation=number))
        for number in ("8", "10", "09", 9, False):
            self.refused(lambda p: p["transition"].update(after_sequence=number))

    def test_head_and_nonce_must_advance_and_be_retained(self):
        self.refused(lambda p: p["transition"].update(next_head=p["transition"]["predecessor_head"]))
        self.refused(lambda p: p["transition"].update(nonce=identity(500, 64)), "nonce")
        self.refused(lambda p: p["continuity"]["after"]["consumed_nonces"].remove(identity(900, 64)), "nonce")

    def test_changed_scope_profile_or_operation_does_not_reuse_old_evidence(self):
        for mutator in (
                lambda p: p["scope"].update(network=identity(99, 64)),
                lambda p: p["current_profile"].update(policy_commitment=identity(99)),
                lambda p: p["transition"].update(operation_id=identity(99))):
            self.refused(mutator, bind=False)

    def test_all_required_material_kinds_are_mandatory(self):
        for kind in review.EVIDENCE_KINDS:
            self.refused(lambda p: p["evidence"].pop(kind), "evidence")

    def test_material_is_not_a_boolean_or_declaration_of_approval(self):
        for value in (True, "verified", {"verified": True}, None):
            self.refused(lambda p: p["evidence"]["current-authority-envelope"].update(material=value))
        self.refused(lambda p: p["evidence"]["successor-possession-material"].update(verified=True))

    def test_material_binding_is_specific_to_the_full_proposal(self):
        self.data["proposal"]["evidence"]["fresh-anchor"]["proposal_sha512"] = identity(99)
        with self.assertRaisesRegex(review.MigrationReviewError, "same migration"):
            review.evaluate(self.data)

    def test_lifetime_identity_is_shared_before_and_after(self):
        for side in ("before", "after"):
            self.refused(lambda p: p["continuity"][side].update(lifetime_id=identity(99)), "lifetime")

    def test_prior_key_epoch_history_cannot_disappear_or_be_rewritten(self):
        self.refused(lambda p: p["continuity"]["after"]["key_epochs"].pop(6), "key/epoch history")
        self.refused(lambda p: p["continuity"]["after"]["key_epochs"][6].update(suite="changed"),
                     "key/epoch history")

    def test_current_and_successor_populations_require_six_distinct_keys(self):
        for side in ("before", "after"):
            self.refused(lambda p: p["continuity"][side]["key_epochs"].pop(-1 if side == "after" else 0))
        self.refused(lambda p: p["continuity"]["after"]["key_epochs"][-1].update(
            key_id=p["continuity"]["after"]["key_epochs"][-2]["key_id"]))

    def test_key_epoch_aliases_and_future_records_refuse(self):
        self.refused(lambda p: p["continuity"]["before"]["key_epochs"].append(
            deepcopy(p["continuity"]["before"]["key_epochs"][0])), "duplicate")
        self.refused(lambda p: p["continuity"]["after"]["key_epochs"][-1].update(generation="9"), "future")
        self.refused(lambda p: p["continuity"]["after"]["key_epochs"][-1].update(role="unknown-role"))
        self.refused(lambda p: p["continuity"]["after"]["key_epochs"][-1].update(role=[]))

    def test_key_identity_has_one_suite_across_roles_and_generations(self):
        self.refused(lambda p: p["continuity"]["after"]["key_epochs"][-1].update(suite="Example-Family-A"),
                     "conflicting suite labels")
        self.refused(lambda p: p["continuity"]["after"]["key_epochs"].append(
            {"key_id": identity(100), "role": "root-approval", "generation": "6", "suite": "different"}),
                     "conflicting suite labels")

    def test_all_six_successor_possession_identities_are_required(self):
        self.refused(lambda p: p["continuity"]["after"]["key_epochs"].pop(), "possession declarations")
        self.refused(lambda p: p["continuity"]["after"]["key_epochs"][-1].update(key_id=identity(999)),
                     "possession declarations")

    def test_partial_historical_role_cohorts_never_establish_population_completeness(self):
        for side in ("before", "after"):
            self.data["proposal"]["continuity"][side]["key_epochs"] = [
                row for row in self.data["proposal"]["continuity"][side]["key_epochs"]
                if row["role"] != "effect-provider"]
        rebind(self.data)
        result = review.evaluate(self.data)
        self.assertNotIn("effect-provider", result["declared_inventory"]["roles_with_submitted_records"])
        self.assertEqual(result["declared_inventory"]["scope"], "submitted-records-only-completeness-unverified")
        self.unqualified(result)

    def test_revoked_and_isolated_role_keys_cannot_be_successors(self):
        self.refused(lambda p: p["continuity"]["after"]["key_epochs"][-7].update(key_id=identity(501)), "revoked")
        self.refused(lambda p: p["continuity"]["after"]["key_epochs"][-7].update(
            key_id=identity(200), suite=review.CURRENT_SUITES[0]), "isolated")

    def test_nonce_and_revocation_history_cannot_shrink(self):
        self.refused(lambda p: p["continuity"]["after"]["consumed_nonces"].pop(0), "consumed nonces")
        self.refused(lambda p: p["continuity"]["after"]["revoked_keys"].clear(), "revoked keys")

    def test_retained_effect_unknown_and_orphan_liability_cannot_be_rewritten(self):
        self.refused(lambda p: p["continuity"]["after"]["retained_effects"].clear(), "effect or orphan liability")
        for field, value in (("outcome", "succeeded"), ("orphan_epoch", "0"),
                             ("intent_sha512", identity(99)), ("owner_id", identity(99)),
                             ("liability_sha512", identity(99))):
            self.refused(lambda p: p["continuity"]["after"]["retained_effects"][0].update({field: value}),
                         "effect or orphan liability")

    def test_effect_duplicate_does_not_count_as_two_independent_outcomes(self):
        self.refused(lambda p: p["continuity"]["after"]["retained_effects"].append(
            deepcopy(p["continuity"]["after"]["retained_effects"][0])), "duplicate")

    def test_removed_algorithm_does_not_remove_its_primitive_history(self):
        self.refused(lambda p: p["continuity"]["after"]["primitives"].pop(0), "primitive union")
        self.refused(lambda p: p["current_profile"]["primitive_ids"].pop(0), "primitive scope")

    def test_shared_primitive_scopes_never_split_or_reset(self):
        self.refused(lambda p: p["continuity"]["after"]["primitives"].append(
            deepcopy(p["continuity"]["after"]["primitives"][0])), "duplicate scopes")
        self.refused(lambda p: p["continuity"]["after"]["primitives"][0].update(prior_scope_id=identity(99)), "reset")
        self.refused(lambda p: p["continuity"]["after"]["primitives"][0].update(observed_queries="16"), "decreased")

    def test_observations_and_new_generation_do_not_turn_unknown_bounds_into_zero(self):
        for side in ("before", "after"):
            for field in ("adversary_query_bound", "initial_advice_bound"):
                for value in ("0", 0, False, "1000"):
                    self.refused(lambda p: p["continuity"][side]["primitives"][0].update({field: value}),
                                 "cannot supply")

    def test_cancelled_failed_offline_and_retired_work_remain_in_scope(self):
        for channel in review.QUERY_COVERAGE:
            self.refused(lambda p: p["continuity"]["after"]["primitives"][0]["coverage"].remove(channel),
                         "query coverage")

    def test_success_flags_and_unbounded_fields_are_not_input_authority(self):
        for field, value in (("migration_authorized", True), ("actual_lifetime_failure_bound", "0"),
                             ("whole_chain_pq_qualified", True), ("production_activation", True)):
            data = deepcopy(self.data)
            data[field] = value
            with self.assertRaises(review.MigrationReviewError):
                review.evaluate(data)
        self.refused(lambda p: p["transition"].update(operation_id="0" * 128))
        self.refused(lambda p: p["continuity"]["after"]["key_epochs"].extend(
            [deepcopy(p["continuity"]["after"]["key_epochs"][0])] * review.MAX_ITEMS))


class MaterialTests(ReviewAssertions, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.temp = tempfile.TemporaryDirectory(prefix="trnm-migration-review-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.manifest = "proposal.json"
        for kind, content in self.materials.items():
            path = self.root / self.data["proposal"]["evidence"][kind]["material"]["path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        self.write()

    def write(self):
        (self.root / self.manifest).write_text(json.dumps(self.data), encoding="utf-8")

    def check(self):
        return review.inspect(self.root, self.manifest)

    def test_checked_synthetic_material_still_cannot_authorize_migration(self):
        result = self.check()
        self.assertIs(result["review_material_complete"], True)
        self.assertIs(result["material_bytes_checked"], True)
        self.assertEqual(result["material_scope"], "bound-input-bytes-only-not-authenticated-evidence")
        self.unqualified(result)

    def test_missing_changed_and_empty_actual_material_refuse(self):
        path = self.root / self.data["proposal"]["evidence"]["current-authority-envelope"]["material"]["path"]
        path.unlink()
        with self.assertRaisesRegex(review.MigrationReviewError, "missing source"):
            self.check()
        path.write_bytes(b"x" * len(self.materials["current-authority-envelope"]))
        with self.assertRaisesRegex(review.MigrationReviewError, "material bytes differ"):
            self.check()
        path.write_bytes(b"")
        with self.assertRaisesRegex(review.MigrationReviewError, "material length differs"):
            self.check()

    def test_statement_commitment_is_checked_against_actual_statement_bytes(self):
        self.data["proposal"]["transition"]["statement_sha512"] = identity(99)
        rebind(self.data)
        self.write()
        with self.assertRaisesRegex(review.MigrationReviewError, "actual statement bytes"):
            self.check()

    def test_symlinked_material_and_manifest_refuse(self):
        path = self.root / self.data["proposal"]["evidence"]["fresh-anchor"]["material"]["path"]
        original = path.with_suffix(".saved")
        path.rename(original)
        path.symlink_to(original)
        with self.assertRaisesRegex(review.MigrationReviewError, "symlink"):
            self.check()
        path.unlink()
        original.rename(path)
        manifest = self.root / self.manifest
        saved = self.root / "saved.json"
        manifest.rename(saved)
        manifest.symlink_to(saved)
        with self.assertRaisesRegex(review.MigrationReviewError, "symlink"):
            self.check()

    def test_unsafe_paths_duplicate_json_and_promotion_refuse(self):
        self.data["proposal"]["evidence"]["fresh-anchor"]["material"]["path"] = "../outside"
        self.write()
        with self.assertRaisesRegex(review.MigrationReviewError, "unsafe source path"):
            self.check()
        for raw in (b'{"schema":"x","schema":"y"}', b'{"x":NaN}', b'{"x":0.0}',
                    b'{"x":"\\ud800"}', b"[]", b"\xff"):
            (self.root / self.manifest).write_bytes(raw)
            with self.assertRaises(review.MigrationReviewError):
                self.check()

    def test_cli_retains_hold_and_returns_structured_refusal(self):
        command = [sys.executable, str(Path(review.__file__).resolve()), "--root", str(self.root),
                   "--manifest", self.manifest]
        result = subprocess.run(command, capture_output=True, text=True, timeout=15, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.unqualified(json.loads(result.stdout))
        del self.data["proposal"]["evidence"]["new-profile-security-reduction"]
        self.write()
        result = subprocess.run(command, capture_output=True, text=True, timeout=15, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(json.loads(result.stderr)["status"], "REFUSE")


if __name__ == "__main__":
    unittest.main()
