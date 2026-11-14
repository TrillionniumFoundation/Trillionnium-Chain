"""Probability semantics and source-contract checks for the V2 review bridge.

All numeric probabilities below belong to explicitly invented finite sample
spaces. They are not measurements or security estimates for Trillionnium.
Source checks use copied declared files and never change the working source.
"""
from copy import deepcopy
from fractions import Fraction
import hashlib
import itertools
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pq_lifetime_composition as composition


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = composition.DEFAULT_MANIFEST
LEGACY = composition.legacy.DEFAULT_MANIFEST
SOURCE_LOCK = composition.legacy.DEFAULT_SOURCE_LOCK
ROOT_REGISTER = composition.root_register.DEFAULT_MANIFEST
TARGET = Fraction(1, 1 << 128)


def ratio(value):
    value = Fraction(value)
    return {"numerator": str(value.numerator), "denominator": str(value.denominator)}


def decode(value):
    if value is None:
        return None
    return Fraction(int(value["numerator"]), int(value["denominator"]))


def declare(data, name, value):
    """Declare a synthetic marginal or loss, never a verified project bound."""
    data["inputs"][name].update({
        "status": "declared-model-bound", "bound": ratio(value),
        "theorem": {
            "reference": "Synthetic finite probability space; no project theorem",
            "locator": "Test fixture only",
            "applicability": "Assume this value bounds the named event or loss in the declared common game; project applicability is unproved.",
        },
    })


def numeric_example(**values):
    data = composition.default_arithmetic()
    data["purpose"] = "arithmetic-example"
    for name in composition.LEAVES:
        declare(data, name, values.get(name, 0))
    return data


def load(path):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


class ContractCase(unittest.TestCase):
    def remains_unqualified(self, report):
        self.assertEqual(report["status"], "HOLD")
        self.assertIsNone(report["actual_lifetime_failure_bound"])
        self.assertIs(report["whole_chain_pq_qualified"], False)
        self.assertIs(report["production_activation"], False)
        for key in ("project_event_relation_proved", "theorems_applicable_to_common_experiment",
                    "composition_coverage_proved", "theorem_applicability_verified",
                    "whole_chain_hash_query_scope_closed", "joint_bound_derived"):
            if key in report:
                self.assertIs(report[key], False, key)

    def arithmetic_refused(self, data):
        with self.assertRaises((composition.CompositionError, composition.legacy.BudgetError)):
            composition.review_arithmetic(data)


class ProbabilitySemanticsTests(ContractCase):
    def test_all_events_in_a_weighted_finite_space_satisfy_root_union_intersection_bound(self):
        # Four atoms with unequal masses. Exhaust all 16^3 choices of C, M, S;
        # correlations are unrestricted and no product probability is assumed.
        weights = (Fraction(1, 2), Fraction(1, 4), Fraction(1, 8), Fraction(1, 8))
        subsets = [frozenset(i for i in range(4) if mask & (1 << i)) for mask in range(16)]

        def mass(event):
            return sum((weights[i] for i in event), Fraction())

        for common, ml, slh in itertools.product(subsets, repeat=3):
            data = numeric_example(common_failure=mass(common), ml_event=mass(ml),
                                   slh_event=mass(slh))
            report = composition.review_arithmetic(data)
            actual = mass(common | (ml & slh))
            self.assertLessEqual(actual, decode(report["conditional_root_declared_bound"]))
        self.remains_unqualified(report)

    def test_perfectly_correlated_family_failures_do_not_multiply(self):
        # M = S = {0} in a uniform 16-atom space, hence P(M intersect S)=1/16.
        event = {0}
        actual = Fraction(len(event & event), 16)
        report = composition.review_arithmetic(numeric_example(ml_event=actual, slh_event=actual))
        self.assertEqual(decode(report["conditional_root_declared_bound"]), actual)
        self.assertGreater(actual, actual * actual)
        self.remains_unqualified(report)

    def test_family_losses_cannot_be_chosen_separately_from_event_bounds(self):
        # Both complete failure sets are {0,...,64}; their internal partitions
        # differ. Choosing min(event) and min(loss) selects incompatible pieces.
        ml_event, ml_loss = set(range(64)), {64}
        slh_event, slh_loss = {0}, set(range(1, 65))
        actual = Fraction(len((ml_event | ml_loss) & (slh_event | slh_loss)), 4096)
        data = numeric_example(ml_event=Fraction(len(ml_event), 4096),
                               ml_loss=Fraction(len(ml_loss), 4096),
                               slh_event=Fraction(len(slh_event), 4096),
                               slh_loss=Fraction(len(slh_loss), 4096))
        report = composition.review_arithmetic(data)
        self.assertEqual(decode(report["cryptographic_intersection_subtotal"]), actual)
        self.assertEqual(actual, Fraction(65, 4096))
        invalid_separate_minima = Fraction(2, 4096)
        self.assertGreater(actual, invalid_separate_minima)
        self.remains_unqualified(report)

    def test_common_failure_and_shared_loss_remain_additive(self):
        report = composition.review_arithmetic(numeric_example(
            common_failure=Fraction(1, 32), shared_game_loss=Fraction(1, 64),
            ml_event=Fraction(1, 8), ml_loss=Fraction(1, 128),
            slh_event=Fraction(1, 16), slh_loss=Fraction(1, 256)))
        self.assertEqual(decode(report["conditional_root_declared_bound"]), Fraction(29, 256))
        self.remains_unqualified(report)

    def test_positive_loss_at_an_exact_target_is_not_rounded_away(self):
        tiny_loss = Fraction(1, 1 << 512)
        report = composition.review_arithmetic(numeric_example(
            ml_event=TARGET, slh_event=TARGET, shared_game_loss=tiny_loss))
        actual_sum = decode(report["conditional_root_declared_bound"])
        self.assertEqual(actual_sum, TARGET + tiny_loss)
        self.assertGreater(actual_sum, TARGET)
        self.remains_unqualified(report)

    def test_probability_cap_preserves_the_uncapped_sum(self):
        report = composition.review_arithmetic(numeric_example(
            common_failure=1, shared_game_loss=1,
            ml_event=1, ml_loss=1, slh_event=1, slh_loss=1))
        self.assertEqual(decode(report["uncapped_declared_sum"]), 4)
        self.assertEqual(decode(report["conditional_root_declared_bound"]), 1)
        self.remains_unqualified(report)

    def test_unknown_required_common_failure_or_shared_loss_does_not_disappear(self):
        for name in ("common_failure", "shared_game_loss"):
            with self.subTest(name=name):
                data = numeric_example(ml_event=Fraction(1, 128), slh_event=Fraction(1, 256))
                data["inputs"][name] = composition.unknown_leaf(name)
                report = composition.review_arithmetic(data)
                self.assertEqual(decode(report["cryptographic_intersection_subtotal"]), Fraction(1, 256))
                self.assertIsNone(report["uncapped_declared_sum"])
                self.assertIsNone(report["conditional_root_declared_bound"])
                self.assertIn(name, report["unknown_inputs"])
                self.remains_unqualified(report)

    def test_partial_family_without_its_loss_is_not_a_complete_bound(self):
        data = numeric_example(ml_event=Fraction(1, 128), slh_event=Fraction(1, 256))
        for name in ("ml_loss", "slh_loss"):
            data["inputs"][name] = composition.unknown_leaf(name)
        report = composition.review_arithmetic(data)
        self.assertIsNone(report["cryptographic_intersection_subtotal"])
        self.assertIsNone(report["conditional_root_declared_bound"])
        self.assertTrue(all(value is None for value in report["family_complete_declared_bounds"].values()))
        self.remains_unqualified(report)

    def test_one_complete_declared_family_bound_is_usable_but_never_qualified(self):
        data = composition.default_arithmetic()
        data["purpose"] = "arithmetic-example"
        for name, value in (("common_failure", 0), ("shared_game_loss", 0),
                            ("ml_event", Fraction(1, 64)), ("ml_loss", Fraction(1, 256))):
            declare(data, name, value)
        report = composition.review_arithmetic(data)
        self.assertEqual(decode(report["conditional_root_declared_bound"]), Fraction(5, 256))
        self.assertIsNone(report["family_complete_declared_bounds"]["SLH-DSA-SHA2-256s"])
        self.assertEqual(set(report["unknown_inputs"]), {"slh_event", "slh_loss"})
        self.remains_unqualified(report)

    def test_zero_marginal_with_an_unknown_reduction_loss_is_not_a_zero_bound(self):
        data = composition.default_arithmetic()
        for name in ("common_failure", "shared_game_loss", "ml_event"):
            declare(data, name, 0)
        report = composition.review_arithmetic(data)
        self.assertIsNone(report["conditional_root_declared_bound"])
        declare(data, "ml_loss", 0)
        report = composition.review_arithmetic(data)
        self.assertEqual(decode(report["conditional_root_declared_bound"]), 0)
        self.remains_unqualified(report)


class ArithmeticContractTests(ContractCase):
    def test_default_unknown_contract_keeps_every_leaf_unknown(self):
        report = composition.review_arithmetic(composition.default_arithmetic())
        self.assertEqual(set(report["unknown_inputs"]), set(composition.LEAVES))
        self.assertIsNone(report["conditional_root_declared_bound"])
        self.remains_unqualified(report)

    def test_cross_experiment_game_model_scope_and_profile_inputs_are_refused(self):
        for key, value in (("experiment_id", "different-experiment"),
                           ("game_id", "fresh-instance-game"),
                           ("model", "classical-ROM"),
                           ("scope", "single-key-per-invocation"),
                           ("profile", "SLH-DSA-SHAKE-256s"),
                           ("resource_instance_id", "slh")):
            with self.subTest(key=key):
                data = numeric_example(ml_event=Fraction(1, 64))
                data["inputs"]["ml_event"][key] = value
                self.arithmetic_refused(data)

    def test_schema_unknown_fields_and_self_verified_claims_are_refused(self):
        mutations = (
            lambda d: d.update(schema="another-schema"),
            lambda d: d.update(independent=True),
            lambda d: d.update(verified=True),
            lambda d: d["inputs"]["ml_event"].update(verified=True),
            lambda d: d["inputs"]["ml_event"].update(status="proved"),
            lambda d: d["inputs"]["ml_event"]["theorem"].update(verified=True),
        )
        for mutate in mutations:
            data = numeric_example()
            mutate(data)
            self.arithmetic_refused(data)

    def test_product_combiner_and_independence_assertion_cannot_enable_multiplication(self):
        for value in ("product", "independent-product", "union"):
            with self.subTest(value=value):
                data = numeric_example()
                data["combiner"] = value
                self.arithmetic_refused(data)
        data = numeric_example()
        data["family_population"]["independent"] = True
        self.arithmetic_refused(data)

    def test_threshold_successor_possession_and_population_scope_are_fixed(self):
        changes = (
            ("root-approval", "required", 1),
            ("successor-possession", "required", 2),
            ("anchor-writer", "roster_size", 4),
            ("effect-provider", "required", 2.0),
        )
        for role, key, value in changes:
            with self.subTest(role=role, key=key):
                data = numeric_example()
                data["family_population"]["required_by_role"][role][key] = value
                self.arithmetic_refused(data)
        data = numeric_example()
        data["family_population"]["scope"] = "current-key-only"
        self.arithmetic_refused(data)

    def test_missing_common_or_loss_input_is_refused_instead_of_defaulted_to_zero(self):
        for name in composition.LEAVES:
            with self.subTest(name=name):
                data = numeric_example()
                del data["inputs"][name]
                self.arithmetic_refused(data)

    def test_unknown_status_cannot_carry_a_number_or_theorem(self):
        for key, value in (("bound", ratio(0)), ("theorem", {"reference": "invented"})):
            data = composition.default_arithmetic()
            data["inputs"]["common_failure"][key] = value
            self.arithmetic_refused(data)

    def test_declared_bounds_require_a_complete_theorem_declaration_and_probability(self):
        bad_bounds = (None, {"numerator": "-1", "denominator": "1"},
                      {"numerator": "2", "denominator": "1"},
                      {"numerator": "1", "denominator": "0"},
                      {"numerator": 1, "denominator": "16"})
        for bound in bad_bounds:
            data = numeric_example()
            data["inputs"]["ml_event"]["bound"] = bound
            self.arithmetic_refused(data)
        data = numeric_example()
        del data["inputs"]["ml_event"]["theorem"]["applicability"]
        self.arithmetic_refused(data)


class InventoryContractTests(ContractCase):
    def test_checked_in_manifest_matches_the_frozen_contract(self):
        data = load(MANIFEST)
        self.assertEqual(data, composition.default_manifest())
        self.remains_unqualified(composition.validate_manifest(data))

    def test_superseded_child_manifest_identities_are_refused(self):
        previous = {
            "legacy": {
                "sha256": "87108ad195c79d17eebbc0f34e320f7141763b507487cc82a3f62d5945fb9b23",
                "declared_revision": "12e510b211110d93d9ead07e02c07a1eecc28ae9",
            },
            "root": {
                "sha256": "eedc1db827d97aab0be4c43e58713a2e2f2a3d0331e045a509f0941557834028",
                "declared_revision": "57e6c17ae2fa8a9cc547e271f34d90ef09115f04",
            },
        }
        for name, fields in previous.items():
            for field, value in fields.items():
                with self.subTest(name=name, field=field):
                    data = load(MANIFEST)
                    self.assertNotEqual(data["input_manifests"][name][field], value)
                    data["input_manifests"][name][field] = value
                    with self.assertRaises(composition.CompositionError):
                        composition.validate_manifest(data)

        # The pre-typed-error root input remains a refused historical identity.
        for field, value in (
            ("sha256", "a94b3e01c8a78a796496182dc268fe23b6fe844e27edec7553876c735ce37cc8"),
            ("declared_revision", "b683714cdd5ba241c16c335a81aebc12c1581902"),
        ):
            with self.subTest(root_continuation_field=field):
                data = load(MANIFEST)
                self.assertNotEqual(data["input_manifests"]["root"][field], value)
                data["input_manifests"]["root"][field] = value
                with self.assertRaises(composition.CompositionError):
                    composition.validate_manifest(data)

    def test_pre_client_timing_legacy_identity_remains_refused(self):
        for field, value in (
            ("sha256", "3ed0e9d451ff885fb27a4a6f7449ca9050eb44707d801a3a40d675fcf5ceaed4"),
            ("declared_revision", "2bb56596e637908c44b5a2ef5984c9c37c7d3cc8"),
        ):
            with self.subTest(legacy_continuation_field=field):
                data = load(MANIFEST)
                self.assertNotEqual(data["input_manifests"]["legacy"][field], value)
                data["input_manifests"]["legacy"][field] = value
                with self.assertRaises(composition.CompositionError):
                    composition.validate_manifest(data)

    def test_previous_five_role_population_cannot_omit_the_witness(self):
        data = load(MANIFEST)
        population = data["conditional_root_arithmetic"]["family_population"]
        population["roles"].remove("witness-response")
        del population["required_by_role"]["witness-response"]
        with self.assertRaises(composition.CompositionError):
            composition.validate_manifest(data)
        self.arithmetic_refused(data["conditional_root_arithmetic"])

    def test_pure_validation_cannot_report_source_or_deployment_checks(self):
        report = composition.validate_manifest(load(MANIFEST))
        self.assertIs(report["declared_source_union_consistent"], False)
        self.assertEqual(report["source_binding_scope"], "unbound")
        self.assertIs(report["source_revision_bound"], False)
        self.assertIs(report["deployment_identity_proved"], False)
        self.assertIs(report["transitive_dependency_closure_proved"], False)
        self.assertNotIn("source_files_sha256", report)
        self.assertNotIn("manifest_sha256", report)
        self.remains_unqualified(report)

    def test_unknowns_and_nonqualification_cannot_be_promoted_in_the_manifest(self):
        changes = (
            lambda d: d.update(actual_lifetime_failure_bound=ratio(0)),
            lambda d: d.update(composition_coverage_proved=True),
            lambda d: d.update(whole_chain_hash_query_scope_closed=True),
            lambda d: d.update(production_activation=True),
            lambda d: d["scope_mappings"].update(joint_bound_derived=True),
            lambda d: d["scope_mappings"].update(root_is_added_to_legacy_sum=True),
            lambda d: d["scope_mappings"].update(root_replaces_legacy_signature_term=True),
            lambda d: d["additional_loss_accounting"].update(total=ratio(0)),
            lambda d: d["primitive_scope_bridge"]["sha256"].update(maximum="0"),
            lambda d: d["shared_substrates"]["keccak-p1600-24"].update(independent_oracles_proved=True),
            lambda d: d["resource_instances"]["ml"].update(node_limits_bound_external_queries=True),
        )
        for mutate in changes:
            data = composition.default_manifest()
            mutate(data)
            with self.assertRaises(composition.CompositionError):
                composition.validate_manifest(data)

    def test_every_resource_instance_retains_all_channels_and_unknown_units(self):
        data = load(MANIFEST)
        for row in data["resource_instances"].values():
            self.assertEqual(set(row["coverage_labels"]), set(composition.COVERAGE))
            self.assertIs(row["coverage_labels_are_disjoint_buckets"], False)
            self.assertIsNone(row["query_unit"])
            self.assertIsNone(row["theorem_resource_transform"])
            self.assertTrue(all(value is None for value in row["variables"].values()))
        data["resource_instances"]["ml"]["coverage_labels"].remove("offline")
        with self.assertRaises(composition.CompositionError):
            composition.validate_manifest(data)

    def test_shared_source_identity_merges_once_and_conflicts_are_refused(self):
        left = {"a.rs": "a" * 64, "shared.rs": "b" * 64}
        right = {"shared.rs": "b" * 64, "c.rs": "c" * 64}
        merged = composition.merge_source_maps(left, right)
        self.assertEqual(len(merged), 3)
        self.assertEqual(merged["shared.rs"], "b" * 64)
        right["shared.rs"] = "d" * 64
        with self.assertRaises(composition.CompositionError):
            composition.merge_source_maps(left, right)

    def test_primitive_bridge_has_four_shared_scopes_without_numerical_budgets(self):
        scopes = composition.bridge_primitives(load(LEGACY), load(ROOT_REGISTER))
        self.assertEqual(set(scopes), {"sha256", "sha512", "shake128", "shake256"})
        self.assertEqual(len({row["public_parameter_id"] for row in scopes.values()}), 4)
        for row in scopes.values():
            self.assertIsNone(row["maximum"])
            self.assertIsNone(row["query_unit"])
            self.assertIs(row["query_budget_proved"], False)
            self.assertTrue(row["legacy_term_ids"])
            self.assertTrue(row["root_use_ids"])

    def test_conflicting_primitive_identity_units_caps_resets_and_sets_are_refused(self):
        changes = (
            lambda d: d["primitives"]["sha256"].update(public_parameter_id="another-shared-instance"),
            lambda d: d["primitives"]["sha256"].update(fixed_across_epochs=False),
            lambda d: d["primitives"]["sha256"]["query_budget"].update(unit="node-observed-calls"),
            lambda d: d["primitives"]["sha256"]["query_budget"].update(maximum="0"),
            lambda d: d["primitives"]["sha256"]["query_budget"].update(reset_at_role_boundary=True),
            lambda d: d["primitives"]["sha256"]["query_budget"].update(reset_at_key_epoch=True),
            lambda d: d["primitives"].pop("sha256"),
        )
        for mutate in changes:
            old, new = load(LEGACY), load(ROOT_REGISTER)
            mutate(new)
            with self.assertRaises(composition.CompositionError):
                composition.bridge_primitives(old, new)


class SourceInspectionTests(ContractCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="pq-lifetime-composition-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.legacy_files = load(SOURCE_LOCK)["files"]
        self.root_files = load(ROOT_REGISTER)["source_files_sha256"]
        paths = set(self.legacy_files) | set(self.root_files)
        paths.update((MANIFEST, LEGACY, SOURCE_LOCK, ROOT_REGISTER))
        for path in paths:
            destination = self.root / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / path, destination)

    def write_json(self, path, data):
        (self.root / path).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    def run_cli(self):
        return subprocess.run([sys.executable, str(ROOT / "scripts/ci/pq_lifetime_composition.py"),
                               "--root", str(self.root)], capture_output=True, text=True,
                              check=False, timeout=20)

    def test_real_inspection_binds_65_distinct_declared_sources_and_four_scopes(self):
        report = composition.inspect(self.root)
        self.assertEqual(report["source_counts"], {"legacy": 21, "root": 46, "shared": 1, "union": 66})
        self.assertEqual(len(report["source_files_sha256"]), 66)
        self.assertEqual(set(report["source_files_sha256"]), set(self.legacy_files) | set(self.root_files))
        self.assertIs(report["declared_source_union_consistent"], True)
        self.assertEqual(report["source_binding_scope"], "declared-path-union-only")
        self.assertIs(report["source_revision_bound"], False)
        self.assertIs(report["deployment_identity_proved"], False)
        self.assertEqual(report["shared_primitive_scope_count"], 4)
        self.assertEqual(report["shared_source_paths"],
                         ["trillionnium/crates/trnm-release-bundle/src/pq_release.rs"])
        self.assertEqual(set(report["unknown_role_lifetime_populations"]),
                         {"root-approval", "successor-possession", "anchor-writer",
                          "anchor-response", "effect-provider", "witness-response"})
        self.assertEqual(decode(report["allocation_headroom"]), 0)
        self.assertIsNone(report["additional_loss_total"])
        self.assertIsNone(report["allocation_sufficiency_under_declared_losses"])
        self.assertIsNone(report["legacy_declared_arithmetic"]["model_arithmetic_sum"])
        self.assertIs(report["legacy_declared_arithmetic"]["not_transferred_to_joint_experiment"], True)
        self.assertEqual(len(report["legacy_declared_arithmetic"]["unknown_terms"]), 8)
        self.assertTrue(all(value is None for value in report["domain_failure_bounds"].values()))
        for name, entry in report["input_manifests"].items():
            self.assertEqual(hashlib.sha256((self.root / entry["path"]).read_bytes()).hexdigest(),
                             entry["sha256"], name)
        self.remains_unqualified(report)

    def test_missing_composition_manifest_is_refused(self):
        (self.root / MANIFEST).unlink()
        with self.assertRaises(composition.CompositionError):
            composition.inspect(self.root)

    def test_missing_each_child_manifest_or_legacy_lock_is_refused(self):
        for path in (LEGACY, ROOT_REGISTER, SOURCE_LOCK):
            with self.subTest(path=path):
                data = (self.root / path).read_bytes()
                (self.root / path).unlink()
                try:
                    with self.assertRaises(composition.CompositionError):
                        composition.inspect(self.root)
                finally:
                    (self.root / path).write_bytes(data)

    def test_changed_child_manifest_bytes_are_refused_even_when_json_semantics_match(self):
        for path in (LEGACY, ROOT_REGISTER):
            with self.subTest(path=path):
                data = (self.root / path).read_bytes()
                (self.root / path).write_bytes(data + b"\n")
                try:
                    with self.assertRaisesRegex(composition.CompositionError, "input manifest differs"):
                        composition.inspect(self.root)
                finally:
                    (self.root / path).write_bytes(data)

    def test_changed_shared_source_is_refused(self):
        shared = set(self.legacy_files) & set(self.root_files)
        self.assertEqual(len(shared), 1)
        path = self.root / next(iter(shared))
        path.write_bytes(path.read_bytes() + b"\n// synthetic source-contract change\n")
        with self.assertRaises(composition.CompositionError):
            composition.inspect(self.root)

    def test_missing_source_from_either_inventory_is_refused(self):
        paths = (next(iter(set(self.legacy_files) - set(self.root_files))),
                 next(iter(set(self.root_files) - set(self.legacy_files))))
        for path in paths:
            with self.subTest(path=path):
                data = (self.root / path).read_bytes()
                (self.root / path).unlink()
                try:
                    with self.assertRaises(composition.CompositionError):
                        composition.inspect(self.root)
                finally:
                    (self.root / path).write_bytes(data)

    def test_conflicting_source_lock_cannot_override_root_source_identity(self):
        lock = load(SOURCE_LOCK)
        shared = next(iter(set(self.legacy_files) & set(self.root_files)))
        lock["files"][shared] = "0" * 64
        self.write_json(SOURCE_LOCK, lock)
        with self.assertRaises(composition.CompositionError):
            composition.inspect(self.root)

    def test_changed_shared_scope_in_child_is_refused_before_joining(self):
        data = load(ROOT_REGISTER)
        data["primitives"]["sha256"]["query_budget"]["reset_at_key_epoch"] = True
        self.write_json(ROOT_REGISTER, data)
        with self.assertRaises(composition.CompositionError):
            composition.inspect(self.root)

    def test_inspection_rejects_duplicate_json_fields(self):
        raw = (self.root / MANIFEST).read_text(encoding="utf-8")
        modified = '{"purpose":"research-obligation-bridge",' + raw.lstrip()[1:]
        (self.root / MANIFEST).write_text(modified, encoding="utf-8")
        with self.assertRaises(composition.CompositionError):
            composition.inspect(self.root)

    def test_cli_inspection_returns_hold_and_null_not_a_security_pass(self):
        process = self.run_cli()
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(process.stderr, "")
        report = json.loads(process.stdout)
        self.assertEqual(report["source_counts"]["union"], 66)
        self.remains_unqualified(report)

    def test_cli_changed_input_returns_structured_refusal_without_qualification(self):
        (self.root / LEGACY).write_bytes(b"{}\n")
        process = self.run_cli()
        self.assertEqual(process.returncode, 2, process.stderr)
        self.assertEqual(process.stderr, "")
        report = json.loads(process.stdout)
        self.assertEqual(report["status"], "REFUSE")
        self.assertIsNone(report["actual_lifetime_failure_bound"])
        self.assertIs(report["whole_chain_pq_qualified"], False)
        self.assertIs(report["production_activation"], False)
        self.assertIn("input manifest differs", report["error"])


class QueryTailSemanticsTests(ContractCase):
    """A bounded-query game leaves the resource-overrun event to be paid.

    All finite spaces and query counts here are invented arithmetic examples.
    They neither measure nor constrain the project's adversary.
    """

    def example(self, **values):
        data = composition.default_query_tail_arithmetic()
        data["purpose"] = "arithmetic-example"
        data["query_budget"] = {"maximum": "16", "unit": "synthetic-oracle-query"}
        for name in composition.QUERY_TAIL_LEAVES:
            data["inputs"][name].update({
                "query_budget": deepcopy(data["query_budget"]),
                "status": "declared-model-bound", "bound": ratio(values.get(name, 0)),
                "theorem": {
                    "reference": "Synthetic finite space; no project theorem",
                    "locator": "Query-tail arithmetic fixture only",
                    "applicability": "Assumed bound in this invented common lifetime experiment; project applicability remains unproved.",
                },
            })
        return data

    def refuse(self, data):
        with self.assertRaises((composition.CompositionError, composition.legacy.BudgetError)):
            composition.review_query_tail_arithmetic(data)

    def remains_unqualified(self, report):
        super().remains_unqualified(report)
        for key in ("composition_coverage_proved", "whole_chain_hash_query_scope_closed",
                    "theorem_applicability_verified", "resource_random_variable_defined_for_project",
                    "bounded_game_to_project_reduction_proved"):
            self.assertIs(report[key], False, key)

    def test_all_bad_and_overrun_events_in_weighted_finite_space_satisfy_bound(self):
        # Q takes values 0 and 17, so O={Q>16} may have any correlation with Bad.
        weights = (Fraction(1, 2), Fraction(1, 4), Fraction(1, 8), Fraction(1, 8))
        subsets = [frozenset(i for i in range(4) if mask & (1 << i)) for mask in range(16)]

        def mass(event):
            return sum((weights[i] for i in event), Fraction())

        for bad, overrun in itertools.product(subsets, repeat=2):
            data = self.example(bounded_query_failure=mass(bad - overrun),
                                query_budget_overrun=mass(overrun))
            report = composition.review_query_tail_arithmetic(data)
            self.assertLessEqual(mass(bad), decode(report["conditional_lifetime_declared_bound"]))
        self.remains_unqualified(report)

    def test_all_unknown_inputs_keep_complete_bound_unknown(self):
        report = composition.review_query_tail_arithmetic(composition.default_query_tail_arithmetic())
        self.assertEqual(set(report["unknown_inputs"]), set(composition.QUERY_TAIL_LEAVES))
        self.assertIsNone(report["uncapped_declared_sum"])
        self.assertIsNone(report["conditional_lifetime_declared_bound"])
        self.remains_unqualified(report)

    def test_unknown_overrun_is_not_zero_even_at_exact_bounded_game_target(self):
        data = self.example(bounded_query_failure=TARGET)
        data["inputs"]["query_budget_overrun"].update(status="unknown", bound=None, theorem=None)
        report = composition.review_query_tail_arithmetic(data)
        self.assertEqual(decode(report["known_declared_subtotal"]), TARGET)
        self.assertEqual(report["unknown_inputs"], ["query_budget_overrun"])
        self.assertIsNone(report["uncapped_declared_sum"])
        self.assertIsNone(report["conditional_lifetime_declared_bound"])
        self.remains_unqualified(report)

    def test_each_required_unknown_input_propagates(self):
        for name in composition.QUERY_TAIL_LEAVES:
            with self.subTest(name=name):
                data = self.example()
                data["inputs"][name].update(status="unknown", bound=None, theorem=None)
                report = composition.review_query_tail_arithmetic(data)
                self.assertIn(name, report["unknown_inputs"])
                self.assertIsNone(report["conditional_lifetime_declared_bound"])
                self.remains_unqualified(report)

    def test_tiny_positive_overrun_exceeds_exhausted_target_without_rounding(self):
        tail = Fraction(1, 1 << 512)
        report = composition.review_query_tail_arithmetic(self.example(
            bounded_query_failure=TARGET, query_budget_overrun=tail))
        self.assertEqual(decode(report["conditional_lifetime_declared_bound"]), TARGET + tail)
        self.assertEqual(decode(report["known_declared_subtotal"]), TARGET + tail)
        self.assertIs(report["declared_target_exceeded_by_known_inputs"], True)
        self.remains_unqualified(report)

    def test_reduction_loss_is_additive_and_cannot_hide_in_overrun(self):
        report = composition.review_query_tail_arithmetic(self.example(
            bounded_query_failure=Fraction(1, 16), query_budget_overrun=Fraction(1, 32),
            bounded_game_reduction_loss=Fraction(1, 64)))
        self.assertEqual(decode(report["conditional_lifetime_declared_bound"]), Fraction(7, 64))
        self.remains_unqualified(report)

    def test_cap_retains_uncapped_three_term_sum(self):
        report = composition.review_query_tail_arithmetic(self.example(
            **{name: 1 for name in composition.QUERY_TAIL_LEAVES}))
        self.assertEqual(decode(report["uncapped_declared_sum"]), 3)
        self.assertEqual(decode(report["conditional_lifetime_declared_bound"]), 1)
        self.remains_unqualified(report)

    def test_declared_zero_requires_all_explicit_inputs_and_never_promotes(self):
        report = composition.review_query_tail_arithmetic(self.example())
        self.assertEqual(decode(report["conditional_lifetime_declared_bound"]), 0)
        self.assertEqual(report["unknown_inputs"], [])
        self.remains_unqualified(report)

    def test_unknown_loss_does_not_erase_known_target_excess(self):
        data = self.example(bounded_query_failure=TARGET,
                            query_budget_overrun=Fraction(1, 1 << 512))
        data["inputs"]["bounded_game_reduction_loss"].update(status="unknown", bound=None, theorem=None)
        report = composition.review_query_tail_arithmetic(data)
        self.assertIsNone(report["conditional_lifetime_declared_bound"])
        self.assertIs(report["declared_target_exceeded_by_known_inputs"], True)
        self.remains_unqualified(report)

    def test_query_count_and_unit_must_agree_for_every_leaf(self):
        for name in composition.QUERY_TAIL_LEAVES:
            for key, value in (("maximum", "17"), ("unit", "other-query-interface")):
                with self.subTest(name=name, key=key):
                    data = self.example()
                    data["inputs"][name]["query_budget"][key] = value
                    self.refuse(data)

    def test_coverage_cannot_drop_external_or_prior_work_channels(self):
        for label in ("online", "offline", "preprocessing", "failed", "unpublished",
                      "recursive", "shared-uses", "initial-state", "classical-advice",
                      "quantum-advice", "all-keys", "all-epochs"):
            with self.subTest(label=label):
                data = self.example()
                data["coverage_labels"].remove(label)
                self.refuse(data)

    def test_node_limits_or_epoch_resets_cannot_supply_a_global_cap(self):
        for key in ("node_limits_bound_external_queries", "reset_at_key_epoch_role_recovery"):
            data = self.example()
            data[key] = True
            self.refuse(data)

    def test_foreign_experiment_game_model_scope_and_query_definition_refused(self):
        for key, value in (("experiment_id", "different-lifetime"),
                           ("game_id", "single-invocation-game"),
                           ("model", "classical-ROM"),
                           ("scope", "current-key-only"),
                           ("query_count_definition", "observed-online-node-queries")):
            data = self.example()
            data[key] = value
            self.refuse(data)

    def test_omitted_input_is_not_an_implicit_zero(self):
        for name in composition.QUERY_TAIL_LEAVES:
            data = self.example()
            del data["inputs"][name]
            self.refuse(data)

    def test_unsupported_fields_and_self_certification_are_refused(self):
        mutations = (
            lambda d: d.update(verified=True),
            lambda d: d.update(independent=True),
            lambda d: d.update(actual_lifetime_failure_bound=ratio(0)),
            lambda d: d["inputs"]["query_budget_overrun"].update(verified=True),
            lambda d: d["inputs"]["query_budget_overrun"].update(status="proved"),
            lambda d: d["inputs"]["query_budget_overrun"]["theorem"].update(verified=True),
        )
        for mutate in mutations:
            data = self.example()
            mutate(data)
            self.refuse(data)

    def test_invalid_query_budget_types_and_partial_budget_are_refused(self):
        for budget in ({"maximum": 16, "unit": "synthetic-oracle-query"},
                       {"maximum": True, "unit": "synthetic-oracle-query"},
                       {"maximum": "16", "unit": 1},
                       {"maximum": "-1", "unit": "synthetic-oracle-query"},
                       {"maximum": "01", "unit": "synthetic-oracle-query"},
                       {"maximum": None, "unit": "synthetic-oracle-query"},
                       {"maximum": "16", "unit": None}):
            data = self.example()
            data["query_budget"] = deepcopy(budget)
            for row in data["inputs"].values():
                row["query_budget"] = deepcopy(budget)
            self.refuse(data)

    def test_unknown_input_cannot_carry_a_number_or_theorem(self):
        for key, value in (("bound", ratio(0)), ("theorem", {"reference": "invented"})):
            data = composition.default_query_tail_arithmetic()
            data["inputs"]["query_budget_overrun"][key] = value
            self.refuse(data)

    def test_invalid_probability_types_ranges_and_missing_theorem_refused(self):
        for bound in (None, {"numerator": "-1", "denominator": "1"},
                      {"numerator": "2", "denominator": "1"},
                      {"numerator": "1", "denominator": "0"},
                      {"numerator": 1, "denominator": "16"}):
            data = self.example()
            data["inputs"]["query_budget_overrun"]["bound"] = bound
            self.refuse(data)
        data = self.example()
        del data["inputs"]["query_budget_overrun"]["theorem"]["applicability"]
        self.refuse(data)

    def test_numeric_declarations_cannot_use_an_unknown_query_count(self):
        data = self.example()
        data["query_budget"] = {"maximum": None, "unit": None}
        for row in data["inputs"].values():
            row["query_budget"] = deepcopy(data["query_budget"])
        self.refuse(data)

    def test_target_headroom_is_exact_and_signed_without_hiding_excess(self):
        for failure, tail in ((Fraction(0), Fraction(0)),
                              (TARGET, Fraction(0)),
                              (TARGET, Fraction(1, 1 << 512))):
            with self.subTest(failure=failure, tail=tail):
                report = composition.review_query_tail_arithmetic(self.example(
                    bounded_query_failure=failure, query_budget_overrun=tail))
                self.assertEqual(decode(report["remaining_target_after_known_inputs"]),
                                 TARGET - failure - tail)
                self.assertIs(report["declared_target_exceeded_by_known_inputs"],
                              failure + tail > TARGET)
                self.assertIs(report["declared_target_met"], failure + tail <= TARGET)
                self.remains_unqualified(report)

    def test_real_inspector_embeds_unknown_tail_without_changing_qualification(self):
        report = composition.inspect(ROOT)
        tail = report["conditional_query_tail_arithmetic"]
        self.assertEqual(set(tail["unknown_inputs"]), set(composition.QUERY_TAIL_LEAVES))
        self.assertEqual(tail["query_budget"], {"maximum": None, "unit": None})
        self.assertIsNone(tail["conditional_lifetime_declared_bound"])
        self.assertIsNone(tail["uncapped_declared_sum"])
        self.assertIsNone(tail["declared_target_met"])
        self.remains_unqualified(tail)
        ContractCase.remains_unqualified(self, report)


if __name__ == "__main__":
    unittest.main()
