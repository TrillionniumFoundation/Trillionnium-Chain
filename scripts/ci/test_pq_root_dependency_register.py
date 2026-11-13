"""Adversarial controls for the V2-V5 root dependency review register.

These tests do not supply cryptographic error estimates. A successful register
check is a source/declaration consistency result, including an explicit list
of unqualified roles, query budgets, epochs and whole-chain domains.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pq_root_dependency_register as register


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = "config/pon/pq-root-dependency-register-v3.json"
EXPECTED_ROLES = {"root-approval", "successor-possession", "anchor-writer",
                  "anchor-response", "effect-provider", "witness-response"}
EXPECTED_PRIMITIVES = {"sha256", "sha512", "shake128", "shake256"}
EXPECTED_DOMAINS = {"signature", "commitment", "proof", "ledger", "transport",
                    "recovery", "release", "application"}
NATIVE_CRYPTO = "trillionnium/crates/trnm-crypto-primitives/src/pq_root_v3.rs"
NATIVE_OWNER = "trillionnium/crates/trnm-pon-node/src/root_recovery_v3.rs"


PREVIOUS_REVIEW_BASE = "225ab38e1e5f7e0852a28372bd8dd769eec1084b"
PREVIOUS_SOURCE_SNAPSHOT_SHA256 = (
    "844d27717babb9b3a286cd28915a06b0cd1152ffcf151ffdf6c30a01708bd9fe"
)
PREVIOUS_SOURCE_PINS = {
    "trillionnium/Cargo.lock":
        "53c4eab0fb3d2951894348de2b765e0a573e49acb5dbfe1fe805719ec868a136",
    "trillionnium/crates/trnm-crypto-primitives/Cargo.toml":
        "caff7ff137c94e26a378a2a95ae029a21b1ee30a79d08a05b8c9e3b1f1810ab8",
    "trillionnium/crates/trnm-crypto-primitives/src/lib.rs":
        "74f11c99984a0c199f6b1a882206dc887440a3c69668dd3833054eb0e98fd32c",
    "trillionnium/crates/trnm-pon-node/Cargo.toml":
        "70b357c460db5a2428e8a1a30ecf71865ebbb3200323b4537aeb90ff601d9ec9",
    "trillionnium/crates/trnm-pon-node/src/lib.rs":
        "0b7e076069645bdf502ff4521ea7c1d77b75a64e5137df3527b0cd6e7167c461",
    "trillionnium/crates/trnm-protocol/src/lib.rs":
        "b965065ca4915d57e61af480ef6cfb8f775465c8ad0e4dec0b2895e110946b86",
}


def manifest():
    return json.loads((ROOT / MANIFEST).read_text(encoding="utf-8"))


class ContractCase(unittest.TestCase):
    def refused(self, data):
        with self.assertRaises(register.RegisterError):
            register.validate_manifest(data)

    def remains_unqualified(self, report):
        self.assertEqual(report["status"], "HOLD")
        self.assertIsNone(report["actual_lifetime_failure_bound"])
        self.assertEqual(set(report["domain_failure_bounds"]), EXPECTED_DOMAINS)
        self.assertTrue(all(value is None for value in report["domain_failure_bounds"].values()))
        for name in ("whole_chain_pq_qualified", "pq_128_qualified",
                     "composition_coverage_proved", "theorem_applicability_verified",
                     "transitive_dependency_closure_proved", "whole_chain_hash_query_scope_closed",
                     "independent_custody_verified",
                     "independent_common_restore_exclusion_proved",
                     "native_witness_durable_service_verified",
                     "anchor_independence_verified", "actual_external_effects_verified",
                     "native_m15_production_integration_complete", "production_activation",
                     "operational_refusal_caps_are_adversary_bounds", "source_revision_bound"):
            self.assertIs(report[name], False, name)


class FrozenRoleTests(ContractCase):
    def test_checked_in_register_names_all_roles_without_promoting_any(self):
        data = manifest()
        self.assertEqual(register.DEFAULT_MANIFEST, MANIFEST)
        self.assertEqual(set(data["roles"]), EXPECTED_ROLES)
        self.assertEqual(set(data["primitives"]), EXPECTED_PRIMITIVES)
        report = register.validate_manifest(data)
        self.assertEqual(set(report["declared_roles"]), EXPECTED_ROLES)
        self.assertEqual(report["native_unwired_roles"], ["effect-provider"])
        self.assertEqual(report["native_readback_candidate_roles"], ["effect-provider"])
        self.assertEqual(report["native_unwired_role_scope"],
                         "effect-entry-and-production-owner-not-readback-code")
        self.assertEqual(set(report["unknown_lifetime_query_budgets"]), EXPECTED_PRIMITIVES)
        self.assertEqual(set(report["unknown_role_lifetime_populations"]), EXPECTED_ROLES)
        self.assertIs(report["source_files_checked"], False)
        self.assertEqual(report["source_binding_scope"], "unbound-until-file-inspection")
        self.remains_unqualified(report)

    def test_every_role_is_mandatory_and_unknown_roles_are_refused(self):
        for role in EXPECTED_ROLES:
            with self.subTest(role=role):
                data = manifest()
                del data["roles"][role]
                self.refused(data)
        data = manifest()
        data["roles"]["emergency-single-family"] = deepcopy(data["roles"]["root-approval"])
        self.refused(data)

    def test_root_and_all_signing_roles_require_both_exact_families(self):
        for role in EXPECTED_ROLES:
            for suite in ("ML-DSA-87", "SLH-DSA-SHA2-256s"):
                with self.subTest(role=role, suite=suite):
                    data = manifest()
                    del data["roles"][role]["approval_policy"]["families"][suite]
                    self.refused(data)
        for original, replacement in (("ML-DSA-87", "ML-DSA-65"),
                                      ("SLH-DSA-SHA2-256s", "SLH-DSA-SHAKE-256s"),
                                      ("SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-128s")):
            data = manifest()
            families = data["roles"]["root-approval"]["approval_policy"]["families"]
            families[replacement] = families.pop(original)
            self.refused(data)

    def test_or_fallback_threshold_and_roster_downgrades_are_refused(self):
        for field, value in (("combiner", "OR"), ("fallback", "ML-DSA-87")):
            data = manifest()
            data["roles"]["anchor-response"]["approval_policy"][field] = value
            self.refused(data)
        for field, value in (("required", 1), ("roster_size", 4), ("required", True)):
            data = manifest()
            data["roles"]["anchor-writer"]["approval_policy"]["families"]["ML-DSA-87"][field] = value
            self.refused(data)

    def test_successor_possession_requires_all_six_not_the_old_approval_threshold(self):
        data = manifest()
        family = data["roles"]["successor-possession"]["approval_policy"]["families"]
        self.assertEqual(family["ML-DSA-87"]["required"], 3)
        self.assertEqual(family["SLH-DSA-SHA2-256s"]["required"], 3)
        family["SLH-DSA-SHA2-256s"]["required"] = 2
        self.refused(data)

    def test_every_root_action_and_each_successor_action_remains_covered(self):
        root_actions = ["normal", "rotate", "revoke", "recover", "policy-change"]
        data = manifest()
        self.assertEqual(data["roles"]["root-approval"]["action_coverage"], root_actions)
        self.assertEqual(data["roles"]["successor-possession"]["action_coverage"],
                         ["rotate", "recover", "policy-change"])
        for action in root_actions:
            data = manifest()
            data["roles"]["root-approval"]["action_coverage"].remove(action)
            self.refused(data)
        for action in ("rotate", "recover", "policy-change"):
            data = manifest()
            data["roles"]["successor-possession"]["action_coverage"].remove(action)
            self.refused(data)

    def test_source_role_bindings_cannot_omit_native_owner_or_anchor(self):
        for role in ("root-approval", "anchor-writer", "anchor-response"):
            with self.subTest(role=role):
                data = manifest()
                paths = data["roles"][role]["implementations"]["rust-v3"]["source_paths"]
                self.assertIn(NATIVE_OWNER, paths)
                paths.remove(NATIVE_OWNER)
                self.refused(data)

    def test_python_provider_success_cannot_claim_native_provider_integration(self):
        data = manifest()
        provider = data["roles"]["effect-provider"]["implementations"]["rust-v3"]
        self.assertEqual(provider["status"], "not-wired-in-native-v3")
        self.assertEqual(provider["source_paths"], [])
        data["roles"]["effect-provider"]["implementations"]["rust-v3"] = deepcopy(
            data["roles"]["anchor-response"]["implementations"]["rust-v3"])
        self.refused(data)

    def test_native_v4_readback_remains_separate_from_effect_entry(self):
        data = manifest()
        implementation = data["roles"]["effect-provider"]["implementations"]["rust-v4-readback"]
        self.assertIn("trillionnium/crates/trnm-pon-node/src/root_recovery_v3/effect_readback_v4.rs",
                      implementation["source_paths"])
        self.assertEqual(implementation["validity_contract"],
                         "historical-operation-fresh-readback-only-no-effect-entry")
        self.assertFalse(implementation["production_qualified"])
        for field, value in (("production_qualified", True),
                             ("validity_contract", "current-final-use-authority")):
            changed = deepcopy(data)
            changed["roles"]["effect-provider"]["implementations"]["rust-v4-readback"][field] = value
            self.refused(changed)
        witnessed = data["roles"]["effect-provider"]["implementations"]["rust-v5-witnessed-readback"]
        self.assertIn(register.NATIVE_WITNESS_PROVIDER, witnessed["source_paths"])
        self.assertIn(register.NATIVE_WITNESS_PROVIDER, data["source_files_sha256"])
        self.assertIn(register.NODE + "tests/root_witness_provider_v5_native.rs", data["source_files_sha256"])
        self.assertEqual(witnessed["validity_contract"],
                         "same-historical-operation-live-witness-before-and-after-readback-no-effect-entry")
        self.assertFalse(witnessed["production_qualified"])
        for field, value in (("production_qualified", True),
                             ("validity_contract", "current-final-use-authority")):
            changed = deepcopy(data)
            changed["roles"]["effect-provider"]["implementations"]["rust-v5-witnessed-readback"][field] = value
            self.refused(changed)

    def test_native_v5_witness_role_hashes_and_unproved_custody_are_explicit(self):
        data = manifest()
        witness = data["roles"]["witness-response"]
        self.assertEqual(set(witness["implementations"]),
                         {"rust-v5-witnessed-owner", "rust-v5-durable-register", "rust-v6-receipted-register"})
        self.assertFalse(witness["independent_custody_verified"])
        self.assertEqual(witness["epoch_scope"], data["roles"]["anchor-response"]["epoch_scope"])
        native = witness["implementations"]["rust-v5-witnessed-owner"]
        self.assertIn(register.NATIVE_WITNESS, native["source_paths"])
        self.assertFalse(native["production_qualified"])
        durable = witness["implementations"]["rust-v5-durable-register"]
        self.assertIn(register.NATIVE_WITNESS_DURABLE, durable["source_paths"])
        self.assertFalse(durable["production_qualified"])
        changed = deepcopy(data)
        del changed["roles"]["witness-response"]["implementations"]["rust-v5-durable-register"]
        self.refused(changed)
        self.assertIn(register.NATIVE_WITNESS_DURABLE, data["source_files_sha256"])
        self.assertIn(register.NODE + "tests/root_witness_v5_durable_native.rs", data["source_files_sha256"])
        self.assertFalse(data["operational_refusal_caps"]["native-witness-database-bytes"]["bounds_adversary_queries"])
        use = data["hash_uses"]["native-fresh-witness-v5"]
        self.assertEqual(use["primitive_ids"], ["sha512"])
        self.assertEqual(use["roles"], ["anchor-writer", "witness-response"])
        for key in ("ml-dsa-internals", "slh-dsa-sha2-internals"):
            self.assertIn("witness-response", data["hash_uses"][key]["roles"])
        for key in ("python-public-key-identities-v2", "python-verified-message-identity-v2",
                    "python-journal-state-scope-effect-v2", "python-provider-executable-integrity"):
            self.assertNotIn("witness-response", data["hash_uses"][key]["roles"])
        for field in ("independent_common_restore_exclusion_proved",
                      "native_witness_durable_service_verified"):
            self.assertFalse(data["profiles"][field])
            changed = deepcopy(data)
            changed["profiles"][field] = True
            self.refused(changed)
        for field in ("roles", "source_paths", "constructions"):
            changed = deepcopy(data)
            changed["hash_uses"]["native-fresh-witness-v5"][field].pop()
            self.refused(changed)

    def test_height_and_unix_expiry_profiles_cannot_be_silently_equated(self):
        data = manifest()
        data["profiles"]["wire_equivalence_proved"] = True
        self.refused(data)
        data = manifest()
        implementations = data["roles"]["root-approval"]["implementations"]
        implementations["rust-v3"]["validity_contract"] = implementations["python-v2"]["validity_contract"]
        self.refused(data)

    def test_trusted_host_inputs_cannot_be_promoted_to_native_authority_proofs(self):
        for field, value in (
                ("native_clock_source", "production-signed-clock"),
                ("native_storage_assumption", "race-proof-sqlite-vfs"),
                ("native_clock_authority_qualified", True),
                ("native_sqlite_descriptor_race_proved_absent", True)):
            data = manifest()
            data["profiles"][field] = value
            self.refused(data)


class SharedHashAndEpochTests(ContractCase):
    def test_slh_sha2_256s_requires_sha512_and_its_hmac_mgf_dependencies(self):
        original = manifest()
        slh = original["hash_uses"]["slh-dsa-sha2-internals"]
        self.assertEqual(set(slh["primitive_ids"]), {"sha256", "sha512"})
        self.assertIn("HMAC-SHA-512", slh["constructions"])
        self.assertIn("MGF1-SHA-512", slh["constructions"])
        for field, value in (("primitive_ids", "sha512"),
                             ("constructions", "HMAC-SHA-512"),
                             ("constructions", "MGF1-SHA-512")):
            with self.subTest(dependency=value):
                data = deepcopy(original)
                data["hash_uses"]["slh-dsa-sha2-internals"][field].remove(value)
                self.refused(data)

    def test_ml_dsa_requires_both_shake_primitives(self):
        for primitive in ("shake128", "shake256"):
            data = manifest()
            data["hash_uses"]["ml-dsa-internals"]["primitive_ids"].remove(primitive)
            self.refused(data)

    def test_sha512_scopes_include_native_python_and_slh_uses_together(self):
        data = manifest()
        uses = set(data["primitives"]["sha512"]["use_ids"])
        self.assertTrue({"slh-dsa-sha2-internals", "python-journal-state-scope-effect-v2",
                         "python-provider-request-v2", "native-key-identities-v3",
                         "native-roster-and-operation-v3", "native-policy-checkpoint-artifact-v3",
                         "native-owner-and-anchor-v3"} <= uses)
        data["primitives"]["sha512"]["use_ids"].remove("slh-dsa-sha2-internals")
        self.refused(data)

    def test_missing_hash_use_cannot_be_hidden_by_rewriting_reverse_index(self):
        data = manifest()
        omitted = "python-provider-request-v2"
        del data["hash_uses"][omitted]
        data["primitives"]["sha512"]["use_ids"].remove(omitted)
        self.refused(data)

    def test_actual_native_delegation_and_commitments_cannot_be_omitted(self):
        data = manifest()
        adapter = "trillionnium/crates/trnm-crypto-primitives/src/pq_candidate.rs"
        profile = "trillionnium/crates/trnm-protocol/src/crypto_profile.rs"
        self.assertIn(adapter, data["source_files_sha256"])
        self.assertIn(profile, data["source_files_sha256"])
        paths = data["hash_uses"]["ml-dsa-internals"]["source_paths"]
        self.assertIn(adapter, paths)
        paths.remove(adapter)
        self.refused(data)
        data = manifest()
        uses = data["hash_uses"]["native-policy-checkpoint-artifact-v3"]["constructions"]
        self.assertIn("native-v3-actual-artifact-bytes", uses)
        uses.remove("native-v3-actual-artifact-bytes")
        self.refused(data)
        data = manifest()
        uses = data["hash_uses"]["native-owner-and-anchor-v3"]["constructions"]
        self.assertIn("native-v3-network-genesis-owner-scope", uses)
        uses.remove("native-v3-network-genesis-owner-scope")
        self.refused(data)

    def test_public_hash_cannot_be_split_by_role_epoch_or_construction_alias(self):
        for alias in ("sha512-new-root-epoch", "sha512-provider-only", "HMAC-SHA-512"):
            with self.subTest(alias=alias):
                data = manifest()
                data["primitives"][alias] = deepcopy(data["primitives"]["sha512"])
                self.refused(data)
        data = manifest()
        data["primitives"]["sha512"]["public_parameter_id"] = "SHA-512-fresh-per-role"
        self.refused(data)

    def test_role_keys_and_epochs_remain_unknown_not_single_roster_population(self):
        for field in ("total_keys", "total_rosters", "total_epochs", "maximum_signatures",
                      "maximum_verification_attempts"):
            for value in (0, "0", 3, "3", "128"):
                with self.subTest(field=field, value=value):
                    data = manifest()
                    data["roles"]["root-approval"]["epoch_scope"][field] = value
                    self.refused(data)

    def test_retired_successor_and_recovered_keys_cannot_be_excluded(self):
        for role in EXPECTED_ROLES:
            for scope in ("initial", "active", "successor", "retired", "recovered"):
                with self.subTest(role=role, scope=scope):
                    data = manifest()
                    data["roles"][role]["epoch_scope"]["coverage"].remove(scope)
                    self.refused(data)

    def test_rotation_recovery_restart_and_role_change_never_reset_a_lifetime(self):
        for field in ("reset_after_rotation", "reset_after_recovery", "reset_after_restart"):
            data = manifest()
            data["roles"]["root-approval"]["epoch_scope"][field] = True
            self.refused(data)
        for field in ("reset_at_key_epoch", "reset_at_recovery", "reset_at_role_boundary"):
            data = manifest()
            data["primitives"]["sha512"]["query_budget"][field] = True
            self.refused(data)

    def test_every_unobserved_query_channel_stays_explicit(self):
        data = manifest()
        channels = data["primitives"]["sha512"]["query_budget"]["coverage"]
        self.assertTrue({"offline", "preprocessing", "failed", "cancelled", "unpublished",
                         "recursive", "helpers", "shared-role", "all-key-epochs"} <= set(channels))
        for channel in channels:
            with self.subTest(channel=channel):
                changed = manifest()
                changed["primitives"]["sha512"]["query_budget"]["coverage"].remove(channel)
                self.refused(changed)


class RefusalCapAndClaimTests(ContractCase):
    def test_local_refusal_limits_are_recorded_without_adversary_conversion(self):
        data = manifest()
        caps = data["operational_refusal_caps"]
        self.assertEqual(caps["python-retained-nonces"]["maximum"], "128")
        self.assertEqual(caps["python-retained-events"]["maximum"], "2048")
        self.assertEqual(caps["native-verification-reservations"]["maximum"], "4096")
        for row in caps.values():
            self.assertEqual(row["purpose"], "operational-refusal-only")
            self.assertIs(row["bounds_adversary_queries"], False)
            self.assertIs(row["permits_history_pruning"], False)
            self.assertIs(row["permits_lifetime_reset"], False)
        self.remains_unqualified(register.validate_manifest(data))

    def test_native_per_operation_caps_cannot_turn_into_a_lifetime_bound(self):
        for key in ("native-verification-reservations", "native-verification-input-bytes",
                    "native-verification-cumulative-bytes", "native-retained-journal-events",
                    "native-artifact-bytes"):
            data = manifest()
            cap = data["operational_refusal_caps"][key]
            data["primitives"]["sha512"]["query_budget"]["maximum"] = cap["maximum"]
            self.refused(data)
            data = manifest()
            data["operational_refusal_caps"][key]["scope"] = "whole-chain-adversary-lifetime"
            self.refused(data)

    def test_default_verification_duration_is_not_a_universal_maximum(self):
        data = manifest()
        deadline = data["operation_deadline_policy"]
        self.assertEqual(deadline["default_verification_budget_seconds"], "60")
        self.assertIsNone(deadline["universal_duration_maximum"])
        deadline["universal_duration_maximum"] = "60"
        self.refused(data)
        data = manifest()
        data["operation_deadline_policy"]["preempts_in_progress_native_call"] = True
        self.refused(data)

    def test_refusal_cap_telemetry_and_receipts_cannot_supply_query_budget(self):
        for basis in ("operational-refusal-cap", "protocol-enforced-cap", "observed-count",
                      "signed-query-receipts", "external-adversary-assumption"):
            for maximum in (None, "0", "128", "2048"):
                with self.subTest(basis=basis, maximum=maximum):
                    data = manifest()
                    data["primitives"]["sha512"]["query_budget"].update(basis=basis, maximum=maximum)
                    self.refused(data)

    def test_even_zero_unknown_query_and_advice_cannot_be_smuggled(self):
        for maximum in ("0", 0, False, "128"):
            data = manifest()
            data["primitives"]["sha256"]["query_budget"]["maximum"] = maximum
            self.refused(data)
        for field in ("total_adversary_queries", "total_initial_advice", "maximum_duration", "stopping_rule"):
            data = manifest()
            data["lifetime"][field] = "0"
            self.refused(data)

    def test_refusal_semantics_and_query_units_cannot_be_relabelled(self):
        for field in ("bounds_adversary_queries", "permits_history_pruning", "permits_lifetime_reset"):
            data = manifest()
            data["operational_refusal_caps"]["python-retained-nonces"][field] = True
            self.refused(data)
        for field, value in (("unit", "observed-signature-calls"),
                             ("resource_to_query_reduction", "one-signature-equals-one-query"),
                             ("telemetry_is_upper_bound", True), ("initial_advice", "zero")):
            data = manifest()
            data["primitives"]["sha512"]["query_budget"][field] = value
            self.refused(data)

    def test_unknown_domain_errors_and_open_obligations_cannot_be_promoted(self):
        for domain in EXPECTED_DOMAINS:
            data = manifest()
            data["domain_failure_bounds"][domain] = {"numerator": "0", "denominator": "1"}
            self.refused(data)
        data = manifest()
        data["open_obligations"]["independent-custody"]["status"] = "verified"
        self.refused(data)
        data = manifest()
        del data["open_obligations"]["whole-chain-event-coverage"]
        self.refused(data)

    def test_no_security_coverage_provenance_or_activation_promotion_fields(self):
        for field, value in (("whole_chain_pq_qualified", True), ("production_activation", True),
                             ("composition_coverage_proved", True),
                             ("transitive_dependency_closure_proved", True),
                             ("whole_chain_hash_query_scope_closed", True),
                             ("prior_register_query_budgets_are_independent", True),
                             ("actual_lifetime_failure_bound", "0"),
                             ("source_revision_bound", True), ("signature_failure_product", "0")):
            data = manifest()
            data[field] = value
            self.refused(data)

    def test_prior_fifteen_path_register_cannot_cover_this_new_component(self):
        data = manifest()
        data["prior_register_covers_this_component"] = True
        self.refused(data)
        old = json.loads((ROOT / "config/pon/pq128-lifetime-budget-v1.json").read_text())
        self.refused(old)

    def test_bool_int_aliases_and_extra_fields_are_refused_at_nested_boundaries(self):
        for container, field, value in (
                ("profiles", "wire_equivalence_proved", 0),
                ("lifetime", "total_adversary_queries", False),
                ("profiles", "production_approved", False)):
            data = manifest()
            data[container][field] = value
            self.refused(data)


class ReviewedSourceTests(ContractCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="trnm-root-register-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.data = manifest()
        for relative in self.data["source_files_sha256"]:
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        self.path = self.root / MANIFEST
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.write()

    def write(self):
        self.path.write_text(json.dumps(self.data), encoding="utf-8")

    def inspect_refuses(self, pattern=None):
        if pattern is None:
            with self.assertRaises(register.RegisterError):
                register.inspect(self.root)
        else:
            with self.assertRaisesRegex(register.RegisterError, pattern):
                register.inspect(self.root)

    def run_cli(self):
        return subprocess.run([sys.executable, str(Path(register.__file__).resolve()),
                               "--root", str(self.root)], capture_output=True,
                              text=True, check=False, timeout=15)

    def test_all_declared_actual_bytes_match_without_security_or_commit_attestation(self):
        report = register.inspect(self.root)
        self.assertIs(report["source_files_checked"], True)
        self.assertEqual(report["source_binding_scope"], "declared-root-component-files-only")
        self.assertEqual(report["source_files_sha256"], self.data["source_files_sha256"])
        self.assertIn(NATIVE_CRYPTO, report["source_files_sha256"])
        self.assertIn(NATIVE_OWNER, report["source_files_sha256"])
        self.assertIn("formal/pon-nakamoto-v1/pq_root_effect_readback_v2.py", report["source_files_sha256"])
        self.remains_unqualified(report)

    def test_actual_source_change_with_same_declared_hash_refuses(self):
        path = self.root / NATIVE_CRYPTO
        path.write_bytes(path.read_bytes() + b"\n// adversarial changed source\n")
        self.inspect_refuses("source hash mismatch")

    def test_rewriting_source_and_its_manifest_hash_cannot_silently_regenerate_review(self):
        path = self.root / NATIVE_CRYPTO
        path.write_bytes(path.read_bytes() + b"\n// unreviewed candidate\n")
        self.data["source_files_sha256"][NATIVE_CRYPTO] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.write()
        self.inspect_refuses("frozen reviewed snapshot")

    def test_reverted_lock_dependency_is_refused_even_with_rewritten_manifest_hash(self):
        # Reproduce the dependency changed by this reviewed source continuation.
        # A different resolvable package version is still different source.
        relative = "trillionnium/Cargo.lock"
        path = self.root / relative
        raw = path.read_bytes()
        current = (b'name = "rustix"\nversion = "1.1.6"\n'
                   b'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                   b'checksum = "e5e76742e5294153d4dde1207dbec5bdd81eef6fabdc0d2118babadabfd858aa"')
        previous = (b'name = "rustix"\nversion = "1.1.4"\n'
                    b'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                    b'checksum = "b6fe4565b9518b83ef4f91bb47ce29620ca828bd32cb7e408f0062e9930ba190"')
        self.assertEqual(raw.count(current), 1)
        path.write_bytes(raw.replace(current, previous, 1))
        self.inspect_refuses("source hash mismatch: trillionnium/Cargo.lock")
        self.data["source_files_sha256"][relative] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.write()
        self.inspect_refuses("frozen reviewed snapshot")

    def test_previous_review_identity_is_preserved_as_a_refused_input(self):
        previous = deepcopy(self.data)
        previous["review_base_revision"] = PREVIOUS_REVIEW_BASE
        previous["source_files_sha256"].update(PREVIOUS_SOURCE_PINS)
        canonical = json.dumps({
            "review_base_revision": previous["review_base_revision"],
            "source_files_sha256": previous["source_files_sha256"],
        }, sort_keys=True, separators=(",", ":")).encode()
        self.assertEqual(hashlib.sha256(canonical).hexdigest(),
                         PREVIOUS_SOURCE_SNAPSHOT_SHA256)
        self.data = previous
        self.write()
        self.inspect_refuses("review_base_revision")

    def test_each_superseded_source_pin_is_refused_under_the_current_review(self):
        current = deepcopy(self.data)
        superseded = list(PREVIOUS_SOURCE_PINS.items())
        superseded.append((
            "trillionnium/crates/trnm-crypto-primitives/src/lib.rs",
            "4dc3fd4c60ee7548adb5b50f8658a8ff9529dcbbeae98bb590f03458a707f0a6",
        ))
        for path, digest in superseded:
            with self.subTest(path=path):
                self.assertNotEqual(current["source_files_sha256"][path], digest)
                self.data = deepcopy(current)
                self.data["source_files_sha256"][path] = digest
                self.write()
                self.inspect_refuses("frozen reviewed snapshot")

    def test_omitted_extra_or_rebound_source_paths_refuse(self):
        original = deepcopy(self.data)
        del self.data["source_files_sha256"][NATIVE_OWNER]
        self.write()
        self.inspect_refuses()
        self.data = deepcopy(original)
        self.data["source_files_sha256"]["undeclared-source.rs"] = "a" * 64
        self.write()
        self.inspect_refuses()
        self.data = deepcopy(original)
        self.data["source_files_sha256"]["../other/source.rs"] = self.data["source_files_sha256"].pop(NATIVE_OWNER)
        self.write()
        self.inspect_refuses()

    def test_review_base_is_not_replaceable_with_current_head_or_short_alias(self):
        for revision in ("main", "HEAD", "080c33c", "0" * 40,
                         "b683714cdd5ba241c16c335a81aebc12c1581902"):
            with self.subTest(revision=revision):
                self.data["review_base_revision"] = revision
                self.write()
                self.inspect_refuses()

    def test_missing_source_and_nonregular_source_refuse_without_hash_only_fallback(self):
        path = self.root / NATIVE_OWNER
        path.unlink()
        self.inspect_refuses("missing source")
        path.mkdir()
        self.inspect_refuses("nonregular")

    def test_symlinked_source_refuses_even_when_bytes_match(self):
        path = self.root / NATIVE_OWNER
        copy = self.root / "same-native-source.rs"
        path.rename(copy)
        path.symlink_to(copy)
        self.inspect_refuses("symlink")

    def test_symlinked_manifest_and_checkout_ancestor_refuse(self):
        copy = self.root / "same-register.json"
        self.path.rename(copy)
        self.path.symlink_to(copy)
        self.inspect_refuses("symlink")
        self.path.unlink()
        self.path.write_bytes(copy.read_bytes())
        alias = self.root / "checkout-alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(register.RegisterError, "symlink"):
            register.inspect(alias)

    def test_oversize_source_is_refused_before_unbounded_read(self):
        (self.root / NATIVE_OWNER).write_bytes(b"x" * (register.MAX_BYTES + 1))
        self.inspect_refuses("oversize")

    def test_ambiguous_json_and_oversized_manifest_refuse(self):
        raw = self.path.read_text()
        duplicate = raw.replace('"roles":', '"roles":{},"roles":', 1)
        self.path.write_text(duplicate)
        self.inspect_refuses("duplicate JSON")
        for bad in (b'{"x":NaN}', b'{"x":0.0}', b'{"x":"\\ud800"}', b"[]", b"\xff"):
            self.path.write_bytes(bad)
            self.inspect_refuses()
        self.path.write_bytes(b" " * (register.MAX_BYTES + 1))
        self.inspect_refuses("oversize")

    def test_cli_exit_zero_is_hold_and_bad_input_has_structured_refusal(self):
        result = self.run_cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.remains_unqualified(json.loads(result.stdout))
        self.data["primitives"]["sha512"]["query_budget"]["maximum"] = "128"
        self.write()
        result = self.run_cli()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(json.loads(result.stderr)["status"], "REFUSE")



class RetainedWitnessV6Tests(ContractCase):
    def test_original_receipt_component_is_required_without_effect_authority(self):
        data = manifest()
        for role in ("anchor-writer", "witness-response"):
            receipt = data["roles"][role]["implementations"]["rust-v6-receipted-register"]
            self.assertIn(register.NATIVE_WITNESS_RECEIPTS, receipt["source_paths"])
            self.assertIn("no-new-authority", receipt["validity_contract"])
            self.assertFalse(receipt["production_qualified"])
            changed = deepcopy(data)
            changed["roles"][role]["implementations"]["rust-v6-receipted-register"]["production_qualified"] = True
            self.refused(changed)
        for path in (register.NATIVE_WITNESS_RECEIPTS,
                     register.NODE + "tests/root_witness_v6_receipts_native.rs"):
            self.assertIn(path, data["source_files_sha256"])
            changed = deepcopy(data)
            del changed["source_files_sha256"][path]
            self.refused(changed)

    def test_receipt_caps_are_refusal_limits_without_pruning_or_query_claims(self):
        expected = {
            "native-witness-receipt-database-bytes-v6": "33554432",
            "native-witness-retained-receipts-v6": "128",
            "native-witness-receipt-record-bytes-v6": "196608",
        }
        for name, maximum in expected.items():
            data = manifest()
            cap = data["operational_refusal_caps"][name]
            self.assertEqual(cap["maximum"], maximum)
            self.assertFalse(cap["bounds_adversary_queries"])
            self.assertFalse(cap["permits_history_pruning"])
            self.assertFalse(cap["permits_lifetime_reset"])
            for field, value in (("maximum", "0"), ("bounds_adversary_queries", True),
                                 ("permits_history_pruning", True), ("permits_lifetime_reset", True)):
                changed = deepcopy(data)
                changed["operational_refusal_caps"][name][field] = value
                self.refused(changed)

    def test_receipt_hash_uses_share_the_original_unknown_sha512_lifetime(self):
        data = manifest()
        name = "native-retained-witness-receipts-v6"
        self.assertEqual(data["hash_uses"][name]["primitive_ids"], ["sha512"])
        self.assertIn(name, data["primitives"]["sha512"]["use_ids"])
        self.assertIsNone(data["primitives"]["sha512"]["query_budget"]["maximum"])
        self.assertIsNone(data["hash_uses"][name]["failure_bound"])
        changed = deepcopy(data)
        changed["hash_uses"][name]["source_paths"].remove(register.NATIVE_WITNESS_RECEIPTS)
        self.refused(changed)
        data["profiles"]["native_witness_receipt_archive_independence_verified"] = True
        self.refused(data)

if __name__ == "__main__":
    unittest.main()
