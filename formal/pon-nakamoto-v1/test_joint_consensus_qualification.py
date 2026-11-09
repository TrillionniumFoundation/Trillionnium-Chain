"""Defensive regressions for the joint research qualification boundary.

These controls alter local declarative inputs only. They do not generate
packets, mine forks, run a network, reproduce an exploit, or estimate risk.
"""
from contextlib import redirect_stdout
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest

import joint_consensus_qualification as q


class JointQualificationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="joint-qualification-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.original = json.loads((q.ROOT / q.MANIFEST).read_text())
        paths = set(q.SOURCE_PATHS) | {q.MANIFEST}
        paths.update(path for path, _ in q.OBLIGATIONS.values())
        for name in paths:
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((q.ROOT / name).read_bytes())

    def write(self, data):
        (self.root / q.MANIFEST).write_text(json.dumps(data))

    def reject(self, data, code):
        self.write(data)
        with self.assertRaisesRegex(q.QualificationError, code):
            q.inspect(self.root)

    def test_current_contract_keeps_all_actual_probabilities_unknown(self):
        report = q.inspect(self.root)
        self.assertEqual(report["contract_validation"], "PASS")
        self.assertEqual(report["qualification"], "HOLD_NO_GO")
        self.assertEqual(report["source_files_checked"], 23)
        self.assertEqual(report["unknown_parameter_count"], 18)
        self.assertEqual(len(report["open_obligations"]), 13)
        self.assertEqual(len(report["fixed_probability_research_contract"]["unknown_cost_points"]), 16)
        for key in ("actual_lifetime_failure_bound", "common_prefix_failure_bound",
                    "chain_growth_failure_bound", "chain_quality_failure_bound",
                    "six_confirmations_failure_bound"):
            self.assertIsNone(report[key])
        for key in ("security_probability_calibrated", "native_execution_performed",
                    "native_semantics_formally_verified", "current_repository_ancestry_verified",
                    "full_build_closure_verified", "production_activation", "finalized",
                    "execution_authority"):
            self.assertIs(report[key], False)

    def test_both_owner_implementations_and_work_relation_are_bound(self):
        pins = q.inspect(self.root)["source_sha256"]
        for path in (
            "trillionnium/crates/trnm-pon-node/src/consensus.rs",
            "trillionnium/crates/trnm-pon-node/src/store.rs",
            "trillionnium/crates/trnm-pon-node/src/store/growth/confirmation.rs",
            "trillionnium/crates/trnm-pon-node/src/store/growth/recovery.rs",
            "trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs",
        ):
            self.assertIn(path, pins)
            self.assertEqual(pins[path], hashlib.sha256((self.root / path).read_bytes()).hexdigest())

    def test_every_open_obligation_is_mandatory(self):
        for name in self.original["obligations"]:
            with self.subTest(name=name):
                data = deepcopy(self.original)
                del data["obligations"][name]
                self.reject(data, "OBLIGATION_ROSTER")

    def test_declaring_an_obligation_proved_does_not_promote_it(self):
        for name in self.original["obligations"]:
            with self.subTest(name=name):
                data = deepcopy(self.original)
                data["obligations"][name]["status"] = "proved"
                self.reject(data, "UNPROVED_OBLIGATION")

    def test_all_unknown_environment_inputs_reject_invented_numbers(self):
        for group, values in self.original["unknown_parameters"].items():
            for name in values:
                with self.subTest(group=group, name=name):
                    data = deepcopy(self.original)
                    data["unknown_parameters"][group][name] = 0
                    self.reject(data, "UNPROVED_ENVIRONMENT_PARAMETER")

    def test_true_is_not_an_authenticated_environment_assumption(self):
        data = deepcopy(self.original)
        data["unknown_parameters"]["clocks"]["wall_clock_skew_and_drift_bound"] = True
        self.reject(data, "UNPROVED_ENVIRONMENT_PARAMETER")

    def test_common_prefix_growth_quality_bounds_cannot_be_self_assigned(self):
        for key in ("common_prefix", "chain_growth", "chain_quality"):
            with self.subTest(key=key):
                data = deepcopy(self.original)
                data["properties"][key]["failure_bound"] = {"numerator": 1, "denominator": 1000000}
                self.reject(data, "UNPROVED_PROPERTY")

    def test_credit_quality_is_not_count_quality(self):
        data = deepcopy(self.original)
        data["properties"]["block_count_quality"]["derived_from_credit_quality"] = True
        self.reject(data, "UNPROVED_PROPERTY")

    def test_chain_growth_is_not_business_liveness(self):
        data = deepcopy(self.original)
        data["properties"]["business_liveness"]["derived_from_chain_growth"] = True
        self.reject(data, "UNPROVED_PROPERTY")

    def test_native_metrics_cannot_be_silently_changed(self):
        data = deepcopy(self.original)
        data["properties"]["chain_quality"]["metric"] = "honest-block-count-fraction"
        self.reject(data, "UNPROVED_PROPERTY")

    def test_six_successors_exclude_inclusion_work(self):
        semantics = q.inspect(self.root)["native_semantics"]
        self.assertEqual(semantics["confirmation_depth_counts"], "successors-excluding-inclusion-block")
        self.assertEqual(semantics["confirmation_work_counts"], "tip-chainwork-minus-inclusion-chainwork")
        self.assertEqual(semantics["confirmation_work_threshold_basis"], "included-block-required-work")
        self.assertIs(semantics["confirmation_requires_both_thresholds"], True)
        data = deepcopy(self.original)
        data["native_semantics"]["confirmation_depth_counts"] = "including-inclusion-block"
        self.reject(data, "NATIVE_SEMANTICS")

    def test_height_only_confirmation_is_refused(self):
        data = deepcopy(self.original)
        data["native_semantics"]["confirmation_requires_both_thresholds"] = False
        self.reject(data, "NATIVE_SEMANTICS")

    def test_header_time_is_not_a_real_cost_clock(self):
        data = deepcopy(self.original)
        data["native_semantics"]["header_time_certifies_elapsed_work"] = True
        self.reject(data, "NATIVE_SEMANTICS")

    def test_sqrt_credit_cannot_be_substituted(self):
        data = deepcopy(self.original)
        data["native_semantics"]["credit_formula"] = "sqrt(floor(2^256/(T+1)))"
        self.reject(data, "NATIVE_SEMANTICS")

    def test_scalar_honest_majority_cannot_be_inserted(self):
        data = deepcopy(self.original)
        data["unknown_parameters"]["participation"]["honest_majority"] = True
        self.reject(data, "UNPROVED_ENVIRONMENT_PARAMETER")

    def test_numeric_lifetime_bound_is_refused_even_if_zero(self):
        for value in (0, 1, True, {"numerator": 1, "denominator": 1000000}):
            with self.subTest(value=value):
                data = deepcopy(self.original)
                data["actual_lifetime_failure_bound"] = value
                self.reject(data, "UNPROVED_LIFETIME_BOUND")

    def test_boolean_and_integer_promotions_are_distinct(self):
        for key in ("security_probability_calibrated", "production_activation"):
            for value in (True, 0, 1, None):
                with self.subTest(key=key, value=value):
                    data = deepcopy(self.original)
                    data[key] = value
                    self.reject(data, "UNSUPPORTED_PROMOTION")

    def test_runtime_finality_and_authority_are_not_granted(self):
        for key in ("finalized", "execution_authority"):
            data = deepcopy(self.original)
            data["native_semantics"][key] = True
            self.reject(data, "NATIVE_SEMANTICS")

    def test_qualified_status_is_refused(self):
        data = deepcopy(self.original)
        data["qualification"] = "PASS"
        self.reject(data, "UNSUPPORTED_QUALIFICATION")

    def test_unknown_schema_or_extra_claim_is_refused(self):
        data = deepcopy(self.original)
        data["schema"] = "trnm-joint-consensus-qualification-v2"
        self.reject(data, "CONTRACT_SCHEMA")
        data = deepcopy(self.original)
        data["six_confirmations_failure_bound"] = 0
        self.reject(data, "CONTRACT_FIELDS")

    def test_changed_native_owner_is_refused(self):
        for path in ("trillionnium/crates/trnm-pon-node/src/store.rs",
                     "trillionnium/crates/trnm-pon-node/src/store/growth/confirmation.rs"):
            source = self.root / path
            original = source.read_bytes()
            source.write_bytes(original + b"\n// changed source\n")
            with self.assertRaisesRegex(q.QualificationError, "SOURCE_DIGEST_MISMATCH"):
                q.inspect(self.root)
            source.write_bytes(original)

    def test_missing_owner_pin_or_extra_source_pin_is_refused(self):
        data = deepcopy(self.original)
        del data["source_sha256"]["trillionnium/crates/trnm-pon-node/src/store/growth/confirmation.rs"]
        self.reject(data, "SOURCE_ROSTER")
        data = deepcopy(self.original)
        data["source_sha256"]["different-profile.rs"] = "0" * 64
        self.reject(data, "SOURCE_ROSTER")

    def test_source_digest_format_and_missing_file_are_refused(self):
        data = deepcopy(self.original)
        data["source_sha256"][q.DEVNET] = "UNKNOWN"
        self.reject(data, "SOURCE_DIGEST_FORMAT")
        self.write(self.original)
        (self.root / q.DEVNET).unlink()
        with self.assertRaises(q.QualificationError):
            q.inspect(self.root)

    def test_repinning_changed_development_threshold_still_fails(self):
        path = self.root / q.DEVNET
        dev = json.loads(path.read_text())
        dev["confirmation_depth"] = 1
        path.write_text(json.dumps(dev))
        data = deepcopy(self.original)
        data["source_sha256"][q.DEVNET] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.reject(data, "REVIEWED_SOURCE_MAP")

    def test_parameter_manifest_cannot_override_installed_policy(self):
        data = deepcopy(self.original)
        data["parameters"]["confirmation_work_multiplier"] = 1
        self.reject(data, "PARAMETER_CONTRACT")

    def test_cost_model_remains_unproved_after_joint_source_repin(self):
        path = self.root / q.COST_CONTRACT
        cost = json.loads(path.read_text())
        cost["cost_envelopes"]["quantum"][0]["lower"] = 0
        path.write_text(json.dumps(cost))
        data = deepcopy(self.original)
        data["source_sha256"][q.COST_CONTRACT] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.reject(data, "REVIEWED_SOURCE_MAP")

    def test_cost_scope_cannot_be_promoted_to_native_credit(self):
        path = self.root / q.COST_CONTRACT
        cost = json.loads(path.read_text())
        cost["relation"]["native_consensus_credit"] = True
        path.write_text(json.dumps(cost))
        data = deepcopy(self.original)
        data["source_sha256"][q.COST_CONTRACT] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.reject(data, "REVIEWED_SOURCE_MAP")

    def test_repinning_native_source_requires_separate_checker_review(self):
        path = "trillionnium/crates/trnm-pon-node/src/consensus.rs"
        target = self.root / path
        target.write_bytes(target.read_bytes() + b"\n// changed source\n")
        data = deepcopy(self.original)
        data["source_sha256"][path] = hashlib.sha256(target.read_bytes()).hexdigest()
        self.reject(data, "REVIEWED_SOURCE_MAP")

    def test_actual_source_activation_flags_are_independently_checked(self):
        blobs = {path: (self.root / path).read_bytes() for path in q.SOURCE_PATHS}
        q.check_development_claims(blobs)
        for path, key in (("config/consensus-mainline.json", "release_ready"),
                          ("config/pon-nakamoto-v1.json", "production_consensus_activation"),
                          ("config/pon/work-profile-v1.json", "production_eligible")):
            data = json.loads(blobs[path])
            data[key] = True
            changed = dict(blobs)
            changed[path] = json.dumps(data).encode()
            with self.assertRaisesRegex(q.QualificationError, "ACTUAL_UNSUPPORTED_PROMOTION"):
                q.check_development_claims(changed)

    def test_actual_active_owner_cannot_be_created_by_json(self):
        blobs = {path: (self.root / path).read_bytes() for path in q.SOURCE_PATHS}
        data = json.loads(blobs["PROJECT_BOUNDARY.json"])
        data["consensus"]["active_implementation"] = "claimed-native-owner"
        blobs["PROJECT_BOUNDARY.json"] = json.dumps(data).encode()
        with self.assertRaisesRegex(q.QualificationError, "ACTUAL_ACTIVE_IMPLEMENTATION"):
            q.check_development_claims(blobs)

    def test_duplicate_json_float_nonfinite_and_oversize_are_refused(self):
        invalid = (b'{"a":1,"a":2}', b'{"a":0.01}', b'{"a":NaN}',
                   b'{"a":Infinity}', b'{"a":123456789012345678901}',
                   b'[' + b' ' * q.MAX_JSON_BYTES + b']', b'[]', b'{"a":"\\ud800"}')
        for raw in invalid:
            with self.subTest(raw=raw[:50]), self.assertRaises(q.QualificationError):
                q.strict_json(raw)

    def test_incomplete_model_contract_reference_fails(self):
        path = self.root / self.original["obligations"]["dynamic-participation"]["contract"]
        path.unlink()
        with self.assertRaises(q.QualificationError):
            q.inspect(self.root)

    def test_bound_scope_is_not_full_binary_closure(self):
        data = deepcopy(self.original)
        data["source_binding_scope"] = "complete-native-build-and-runtime"
        self.reject(data, "SOURCE_SCOPE")

    def test_cli_has_distinct_check_and_qualification_exit_codes(self):
        with redirect_stdout(io.StringIO()) as output:
            code = q.main(["--root", str(self.root), "--check"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["qualification"], "HOLD_NO_GO")
        with redirect_stdout(io.StringIO()) as output:
            code = q.main(["--root", str(self.root), "--require-qualified"])
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(output.getvalue())["qualification_request"],
                         "REFUSED_UNPROVED_JOINT_CONSENSUS")
        (self.root / q.MANIFEST).write_bytes(b'{}')
        with redirect_stdout(io.StringIO()) as output:
            code = q.main(["--root", str(self.root), "--check"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())["contract_validation"], "FAIL")


if __name__ == "__main__":
    unittest.main()
