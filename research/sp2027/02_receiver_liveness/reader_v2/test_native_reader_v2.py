"""Synthetic endpoint controls only; these are not native experiment results."""
import copy
import hashlib
import unittest

import native_reader_v2 as v2

T = 4_000_000_000


def observed():
    return {"confirmed": True, "transaction": "tx", "included_block": "block",
            "policy": "installed-depth-and-required-work", "depth": 6,
            "work_delta": "0c", "required_work_delta": "0c", "execution_authority": False}


def native_row(when, gate):
    return {"transaction": "tx", "included_block": "block", "ended_ns": when,
            "confirmed_inside_pressure_window": gate, "observation": observed()}


def consumer_sample(when, gate):
    """Minimum explicit mapping into the actually retained Agent06 consumer."""
    run = {"run_id": "synthetic", "chain_instance_id": "synthetic-ledger",
           "profile_id": "synthetic-boundary-validation", "clock_id": "synthetic-epoch",
           "observer_id": "synthetic-independent-client", "window_start_ns": 0,
           "window_end_ns": T, "event_coverage_complete": True,
           "identity": {"source_commit": None, "source_tree": None,
                        "binary_sha256": None, "config_sha256": None},
           "confirmation_policy": {"policy_id": "installed-depth-and-required-work",
                                   "min_depth": 6, "required_work_delta": "0c",
                                   "semantics": "first_observed", "window_end_rule": "exclusive",
                                   "require_native_window_gate": True}}
    contract = {"schema": "sp27-confirmed-goodput-contract-v1",
                "evidence_scope": "synthetic_validation", "runs": [run]}
    operation = {"operation_id": "op", "run_id": "synthetic", "scheduled_ns": 0,
                 "deadline_ns": T, "transaction_ids": ["tx"], "expected_block_id": "block",
                 "content_id": None, "useful_compute_id": None, "useful_compute_evidence": None,
                 "plan_provenance": "synthetic edge test; no experiment"}
    event = {"event_id": "confirmation", "run_id": "synthetic", "operation_id": "op",
             "type": "confirmation", "at_ns": when, "clock_id": "synthetic-epoch",
             "actor_id": "synthetic-independent-client", "attempt_id": "attempt",
             "transaction_id": "tx", "block_id": "block",
             "policy_id": "installed-depth-and-required-work", "depth": 6,
             "work_delta": "0c", "required_work_delta": "0c", "execution_authority": False,
             "flags": {k: True for k in ["full_verification", "admission", "host", "history", "activation"]},
             "provenance": {"artifact_sha256": "0" * 64, "member": "synthetic", "pointer": "/observation"}}
    if gate is not None:
        event["native_window_gate"] = gate
    return contract, [operation], [event]


class NativeEndpointV2(unittest.TestCase):
    def test_original_reader_bytes_are_retained_exactly(self):
        path = v2.HERE / "frozen" / v2.FROZEN["legacy"][0]
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), v2.FROZEN["legacy"][1])

    def test_t_minus_one_t_and_t_plus_one_with_native_gate(self):
        lib = v2.get_reader()
        for when, gate, expected in [(T - 1, True, True), (T, False, False),
                                     (T + 1, False, False)]:
            with self.subTest(when=when):
                self.assertEqual(lib.is_native_confirmation(native_row(when, gate), T), expected)

    def test_original_inclusive_behavior_remains_replayable(self):
        row = native_row(T, False)
        self.assertTrue(v2.get_reader(version=1).is_native_confirmation(row, T))
        self.assertFalse(v2.get_reader(version=2).is_native_confirmation(row, T))

    def test_endpoint_before_t_does_not_override_false_final_gate(self):
        row = native_row(T - 1, False)
        untouched = copy.deepcopy(row)
        decision = v2.window_decision(row["observation"], row["ended_ns"], T,
                                      row["confirmed_inside_pressure_window"])
        self.assertTrue(decision["observed_confirmed"])
        self.assertTrue(decision["endpoint_before_window_end"])
        self.assertFalse(decision["confirmed_in_window"])
        self.assertEqual(decision["recorded_endpoint_ns"], T - 1)
        self.assertEqual(decision["exclusion_reasons"], ["NATIVE_GATE_FALSE"])
        self.assertEqual(row, untouched)

    def test_missing_final_gate_remains_unknown_without_credit(self):
        decision = v2.window_decision(observed(), T - 1, T, None)
        self.assertEqual(decision["status"], "UNKNOWN")
        self.assertIsNone(decision["native_window_gate"])
        self.assertFalse(decision["confirmed_in_window"])

    def test_impossible_positive_gate_is_refused(self):
        for when in [T, T + 1, None]:
            with self.subTest(when=when), self.assertRaisesRegex(ValueError, "NATIVE_GATE_CLOCK_CONTRADICTION"):
                v2.window_decision(observed(), when, T, True)
        with self.assertRaisesRegex(ValueError, "NATIVE_GATE_WITHOUT_CONFIRMATION"):
            v2.window_decision(None, T - 1, T, True)

    def test_booleans_floats_and_numeric_gate_are_not_clocks_or_booleans(self):
        for when in [True, 1.0, -1]:
            with self.subTest(when=when), self.assertRaisesRegex(ValueError, "ENDPOINT_TYPE"):
                v2.window_decision(observed(), when, T, False)
        with self.assertRaisesRegex(ValueError, "NATIVE_GATE_TYPE"):
            v2.window_decision(observed(), T - 1, T, 1)

    def test_existing_identity_and_policy_checks_still_refuse_substitution(self):
        for field, value, error in [("transaction", "wrong", "TRANSACTION_BINDING"),
                                    ("included_block", "wrong", "BLOCK_BINDING"),
                                    ("policy", "wrong", "CONFIRMATION_POLICY"),
                                    ("depth", 5, "DEPTH_WORK"),
                                    ("execution_authority", True, "OBSERVATION_AUTHORITY")]:
            row = native_row(T - 1, True)
            row["observation"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, error):
                v2.get_reader().is_native_confirmation(row, T)

    def test_frozen_06_consumer_agrees_for_all_required_edge_cases(self):
        analyzer = v2.load_frozen("analyzer")
        for when, gate, expected in [(T - 1, True, True), (T, False, False),
                                     (T + 1, False, False), (T - 1, False, False),
                                     (T - 1, None, False)]:
            with self.subTest(when=when, gate=gate):
                result = analyzer.analyze(*consumer_sample(when, gate))
                operation = result["operations"][0]
                self.assertEqual(operation["confirmed_in_window"], expected)
                self.assertEqual(operation["confirmation_ns"], when)
                self.assertEqual(result["runs"][0]["planned_operations"], 1)
                if gate is not True:
                    self.assertTrue(operation["native_window_gate_failed"])
                self.assertEqual(operation["confirmed_in_window"],
                                 v2.window_decision(observed(), when, T, gate)["confirmed_in_window"])

    def test_resource_interval_endpoint_is_not_a_confirmation_endpoint(self):
        # The existing interval is [started, ended), so an ended==T span may be
        # wholly in the window. This change must not globally replace <= by <.
        result = v2.get_reader().interval_summary([{"started_ns": 0, "ended_ns": T}], T)
        self.assertEqual(result["ended_inside_window"], 1)
        self.assertIsNone(result["cpu_inside_window_ns"])


if __name__ == "__main__":
    unittest.main()
