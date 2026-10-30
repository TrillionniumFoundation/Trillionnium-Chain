#!/usr/bin/env python3
"""Synthetic fresh-caller reader controls; never native pressure evidence."""
import copy
import unittest
from unittest import mock

import check_pure_pon_fresh_caller_v1 as reader
import test_check_pure_pon_pressure_v2 as old


def fixture():
    prepared = old.prepared()
    business = old.reader.preparation(prepared)
    prepared["schema"] = reader.SCHEMA
    phases = [old.phase(name, business) for name in old.reader.PHASES]
    for phase in phases:
        phase["schema"] = reader.SCHEMA
        callers = {item["body"]: reader.public_key(bytes([73]) * 32) for item in business}
        for wrapper in phase["actors"]:
            wrapper["report"]["schema"] = reader.SCHEMA
            actor = wrapper["report"]["result"]
            for row in actor["calls"]:
                row["caller_public_key"] = reader.caller_key(phase["phase"], actor["actor"], row["sequence"])
                callers[row["body_digest"]] = row["caller_public_key"]
        for capture in phase["observations"]:
            capture["snapshot"]["schema"] = reader.OBSERVATION_SCHEMA
            for row in capture["snapshot"]["records"]:
                row["authenticated_caller"] = callers[bytes(row["body_digest"]).hex()]
                row["dispatch_started"] = True
    manifest = {"schema": reader.SCHEMA, "window_ns": old.reader.WINDOW, "attackers": 24,
                "actor_call_cap": 480, "rounds": 3, "policy": old.policy(),
                "phases": [{"phase": name, "file": name + ".json", "all_rounds_confirmed": True}
                           for name in old.reader.PHASES], "public_fairness_qualified": False,
                "production_qualified": False, "work_hardness_qualified": False,
                "installation_authorized": False}
    return manifest, prepared, phases


class FreshCallerControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = fixture()

    def test_independent_vector_and_phase_actor_sequence_separation(self):
        self.assertEqual(reader.caller_key("from-zero", 0, 0), reader.KEY_VECTOR)
        keys = {reader.caller_key(phase, actor, sequence)
                for phase in old.reader.PHASES[1:] for actor in range(24) for sequence in range(3)}
        self.assertEqual(len(keys), 144)
        self.assertEqual(reader.check_environment()["cryptography_version"], "50.0.2")

    def test_complete_synthetic_fixture_preserves_original_contract_and_counts(self):
        manifest, prepared, phases = copy.deepcopy(self.base)
        before = copy.deepcopy((manifest, prepared, phases))
        result = reader.check(manifest, prepared, phases)
        self.assertEqual((manifest, prepared, phases), before)
        self.assertTrue(result["finite_qualification"])
        self.assertTrue(result["original_pressure_qualification"]["finite_qualification"])
        for row in result["phases"][1:]:
            self.assertEqual(row["authenticated_distinct_attack_callers"], 72)
            self.assertEqual(row["minimum_authenticated_distinct_attack_callers"], 65)
            self.assertEqual(row["offered_honest_bodies"], 21)
            self.assertEqual(row["honest_submission_retries"], 0)
        self.assertFalse(result["public_fairness_qualified"])
        self.assertFalse(result["work_hardness_qualified"])

    def test_legacy_raw_or_observer_namespace_cannot_be_relabelled(self):
        for target in ("campaign", "prepared", "phase", "actor", "observer"):
            with self.subTest(target=target):
                m, p, phases = copy.deepcopy(self.base)
                value = {"campaign": m, "prepared": p, "phase": phases[1],
                         "actor": phases[1]["actors"][0]["report"],
                         "observer": phases[1]["observations"][0]["snapshot"]}[target]
                value["schema"] = old.reader.SCHEMA
                with self.assertRaisesRegex(ValueError, "namespace|v4 observation"):
                    reader.check(m, p, phases)

    def test_claimed_key_cannot_replace_independent_key(self):
        for key in ("00" * 32, reader.caller_key("correct-product-false-trace", 0, 0),
                    reader.caller_key("from-zero", 1, 0), reader.caller_key("from-zero", 0, 1)):
            with self.subTest(key=key):
                m, p, phases = copy.deepcopy(self.base)
                phases[1]["actors"][0]["report"]["result"]["calls"][0]["caller_public_key"] = key
                with self.assertRaisesRegex(ValueError, "independently derived"):
                    reader.check(m, p, phases)

    def test_actual_signature_caller_must_bind_its_own_body(self):
        for key in ("00" * 32, reader.caller_key("from-zero", 0, 1),
                    reader.public_key(bytes([73]) * 32)):
            with self.subTest(key=key):
                m, p, phases = copy.deepcopy(self.base)
                phases[1]["observations"][0]["snapshot"]["records"][0]["authenticated_caller"] = key
                with self.assertRaisesRegex(ValueError, "caller/attack body"):
                    reader.check(m, p, phases)

    def test_hello_claim_does_not_count_as_authentication_for_dispatch(self):
        m, p, phases = copy.deepcopy(self.base)
        row = phases[1]["observations"][0]["snapshot"]["records"][0]
        row["claimed_caller"] = row.pop("authenticated_caller")
        with self.assertRaisesRegex(ValueError, "dispatch without authenticated"):
            reader.check(m, p, phases)

    def test_64_actually_authenticated_callers_does_not_satisfy_65_gate(self):
        m, p, phases = copy.deepcopy(self.base)
        phase = phases[1]
        snapshot = phase["observations"][0]["snapshot"]
        removed = {row["connection_id"] for row in snapshot["records"][:8]}
        snapshot["records"] = snapshot["records"][8:]
        snapshot["accepted_connections_seen"] -= 8
        for round_ in phase["rounds"]:
            for side in ("hostile_before", "hostile_after"):
                round_[side]["rejections"] = [row for row in round_[side]["rejections"]
                                               if row["listener"] != 0 or row["connection_id"] not in removed]
        result = reader.check(m, p, phases)
        self.assertTrue(result["original_pressure_qualification"]["finite_qualification"])
        self.assertEqual(result["phases"][1]["authenticated_distinct_attack_callers"], 64)
        self.assertFalse(result["phases"][1]["fresh_caller_coverage_qualified"])
        self.assertFalse(result["finite_qualification"])

    def test_original_window_deadline_and_cpu_envelope_still_reject_mutation(self):
        for target in ("window", "deadline", "cpu"):
            with self.subTest(target=target):
                m, p, phases = copy.deepcopy(self.base)
                if target == "window": m["window_ns"] += 1
                elif target == "deadline": phases[1]["actors"][0]["report"]["result"]["calls"][0]["deadline_ns"] += 1
                else: phases[1]["initial_budget"]["burst_ns"] += 1
                with self.assertRaises(ValueError):
                    reader.check(m, p, phases)

    def test_original_service_failure_cannot_be_overruled_by_caller_coverage(self):
        m, p, phases = copy.deepcopy(self.base)
        phase = phases[0]
        phase["rounds"][2]["observation"]["confirmed"] = False
        phase["rounds"][2]["confirmed_inside_pressure_window"] = False
        m["phases"][0]["all_rounds_confirmed"] = False
        result = reader.check(m, p, phases)
        self.assertTrue(all(row["fresh_caller_coverage_qualified"] for row in result["phases"]))
        self.assertFalse(result["finite_qualification"])

    def test_dependency_version_mismatch_fails_closed(self):
        with mock.patch("cryptography.__version__", "50.0.1"):
            with self.assertRaisesRegex(ValueError, "pinned cryptography"):
                reader.check_environment()


if __name__ == "__main__":
    unittest.main()
