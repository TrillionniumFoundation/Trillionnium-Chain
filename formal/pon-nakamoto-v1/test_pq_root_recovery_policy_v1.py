#!/usr/bin/env python3
"""Counterexamples for a pure policy model; no signature or custody evidence."""
import copy
import hashlib
import io
import itertools
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout

import pq_root_recovery_policy_v1 as r


def rebind_claims(scenario):
    """Only update declared message IDs, never fabricate a real signature."""
    digest = r.statement_id(scenario["statement"])
    for row in scenario["approval_claims"]:
        row["statement_sha512"] = digest


def rebind_policy(scenario):
    digest = r.policy_id(scenario["policy"])
    scenario["statement"]["policy_sha512"] = digest
    scenario["context"]["anchor"]["policy_sha512"] = digest
    rebind_claims(scenario)


class RootRecoveryPolicyTests(unittest.TestCase):
    def setUp(self):
        self.scenario = r.example()

    def refuse(self, scenario=None, reason=None):
        result = r.inspect(self.scenario if scenario is None else scenario)
        self.assertFalse(result["model_checks_satisfied"])
        self.assertEqual(result["model_decision"], "REJECTED_SCENARIO")
        self.assertEqual(result["status"], "HOLD")
        self.assertFalse(result["authorization_granted"])
        if reason:
            self.assertEqual(result["reason"], reason)
        return result

    def test_all_five_paths_and_nine_distinct_quorums_remain_hold(self):
        combos = tuple(itertools.combinations(range(3), 2))
        for action, pair in itertools.product(r.ACTIONS, itertools.product(combos, repeat=2)):
            with self.subTest(action=action, pairs=pair):
                result = r.inspect(r.example(action, pair))
                self.assertTrue(result["model_checks_satisfied"])
                self.assertEqual(result["model_decision"], "HOLD_UNRESOLVED_SCENARIO")
                self.assertEqual(result["policy_paths_checked"], list(r.ACTIONS))
                self.assertEqual(result["approval_claims_checked"], 4)
                self.assertEqual(result["status"], "HOLD")
                self.assertFalse(result["signatures_verified"])
                self.assertFalse(result["root_effect_executed"])

    def test_a_recovery_or_path_poisoning_the_current_policy_is_refused_even_for_normal(self):
        for action in r.ACTIONS:
            scenario = r.example(action)
            scenario["policy"]["rules"]["recover"]["operator"] = "OR"
            self.refuse(scenario, "rule:operator")

    def test_every_path_must_have_and_and_both_families(self):
        for action in r.ACTIONS:
            for mode in ("missing-family", "or", "lower-quorum", "extra-alternative"):
                scenario = r.example()
                rule = scenario["policy"]["rules"][action]
                if mode == "missing-family":
                    rule["requirements"].pop()
                elif mode == "or":
                    rule["operator"] = "OR"
                elif mode == "lower-quorum":
                    rule["requirements"][0]["quorum"] = 1
                else:
                    rule["fallback"] = "ML-DSA-87"
                with self.subTest(action=action, mode=mode):
                    self.refuse(scenario)

    def test_missing_and_unknown_operation_routes_are_not_silently_ignored(self):
        del self.scenario["policy"]["rules"]["revoke"]
        self.refuse(reason="policy:actions:fields")
        scenario = r.example()
        scenario["policy"]["rules"]["emergency"] = copy.deepcopy(scenario["policy"]["rules"]["recover"])
        self.refuse(scenario, "policy:actions:fields")

    def test_weaker_or_unknown_parameter_sets_and_boolean_quorums_refuse(self):
        for suite in ("ML-DSA-65", "SLH-DSA-SHA2-128s", "unknown", "ML-DSA"):
            scenario = r.example()
            scenario["policy"]["rules"]["recover"]["requirements"][0]["suite"] = suite
            self.refuse(scenario, "rule:suite")
        for quorum in (True, False, 0, 1, 3, "2", 2.0):
            scenario = r.example()
            scenario["policy"]["rules"]["recover"]["requirements"][0]["quorum"] = quorum
            self.refuse(scenario, "rule:quorum")

    def test_rosters_require_exact_three_distinct_keys_and_no_cross_family_alias(self):
        for keys in (["01" * 64] * 3, ["01" * 64] * 2, ["01" * 64] * 4):
            scenario = r.example()
            scenario["policy"]["rosters"][r.SUITES[0]] = keys
            self.refuse(scenario)
        self.scenario["policy"]["rosters"][r.SUITES[1]][0] = "01" * 64
        self.refuse(reason="roster:cross-family-alias")

    def test_missing_family_cannot_be_replaced_by_extra_claims_from_the_other(self):
        for count in (0, 2, 3):
            scenario = r.example()
            scenario["approval_claims"] = scenario["approval_claims"][:count]
            self.refuse(scenario, "approval-claims:quorum")
        scenario = r.example()
        scenario["approval_claims"][2:] = copy.deepcopy(scenario["approval_claims"][:2])
        self.refuse(scenario, "approval-claims:distinct-family-quorum")

    def test_duplicate_unknown_cross_family_and_revoked_signers_refuse(self):
        duplicate = r.example()
        duplicate["approval_claims"][1] = copy.deepcopy(duplicate["approval_claims"][0])
        self.refuse(duplicate, "approval-claims:distinct-family-quorum")
        for value in ("ff" * 64, self.scenario["policy"]["rosters"][r.SUITES[1]][0]):
            scenario = r.example()
            scenario["approval_claims"][0]["signer_id"] = value
            self.refuse(scenario, "approval-claim:current-roster")
        self.scenario["context"]["revoked_signers"] = [self.scenario["approval_claims"][0]["signer_id"]]
        self.refuse(reason="approval-claim:revoked")

    def test_unknown_family_is_not_mapped_to_a_default_family(self):
        for family in ("SLH-DSA-SHA2-128s", "unknown", None, []):
            scenario = r.example()
            scenario["approval_claims"][0]["suite"] = family
            self.refuse(scenario, "approval-claim:suite")

    def test_all_claims_must_bind_the_same_complete_statement(self):
        other = r.example()
        other["statement"]["payload_hex"] = b"another requested root effect".hex()
        other_id = r.statement_id(other["statement"])
        self.scenario["approval_claims"][-1]["statement_sha512"] = other_id
        self.refuse(reason="approval-claim:cross-statement")

    def test_freshly_redeclared_stale_state_cannot_change_the_expected_context(self):
        changes = {"network": "99" * 32, "genesis": "99" * 32, "owner_generation": "6",
                   "key_epoch": "2", "previous_state": "99" * 64, "sequence": "40"}
        for field, value in changes.items():
            scenario = r.example()
            scenario["statement"][field] = value
            rebind_claims(scenario)
            self.refuse(scenario, "context-mismatch:" + field)

    def test_future_expired_inverted_and_noncanonical_windows_refuse(self):
        for now in ("99", "201"):
            scenario = r.example()
            scenario["context"]["now_height"] = now
            self.refuse(scenario, "statement:expired-or-future")
        for invalid in (True, "01", "-1", "18446744073709551616"):
            scenario = r.example()
            scenario["statement"]["sequence"] = invalid
            self.refuse(scenario, "sequence:u64")
        self.scenario["statement"]["valid_until"] = "99"
        self.refuse(reason="statement:validity-order")

    def test_anchor_mismatch_in_each_authority_dimension_refuses(self):
        changes = {"network": "99" * 32, "genesis": "99" * 32, "owner_generation": "6",
                   "key_epoch": "2", "previous_state": "99" * 64, "last_sequence": "39",
                   "policy_sha512": "99" * 64}
        for field, value in changes.items():
            scenario = r.example()
            scenario["context"]["anchor"][field] = value
            self.refuse(scenario, "anchor-mismatch:" + ("policy" if field == "policy_sha512" else field))

    def test_each_unknown_evidence_dimension_holds_even_if_other_scenarios_are_assumed(self):
        for name in r.OBSERVATIONS:
            scenario = r.example()
            scenario["context"]["observations"] = {n: "scenario-assumed" for n in r.OBSERVATIONS}
            scenario["context"]["observations"][name] = "unknown"
            result = r.inspect(scenario)
            self.assertEqual(result["unknown_scenario_observations"], [name])
            self.assertEqual(result["model_decision"], "HOLD_UNRESOLVED_SCENARIO")
            self.assertFalse(result["authorization_granted"])

    def test_self_reported_verified_true_is_not_an_evidence_input(self):
        for forged in (True, "verified", "attested", {"verified": True}):
            scenario = r.example()
            scenario["context"]["observations"]["independent-custody"] = forged
            self.refuse(scenario, "observations:unsupported-evidence-claim")
        self.scenario["context"]["observations"]["verified"] = True
        self.refuse(reason="observations:fields")

    def test_all_scenario_assumptions_never_promote_any_real_evidence_or_effect(self):
        self.scenario["context"]["observations"] = {n: "scenario-assumed" for n in r.OBSERVATIONS}
        result = r.inspect(self.scenario)
        self.assertEqual(result["model_decision"], "SCENARIO_CONSTRAINTS_SATISFIED")
        self.assertEqual(result["status"], "HOLD")
        for key in ("authorization_granted", "root_effect_executed", "activation_performed",
                    "production_qualified", "signatures_verified", "custody_verified",
                    "currentness_verified", "anchor_independence_verified",
                    "external_effects_reconciled", "history_persisted"):
            self.assertIs(result[key], False)
        self.assertIn("successor-key-possession-and-handoff", result["unresolved_real_obligations"])

    def test_successor_policy_must_preserve_all_paths_even_when_authorized_by_current_policy(self):
        for action in r.SUCCESSOR_ACTIONS:
            scenario = r.example(action)
            scenario["statement"]["next_policy"]["rules"]["recover"]["operator"] = "OR"
            self.refuse(scenario, "rule:operator")
        self.scenario["statement"]["next_policy"] = None
        self.refuse(reason="policy:fields")

    def test_new_roster_cannot_self_authorize_its_installation(self):
        successor = self.scenario["statement"]["next_policy"]
        successor["rosters"][r.SUITES[0]] = [f"{n:02x}" * 64 for n in (80, 81, 82)]
        rebind_claims(self.scenario)
        self.assertTrue(r.inspect(self.scenario)["model_checks_satisfied"])
        self.scenario["approval_claims"][0]["signer_id"] = successor["rosters"][r.SUITES[0]][0]
        self.refuse(reason="approval-claim:current-roster")

    def test_replay_and_same_nonce_different_intent_are_both_refused(self):
        oid = r.operation_id(self.scenario["statement"])
        self.scenario["context"]["history"] = [{"nonce": self.scenario["statement"]["nonce"], "operation_id": oid}]
        self.refuse(reason="history:nonce-reuse")
        self.scenario["statement"]["payload_hex"] = b"same nonce; changed intent".hex()
        rebind_claims(self.scenario)
        self.assertNotEqual(r.operation_id(self.scenario["statement"]), oid)
        self.refuse(reason="history:nonce-reuse")

    def test_recovery_or_epoch_advancement_does_not_clear_supplied_local_history(self):
        oid = r.operation_id(self.scenario["statement"])
        self.scenario["context"]["history"] = [{"nonce": self.scenario["statement"]["nonce"], "operation_id": oid}]
        for target in (self.scenario["statement"], self.scenario["context"], self.scenario["context"]["anchor"]):
            target["key_epoch"] = "4"
        rebind_claims(self.scenario)
        self.refuse(reason="history:nonce-reuse")

    def test_signature_bytes_and_selected_witnesses_do_not_define_operation_identity(self):
        identities = set()
        for pairs in itertools.product(itertools.combinations(range(3), 2), repeat=2):
            scenario = r.example("recover", pairs)
            identities.add(r.inspect(scenario)["operation_id"])
            scenario["approval_claims"].reverse()
            self.assertTrue(r.inspect(scenario)["model_checks_satisfied"])
            self.assertIn(r.inspect(scenario)["operation_id"], identities)
        self.assertEqual(len(identities), 1)
        self.scenario["approval_claims"][0]["signature_sha512"] = "99" * 64
        self.refuse(reason="approval-claim:fields")

    def test_action_nonce_epoch_payload_and_successor_bytes_change_statement_and_operation(self):
        original = self.scenario["statement"]
        for field, replacement in (("action", "rotate"), ("nonce", "55" * 32),
                                   ("key_epoch", "4"), ("payload_hex", b"replacement".hex())):
            changed = copy.deepcopy(original)
            changed[field] = replacement
            self.assertNotEqual(r.statement_id(changed), r.statement_id(original))
            self.assertNotEqual(r.operation_id(changed), r.operation_id(original))
        changed = copy.deepcopy(original)
        changed["next_policy"]["rosters"][r.SUITES[0]][2] = "20" * 64
        self.assertNotEqual(r.statement_id(changed), r.statement_id(original))

    def test_input_history_and_payload_bounds_are_refusal_not_silent_truncation(self):
        self.scenario["context"]["history"] = [{"nonce": f"{n:064x}", "operation_id": f"{n:0128x}"}
                                              for n in range(r.MAX_HISTORY)]
        self.assertTrue(r.inspect(self.scenario)["model_checks_satisfied"])
        self.scenario["context"]["history"].append({"nonce": "ff" * 32, "operation_id": "ff" * 64})
        self.refuse(reason="history:list")
        scenario = r.example()
        scenario["statement"]["payload_hex"] = "ff" * (r.MAX_PAYLOAD + 1)
        self.refuse(scenario, "statement:payload")

    def test_json_duplicate_keys_depth_nonfinite_and_utf8_refuse(self):
        bad = (b'{"a":1,"a":2}', b'{"a":1.5}', b'{"a":NaN}', b'"\xff"',
               b'{"a":"\\ud800"}', b'[' * 20 + b'0' + b']' * 20,
               b" " * (r.MAX_INPUT + 1))
        for raw in bad:
            with self.subTest(raw=raw[:30]), self.assertRaises(r.Reject):
                r.strict_json(raw)

    def test_research_domains_and_canonical_json_do_not_depend_on_wire_object_order(self):
        statement = self.scenario["statement"]
        reordered = dict(reversed(list(statement.items())))
        self.assertEqual(r.statement_bytes(statement), r.statement_bytes(reordered))
        self.assertTrue(r.statement_bytes(statement).startswith(r.STATEMENT_DOMAIN))
        self.assertEqual(r.statement_id(statement), hashlib.sha512(r.statement_bytes(statement)).hexdigest())
        # Exact fixture commitments pin this V1 encoding and its signed fields.
        self.assertEqual(r.policy_id(self.scenario["policy"]), "c16cf5a3b606ef399316117162fcff7a8ca8f0a4036d4e8823c02844b3448cb11753e9cba1d829fdc3ebba1b64e49c85f923349565419c82d4e1e003494f6f2d")
        self.assertEqual(r.statement_id(statement), "9c974056d3b0259aa17a22581d02872b48b1f8db52a008167e7f3fbb5ddf43500e06c8026a1dd221e28989465175a08226f9aa53cfc5200fcb414e62c5d44907")
        self.assertEqual(r.operation_id(statement), "813e650d553b03aee95ceec0bf31f4940d810efc8e7cfc742d162675a0827159a9c9e4bca58091b2ed57529a164e0053e627562a59d16ccf88e4fe2911070727")

    def test_cli_success_exit_is_only_a_hold_diagnostic_and_invalid_input_is_nonzero(self):
        stream = io.StringIO()
        with redirect_stdout(stream):
            self.assertEqual(r.main(["--example"]), 0)
        result = json.loads(stream.getvalue())
        self.assertEqual(result["status"], "HOLD")
        self.assertFalse(result["authorization_granted"])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.json"
            path.write_text('{"x":1,"x":2}')
            stream = io.StringIO()
            with redirect_stdout(stream):
                self.assertEqual(r.main(["--input", str(path)]), 1)
            self.assertEqual(json.loads(stream.getvalue())["status"], "HOLD")


if __name__ == "__main__":
    unittest.main()
