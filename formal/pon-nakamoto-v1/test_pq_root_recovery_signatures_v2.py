#!/usr/bin/env python3
"""Structure and refusal tests; synthetic keys here are never native evidence."""
from __future__ import annotations

import copy
import time
import unittest
from unittest.mock import patch

from pq_operation_budget import BudgetExpired, OperationBudget
import pq_root_recovery_policy_v1 as model
import pq_root_recovery_signatures_v2 as native


def fixture(action="normal", offset=0):
    """Structurally valid public placeholders only; no private keys exist."""
    scenario = model.example(action)
    keys = {}
    for family, suite in enumerate(native.SUITES):
        roster = []
        for member in range(3):
            public = native.SPKI_PREFIX[suite] + bytes([1 + offset + 3 * family + member]) * native.PUBLIC_KEY_BYTES[suite]
            signer = native.key_id(suite, public)
            keys[signer] = public
            roster.append(signer)
        scenario["policy"]["rosters"][suite] = sorted(roster)
    policy_hash = model.policy_id(scenario["policy"])
    scenario["context"]["anchor"]["policy_sha512"] = policy_hash
    scenario["statement"]["policy_sha512"] = policy_hash
    if action in model.SUCCESSOR_ACTIONS:
        scenario["statement"]["next_policy"] = copy.deepcopy(scenario["policy"])
    return scenario, keys


def placeholder_rows(policy, per_family=2):
    return [{"suite": suite, "signer_id": signer,
             "signature_hex": "00" * native.SIGNATURE_BYTES[suite]}
            for suite in native.SUITES for signer in policy["rosters"][suite][:per_family]]


class RootNativeStructureTests(unittest.TestCase):
    def rejected_without_backend(self, action="normal", mutate=lambda s, k, a, p: None):
        scenario, keys = fixture(action)
        approvals = placeholder_rows(scenario["policy"])
        possessions = placeholder_rows(scenario["policy"], 3) if action in model.SUCCESSOR_ACTIONS else None
        mutate(scenario, keys, approvals, possessions)
        with patch.object(native.backend, "run", side_effect=AssertionError("invalid input reached backend")):
            with self.assertRaises(native.Reject):
                native.verified_statement(scenario["policy"], scenario["context"], scenario["statement"],
                                          keys, approvals,
                                          successor_public_keys=keys if possessions is not None else None,
                                          successor_possessions=possessions)

    def test_spki_sizes_and_suite_framed_identity(self):
        expected = {
            "ML-DSA-87": "8cb73b95ed11db62bd766173b0aa8a9324be7659b74270820b245d94aee704df7"
                         "430a747f30a5091259137089e5973a120a882c9e32ce9dc78b976e9eabf5cb9",
            "SLH-DSA-SHA2-256s": "4a92a3e724352652516a769c3b8c0071d6564dc24d2feef7995f7526545a19eb"
                                 "86b3b2524fcf22e0a72c547fefb5900796a432341b9d08c1a730c6ac660841c0",
        }
        for suite in native.SUITES:
            raw = native.SPKI_PREFIX[suite] + bytes([1]) * native.PUBLIC_KEY_BYTES[suite]
            self.assertEqual(native.key_id(suite, raw), expected[suite])
            self.assertNotEqual(native.key_id(suite, raw), native.key_id(suite, raw[:-1] + b"\x02"))
        self.assertEqual(len(native.SPKI_PREFIX["ML-DSA-87"]) + native.PUBLIC_KEY_BYTES["ML-DSA-87"], 2614)
        self.assertEqual(len(native.SPKI_PREFIX["SLH-DSA-SHA2-256s"]) + native.PUBLIC_KEY_BYTES["SLH-DSA-SHA2-256s"], 82)

    def test_spki_same_length_shake_oid_is_rejected(self):
        suite = "SLH-DSA-SHA2-256s"
        wrong = bytes.fromhex("3050300b060960864801650304031e034100") + b"\x01" * 64
        with self.assertRaisesRegex(native.Reject, "algorithm-or-encoding"):
            native.key_id(suite, wrong)

    def test_noncanonical_or_trailing_spki_and_unknown_suite_rejected(self):
        for suite in native.SUITES:
            public = native.SPKI_PREFIX[suite] + b"\x01" * native.PUBLIC_KEY_BYTES[suite]
            for wrong in (public[1:], public + b"\x00", bytearray(public), public[:2] + b"\x00" + public[3:]):
                with self.subTest(suite=suite, wrong_type=type(wrong).__name__):
                    with self.assertRaises(native.Reject):
                        native.key_id(suite, wrong)
        for suite in ("ML-DSA-65", "SLH-DSA-SHAKE-256s", "", None):
            with self.assertRaises(native.Reject):
                native.key_id(suite, b"")

    def test_roster_requires_all_six_and_no_extra_key(self):
        scenario, keys = fixture()
        self.assertEqual(native.validate_roster(scenario["policy"], keys), keys)
        for change in (lambda m: m.pop(next(iter(m))), lambda m: m.update({"ff" * 64: b""})):
            candidate = dict(keys)
            change(candidate)
            with self.assertRaises(native.Reject):
                native.validate_roster(scenario["policy"], candidate)

    def test_unused_third_key_cannot_be_mislabeled_or_omitted(self):
        def mutate(s, keys, _a, _p):
            unused = s["policy"]["rosters"][native.SUITES[1]][2]
            keys[unused] = keys[unused][:-1] + b"\xff"
        self.rejected_without_backend(mutate=mutate)

    def test_whole_policy_checks_every_inactive_path(self):
        for action in model.ACTIONS:
            with self.subTest(action=action):
                self.rejected_without_backend(mutate=lambda s, _k, _a, _p:
                    s["policy"]["rules"][action].update(operator="OR"))

    def test_statement_frame_has_full_maximum_payload_and_successor(self):
        scenario, _ = fixture("recover")
        statement = scenario["statement"]
        statement["payload_hex"] = "ac" * model.MAX_PAYLOAD
        serialized = model.statement_bytes(statement)
        message = native.approval_message(statement)
        self.assertEqual(message, native.APPROVAL_DOMAIN + len(serialized).to_bytes(8, "big") + serialized)
        self.assertGreater(len(message), 8192)
        self.assertLessEqual(len(message), native.MAX_MESSAGE)
        for suite in native.SUITES:
            for signer in statement["next_policy"]["rosters"][suite]:
                possession = native.possession_message(statement, suite, signer)
                self.assertIn(serialized, possession)
                self.assertLessEqual(len(possession), native.MAX_MESSAGE)
        changed = copy.deepcopy(statement)
        changed["payload_hex"] = changed["payload_hex"][:-2] + "ad"
        self.assertNotEqual(message, native.approval_message(changed))
        self.assertNotEqual(native.operation_id(statement), native.operation_id(changed))

    def test_all_actions_have_distinct_native_identity(self):
        messages = [native.approval_message(fixture(action)[0]["statement"]) for action in model.ACTIONS]
        self.assertEqual(len(set(messages)), 5)
        statement = fixture()[0]["statement"]
        self.assertNotEqual(native.operation_id(statement), model.operation_id(statement))
        self.assertNotEqual(native.statement_id(statement), model.statement_id(statement))

    def test_quorum_selection_is_not_part_of_operation_identity(self):
        scenario, _ = fixture()
        statement = scenario["statement"]
        first = placeholder_rows(scenario["policy"])
        second = copy.deepcopy(first)
        for family, suite in enumerate(native.SUITES):
            second[family * 2]["signer_id"] = scenario["policy"]["rosters"][suite][2]
            second[family * 2]["signature_hex"] = "ff" * native.SIGNATURE_BYTES[suite]
        self.assertNotEqual(first, second)
        # Only intent is an input to identity. Neither these synthetic rows nor
        # any backend result is accepted as evidence by this structure test.
        self.assertEqual(native.operation_id(copy.deepcopy(statement)), native.operation_id(statement))

    def test_possession_roles_and_intents_are_distinct(self):
        scenario, _ = fixture("recover")
        statement = scenario["statement"]
        suite = native.SUITES[0]
        one, two = statement["next_policy"]["rosters"][suite][:2]
        baseline = native.possession_message(statement, suite, one)
        self.assertNotEqual(baseline, native.approval_message(statement))
        self.assertNotEqual(baseline, native.possession_message(statement, suite, two))
        for field, value in (("payload_hex", "01"), ("nonce", "ab" * 32),
                             ("owner_generation", "8"), ("key_epoch", "4"),
                             ("network", "99" * 32), ("action", "rotate")):
            changed = copy.deepcopy(statement)
            changed[field] = value
            self.assertNotEqual(baseline, native.possession_message(changed, suite, one))

    def test_one_family_duplicates_unknown_fields_and_wrong_signature_sizes(self):
        mutations = (
            lambda s, _k, a, _p: a.pop(),
            lambda s, _k, a, _p: a.__setitem__(1, copy.deepcopy(a[0])),
            lambda s, _k, a, _p: a[0].update(signature_hex="00"),
            lambda s, _k, a, _p: a[0].update(signature_hex=a[0]["signature_hex"] + "00"),
            lambda s, _k, a, _p: a[0].update(statement_sha512=model.statement_id(s["statement"])),
            lambda s, _k, a, _p: a[0].update(suite="ML-DSA-65"),
            lambda s, _k, a, _p: a[0].update(signer_id=s["policy"]["rosters"][native.SUITES[1]][0]),
        )
        for mutation in mutations:
            self.rejected_without_backend(mutate=mutation)

    def test_trusted_scope_sequence_revocation_and_replay_precede_backend(self):
        mutations = (
            lambda s, _k, _a, _p: s["context"].update(network="99" * 32),
            lambda s, _k, _a, _p: s["context"].update(last_sequence="41"),
            lambda s, _k, _a, _p: s["context"].update(now_height="201"),
            lambda s, _k, a, _p: s["context"].update(revoked_signers=[a[0]["signer_id"]]),
            lambda s, _k, _a, _p: s["context"].update(history=[{"nonce": s["statement"]["nonce"], "operation_id": "11" * 64}]),
            lambda s, _k, _a, _p: s["context"].update(history=[{"nonce": "00" * 32, "operation_id": native.operation_id(s["statement"])}]),
        )
        for mutation in mutations:
            self.rejected_without_backend(mutate=mutation)

    def test_successor_policy_and_every_possession_checked_before_backend(self):
        for action in model.SUCCESSOR_ACTIONS:
            self.rejected_without_backend(action, lambda s, _k, _a, p: p.pop())
            self.rejected_without_backend(action, lambda s, _k, _a, p: p.__setitem__(2, copy.deepcopy(p[0])))
            self.rejected_without_backend(action, lambda s, _k, _a, p: p[-1].update(signature_hex="ff"))
            self.rejected_without_backend(action, lambda s, _k, _a, _p:
                s["statement"]["next_policy"]["rules"]["recover"].update(operator="OR"))

    def test_normal_and_revoke_cannot_supply_hidden_successor(self):
        for action in ("normal", "revoke"):
            s, keys = fixture(action)
            with patch.object(native.backend, "run", side_effect=AssertionError("reached backend")):
                with self.assertRaisesRegex(native.Reject, "unexpected-input"):
                    native.verified_statement(s["policy"], s["context"], s["statement"], keys,
                                              placeholder_rows(s["policy"]), successor_public_keys=keys)

    def test_input_size_depth_boolean_and_message_bounds(self):
        s, keys = fixture()
        for value in ({"x": "a" * (native.MAX_JSON + 1)}, {"x": True}, {"x": float("nan")}, {"x": -1}):
            with self.assertRaises(native.Reject):
                native.validate_roster(value, keys)
        nested = None
        for _ in range(model.MAX_DEPTH + 1):
            nested = {"x": nested}
        with self.assertRaises(native.Reject):
            native.validate_roster(nested, keys)
        for message in (b"", b"a" * (native.MAX_MESSAGE + 1), "text", bytearray(b"a")):
            with patch.object(native.backend, "run", side_effect=AssertionError("reached backend")):
                with self.assertRaises(native.Reject):
                    native.verify_quorum(s["policy"], keys, message, placeholder_rows(s["policy"]))

    def test_expired_or_cancelled_original_budget_refuses_without_backend(self):
        s, keys = fixture()
        for budget in (OperationBudget(time.monotonic() - 1), OperationBudget(time.monotonic() + 10)):
            budget.cancel()
            with patch.object(native.backend, "run", side_effect=AssertionError("reached backend")):
                with self.assertRaises(BudgetExpired):
                    native.verify_quorum(s["policy"], keys, b"TRNM/Test/v2\x00", placeholder_rows(s["policy"]), budget)

    def test_public_result_boundary_never_grants_whole_chain_or_production(self):
        flags = native.no_authority()
        self.assertEqual(flags["status"], "HOLD")
        self.assertIsNone(flags["actual_lifetime_failure_bound"])
        for key in ("signatures_verified", "authorization_granted", "production_qualified", "custody_verified",
                    "anchor_independence_verified", "root_effect_executed", "history_persisted",
                    "whole_chain_pq_qualified", "composition_coverage_proved"):
            self.assertIs(flags[key], False)


if __name__ == "__main__":
    unittest.main()
