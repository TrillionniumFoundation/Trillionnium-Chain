#!/usr/bin/env python3
"""Mandatory real-OpenSSL campaign, separate from synthetic structure tests.

No skip switch or verifier double exists in this suite. Set the explicit
TRNM_PQ_OPENSSL, TRNM_PQ_OPENSSL_SHA256, TRNM_PQ_OPENSSL_VERSION and OPENSSL_DIR
pins required by pq_openssl_backend. Missing/mismatched pins fail the campaign.
All private fixture keys live only in the temporary directory removed at exit.
"""
from __future__ import annotations

import copy
import itertools
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import pq_openssl_backend as backend
from pq_operation_budget import BudgetExpired, OperationBudget
import pq_root_recovery_policy_v1 as model
import pq_root_recovery_signatures_v2 as native


class NativeFixture:
    """Reusable ephemeral native fixture for integration tests; no fake crypto."""

    def __init__(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="trnm-root-native-fixture-v2-")
        self.directory = Path(self.temporary.name)
        self.private_keys = {}
        self.cache = {}
        setup_budget = OperationBudget(time.monotonic() + 300)
        try:
            # Check explicit pins before any private material is generated.
            backend.binding(budget=setup_budget)
            self.policy, self.public_keys = self._roster("current", setup_budget)
            self.next_policy, self.next_public_keys = self._roster("successor", setup_budget)
        except BaseException:
            self.close()
            raise

    def _roster(self, label, budget):
        policy = model.example()["policy"]
        public_keys = {}
        for suite in native.SUITES:
            roster = []
            for index in range(3):
                private = self.directory / (label + "-" + suite + "-" + str(index) + ".pem")
                backend.run(["genpkey", "-algorithm", suite, "-out", str(private)], budget=budget)
                private.chmod(0o600)
                public = backend.run(["pkey", "-in", str(private), "-pubout", "-outform", "DER"], budget=budget)
                signer = native.key_id(suite, public)
                roster.append(signer)
                public_keys[signer] = public
                self.private_keys[signer] = private
            policy["rosters"][suite] = sorted(roster)
        native.validate_roster(policy, public_keys)
        return policy, public_keys

    def close(self):
        self.temporary.cleanup()

    def scenario(self, action="normal", same_roster=False):
        scenario = model.example(action)
        scenario["policy"] = copy.deepcopy(self.policy)
        scenario["context"]["anchor"]["policy_sha512"] = model.policy_id(self.policy)
        statement = scenario["statement"]
        statement["policy_sha512"] = model.policy_id(self.policy)
        if action in model.SUCCESSOR_ACTIONS:
            statement["next_policy"] = copy.deepcopy(self.policy if same_roster else self.next_policy)
        # The largest legal payload must remain supported for a full successor
        # statement; signing a substituted digest would not pass these inputs.
        if action == "recover":
            statement["payload_hex"] = "ac" * model.MAX_PAYLOAD
        return scenario

    def sign(self, suite, signer, message, budget=None):
        budget = budget or OperationBudget(time.monotonic() + 90)
        cache_key = (suite, signer, message)
        if cache_key not in self.cache:
            message_path = self.directory / "sign.message"
            signature_path = self.directory / "sign.signature"
            message_path.write_bytes(message)
            backend.run(["pkeyutl", "-sign", "-rawin", "-inkey", str(self.private_keys[signer]),
                         "-in", str(message_path), "-out", str(signature_path)], budget=budget)
            signature = signature_path.read_bytes()
            if len(signature) != native.SIGNATURE_BYTES[suite]:
                raise AssertionError("native fixture returned an unexpected signature length")
            self.cache[cache_key] = signature.hex()
        return {"suite": suite, "signer_id": signer, "signature_hex": self.cache[cache_key]}

    def sign_quorum(self, message, policy=None, pairs=((0, 1), (0, 1)), budget=None):
        """Sign a caller-constructed domain-separated receipt with real keys."""
        policy = self.policy if policy is None else policy
        budget = budget or OperationBudget(time.monotonic() + 120)
        return [self.sign(suite, policy["rosters"][suite][index], message, budget)
                for suite, pair in zip(native.SUITES, pairs) for index in pair]

    def approvals(self, statement, policy=None, pairs=((0, 1), (0, 1)), budget=None):
        return self.sign_quorum(native.approval_message(statement), policy, pairs, budget)

    def possessions(self, statement, budget=None):
        budget = budget or OperationBudget(time.monotonic() + 120)
        return [self.sign(suite, signer, native.possession_message(statement, suite, signer), budget)
                for suite in native.SUITES for signer in statement["next_policy"]["rosters"][suite]]

    def verify(self, scenario, approvals=None, possessions=None, budget=None, same_roster=False):
        statement = scenario["statement"]
        required = statement["action"] in model.SUCCESSOR_ACTIONS
        return native.verified_statement(
            scenario["policy"], scenario["context"], statement, self.public_keys,
            self.approvals(statement) if approvals is None else approvals,
            successor_public_keys=(self.public_keys if same_roster else self.next_public_keys) if required else None,
            successor_possessions=(self.possessions(statement) if possessions is None else possessions) if required else None,
            budget=budget or OperationBudget(time.monotonic() + 60))


class RootNativeCryptographyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = NativeFixture()
        cls.addClassCleanup(cls.fixture.close)

    def rejected(self, callback):
        with self.assertRaises((native.Reject, backend.BackendError, BudgetExpired)):
            callback()

    def test_all_five_actions_real_current_quorum_and_all_successor_keys(self):
        for action in model.ACTIONS:
            with self.subTest(action=action):
                scenario = self.fixture.scenario(action)
                result = self.fixture.verify(scenario)
                self.assertTrue(result["signatures_verified"])
                self.assertTrue(result["current_quorum_verified"])
                self.assertEqual(result["verified_signatures"], 10 if action in model.SUCCESSOR_ACTIONS else 4)
                self.assertEqual(result["successor_possession_verified"], action in model.SUCCESSOR_ACTIONS)
                self.assertEqual(result["status"], "HOLD")
                self.assertFalse(result["authorization_granted"])
                self.assertFalse(result["production_qualified"])
                self.assertFalse(result["whole_chain_pq_qualified"])
                self.assertFalse(result["composition_coverage_proved"])
                self.assertFalse(result["custody_verified"])
                self.assertFalse(result["anchor_independence_verified"])
                self.assertIsNone(result["actual_lifetime_failure_bound"])
                if action == "recover":
                    self.assertGreater(len(native.approval_message(scenario["statement"])), 8192)

    def test_all_nine_real_quorum_pairs_share_one_semantic_operation(self):
        scenario = self.fixture.scenario()
        identities = set()
        for pairs in itertools.product(itertools.combinations(range(3), 2), repeat=2):
            approvals = self.fixture.approvals(scenario["statement"], pairs=pairs)
            result = self.fixture.verify(scenario, approvals)
            identities.add(result["operation_id"])
        self.assertEqual(identities, {native.operation_id(scenario["statement"])})

    def test_mutation_after_signing_cannot_rebind_current_approval(self):
        scenario = self.fixture.scenario()
        approvals = self.fixture.approvals(scenario["statement"])
        for field, value in (("payload_hex", "fe"), ("nonce", "ee" * 32), ("valid_until", "201")):
            altered = copy.deepcopy(scenario)
            altered["statement"][field] = value
            self.rejected(lambda: self.fixture.verify(altered, approvals))

    def test_each_current_family_rejects_same_length_corrupt_signature(self):
        scenario = self.fixture.scenario()
        good = self.fixture.approvals(scenario["statement"])
        for index in (0, 2):
            approvals = copy.deepcopy(good)
            signature = bytes.fromhex(approvals[index]["signature_hex"])
            approvals[index]["signature_hex"] = (signature[:-1] + bytes([signature[-1] ^ 1])).hex()
            self.rejected(lambda: self.fixture.verify(scenario, approvals))

    def test_new_roster_cannot_self_authorize_old_root_transition(self):
        scenario = self.fixture.scenario("rotate")
        approvals = self.fixture.approvals(scenario["statement"], policy=self.fixture.next_policy)
        self.rejected(lambda: self.fixture.verify(scenario, approvals))

    def test_each_successor_family_rejects_one_invalid_possession(self):
        scenario = self.fixture.scenario("recover")
        approvals = self.fixture.approvals(scenario["statement"])
        good = self.fixture.possessions(scenario["statement"])
        for index in (2, 5):
            possessions = copy.deepcopy(good)
            signature = bytes.fromhex(possessions[index]["signature_hex"])
            possessions[index]["signature_hex"] = (signature[:-1] + bytes([signature[-1] ^ 1])).hex()
            self.rejected(lambda: self.fixture.verify(scenario, approvals, possessions))

    def test_missing_any_successor_possession_refuses_the_real_transition(self):
        scenario = self.fixture.scenario("recover")
        approvals = self.fixture.approvals(scenario["statement"])
        good = self.fixture.possessions(scenario["statement"])
        for index in range(6):
            possessions = good[:index] + good[index + 1:]
            self.rejected(lambda: self.fixture.verify(scenario, approvals, possessions))

    def test_possession_cannot_move_between_complete_transitions(self):
        earlier = self.fixture.scenario("recover")
        possessions = self.fixture.possessions(earlier["statement"])
        later = self.fixture.scenario("rotate")
        self.rejected(lambda: self.fixture.verify(later, self.fixture.approvals(later["statement"]), possessions))

    def test_possession_and_approval_domains_cannot_be_swapped_even_same_roster(self):
        scenario = self.fixture.scenario("recover", same_roster=True)
        approvals = self.fixture.approvals(scenario["statement"])
        possessions = self.fixture.possessions(scenario["statement"])
        self.assertTrue(self.fixture.verify(scenario, approvals, possessions, same_roster=True)["signatures_verified"])
        by_signer = {row["signer_id"]: row for row in possessions}
        swapped = [copy.deepcopy(by_signer[row["signer_id"]]) for row in approvals]
        self.rejected(lambda: self.fixture.verify(scenario, swapped, possessions, same_roster=True))
        wrong_possessions = copy.deepcopy(possessions)
        wrong_possessions[0] = self.fixture.sign(wrong_possessions[0]["suite"], wrong_possessions[0]["signer_id"],
                                                native.approval_message(scenario["statement"]))
        self.rejected(lambda: self.fixture.verify(scenario, approvals, wrong_possessions, same_roster=True))

    def test_real_same_length_shake_key_and_signature_are_not_sha2(self):
        budget = OperationBudget(time.monotonic() + 60)
        private = self.fixture.directory / "wrong-shake.pem"
        backend.run(["genpkey", "-algorithm", "SLH-DSA-SHAKE-256s", "-out", str(private)], budget=budget)
        private.chmod(0o600)
        public = backend.run(["pkey", "-in", str(private), "-pubout", "-outform", "DER"], budget=budget)
        self.assertEqual(len(public), 82)
        message_path = self.fixture.directory / "wrong-shake.message"
        signature_path = self.fixture.directory / "wrong-shake.signature"
        message_path.write_bytes(b"TRNM/TestWrongSuite/v2\x00")
        backend.run(["pkeyutl", "-sign", "-rawin", "-inkey", str(private), "-in", str(message_path),
                     "-out", str(signature_path)], budget=budget)
        self.assertEqual(signature_path.stat().st_size, native.SIGNATURE_BYTES[native.SUITES[1]])
        with self.assertRaisesRegex(native.Reject, "algorithm-or-encoding"):
            native.key_id(native.SUITES[1], public)

    def test_generic_receipt_signatures_bind_challenge_and_cannot_approve_root(self):
        budget = OperationBudget(time.monotonic() + 120)
        message = b"TRNM/IndependentRootAnchorReceipt/v2\x00" + b"fresh-challenge:" + bytes(range(32))
        approvals = [self.fixture.sign(suite, signer, message, budget) for suite in native.SUITES
                     for signer in self.fixture.policy["rosters"][suite][:2]]
        result = native.verify_quorum(self.fixture.policy, self.fixture.public_keys, message, approvals, budget)
        self.assertTrue(result["signatures_verified"])
        self.assertFalse(result["authorization_granted"])
        self.rejected(lambda: native.verify_quorum(self.fixture.policy, self.fixture.public_keys,
                                                  message[:-1] + b"x", approvals, budget))
        self.rejected(lambda: self.fixture.verify(self.fixture.scenario(), approvals))

    def test_one_original_budget_covers_both_real_verification_stages(self):
        scenario = self.fixture.scenario("recover")
        approvals, possessions = self.fixture.approvals(scenario["statement"]), self.fixture.possessions(scenario["statement"])
        budget = OperationBudget(time.monotonic() + 60)
        seen = []
        real_run = backend.run

        def observe(args, **kwargs):
            seen.append(kwargs["budget"])
            return real_run(args, **kwargs)

        with patch.object(backend, "run", side_effect=observe):
            result = self.fixture.verify(scenario, approvals, possessions, budget)
        self.assertTrue(result["signatures_verified"])
        self.assertEqual(len(seen), 10)
        self.assertTrue(all(item is budget for item in seen))

    def test_cancellation_after_current_quorum_never_returns_success_or_resets_budget(self):
        scenario = self.fixture.scenario("recover")
        approvals, possessions = self.fixture.approvals(scenario["statement"]), self.fixture.possessions(scenario["statement"])
        budget = OperationBudget(time.monotonic() + 60)
        count = []
        real_run = backend.run

        def cancel_after_current(args, **kwargs):
            self.assertIs(kwargs["budget"], budget)
            result = real_run(args, **kwargs)
            count.append(1)
            if len(count) == 4:
                budget.cancel()
            return result

        with patch.object(backend, "run", side_effect=cancel_after_current):
            with self.assertRaises(BudgetExpired):
                self.fixture.verify(scenario, approvals, possessions, budget)
        self.assertEqual(len(count), 4)

    def test_mismatched_executable_pin_has_no_fallback(self):
        scenario = self.fixture.scenario()
        approvals = self.fixture.approvals(scenario["statement"])
        with patch.dict("os.environ", {"TRNM_PQ_OPENSSL_SHA256": "00" * 32}):
            with self.assertRaises(backend.BackendError):
                self.fixture.verify(scenario, approvals)


if __name__ == "__main__":
    unittest.main()
