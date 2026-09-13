"""Bounded examples and retained negative cases; not a BFT proof or Rust test."""
from copy import deepcopy
from dataclasses import replace
from itertools import combinations
from pathlib import Path
import json
import unittest

from model import (Context, CertifiedHeader, SigningTrace, ResourceLedger,
                   check_finality_shape, check_quorum, threshold, MAX_U128)

CTX = Context("genesis-A", "chain-A", 0, 0, "set-A", "params-A")
WEIGHTS = {str(i): 1 for i in range(7)}


def headers():
    return tuple(CertifiedHeader(CTX, f"b{i}", f"b{i-1}", i, i,
                                f"qc{i}", f"qc{i-1}", tuple("01234"))
                 for i in (1, 2, 3))


class QuorumTests(unittest.TestCase):
    def test_all_small_equal_weight_quorum_intersections(self):
        for n in range(1, 11):
            q = threshold({str(i): 1 for i in range(n)})
            f = (n - 1) // 3
            sets = [set(s) for s in combinations(range(n), q)]
            self.assertTrue(all(len(a & b) > f for a in sets for b in sets))

    def test_weighted_intersection(self):
        for values in ((1, 2, 3, 4), (2, 2, 3, 3), (1, 1, 1, 1, 1)):
            weights = {str(i): w for i, w in enumerate(values)}
            q = threshold(weights)
            valid = [set(s) for size in range(len(values) + 1)
                     for s in combinations(weights, size) if sum(weights[x] for x in s) >= q]
            bound = (sum(values) - 1) // 3
            self.assertTrue(all(sum(weights[x] for x in a & b) > bound for a in valid for b in valid))

    def test_simple_majority_mutant_has_counterexample(self):
        self.assertEqual(len({0, 1, 2, 3} & {0, 1, 4, 5}), 2)
        self.assertEqual(threshold(WEIGHTS), 5)
        with self.assertRaises(ValueError):
            check_quorum(WEIGHTS, tuple("0123"))

    def test_two_f_plus_one_is_not_general_n_formula(self):
        # n=5,f=1: two size-3 sets can intersect only at the faulty validator.
        self.assertEqual({0, 1, 2} & {0, 3, 4}, {0})
        self.assertEqual(threshold({str(i): 1 for i in range(5)}), 4)

    def test_duplicate_unsorted_unknown_signers(self):
        for bad in (tuple("001234"), tuple("43210"), tuple("01239")):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                check_quorum(WEIGHTS, bad)

    def test_invalid_arithmetic(self):
        for weights in ({}, {"a": 0}, {"a": -1}, {"a": True}, {"a": MAX_U128}):
            with self.subTest(weights=weights), self.assertRaises(ValueError):
                threshold(weights)


class ProofTests(unittest.TestCase):
    def test_three_chain_relationships(self):
        check_finality_shape("poco-three-chain-v0", headers(), CTX, WEIGHTS, "b1")

    def test_no_single_qc_or_legacy_upgrade(self):
        for kind in ("legacy-live-qc", "qc", "timeout-certificate", "migration-import"):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                check_finality_shape(kind, headers(), CTX, WEIGHTS, "b1")
        with self.assertRaises(ValueError):
            check_finality_shape("poco-three-chain-v0", headers()[:1], CTX, WEIGHTS, "b1")

    def test_every_context_dimension_is_bound(self):
        changes = {"genesis": "other", "chain": "other", "protocol": 1,
                   "epoch": 1, "validator_set": "other", "parameters": "other"}
        for field, value in changes.items():
            mutated = list(headers())
            mutated[1] = replace(mutated[1], context=replace(CTX, **{field: value}))
            with self.subTest(field=field), self.assertRaises(ValueError):
                check_finality_shape("poco-three-chain-v0", mutated, CTX, WEIGHTS, "b1")

    def test_parent_height_view_and_exact_justification(self):
        for change in ({"parent": "fork"}, {"height": 9}, {"view": 1},
                       {"justify_digest": "another-valid-subset"}, {"view": 0},
                       {"signers": tuple("0123")}):
            mutated = list(headers())
            mutated[1] = replace(mutated[1], **change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                check_finality_shape("poco-three-chain-v0", mutated, CTX, WEIGHTS, "b1")

    def test_target_binding(self):
        with self.assertRaises(ValueError):
            check_finality_shape("poco-three-chain-v0", headers(), CTX, WEIGHTS, "b2")


class AuthorityTests(unittest.TestCase):
    def setUp(self):
        self.trace = SigningTrace(CTX)
        self.key = self.trace.decide("vote", 1, "digest-A")

    def test_vote_publishes_before_any_finality(self):
        self.trace.advance(self.key, "digest-A", 1, "SignatureRecorded")
        self.trace.advance(self.key, "digest-A", 1, "VotePublished")
        self.assertEqual(self.trace.finalized_height, 0)

    def test_no_skip_or_wrong_receipt(self):
        for digest, generation, stage in (("digest-A", 1, "VotePublished"),
                                           ("digest-B", 1, "SignatureRecorded"),
                                           ("digest-A", 0, "SignatureRecorded")):
            with self.subTest(stage=stage), self.assertRaises(ValueError):
                self.trace.advance(self.key, digest, generation, stage)

    def test_crash_each_recorded_stage(self):
        for stage in self.trace.stages:
            if stage != "IntentDurable":
                self.trace.advance(self.key, "digest-A", 1, stage)
            recovered = self.trace.reopen()
            self.assertEqual(recovered.decide("vote", 1, "digest-A"), self.key)
            with self.assertRaises(ValueError):
                recovered.decide("vote", 1, "digest-B")
            with self.assertRaises(ValueError):
                recovered.advance(self.key, "digest-A", 1, stage)
            recovered.advance(self.key, "digest-A", 2, stage)

    def test_watermark_and_timeout_have_different_meanings(self):
        self.trace.decide("vote", 3, "digest-C")
        self.trace.decide("timeout", 3, "timeout-C")
        with self.assertRaises(ValueError):
            self.trace.decide("vote", 2, "digest-B")
        self.assertEqual(self.trace.decide("vote", 1, "digest-A"), self.key)


class AILedgerTests(unittest.TestCase):
    def setUp(self):
        self.ledger = ResourceLedger()

    def admit(self, key="t1", **changes):
        values = dict(owner="agent", lane=0, nonce=1, funds=40,
                      work=(10, 20, 5), deadline=2, retain_until=5, profile="profile-A")
        values.update(changes)
        self.ledger.admit(key, **values)

    def rejected_without_mutation(self, action):
        before = self.ledger.snapshot()
        with self.assertRaises((ValueError, KeyError)):
            action()
        self.assertEqual(before, self.ledger.snapshot())

    def test_shared_budget_never_overdrawn(self):
        self.admit(funds=60)
        self.rejected_without_mutation(lambda: self.admit("t2", nonce=2, funds=60))

    def test_pairwise_compatibility_does_not_prove_aggregate_capacity(self):
        self.admit(funds=10, work=(40, 1, 1))
        self.admit("t2", nonce=2, funds=10, work=(40, 1, 1))
        self.rejected_without_mutation(lambda: self.admit("t3", nonce=3, funds=10, work=(40, 1, 1)))

    def test_nonce_lanes_and_replay(self):
        self.admit(funds=10)
        self.admit("t2", lane=1, funds=10)
        self.rejected_without_mutation(lambda: self.admit("t3", funds=10))
        self.rejected_without_mutation(lambda: self.admit(nonce=2, funds=10))

    def test_profile_is_pinned(self):
        self.admit()
        self.rejected_without_mutation(lambda: self.ledger.resolve("t1", "profile-B", True))

    def test_no_unverified_settlement(self):
        self.admit()
        self.rejected_without_mutation(lambda: self.ledger.settle("t1"))

    def test_success_is_paid_once_and_retention_survives(self):
        self.admit()
        self.ledger.resolve("t1", "profile-A", True)
        self.ledger.settle("t1")
        self.ledger.settle("t1")
        self.assertEqual((self.ledger.paid, self.ledger.escrow), (40, 0))
        self.assertEqual(self.ledger.reserved, [0, 20, 0])
        for h in range(1, 7):
            self.ledger.begin_block(h)
        self.assertEqual(self.ledger.reserved, [0, 0, 0])

    def test_invalid_result_refunds_once(self):
        self.admit()
        self.ledger.resolve("t1", "profile-A", False)
        self.ledger.begin_block(1)
        self.ledger.settle("t1")
        self.assertEqual((self.ledger.available, self.ledger.refunded), (100, 40))

    def test_empty_blocks_expire_and_refund(self):
        self.admit()
        for h in range(1, 4):
            self.ledger.begin_block(h)
        self.assertEqual(self.ledger.tasks["t1"].phase, "Settled")
        self.assertEqual(self.ledger.tasks["t1"].outcome, "timeout-not-fraud")
        self.assertEqual(self.ledger.available, 100)

    def test_result_at_deadline_allowed_late_result_rejected(self):
        self.admit()
        self.ledger.begin_block(1)
        self.ledger.begin_block(2)
        self.ledger.resolve("t1", "profile-A", True)
        other = ResourceLedger()
        other.admit("t", "a", 0, 1, 1, (1, 1, 1), 1, 4, "p")
        other.begin_block(1)
        other.begin_block(2)
        with self.assertRaises(ValueError):
            other.resolve("t", "p", True)

    def test_bounded_service_does_not_skip_expiry(self):
        for i in range(5):
            self.admit(f"t{i}", nonce=i + 1, funds=1, work=(1, 1, 1))
        for h in range(1, 6):
            self.ledger.begin_block(h)
        self.assertTrue(all(t.phase == "Settled" for t in self.ledger.tasks.values()))
        self.assertEqual(self.ledger.refunded, 5)

    def test_recovery_replay_does_not_pay_again(self):
        self.admit()
        self.ledger.resolve("t1", "profile-A", True)
        self.ledger.settle("t1")
        recovered = deepcopy(self.ledger)
        recovered.settle("t1")
        self.assertEqual(recovered.snapshot(), self.ledger.snapshot())

    def test_bad_limits_or_skipped_height_do_not_mutate(self):
        for change in ({"funds": -1}, {"funds": True}, {"work": (0, 1, 1)},
                       {"deadline": 0}, {"retain_until": 2}, {"lane": 65536}):
            with self.subTest(change=change):
                self.rejected_without_mutation(lambda: self.admit(**change))
        self.rejected_without_mutation(lambda: self.ledger.begin_block(2))

    def test_new_ready_events_cannot_overtake_older_events(self):
        ledger = ResourceLedger(service_cap=1)
        for i, key in enumerate(("a", "z"), 1):
            ledger.admit(key, "owner", 0, i, 1, (1, 1, 1), 5, 9, "p")
            ledger.resolve(key, "p", True)
        ledger.begin_block(1)
        ledger.admit("00", "owner", 0, 3, 1, (1, 1, 1), 5, 9, "p")
        ledger.resolve("00", "p", True)
        ledger.begin_block(2)
        self.assertEqual(ledger.tasks["z"].phase, "Settled")
        self.assertEqual(ledger.tasks["00"].phase, "Ready")

    def test_configuration_cannot_disable_progress(self):
        with self.assertRaises(ValueError):
            ResourceLedger(service_cap=0)


class CandidatePolicyTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[2]
        self.policy = json.loads((root / "config/poco-convergence-v1.json").read_text())

    def test_no_false_promotion(self):
        for field in ("runtime_authority_rewired", "ai_runtime_integrated",
                      "proof_migration_implemented", "production_candidate",
                      "production_consensus_activation", "public_testnet_ready",
                      "release_ready", "all_gaps_closed", "ocf_consensus_authority",
                      "control_plane_consensus_authority", "legacy_live_qc_can_be_upgraded",
                      "wire_protocol_change_in_this_commit"):
            self.assertIs(self.policy[field], False, field)

    def test_one_core_one_proof_meaning(self):
        self.assertEqual(self.policy["consensus_core"], "trnm-consensus-core")
        self.assertEqual(self.policy["quorum_formula"], "floor(2*W/3)+1")
        self.assertEqual(self.policy["finality_kind"], "poco-three-chain-v0")
        self.assertEqual(self.policy["finality_certified_blocks"], 3)
        self.assertEqual(self.policy["consumption_weight_mode"], "shadow")
        self.assertIs(self.policy["ai_extension_activation_requires_new_profile"], True)

    def test_separate_publication_barriers(self):
        self.assertEqual(tuple(self.policy["signing_stages"]), SigningTrace.stages)
        self.assertNotIn("FinalityVerified", self.policy["signing_stages"])
        self.assertEqual(self.policy["commit_stages"][0], "FinalityVerified")
        self.assertIs(self.policy["vote_publication_waits_for_finality"], False)
        self.assertIs(self.policy["receipt_publication_requires_finality"], True)


if __name__ == "__main__":
    unittest.main()
