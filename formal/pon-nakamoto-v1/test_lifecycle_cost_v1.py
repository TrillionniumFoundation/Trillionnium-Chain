"""Adversarial controls for finite lifecycle accounting; no native qualification."""
import copy
from dataclasses import replace
from fractions import Fraction as Q
from itertools import product
import unittest

import lifecycle_cost_v1 as L


def one_state(*actions, initial=(("s", Q(1)),)):
    return L.Game("test-law", ("s",), initial, {"s": tuple(actions)},
                  "explicit test-only oracle prices and law")


def action_at(game, state, name):
    return next(action for action in game.actions[state] if action.name == name)


def fair_coin_game():
    return one_state(L.Action("paid_coin", (
        L.Outcome(Q(1, 2), "s", Q(1), Q(1)),
        L.Outcome(Q(1, 2), "s", Q(0), Q(1)))))


class LifecyclePotentialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.game = L.nonce_bank_game()
        cls.result = L.synthesize_potential(cls.game, kappa=Q(1, 8), initial_budget_cap=0)
        cls.certificate = cls.result["certificate"]

    def verify(self, certificate, game=None, cap=0):
        return L.verify_potential(game or self.game, certificate,
                                  expected_kappa=Q(1, 8), initial_budget_cap=cap)

    def test_all_actions_of_expanded_nonce_bank_are_checked(self):
        self.assertEqual(self.result["status"], "CERTIFIED_FINITE_MODEL")
        report = self.verify(self.certificate)
        self.assertEqual(report["checked_states"], 216)
        self.assertEqual(report["checked_actions"], 1848)
        self.assertEqual(report["initial_expected_potential"], "0")
        self.assertFalse(report["actual_work_lower_bound_proven"])
        self.assertFalse(report["production_qualified"])

    def test_simple_analytic_potential_independently_dominates_bellman(self):
        # A paid selector retains at most 1/8 excess credit.  An unclaimed hit
        # retains one whole credit.  An already redeemed hit retains zero.
        phi = {}
        for state in self.game.states:
            records = state.split("/")[-1].split(",")
            phi[state] = sum((Q(1, 8) if r in {"p0", "p1"}
                              else Q(1) if r == "h" else Q(0) for r in records), Q(0))
        self.verify(L.potential_certificate(self.game, Q(1, 8), phi))
        for state in self.game.states:
            self.assertLessEqual(Q(self.certificate["potential"][state]), phi[state])

    def test_deferred_selectors_failures_unused_bank_and_cache_reuse_are_charged(self):
        state = "alias0/cache-1/u,u"
        cost = reward = Q(0)
        # Both selectors are paid before continuation, and the first loses.
        path = [("prepay_nonce:0", 0), ("prepay_nonce:1", 0),
                ("acquire_result:0", 0), ("continue_nonce:0", 1),
                ("restart_preserve_all_accounts", 0), ("relabel_context_same_work", 0),
                ("continue_nonce:1", 0), ("stop", 0), ("publish_once:1", 0),
                ("duplicate_publication:1", 0)]
        for name, outcome_index in path:
            outcome = action_at(self.game, state, name).outcomes[outcome_index]
            cost += outcome.cost
            reward += outcome.reward
            state = outcome.next_state
        self.assertEqual((cost, reward), (6, 1))
        self.assertEqual(state, "alias1/cache0/m,r")
        self.assertEqual(self.certificate["potential"][state], "0")
        # This particular lucky trajectory has positive excess.  The theorem
        # is conditional expectation, not a deterministic cost-per-win bound.
        self.assertEqual(reward - Q(1, 8) * cost, Q(1, 4))

    def test_uncontinued_paid_nonce_survives_a_win(self):
        state, cost = "alias0/cache-1/u,u", Q(0)
        for name in ("prepay_nonce:0", "prepay_nonce:1", "acquire_result:0",
                     "continue_nonce:0", "publish_once:0"):
            outcome = action_at(self.game, state, name).outcomes[0]
            state, cost = outcome.next_state, cost + outcome.cost
        self.assertEqual(cost, 5)
        self.assertEqual(state, "alias0/cache0/r,p0")
        self.assertEqual(Q(self.certificate["potential"][state]), Q(1, 8))

    def test_restart_and_alias_keep_unspent_and_spent_records(self):
        for state in self.game.states:
            restart = action_at(self.game, state, "restart_preserve_all_accounts").outcomes[0]
            relabel = action_at(self.game, state, "relabel_context_same_work").outcomes[0]
            self.assertEqual(restart.next_state, state)
            self.assertEqual(relabel.next_state.split("/")[1:], state.split("/")[1:])
            self.assertEqual(self.certificate["potential"][relabel.next_state],
                             self.certificate["potential"][state])

    def test_discarding_or_aborting_can_only_destroy_unpaid_potential(self):
        phi = {s: Q(v) for s, v in self.certificate["potential"].items()}
        for state in self.game.states:
            for action in self.game.actions[state]:
                if action.name.startswith("abort_or_withhold") or action.name.startswith("retire_context"):
                    outcome = action.outcomes[0]
                    self.assertEqual((outcome.reward, outcome.cost), (0, 0))
                    self.assertLessEqual(phi[outcome.next_state], phi[state])
                    before, after = state.split("/")[-1], outcome.next_state.split("/")[-1]
                    for a, b in zip(before.split(","), after.split(",")):
                        if a == "r":
                            self.assertEqual(b, "r")

    def test_initial_bank_requires_a_finite_initial_credit_allowance(self):
        game = L.nonce_bank_game(initial_records=("p0", "p0"), initial_cache=0)
        refused = L.synthesize_potential(game, kappa=Q(1, 8), initial_budget_cap=0)
        self.assertEqual(refused["status"], "INITIAL_BUDGET_REFUTED")
        L.verify_budget_refutation(game, refused["witness"], expected_kappa=Q(1, 8),
                                   initial_budget_cap=0)
        admitted = L.synthesize_potential(game, kappa=Q(1, 8), initial_budget_cap=Q(1, 4))
        self.assertEqual(admitted["status"], "CERTIFIED_FINITE_MODEL")
        self.assertEqual(admitted["verification"]["initial_expected_potential"], "1/4")

    def test_adding_constant_potential_cannot_hide_initial_cost(self):
        altered = copy.deepcopy(self.certificate)
        altered["potential"] = {s: str(Q(v) + 1) for s, v in altered["potential"].items()}
        with self.assertRaisesRegex(ValueError, "INITIAL_POTENTIAL_BUDGET"):
            self.verify(altered)

    def test_redeemed_credit_cannot_remain_in_potential(self):
        altered = copy.deepcopy(self.certificate)
        altered["potential"]["alias0/cache0/r,r"] = "1"
        with self.assertRaisesRegex(ValueError, "POTENTIAL_ACTION"):
            self.verify(altered)

    def test_negative_terminal_and_missing_states_are_refused(self):
        negative = copy.deepcopy(self.certificate)
        negative["potential"]["alias0/cache0/r,r"] = "-1"
        with self.assertRaisesRegex(ValueError, "NEGATIVE_POTENTIAL"):
            self.verify(negative)
        missing = copy.deepcopy(self.certificate)
        missing["potential"].pop("alias0/cache0/r,r")
        with self.assertRaisesRegex(ValueError, "POTENTIAL_COVERAGE"):
            self.verify(missing)

    def test_verifier_owns_kappa_and_exact_game(self):
        altered = copy.deepcopy(self.certificate)
        altered["kappa"] = "1"
        with self.assertRaisesRegex(ValueError, "KAPPA_BINDING"):
            self.verify(altered)
        changed = replace(self.game, cost_model="different declared resource model")
        with self.assertRaisesRegex(ValueError, "POTENTIAL_GAME"):
            self.verify(self.certificate, game=changed)

    def test_iteration_limit_is_not_a_certificate(self):
        result = L.synthesize_potential(self.game, kappa=Q(1, 8),
                                        initial_budget_cap=0, max_iterations=1)
        self.assertEqual(result["status"], "INCONCLUSIVE")
        self.assertNotIn("certificate", result)

    def test_asymptotic_bellman_convergence_never_uses_float_tolerance(self):
        game = L.Game("geometric", ("s", "done"), (("s", Q(1)),), {
            "s": (L.Action("try", (L.Outcome(Q(1, 2), "done", Q(1)),
                                     L.Outcome(Q(1, 2), "s"))),),
            "done": (L.Action("stop", (L.Outcome(Q(1), "done"),)),)}, "test-only")
        result = L.synthesize_potential(game, kappa=0, initial_budget_cap=1, max_iterations=32)
        self.assertEqual(result["status"], "INCONCLUSIVE")
        self.assertEqual(Q(result["finite_horizon_initial_excess"]), 1 - Q(1, 2**32))
        # A separately proposed exact potential can still be verified.
        L.verify_potential(game, L.potential_certificate(game, 0, {"s": Q(1), "done": Q(0)}),
                            expected_kappa=0, initial_budget_cap=1)

    def test_new_batch_shortcut_invalidates_an_old_atomic_oracle_certificate(self):
        state = "alias0/cache0/p0,p0"
        rows = []
        for a, b in product(("h", "m"), repeat=2):
            p = (Q(1, 4) if a == "h" else Q(3, 4)) * (Q(1, 4) if b == "h" else Q(3, 4))
            rows.append(L.Outcome(p, f"alias0/cache0/{a},{b}", Q(0), Q(1)))
        actions = dict(self.game.actions)
        actions[state] += (L.Action("shared_continuation_for_two_nonces", tuple(rows)),)
        # The independently fixed initial law is the already selected warm
        # bank.  A shortcut conditional on this state alone need not improve
        # the cold-start average over all random selector outcomes.
        game = replace(self.game, actions=actions, initial=((state, Q(1)),))
        old_phi = {s: Q(v) for s, v in self.certificate["potential"].items()}
        repackaged = L.potential_certificate(game, Q(1, 8), old_phi)
        with self.assertRaisesRegex(ValueError, "POTENTIAL_ACTION"):
            self.verify(repackaged, game=game, cap=Q(1, 4))
        result = L.synthesize_potential(game, kappa=Q(1, 8), initial_budget_cap=Q(1, 4))
        self.assertEqual(result["status"], "INITIAL_BUDGET_REFUTED")
        self.assertGreater(Q(result["verification"]["strict_excess"]), 0)

    def test_policy_refutation_is_recomputed_forward(self):
        game = one_state(L.Action("free_credit", (L.Outcome(Q(1), "s", Q(1)),)))
        result = L.synthesize_potential(game, kappa=1, initial_budget_cap=0)
        witness = result["witness"]
        self.assertEqual(result["verification"]["strict_excess"], "1")
        altered = copy.deepcopy(witness)
        altered["policies_by_remaining_steps"][0]["s"] = None
        with self.assertRaisesRegex(ValueError, "NOT_AN_INITIAL_BUDGET_REFUTATION"):
            L.verify_budget_refutation(game, altered, expected_kappa=1, initial_budget_cap=0)


class LifecycleCycleTests(unittest.TestCase):
    def test_restart_recredit_has_an_exact_positive_cycle(self):
        game = L.nonce_bank_game(reset_spent_on_restart=True)
        witness = L.find_positive_cycle(game, kappa=Q(1, 8))
        report = L.verify_positive_cycle(game, witness, expected_kappa=Q(1, 8))
        self.assertEqual(report["net_credit_per_cycle"], "1")
        altered = copy.deepcopy(witness)
        altered["cycle"] = altered["cycle"][:1]
        with self.assertRaisesRegex(ValueError, "CYCLE_EDGE"):
            L.verify_positive_cycle(game, altered, expected_kappa=Q(1, 8))

    def test_zero_gain_cycle_is_not_a_counterexample(self):
        game = one_state(L.Action("idle", (L.Outcome(Q(1), "s"),)))
        self.assertIsNone(L.find_positive_cycle(game, kappa=1))
        witness = {"schema": "pon-lifecycle-positive-cycle-v1",
                   "game_sha256": L.game_digest(game), "kappa": "1",
                   "cycle": [{"state": "s", "action": "idle"}]}
        with self.assertRaisesRegex(ValueError, "CYCLE_NOT_POSITIVE"):
            L.verify_positive_cycle(game, witness, expected_kappa=1)

    def test_stochastic_occupation_witness_covers_more_than_deterministic_cycles(self):
        game = one_state(L.Action("unpaid_lottery", (
            L.Outcome(Q(1, 4), "s", Q(1)), L.Outcome(Q(3, 4), "s"))))
        self.assertIsNone(L.find_positive_cycle(game, kappa=1))
        result = L.verify_occupation_witness(game, {("s", "unpaid_lottery"): Q(1)},
                                             expected_kappa=1)
        self.assertEqual(result["net_credit_per_step"], "1/4")

    def test_nonstationary_flow_cannot_masquerade_as_unlimited_credit(self):
        game = L.Game("one-shot", ("s", "done"), (("s", Q(1)),), {
            "s": (L.Action("claim", (L.Outcome(Q(1), "done", Q(1)),)),),
            "done": (L.Action("idle", (L.Outcome(Q(1), "done"),)),)}, "test-only")
        with self.assertRaisesRegex(ValueError, "OCCUPATION_FLOW"):
            L.verify_occupation_witness(game, {("s", "claim"): Q(1)}, expected_kappa=1)

    def test_eta_is_cumulative_credit_gap_not_erased_cost(self):
        game = one_state(L.Action("slack_credit", (L.Outcome(Q(1), "s", Q(1)),), eta=Q(1)))
        potential = L.potential_certificate(game, 1, {"s": Q(0)})
        report = L.verify_potential(game, potential, expected_kappa=1, initial_budget_cap=0)
        self.assertEqual(report["max_eta_per_step"], "1")
        self.assertEqual(sum(L.gain(action_at(game, "s", "slack_credit").outcomes[0],
                                    action_at(game, "s", "slack_credit"), Q(1))
                             for _ in range(10)), 0)
        with self.assertRaisesRegex(ValueError, "OCCUPATION_NOT_POSITIVE"):
            L.verify_occupation_witness(game, {("s", "slack_credit"): Q(1)}, expected_kappa=1)


class LifecycleTailTests(unittest.TestCase):
    def setUp(self):
        self.game = fair_coin_game()
        self.potential = L.potential_certificate(self.game, Q(1, 2), {"s": Q(0)})
        self.tail = L.synthesize_tail_certificate(self.game, self.potential,
            expected_kappa=Q(1, 2), initial_budget_cap=0, tilt=Q(2))

    def verify(self, tail=None, horizon=10, threshold=Q(4)):
        return L.verify_tail_bound(self.game, self.potential, tail or self.tail,
            expected_kappa=Q(1, 2), initial_budget_cap=0,
            horizon=horizon, threshold=threshold)

    def test_exact_tail_bounds_all_crossing_times_not_just_terminal_time(self):
        hit = 0
        for path in product((0, 1), repeat=10):
            centered = Q(0)
            for coin in path:
                centered += Q(coin) - Q(1, 2)
                if centered >= 4:
                    hit += 1
                    break
        exact = Q(hit, 2**10)
        self.assertEqual(exact, Q(3, 256))
        report = self.verify()
        self.assertEqual(Q(self.tail["normalizer"]), Q(5, 4))
        self.assertEqual(Q(report["probability_upper_bound"]), Q(5, 4)**10 / 2**8)
        self.assertGreaterEqual(Q(report["probability_upper_bound"]), exact)
        self.assertLess(Q(report["probability_upper_bound"]), Q(1, 20))
        self.assertIsNone(report["native_chain_security_probability"])

    def test_initial_expectation_is_not_substituted_for_exponential_moment(self):
        game = L.Game("rare-initial-bank", ("empty", "rich"),
                      (("empty", Q(7, 8)), ("rich", Q(1, 8))), {
            "empty": (L.Action("stop", (L.Outcome(Q(1), "empty"),)),),
            "rich": (L.Action("redeem", (L.Outcome(Q(1), "empty", Q(8)),)),)},
            "finite initial law; no conditioning on selected starts")
        potential = L.potential_certificate(game, 0, {"empty": Q(0), "rich": Q(8)})
        checked = L.verify_potential(game, potential, expected_kappa=0, initial_budget_cap=1)
        self.assertEqual(checked["initial_expected_potential"], "1")
        tail = L.synthesize_tail_certificate(game, potential, expected_kappa=0,
                                             initial_budget_cap=1, tilt=Q(2))
        report = L.verify_tail_bound(game, potential, tail, expected_kappa=0,
                                    initial_budget_cap=1, horizon=1, threshold=8)
        self.assertEqual(Q(report["probability_upper_bound"]), Q(263, 2048))
        self.assertGreaterEqual(Q(report["probability_upper_bound"]), Q(1, 8))
        self.assertLess(Q(2**1, 2**8), Q(1, 8))  # The invalid mean substitution.

    def test_unverified_normalizer_cannot_hide_tail(self):
        altered = dict(self.tail, normalizer="1")
        with self.assertRaisesRegex(ValueError, "TAIL_ACTION"):
            self.verify(altered)

    def test_negative_or_subunit_normalizer_and_degenerate_tilt_are_rejected(self):
        for changes in ({"normalizer": "9/10"}, {"normalizer": "-1"}, {"tilt": "1"}):
            with self.assertRaisesRegex(ValueError, "TAIL_PARAMETERS"):
                self.verify(dict(self.tail, **changes))

    def test_nonintegral_exponents_and_unbounded_horizons_are_not_rounded(self):
        with self.assertRaisesRegex(ValueError, "EXPONENT_DOMAIN"):
            self.verify(dict(self.tail, scale=1))
        with self.assertRaisesRegex(ValueError, "EXPONENT_DOMAIN"):
            self.verify(threshold=Q(1, 3))
        with self.assertRaisesRegex(ValueError, "TAIL_HORIZON"):
            self.verify(horizon=1025)

    def test_loose_tail_is_explicitly_one(self):
        result = self.verify(threshold=Q(0))
        self.assertEqual(result["probability_upper_bound"], "1")
        self.assertFalse(result["production_qualified"])

    def test_tail_certificate_is_bound_to_exact_potential(self):
        altered = dict(self.tail, potential_sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "TAIL_BINDING"):
            self.verify(altered)

    def test_synthesizer_refuses_an_unsupported_initial_moment_too(self):
        game = one_state(L.Action("idle", (L.Outcome(Q(1), "s"),)))
        potential = L.potential_certificate(game, 0, {"s": Q(4097)})
        L.verify_potential(game, potential, expected_kappa=0, initial_budget_cap=4097)
        # Delta is zero, but the nonzero initial state must also fit the
        # exact verifier's documented exponent limit.
        with self.assertRaisesRegex(ValueError, "EXPONENT_DOMAIN"):
            L.synthesize_tail_certificate(game, potential, expected_kappa=0,
                                           initial_budget_cap=4097, tilt=Q(2))


class LifecycleInputTests(unittest.TestCase):
    def test_float_bool_and_noncanonical_rationals_are_rejected(self):
        for value in (0.25, True, "1/4"):
            with self.assertRaises(ValueError):
                L.rational(value)
        for value in ("0.5", "2/4", "1/1", "01", "1/0", 1, True):
            with self.assertRaises(ValueError):
                L.read_rational(value)

    def test_cost_rewards_eta_and_probability_are_validated(self):
        cases = [L.Action("bad", (L.Outcome(Q(1), "s", cost=Q(-1)),)),
                 L.Action("bad", (L.Outcome(Q(1), "s", reward=Q(-1)),)),
                 L.Action("bad", (L.Outcome(Q(1), "s"),), eta=Q(-1)),
                 L.Action("bad", (L.Outcome(Q(1, 2), "s"),)),
                 L.Action("bad", (L.Outcome(0.5, "s"),)),
                 L.Action("bad", (L.Outcome(Q(1), "missing"),))]
        for action in cases:
            with self.subTest(action=action):
                with self.assertRaises(ValueError):
                    L.validate_game(one_state(action))

    def test_sub_float_epsilon_violation_is_detected_exactly(self):
        cost = 1 - Q(1, 10**16)
        game = one_state(L.Action("tiny_arbitrage", (L.Outcome(Q(1), "s", Q(1), cost),)))
        potential = L.potential_certificate(game, 1, {"s": Q(0)})
        with self.assertRaisesRegex(ValueError, "POTENTIAL_ACTION"):
            L.verify_potential(game, potential, expected_kappa=1, initial_budget_cap=0)
        result = L.synthesize_potential(game, kappa=1, initial_budget_cap=0)
        self.assertEqual(Q(result["verification"]["strict_excess"]), Q(1, 10**16))


if __name__ == "__main__":
    unittest.main(verbosity=2)
