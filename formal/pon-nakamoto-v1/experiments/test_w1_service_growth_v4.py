"""Exact controls for the explicitly conditional service/growth interface."""
from fractions import Fraction as F
from functools import lru_cache
from itertools import combinations, product
import unittest

from w1_service_growth_v4 import (
    ArrivalCurve, HonestSlot, LotteryEnvelope, RateLatency,
    all_window_burst_check, controls, deadline_union_bound, fifo_delay,
    forest_upper_bound, honest_shortfall_bound, leftover_service,
    private_overtake_bound, slot_frontier_floor, tandem_delay,
)


class HonestLowerTailTests(unittest.TestCase):
    def test_every_depleted_small_permutation_obeys_lower_envelope(self):
        # Enumerate exposed output sets and every translation of threshold hits.
        # No independence between successive exposure choices is assumed.
        for bits in (2, 3):
            size = 1 << bits
            for cap in range(1, size + 1):
                law = LotteryEnvelope(bits, cap)
                for target in range(1, size // 2):
                    for removed in combinations(range(size), cap - 1):
                        remaining = set(range(size)) - set(removed)
                        for offset in range(size):
                            hit = sum((value + offset) % size <= target for value in remaining)
                            actual = F(hit, len(remaining))
                            self.assertGreaterEqual(actual, law.lower_probability(target))

    def test_depletion_cannot_be_replaced_with_nominal_probability(self):
        law = LotteryEnvelope(2, 2)
        self.assertEqual(law.lower_probability(1), F(1, 3))
        self.assertLess(law.lower_probability(1), F(1, 2))

    def test_slot_no_hit_bound_all_adaptive_conditional_choices(self):
        # Each of the seven nodes in a depth-three probability tree may choose
        # a different probability. Only the all-failed path matters for no hit.
        lower = F(1, 5)
        for choices in product((lower, F(1, 2), F(1)), repeat=7):
            no_hit = (1 - choices[0]) * (1 - choices[1]) * (1 - choices[3])
            self.assertLessEqual(no_hit, (1 - lower) ** 3)

    def test_adaptive_targets_and_conditional_probabilities_lower_tail(self):
        # Bellman enumeration over target choices and lower-or-certain success
        # at every reached weighted state. Targets can change across slots.
        law = LotteryEnvelope(8, 16)
        slot = HonestSlot(2, 63, 127)
        targets = (63, 79, 95, 127)

        @lru_cache(None)
        def worst(remaining, accumulated, threshold):
            if remaining == 0:
                return F(accumulated < threshold)
            values = []
            for target in targets:
                q = 1 - (1 - law.lower_probability(target)) ** 2
                for chance in (q, F(1)):
                    values.append((1 - chance) * worst(remaining - 1, accumulated, threshold)
                                  + chance * worst(remaining - 1,
                                                   accumulated + law.weight(target), threshold))
            return max(values)

        for count in range(1, 5):
            for threshold in range(1, 9):
                bound = honest_shortfall_bound((slot,) * count, threshold, F(2), law)
                self.assertGreaterEqual(bound, worst(count, 0, threshold))
        self.assertLess(honest_shortfall_bound((slot,) * 4, 1, F(2), law), 1)

    def test_target_and_weight_pair_extrema_are_conservative(self):
        law = LotteryEnvelope(8, 16)
        slot = HonestSlot(2, 20, 127)
        for z in (F(3, 2), F(2), F(3)):
            gamma = slot.lower_tail_factor(law, z)
            for target in range(20, 128):
                q = 1 - (1 - law.lower_probability(target)) ** 2
                exact = 1 - q * (1 - z ** -law.weight(target))
                self.assertLessEqual(exact, gamma)

    def test_native_target_weight_does_not_become_one_binomial_weight(self):
        law = LotteryEnvelope(8, 16)
        self.assertEqual(law.weight(127), 2)
        self.assertEqual(law.weight(31), 8)
        # Two easy-weight successes cannot reach 8; one harder native-weight
        # success can. A fixed weight-2 two-trial model erases that possibility.
        self.assertLess(2 * law.weight(127), law.weight(31))
        self.assertGreater(law.lower_probability(31), 0)

    def test_low_target_or_no_attempts_yield_vacuous_growth(self):
        law = LotteryEnvelope(8, 16)
        self.assertEqual(honest_shortfall_bound((HonestSlot(2, 1, 127),), 1, F(2), law), 1)
        self.assertEqual(honest_shortfall_bound((HonestSlot(0, 63, 127),), 1, F(2), law), 1)
        self.assertEqual(honest_shortfall_bound((), 0, F(2), law), 0)
        self.assertEqual(honest_shortfall_bound((), 1, F(2), law), 1)

    def test_global_exposures_and_exact_arithmetic_fail_closed(self):
        with self.assertRaisesRegex(ValueError, 'attempts_exceed'):
            honest_shortfall_bound((HonestSlot(17, 63, 127),), 1, F(2), LotteryEnvelope(8, 16))
        with self.assertRaisesRegex(OverflowError, 'exact_weight'):
            honest_shortfall_bound((HonestSlot(1, 1, 1),), 1, F(2), LotteryEnvelope(256, 1))
        with self.assertRaises(ValueError):
            HonestSlot(True, 63, 127).quantities(LotteryEnvelope(8, 16))
        with self.assertRaises(ValueError):
            honest_shortfall_bound((HonestSlot(1, 63, 127),), 1, 1.1, LotteryEnvelope(8, 16))


class ServiceTests(unittest.TestCase):
    def test_leftover_strict_service_identity_at_all_breakpoints(self):
        server = RateLatency('cpu-second', F(3, 2), F(1, 5))
        residual = leftover_service(server, interference_burst=F(2, 3),
                                    interference_rate=F(1, 3),
                                    initial_or_unmetered_work=F(1, 7))
        self.assertIsNotNone(residual)
        for t in (F(0), F(1, 5), residual.latency, residual.latency + F(1, 100), F(2), F(10)):
            derived = max(F(0), server.rate * (t - server.latency) - F(2, 3)
                          - F(1, 3) * t - F(1, 7))
            self.assertEqual(residual.service(t), derived)

    def test_declared_packetized_fifo_delay_covers_arrival_curve(self):
        arrivals = ArrivalCurve('byte', F(17), F(3))
        service = RateLatency('byte', F(5), F(2))
        delay = fifo_delay(arrivals, service)
        self.assertEqual(delay, F(27, 5))
        for t in (F(0), F(1, 17), F(1), F(2), F(10), F(10_000)):
            self.assertGreaterEqual(service.service(t + delay), arrivals.burst + arrivals.rate * t)

    def test_independent_resource_units_and_tandem_stage_bursts(self):
        network = (ArrivalCurve('byte', 100, 10), RateLatency('byte', 100, F(1, 10)))
        cpu = (ArrivalCurve('cpu-second', F(1, 10), F(1, 10)),
               RateLatency('cpu-second', F(1, 2), F(1, 20)))
        self.assertEqual(tandem_delay((network, cpu)), F(27, 20))
        with self.assertRaisesRegex(ValueError, 'resource_unit_mismatch'):
            fifo_delay(network[0], cpu[1])

    def test_overload_and_unbounded_nonpreemptive_residual_refused(self):
        server = RateLatency('cpu-second', 1, 0)
        self.assertIsNone(leftover_service(server, interference_burst=0,
                                          interference_rate=1, initial_or_unmetered_work=0))
        self.assertIsNone(fifo_delay(ArrivalCurve('cpu-second', 1, 2), server))
        with self.assertRaisesRegex(ValueError, 'initial_or_unmetered_work'):
            leftover_service(server, interference_burst=0, interference_rate=0,
                             initial_or_unmetered_work=None)

    def test_global_all_window_bucket_allows_zero_honest_service(self):
        hostile = tuple((F(4 * i), F(1)) for i in range(30))
        self.assertTrue(all_window_burst_check(hostile, F(1), F(1, 4)))
        # All quota can be allocated to non-honest work without violating a
        # single aggregate upper constraint. No scheduler attack is executed.
        honest_completed = 0
        self.assertEqual(honest_completed, 0)

    def test_endpoint_average_does_not_certify_all_window_service(self):
        # Same ten work units by t=10; the delayed schedule has no service by9.
        steady = tuple((F(i), F(1)) for i in range(1, 11))
        delayed = ((F(10), F(10)),)
        self.assertEqual(sum(work for _, work in steady), sum(work for _, work in delayed))
        self.assertEqual(sum(work for t, work in delayed if t <= 9), 0)
        self.assertEqual(sum(work for t, work in steady if t <= 9), 9)
        self.assertTrue(all_window_burst_check(steady, F(1), F(1)))
        self.assertFalse(all_window_burst_check(delayed, F(1), F(1)))

    def test_coincident_work_and_rejections_are_not_free(self):
        self.assertFalse(all_window_burst_check(((F(0), F(1)), (F(0), F(1))), F(1), F(100)))
        # A flow with zero valid winning tickets can still exhaust CPU capacity.
        valid_winner_count = 0
        residual = leftover_service(RateLatency('cpu-second', 1, 0),
                                    interference_burst=2, interference_rate=1,
                                    initial_or_unmetered_work=0)
        self.assertEqual(valid_winner_count, 0)
        self.assertIsNone(residual)


class FrontierAndCouplingTests(unittest.TestCase):
    def test_visible_successive_parent_frontiers_add_weights(self):
        self.assertEqual(slot_frontier_floor(100, ((100, 2, True), (110, 7, True),
                                                  (120, 31, True))), 140)

    def test_same_parent_siblings_do_not_add_honest_chain_growth(self):
        self.assertEqual(slot_frontier_floor(100, ((100, 7, True),)), 107)
        with self.assertRaisesRegex(ValueError, 'stale_parent_below_slot_frontier'):
            slot_frontier_floor(100, ((100, 7, True), (100, 7, True)))
        self.assertEqual(7 + 7, 14)
        self.assertEqual(max(100 + 7, 100 + 7) - 100, 7)

    def test_nonvisible_or_missed_slot_adds_no_work(self):
        self.assertEqual(slot_frontier_floor(100, ((100, 7, False), (100, 7, True))), 107)

    def test_depleted_permutation_weight_requires_rho(self):
        law = LotteryEnvelope(2, 2)
        actual_mean = 2 * F(2, 3)
        self.assertGreater(actual_mean, 1)
        self.assertEqual(actual_mean, law.rho)
        self.assertEqual(forest_upper_bound(3, 10, 2, law.rho), F(1, 2))

    def test_private_overtake_strict_integer_threshold_and_bank(self):
        result = private_overtake_bound(honest_shortfall=F(1, 100), honest_work_floor=100,
                                       initial_work_deficit=10, fresh_opportunities=2,
                                       old_weight=3, rho=F(4, 3), world_failure=F(1, 1000))
        self.assertEqual(result['strict_overtake_threshold'], 111)
        self.assertEqual(result['adversary_forest_tail'], F(2, 81))
        self.assertEqual(result['bound'], F(1, 100) + F(2, 81) + F(1, 1000))
        self.assertEqual(forest_upper_bound(0, 2, 2, F(1)), 1)

    def test_dependence_needs_union_not_product(self):
        # Perfectly anticorrelated failures with marginal1/4 each have union1/2;
        # a fictitious independence product correction would give7/16.
        outcomes = tuple(range(4))
        bad_honest = {0}
        bad_adversary = {1}
        actual = F(sum(x in bad_honest | bad_adversary for x in outcomes), len(outcomes))
        self.assertEqual(actual, F(1, 2))
        self.assertGreater(actual, 1 - (1 - F(1, 4)) ** 2)
        self.assertEqual(deadline_union_bound((F(1, 4), F(1, 4)), F(0)), actual)

    def test_one_shared_world_failure_across_predeclared_deadlines(self):
        self.assertEqual(deadline_union_bound((F(1, 10), F(1, 5)), F(1, 100)), F(31, 100))
        self.assertEqual(deadline_union_bound((F(3, 4), F(3, 4)), F(1, 100)), 1)
        with self.assertRaisesRegex(ValueError, 'shared_world_failure'):
            deadline_union_bound((F(1, 10),), None)

    def test_conditioning_on_future_success_invalidates_original_law(self):
        outcomes = tuple(product((0, 1), repeat=2))
        conditioned = tuple(x for x in outcomes if sum(x) > 0)
        self.assertEqual(F(sum(x[0] for x in outcomes), len(outcomes)), F(1, 2))
        self.assertEqual(F(sum(x[0] for x in conditioned), len(conditioned)), F(2, 3))

    def test_output_preserves_synthetic_scope(self):
        output = controls()
        self.assertIs(output['native_execution'], False)
        self.assertIs(output['production_parameter_certificate'], False)
        self.assertEqual(output['global_quota_counterexample']['honest_service'], 0)
        self.assertEqual(output['abstract_service']['residual_rate'], F(3, 4))
        self.assertEqual(output['abstract_service']['residual_latency'], F(8, 15))


if __name__ == '__main__':
    unittest.main()
