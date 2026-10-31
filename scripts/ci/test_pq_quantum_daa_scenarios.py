"""Independent negative tests for *conditional* quantum/DAA sensitivity only."""
import json
from pathlib import Path
import tempfile
import unittest
from copy import deepcopy

from pq_quantum_daa_scenarios import (DEFAULT_CONFIG, InvalidScenario,
                                      compare_scenarios, load_profile,
                                      simulate, target_search_proxies)


class TestQuantumDaaScenario(unittest.TestCase):
    def setUp(self):
        self.profile = load_profile(DEFAULT_CONFIG)

    def test_chainwork_is_linear_but_sqrt_proxy_is_sublinear(self):
        first = target_search_proxies((1 << 252) - 1)
        four_times_harder = target_search_proxies((1 << 250) - 1)
        self.assertEqual(four_times_harder['chainwork'], first['chainwork'] * 4)
        self.assertEqual(four_times_harder['expected_classical_trials_proxy'],
                         first['expected_classical_trials_proxy'] * 4)
        self.assertEqual(four_times_harder['ideal_sqrt_search_index'],
                         first['ideal_sqrt_search_index'] * 2)

    def test_real_reference_daa_and_median_are_exercised(self):
        report = compare_scenarios(self.profile, 4)
        fast = report['fast_timestamp_hypothesis']['epochs']
        ordinary = report['nominal_timestamp_reference']['epochs']
        self.assertEqual(len(fast), 4)
        self.assertEqual(fast[0]['target_hex'], ordinary[0]['target_hex'])
        self.assertGreater(fast[1]['chainwork'], ordinary[1]['chainwork'])
        self.assertGreater(fast[2]['chainwork'], fast[1]['chainwork'])
        # Actual target arithmetic floors at each epoch: do not call it exact x4.
        parent_target = int(fast[0]['target_hex'], 16)
        self.assertEqual(int(fast[0]['next_target_hex'], 16),
                         parent_target * 38 // 150)
        self.assertGreater(fast[-1]['cumulative_chainwork'],
                           ordinary[-1]['cumulative_chainwork'])
        self.assertFalse(report['same_wall_clock_or_mining_budget'])
        self.assertEqual(report['status'], 'HOLD_RESEARCH_ONLY')

    def test_timestamp_median_and_future_deferral_are_explicit(self):
        from pq_quantum_daa_scenarios import timestamp_state
        ancestors = list(range(100, 111))
        self.assertEqual(timestamp_state(105, ancestors, 110, 120), 'invalid-median')
        self.assertEqual(timestamp_state(231, ancestors, 110, 120), 'deferred-future')
        self.assertEqual(timestamp_state(111, ancestors, 111, 120), 'admissible')

    def test_profile_rejects_activation_and_unmodeled_DAA(self):
        for field, value in [('production_activation', True),
                             ('retarget_factor', 8), ('retarget_interval', 4),
                             ('median_time_width', 3), ('pow_limit_hex', '00')]:
            with self.subTest(field=field):
                config = deepcopy(self.profile)
                config[field] = value
                with tempfile.TemporaryDirectory() as d:
                    path = Path(d) / 'devnet.json'
                    path.write_text(json.dumps(config))
                    with self.assertRaises(InvalidScenario):
                        load_profile(path)

    def test_malformed_and_duplicate_config_fail_closed(self):
        for data in ('{"schema":"pon-devnet-2","schema":"pon-devnet-2"}',
                     '{"schema":NaN}', '{', '[]'):
            with self.subTest(data=data):
                with tempfile.TemporaryDirectory() as d:
                    path = Path(d) / 'config.json'
                    path.write_text(data)
                    with self.assertRaises(InvalidScenario):
                        load_profile(path)

    def test_bounded_epochs_steps_and_excluded_real_attack_claims(self):
        for epochs, step in [(0, 1), (33, 1), (1, 0), (1, -1), (1, 3601), (True, 1)]:
            with self.subTest(epochs=epochs, step=step):
                with self.assertRaises(InvalidScenario):
                    simulate(self.profile, epochs, step)
        normal = simulate(self.profile, 2, 10)
        self.assertFalse(normal['quantum_hardness_qualified'])
        self.assertFalse(normal['production_activation'])
        self.assertEqual(normal['status'], 'UNQUALIFIED_HYPOTHETICAL')


if __name__ == '__main__':
    unittest.main()
