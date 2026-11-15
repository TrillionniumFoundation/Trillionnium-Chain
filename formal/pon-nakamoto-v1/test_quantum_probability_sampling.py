"""Exact finite random-word controls; no physical quantum qualification."""
from __future__ import annotations

from fractions import Fraction
import json
import math
from pathlib import Path
import random
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "experiments"))

from quantum_adversarial_search import TrialCosts, sample_binary_probability
from quantum_network_sim import NetworkScenario, Simulator, Trial
import w1_marked_domain
from experiments import quantum_adversarial_campaign as adversarial
from experiments import quantum_network_campaign as network
from experiments import quantum_resource_clock_campaign as resources
from experiments import w1_marked_domain_campaign as literal


class Words:
    def __init__(self, words):
        self.words = iter(words)
        self.widths = []
        self.float_calls = 0

    def getrandbits(self, width):
        self.widths.append(width)
        word = next(self.words)
        if not 0 <= word < (1 << width):
            raise AssertionError("control word outside declared uniform support")
        return word

    def random(self):
        # An actual 53-bit grid contains zero. For the tail path below it makes
        # the old comparison succeed even though the chosen 60-bit word fails.
        self.float_calls += 1
        return 0.0


class ExactProbabilitySamplingTests(unittest.TestCase):
    def test_enumerated_small_dyadic_support_has_exact_success_mass(self):
        for bits in range(1, 7):
            for numerator in range(1, 1 << bits):
                expected = Fraction(numerator, 1 << bits)
                words = Words(range(expected.denominator))
                wins = sum(sample_binary_probability(words, float(expected))
                           for _ in range(expected.denominator))
                self.assertEqual(Fraction(wins, expected.denominator), expected)
                self.assertEqual(words.float_calls, 0)

    def test_rare_and_subnormal_tails_use_the_complete_integer_support(self):
        for exponent in (54, 60, 255, 1022, 1074):
            with self.subTest(exponent=exponent):
                words = Words((0, 1, (1 << exponent) - 1))
                probability = math.ldexp(1.0, -exponent)
                self.assertEqual([sample_binary_probability(words, probability)
                                  for _ in range(3)], [True, False, False])
                self.assertEqual(words.widths, [exponent] * 3)
                self.assertEqual(words.float_calls, 0)

    def test_largest_probability_below_one_retains_its_failure_word(self):
        probability = math.nextafter(1.0, 0.0)
        words = Words(((1 << 53) - 2, (1 << 53) - 1))
        self.assertTrue(sample_binary_probability(words, probability))
        self.assertFalse(sample_binary_probability(words, probability))
        self.assertEqual(words.widths, [53, 53])

    def test_zero_and_one_need_no_random_draws(self):
        words = Words(())
        for probability in (0, 0.0, 1, 1.0):
            self.assertIs(sample_binary_probability(words, probability), bool(probability))
        self.assertEqual(words.widths, [])
        self.assertEqual(words.float_calls, 0)

    def test_invalid_probability_refuses_before_randomness(self):
        words = Words(())
        for probability in (True, False, None, "0.5", Fraction(1, 2), -0.1,
                            math.nextafter(1.0, math.inf), math.nan, math.inf, -math.inf):
            with self.subTest(probability=probability):
                with self.assertRaisesRegex(ValueError, "PROBABILITY"):
                    sample_binary_probability(words, probability)
        self.assertEqual(words.widths, [])

    def test_network_tail_failure_does_not_create_a_winning_proof(self):
        sim = Simulator(NetworkScenario("dyadic_tail_control",
                        classical_block_rate_at_initial_target=0, quantum_initial_factor=0))
        words = Words((1,))
        sim.rngs["q"] = words
        sim.active["q"] = Trial(1, "q", "prefix", sim.base.timestamp + 1,
                sim.initial_target, False, 0.0, 1.0, 0, 2.0 ** -60, 0.0, 1.0)
        sim.now = 1.0
        sim._search_done("q", 1)
        self.assertEqual(sim.counts["q"]["searches_failed"], 1)
        self.assertEqual(sim.counts["q"]["proofs_started"], 0)
        self.assertEqual(words.widths, [60])
        self.assertEqual(words.float_calls, 0)

    def test_literal_measurements_and_nonce_choices_use_integer_draws(self):
        template = literal.with_parameters(literal.retained.reduced_template(), 4,
                                           target=(1 << 255) - 1)
        domain = w1_marked_domain.enumerate_domain(template)
        self.assertGreater(domain["marked_count"], 0)
        self.assertLess(domain["marked_count"], domain["domain_size"])

        class IntegerOnlyRandom(random.Random):
            def random(self):
                raise AssertionError("53-bit floating draw reached literal measurements")

            def getrandbits(self, width):
                return super().getrandbits(width)

        with patch.object(w1_marked_domain.random, "Random", IntegerOnlyRandom):
            result = w1_marked_domain.simulate_measurements(
                (domain,), ((0, 0), (0, 1)), 3, 20261112,
                TrialCosts(1, 2, 3, 5, 7, 11, "upward"))
        self.assertEqual(result["schema"], "trnm-w1-literal-domain-measurements-v3")
        self.assertEqual(result["measurement_sampler"],
                         "exact-dyadic-Bernoulli-of-binary64-probability")
        self.assertEqual(domain["schema"], "trnm-w1-literal-marked-domain-v1")
        for trial in result["trials"]:
            for sample in trial["measurements"]:
                self.assertIs(sample["winner"], domain["outcomes"][sample["nonce"]]["winner"])

    def test_network_and_adversarial_readers_refuse_historical_random_streams(self):
        for module, prefix in ((network, "trnm-quantum-network-campaign"),
                               (adversarial, "trnm-quantum-adversarial-campaign")):
            self.assertEqual(module.SCHEMA, prefix + "-v3")
            for version in (1, 2):
                with self.subTest(prefix=prefix, version=version), tempfile.TemporaryDirectory() as tmp:
                    out = Path(tmp)
                    report = {key: None for key in getattr(module, "REPORT_KEYS", ())}
                    report["schema"] = prefix + "-v" + str(version)
                    (out / "report.json").write_text(json.dumps(report))
                    (out / "manifest.json").write_text("{}")
                    with self.assertRaisesRegex(ValueError, "REPORT_SCHEMA"):
                        module.verify_campaign(out)

    def test_literal_and_resource_readers_refuse_historical_random_streams(self):
        self.assertEqual(literal.SCHEMA, "trnm-w1-literal-domain-campaign-v3")
        for version in (1, 2):
            with self.assertRaisesRegex(ValueError, "CAMPAIGN_SCHEMA"):
                literal.replay_campaign({"schema": "trnm-w1-literal-domain-campaign-v" + str(version)})
        self.assertEqual(resources.SCHEMA, "trnm-quantum-resource-clock-campaign-v2")
        with self.assertRaisesRegex(ValueError, "RESOURCE_CAMPAIGN_SCHEMA"):
            resources.verify({"schema": "trnm-quantum-resource-clock-campaign-v1"})


if __name__ == "__main__":
    unittest.main()
