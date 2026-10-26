"""P2 counterexamples for only-conditional cost pricing, not a hardware report."""
import unittest
import w2_admission_cost_envelope as E


def evidence(**values):
    record = {
        "honest_hash_cpu_ns":None,
        "attacker_fastest_hash_ns":None,
        "invalid_w1_cpu_ns":None,
        "honest_nonhash_ns":None,
        "honest_deadline_ns":None,
        "observation_scope":"synthetic",
    }
    record.update(values)
    return record


class CostEnvelopeTests(unittest.TestCase):
    def test_absent_gpu_cost_must_keep_all_admission_bits_unknown(self):
        item=E.evaluate(evidence(honest_hash_cpu_ns=2000,invalid_w1_cpu_ns=3_000_000,
                                 honest_nonhash_ns=200_000, honest_deadline_ns=2_000_000_000))
        self.assertEqual(item["research_verdict"],"UNKNOWN_INCOMPLETE_MEASUREMENTS")
        self.assertEqual([row["conditional_feasibility"] for row in item["rows"]],[None]*4)
        self.assertFalse(item["production_consensus_activation"])

    def test_fast_attacker_hardware_exposes_expected_cost_gap(self):
        item=E.evaluate(evidence(
            honest_hash_cpu_ns=1000,attacker_fastest_hash_ns=1,
            invalid_w1_cpu_ns=3_000_000,
            honest_nonhash_ns=1_000_000,honest_deadline_ns=2_000_000_000))
        self.assertTrue(all(row["conditional_feasibility"] is False for row in item["rows"]))
        self.assertLess(item["rows"][-1]["expected_attacker_over_receiver_cpu"],1)

    def test_sample_expected_pricing_cannot_be_relabelled_cryptographic_security(self):
        item=E.evaluate(evidence(
            honest_hash_cpu_ns=1000,attacker_fastest_hash_ns=100,
            invalid_w1_cpu_ns=3_000_000,
            honest_nonhash_ns=1_000_000,honest_deadline_ns=2_000_000_000))
        result={row["bits"]:row for row in item["rows"]}
        self.assertTrue(result[16]["conditional_feasibility"])
        self.assertFalse(result[20]["conditional_feasibility"])
        self.assertEqual(item["research_verdict"],"EXPECTED_COST_CONDITIONAL_ONLY")
        self.assertFalse(item["gpu_asic_independence_proven"])
        self.assertFalse(item["permissionless_sybil_safety_proven"])
        self.assertTrue(all(x["worst_case_one_hash_attack_possible"] for x in item["rows"]))

    def test_monotone_geometric_quantile_and_strict_bounds(self):
        qs=[E.quantile_trials(b) for b in E.BITS]
        self.assertEqual(qs,sorted(qs))
        for value in (-1,0,21):
            with self.assertRaises(ValueError):
                E.quantile_trials(value)
        with self.assertRaises(ValueError):
            E.evaluate(evidence(honest_deadline_ns=float("inf")))
        with self.assertRaises(ValueError):
            E.evaluate(evidence(honest_deadline_ns=1,honest_nonhash_ns=1))
        with self.assertRaises(ValueError):
            E.evaluate(evidence(fake_extra_record=True))


if __name__ == "__main__":
    unittest.main(verbosity=2)
