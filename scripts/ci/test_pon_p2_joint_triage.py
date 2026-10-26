"""Two independent P2 inputs must never be promoted to public security authority."""
from pathlib import Path
import copy
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pon_p2_joint_triage as J


def input_record():
    return {
        "schema": J.SCHEMA,
        "binding": {
            "source_commit": "a" * 40, "challenge": "c" * 64, "task": "b" * 64,
            "target": "f" * 64, "host_receipt_sha256": "d" * 64,
        },
        "v3_model": {
            "schema": J.v3.SCHEMA,
            "honest_hashes_per_second": "1000000",
            "honest_fixed_ms": "5",
            "cookie_lifetime_ms": "2000",
            "honest_p95_budget_ms": "2000",
            "false_w1_receiver_cost_usd": "0.000001",
            "cost_margin": "1",
            "attacker_arms": [{
                "name": "CPU-only-illustrative", "hashes_per_second": "10000000000",
                "cost_usd_per_second": "0.01", "hardware": "gpu",
                "provenance_sha256": "e" * 64,
            }],
            "measurement_identity": {"source_commit": "a" * 40,
                                     "measured_on_real_hardware": False,
                                     "independent_operator": False},
        },
        "w2c_cost": {
            "schema": J.w2c.SCHEMA,
            "ticket_scope": "receiver-bound",
            "receiver_count": 2,
            "gpu_cpu_speedup_upper_bound": 1,
            "asic_cpu_speedup_upper_bound": 1,
            "trials": [{
                "attempts": 2, "actual_ticket_search_cpu_ns": 1000,
                "full_forgery_build_cpu_ns": 100, "full_send_transport_cpu_ns": 100,
                "complete_receiver_reject_cpu_ns": 20000,
            }],
        },
    }


class JointGate(unittest.TestCase):
    def test_observed_forgery_is_a_blocker_even_if_cookie_bits_are_modeled(self):
        record = input_record()
        result = J.analyze(record)
        self.assertEqual(result["verdict"], "HOLD_NO_GO")
        self.assertIn("W2C_RECEIVER_CPU_AMPLIFICATION_OBSERVED", result["unclosed_gates"])
        self.assertFalse(result["production_activation"])
        self.assertFalse(result["source_and_host_attested_by_joint_reader"])

    def test_missing_gpu_and_sender_cost_must_not_become_safe(self):
        record = input_record()
        record["w2c_cost"]["gpu_cpu_speedup_upper_bound"] = None
        record["w2c_cost"]["trials"][0]["full_send_transport_cpu_ns"] = None
        result = J.analyze(record)
        self.assertEqual(result["w2c_observation_status"], "UNKNOWN")
        self.assertIn("W2C_ACCELERATOR_OR_TRANSPORT_UNOBSERVED", result["unclosed_gates"])

    def test_replayed_security_ticket_does_not_price_fanout(self):
        record = input_record()
        record["w2c_cost"]["ticket_scope"] = "globally-replayable"
        result = J.analyze(record)
        self.assertIn("GLOBAL_TICKET_CROSS_RECEIVER_REPLAY", result["unclosed_gates"])

    def test_allegedly_verified_hardware_still_cannot_be_attested_here(self):
        record = input_record()
        record["v3_model"]["measurement_identity"]["independent_operator"] = True
        record["v3_model"]["measurement_identity"]["measured_on_real_hardware"] = True
        result = J.analyze(record)
        self.assertFalse(result["independent_accepted"])
        self.assertIn("SOURCE_HOST_RECEIPT_NOT_INDEPENDENTLY_VERIFIED", result["unclosed_gates"])

    def test_mutated_source_and_context_reject(self):
        data = input_record()
        for name, bad in (("source_commit","f"*40), ("challenge","xyz"),
                          ("target","0"*63), ("host_receipt_sha256","A"*64)):
            sample = copy.deepcopy(data)
            sample["binding"][name] = bad
            with self.assertRaises(ValueError):
                J.analyze(sample)
        sample = input_record()
        sample["v3_model"]["measurement_identity"]["source_commit"] = "f"*40
        with self.assertRaisesRegex(ValueError,"SOURCE_MISMATCH"):
            J.analyze(sample)

    def test_unknown_surplus_field_and_authority_schema_refused(self):
        sample = input_record()
        sample["production_activation"] = True
        with self.assertRaisesRegex(ValueError,"JOINT_SCHEMA"):
            J.analyze(sample)
        sample = input_record()
        sample["w2c_cost"]["trials"][0]["actual_ticket_search_cpu_ns"] = -1
        with self.assertRaises(ValueError):
            J.analyze(sample)


if __name__ == "__main__":
    unittest.main(verbosity=2)
