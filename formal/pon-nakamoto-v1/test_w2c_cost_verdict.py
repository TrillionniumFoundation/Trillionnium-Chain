"""Cost-verdict negatives, no guessed GPU price or public activation."""
import copy
import unittest
import w2c_cost_verdict as V

def case():
    return {"schema":V.SCHEMA,"ticket_scope":"receiver-bound","receiver_count":2,
            "gpu_cpu_speedup_upper_bound":1,"asic_cpu_speedup_upper_bound":1,
            "trials":[{"attempts":2,"actual_ticket_search_cpu_ns":1_000,
                       "full_forgery_build_cpu_ns":100,"full_send_transport_cpu_ns":100,
                       "complete_receiver_reject_cpu_ns":20_000}]}

class ConservativeCostTests(unittest.TestCase):
    def test_fast_forgery_must_report_observed_amplification(self):
        result=V.decide(case())
        self.assertEqual(result["status"],"OBSERVED_AMPLIFICATION")
        self.assertFalse(result["production_qualified"])

    def test_missing_hardware_or_transport_is_unknown(self):
        for key in ("gpu_cpu_speedup_upper_bound","asic_cpu_speedup_upper_bound"):
            data=case();data[key]=None
            self.assertEqual(V.decide(data)["status"],"UNKNOWN")
        data=case();del data["trials"][0]["full_send_transport_cpu_ns"]
        self.assertEqual(V.decide(data)["status"],"UNKNOWN")

    def test_globally_replayable_ticket_multiplies_receiver_cost(self):
        data=case()
        data["trials"][0]["actual_ticket_search_cpu_ns"]=35_000
        data["trials"][0]["complete_receiver_reject_cpu_ns"]=20_000
        self.assertEqual(V.decide(data)["status"],"NO_OBSERVED_AMPLIFICATION")
        data["ticket_scope"]="globally-replayable"
        self.assertEqual(V.decide(data)["status"],"OBSERVED_AMPLIFICATION")

    def test_accelerator_advantage_can_reverse_observed_verdict(self):
        data=case()
        data["trials"][0]["actual_ticket_search_cpu_ns"]=40_000
        data["trials"][0]["complete_receiver_reject_cpu_ns"]=20_000
        self.assertEqual(V.decide(data)["status"],"NO_OBSERVED_AMPLIFICATION")
        data["gpu_cpu_speedup_upper_bound"]=4
        self.assertEqual(V.decide(data)["status"],"OBSERVED_AMPLIFICATION")

    def test_malformed_and_overflow_reject_not_pass(self):
        for edit in (
            lambda d:d.update(receiver_count=0),
            lambda d:d.update(trials=[]),
            lambda d:d["trials"][0].update(attempts=0),
            lambda d:d["trials"][0].update(full_forgery_build_cpu_ns=-1),
            lambda d:d.update(gpu_cpu_speedup_upper_bound=1000001),
            lambda d:d["trials"][0].update(actual_ticket_search_cpu_ns=(1<<63)-1,
                                            full_forgery_build_cpu_ns=2),
        ):
            data=case();edit(data)
            with self.assertRaises(ValueError): V.decide(data)

    def test_known_cost_is_never_production_qualification(self):
        data=case()
        data["trials"][0]["actual_ticket_search_cpu_ns"]=10**9
        data["trials"][0]["complete_receiver_reject_cpu_ns"]=100
        result=V.decide(data)
        self.assertEqual(result["status"],"NO_OBSERVED_AMPLIFICATION")
        self.assertIs(result["production_qualified"],False)
        self.assertIs(result["no_consensus_authority"],True)

if __name__=="__main__":
    unittest.main(verbosity=2)
