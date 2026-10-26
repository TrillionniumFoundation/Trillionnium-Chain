import copy
import unittest
from campaign_gate import *

class CampaignTests(unittest.TestCase):
    def sample(self):
        return dict(schema="trnm-continuous-native-pipeline-v1", requested_blocks=2, transactions_per_block=4,
                    accepted_transactions=8, confirmed_transactions=8, pending_confirmation_blocks=0,
                    whole_campaign_seconds=20, whole_campaign_confirmed_transactions_per_second=.4,
                    logical_pacing=False, campaign_passed=True, producer_validator_heads_agree=True,
                    network="n",parameters="p",genesis="g",transaction_type="transfer",pattern="hot",
                    pace_ms=1000,admission_profile="connection-work-v1",
                    stage_counts=dict(input_constructed=8,execution_and_work_completed=8,local_durable_admitted=8,
                                      local_active=8,remote_acknowledged=8,remote_membership_verified=8,policy_confirmed=8))

    def test_confirmed_not_inclusion_rate(self):
        s=self.sample();s["measured_inclusion_transactions_per_second"]=1000
        self.assertEqual(pipeline_observation(s)["confirmed_goodput_including_drain"],.4)

    def test_failed_observation_keeps_denominator_and_has_no_speedup(self):
        a=self.sample();b=copy.deepcopy(a);b["campaign_passed"]=False
        b["confirmed_transactions"]=4;b["stage_counts"]["policy_confirmed"]=4
        b["whole_campaign_confirmed_transactions_per_second"]=.2;b["pending_confirmation_blocks"]=1
        r=compare_pipeline(a,b,"same-host-profile","same-host-profile")
        self.assertEqual(r["candidate"]["unsuccessful_or_unobserved_transactions"],4)
        self.assertIsNone(r["observed_goodput_ratio"])

    def test_false_success_rejected(self):
        s=self.sample();s["pending_confirmation_blocks"]=1
        with self.assertRaises(Refusal):pipeline_observation(s)

    def test_nonfinite_zero_bool_time_refused(self):
        for v in (0,True,float("nan"),float("inf"),-1):
            s=self.sample();s["whole_campaign_seconds"]=v
            with self.assertRaises(Refusal):pipeline_observation(s)

    def test_counter_inflation_refused(self):
        s=self.sample();s["confirmed_transactions"]=9
        with self.assertRaises(Refusal):pipeline_observation(s)

    def test_stage_inflation_refused(self):
        s=self.sample();s["stage_counts"]["remote_acknowledged"]=7
        with self.assertRaises(Refusal):pipeline_observation(s)

    def test_claimed_rate_recomputed(self):
        s=self.sample();s["whole_campaign_confirmed_transactions_per_second"]=8
        with self.assertRaises(Refusal):pipeline_observation(s)

    def test_hot_and_disjoint_not_comparable(self):
        a=self.sample();b=self.sample();b["pattern"]="disjoint4"
        with self.assertRaises(Refusal):compare_pipeline(a,b,"same","same")

    def test_security_and_hardware_mismatch_refused(self):
        a=self.sample();b=self.sample();b["admission_profile"]="legacy-development"
        with self.assertRaises(Refusal):compare_pipeline(a,b,"same","same")
        with self.assertRaises(Refusal):compare_pipeline(a,a,"x64","arm64")

    def test_logical_measurement_never_public_tps(self):
        s=self.sample();s["logical_pacing"]=True
        r=pipeline_observation(s)
        self.assertTrue(r["logical_pacing"]);self.assertFalse(r["saturation_accepted"])

    def test_learning_source_substitution_refused_before_existing_owner(self):
        pair={k:"a"*40 for k in PAIR_FIELDS}
        with self.assertRaisesRegex(Refusal,"SOURCE_PAIR"):
            verify_learning_packet(dict(pair={}),dict(pair=pair))

    def test_learning_absent_three_generations_cannot_be_promoted(self):
        pair={k:"a"*40 for k in PAIR_FIELDS}
        p=dict(pair=pair,campaign="b"*64,history_hex="",generations=[])
        t=dict(pair=pair,campaign="b"*64,initial_model="c"*64,history="d"*64)
        with self.assertRaisesRegex(Refusal,"THREE_GENERATIONS"):
            verify_learning_packet(p,t)

    def test_good_local_ratio_does_not_grant_general_speedup(self):
        a=self.sample();b=self.sample();b["whole_campaign_seconds"]=10;b["whole_campaign_confirmed_transactions_per_second"]=.8
        r=compare_pipeline(a,b,"same","same")
        self.assertEqual(r["observed_goodput_ratio"],2)
        self.assertFalse(r["general_speedup_accepted"])

if __name__=="__main__":unittest.main()
