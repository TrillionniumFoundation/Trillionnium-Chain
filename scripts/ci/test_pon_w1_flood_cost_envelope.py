#!/usr/bin/env python3
"""Source-level negative controls for read-only W1 flood cost arithmetic."""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pon_w1_flood_cost_envelope as E


def fixture():
    return {
        'schema': E.SCHEMA,
        'source': {'head':'1'*64, 'tree':'2'*64,
                   'profile':'pon-matmul-transcript-64-v1'},
        'cases': [{
            'proof_sha256':'a'*64, 'complete_attacker_cpu_ns':1000,
            'attempted_trials':2,
            'trials':[{'nonce':0,'ticket_hit':False,'cpu_ns':10},
                      {'nonce':1,'ticket_hit':True,'cpu_ns':20}],
            'receivers':[
                {'call_sha256':'3'*64,'node_claim_sha256':'5'*64,
                 'outcome':'TRANSCRIPT','whole_receiver_cpu_ns':8000,
                 'chainwork_granted':False},
                {'call_sha256':'4'*64,'node_claim_sha256':'6'*64,
                 'outcome':'TRANSCRIPT','whole_receiver_cpu_ns':4000,
                 'chainwork_granted':False},
            ],
        }],
    }


class FloodCostSourceTests(unittest.TestCase):
    def test_one_forgery_many_receivers_pays_producer_once(self):
        result=E.analyze(fixture())
        self.assertEqual((result['cases'],result['unique_proofs'],result['calls']),(1,1,2))
        self.assertEqual(result['total_attacker_cpu_ns'],1000)
        self.assertEqual(result['total_receiver_cpu_ns'],12000)
        self.assertEqual(result['observed_aggregate_amplification']['numerator'],12)
        self.assertEqual(result['observed_aggregate_amplification']['denominator'],1)
        self.assertEqual(result['scope_verdict'],'CPU_ONLY_OBSERVATION')
        self.assertEqual(result['public_fairness_or_security_verdict'],'UNKNOWN')
        self.assertFalse(result['p0_to_p6_closed'])

    def test_unknown_cpu_and_zero_cost_never_convert_into_security_pass(self):
        for field in ('complete_attacker_cpu_ns','whole_receiver_cpu_ns'):
            row=fixture()
            if field=='complete_attacker_cpu_ns':
                row['cases'][0][field]=None
            else:
                row['cases'][0]['receivers'][0][field]=None
            result=E.analyze(row)
            self.assertEqual(result['scope_verdict'],'UNKNOWN')
            self.assertIsNone(result['observed_aggregate_amplification'])
        row=fixture()
        row['cases'][0]['complete_attacker_cpu_ns']=0
        row['cases'][0]['trials'][0]['cpu_ns']=0
        row['cases'][0]['trials'][1]['cpu_ns']=0
        self.assertIsNone(E.analyze(row)['observed_aggregate_amplification'])

    def test_proof_double_charge_and_duplicate_calls_refuse(self):
        for target in ('cases','receivers'):
            row=fixture()
            if target=='cases':
                row['cases'].append(copy.deepcopy(row['cases'][0]))
            else:
                row['cases'][0]['receivers'].append(copy.deepcopy(
                    row['cases'][0]['receivers'][0]))
            with self.assertRaisesRegex(ValueError,'DOUBLE_CHARGED_PROOF|DUPLICATE_CALL'):
                E.analyze(row)

    def test_cherry_picked_trials_and_false_chainwork_refuse(self):
        for mutation in (
            lambda d: d['cases'][0].update(attempted_trials=1),
            lambda d: d['cases'][0]['trials'][0].update(ticket_hit=True),
            lambda d: d['cases'][0]['trials'][0].update(nonce=9),
            lambda d: d['cases'][0].update(complete_attacker_cpu_ns=1),
            lambda d: d['cases'][0]['receivers'][1].update(chainwork_granted=True),
        ):
            row=fixture()
            mutation(row)
            with self.assertRaises(ValueError):
                E.analyze(row)

    def test_bool_cpu_negative_cpu_and_missing_source_refuse(self):
        for mutation in (
            lambda d: d['cases'][0].update(complete_attacker_cpu_ns=True),
            lambda d: d['cases'][0]['receivers'][0].update(whole_receiver_cpu_ns=-1),
            lambda d: d['source'].update(head='bad'),
        ):
            row=fixture()
            mutation(row)
            with self.assertRaises(ValueError):
                E.analyze(row)

    def test_untrusted_json_duplicate_nonfinite_float_refused(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'input.json'
            for raw in ('{"schema":"x","schema":"y"}',
                        '{"cpu":NaN}',
                        '{"cpu":0.25}'):
                path.write_text(raw)
                with self.assertRaises(ValueError):
                    E.read(path)

    def test_no_attacker_asic_or_host_independence_claim(self):
        result=E.analyze(fixture())
        for field in ('source_attestation_checked',
                      'sample_hardware_independence_checked',
                      'attacker_gpu_asic_cost_measured',
                      'payload_relation_independently_verified',
                      'production_activation'):
            self.assertFalse(result[field])


if __name__=='__main__':
    unittest.main(verbosity=2)
