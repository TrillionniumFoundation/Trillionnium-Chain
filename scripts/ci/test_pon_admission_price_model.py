from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import copy
import unittest
import pon_admission_price_model as M

def sample():
    return {'schema':M.SCHEMA,'honest_hashes_per_second':'1000000',
            'honest_fixed_ms':'5','cookie_lifetime_ms':'2000',
            'honest_p95_budget_ms':'2000','false_w1_receiver_cost_usd':'0.000001',
            'cost_margin':'1','attacker_arms':[
                {'name':'synthetic-gpu','hashes_per_second':'10000000000',
                 'cost_usd_per_second':'0.01','hardware':'gpu',
                 'provenance_sha256':'f'*64}],
            'measurement_identity':{'source_commit':'a'*40,'measured_on_real_hardware':False,
                                    'independent_operator':False}}

class PriceGate(unittest.TestCase):
    def test_no_solution_when_needed_20_bit_hashcash_exceeds_cookie(self):
        out=M.evaluate(sample())
        self.assertEqual(len(out['rows']),13)
        self.assertEqual(out['model_feasible_bits'],[])
        self.assertFalse(out['production_activation'])
        self.assertGreater(float(out['rows'][-1]['honest_p95_total_ms']),2000)
    def test_slower_receiver_can_have_a_model_solution_but_no_activation(self):
        data=sample();data['false_w1_receiver_cost_usd']='0.000000001'
        out=M.evaluate(data)
        self.assertTrue(out['model_has_solution'])
        self.assertFalse(out['independent_security_accepted'])
    def test_fast_gpu_wins_cheapest_attacker_arm(self):
        data=sample();data['attacker_arms'].append({'name':'synthetic-cpu',
            'hashes_per_second':'1000000','cost_usd_per_second':'0.01',
            'hardware':'cpu','provenance_sha256':'e'*64})
        out=M.evaluate(data)
        self.assertEqual(out['rows'][0]['attacker_cheapest_hardware'],'gpu')
    def test_missing_and_bad_measures_fail_closed(self):
        for key,value in [('cost_margin','nan'),('honest_hashes_per_second','0'),('cookie_lifetime_ms','3000')]:
            d=sample();d[key]=value
            with self.assertRaises(ValueError):M.evaluate(d)
        d=sample();d['attacker_arms'][0]['provenance_sha256']='deadbeef'
        with self.assertRaises(ValueError):M.evaluate(d)
        d=sample();d['measurement_identity']['source_commit']='wrong'
        with self.assertRaises(ValueError):M.evaluate(d)

if __name__=='__main__':unittest.main(verbosity=2)
