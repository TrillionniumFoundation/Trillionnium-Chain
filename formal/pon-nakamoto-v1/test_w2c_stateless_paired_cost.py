"""Controlled cost denominator tests, not public attack economic certification."""
import unittest
import w2c_stateless_paired_cost as C

class PairedCpuCostResearchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.observation = C.run(seed=1,samples=1,bits=(8,),w1_attempts=4,ticket_attempts=1024)

    def test_same_task_target_and_complete_valid_misses_are_retained(self):
        d=self.observation
        self.assertEqual(d['w1_oracle_blob_sha1'],C.EXPECTED_W1_ORACLE_BLOB)
        self.assertFalse(d['native_rust_runtime'])
        self.assertFalse(d['real_v3_cookie'])
        self.assertIsNone(d['gpu_cost'])
        self.assertEqual(len(d['rows']),1)
        row=d['rows'][0]
        self.assertEqual(row['status'],'COMPLETE_TICKET_PAID')
        self.assertEqual(row['false_relation_error'],'TRANSCRIPT')
        self.assertFalse(row['false_work_accepted'])
        self.assertFalse(row['w2c_grants_chainwork'])
        self.assertGreaterEqual(row['legal_full_search_cpu_ns'],row['legal_verify_cpu_ns']/10)
        self.assertEqual(row['work_attempts_executed'],len(row['work_attempts']))
        self.assertTrue(row['work_attempts'][-1]['target_hit'])
        self.assertEqual(row['legal_full_search_cpu_ns'],sum(a['producer_cpu_ns'] for a in row['work_attempts']))
        self.assertTrue(all(not a['target_hit'] for a in row['work_attempts'][:-1]))
        self.assertTrue(all(not a['target_hit'] for a in row['false_attempts'][:-1]))

    def test_exhausted_cost_ticket_must_not_look_paid(self):
        d=C.run(seed=1,samples=1,bits=(8,),w1_attempts=4,ticket_attempts=1)
        row=d['rows'][0]
        self.assertIn(row['status'],('FALSE_TICKET_EXHAUSTED','W2C_TICKET_EXHAUSTED'))
        self.assertFalse(row['verified_work'] if 'verified_work' in row else row['w2c_grants_chainwork'])
        if row['status']=='W2C_TICKET_EXHAUSTED':
            self.assertIsNone(row['w2c_admission'])
            self.assertIsNone(row['w2c_consume_cpu_ns'])

    def test_bounds_do_not_coerce_invalid_limits(self):
        for kwargs in [dict(samples=0),dict(samples=9),dict(bits=(7,)),
                       dict(bits=(8,8)),dict(w1_attempts=0),dict(ticket_attempts=0),
                       dict(seed=-1)]:
            with self.assertRaisesRegex(ValueError,'BOUNDED_INPUT'):
                C.run(**kwargs)

if __name__=='__main__':unittest.main(verbosity=2)
