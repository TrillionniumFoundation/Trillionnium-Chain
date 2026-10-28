#!/usr/bin/env python3
"""Parser controls use synthetic text, never claim native execution."""
import json
import unittest
from run_native_pq_quota_v3 import QUOTA_CASES,NATIVE_QUOTA_CASES,PHASE_SCHEMA,PHASE_SCOPE,quota_phases,test_result
from run_native_pq_accounts_v2 import NATIVE_CASES
from test_native_pq_accounts_v2_research import log
class QuotaReaderTests(unittest.TestCase):
    def test_exact_actual_sets_cannot_be_replaced_by_retained_pq2(self):
        for names in (QUOTA_CASES,NATIVE_QUOTA_CASES):
            rows=[(n,'ok') for n in sorted(names)]
            self.assertEqual(test_result(log(rows),names,exact=True)['passed'],len(names))
            for text in (log(rows[:-1]),log(rows,filtered=1),log([(n,'ok') for n in NATIVE_CASES]),'Finished compiling\n'):
                with self.assertRaises(ValueError): test_result(text,names,exact=True)
    @staticmethod
    def phases():
        return [{'schema':PHASE_SCHEMA,'phase':'make-complete-w1-independent-reference-admit-sql','transactions':int(n>0),'raw_bytes':n,'wall_nanoseconds':1,'block':'01'*32,'scope':PHASE_SCOPE} for n in (3821,7314,0,0,7314,3821,9272,7314,0,0,0,9432,3821,7314,0,0,0,0,9432)]
    @staticmethod
    def text(rows): return '\n'.join(json.dumps(r,separators=(',',':')) for r in rows)
    def test_complete_synthetic_phase_set_only_tests_the_reader(self):
        self.assertEqual(len(quota_phases(self.text(self.phases()))),19)
    def test_missing_duplicate_or_changed_full_byte_phase_refuses(self):
        rows=self.phases()
        for mutant in (rows[:-1],rows+[rows[0]],rows[:-1]+[rows[0]]):
            with self.assertRaises(ValueError): quota_phases(self.text(mutant))
    def test_invalid_timing_identity_or_scope_refuses(self):
        for key,value in [('wall_nanoseconds',True),('wall_nanoseconds',-1),('block','g'*64),('scope','isolated cost'),('transactions',False),('raw_bytes',7313)]:
            rows=self.phases();rows[0][key]=value
            with self.assertRaises(ValueError): quota_phases(self.text(rows))
if __name__=='__main__':unittest.main()
