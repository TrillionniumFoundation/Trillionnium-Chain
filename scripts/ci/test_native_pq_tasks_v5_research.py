#!/usr/bin/env python3
"""Synthetic parser controls only; these never count as native task execution."""
import json
from pathlib import Path
import re
import unittest
from run_native_pq_tasks_v5 import (TASK_CASES, NATIVE_TASK_CASES, EXPECTED_RAW_BYTES,
    PHASE_SCHEMA, PHASE_SCOPE, EXPECTED_OUTCOMES, task_phases, test_result, unit_result)
from run_native_pq_quota_v3 import QUOTA_CASES, NATIVE_QUOTA_CASES
from test_native_pq_accounts_v2_research import log

class TaskReaderTests(unittest.TestCase):
    def test_retained_libraries_require_every_original_case_and_only_original_ignores(self):
        for target,expected in EXPECTED_OUTCOMES.items():
            rows=sorted(expected.items())
            self.assertEqual(unit_result(log(rows,ignored=sum(v=='ignored' for _,v in rows)),target)['test_outcomes'],expected)
            first=next(i for i,(_,outcome) in enumerate(rows) if outcome=='ok')
            ignored=next(i for i,(_,outcome) in enumerate(rows) if outcome=='ignored')
            lost=rows[:first]+rows[first+1:]
            newly_ignored=rows.copy();newly_ignored[first]=(rows[first][0],'ignored')
            replaced_ignore=rows.copy();replaced_ignore[ignored]=('forged_ignored_case','ignored')
            for bad in (lost,newly_ignored,replaced_ignore,rows+[('forged_extra_case','ok')]):
                with self.assertRaises(ValueError): unit_result(log(bad,ignored=sum(v=='ignored' for _,v in bad)),target)

    @staticmethod
    def phases():
        rows=[{'schema':PHASE_SCHEMA,'phase':'maintenance','transactions':32 if n in (129696,252608,264768) else int(n>0),
            'raw_bytes':n,'proof_bytes':49188,'wall_nanoseconds':1,'block':'01'*32,'scope':PHASE_SCOPE} for n in EXPECTED_RAW_BYTES]
        for row in rows: row['packet_bytes']=8+318+2+2*row['transactions']+row['raw_bytes']+row['proof_bytes']
        for row in rows[-8:]: row['phase']='registered-material'
        next(r for r in rows if r['raw_bytes']==4121)['phase']='registered-material'
        next(r for r in rows if r['raw_bytes']==8274)['phase']='registered-material'
        return rows
    @staticmethod
    def text(rows): return '\n'.join(json.dumps(r,separators=(',',':')) for r in rows)
    def test_exact_native_task_sets_cannot_be_replaced_by_quota_or_compiled_only(self):
        for required in (TASK_CASES,NATIVE_TASK_CASES):
            rows=[(name,'ok') for name in sorted(required)]
            self.assertEqual(test_result(log(rows),required,exact=True)['passed'],len(required))
            for bad in (log(rows[:-1]),log(rows,filtered=1),log([(n,'ok') for n in QUOTA_CASES]),
                        log([(n,'ok') for n in NATIVE_QUOTA_CASES]),'Finished compiling\n'):
                with self.assertRaises(ValueError): test_result(bad,required,exact=True)
    def test_ignored_failed_and_duplicate_actual_case_labels_refuse(self):
        names=sorted(NATIVE_TASK_CASES)
        for bad in (log([(n,'ignored' if i==0 else 'ok') for i,n in enumerate(names)]),
                    log([(n,'FAILED' if i==0 else 'ok') for i,n in enumerate(names)]),
                    log([(n,'ok') for n in names]+[(names[0],'ok')])):
            with self.assertRaises(ValueError): test_result(bad,NATIVE_TASK_CASES,exact=True)
    def test_complete_synthetic_phase_set_tests_only_reader(self):
        self.assertEqual(len(task_phases(self.text(self.phases()))),37)
    def test_partial_duplicate_or_replaced_phase_set_refuses(self):
        rows=self.phases()
        for bad in (rows[:-1],rows+[rows[0]],rows[:-1]+[rows[0]]):
            with self.assertRaises(ValueError): task_phases(self.text(bad))
    def test_split_witness_cannot_hide_full_dual_proof_bytes(self):
        for value in (2000,4000,7894,8273):
            rows=self.phases(); next(r for r in rows if r['raw_bytes']==8274)['raw_bytes']=value
            with self.assertRaises(ValueError): task_phases(self.text(rows))
    def test_full_slots_require_all_transactions_and_original_w1_proof(self):
        for key,value in [('transactions',1),('raw_bytes',32*4361),('proof_bytes',0),('proof_bytes',49187)]:
            rows=self.phases(); next(r for r in rows if r['raw_bytes']==264768)[key]=value
            with self.assertRaises(ValueError): task_phases(self.text(rows))
    def test_material_path_cannot_be_renamed_maintenance(self):
        rows=self.phases(); rows[-1]['phase']='maintenance'
        with self.assertRaises(ValueError): task_phases(self.text(rows))
    def test_timing_identity_type_and_scope_cannot_be_promoted(self):
        for key,value in [('wall_nanoseconds',True),('wall_nanoseconds',0),('wall_nanoseconds',-1),
                          ('proof_bytes',True),('packet_bytes',True),('packet_bytes',0),('packet_bytes',1048577),('block','g'*64),('transactions',False),('scope','isolated worst-case accepted')]:
            rows=self.phases();rows[0][key]=value
            with self.assertRaises(ValueError): task_phases(self.text(rows))
    def test_declared_rosters_match_every_new_integration_test(self):
        root=Path(__file__).resolve().parents[2]
        for path,required in [('trillionnium/crates/trnm-mvcc-fee/tests/pq5_task_renewal.rs',TASK_CASES),
                              ('trillionnium/crates/trnm-pon-node/tests/native_pq_v5.rs',NATIVE_TASK_CASES)]:
            actual=set(re.findall(r'#\[test\]\s*fn\s+([a-z0-9_]+)\s*\(', (root/path).read_text()))
            self.assertEqual(actual,required)
    def test_atomic_and_staged_material_phases_cannot_borrow_empty_work_observations(self):
        for value in (4121,8274):
            rows=self.phases()
            row=next(r for r in rows if r['raw_bytes']==value and r['phase']=='registered-material')
            row['phase']='maintenance'
            with self.assertRaises(ValueError): task_phases(self.text(rows))
    def test_original_v4_phase_set_cannot_qualify_v5_renewal(self):
        from test_native_pq_tasks_v4_research import TaskReaderTests as Old
        rows=Old.phases()
        for row in rows: row['schema']=PHASE_SCHEMA
        with self.assertRaises(ValueError): task_phases(self.text(rows))
if __name__=='__main__': unittest.main()
