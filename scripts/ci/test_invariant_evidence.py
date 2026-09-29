#!/usr/bin/env python3
"""Mutations of recorded evidence must not manufacture stronger acceptance."""
import copy,hashlib,json,shutil,tempfile,unittest
from pathlib import Path
from check_invariant_evidence import ROOT,validate

class InvariantEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='pon-evidence-negative-')
        cls.evidence=Path(cls.temp.name)/'evidence'
        shutil.copytree(ROOT/'evidence/pon-v3',cls.evidence)
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    def mutate(self,relative,change):
        p=self.evidence/relative;raw=p.read_bytes();mp=self.evidence/'manifest.json';original=mp.read_bytes()
        try:
            data=json.loads(raw);change(data);p.write_text(json.dumps(data,indent=2)+'\n')
            m=json.loads(original);m['files'][relative]=hashlib.sha256(p.read_bytes()).hexdigest();mp.write_text(json.dumps(m))
            with self.assertRaises(ValueError):validate(ROOT,self.evidence,require_current_runtime=False)
        finally:p.write_bytes(raw);mp.write_bytes(original)
    def test_recorded_source_and_results(self):
        result=validate(ROOT,self.evidence,require_current_runtime=False)
        self.assertFalse(result['independent_accepted']);self.assertGreater(result['executed_invariant_selectors'],0)
    def test_prior_execution_cannot_be_promoted_to_current_runtime(self):
        historical=validate(ROOT,self.evidence,require_current_runtime=False)
        self.assertFalse(historical['runtime_matches_measured_source'])
        with self.assertRaisesRegex(ValueError,'runtime changed'):
            validate(ROOT,self.evidence,require_current_runtime=True)
    def test_runtime_failure_is_not_success(self):
        self.mutate('qualification/report.json',lambda d:d['results'][0].update(returncode=1))
    def test_native_count_cannot_be_inflated(self):
        def inflate(data):
            row=next(r for r in data['results']if r['command'][:2]==['cargo','test']and '--workspace'in r['command']and '--all-targets'in r['command'])
            row['passed']+=1
        self.mutate('qualification/report.json',inflate)
    def test_dirty_source_is_not_exact_head(self):
        self.mutate('qualification/report.json',lambda d:d.update(source_clean=False))
    def test_wrong_source_commit_is_rejected(self):
        self.mutate('qualification/report.json',lambda d:d.update(source_commit='0'*40))
    def test_fixture_history_cannot_be_real_work(self):
        self.mutate('long-history/report.json',lambda d:d.update(used_inserted_history_fixtures=True))
    def test_executor_sample_cannot_be_chain_tps(self):
        self.mutate('parallel/report.json',lambda d:d['samples'][0].update(client_confirmed=64))
    def test_parallel_different_roots_reject(self):
        self.mutate('parallel/report.json',lambda d:d['samples'][0].update(root='0'*64))
    def test_busy_and_recomputed_counts_must_conserve(self):
        self.mutate('work/admission.json',lambda d:d.update(busy_before_work=d['attempted_public_jobs']))
    def test_no_implicit_public_fairness(self):
        self.mutate('work/admission.json',lambda d:d.update(permissionless_honest_admission_guaranteed=True))
    def test_no_cost_theorem_from_timing(self):
        self.mutate('work/structured.json',lambda d:d.update(hardness_accepted=True))
    def test_failed_learning_cannot_be_paid(self):
        self.mutate('learning/report.json',lambda d:d.update(total_model_reward=1))
    def test_training_attempts_cannot_be_improving_generations(self):
        self.mutate('learning/report.json',lambda d:d.update(three_improving_public_generations=True))
    def test_multihost_is_not_independent_operation(self):
        self.mutate('multihost/report.json',lambda d:d.update(independent_operators=True))
    def test_process_crash_is_not_power_loss(self):
        self.mutate('multihost/report.json',lambda d:d.update(physical_power_loss=True))
    def test_public_owner_path_cannot_be_fabricated(self):
        self.mutate('multihost/report.json',lambda d:d.update(ordinary_hepta_entry=True))
    def test_page_limit_is_not_a_physical_disk_outage(self):
        self.mutate('multihost/disk-errors.json',lambda d:d['results'][0]['report']['cases'][2].update(physical_device_full=True))
    def test_initial_harness_failure_cannot_be_hidden(self):
        self.mutate('multihost/disk-errors-initial-harness-failure.json',lambda d:d.update(all_cases_passed=True))
    def test_raw_log_tampering_is_rejected(self):
        p=self.evidence/'qualification/7.log';data=p.read_bytes()
        try:
            p.write_bytes(b'OK\n')
            with self.assertRaises(ValueError):validate(ROOT,self.evidence,require_current_runtime=False)
        finally:p.write_bytes(data)

if __name__=='__main__':unittest.main(verbosity=2)
