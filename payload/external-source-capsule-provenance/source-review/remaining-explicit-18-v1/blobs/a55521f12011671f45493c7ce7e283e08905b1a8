#!/usr/bin/env python3
"""Mutation tests keep actual runtime and bounded-performance evidence distinct."""
import hashlib,json,shutil,tempfile,unittest
from pathlib import Path
from check_completion_evidence import ROOT,validate
class CompletionEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(prefix='pon-continuation-evidence-')
        cls.folder=Path(cls.tmp.name)/'evidence';shutil.copytree(ROOT/'evidence/pon-v4',cls.folder)
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()
    def mutate(self,path,change):
        p=self.folder/path;raw=p.read_bytes();m=self.folder/'manifest.json';before=m.read_bytes()
        try:
            data=json.loads(raw);change(data);p.write_text(json.dumps(data,indent=2)+'\n')
            if path!='manifest.json':
                index=json.loads(before);index['files'][path]=hashlib.sha256(p.read_bytes()).hexdigest();m.write_text(json.dumps(index))
            with self.assertRaises(ValueError):validate(ROOT,self.folder)
        finally:p.write_bytes(raw);m.write_bytes(before)
    def test_current_receipt(self):self.assertTrue(validate(ROOT,self.folder)['runtime_matches'])
    def test_model_generations_cannot_be_invented(self):self.mutate('manifest.json',lambda d:d.update(three_improving_generations=True))
    def test_hepta_owner_cannot_be_invented(self):self.mutate('manifest.json',lambda d:d.update(ordinary_hepta_entry=True))
    def test_no_independent_operator_from_same_owner(self):self.mutate('manifest.json',lambda d:d.update(independent_accepted=True))
    def test_old_campaign_cannot_be_promoted(self):self.mutate('manifest.json',lambda d:d['historical_evidence'].update(claimed_current_runtime=True))
    def test_bad_exit_is_not_a_pass(self):self.mutate('qualification/report.json',lambda d:d['results'][0].update(returncode=1))
    def test_dirty_execution_not_qualified(self):self.mutate('qualification/report.json',lambda d:d.update(source_clean=False))
    def test_included_count_cannot_be_inferred(self):self.mutate('comparison/report.json',lambda d:d['samples'][0].update(included=64))
    def test_missing_binary_samples_reject(self):self.mutate('comparison/report.json',lambda d:d['samples'].pop())
    def test_changed_root_rejects_even_after_rehash(self):self.mutate('comparison/report.json',lambda d:d['samples'][0].update(root='0'*64))
    def test_different_inputs_not_comparable(self):self.mutate('comparison/report.json',lambda d:d['samples'][0].update(input_sha256='0'*64))
    def test_summary_cannot_hide_regression(self):self.mutate('comparison/report.json',lambda d:d['summary'][0].update(candidate_median_ns=1))
    def test_worker_creation_bound_is_real(self):
        def change(d):next(x for x in d['samples']if x['binary']=='candidate')['metrics']['workers_spawned']=999
        self.mutate('comparison/report.json',change)
    def test_signature_count_does_not_disappear(self):
        def change(d):next(x for x in d['samples']if x['binary']=='candidate')['metrics']['signature_verifications']=0
        self.mutate('comparison/report.json',change)
    def test_raw_log_cannot_be_replaced(self):
        m=json.loads((self.folder/'manifest.json').read_text());path=next(x for x in m['files']if x.startswith('qualification/')and x.endswith('.log'))
        p=self.folder/path;old=p.read_bytes()
        try:
            p.write_bytes(b'OK\n')
            with self.assertRaises(ValueError):validate(ROOT,self.folder)
        finally:p.write_bytes(old)
if __name__=='__main__':unittest.main(verbosity=2)
