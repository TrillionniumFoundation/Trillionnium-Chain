#!/usr/bin/env python3
import hashlib,json,shutil,tempfile,unittest
from pathlib import Path
from check_pon_evidence import validate
ROOT=Path(__file__).resolve().parents[2]
class EvidenceRejectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='pon-evidence-mutant-');self.e=Path(self.tmp.name)/'evidence';shutil.copytree(ROOT/'evidence/pon-v1',self.e)
    def tearDown(self):self.tmp.cleanup()
    def mutate(self,file,action):
        p=self.e/file;d=json.loads(p.read_text());action(d);p.write_text(json.dumps(d)+'\n')
        if file!='manifest.json':
            p=self.e/'manifest.json';m=json.loads(p.read_text());m['files'][file]=hashlib.sha256((self.e/file).read_bytes()).hexdigest();p.write_text(json.dumps(m)+'\n')
    def reject(self):
        with self.assertRaises(ValueError):validate(ROOT,self.e)
    def test_current_local_evidence(self):self.assertFalse(validate(ROOT,self.e)['independent_accepted'])
    def test_independent_acceptance_cannot_be_fabricated(self):self.mutate('manifest.json',lambda d:d.update(independent_accepted=True));self.reject()
    def test_failed_experiment_cannot_be_omitted(self):self.mutate('manifest.json',lambda d:d['files'].pop('exploratory-failure/report.json'));self.reject()
    def test_raw_artifact_cannot_be_swapped(self):
        with(self.e/'artifacts/model.json').open('ab')as f:f.write(b' ')
        self.reject()
    def test_future_window_claim_rejected_even_after_rehash(self):self.mutate('summary.json',lambda d:d['model'].update(future_window_accepted=True));self.reject()
    def test_best_expert_control_cannot_be_hidden(self):self.mutate('summary.json',lambda d:d['model'].update(best_single_correct=0));self.reject()
    def test_skipped_campaign_cannot_be_a_pass(self):self.mutate('campaign.json',lambda d:d['commands'].pop());self.reject()
    def test_source_digest_cannot_be_stale(self):self.mutate('manifest.json',lambda d:d['source_files_sha256'].update({'formal/pon-nakamoto-v1/ledger.py':'0'*64}));self.reject()
    def test_evidence_path_cannot_escape(self):self.mutate('manifest.json',lambda d:d['files'].update({'../outside':'0'*64}));self.reject()
if __name__=='__main__':unittest.main(verbosity=2)
