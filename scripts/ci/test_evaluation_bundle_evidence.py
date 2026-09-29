#!/usr/bin/env python3
"""Mutate current scope and executed artifacts; never infer independence from hashes."""
import hashlib,json,shutil,tempfile,unittest
from pathlib import Path
from check_evaluation_bundle_evidence import ROOT,validate

class CurrentEvaluationEvidenceTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.temp=tempfile.TemporaryDirectory(prefix='pon-evaluation-evidence-mutants-')
  cls.folder=Path(cls.temp.name)/'evidence';shutil.copytree(ROOT/'evidence/pon-evaluation-bundle-v1',cls.folder)
 @classmethod
 def tearDownClass(cls):cls.temp.cleanup()
 def mutate(self,path,change):
  p=self.folder/path;raw=p.read_bytes();m=self.folder/'manifest.json';before=m.read_bytes()
  try:
   obj=json.loads(raw);change(obj);p.write_text(json.dumps(obj,indent=2)+'\n')
   if path!='manifest.json':
    manifest=json.loads(before);manifest['files'][path]=hashlib.sha256(p.read_bytes()).hexdigest();m.write_text(json.dumps(manifest))
   with self.assertRaises((ValueError,KeyError)):validate(ROOT,self.folder,exact_inventory=False)
  finally:p.write_bytes(raw);m.write_bytes(before)
 def test_current_source_and_all_named_experiments_recompute(self):
  result=validate(ROOT,self.folder,exact_inventory=False);self.assertTrue(result['recorded_runtime_matches']);self.assertEqual(result['model_reward'],0)
 def test_original_evidence_does_not_cover_new_client_runtime(self):
  result=validate(ROOT,self.folder,exact_inventory=False)
  self.assertFalse(result['runtime_matches'])
  self.assertIn('formal/pon-nakamoto-v1/client_confirmation.py',result['unmeasured_added_runtime'])
  with self.assertRaisesRegex(ValueError,'runtime inventory mismatch'):validate(ROOT,self.folder)
 def test_independent_operators_cannot_be_invented(self):self.mutate('manifest.json',lambda d:d.update(independent_accepted=True))
 def test_future_generations_cannot_be_invented(self):self.mutate('manifest.json',lambda d:d.update(three_improving_generations=True))
 def test_missing_native_oracle_command_rejects(self):self.mutate('qualification.json',lambda d:d['results'].pop())
 def test_failed_command_cannot_be_counted(self):self.mutate('qualification.json',lambda d:d['results'][0].update(returncode=1))
 def test_native_backend_cannot_be_silently_reference(self):
  self.mutate('qualification.json',lambda d:next(r for r in d['results']if r['name']=='native-ledger').update(environment_overrides={}))
 def test_class_name_in_another_file_is_not_a_test_invocation(self):
  self.mutate('qualification.json',lambda d:next(r for r in d['results']if r['name']=='test_evaluation_bundle').update(command=['python3','formal/pon-nakamoto-v1/test_evaluation.py']))
 def test_supplement_must_be_same_clean_implementation(self):
  self.mutate('qualification-supplement.json',lambda d:d.update(source_clean=False))
 def test_unmeasured_vram_cannot_be_filled(self):self.mutate('qualification.json',lambda d:d['results'][0].update(vram_bytes=123))
 def test_retrospective_zero_reward_cannot_be_promoted(self):self.mutate('settlement/report.json',lambda d:d.update(model_reward=1,outcome='adopted'))
 def test_three_no_change_attempts_are_not_three_adoptions(self):self.mutate('cycles/report.json',lambda d:d.update(three_improving_public_generations=True))
 def test_host_result_cannot_change_its_evaluation_hash(self):self.mutate('hosts/report.json',lambda d:d['results'][0]['samples'][0].update(result_sha256='00'*32))
 def test_failed_remote_cleanup_is_not_hidden(self):self.mutate('hosts/report.json',lambda d:d['results'][0].update(owned_temporary_directory_removed=False))
 def test_old_evidence_is_not_silently_replaced(self):self.mutate('manifest.json',lambda d:d.update(historical_v4_sha256='00'*32))
 def test_forged_aggregate_score_fails_even_with_updated_file_hash(self):
  self.mutate('model/report.json',lambda d:d['results']['evaluation_a']['whole_gain'].update(score=999999))
 def test_historical_component_mode_cannot_drop_a_transitive_runtime_input(self):
  self.mutate('qualification.json',lambda d:d['source_files_sha256'].pop('formal/pon-nakamoto-v1/model_contract.py'))
 def test_historical_component_mode_cannot_drop_locked_native_dependencies(self):
  self.mutate('qualification.json',lambda d:d['source_files_sha256'].pop('trillionnium/Cargo.lock'))
 def test_source_hash_binding_cannot_be_omitted(self):
  self.mutate('qualification.json',lambda d:d['source_files_sha256'].pop('formal/pon-nakamoto-v1/evaluation_bundle.py'))

if __name__=='__main__':unittest.main(verbosity=2)
