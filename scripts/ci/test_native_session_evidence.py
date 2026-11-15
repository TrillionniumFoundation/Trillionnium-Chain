#!/usr/bin/env python3
"""Negative tests for original measured runtime evidence; history stays immutable."""
import copy
import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from check_client_confirmation_evidence import ROOT, validate, require_tracked_evidence


class NativeSessionEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original=ROOT/'evidence/pon-closed-round-v1'
        from historical_evidence import measured_checkout
        cls.original_root=cls.enterClassContext(measured_checkout(ROOT,cls.original))
        cls.baseline=validate(root=cls.original_root,evidence=cls.original)

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='pon-session-evidence-')
        self.addCleanup(self.temp.cleanup)
        self.folder=Path(self.temp.name)/'evidence'
        shutil.copytree(self.original,self.folder)
        self.manifest=json.loads((self.folder/'manifest.json').read_text())
        self.q=json.loads((self.folder/'qualification.json').read_text())

    def reject(self,pattern):
        (self.folder/'qualification.json').write_text(json.dumps(self.q,indent=2)+'\n')
        for name in self.manifest['files']:
            self.manifest['files'][name]=hashlib.sha256((self.folder/name).read_bytes()).hexdigest()
        (self.folder/'manifest.json').write_text(json.dumps(self.manifest,indent=2)+'\n')
        with self.assertRaisesRegex(ValueError,pattern):validate(root=self.original_root,evidence=self.folder)

    def row(self,name):return next(row for row in self.q['results'] if row['name']==name)

    def change(self,path,mutate):
        file=self.folder/path;data=json.loads(file.read_text());mutate(data)
        file.write_text(json.dumps(data,indent=2)+'\n')

    def test_original_measured_runtime_has_its_own_complete_receipt(self):
        self.assertTrue(self.baseline['runtime_matches'])
        self.assertGreater(self.baseline['controlled_work_blocks_replayed'],0)
        self.assertGreater(self.baseline['controlled_policy_confirmations_replayed'],0)
        self.assertIsNone(self.baseline['public_confirmed_tps'])
        self.assertFalse(self.baseline['native_full_node'])

    def test_current_root_cannot_claim_the_historical_runtime_receipt(self):
        with self.assertRaisesRegex(ValueError,'current source differs|runtime inventory'):
            validate(root=ROOT,evidence=self.original)

    def test_successor_policy_configuration_is_not_an_omittable_input(self):
        self.q['source_files_sha256'].pop('config/pon/evaluation-round-v1.json')
        self.reject('runtime inventory')

    def test_successor_execution_cannot_be_replaced_with_legacy_passes(self):
        self.q['results'].remove(self.row('test_evaluation_round'))
        self.reject('execution matrix')

    def test_every_successor_selector_must_have_actually_run(self):
        path=self.folder/self.row('test_evaluation_round')['log']
        path.write_text(path.read_text().replace(
            'test_ordinary_native_cli_uses_successor_and_reopens_only_its_namespace','omitted_case'))
        self.reject('unobserved successor selector')

    def test_missing_session_input_cannot_be_called_unmeasured_addition(self):
        self.q['source_files_sha256'].pop('formal/pon-nakamoto-v1/native_session.py')
        self.reject('runtime inventory')

    def test_failed_session_configuration_cannot_be_counted(self):
        self.row('session-client-confirmation')['returncode']=1
        self.reject('failed execution')

    def test_old_receipt_cannot_replace_actual_new_backend_run(self):
        self.q['results'].remove(self.row('session-ledger'))
        self.reject('execution matrix')

    def test_duplicate_named_run_is_not_more_evidence(self):
        self.q['results'].append(copy.deepcopy(self.row('test_native_session')))
        self.reject('execution matrix')

    def test_session_must_be_explicit_not_single_shot_or_reference(self):
        self.row('session-client-confirmation')['environment_overrides'].pop('TRNM_NATIVE_SESSION')
        self.reject('explicit session backend')

    def test_pipeline_must_select_actual_native_components(self):
        self.row('session-pipeline')['environment_overrides'].pop('TRNM_NATIVE_WORK')
        self.reject('explicit pipeline backend')

    def test_rehashed_native_test_count_inflation_rejects(self):
        self.row('native-suite')['native_passed']+=1
        self.reject('native result count')

    def test_real_new_selectors_cannot_be_erased_from_success_log(self):
        path=self.folder/self.row('test_native_session')['log']
        path.write_text(path.read_text().replace('test_lost_reply_discards_advanced_cache_and_retries_same_input','removed_case'))
        self.reject('unobserved session/precheck selector')

    def test_model_efficacy_not_rerun_by_this_workstream(self):
        self.q['model_experiments_rerun']=True
        self.reject('wrong experiment scope')

    def test_independent_acceptance_is_not_created_by_hashes(self):
        self.manifest['independent_accepted']=True
        self.reject('unsupported authority')

    def test_missing_historical_client_manifest_rejects(self):
        self.q['historical_evidence_sha256'].pop('evidence/pon-client-confirmation-v1/manifest.json')
        self.reject('historical inventory')

    def test_cached_repeat_cannot_be_counted_as_execution_sample(self):
        self.change('comparison/report.json',lambda d:next(row for row in d['samples'] if row['variant']=='delta-session')['metrics'].update(request_cache_hit=True))
        self.reject('cache hit is not an execution sample')

    def test_duplicate_samples_cannot_inflate_throughput(self):
        self.change('comparison/report.json',lambda d:d['samples'].append(copy.deepcopy(d['samples'][0])))
        self.reject('duplicate/unknown sample')

    def test_hidden_regression_rejects_even_after_rehash(self):
        self.change('comparison/report.json',lambda d:d['summary'][0].update(wall_regression=not d['summary'][0]['wall_regression']))
        self.reject('hidden regression')

    def test_executor_samples_cannot_be_called_confirmed(self):
        self.change('comparison/report.json',lambda d:d['samples'][0].update(confirmed=64))
        self.reject('unmeasured performance claim')

    def test_pipeline_is_not_a_native_full_node(self):
        self.change('pipeline/report.json',lambda d:d.update(full_native_node=True))
        self.reject('pipeline overclaim')

    def test_pipeline_is_not_public_confirmed_tps(self):
        self.change('pipeline/report.json',lambda d:d.update(public_confirmed_tps=1000))
        self.reject('pipeline transport/clock scope')

    def test_fabricated_confirmation_is_rejected_by_real_replay(self):
        self.change('pipeline/report.json',lambda d:d['samples'][0]['confirmations'][0].update(cumulative_work_delta='999999'))
        self.reject('pipeline confirmation replay')

    def test_omitted_receiver_sample_is_not_complete_pipeline(self):
        self.change('pipeline/report.json',lambda d:d['samples'].pop())
        self.reject('pipeline coverage')



class RepositoryEvidenceTrackingTests(unittest.TestCase):
    """Exercise a real Git index; file existence alone did not catch ignored logs."""
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='pon-evidence-tracking-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / 'repository'
        self.root.mkdir()
        self.git('init', '-q')
        (self.root / '.gitignore').write_text('*.log\n')
        self.folder = self.root / 'evidence' / 'sample'
        self.folder.mkdir(parents=True)
        self.raw = b'actual process output with trailing spaces  \n'
        (self.folder / 'run.log').write_bytes(self.raw)
        self.manifest = {'files': {'run.log': hashlib.sha256(self.raw).hexdigest()}}
        (self.folder / 'manifest.json').write_text(json.dumps(self.manifest))
        self.git('add', '--', '.gitignore', 'evidence/sample/manifest.json')

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.root), *args], check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_present_but_ignored_raw_log_is_not_published_evidence(self):
        self.assertTrue((self.folder / 'run.log').is_file())
        with self.assertRaisesRegex(ValueError, 'untracked evidence artifact'):
            require_tracked_evidence(self.root, self.folder, self.manifest)

    def test_explicitly_tracked_log_preserves_its_original_bytes(self):
        self.git('add', '-f', '--', 'evidence/sample/run.log')
        self.assertTrue(require_tracked_evidence(self.root, self.folder, self.manifest))
        self.assertEqual(self.git('show', ':evidence/sample/run.log').stdout, self.raw)

    def test_removing_log_only_from_index_cannot_keep_a_passing_delivery(self):
        self.git('add', '-f', '--', 'evidence/sample/run.log')
        self.git('rm', '--cached', '--', 'evidence/sample/run.log')
        self.assertEqual((self.folder / 'run.log').read_bytes(), self.raw)
        with self.assertRaisesRegex(ValueError, 'untracked evidence artifact'):
            require_tracked_evidence(self.root, self.folder, self.manifest)

    def test_external_historical_package_does_not_claim_source_tree_publication(self):
        external = self.root.parent / 'historical-evidence'
        external.mkdir()
        self.assertFalse(require_tracked_evidence(self.root, external, self.manifest))


if __name__=='__main__':unittest.main(verbosity=2)
