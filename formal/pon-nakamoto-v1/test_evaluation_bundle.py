"""Frozen-input and statistical counterexamples, not learned efficacy evidence."""
from __future__ import annotations
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from contract_wire import H, canonical
from ledger import FAMILY
from evaluation import assess, macro_accuracy, select_reference, CONTROL_ORDER
from evaluation_bundle import *


def model(label=0):
    base = [[0] * 257 for _ in range(3)]; base[label][-1] = 1
    return dict(schema='hepta-source-owner-linear-256-v1', family=FAMILY.hex(), scale=1024,
                source='public-test-fixture', feature='signed-token-hash-256-clipped8-plus-bias-v1',
                classes=['M00', 'M04', 'M10'], base=base, router=[[0]*257 for _ in range(3)],
                deltas=[[[0]*257 for _ in range(3)] for _ in range(3)])


def rows(prefix, count=24, label=1):
    return [{'id': H('fixture-id', prefix.encode(), str(i).encode()).hex(),
             'file': prefix+'/'+str(i)+'.rs', 'label': label, 'split': prefix,
             'source_content_sha256': H('fixture-content', prefix.encode(), str(i).encode()).hex(),
             'x': [0]*256+[8]} for i in range(count)]


class FrozenEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.current=model(0); self.candidate=model(1)
        self.controls={name:copy.deepcopy(self.current) for name in CONTROL_ORDER}
        self.partitions={name:rows(name) for name in ['train','calibration','evaluation']}
        self.raw,self.digest=self.freeze()

    def freeze(self):
        return freeze_bundle(source_commit='ab'*20, round_number=1,parent_release='00'*32,
            current=self.current,candidate=self.candidate,controls=self.controls,partitions=self.partitions)

    def alter(self, mutate):
        bundle=json.loads(self.raw);mutate(bundle);return canonical(bundle)

    def evaluate(self, raw=None, digest=None, data=None, partition='evaluation'):
        return evaluate_bundle(self.raw if raw is None else raw,self.digest if digest is None else digest,
            self.partitions['evaluation'] if data is None else data,partition,
            calibration_rows=self.partitions['calibration'],expected_parent=artifact_id(self.current))

    def test_exact_bundle_drives_actual_integer_inference(self):
        result=self.evaluate()
        self.assertEqual(result['predictions'],[1]*24)
        self.assertTrue(result['primary']['cluster_gate'])
        self.assertFalse(result['public_reward_eligible'])
        self.assertFalse(result['ordinary_hepta_entry'])

    def test_every_control_parameter_is_bound_before_inference(self):
        for control in CONTROL_ORDER:
            raw=self.alter(lambda b:b['controls'][control]['base'][0].__setitem__(0,1))
            with self.subTest(control=control),patch('evaluation_bundle.infer') as run:
                with self.assertRaisesRegex(ValueError,'BUNDLE_IDENTITY'):self.evaluate(raw)
                run.assert_not_called()

    def test_weak_reference_replacement_rejects(self):
        raw=self.alter(lambda b:b.update(selected='pooled'))
        with self.assertRaisesRegex(ValueError,'BUNDLE_IDENTITY'):self.evaluate(raw)
        with self.assertRaisesRegex(ValueError,'CONTROL_SELECTION'):
            self.evaluate(raw,H('evaluation-bundle-v3',raw).hex())

    def test_control_digest_cannot_be_changed_even_with_new_plan_hash(self):
        raw=self.alter(lambda b:b['control_artifacts'].update(current='00'*32))
        with self.assertRaisesRegex(ValueError,'CONTROL_IDENTITY'):
            self.evaluate(raw,H('evaluation-bundle-v3',raw).hex())

    def test_candidate_file_identity_and_parent_are_distinct(self):
        raw=self.alter(lambda b:b['candidate']['base'][0].__setitem__(0,1))
        with self.assertRaisesRegex(ValueError,'CANDIDATE_IDENTITY'):
            self.evaluate(raw,H('evaluation-bundle-v3',raw).hex())
        with self.assertRaisesRegex(ValueError,'PARENT_ARTIFACT'):
            verify_bundle(self.raw,self.digest,expected_parent='01'*32)

    def test_input_label_content_identity_and_group_substitution_reject(self):
        changes=[lambda r:r.update(label=0),lambda r:r['x'].__setitem__(0,1),
                 lambda r:r.update(id='aa'*32),lambda r:r.update(source_content_sha256='bb'*32),
                 lambda r:r.update(file='other-group')]
        for mutate in changes:
            data=copy.deepcopy(self.partitions['evaluation']);mutate(data[0])
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):self.evaluate(data=data)

    def test_training_or_calibration_cannot_be_reported_as_evaluation(self):
        for partition in ['train','calibration','absent']:
            with self.subTest(partition=partition),self.assertRaisesRegex(ValueError,'EVALUATION_PARTITION'):
                self.evaluate(partition=partition)

    def test_cross_partition_source_group_overlap_rejects(self):
        self.partitions['evaluation'][0]['file']=self.partitions['train'][0]['file']
        with self.assertRaisesRegex(ValueError,'PARTITION_OVERLAP'):self.freeze()

    def test_cross_partition_exact_content_overlap_rejects(self):
        self.partitions['evaluation'][0]['source_content_sha256']=self.partitions['train'][0]['source_content_sha256']
        with self.assertRaisesRegex(ValueError,'PARTITION_OVERLAP'):self.freeze()

    def test_cross_partition_task_id_overlap_rejects(self):
        self.partitions['evaluation'][0]['id']=self.partitions['train'][0]['id']
        with self.assertRaisesRegex(ValueError,'PARTITION_OVERLAP'):self.freeze()

    def test_duplicate_task_and_content_within_partition_reject(self):
        for field,code in [('id','DUPLICATE_TASK'),('source_content_sha256','DUPLICATE_CONTENT')]:
            data=copy.deepcopy(self.partitions['evaluation']);data[1][field]=data[0][field]
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,code):partition_manifest(data)

    def test_source_group_alias_cannot_amplify_sample_count(self):
        self.partitions['evaluation'][0]['source_group']='invented-group'
        with self.assertRaisesRegex(ValueError,'SOURCE_GROUP_BINDING'):self.freeze()

    def test_noncanonical_or_partial_bundle_fails(self):
        for raw in [self.raw+b' ',self.raw[:-1]]:
            with self.assertRaises(ValueError):verify_bundle(raw,H('evaluation-bundle-v3',raw).hex())

    def test_duplicate_json_keys_fail(self):
        raw=self.raw[:-1]+b',"schema":"pon-evaluation-bundle-v3"}'
        with self.assertRaisesRegex(ValueError,'duplicate'):
            verify_bundle(raw,H('evaluation-bundle-v3',raw).hex())

    def test_unknown_and_fabricated_authority_fields_reject(self):
        for mutation in [lambda b:b.update(approved=True),lambda b:b.update(scope='independent-future-accepted')]:
            raw=self.alter(mutation)
            with self.assertRaises(ValueError):verify_bundle(raw,H('evaluation-bundle-v3',raw).hex())

    def test_policy_multiplicity_cannot_be_lowered(self):
        raw=self.alter(lambda b:b['policy'].update(comparisons=1))
        with self.assertRaisesRegex(ValueError,'BUNDLE_POLICY'):
            verify_bundle(raw,H('evaluation-bundle-v3',raw).hex())

    def test_wrong_network_rejects(self):
        raw=self.alter(lambda b:b.update(network='00'*32))
        with self.assertRaisesRegex(ValueError,'BUNDLE_NETWORK'):
            verify_bundle(raw,H('evaluation-bundle-v3',raw).hex())

    def test_self_consistent_rehashed_calibration_score_still_requires_actual_replay(self):
        b=json.loads(self.raw);b['control_macro_scores']['pooled']=['1','1'];b['selected']='pooled'
        raw=canonical(b)
        with self.assertRaisesRegex(ValueError,'CALIBRATION_RESULT'):
            self.evaluate(raw,H('evaluation-bundle-v3',raw).hex())
    def test_changed_calibration_data_cannot_be_substituted(self):
        changed=copy.deepcopy(self.partitions['calibration']);changed[0]['label']=0
        with self.assertRaisesRegex(ValueError,'CALIBRATION_TASKS'):
            evaluate_bundle(self.raw,self.digest,self.partitions['evaluation'],'evaluation',calibration_rows=changed)
    def test_model_shape_and_numeric_ranges_are_checked(self):
        for mutation in [lambda b:b['controls']['pooled']['base'].pop(),
                         lambda b:b['controls']['pooled']['base'][0].__setitem__(0,True)]:
            raw=self.alter(mutation)
            with self.assertRaises(ValueError):verify_bundle(raw,H('evaluation-bundle-v3',raw).hex())

    def test_reduced_fraction_only_for_calibration_scores(self):
        raw=self.alter(lambda b:b['control_macro_scores'].update(current=['0','2']))
        with self.assertRaisesRegex(ValueError,'CONTROL_SCORE_CANONICAL'):
            verify_bundle(raw,H('evaluation-bundle-v3',raw).hex())

    def test_control_current_must_be_actual_parent(self):
        self.controls['current']=model(2)
        with self.assertRaisesRegex(ValueError,'PARENT_ARTIFACT'):self.freeze()

    def test_write_once_plan_survives_readback_and_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'bundle.json';write_new(path,self.raw)
            verify_bundle(read_bounded(path,MAX_BUNDLE_BYTES),self.digest)
            with self.assertRaises(FileExistsError):write_new(path,self.raw)

    def test_oversize_input_rejected_before_parser(self):
        with patch('evaluation_bundle.json.loads') as decode:
            with self.assertRaisesRegex(ValueError,'BUNDLE_LIMIT'):verify_bundle(b' '*(MAX_BUNDLE_BYTES+1),self.digest)
            decode.assert_not_called()
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'too-big';path.write_bytes(b'x'*9)
            with self.assertRaisesRegex(ValueError,'INPUT_LIMIT'):read_bounded(path,8)

    def test_materialized_controls_equal_original_inference_modes(self):
        from experiments.model_loop import predict
        import numpy as np
        candidate=model();candidate['base'][1][0]=3
        for i in range(3):candidate['deltas'][i][i][1]=4+i
        data=rows('calibration',30)
        for i,row in enumerate(data):row['x'][0]=i%7-3;row['x'][1]=i%5-2;row['label']=i%3
        material=control_models(self.current,candidate,data,candidate['base'])
        x=np.asarray([r['x'] for r in data])
        single=[predict(candidate,x,mode='expert',expert=i).tolist() for i in range(3)]
        best=max(range(3),key=lambda i:(macro_accuracy(data,single[i]),-i))
        self.assertEqual(predict_rows(material['best_single'],data),single[best])
        self.assertEqual(predict_rows(material['mean_merge'],data),predict(candidate,x,mode='merge').tolist())


class EvaluationWorkerTests(unittest.TestCase):
    def invoke(self, mutate=None, legacy=False):
        import subprocess,sys
        current=model(0);candidate=model(1)
        partitions={name:rows(name)for name in ['train','calibration','evaluation']}
        raw,digest=freeze_bundle(source_commit='ab'*20,round_number=1,parent_release='00'*32,
            current=current,candidate=candidate,controls={name:copy.deepcopy(current)for name in CONTROL_ORDER},
            partitions=partitions)
        if mutate is not None:raw=mutate(raw)
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);(root/'model.json').write_bytes(canonical(candidate))
            (root/'tasks.json').write_bytes(canonical(partitions['evaluation']))
            (root/'calibration.json').write_bytes(canonical(partitions['calibration']))
            (root/'bundle.json').write_bytes(raw)
            (root/'old-reference.json').write_bytes(canonical({'candidate':artifact_id(candidate),'selected':'current'}))
            command=[sys.executable,str(Path(__file__).parent/'experiments/model_loop.py'),'--mode','evaluate',
                '--tasks',str(root/'tasks.json'),'--model',str(root/'model.json'),'--out',str(root/'result.json')]
            if legacy:command+=['--reference',str(root/'old-reference.json')]
            else:command+=['--evaluation-bundle',str(root/'bundle.json'),'--bundle-hash',digest,'--partition','evaluation','--calibration',str(root/'calibration.json')]
            process=subprocess.run(command,capture_output=True,text=True,timeout=30)
            result=json.loads((root/'result.json').read_text())if(root/'result.json').exists()else None
            return process,result,digest
    def test_normal_evaluation_worker_consumes_exact_bundle(self):
        process,result,digest=self.invoke()
        self.assertEqual(process.returncode,0,process.stderr)
        self.assertEqual(result['evaluation_bundle'],digest)
        self.assertEqual(result['composed_correct'],24)
        self.assertFalse(result['public_reward_eligible'])
    def test_legacy_unbound_reference_cannot_authorize_evaluation(self):
        process,result,_=self.invoke(legacy=True)
        self.assertNotEqual(process.returncode,0)
        self.assertIn('FROZEN_BUNDLE_REQUIRED',process.stderr);self.assertIsNone(result)
    def test_changed_reference_file_produces_no_evaluation_artifact(self):
        def mutate(raw):
            b=json.loads(raw);b['controls']['current']['base'][1][-1]=10;return canonical(b)
        process,result,_=self.invoke(mutate=mutate)
        self.assertNotEqual(process.returncode,0)
        self.assertIn('BUNDLE_IDENTITY',process.stderr);self.assertIsNone(result)


class SettlementObservationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import subprocess,sys
        cls.tmp=tempfile.TemporaryDirectory();cls.root=Path(cls.tmp.name)
        current=model(0);candidate=model(1)
        partitions={name:rows(name)for name in ['train','calibration','evaluation_a','evaluation_b']}
        raw,cls.digest=freeze_bundle(source_commit='ab'*20,round_number=1,parent_release='00'*32,
            current=current,candidate=candidate,controls={name:copy.deepcopy(current)for name in CONTROL_ORDER},partitions=partitions)
        (cls.root/'evaluation-bundle.json').write_bytes(raw)
        (cls.root/'model.json').write_bytes(canonical(candidate));results={}
        (cls.root/'calibration.json').write_bytes(canonical(partitions['calibration']))
        for name in ['evaluation_a','evaluation_b']:
            (cls.root/(name+'.json')).write_bytes(canonical(partitions[name]))
            run=subprocess.run([sys.executable,str(Path(__file__).parent/'experiments/model_loop.py'),
                '--mode','evaluate','--tasks',str(cls.root/(name+'.json')),'--model',str(cls.root/'model.json'),
                '--evaluation-bundle',str(cls.root/'evaluation-bundle.json'),'--bundle-hash',cls.digest,
                '--partition',name,'--calibration',str(cls.root/'calibration.json'),'--out',str(cls.root/(name+'-result.json'))],capture_output=True,text=True,timeout=30)
            if run.returncode:raise RuntimeError(run.stderr)
            results[name]=json.loads((cls.root/(name+'-result.json')).read_text())
        report={'source':'ab'*20,'models':{'artifact_hash':artifact_id(candidate),'bytes':len(canonical(candidate))},
                'evaluation_bundle':cls.digest,'results':results}
        (cls.root/'report.json').write_text(json.dumps(report,sort_keys=True)+'\n')
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()
    def test_observed_results_are_recomputed_before_signed_settlement(self):
        from experiments.settle_model import verify_observation
        report,candidate=verify_observation(self.root,self.digest)
        self.assertEqual(report['evaluation_bundle'],self.digest);self.assertEqual(candidate,model(1))
    def test_zero_marginal_candidate_creates_no_ledger_or_reward(self):
        from experiments.settle_model import run
        with tempfile.TemporaryDirectory()as parent:
            output=Path(parent)/'settlement'
            from contextlib import redirect_stdout
            import io
            with redirect_stdout(io.StringIO()):run(self.root,output,self.digest)
            report=json.loads((output/'report.json').read_text())
            self.assertEqual(report['outcome'],'not_adopted');self.assertEqual(report['model_reward'],0)
            self.assertFalse((output/'chain').exists())
    def test_mutating_both_summary_and_evaluator_score_does_not_authorize_reward(self):
        from experiments.settle_model import verify_observation
        paths=[self.root/'report.json',self.root/'evaluation_a-result.json'];old=[p.read_bytes()for p in paths]
        try:
            summary=json.loads(old[0]);record=json.loads(old[1])
            summary['results']['evaluation_a']['marginal'][0]['score']=1000000
            record['marginal'][0]['score']=1000000
            paths[0].write_text(json.dumps(summary));paths[1].write_text(json.dumps(record))
            with self.assertRaisesRegex(ValueError,'OBSERVED_EVALUATION_MISMATCH'):verify_observation(self.root,self.digest)
        finally:
            for p,raw in zip(paths,old):p.write_bytes(raw)
    def test_undeclared_bundle_cannot_be_read_from_summary_as_authority(self):
        from experiments.settle_model import verify_observation
        with self.assertRaisesRegex(ValueError,'BUNDLE_IDENTITY'):verify_observation(self.root,'00'*32)


class StatisticalBoundaryTests(unittest.TestCase):
    def test_calibration_weights_source_groups_not_number_of_snippets(self):
        data=rows('cal',100)+rows('small-a',1)+rows('small-b',1)
        for row in data[:100]:row['file']='one-large-file'
        controls={'current':[1]*100+[0,0],'best_single':[0]*100+[1,1],
                  'mean_merge':[0]*102,'pooled':[0]*102}
        selected,_=select_reference(data,controls)
        self.assertEqual(selected,'best_single')

    def test_positive_direction_majority_with_negative_mean_is_rejected(self):
        data=[];candidate=[];reference=[]
        for i in range(30):
            group=rows('tiny-'+str(i),100)
            for row in group:row['file']='tiny-'+str(i)
            data+=group;candidate += [1]+[0]*99;reference += [0]*100
        for i in range(2):
            data+=rows('large-loss-'+str(i),1);candidate.append(0);reference.append(1)
        result=assess(data,candidate,reference)
        self.assertEqual((result['wins'],result['losses']),(30,2))
        self.assertLess(result['mean_gain_numerator'],0)
        self.assertFalse(result['cluster_gate']);self.assertEqual(result['exploratory_score'],0)

    def test_labels_and_predictions_do_not_accept_boolean_aliases(self):
        data=rows('typed')
        with self.assertRaisesRegex(ValueError,'PREDICTION'):assess(data,[True]*24,[0]*24)
        data[0]['label']=True
        with self.assertRaisesRegex(ValueError,'LABEL'):assess(data,[1]*24,[0]*24)

    def test_caller_cannot_lower_statistical_gate(self):
        for kwargs in [dict(comparisons=1),dict(comparisons=True),dict(minimum_clusters=0),dict(minimum_clusters=True)]:
            with self.subTest(kwargs=kwargs),self.assertRaises(ValueError):assess(rows('gate'),[1]*24,[0]*24,**kwargs)

    def test_caller_future_flag_is_not_observation_or_reward(self):
        result=assess(rows('future'),[1]*24,[0]*24,future_window=True)
        self.assertTrue(result['caller_future_window_claim'])
        self.assertFalse(result['future_window_observed']);self.assertFalse(result['public_reward_eligible'])


if __name__=='__main__':unittest.main(verbosity=2)
