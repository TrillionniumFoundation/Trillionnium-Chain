"""Exact artifact identity and loader boundaries; not remote custodian acceptance."""
import importlib.util,json,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from contract_wire import ROOT,canonical,H
spec=importlib.util.spec_from_file_location('model_loop',Path(__file__).parent/'experiments/model_loop.py')
model_loop=importlib.util.module_from_spec(spec);spec.loader.exec_module(model_loop)
class ArtifactBindingTests(unittest.TestCase):
    def setUp(self):self.raw=(ROOT/'evidence/pon-v1/artifacts/model.json').read_bytes()
    def load(self,raw,expected=None):
        with tempfile.TemporaryDirectory()as directory:
            path=Path(directory)/'model.json';path.write_bytes(raw);return model_loop.load_model(path,expected)
    def test_exact_expected_artifact_not_mutable_path(self):
        self.load(self.raw,H('artifact',self.raw))
        model=json.loads(self.raw);model['base'][0][0]+=1
        with self.assertRaisesRegex(ValueError,'ARTIFACT_IDENTITY'):self.load(canonical(model),H('artifact',self.raw))
    def test_shapes_fields_and_noncanonical_bytes_reject(self):
        for mutate in [lambda m:m.update(executable='not allowed'),lambda m:m['router'].pop(),lambda m:m.update(family='00'*32)]:
            model=json.loads(self.raw);mutate(model)
            with self.assertRaises(ValueError):self.load(canonical(model))
        with self.assertRaisesRegex(ValueError,'ARTIFACT_CANONICAL'):self.load(self.raw+b' ')
    def test_loader_size_is_bounded_before_json_decode(self):
        with self.assertRaisesRegex(ValueError,'ARTIFACT_LIMIT'):self.load(b' '*65537)

    def test_infer_receipt_hashes_loaded_bytes_after_path_replacement(self):
        model=json.loads(self.raw)
        model['base']=[[0]*257 for _ in range(3)]
        model['router']=[[0]*257 for _ in range(3)]
        model['deltas']=[[[0]*257 for _ in range(3)]for _ in range(3)]
        model['base'][0][-1]=1
        first=canonical(model)
        model['base'][0][-1]=0;model['base'][1][-1]=1
        replacement=canonical(model)
        rows=[dict(id='01'*32,source_content_sha256='02'*32,
                   file='ordinary-fixture.rs',label=0,x=[0]*256+[8])]
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);path=root/'model.json'
            tasks=root/'tasks.json';out=root/'receipt.json'
            path.write_bytes(first);tasks.write_bytes(canonical(rows))
            args=SimpleNamespace(mode='infer',model=path,tasks=tasks,out=out)
            original_predict=model_loop.predict
            def replace_after_prediction(parsed,x):
                predictions=original_predict(parsed,x)
                path.write_bytes(replacement)
                return predictions
            with patch.object(model_loop,'predict',side_effect=replace_after_prediction)as prediction:
                model_loop.worker(args)
            prediction.assert_called_once()
            self.assertEqual(path.read_bytes(),replacement)
            observed=json.loads(out.read_text())
            self.assertEqual(observed['predictions'],[0])
            self.assertEqual(observed['model_artifact'],H('artifact',first).hex())
            self.assertNotEqual(observed['model_artifact'],H('artifact',replacement).hex())
            self.assertEqual(observed['task_commitment'],H('tasks',canonical(rows)).hex())
            self.assertEqual(observed['schema'],'controlled-source-inference-v2')
            self.assertIs(observed['training_consent'],False)

    def test_infer_oversize_keeps_artifact_limit_before_prediction(self):
        rows=[dict(id='01'*32,source_content_sha256='02'*32,
                   file='ordinary-fixture.rs',label=0,x=[0]*256+[8])]
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);path=root/'model.json'
            tasks=root/'tasks.json';out=root/'receipt.json'
            path.write_bytes(b' '*65537);tasks.write_bytes(canonical(rows))
            args=SimpleNamespace(mode='infer',model=path,tasks=tasks,out=out)
            with patch.object(model_loop,'predict',side_effect=AssertionError('unexpected prediction'))as prediction:
                with self.assertRaisesRegex(ValueError,'^ARTIFACT_LIMIT$'):
                    model_loop.worker(args)
            prediction.assert_not_called()
            self.assertFalse(out.exists())

if __name__=='__main__':unittest.main(verbosity=2)
