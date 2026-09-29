"""Exact artifact identity and loader boundaries; not remote custodian acceptance."""
import importlib.util,json,tempfile,unittest
from pathlib import Path
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
if __name__=='__main__':unittest.main(verbosity=2)
