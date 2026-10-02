import json,tempfile,unittest
from source_binding_fixture import copy_source_bindings
from pathlib import Path
from check_invariants import validate
ROOT=Path(__file__).resolve().parents[2]
class InvariantRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.root=Path(cls.tmp.name)/'tree';copy_source_bindings(ROOT,cls.root)
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()
    def reject(self,change):
        path=self.root/'config/pon/invariants-v2.json';original=path.read_bytes();data=json.loads(original)
        try:change(data);path.write_text(json.dumps(data));self.assertRaises(ValueError,validate,self.root)
        finally:path.write_bytes(original)
    def test_real_function_bindings(self):self.assertFalse(validate(self.root)['tests_executed_by_this_checker'])
    def test_prose_rephrase_and_heading_change_do_not_fake_a_failure(self):
        from check_detailed_contracts import validate as validate_details
        doc=self.root/'docs/modules/M02_CONSENSUS_CORE_TECHNICAL_SPEC_V1.md';old=doc.read_bytes()
        try:
            text=old.decode().replace('## PoN State machine','## Admission and branch recovery')
            text=text.replace('A persisted valid higher-work block is selected after restart even if activation intent was never written.','After restart, recover the best verified persisted branch even without a prior activation intent.')
            doc.write_text(text);validate(self.root);validate_details(self.root)
        finally:doc.write_bytes(old)
    def test_stale_genesis_revision_rejected(self):self.reject(lambda d:d.update(genesis_revision=2))
    def test_boolean_revision_is_not_integer(self):self.reject(lambda d:d.update(genesis_revision=True))
    def test_missing_atomic_boundary(self):self.reject(lambda d:d['invariants'][3].update(atomic=''))
    def test_no_counterexample_schedule(self):self.reject(lambda d:d['invariants'][3].update(cuts=[]))
    def test_class_name_is_not_a_test_function(self):self.reject(lambda d:d['invariants'][3].update(tests=['formal/pon-nakamoto-v1/test_invariants.py::EffectLinearizationTests']))
    def test_wrong_test_selector_rejected(self):self.reject(lambda d:d['invariants'][3].update(tests=['formal/pon-nakamoto-v1/test_invariants.py::EffectLinearizationTests.test_not_present']))
    def test_known_revoke_obligation_cannot_be_omitted(self):self.reject(lambda d:d['invariants'].pop(3))
    def test_duplicate_identity_rejected(self):self.reject(lambda d:d['invariants'].append(d['invariants'][0]))
    def test_binding_cannot_grant_execution(self):self.reject(lambda d:d.update(binding_is_execution=True))
    def test_independence_cannot_be_granted(self):self.reject(lambda d:d.update(independent_accepted=True))
if __name__=='__main__':unittest.main(verbosity=2)
