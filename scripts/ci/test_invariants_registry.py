import json,shutil,tempfile,unittest
from pathlib import Path
from check_invariants import validate
ROOT=Path(__file__).resolve().parents[2]
class InvariantRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.root=Path(cls.tmp.name)/'tree';shutil.copytree(ROOT,cls.root,ignore=shutil.ignore_patterns('.git','__pycache__','target'))
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


class NativeSelectorBindingTests(unittest.TestCase):
    """Exercise the invariant checker without relying on the live registry snapshot."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='pon-invariant-selector-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        config = self.root / 'config/pon'
        config.mkdir(parents=True)
        (self.root / 'fixture.py').write_text('def test_reference():\n    pass\n')
        self.native = self.root / 'fixture.rs'
        self.native.write_text('#[test]\nfn native_case() {}\n')
        modules = []
        invariants = []
        for index, identity in enumerate([
            'M03.RevokeEntryLinearization', 'M07.OwnedInitialization',
            'M10.PendingNotHistory', 'M02.RecoveredBestChain',
        ]):
            module, name = identity.split('.')
            selector = 'fixture.rs::native_case' if index == 0 else 'fixture.py::test_reference'
            document = module + '.md'
            (self.root / document).write_text(identity + '\n' + selector + '\n')
            modules.append({'id': module, 'specification': document})
            invariants.append({
                'module': module, 'id': name, 'claim': 'Exact source binding',
                'scope': 'Synthetic checker fixture', 'atomic': 'No runtime execution',
                'cuts': ['Missing or fake attributed function'], 'tests': [selector],
                'source': [selector.split('::')[0]], 'limit': 'Source binding only',
                'threat': 'Comment or string masquerading as a test',
                'remaining': 'Execution requires separate evidence',
            })
        (config / 'module-contracts-v1.json').write_text(json.dumps({'modules': modules}))
        (config / 'devnet-v1.json').write_text(json.dumps({'consensus_revision': 1}))
        (config / 'invariants-v2.json').write_text(json.dumps({
            'schema': 'pon-invariants-v2', 'genesis_revision': 1,
            'binding_is_execution': False, 'independent_accepted': False,
            'invariants': invariants,
        }))

    def assert_binding_only(self, source):
        self.native.write_text(source)
        result = validate(self.root)
        self.assertTrue(result['binding_consistent'])
        self.assertFalse(result['tests_executed_by_this_checker'])
        self.assertFalse(result['independent_accepted'])

    def test_ordinary_attributed_native_test_remains_bound(self):
        self.assert_binding_only('#[test]\nfn native_case() {}\n')

    def test_ignored_native_test_binds_without_claiming_execution(self):
        for attribute in ['#[ignore]', '#[ignore = "release fixture requires explicit execution"]']:
            with self.subTest(attribute=attribute):
                self.assert_binding_only('#[test]\n' + attribute + '\nfn native_case() {}\n')

    def test_intervening_attributes_and_comments_preserve_native_binding(self):
        self.assert_binding_only('''#[test]
// An actual test may have additional attributes before its declaration.
#[ignore = "explicit release run"]
/* outer /* inner */ comment */
#[allow(dead_code)]
fn native_case() {}
''')

    def test_comment_decoys_do_not_bind_native_test(self):
        for source in [
            '// #[test] fn native_case() {}\n',
            '/* #[test] fn native_case() {} */\n',
            '/* outer /* inner */ #[test] fn native_case() {} */\n',
            '/* #[test] */ fn native_case() {}\n',
        ]:
            with self.subTest(source=source):
                self.native.write_text(source)
                with self.assertRaisesRegex(ValueError, 'missing exact native test'):
                    validate(self.root)

    def test_string_decoys_do_not_bind_native_test(self):
        for source in [
            'const S: &str = "#[test] fn native_case() {}";\n',
            'const S: &str = r#"#[test] fn native_case() {}"#;\n',
            'const S: &[u8] = br##"#[test] #[ignore] fn native_case() {}"##;\n',
            'const S: &str = "#[test]"; fn native_case() {}\n',
        ]:
            with self.subTest(source=source):
                self.native.write_text(source)
                with self.assertRaisesRegex(ValueError, 'missing exact native test'):
                    validate(self.root)

    def test_helper_or_different_native_test_cannot_replace_exact_selector(self):
        for source in [
            'fn native_case() {}\n',
            '#[test]\nfn native_case_extra() {}\n',
            '#[test]\nfn another_case() {}\nfn native_case() {}\n',
        ]:
            with self.subTest(source=source):
                self.native.write_text(source)
                with self.assertRaisesRegex(ValueError, 'missing exact native test'):
                    validate(self.root)

    def test_python_class_is_still_not_a_function_binding(self):
        (self.root / 'fixture.py').write_text('class test_reference:\n    pass\n')
        with self.assertRaisesRegex(ValueError, 'missing exact Python test'):
            validate(self.root)

if __name__=='__main__':unittest.main(verbosity=2)
