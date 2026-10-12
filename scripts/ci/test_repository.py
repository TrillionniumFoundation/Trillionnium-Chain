#!/usr/bin/env python3
"""Negative boundary tests. A pass is not consensus or independent acceptance."""
from __future__ import annotations
import copy,json,pathlib,shutil,tempfile,unittest
from check_repository import ROOT,Invalid,check,graph_acyclic,no_promotion,unique

class EvidenceBoundaryTests(unittest.TestCase):
    def test_current_claims_are_unactivated(self):
        no_promotion(json.loads((ROOT/'config/consensus-mainline.json').read_text()))
        no_promotion(json.loads((ROOT/'config/pon-nakamoto-v1.json').read_text()))
    def test_no_runtime_claim(self):
        with self.assertRaises(Invalid):no_promotion({'runtime_implemented':True})
    def test_no_release_from_nested_report(self):
        with self.assertRaises(Invalid):no_promotion({'reports':[{'release_ready':True}]})
    def test_no_work_qualification_from_reference(self):
        with self.assertRaises(Invalid):no_promotion({'work_profile_qualified':True})
    def test_false_is_not_integer_zero(self):
        with self.assertRaises(Invalid):no_promotion({'production_consensus_activation':0})
    def test_duplicate_json_claims(self):
        with self.assertRaises(Invalid):json.loads('{"runtime_implemented":false,"runtime_implemented":true}',object_pairs_hook=unique)
    def test_explicit_missing_native_core(self):
        inventory=json.loads((ROOT/'config/portability-inventory-v1.json').read_text())
        self.assertFalse(inventory['runtime_implemented'])
        self.assertFalse(any(row['module']=='M02' for row in inventory['packages']))
    def test_old_protocol_is_not_supported(self):
        inventory=json.loads((ROOT/'config/portability-inventory-v1.json').read_text())
        self.assertIs(inventory['old_protocol_compatibility'],False)

class DependencyTests(unittest.TestCase):
    def test_acyclic(self):graph_acyclic({'a':{'b'},'b':set()})
    def test_cycle_rejected(self):
        with self.assertRaises(Invalid):graph_acyclic({'a':{'b'},'b':{'a'}})
    def test_self_cycle_rejected(self):
        with self.assertRaises(Invalid):graph_acyclic({'a':{'a'}})
    def test_undeclared_dependency_rejected(self):
        with self.assertRaises(Invalid):graph_acyclic({'a':{'missing'}})

class RepositoryMutants(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory(prefix='trnm-source-mutants-')
        cls.root=pathlib.Path(cls.temporary.name)/'source'
        shutil.copytree(ROOT,cls.root,ignore=shutil.ignore_patterns('.git','target','__pycache__','node_modules'))
    @classmethod
    def tearDownClass(cls):cls.temporary.cleanup()
    def reject_text(self,relative,transform):
        path=self.root/relative;old=path.read_bytes()
        try:
            path.write_text(transform(old.decode()))
            with self.assertRaises((Invalid,KeyError,ValueError)):check(self.root)
        finally:path.write_bytes(old)
    def reject_json(self,relative,mutate):
        def transform(text):
            data=json.loads(text);mutate(data);return json.dumps(data)
        self.reject_text(relative,transform)
    def test_actual_source(self):self.assertEqual(check(self.root)['workspace_packages'],len(json.loads((self.root/'config/portability-inventory-v1.json').read_text())['packages']))
    def test_duplicate_package(self):
        self.reject_json('config/portability-inventory-v1.json',lambda d:d['packages'].append(copy.deepcopy(d['packages'][0])))
    def test_omitted_package(self):
        self.reject_json('config/portability-inventory-v1.json',lambda d:d['packages'].pop())
    def test_owner_unknown(self):
        self.reject_json('config/portability-inventory-v1.json',lambda d:d['packages'][0].update(module='M99'))
    def test_source_authority_cannot_be_issued(self):
        self.reject_json('config/portability-inventory-v1.json',lambda d:d['packages'][0].update(consensus_authority=True))
    def test_removed_core_cannot_return_as_dependency(self):
        self.reject_text('trillionnium/crates/trnm-types/Cargo.toml',lambda t:t+'\n[target.\'cfg(unix)\'.build-dependencies]\ntrnm-consensus-core = "0.1"\n')
    def test_external_path_dependency(self):
        self.reject_text('trillionnium/crates/trnm-types/Cargo.toml',lambda t:t+'\n[target.\'cfg(unix)\'.build-dependencies]\nforeign = {path = "../../../../other-repo"}\n')
    def test_removed_vote_symbol(self):
        self.reject_text('trillionnium/crates/trnm-types/src/lib.rs',lambda t:t+'\npub struct QuorumCertificate;\n')
    def test_undeclared_crate_directory(self):
        p=self.root/'trillionnium/crates/unused-extra';p.mkdir()
        try:
            with self.assertRaises(Invalid):check(self.root)
        finally:p.rmdir()
    def test_missing_runtime_claim_is_not_false_evidence(self):
        self.reject_json('config/consensus-mainline.json',lambda d:d.pop('runtime_implemented'))
    def test_missing_implementation_axis(self):
        self.reject_json('config/pon-nakamoto-v1.json',lambda d:d['implementation'].pop('independent_security_accepted'))
    def test_unknown_implementation_axis(self):
        self.reject_json('config/pon-nakamoto-v1.json',lambda d:d['implementation'].update(extra_accepted=False))
    def test_algorithm_cannot_be_replaced_with_tbd(self):
        import re
        self.reject_text('docs/modules/M02_CONSENSUS_CORE_TECHNICAL_SPEC_V1.md',lambda t:re.sub(r'(?ms)(^## PoN State machine\s*\n).*?(?=^## |\Z)',r'\1TBD\n\n',t))
    def test_missing_procedure_commit_is_rejected(self):
        self.reject_json('config/pon/module-contracts-v1.json',lambda d:d['modules'][0]['operations'][0].pop('commit'))
    def test_wrong_wire_width_is_rejected(self):
        self.reject_json('config/pon/ledger-v1.json',lambda d:d['commands'][0].update(fixed_payload_bytes=41))
    def test_candidate_profile_is_not_production_qualified(self):
        self.reject_json('config/pon/work-profile-v1.json',lambda d:d.update(production_eligible=True))
    def test_reference_does_not_imply_native_product_integration(self):
        self.reject_json('config/pon/module-maturity-v1.json',lambda d:d['modules'][2].update(native_product_integrated=True))
    def test_review_policy_matches_owner_decision(self):
        self.reject_json('PROJECT_BOUNDARY.json',lambda d:d['repository'].update(required_pull_request_reviews=2))
    def test_missing_native_contract_test_is_rejected(self):
        self.reject_json('config/pon/module-contracts-v1.json',lambda d:d['modules'][0].update(test_classes=['DoesNotExist']))
    def test_wrong_fork_choice(self):
        self.reject_json('config/pon-nakamoto-v1.json',lambda d:d.update(fork_choice='highest-quality'))
    def test_quality_cannot_be_work(self):
        self.reject_json('config/pon-nakamoto-v1.json',lambda d:d.update(quality_weighted_chainwork=True))
    def test_vote_cannot_return(self):
        self.reject_json('config/pon-nakamoto-v1.json',lambda d:d.update(validator_voting=True))
    def test_no_automatic_fallback(self):
        self.reject_json('config/pon-nakamoto-v1.json',lambda d:d.update(automatic_bft_fallback=True))
    def test_unknown_concrete_work_profile_rejected(self):
        self.reject_json('config/pon-nakamoto-v1.json',lambda d:d['work_profile'].update(concrete_profile_id='unregistered-profile'))
    def test_fake_qualified_primitive(self):
        self.reject_json('config/pon-nakamoto-v1.json',lambda d:d['work_profile'].update(status='qualified'))
    def test_fake_public_model_efficacy(self):
        self.reject_json('config/pon-nakamoto-v1.json',lambda d:d['implementation'].update(public_model_efficacy_measured=True))
    def test_legacy_appendix_cannot_return(self):
        path='docs/modules/M00_FOUNDATION_PROTOCOL_TECHNICAL_SPEC_V1.md'
        self.reject_text(path,lambda t:t+'\n## Retired PoCO implementation reference\nold engine\n')
    def test_missing_module_contract(self):
        self.reject_json('config/pon-nakamoto-v1.json',lambda d:d['module_targets'].pop())
    def test_broken_navigation(self):
        self.reject_text('README.md',lambda t:t+'\n[missing](docs/deleted-protocol.md)\n')
    def test_removed_decoder_requirement_cannot_return(self):
        self.reject_text('docs/modules/M01_CRYPTO_IDENTITY_TECHNICAL_SPEC_V1.md',lambda t:t+'\nVerifyHistoricalPoCO\n')
    def test_fault_harness_isolation_remains_explicit(self):
        self.reject_text('.github/workflows/trnm-required-baseline.yml',lambda t:t.replace('RUST_TEST_THREADS: "1"','RUST_TEST_THREADS: "8"'))
    def test_job_env_cannot_use_unallocated_runner_context(self):
        self.reject_text('.github/workflows/trnm-required-baseline.yml',lambda t:t.replace('    steps:', '    env:\n      BAD: ${{ runner.temp }}\n    steps:',1))
    def test_every_job_has_runner_stage_cargo_isolation(self):
        self.reject_text('.github/workflows/trnm-required-baseline.yml',lambda t:t.replace('name: Set isolated Cargo paths after runner allocation','name: Removed isolation',1))
    def test_required_job_not_dropped(self):
        self.reject_text('.github/workflows/trnm-required-baseline.yml',lambda t:t.replace('  rust-baseline:','  renamed-job:'))
    def test_no_persistent_runner_for_untrusted_pr(self):
        self.reject_text('.github/workflows/trnm-required-baseline.yml',lambda t:t.replace('ubuntu-24.04','self-hosted'))
    def test_no_write_permission_for_untrusted_pr(self):
        self.reject_text('.github/workflows/trnm-required-baseline.yml',lambda t:t.replace('contents: read','contents: write'))
    def test_no_checkout_credential_persistence(self):
        self.reject_text('.github/workflows/trnm-required-baseline.yml',lambda t:t.replace('persist-credentials: false','persist-credentials: true'))
    def test_no_privileged_pr_event(self):
        self.reject_text('.github/workflows/trnm-required-baseline.yml',lambda t:t.replace('  pull_request:','  pull_request_target:'))

if __name__=='__main__':unittest.main(verbosity=2)
