#!/usr/bin/env python3
"""Negative target/retirement/claim tests; no execution or security acceptance."""
from copy import deepcopy
import json
import unittest
from check_pon_documentation_v1 import ROOT, CONTRACT, SECTIONS, TargetError, read_json, strict_object, validate_contract, validate_spec, validate_repository

class TargetTests(unittest.TestCase):
    def setUp(self): self.data=read_json(ROOT/CONTRACT)
    def reject(self, mutate):
        mutate(self.data)
        with self.assertRaises((TargetError,KeyError,ValueError)):validate_contract(self.data)
    def test_current_contract(self):validate_contract(self.data)
    def test_repository_inventory_and_links(self):self.assertEqual(validate_repository(ROOT)['modules'],18)
    def test_unknown_field(self):self.reject(lambda d:d.update(arbitrary=True))
    def test_wrong_selected_target(self):self.reject(lambda d:d.update(selected_development_target='native-poco-bft'))
    def test_poco_not_retired(self):self.reject(lambda d:d.update(poco_development_retired=False))
    def test_highest_height_not_work(self):self.reject(lambda d:d.update(fork_choice='highest-height'))
    def test_deterministic_finality(self):self.reject(lambda d:d.update(confirmation='QC-finality'))
    def test_quality_weight(self):self.reject(lambda d:d.update(quality_weighted_chainwork=True))
    def test_validator_vote(self):self.reject(lambda d:d.update(validator_voting=True))
    def test_bft_fallback(self):self.reject(lambda d:d.update(automatic_bft_fallback=True))
    def test_hash_only_fallback(self):self.reject(lambda d:d.update(automatic_hash_only_fallback=True))
    def test_no_production_flag(self):self.reject(lambda d:d.update(production_consensus_activation=True))
    def test_no_implicit_implementation(self):self.reject(lambda d:d['implementation'].update(runtime_implemented=True))
    def test_no_implicit_efficacy(self):self.reject(lambda d:d['implementation'].update(public_model_efficacy_measured=True))
    def test_unqualified_primitive(self):self.reject(lambda d:d['work_profile'].update(status='qualified'))
    def test_fake_concrete_primitive(self):self.reject(lambda d:d['work_profile'].update(concrete_profile_id='hash-with-model-label'))
    def test_historical_training_not_fresh(self):self.reject(lambda d:d['work_profile'].update(historical_training_is_fresh_work=True))
    def test_uncalibrated_work_classes(self):self.reject(lambda d:d['work_profile'].update(work_class_count=2))
    def test_missing_module(self):self.reject(lambda d:d['module_targets'].pop())
    def test_duplicate_module(self):self.reject(lambda d:d['module_targets'].__setitem__(1,deepcopy(d['module_targets'][0])))
    def test_module_source_not_second_registry(self):self.reject(lambda d:d['module_targets'][0].update(source_owner_registry='new-registry'))
    def test_missing_protocol(self):self.reject(lambda d:d['protocol_documents'].pop())
    def test_old_runtime_not_renamed(self):self.reject(lambda d:d['legacy_implementation'].update(consensus_mainline='pon-runtime'))
    def test_duplicate_json_key(self):
        with self.assertRaises(TargetError):json.loads('{"activation":false,"activation":true}',object_pairs_hook=strict_object)
    def test_missing_target_section(self):
        row=self.data['module_targets'][0];text=(ROOT/row['technical_spec']).read_text()
        for heading in SECTIONS:
            with self.subTest(heading=heading),self.assertRaises(TargetError):
                validate_spec(text.replace('## PoN '+heading+'\n','## Missing '+heading+'\n'),'M00')
    def test_missing_legacy_scope(self):
        row=self.data['module_targets'][0];text=(ROOT/row['technical_spec']).read_text()
        with self.assertRaises(TargetError):validate_spec(text.replace('## Retired PoCO implementation reference','## Active legacy'),'M00')

if __name__=='__main__':unittest.main(verbosity=2)
