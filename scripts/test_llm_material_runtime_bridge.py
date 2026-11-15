#!/usr/bin/env python3
"""Pure closed-pair contract controls; these never import Torch or load a model.

The two canonical fixtures retain the exact public V2 material bytes from Hepta
dd32a0d510cbeb3dfed0554d982c75168a59d95d. They are not newly generated execution
receipts and do not qualify any runtime, source set or installed parent.
"""
import copy
import hashlib
import json
from pathlib import Path
import unittest

import llm_neural_read_worker as worker

FIXTURES = Path(__file__).resolve().parents[1] / 'tests/fixtures/llm_material_runtime_bridge_v1'
PLAN_SHA = '01ec1a644f37b9fc7a4c6616f589768df97f8eed7a289b5de86afadaa7ce6165'
TARGET_SHA = 'ebc8ac84999a91acb823d1bf8959a7dbc61fe20d7ba137f11affe426605d9852'
CONTRACT = 'c9b06f9a029a3257801844f89acb59b5f59f6a39087335af323f274e9152992f'
CURRENT = '13e4c11d51931d902483372a9a05c7180333893202ecb1d663d57a83111eccc7'


def changed(value):
    if type(value) is bool:
        return not value
    if type(value) is int:
        return value + 1
    if type(value) is str:
        return value + '.'
    if type(value) is list:
        return value + [None]
    if type(value) is dict:
        return dict(value, unexpected=None)
    raise AssertionError(type(value))


class MaterialRuntimeBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan_raw = (FIXTURES / 'historical_plan.json').read_bytes()
        cls.target_raw = (FIXTURES / 'historical_target.json').read_bytes()
        assert hashlib.sha256(cls.plan_raw).hexdigest() == PLAN_SHA
        assert hashlib.sha256(cls.target_raw).hexdigest() == TARGET_SHA

    def setUp(self):
        self.historical_plan = json.loads(self.plan_raw)
        self.current_plan = dict(self.historical_plan, runtime_source=CURRENT)
        self.current_target = json.loads(self.target_raw)
        # Independently retained exact source/formula analysis, not values
        # obtained from the helper under test.
        self.current_target['tokenizer']['behavior_contract'] = (
            '882d9c90a3fb05cc56012a4122f6c43d49f95ccfda67a5b767991c7a399235c0')
        self.current_target['numeric']['operator_contract'] = (
            'e4aff215aa8e74f481c39253326e6c2abdc10e56a1e6eb9f283c5cc4143de576')
        self.current_target['registration']['target_admission'] = (
            '685812fd2084828870b11a8a07b2a685612d76ed4c82d21ef703ccc548370a9f')

    def prepare(self, **changes):
        values = dict(profile=worker.MATERIAL_BRIDGE_PROFILE_V1,
                      material_plan_raw=self.plan_raw,
                      current_plan=self.current_plan,
                      material_contract_raw=self.target_raw,
                      material_contract_id=CONTRACT)
        values.update(changes)
        return worker._MaterialRuntimeBridgeV1(**values)

    def test_authentic_closed_pair_preserves_both_source_identities(self):
        proof = self.prepare().verify_loaded_contract(self.current_target)
        self.assertEqual(proof['historical_runtime_source'], self.historical_plan['runtime_source'])
        self.assertEqual(proof['execution_runtime_source'], CURRENT)
        self.assertNotEqual(proof['historical_runtime_source'], proof['execution_runtime_source'])
        self.assertEqual(proof['historical_plan_sha256'], PLAN_SHA)
        self.assertEqual(proof['historical_contract_sha256'], TARGET_SHA)
        self.assertEqual(proof['historical_contract'], CONTRACT)
        self.assertEqual(proof['execution_contract_sha256'],
                         hashlib.sha256(worker._bridge_canonical(self.current_target)).hexdigest())

    def test_explicit_profile_and_exact_material_endpoint_are_required(self):
        for arguments in [
            dict(profile=None), dict(profile='hepta-smollm-public-initial-v11'),
            dict(profile=worker.MATERIAL_BRIDGE_PROFILE_V1 + '.'),
            dict(material_contract_id='0' * 64),
            dict(material_plan_raw=self.plan_raw + b' '),
            dict(material_contract_raw=self.target_raw + b'\n'),
        ]:
            with self.subTest(arguments=list(arguments)):
                with self.assertRaises(ValueError):
                    self.prepare(**arguments)

    def test_historical_or_arbitrary_runtime_cannot_be_reported_as_current(self):
        for runtime_source in [self.historical_plan['runtime_source'],
                               'ac6b1d9058610907a7dd3486c663c1ee6ad40135a34c63770daa5f556e5879cc',
                               '0' * 64, CURRENT + '.']:
            with self.subTest(source=runtime_source):
                with self.assertRaisesRegex(ValueError, 'NEURAL_BRIDGE_CURRENT_PLAN'):
                    self.prepare(current_plan=dict(self.current_plan, runtime_source=runtime_source))

    def test_every_other_plan_field_is_compared_without_projection(self):
        for name, value in self.current_plan.items():
            if name == 'runtime_source':
                continue
            candidate = copy.deepcopy(self.current_plan)
            candidate[name] = changed(value)
            with self.subTest(field=name):
                with self.assertRaisesRegex(ValueError, 'NEURAL_BRIDGE_CURRENT_PLAN'):
                    self.prepare(current_plan=candidate)
        for candidate in [dict(self.current_plan, unexpected=True),
                          {k: v for k, v in self.current_plan.items() if k != 'threads'}]:
            with self.assertRaisesRegex(ValueError, 'NEURAL_BRIDGE_CURRENT_PLAN'):
                self.prepare(current_plan=candidate)

    def test_every_actual_contract_top_level_field_remains_checked(self):
        bridge = self.prepare()
        for name, value in self.current_target.items():
            candidate = copy.deepcopy(self.current_target)
            candidate[name] = changed(value)
            with self.subTest(field=name):
                with self.assertRaisesRegex(ValueError, 'NEURAL_BRIDGE_LOADED_CONTRACT'):
                    bridge.verify_loaded_contract(candidate)

    def test_all_three_derived_hashes_must_match_and_none_may_be_dropped(self):
        bridge = self.prepare()
        historical = json.loads(self.target_raw)
        for section, field in [('tokenizer', 'behavior_contract'),
                               ('numeric', 'operator_contract'),
                               ('registration', 'target_admission')]:
            for operation in ['old', 'changed', 'missing']:
                candidate = copy.deepcopy(self.current_target)
                if operation == 'old':
                    candidate[section][field] = historical[section][field]
                elif operation == 'changed':
                    candidate[section][field] = '0' * 64
                else:
                    del candidate[section][field]
                with self.subTest(section=section, operation=operation):
                    with self.assertRaisesRegex(ValueError, 'NEURAL_BRIDGE_LOADED_CONTRACT'):
                        bridge.verify_loaded_contract(candidate)
        with self.assertRaisesRegex(ValueError, 'NEURAL_BRIDGE_LOADED_CONTRACT'):
            bridge.verify_loaded_contract(historical)

    def test_current_contract_registration_is_not_exempt(self):
        bridge = self.prepare()
        for field in self.current_target['registration']:
            candidate = copy.deepcopy(self.current_target)
            candidate['registration'][field] = changed(candidate['registration'][field])
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, 'NEURAL_BRIDGE_LOADED_CONTRACT'):
                    bridge.verify_loaded_contract(candidate)

    def test_success_does_not_skip_the_next_actual_contract_comparison(self):
        bridge = self.prepare()
        record = bridge.verify_loaded_contract(self.current_target)
        record['execution_runtime_source'] = self.historical_plan['runtime_source']
        candidate = copy.deepcopy(self.current_target)
        candidate['numeric']['operator_contract'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'NEURAL_BRIDGE_LOADED_CONTRACT'):
            bridge.verify_loaded_contract(candidate)
        self.assertEqual(bridge.verify_loaded_contract(self.current_target)['execution_runtime_source'],
                         CURRENT)

    def test_material_and_current_inputs_are_never_rewritten(self):
        before = (self.plan_raw, self.target_raw, copy.deepcopy(self.current_plan),
                  copy.deepcopy(self.current_target))
        self.prepare().verify_loaded_contract(self.current_target)
        self.assertEqual((self.plan_raw, self.target_raw, self.current_plan, self.current_target),
                         before)
        self.assertEqual((FIXTURES / 'historical_plan.json').read_bytes(), self.plan_raw)
        self.assertEqual((FIXTURES / 'historical_target.json').read_bytes(), self.target_raw)

    def test_bounds_types_nonfinite_values_and_unknown_fields_refuse(self):
        for arguments in [
            dict(material_plan_raw=b' ' * (64 * 1024 + 1)),
            dict(material_contract_raw=b' ' * (1024 * 1024 + 1)),
            dict(material_plan_raw=self.plan_raw.decode()),
            dict(material_contract_raw=self.target_raw.decode()),
            dict(current_plan=dict(self.current_plan, threads=float('nan'))),
            dict(current_plan=[]),
        ]:
            with self.subTest(arguments=list(arguments)):
                with self.assertRaises(ValueError):
                    self.prepare(**arguments)
        with self.assertRaises(ValueError):
            self.prepare().verify_loaded_contract(dict(self.current_target, unexpected=True))


if __name__ == '__main__':
    unittest.main()
