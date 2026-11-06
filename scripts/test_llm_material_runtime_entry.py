#!/usr/bin/env python3
"""Preflight component controls: real material bytes, no Torch/model execution.

These tests deliberately use an observed local file-verification context, not a
qualified runtime snapshot. The original runtime and bootstrap suites retain the
full snapshot/isolated-import gates. Nothing here claims a successful model load.
"""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import types
import unittest

import llm_initial_trainable_setup_v2 as setup
import llm_inherited_runtime as inherited
import llm_neural_read_worker as worker
import llm_python_runtime_contract as runtime_contract
import llm_runtime_pilot as runtime


class MaterialRuntimeEntryTests(unittest.TestCase):
    def setUp(self):
        self.saved = {name: getattr(worker, name, None)
                      for name in ('runtime', 'inherited', 'python_runtime')}
        worker.runtime, worker.inherited = runtime, inherited
        worker.python_runtime = runtime_contract
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.repository = Path(worker.__file__).resolve().parents[1]
        fixture = self.repository / 'tests/fixtures/llm_material_runtime_bridge_v1'
        self.material_plan = (fixture / 'historical_plan.json').read_bytes()
        contract_raw = (fixture / 'historical_target.json').read_bytes()
        contract = json.loads(contract_raw)
        artifact = setup.canonical_zero_parent()
        factors = inherited.parent_material.factor_bytes(artifact, contract)
        wrapped = setup._wrapped(contract, worker._MATERIAL_CONTRACT_ID, factors)
        wrapped_raw, adapter = runtime.contract_module().freeze_wrapped_adapter(
            wrapped, contract, worker._MATERIAL_CONTRACT_ID)
        self.parent_root = self.root / 'parent'
        self.parent_root.mkdir()
        for name, raw in (('target-contract.json', contract_raw),
                          ('wrapped-adapter.json', wrapped_raw),
                          ('artifact.safetensors', artifact)):
            (self.parent_root / name).write_bytes(raw)
        self.parent = dict(schema=inherited.PARENT_SCHEMA, generation=1,
            operation_id='material-runtime-entry-control', directory=str(self.parent_root),
            contract=worker._MATERIAL_CONTRACT_ID, adapter=adapter,
            file_sha256=hashlib.sha256(artifact).hexdigest())
        runtime_plan = json.loads(self.material_plan)
        runtime_plan['runtime_source'] = worker._EXECUTION_RUNTIME_SHA256
        self.plan = dict(schema=worker.BRIDGED_PLAN_SCHEMA_V1, runtime=runtime_plan,
            parent=self.parent, inherited_sources=worker.worker_sources(),
            worker_source=runtime.file_sha(worker.__file__), actions=[],
            runtime_snapshot_sha256='11' * 32,
            material_bridge=dict(profile=worker.MATERIAL_BRIDGE_PROFILE_V1,
                                 material_plan=self.material_plan.decode()))
        names = set(self.plan['inherited_sources']) | {Path(worker.__file__).name}
        paths = [*sorted((self.repository / 'scripts').glob('*.py')),
                 self.repository / 'formal/pon-nakamoto-v1/contract_wire.py',
                 self.repository / 'formal/pon-nakamoto-v1/llm_adapter_contract.py',
                 *sorted((self.repository / 'config/pon').glob('*.json'))]
        self.sources = {str(path): runtime.file_sha(path)
                        for path in paths if path.name in names}
        self.assertEqual(len(self.sources), 13)
        prefix, stdlib = self.root / 'prefix', self.root / 'stdlib'
        prefix.mkdir(); stdlib.mkdir()
        self.probe = self.root / 'measured-component'
        self.probe.write_bytes(b'actual bounded component observation')
        context = dict(prefix=str(prefix), stdlib_root=str(stdlib),
                       managed_inventory=[], files={str(self.probe): runtime.file_sha(self.probe)})
        self.args = types.SimpleNamespace(plan=str(self.root / 'plan.json'),
            runtime_contract=context, runtime_source_pins=dict(self.sources),
            runtime_snapshot_sha256=self.plan['runtime_snapshot_sha256'])
        self.save_plan()

    def tearDown(self):
        for name, value in self.saved.items():
            if value is None:
                delattr(worker, name)
            else:
                setattr(worker, name, value)

    def save_plan(self):
        raw = runtime.canonical(self.plan)
        Path(self.args.plan).write_bytes(raw)
        self.args.plan_sha256 = hashlib.sha256(raw).hexdigest()

    def test_actual_parent_and_current_plan_pass_preflight_without_loading_model(self):
        self.assertIsNone(worker.preflight_material_runtime_bridge_v1(self.args))
        plan, pilot, bridge = worker._read_worker_plan(self.args, True)
        self.assertEqual(plan, self.plan)
        self.assertEqual(pilot['runtime_source'], worker._EXECUTION_RUNTIME_SHA256)
        self.assertIsInstance(bridge, worker._MaterialRuntimeBridgeV1)
        self.assertFalse((self.root / 'worker').exists())
        self.assertRegex(worker._bridge_source_commitment(self.args), r'^[0-9a-f]{64}$')

    def test_legacy_and_explicit_bridge_modes_reject_each_other_before_entry(self):
        with self.assertRaisesRegex(ValueError, 'NEURAL_READ_PLAN'):
            worker._read_worker_plan(self.args, False)
        self.plan.pop('material_bridge')
        self.plan['schema'] = worker.SCHEMA
        self.save_plan()
        with self.assertRaisesRegex(ValueError, 'NEURAL_READ_PLAN'):
            worker.preflight_material_runtime_bridge_v1(self.args)
        _, _, bridge = worker._read_worker_plan(self.args, False)
        self.assertIsNone(bridge)

    def test_preflight_measures_actual_runtime_context_before_plan_processing(self):
        self.probe.write_bytes(b'changed after observation')
        Path(self.args.plan).unlink()
        with self.assertRaisesRegex(ValueError, 'BYTE_DRIFT'):
            worker.preflight_material_runtime_bridge_v1(self.args)

    def test_complete_thirteen_source_set_is_closed_and_alias_free(self):
        for omitted in self.sources:
            with self.subTest(omitted=omitted):
                self.args.runtime_source_pins = {k: v for k, v in self.sources.items() if k != omitted}
                with self.assertRaisesRegex(ValueError, 'NEURAL_BRIDGE_SOURCE_SET'):
                    worker.preflight_material_runtime_bridge_v1(self.args)
        for extra in ('unreviewed_caller.py', 'hepta_neural_forward_v2.py'):
            self.args.runtime_source_pins = dict(self.sources)
            self.args.runtime_source_pins[str(self.root / extra)] = '22' * 32
            with self.assertRaisesRegex(ValueError, 'NEURAL_BRIDGE_SOURCE_SET'):
                worker.preflight_material_runtime_bridge_v1(self.args)
        self.args.runtime_source_pins = dict(self.sources)
        self.args.runtime_source_pins[str(self.root / 'llm_runtime_pilot.py')] = '22' * 32
        with self.assertRaisesRegex(ValueError, 'NEURAL_BRIDGE_SOURCE_ALIAS'):
            worker.preflight_material_runtime_bridge_v1(self.args)

    def test_execution_source_must_equal_the_actual_fixed_pilot_not_a_claim(self):
        self.args.runtime_source_pins[str(Path(runtime.__file__).resolve())] = worker._MATERIAL_RUNTIME_SHA256
        with self.assertRaisesRegex(ValueError, 'NEURAL_BRIDGE_EXECUTION_SOURCE'):
            worker.preflight_material_runtime_bridge_v1(self.args)
        self.args.runtime_source_pins = dict(self.sources)
        self.plan['runtime']['runtime_source'] = worker._MATERIAL_RUNTIME_SHA256
        self.save_plan()
        with self.assertRaisesRegex(ValueError, 'NEURAL_BRIDGE_CURRENT_PLAN'):
            worker.preflight_material_runtime_bridge_v1(self.args)

    def test_loaded_parent_bytes_are_verified_before_bridge_admission(self):
        for name in ('target-contract.json', 'wrapped-adapter.json', 'artifact.safetensors'):
            path = self.parent_root / name
            original = path.read_bytes()
            path.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
            with self.subTest(name=name), self.assertRaises((ValueError, UnicodeError)):
                worker.preflight_material_runtime_bridge_v1(self.args)
            path.write_bytes(original)
        worker.preflight_material_runtime_bridge_v1(self.args)

    def test_only_exact_material_profile_and_raw_plan_are_accepted(self):
        original = copy.deepcopy(self.plan['material_bridge'])
        for change in ({'profile': 'legacy'},
                       {'material_plan': self.material_plan.decode().rstrip()},
                       {'caller_asserted_compatible': True}):
            self.plan['material_bridge'] = dict(original, **change)
            self.save_plan()
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'NEURAL_BRIDGE_'):
                worker.preflight_material_runtime_bridge_v1(self.args)

    def test_existing_cpu_and_runtime_snapshot_checks_still_precede_model_load(self):
        original = copy.deepcopy(self.plan)
        for key, value, expected in (('runtime_snapshot_sha256', '00' * 32, 'NEURAL_READ_SOURCE_CHANGED'),
                                     ('worker_source', '00' * 32, 'NEURAL_READ_SOURCE_CHANGED')):
            self.plan = dict(original, **{key: value})
            self.save_plan()
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, expected):
                worker.preflight_material_runtime_bridge_v1(self.args)
        self.plan = copy.deepcopy(original)
        self.plan['runtime']['threads'] = 5
        self.save_plan()
        with self.assertRaisesRegex(ValueError, 'NEURAL_READ_CPU_ONLY'):
            worker.preflight_material_runtime_bridge_v1(self.args)

    def test_preadmission_returns_no_load_or_ready_capability(self):
        self.assertIsNone(worker.preflight_material_runtime_bridge_v1(self.args))
        self.assertFalse(hasattr(self.args, 'material_bridge_verified'))
        self.assertFalse(hasattr(self.args, 'runtime_ready'))
        self.plan['material_bridge']['profile'] = 'changed-after-success'
        self.save_plan()
        with self.assertRaisesRegex(ValueError, 'NEURAL_BRIDGE_PROFILE'):
            worker.preflight_material_runtime_bridge_v1(self.args)


if __name__ == '__main__':
    unittest.main()
