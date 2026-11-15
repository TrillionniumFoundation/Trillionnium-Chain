"""Source-admission controls only; no model, native export or authority claim."""
import copy
from dataclasses import replace
import hashlib
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import llm_cell_host_handoff as handoff
import llm_cell_release as release
import llm_inherited_runtime as inherited
import llm_initial_trainable_setup_v2 as setup
import llm_neural_read_worker as neural
import llm_runtime_candidate_observation_v1 as candidate
import llm_runtime_parent_step as step
import llm_runtime_parent_step_v2 as v2
import llm_runtime_pilot as runtime
import test_llm_inherited_runtime as inherited_fixture
import test_llm_runtime_parent_step as parent_fixture
import test_llm_runtime_parent_step_v2 as parent_v2_fixture


HELPER = 'llm_base_material.py'


class _SourceGatePassed(RuntimeError):
    """Stop at the next boundary, before any model or native operation."""


class BaseMaterialSourceClosureTests(unittest.TestCase):
    def fixture(self, case):
        value = case()
        value.setUp()
        self.addCleanup(value.doCleanups)
        return value

    def test_current_helper_is_pinned_by_every_transitive_loader_entry(self):
        expected = runtime.file_sha(Path(runtime.__file__).with_name(HELPER))
        for pins in (runtime.run_components(), inherited.source_pins(), setup._sources()):
            self.assertEqual(pins[HELPER], expected)
        self.assertEqual(step.sources()['base_material'], expected)
        profiles = (v2.PROFILE, v2.NEW_TASK_PROFILE, v2.research.PROFILE,
                    v2.task_research.PROFILE, v2.observed.PROFILE,
                    v2.binary.PROFILE, v2.diverse.PROFILE)
        for profile in profiles:
            with self.subTest(profile=profile):
                self.assertEqual(v2.sources(profile)['base_material'], expected)
                self.assertEqual(candidate._sources(profile)['producer']['base_material'], expected)
        self.assertEqual(set(release.SOURCE_PATHS), set(handoff.SOURCES.values()))
        self.assertEqual(handoff.SOURCES[HELPER], 'scripts/' + HELPER)

    def test_inherited_plan_rejects_omitted_changed_or_stale_helper(self):
        plan = self.fixture(inherited_fixture.InheritedRuntimeTests).plan
        self.assertIs(inherited.validate_plan(plan), plan)
        for change in ('missing', 'wrong-hash'):
            value = copy.deepcopy(plan)
            if change == 'missing':
                value['source_pins'].pop(HELPER)
            else:
                value['source_pins'][HELPER] = 'f' * 64
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, '^INHERITED_SOURCE_CHANGED$'):
                inherited.validate_plan(value)
        original_hash = runtime.file_sha
        helper = Path(runtime.__file__).with_name(HELPER)
        altered_hash = hashlib.sha256(helper.read_bytes() + b'\n# changed source fixture\n').hexdigest()
        def altered_source(path):
            return altered_hash if Path(path) == helper else original_hash(path)
        with patch.object(runtime, 'file_sha', side_effect=altered_source), \
                self.assertRaisesRegex(ValueError, '^INHERITED_SOURCE_CHANGED$'):
            inherited.validate_plan(plan)

    def test_parent_v1_v2_preflight_rejects_missing_or_changed_helper(self):
        for case, code in ((parent_fixture.ParentStepTests, 'PARENT_STEP_SOURCE'),
                           (parent_v2_fixture.ParentStepV2Tests, 'PARENT_V2_SCOPE_SOURCE')):
            fixture = self.fixture(case)
            with patch.object(runtime, 'runtime_import', side_effect=AssertionError('no model import')) as imports:
                step.preflight(fixture.value)
                for change in ('missing', 'wrong-hash'):
                    value = copy.deepcopy(fixture.value)
                    if change == 'missing':
                        value['source'].pop('base_material')
                    else:
                        value['source']['base_material'] = 'f' * 64
                    with self.subTest(case=case.__name__, change=change), \
                            self.assertRaisesRegex(ValueError, '^' + code + '$'):
                        step.preflight(value)
                imports.assert_not_called()
            self.assertFalse(Path(fixture.value['output']).parent.exists())

    def test_neural_worker_checks_helper_before_runtime_or_material_access(self):
        plan = dict(schema=neural.SCHEMA, runtime={'source-gate-fixture': True}, parent=None,
                    inherited_sources=inherited.source_pins(), worker_source=runtime.file_sha(neural.__file__),
                    actions=[])
        args = SimpleNamespace(plan='/not-read/source-fixture', plan_sha256='a' * 64)
        with patch.object(inherited, 'checked_json', return_value=plan), \
                patch.object(runtime, 'validate_plan', side_effect=_SourceGatePassed) as gate:
            with self.assertRaises(_SourceGatePassed):
                neural.worker(args)
            gate.assert_called_once_with(plan['runtime'])
        for change in ('missing', 'wrong-hash'):
            value = copy.deepcopy(plan)
            if change == 'missing':
                value['inherited_sources'].pop(HELPER)
            else:
                value['inherited_sources'][HELPER] = 'f' * 64
            with self.subTest(change=change), patch.object(inherited, 'checked_json', return_value=value), \
                    patch.object(runtime, 'validate_plan') as gate, \
                    self.assertRaisesRegex(ValueError, '^NEURAL_READ_SOURCE_CHANGED$'):
                neural.worker(args)
            gate.assert_not_called()

    def test_candidate_observer_inherits_helper_check_before_producer(self):
        training = dict(schema=v2.SCHEMA, initial_setup=dict(profile=v2.PROFILE))
        value = dict(schema=candidate.INPUT, training_directory='/not-read/source-fixture',
                     source=candidate._sources(v2.PROFILE))
        with patch.object(step, 'read_object', return_value=training), \
                patch.object(v2, 'preflight', side_effect=_SourceGatePassed) as gate:
            with self.assertRaises(_SourceGatePassed):
                candidate._producer(value)
            gate.assert_called_once_with(training)
        for change in ('missing', 'wrong-hash'):
            altered = copy.deepcopy(value)
            if change == 'missing':
                altered['source']['producer'].pop('base_material')
            else:
                altered['source']['producer']['base_material'] = 'f' * 64
            with self.subTest(change=change), patch.object(step, 'read_object', return_value=training), \
                    patch.object(v2, 'preflight') as gate, \
                    self.assertRaisesRegex(ValueError, '^CANDIDATE_OBSERVATION_SOURCE$'):
                candidate._producer(altered)
            gate.assert_not_called()

    def test_initial_setup_checks_captured_helper_before_any_factor_read(self):
        # Only the private source-gate record is constructed. No tensor capture
        # or preparation is claimed; the next factor boundary always raises.
        model = object()
        captured = setup._CapturedA(setup._SEAL, model, (), (),
            tuple(sorted(setup._sources().items())), tuple(sorted(setup.RECIPE.items())), ())
        arguments = dict(model=model, contract={}, contract_digest='a' * 64,
            parent=dict(generation=1, contract='a' * 64, adapter='b' * 64,
                        file_sha256=setup.PARENT_SHA256),
            parent_bytes=setup.canonical_zero_parent(), captured=captured, torch=None,
            operation_id='source-gate-only')
        with patch.object(setup, '_parameters', side_effect=_SourceGatePassed) as gate:
            with self.assertRaises(_SourceGatePassed):
                setup.prepare_working_copy(**arguments)
            gate.assert_called_once_with(model, {}, None)
        for change in ('missing', 'wrong-hash'):
            pins = dict(captured.sources)
            if change == 'missing':
                pins.pop(HELPER)
            else:
                pins[HELPER] = 'f' * 64
            altered = replace(captured, sources=tuple(sorted(pins.items())))
            with self.subTest(change=change), patch.object(setup, '_parameters') as gate, \
                    self.assertRaisesRegex(ValueError, '^INITIAL_SETUP_CAPTURE_SOURCE$'):
                setup.prepare_working_copy(**dict(arguments, captured=altered))
            gate.assert_not_called()

    def checkout(self, root):
        chain = root / 'chain'
        for relative in handoff.SOURCES.values():
            path = chain / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(('source binding fixture: ' + relative).encode())
        return chain

    def test_controlled_release_requires_helper_file_before_native_export(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); chain = self.checkout(root)
            parent = dict(generation=1, operation_id='source-gate-only', directory=str(root / 'parent'))
            args = SimpleNamespace(chain=chain, output=root / 'absent-output')
            members = [dict(name=name) for name in release.ROSTER]
            normal = release.read_regular
            observed = []
            def source_only(path, maximum):
                if Path(path) == root / 'parent' / 'target-contract.json':
                    raise _SourceGatePassed
                observed.append(Path(path))
                return normal(path, maximum)
            with patch.object(release, 'read_regular', side_effect=source_only), \
                    patch.object(release.subprocess, 'run') as export:
                with self.assertRaises(_SourceGatePassed):
                    release.prepare_sidecar(args, None, parent, None, members, None, None, None)
                self.assertIn(chain / handoff.SOURCES[HELPER], observed)
                (chain / handoff.SOURCES[HELPER]).unlink()
                with self.assertRaises(FileNotFoundError):
                    release.prepare_sidecar(args, None, parent, None, members, None, None, None)
                export.assert_not_called()
            self.assertFalse(args.output.exists())

    def test_host_rejects_missing_wrong_and_changed_helper_before_export(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); chain = self.checkout(root)
            args = SimpleNamespace(chain=chain, python=Path(sys.executable), output=root / 'absent-output')
            pins = {str(chain / relative): handoff.checksum((chain / relative).read_bytes())
                    for relative in handoff.SOURCES.values()}
            worker = dict(source_pins=pins, script=str(chain / handoff.SOURCES['llm_neural_read_worker.py']),
                          python=str(args.python))
            plan = SimpleNamespace(host=dict(owner=dict(worker=worker)), value=dict(context={}, generation=1))
            parent = dict(generation=1, directory=str(root / 'parent'))
            members = [dict(name=name) for name in handoff.NAMES]
            normal = handoff.bounded
            def source_only(path, maximum):
                if Path(path) == root / 'parent' / 'target-contract.json':
                    raise _SourceGatePassed
                return normal(path, maximum)
            def prepare(value):
                return handoff.prepare(value, args, {}, parent, members, None, None, None, 0)
            with patch.object(handoff, 'bounded', side_effect=source_only), \
                    patch.object(handoff.subprocess, 'run') as export:
                with self.assertRaises(_SourceGatePassed):
                    prepare(plan)
                helper = chain / handoff.SOURCES[HELPER]
                for change in ('missing', 'wrong-hash'):
                    altered = copy.deepcopy(plan)
                    changed_pins = altered.host['owner']['worker']['source_pins']
                    if change == 'missing':
                        changed_pins.pop(str(helper))
                    else:
                        changed_pins[str(helper)] = 'f' * 64
                    with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'worker executable/source pins'):
                        prepare(altered)
                helper.write_bytes(helper.read_bytes() + b'\nchanged after freeze')
                with self.assertRaisesRegex(ValueError, 'worker executable/source pins'):
                    prepare(plan)
                export.assert_not_called()
            self.assertFalse(args.output.exists())


if __name__ == '__main__':
    unittest.main()
