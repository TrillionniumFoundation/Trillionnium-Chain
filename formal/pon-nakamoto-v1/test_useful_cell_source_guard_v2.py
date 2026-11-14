"""Regression controls for V2's local loaded-source consistency boundary.

The retained pre-fix counterexample accepted a wrong recurrent transition with
five real W1 transcripts after replacing a module binding. These tests retain
the actual source/W1 fixture and require refusal before such a substitution
can produce or verify a new statement. They do not claim process isolation or
attestation against arbitrary same-privilege modification of the checker.
"""
from __future__ import annotations

import functools
import builtins
import os
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

import bounded_process
from experiments import shared_cell_operator_v1 as cell
import useful_cell_execution_v2 as execution
import useful_cell_relation_v1 as v1
import useful_cell_relation_v2 as relation
import useful_cell_numeric_v1 as numeric
import test_useful_cell_relation_v2 as relation_tests


class UsefulCellSourceGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        relation_tests.StatefulCellRelationTests.setUpClass()
        cls.fixture = relation_tests.StatefulCellRelationTests
        cls.identity = relation.current_identity()

    def verify_fixture(self):
        f = self.fixture
        return relation.verify_historical_relation(f.raw, f.before, f.proved['output'],
                                                  f.proved['after_state'], f.proved['witness'],
                                                  expected=f.expected)

    def test_complete_real_fixture_and_repeated_identity_remain_valid(self):
        self.assertEqual(relation.current_identity(), self.identity)
        self.assertEqual(self.verify_fixture()['complete_w1_transcripts_verified'], 5)

    def test_original_foreign_function_rebinding_attack_is_refused(self):
        original = execution.execute

        def foreign_execute(model, rows, before, policy, *, verified_products=None):
            result = original(model, rows, before, policy, verified_products=verified_products)
            result['after_state']['memory'][0] += 1
            result['trace'][-1]['outputs']['after']['memory'][0] += 1
            return result

        with patch.object(execution, 'execute', foreign_execute):
            with self.assertRaisesRegex(ValueError, 'V2_LOADED_BINDING_MISMATCH'):
                relation.current_identity()
            f = self.fixture
            with self.assertRaisesRegex(ValueError, 'V2_LOADED_BINDING_MISMATCH'):
                relation.prove_reference(f.raw, f.model, f.rows, f.before, max_attempts=1)
            with self.assertRaisesRegex(ValueError, 'V2_LOADED_BINDING_MISMATCH'):
                self.verify_fixture()
        self.assertEqual(relation.current_identity(), self.identity)

    def test_functools_wraps_cannot_hide_changed_outer_code(self):
        original = execution.execute

        @functools.wraps(original)
        def outer(*args, **kwargs):
            result = original(*args, **kwargs)
            result['after_state']['sequence'] += 1
            return result

        with patch.object(execution, 'execute', outer):
            with self.assertRaisesRegex(ValueError, 'V2_LOADED_BINDING_MISMATCH'):
                relation.current_identity()

    def test_forged_function_module_name_and_qualname_do_not_replace_code(self):
        def forged(*args, **kwargs):
            return {}

        forged.__module__ = execution.__name__
        forged.__name__ = forged.__qualname__ = 'execute'
        with patch.object(execution, 'execute', forged):
            with self.assertRaisesRegex(ValueError, 'V2_LOADED_BINDING_MISMATCH'):
                relation.current_identity()

    def test_identical_code_in_different_globals_is_refused(self):
        original = execution.execute
        replacement = types.FunctionType(original.__code__, dict(vars(execution)), original.__name__)
        replacement.__kwdefaults__ = dict(original.__kwdefaults__)
        with patch.object(execution, 'execute', replacement):
            with self.assertRaisesRegex(ValueError, 'V2_LOADED_BINDING_MISMATCH'):
                relation.current_identity()

    def test_undeclared_global_cannot_shadow_an_executed_builtin(self):
        with patch.object(execution, 'max', lambda *args, **kwargs: 0, create=True):
            with self.assertRaisesRegex(ValueError, 'V2_BUILTIN_BINDING_MISMATCH'):
                relation.current_identity()

    def test_identical_code_and_globals_cannot_retain_different_builtins(self):
        original = execution.execute
        namespace = vars(execution)
        saved = namespace['__builtins__']
        try:
            namespace['__builtins__'] = dict(vars(builtins), max=lambda *args, **kwargs: 0)
            replacement = types.FunctionType(original.__code__, namespace, original.__name__)
            replacement.__kwdefaults__ = dict(original.__kwdefaults__)
        finally:
            namespace['__builtins__'] = saved
        with patch.object(execution, 'execute', replacement):
            with self.assertRaisesRegex(ValueError, 'V2_BUILTIN_BINDING_MISMATCH'):
                relation.current_identity()

    def test_deleted_or_callable_object_bindings_are_refused(self):
        original = execution.execute
        del execution.execute
        try:
            with self.assertRaisesRegex(ValueError, 'V2_LOADED_BINDING_MISMATCH'):
                relation.current_identity()
        finally:
            execution.execute = original

        class Callable:
            def __call__(self, *args, **kwargs):
                return {}

        with patch.object(execution, 'execute', Callable()):
            with self.assertRaisesRegex(ValueError, 'V2_LOADED_BINDING_MISMATCH'):
                relation.current_identity()

    def test_repository_function_import_alias_is_checked_by_identity(self):
        with patch.object(execution, 'evaluate_exact', lambda *args: {}):
            with self.assertRaisesRegex(ValueError, 'V2_IMPORT_BINDING_MISMATCH'):
                relation.current_identity()
        self.assertIs(execution.evaluate_exact, numeric.evaluate_exact)

    def test_repository_module_alias_cannot_point_to_a_separate_namespace(self):
        replacement = types.SimpleNamespace(**vars(execution))
        with patch.object(relation, 'execution', replacement):
            with self.assertRaisesRegex(ValueError, 'V2_IMPORT_BINDING_MISMATCH'):
                relation.current_identity()

    def test_upstream_v1_source_replay_and_product_consumer_bindings_are_guarded(self):
        for module, name in ((v1, '_verify_upstream'), (cell, 'consume_products'), (cell, 'build_tiles')):
            with self.subTest(module=module.__name__, name=name):
                with patch.object(module, name, lambda *args, **kwargs: {}):
                    with self.assertRaisesRegex(ValueError, 'V2_LOADED_BINDING_MISMATCH'):
                        relation.current_identity()

    def test_positional_defaults_are_rebuilt_from_source_not_current_function(self):
        original = execution._identity.__defaults__
        try:
            execution._identity.__defaults__ = (1000000,)
            with self.assertRaisesRegex(ValueError, 'V2_LOADED_DEFAULT_MISMATCH'):
                relation.current_identity()
        finally:
            execution._identity.__defaults__ = original

    def test_keyword_defaults_are_rebuilt_from_source(self):
        original = execution._matrix.__kwdefaults__
        try:
            execution._matrix.__kwdefaults__ = dict(original, bound=32768)
            with self.assertRaisesRegex(ValueError, 'V2_LOADED_DEFAULT_MISMATCH'):
                relation.current_identity()
        finally:
            execution._matrix.__kwdefaults__ = original

    def test_upstream_defaults_are_guarded_too(self):
        original = v1.hex_value.__defaults__
        try:
            v1.hex_value.__defaults__ = (1, 'DIGEST')
            with self.assertRaisesRegex(ValueError, 'V2_LOADED_DEFAULT_MISMATCH'):
                relation.current_identity()
        finally:
            v1.hex_value.__defaults__ = original

    def test_derived_schema_constants_cannot_be_relabelled(self):
        for name in ('STATE_SCHEMA', 'OPTIMIZER_SCHEMA', 'OUTPUT_SCHEMA'):
            with self.subTest(name=name):
                with patch.object(execution, name, 'wrong-schema'):
                    with self.assertRaisesRegex(ValueError, 'V2_LOADED_CONSTANT_MISMATCH'):
                        relation.current_identity()

    def test_default_lambda_code_cannot_be_replaced(self):
        original = relation.verify_live_relation.__kwdefaults__
        try:
            relation.verify_live_relation.__kwdefaults__ = dict(original, clock_ms=lambda: 1500)
            with self.assertRaises(ValueError):
                relation.current_identity()
        finally:
            relation.verify_live_relation.__kwdefaults__ = original

    def test_lru_cache_outer_wrapper_must_be_native_and_have_the_real_target(self):
        original = v1._replayed_source

        @functools.wraps(original)
        def wrapper(*args, **kwargs):
            return original(*args, **kwargs)

        with patch.object(v1, '_replayed_source', wrapper):
            with self.assertRaisesRegex(ValueError, 'V2_LOADED_BINDING_MISMATCH'):
                relation.current_identity()
        inner = original.__wrapped__
        try:
            original.__wrapped__ = lambda *args: b'[]'
            with self.assertRaisesRegex(ValueError, 'V2_LOADED_WRAPPER_MISMATCH'):
                relation.current_identity()
        finally:
            original.__wrapped__ = inner

    def test_dataclass_runtime_generated_method_cannot_be_rebound(self):
        with patch.object(bounded_process.Result, '__init__', lambda *args, **kwargs: None):
            with self.assertRaisesRegex(ValueError, 'V2_LOADED_CLASS_MISMATCH'):
                relation.current_identity()

    def test_historical_replay_still_never_reads_present_wall_clock(self):
        with patch.object(relation.time, 'time_ns', side_effect=AssertionError('WALL_CLOCK_READ')):
            self.assertTrue(self.verify_fixture()['relation_valid'])

    def test_changes_before_v2_import_are_rejected_from_ast_expectations(self):
        cases = {
            'keyword-default': "import useful_cell_execution_v2 as e\ne._matrix.__kwdefaults__['bound'] = 32768\n",
            'positional-default': "import useful_cell_execution_v2 as e\ne._identity.__defaults__ = (1000000,)\n",
            'import-alias': "import useful_cell_execution_v2 as e\ne.evaluate_exact = lambda *args: {}\n",
            'source-binding': "import useful_cell_execution_v2 as e\ne.execute = lambda *args, **kwargs: {}\n",
        }
        suffix = """
import useful_cell_relation_v2 as relation
try:
    relation.current_identity()
except ValueError as error:
    print(str(error))
else:
    raise AssertionError('STALE_BINDING_WRONGLY_ACCEPTED')
"""
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
        environment['PYTHONPATH'] = str(Path(__file__).resolve().parent)
        for name, prefix in cases.items():
            with self.subTest(case=name):
                completed = subprocess.run([sys.executable, '-B', '-c', prefix + suffix],
                                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, env=environment, timeout=30, check=False)
                self.assertEqual(completed.returncode, 0, completed.stderr.decode(errors='replace'))
                self.assertIn(completed.stdout.decode().strip(), (
                    'V2_LOADED_DEFAULT_MISMATCH', 'V2_IMPORT_BINDING_MISMATCH',
                    'V2_LOADED_BINDING_MISMATCH'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
