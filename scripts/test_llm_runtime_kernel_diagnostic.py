"""Actual ordinary owned pidfds; synthetic terminal errors, no cgroup/model."""
import builtins
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import llm_runtime_kernel_aggregate as aggregate
import llm_runtime_pilot as runtime


class TerminalDiagnosticTests(unittest.TestCase):
    def test_default_stdout_and_unsupported_receipt_keep_original_bytes(self):
        original_import = builtins.__import__
        def no_aggregate(name, *args, **kwargs):
            if name == 'llm_runtime_kernel_aggregate': raise AssertionError('default dependency changed')
            return original_import(name, *args, **kwargs)
        with tempfile.TemporaryDirectory() as directory, patch.object(builtins, '__import__', no_aggregate):
            normal = Path(directory)/'normal'
            result = runtime.supervise(['/bin/echo', 'ordinary-output'], normal,
                dict(wall_seconds=2, rss_bytes=64*1024**2))
            self.assertEqual((normal/'process.log').read_bytes(), b'ordinary-output\n')
            self.assertEqual((normal/'supervisor.json').read_bytes(), runtime.canonical(result)+b'\n')
            self.assertNotIn('controlled_kernel_spawn', result)
            unsupported = Path(directory)/'unsupported'
            with patch.object(runtime, '_Wait4Child', side_effect=runtime._Wait4Unsupported('fixture')):
                failed = runtime.supervise(['/bin/true'], unsupported,
                    dict(wall_seconds=2, rss_bytes=64*1024**2))
            self.assertEqual((unsupported/'process.log').read_bytes(), b'')
            self.assertEqual((unsupported/'supervisor.json').read_bytes(), runtime.canonical(failed)+b'\n')
            self.assertEqual(json.loads((unsupported/'supervisor.json').read_text()), failed)
            self.assertEqual(failed['stop_reason'], 'rss-owner-unsupported')

    def child(self, error):
        with open(os.devnull, 'wb') as output:
            child = runtime._Wait4Child(['/bin/true'], stdout=output, stderr=subprocess.STDOUT)
        self.assertEqual(child.reap(0), 'terminal')
        self.addCleanup(child.finish)
        # Synthetic already-bound aggregate/error types, not a cgroup capability.
        child._counter_error_type = aggregate.AggregateCounterError
        child._counter_diagnostic_type = aggregate._CounterDiagnostic
        child._counter_filenames = ('aggregate/cpu.stat',)
        child._counter_reasons = ('aggregate-counter-format',)
        child.kernel_operation = SimpleNamespace(terminal_record=Mock(side_effect=error))
        return child

    def error(self):
        return aggregate.AggregateCounterError('aggregate-counter-format',
            'aggregate/cpu.stat', 'invalid.dotted 0\n')

    def assert_closed_with_original_failure(self, child, descriptor):
        self.assertTrue(child.reaped)
        self.assertTrue(child.reap_resolved)
        self.assertIsNone(child.termination_fd)
        with self.assertRaises(OSError): os.fstat(descriptor)
        self.assertEqual(child.observation_error, 'kernel-terminal:AggregateCounterError')

    def test_exact_error_copies_existing_immutable_tuple_and_closes_real_pidfd(self):
        error = self.error(); child = self.child(error); descriptor = child.termination_fd
        child.finish()
        self.assert_closed_with_original_failure(child, descriptor)
        self.assertIs(child.kernel_counter_diagnostic, error.counter_diagnostic)
        self.assertTrue(all(type(value) is str for value in child.kernel_counter_diagnostic))
        self.assertFalse(child.kernel_counter_diagnostic_projection_failed)

    def test_optional_projection_memoryerror_and_keyboardinterrupt_never_skip_close(self):
        for fault in (MemoryError, KeyboardInterrupt):
            with self.subTest(fault=fault.__name__):
                child = self.child(self.error()); descriptor = child.termination_fd
                with patch.object(child, '_retain_kernel_counter_diagnostic', side_effect=fault):
                    child.finish()
                self.assert_closed_with_original_failure(child, descriptor)
                self.assertIsNone(child.kernel_counter_diagnostic)
                self.assertTrue(child.kernel_counter_diagnostic_projection_failed)

    def test_projection_fault_after_copy_keeps_only_pure_tuple_and_original_failure(self):
        error = self.error(); child = self.child(error); descriptor = child.termination_fd
        original = child._retain_kernel_counter_diagnostic
        def interrupted(value):
            original(value)
            raise KeyboardInterrupt
        with patch.object(child, '_retain_kernel_counter_diagnostic', side_effect=interrupted):
            child.finish()
        self.assert_closed_with_original_failure(child, descriptor)
        self.assertIs(child.kernel_counter_diagnostic, error.counter_diagnostic)
        self.assertTrue(child.kernel_counter_diagnostic_projection_failed)

    def test_subclass_or_mutated_tuple_never_enters_diagnostic(self):
        class OtherError(aggregate.AggregateCounterError): pass
        for error in (OtherError('aggregate-counter-format', 'aggregate/cpu.stat', 'bad.x 0\n'), self.error()):
            if type(error) is aggregate.AggregateCounterError:
                error._counter_diagnostic = aggregate._CounterDiagnostic('aggregate/cpu.stat', object(),
                    'aggregate-counter-format')
            child = self.child(error); descriptor = child.termination_fd
            child.finish()
            with self.assertRaises(OSError): os.fstat(descriptor)
            self.assertIsNone(child.kernel_counter_diagnostic)

    def test_no_terminal_projection_without_exact_reap_boundary(self):
        child = self.child(self.error()); descriptor = child.termination_fd
        child.observation_error = 'prior-failure'
        child.finish()
        child.kernel_operation.terminal_record.assert_not_called()
        self.assertIsNone(child.kernel_counter_diagnostic)
        self.assertEqual(child.observation_error, 'prior-failure')
        with self.assertRaises(OSError): os.fstat(descriptor)

    def test_aggregate_error_types_are_bound_before_any_native_spawn(self):
        cap = object.__new__(aggregate._AggregateOperation)
        cap.native = SimpleNamespace(close_handoff=Mock(return_value=0))
        def refused(command, output, child):
            self.assertIs(child._counter_error_type, aggregate.AggregateCounterError)
            self.assertIs(child._counter_diagnostic_type, aggregate._CounterDiagnostic)
            self.assertIsNone(child.kernel_counter_diagnostic)
            raise ValueError('synthetic-before-native-refusal')
        cap.spawn = refused
        with open(os.devnull, 'wb') as output, self.assertRaisesRegex(ValueError, 'before-native-refusal'):
            runtime._Wait4Child(['/bin/true'], stdout=output, stderr=subprocess.STDOUT,
                _aggregate_operation=cap, _kernel_deadline=1.0)


if __name__ == '__main__': unittest.main()
