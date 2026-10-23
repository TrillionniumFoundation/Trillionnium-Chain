"""Real ordinary pidfds/files; synthetic errors, never a cgroup or model."""
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import llm_runtime_kernel_aggregate as aggregate
import llm_runtime_kernel_owned as kernel
import llm_runtime_pilot as runtime


class TerminalCodeTests(unittest.TestCase):
    def child(self, error):
        with open(os.devnull, 'wb') as output:
            child = runtime._Wait4Child(['/bin/true'], stdout=output, stderr=subprocess.STDOUT)
        self.assertEqual(child.reap(0), 'terminal')
        self.addCleanup(child.finish)
        cap = SimpleNamespace(terminal_record=Mock(side_effect=error))
        child.kernel_operation = cap
        child._tiny_pipe = SimpleNamespace(capability=cap)
        child._tiny_pipe_type = SimpleNamespace
        # Synthetic prebindings exercise the original catch/real pidfd closure.
        child._terminal_budget_error_type = kernel.KernelBudgetError
        child._terminal_budget_codes = getattr(runtime, '_AGGREGATE_TERMINAL_CODES',
            ('aggregate-charge-retained', 'aggregate-counter-snapshot-changed'))
        child._counter_error_type = aggregate.AggregateCounterError
        child._counter_diagnostic_type = aggregate._CounterDiagnostic
        child._counter_filenames = tuple('aggregate/'+name for name in aggregate._RAW) + ('unit/cgroup.stat',)
        child._charge_counter_filenames = ('aggregate/memory.current', 'aggregate/memory.swap.current')
        child._counter_reasons = ('aggregate-counter-format', 'aggregate-counter-overflow',
            'aggregate-counter-fields', 'aggregate-counter-scalar', 'aggregate-charge-retained')
        return child

    def assert_original_failure_and_close(self, child, descriptor):
        self.assertEqual(child.observation_error, 'kernel-terminal-tiny-evidence-unavailable')
        self.assertIsNone(child.termination_fd)
        with self.assertRaises(OSError): os.fstat(descriptor)
        self.assertIsNone(child.kernel_evidence)

    def test_exact_known_code_is_retained_without_stringifying_error(self):
        error = kernel.KernelBudgetError('aggregate-counter-snapshot-changed')
        child = self.child(error); descriptor = child.termination_fd
        with patch.object(kernel.KernelBudgetError, '__str__', side_effect=AssertionError('no formatting')):
            child._finish_tiny_pipe()
        self.assert_original_failure_and_close(child, descriptor)
        self.assertEqual(getattr(child, 'kernel_tiny_terminal_code', None), 'aggregate-counter-snapshot-changed')
        self.assertEqual(child.kernel_tiny_terminal_failure, 'KernelBudgetError')

    def test_unknown_subclass_and_malformed_arguments_never_become_terminal_codes(self):
        class Other(kernel.KernelBudgetError): pass
        class Text(str): pass
        for error in (Other('aggregate-charge-retained'), ValueError('aggregate-charge-retained'),
                kernel.KernelBudgetError('unknown-code'), kernel.KernelBudgetError('x'*129),
                kernel.KernelBudgetError(), kernel.KernelBudgetError('aggregate-charge-retained', 'extra'),
                kernel.KernelBudgetError(Text('aggregate-charge-retained'))):
            with self.subTest(error=type(error).__name__, args=error.args):
                child = self.child(error); descriptor = child.termination_fd
                child._finish_tiny_pipe()
                self.assert_original_failure_and_close(child, descriptor)
                self.assertIsNone(getattr(child, 'kernel_tiny_terminal_code', None))

    def test_first_failure_code_is_not_replaced_by_a_later_catch(self):
        child = self.child(kernel.KernelBudgetError('aggregate-charge-retained'))
        child._finish_tiny_pipe()
        child._tiny_pipe = object()  # Second synthetic ownership failure.
        child._finish_tiny_pipe()
        self.assertEqual(child.kernel_tiny_terminal_failure, 'KernelBudgetError')
        self.assertEqual(getattr(child, 'kernel_tiny_terminal_code', None), 'aggregate-charge-retained')
        self.assertEqual(child.observation_error, 'kernel-terminal-tiny-evidence-unavailable')

    def test_code_projection_faults_keep_original_failure_and_close(self):
        for fault in (MemoryError, KeyboardInterrupt):
            with self.subTest(fault=fault.__name__):
                child = self.child(kernel.KernelBudgetError('aggregate-charge-retained'))
                descriptor = child.termination_fd
                with patch.object(child, '_retain_kernel_terminal_code', create=True, side_effect=fault):
                    child._finish_tiny_pipe()
                self.assert_original_failure_and_close(child, descriptor)
                self.assertTrue(getattr(child, 'kernel_terminal_code_projection_failed', False))

    def test_budget_code_types_and_fixed_set_bind_before_spawn(self):
        cap = object.__new__(aggregate._AggregateOperation)
        cap.native = SimpleNamespace(close_handoff=Mock(return_value=0))
        def refused(command, output, child):
            self.assertIs(getattr(child, '_terminal_budget_error_type', None), kernel.KernelBudgetError)
            self.assertIs(child._terminal_budget_codes, runtime._AGGREGATE_TERMINAL_CODES)
            self.assertIsNone(child.kernel_tiny_terminal_code)
            raise ValueError('synthetic-before-spawn')
        cap.spawn = refused
        with open(os.devnull, 'wb') as output, self.assertRaisesRegex(ValueError, 'before-spawn'):
            runtime._Wait4Child(['/bin/true'], stdout=output, stderr=subprocess.STDOUT,
                _aggregate_operation=cap, _kernel_deadline=1.0)

    def test_typed_charge_raw_survives_code_projection_fault_and_closes_pidfd(self):
        for filename in ('aggregate/memory.current', 'aggregate/memory.swap.current'):
            for fault in (MemoryError, KeyboardInterrupt):
                with self.subTest(filename=filename, fault=fault.__name__):
                    error = aggregate.AggregateCounterError('aggregate-charge-retained', filename, '290816\n')
                    child = self.child(error); descriptor = child.termination_fd
                    with patch.object(child, '_retain_kernel_terminal_code', side_effect=fault):
                        child._finish_tiny_pipe()
                    self.assert_original_failure_and_close(child, descriptor)
                    self.assertIs(child.kernel_counter_diagnostic, error.counter_diagnostic)
                    self.assertTrue(child.kernel_terminal_code_projection_failed)
                    self.assertFalse(child.kernel_counter_diagnostic_projection_failed)

    def test_charge_diagnostic_pairs_reject_mutation_without_losing_pidfd_close(self):
        error = aggregate.AggregateCounterError('aggregate-charge-retained', 'aggregate/memory.current', '1\n')
        error._counter_diagnostic = aggregate._CounterDiagnostic('aggregate/cpu.stat', 'usage_usec 1\n',
            'aggregate-charge-retained')
        child = self.child(error); descriptor = child.termination_fd
        child._finish_tiny_pipe()
        self.assert_original_failure_and_close(child, descriptor)
        self.assertIsNone(child.kernel_counter_diagnostic)


class ChargeInputTests(unittest.TestCase):
    def test_first_charge_zero_failure_keeps_exact_raw_and_original_short_circuit(self):
        for current, swap, filename in (('1\n', 'bad\n', 'memory.current'),
                ('0\n', '1\n', 'memory.swap.current')):
            with self.subTest(current=current, swap=swap), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                values = {'memory.current': current, 'memory.swap.current': swap, 'memory.peak': '1\n',
                    'memory.events': 'oom 0\n', 'cpu.stat': 'usage_usec 1\n',
                    'cgroup.events': 'populated 0\n', 'cgroup.stat': 'nr_descendants 0\nnr_dying_descendants 0\n',
                    'pids.current': '0\n', 'cgroup.procs': ''}
                for name, text in values.items(): (root/name).write_text(text)
                fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                try:
                    reads = []; original = kernel._text
                    def read(descriptor, name):
                        reads.append(name); return original(descriptor, name)
                    with patch.object(kernel, '_text', side_effect=read), self.assertRaises(kernel.KernelBudgetError) as caught:
                        aggregate._raw(fd)
                    self.assertIs(type(caught.exception), aggregate.AggregateCounterError)
                    self.assertEqual(caught.exception.counter_diagnostic,
                        ('aggregate/'+filename, values[filename], 'aggregate-charge-retained'))
                    self.assertEqual(reads, list(aggregate._RAW))
                    (root/filename).write_text('0\n')
                    self.assertEqual(caught.exception.counter_diagnostic.raw, values[filename])
                finally: os.close(fd)

    def test_charge_constructor_is_limited_to_exact_two_memory_files(self):
        for filename in (*('aggregate/'+name for name in aggregate._RAW), 'unit/cgroup.stat'):
            with self.subTest(filename=filename):
                if filename in ('aggregate/memory.current', 'aggregate/memory.swap.current'):
                    error = aggregate.AggregateCounterError('aggregate-charge-retained', filename, '1\n')
                    self.assertEqual(error.counter_diagnostic, (filename, '1\n', 'aggregate-charge-retained'))
                else:
                    with self.assertRaisesRegex(kernel.KernelBudgetError, 'charge-filename'):
                        aggregate.AggregateCounterError('aggregate-charge-retained', filename, '1\n')


if __name__ == '__main__': unittest.main()
