"""Pure parser/ordinary-file controls, independent of the controlled native ABI."""
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import llm_runtime_kernel_aggregate as aggregate


# Exact new existing SSH-cgroup observation on 4060, 2026-10-22T22:16:10Z.
# This is not the deleted ea2434d5 aggregate's unknown original counter input.
_OBSERVED_CPU = ('usage_usec 105961\nuser_usec 44402\nsystem_usec 61558\n'
    'nice_usec 0\ncore_sched.force_idle_usec 0\nnr_periods 0\nnr_throttled 0\n'
    'throttled_usec 0\nnr_bursts 0\nburst_usec 0\n')


class CounterTests(unittest.TestCase):
    def test_new_observed_kernel_cpu_input_is_accepted_without_dropping_fields(self):
        result = aggregate._numbers(_OBSERVED_CPU, 'aggregate/cpu.stat')
        self.assertEqual(len(result), 10)
        self.assertEqual(result['usage_usec'], 105961)
        self.assertEqual(result['core_sched.force_idle_usec'], 0)
        # The new field is retained even when nonzero; freshness still checks
        # every returned value rather than discarding an inconvenient counter.
        self.assertEqual(aggregate._numbers('usage_usec 0\ncore_sched.force_idle_usec 1\n',
            'aggregate/cpu.stat')['core_sched.force_idle_usec'], 1)

    def test_only_exact_official_dotted_key_is_added(self):
        for key in ('core_sched.force_idle_usec.extra', 'core_sched..force_idle_usec',
                    'core_sched_force_idle_usec.', '.usage_usec', 'usage.usec',
                    'core_sched.force_idle_usec1'):
            with self.subTest(key=key), self.assertRaisesRegex(aggregate.AggregateCounterError, 'format'):
                aggregate._numbers(key+' 0\n', 'aggregate/cpu.stat')

    def test_duplicates_nondecimal_u64_and_field_bounds_still_refuse(self):
        cases = [('core_sched.force_idle_usec 0\ncore_sched.force_idle_usec 1\n', 'format'),
            ('usage_usec 0\nusage_usec 1\n', 'format'), ('usage_usec -1\n', 'format'),
            ('usage_usec 1.0\n', 'format'), ('usage_usec '+str(2**64)+'\n', 'overflow'),
            ('usage_usec '+str(10**20)+'\n', 'format'), ('', 'fields'),
            (''.join('counter'+'a'*i+' 0\n' for i in range(65)), 'fields')]
        for raw, reason in cases:
            with self.subTest(raw=raw), self.assertRaisesRegex(aggregate.AggregateCounterError, reason):
                aggregate._numbers(raw, 'aggregate/cpu.stat')
        self.assertEqual(aggregate._numbers('usage_usec '+str(2**64-1)+'\n',
            'aggregate/cpu.stat')['usage_usec'], 2**64-1)

    def test_original_bounded_input_and_qualified_filename_are_immutable_diagnostics(self):
        for filename in ('aggregate/cpu.stat', 'aggregate/cgroup.events',
                         'aggregate/cgroup.stat', 'aggregate/memory.events', 'unit/cgroup.stat'):
            raw = 'wrong.key 0\n'
            with self.subTest(filename=filename), self.assertRaises(aggregate.AggregateCounterError) as caught:
                aggregate._numbers(raw, filename)
            error = caught.exception
            diagnostic = error.counter_diagnostic
            self.assertEqual(str(error), 'aggregate-counter-format')
            self.assertEqual(diagnostic, (filename, raw, 'aggregate-counter-format'))
            self.assertEqual(diagnostic._fields, ('filename', 'raw', 'reason'))
            with self.assertRaises(AttributeError): diagnostic.raw = 'replacement'
            with self.assertRaises(TypeError): diagnostic[1] = 'replacement'
            with self.assertRaises(AttributeError): error.counter_diagnostic = ()

    def test_scalar_failure_retains_exact_input_and_bound_rejects_before_retention(self):
        with self.assertRaises(aggregate.AggregateCounterError) as caught:
            aggregate._scalar('max\n', 'aggregate/memory.current')
        self.assertEqual(caught.exception.counter_diagnostic,
            ('aggregate/memory.current', 'max\n', 'aggregate-counter-scalar'))
        with self.assertRaisesRegex(aggregate.kernel.KernelBudgetError, 'aggregate-counter-bound'):
            aggregate.AggregateCounterError('format', 'aggregate/cpu.stat', 'x'*65537)
        with self.assertRaisesRegex(aggregate.kernel.KernelBudgetError, 'aggregate-counter-bound'):
            aggregate._numbers('x'*65537, 'aggregate/cpu.stat')
        with self.assertRaisesRegex(aggregate.kernel.KernelBudgetError, 'aggregate-counter-filename'):
            aggregate._numbers('bad.key 0\n', 'unbound/path')

    def test_first_bad_raw_is_not_replaced_by_later_file_contents_or_extra_read(self):
        fields = dict(zip(aggregate._RAW, ('0\n', '0\n', '0\n', 'oom 0\n',
            'bad.key 0\n', 'populated 0\n', 'nr_descendants 0\nnr_dying_descendants 0\n',
            '0\n', '')))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, value in fields.items(): (root/name).write_text(value)
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            self.addCleanup(os.close, fd)
            original = aggregate.kernel._text
            reads = []
            def read(descriptor, filename):
                reads.append(filename)
                value = original(descriptor, filename)
                if filename == 'cpu.stat': (root/filename).write_text('usage_usec 0\n')
                return value
            with patch.object(aggregate.kernel, '_text', side_effect=read), \
                    self.assertRaises(aggregate.AggregateCounterError) as caught:
                aggregate._raw(fd)
            self.assertEqual(reads, list(aggregate._RAW))
            self.assertEqual(caught.exception.counter_diagnostic,
                ('aggregate/cpu.stat', 'bad.key 0\n', 'aggregate-counter-format'))
            self.assertEqual((root/'cpu.stat').read_text(), 'usage_usec 0\n')

    def test_existing_cleanup_fault_retains_owner_and_original_error_context(self):
        # Exercise the original initializer's exception path without a native
        # build, real group or public capability admission. The fake opener
        # raises an actual parser error, then existing cleanup itself fails.
        cap = object.__new__(aggregate._AggregateOperation)
        native = SimpleNamespace(fd=0, operation=None)
        owner = object()
        cap._open = lambda *args: aggregate._numbers('bad.key 0\n', 'aggregate/cpu.stat')
        def close(original_owner):
            self.assertIs(original_owner, owner)
            raise RuntimeError('synthetic-close-fault')
        cap._close_locked = close
        def read(path, *args, **kwargs):
            if str(path) == '/proc/self/cgroup':
                return '0::/user.slice/fixture.service/controller\n'
            return 'synthetic-boot\n'
        with patch.object(Path, 'read_text', read), patch.object(aggregate, '_source', return_value='source'), \
                patch.dict(os.environ, {'INVOCATION_ID': '1'*32}), \
                patch.object(aggregate.os, 'open', side_effect=AssertionError('no group FD')), \
                self.assertRaises(aggregate.kernel.KernelOwnedCloseRequired) as caught:
            cap._initialize_locked(native, 'fixture.service', '1'*32,
                '/sys/fs/cgroup/user.slice/fixture.service/aggregate-'+'a'*32,
                8*1024**3, dict(memory_bytes=128*1024**2, cpu_quota_us=100000, tasks=16), owner)
        self.assertIs(caught.exception.capability, cap)
        self.assertIs(native.operation, cap)
        self.assertIs(cap.owner, owner)
        cleanup = caught.exception.__context__
        self.assertIsInstance(cleanup, RuntimeError)
        self.assertIsInstance(cleanup.__context__, aggregate.AggregateCounterError)
        self.assertEqual(cleanup.__context__.counter_diagnostic,
            ('aggregate/cpu.stat', 'bad.key 0\n', 'aggregate-counter-format'))


if __name__ == '__main__': unittest.main()
