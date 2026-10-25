"""Modeled held-directory/clock controls, not native cgroup qualification."""
import time
import unittest
from unittest.mock import Mock, patch

import llm_runtime_host_aggregate as aggregate
import llm_runtime_host_scope as host
import llm_runtime_kernel_owned as kernel
import test_llm_runtime_host_retirement as previous


class HostUReadbackTests(unittest.TestCase):
    fixture = previous.HostRetirementTests.fixture
    prepared = previous.HostRetirementTests.prepared
    binding = previous.HostRetirementTests.binding
    launch = previous.HostRetirementTests.launch
    terminal = previous.HostRetirementTests.terminal

    def completed(self):
        launch, op, cap, paths, child = self.terminal()
        def activate(parent, a, c, original, identities, deadline, out):
            for name, slot in [('aggregate', a), ('controller', c)]:
                for file in paths[name].iterdir(): file.unlink()
                paths[name].rmdir()
                op.native.release_owned(slot)
            op.native.close_handoff(original, 2)
            for role, count in [('scope', 3), ('host', 2), ('observer', 0), ('operation', 0)]:
                (paths[role]/'cgroup.stat').write_text('nr_descendants '+str(count)+
                    '\nnr_dying_descendants 0\nnr_subsys_cpu 1\nnr_dying_subsys_cpu 0\n')
            out[0]=7; out[17]=1; out[19]=1; out[20]=31; out[21]=1; out[23]=5
            return 0
        op.native.activate_retirement = Mock(side_effect=activate)
        self.assertTrue(op._retire_children()['child_unlink_and_close_proven'])
        return launch, op, cap, paths

    def zero(self, paths):
        (paths['operation']/'memory.current').write_text('0\n')
        (paths['operation']/'cgroup.stat').write_text('nr_descendants 0\n'
            'nr_dying_descendants 0\nnr_subsys_cpu 1\nnr_subsys_memory 1\n'
            'nr_dying_subsys_cpu 0\nnr_dying_subsys_memory 0\n')

    def retained(self, launch, op, cap, saved):
        self.assertTrue(op.failed)
        self.assertIs(host._retained_aggregate_owner(), cap)
        self.assertEqual(tuple(tuple(slot) for slot, _ in cap._fds), saved)
        self.assertEqual(cap._leaf_phase, 'UNKNOWN_RETAINED')
        self.assertTrue(launch._u_readback.consumed)
        first = op._first_error
        with self.assertRaisesRegex(ValueError, 'single-attempt'): op._read_u_terminal()
        self.assertIs(op._first_error, first)

    def test_predeclared_private_slot_and_no_caller_boolean_or_deadline(self):
        launch, op, cap, paths = self.launch()
        state = launch._u_readback
        self.assertIs(state.launch, launch)
        self.assertIs(state.group, cap._groups['operation'])
        self.assertEqual((state.deadline_ns, state.consumed, state.samples, state.last),
            (int(op.deadline*10**9), False, 0, None))
        for value in (True, {}, 8):
            with self.assertRaises(TypeError): op._read_u_terminal(value)
        self.assertFalse(state.consumed)
        with self.assertRaises(ValueError): op._read_u_terminal()
        self.assertTrue(state.consumed)
        self.assertIs(host._retained_aggregate_owner(), cap)

    def test_positive_current_drains_two_full_zero_reads_preserve_history_and_self_subsystems(self):
        launch, op, cap, paths = self.completed()
        before = op._meters['operation']
        verify = launch._retirement_status_locked
        with (patch.object(aggregate.time, 'sleep', side_effect=lambda _:self.zero(paths)) as sleep,
              patch.object(launch, '_retirement_status_locked', wraps=verify) as status):
            result = op._read_u_terminal()
        self.assertEqual((status.call_count, sleep.call_count, result['samples']), (3, 1, 3))
        self.assertTrue(result['raw_u_zero_observed'])
        for key in ('whole_u_terminal', 'funded_whole_u', 'resource_return_proven', 'authorization'):
            self.assertIs(result[key], False)
        self.assertEqual((result['reservation'], result['outer_reconciliation']), ('RETAINED', 'UNKNOWN'))
        self.assertIn('nr_subsys_memory 1\n', result['counters']['cgroup.stat'])
        self.assertEqual(op._meters['operation'], before)
        self.assertGreater(before[0], 0)
        self.assertIs(host._retained_aggregate_owner(), cap)
        with self.assertRaisesRegex(ValueError, 'single-attempt'): op._read_u_terminal()

    def test_each_dying_descendant_counter_blocks_even_with_zero_memory(self):
        for key in ('nr_dying_descendants', 'nr_dying_subsys_cpu', 'nr_dying_subsys_memory'):
            with self.subTest(key=key):
                launch, op, cap, paths = self.completed()
                self.zero(paths)
                stat = paths['operation']/'cgroup.stat'
                stat.write_text(stat.read_text().replace(key+' 0\n', key+' 2\n'))
                with patch.object(aggregate.time, 'sleep', side_effect=lambda _:self.zero(paths)) as sleep:
                    result = op._read_u_terminal()
                self.assertEqual((sleep.call_count, result['samples']), (1, 3))

    def test_persistent_charge_hits_original_cutoff_and_never_reopens_attempt(self):
        launch, op, cap, paths = self.completed()
        saved = tuple(tuple(slot) for slot, _ in cap._fds)
        now = [launch.deadline_ns-15_000_000]
        def advance(seconds): now[0] += round(seconds*10**9)
        with (patch.object(aggregate.time, 'monotonic_ns', side_effect=lambda:now[0]),
              patch.object(aggregate.time, 'sleep', side_effect=advance) as sleep):
            with self.assertRaisesRegex(ValueError, 'original-cutoff'): op._read_u_terminal()
        self.assertEqual(sleep.call_count, 2)
        self.assertEqual(now[0], launch.deadline_ns)
        self.retained(launch, op, cap, saved)

    def test_sample_bound_is_independent_of_a_clock_that_does_not_advance(self):
        launch, op, cap, paths = self.completed()
        now = time.monotonic_ns()
        with (patch.object(aggregate.time, 'monotonic_ns', return_value=now),
              patch.object(aggregate.time, 'sleep') as sleep):
            with self.assertRaisesRegex(ValueError, 'sample-bound-retained'): op._read_u_terminal()
        self.assertEqual((launch._u_readback.samples, sleep.call_count), (801, 801))
        self.assertTrue(op.failed)

    def test_malformed_or_missing_descendant_fields_refuse_without_wait(self):
        for raw in ('nr_descendants 0\n', 'nr_descendants 0\nnr_dying_descendants bad\n'):
            with self.subTest(raw=raw):
                launch, op, cap, paths = self.completed()
                self.zero(paths)
                (paths['operation']/'cgroup.stat').write_text(raw)
                with patch.object(aggregate.time, 'sleep') as sleep:
                    with self.assertRaises(ValueError): op._read_u_terminal()
                sleep.assert_not_called()
                self.assertTrue(op.failed)

    def test_existing_swap_population_descendant_and_event_assertions_stay_immediate(self):
        mutations = [('memory.swap.current', '1\n'), ('pids.current', '1\n'),
            ('cgroup.procs', '123\n'), ('cgroup.events', 'populated 1\nfrozen 0\n'),
            ('cgroup.stat', 'nr_descendants 1\nnr_dying_descendants 0\n'),
            ('memory.events', 'low 0\nhigh 0\nmax 1\noom 0\noom_kill 0\n')]
        for key, value in mutations:
            with self.subTest(key=key):
                launch, op, cap, paths = self.completed()
                self.zero(paths)
                (paths['operation']/key).write_text(value)
                with patch.object(aggregate.time, 'sleep') as sleep:
                    with self.assertRaises(ValueError): op._read_u_terminal()
                sleep.assert_not_called()
                self.assertTrue(op.failed)

    def test_identity_source_limit_and_history_drift_during_drain_refuse(self):
        for mode in ('identity', 'held-U-tuple', 'source', 'limit', 'peak', 'cpu'):
            with self.subTest(mode=mode):
                launch, op, cap, paths = self.completed()
                saved = tuple(tuple(slot) for slot, _ in cap._fds)
                def drift(_):
                    self.zero(paths)
                    if mode=='identity':
                        paths['operation'].rename(paths['operation'].with_name('replaced-U'))
                        paths['operation'].mkdir()
                    elif mode=='held-U-tuple': cap._groups['operation'] = tuple(list(cap._groups['operation']))
                    elif mode=='source': launch.source = '0'*64
                    elif mode=='limit': (paths['operation']/'memory.max').write_text('max\n')
                    elif mode=='peak': (paths['operation']/'memory.peak').write_text('0\n')
                    else: op._meters['operation'] = (op._meters['operation'][0], 2**64-1)
                with patch.object(aggregate.time, 'sleep', side_effect=drift) as sleep:
                    with self.assertRaises(ValueError): op._read_u_terminal()
                self.assertEqual(sleep.call_count, 1)
                self.retained(launch, op, cap, saved)

    def test_a_positive_read_between_zeros_resets_the_consecutive_observation(self):
        launch, op, cap, paths = self.completed()
        self.zero(paths)
        verify = launch._retirement_status_locked
        calls = []
        def observe():
            calls.append(1)
            if len(calls)==2: (paths['operation']/'memory.current').write_text('1\n')
            elif len(calls)==3: self.zero(paths)
            return verify()
        with (patch.object(launch, '_retirement_status_locked', side_effect=observe),
              patch.object(aggregate.time, 'sleep') as sleep):
            result = op._read_u_terminal()
        self.assertEqual((len(calls), sleep.call_count, result['samples']), (4, 1, 4))

    def test_second_full_zero_read_late_is_not_accepted(self):
        launch, op, cap, paths = self.completed()
        self.zero(paths)
        saved = tuple(tuple(slot) for slot, _ in cap._fds)
        now = [time.monotonic_ns()]
        verify = launch._retirement_status_locked
        calls = []
        def observe():
            result = verify()
            calls.append(1)
            if len(calls)==2: now[0] = launch.deadline_ns
            return result
        with (patch.object(aggregate.time, 'monotonic_ns', side_effect=lambda:now[0]),
              patch.object(launch, '_retirement_status_locked', side_effect=observe)):
            with self.assertRaisesRegex(ValueError, 'original-cutoff'): op._read_u_terminal()
        self.assertEqual((len(calls), launch._u_readback.samples), (2, 1))
        self.retained(launch, op, cap, saved)

    def test_cancel_between_complete_read_and_acceptance_preserves_first_error(self):
        launch, op, cap, paths = self.completed()
        self.zero(paths)
        saved = tuple(tuple(slot) for slot, _ in cap._fds)
        first = MemoryError('original pending cancel')
        verify = launch._retirement_status_locked
        def cancel():
            result = verify()
            op._refuse(first)
            return result
        with patch.object(launch, '_retirement_status_locked', side_effect=cancel):
            with self.assertRaisesRegex(ValueError, 'retirement-not-proven'): op._read_u_terminal()
        self.assertIs(op._first_error, first)
        self.retained(launch, op, cap, saved)

    def test_deadline_change_or_unknown_native_state_cannot_renew_readback(self):
        for mode in ('deadline', 'unknown'):
            with self.subTest(mode=mode):
                launch, op, cap, paths = self.completed()
                self.zero(paths)
                if mode=='deadline': op.deadline += 8
                else: launch._retirement[23] = 0x80000005
                with self.assertRaises(ValueError): op._read_u_terminal()
                self.assertTrue(op.failed)
                self.assertIs(host._retained_aggregate_owner(), cap)

    def test_pending_observation_exception_consumes_slot_without_close_or_retry(self):
        launch, op, cap, paths = self.completed()
        saved = tuple(tuple(slot) for slot, _ in cap._fds)
        first = MemoryError('pending raw observation')
        with patch.object(launch, '_retirement_status_locked', side_effect=first) as read:
            with self.assertRaises(MemoryError): op._read_u_terminal()
        self.assertEqual(read.call_count, 1)
        self.assertIs(op._first_error, first)
        self.retained(launch, op, cap, saved)


if __name__ == '__main__': unittest.main(verbosity=2)
