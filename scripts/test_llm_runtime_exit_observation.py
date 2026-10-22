"""Adversarial exit observer controls; fixtures never establish model efficacy."""
import contextlib
import copy
import errno
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import llm_runtime_exit_observation as exits
import llm_runtime_pilot as runtime


class ExitObservationTests(unittest.TestCase):
    def status(self, pid=10001, state='Z'):
        return (f'Pid:\t{pid}\nPPid:\t10000\nTgid:\t10001\nNSpid:\t{pid} {pid-9500}\n'
                f'NStgid:\t10001 501\nState:\t{state} (fixture)\nThreads:\t2\n')

    def stat(self, pid=10001, state='Z', flags=4, start=12345, vsize=0, rss=0):
        values = [state, '10000', '1', '1', '0', '-1', str(flags)] + ['0'] * 43
        values[19:22] = [str(start), str(vsize), str(rss)]
        return f'{pid} (explicit fixture ) comm) ' + ' '.join(values) + '\n'

    @contextlib.contextmanager
    def proc(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'task').mkdir()
            (root/'status').write_text(self.status())
            for pid, state in [(10001, 'Z'), (10002, 'R')]:
                task = root/'task'/str(pid); task.mkdir()
                (task/'status').write_text(self.status(pid, state))
                (task/'stat').write_text(self.stat(pid, state))
            held = os.open(root/'status', os.O_RDONLY)
            token = object()
            def opened(_):
                return os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            with patch.object(exits, '_pidfd_identity', return_value=(10001, 10000, (10001, 501))), \
                    patch.object(exits, '_open_group', side_effect=opened):
                try:
                    yield root, held, token
                finally:
                    try: os.close(held)
                    except OSError: pass  # Supervisor may already have closed its own fd.

    def observation(self, held, token):
        return exits.ExitOnlyObservation(501, held, token, exits._status(self.status()), time.monotonic_ns())

    def test_held_task_fd_double_frontier_and_borrowed_owner(self):
        with self.proc() as (_, held, token):
            observed = self.observation(held, token)
            try:
                self.assertTrue(observed.belongs_to(501, held, token))
                self.assertFalse(observed.belongs_to(501, held, object()))
                self.assertFalse(observed.belongs_to(502, held, token))
                self.assertEqual(observed.record['tasks'], ['10001', '10002'])
                self.assertGreaterEqual(observed.record['classification_completed_ns'], observed.sample_started_ns)
                self.assertNotIn('rss_bytes', observed.record)
                self.assertEqual(observed.recheck()['frontier_before']['10002']['flags'], 4)
            finally: observed.close()
            os.fstat(held)  # Borrowed pidfd is never the observer's to close.
            self.assertFalse(observed.belongs_to(501, held, token))

    def test_live_kthread_or_observable_memory_never_classifies(self):
        for changes in [dict(flags=0), dict(flags=4 | exits.PF_KTHREAD), dict(vsize=4096), dict(rss=1)]:
            with self.subTest(changes=changes), self.proc() as (root, held, token):
                (root/'task/10002/stat').write_text(self.stat(10002, 'R', **changes))
                with self.assertRaises(exits.ExitObservationError): self.observation(held, token)
        with self.proc() as (root, held, token):
            path = root/'task/10002/status'; path.write_text(path.read_text()+'VmRSS:\t0 kB\n')
            with self.assertRaises(exits.ExitObservationError): self.observation(held, token)

    def test_malformed_duplicate_truncated_and_illegal_numbers_refuse(self):
        values = [self.stat(10002, 'R').rstrip(), self.stat(10002, 'R').replace(' 4 ', ' -4 ', 1),
                  self.stat(10002, 'R', start=0), self.stat(10002, 'R', start=-1),
                  self.stat(10002, 'RS'), self.stat(10002, 'R', flags=1 << 32),
                  self.stat(10002, 'R')+'0\n']
        for raw in values:
            with self.subTest(raw=raw[:90]), self.proc() as (root, held, token):
                (root/'task/10002/stat').write_text(raw)
                with self.assertRaises((ValueError, KeyError)): self.observation(held, token)
        for raw in [self.status(10002, 'R')+'Pid: 10002\n', self.status(10002, 'R').rstrip(),
                    self.status(10002, 'R').replace('Threads:\t2', 'Threads:\t+2'),
                    self.status(10002, 'R')+'malformed\n']:
            with self.subTest(raw=raw[:90]), self.proc() as (root, held, token):
                (root/'task/10002/status').write_text(raw)
                with self.assertRaises((ValueError, KeyError)): self.observation(held, token)

    def test_task_count_identity_and_starttime_changes_refuse(self):
        for raw in [self.status(10002, 'R').replace('Threads:\t2', 'Threads:\t3'),
                    self.status(10002, 'R').replace('Tgid:\t10001', 'Tgid:\t10003'),
                    self.status(10002, 'R').replace('NStgid:\t10001 501', 'NStgid:\t10001 502')]:
            with self.subTest(raw=raw), self.proc() as (root, held, token):
                (root/'task/10002/status').write_text(raw)
                with self.assertRaises(exits.ExitObservationError): self.observation(held, token)
        for change in ['starttime', 'taskset', 'non-exiting']:
            with self.subTest(change=change), self.proc() as (root, held, token):
                observed = self.observation(held, token)
                try:
                    if change == 'taskset': (root/'task/10003').mkdir()
                    else: (root/'task/10002/stat').write_text(self.stat(10002, 'R',
                        start=999 if change == 'starttime' else 12345, flags=0 if change == 'non-exiting' else 4))
                    with self.assertRaises(exits.ExitObservationError): observed.recheck()
                finally: observed.close()
        with self.proc() as (root, held, token):
            (root/'task/10001').rename(root/'task/10003')
            with self.assertRaisesRegex(exits.ExitObservationError, 'leader-not-in-task-set'):
                self.observation(held, token)

    def test_held_directory_prevents_numeric_tid_aba_and_fd_reuse(self):
        for change in ['numeric-aba', 'descriptor-reuse']:
            with self.subTest(change=change), self.proc() as (root, held, token):
                observed = self.observation(held, token)
                try:
                    if change == 'numeric-aba':
                        old = root/'task/10002'; (old/'status').unlink(); (old/'stat').unlink(); old.rmdir(); old.mkdir()
                        (old/'status').write_text(self.status(10002, 'R')); (old/'stat').write_text(self.stat(10002, 'R'))
                    else:
                        new = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                        try: os.dup2(new, observed.task_fds['10002'])
                        finally: os.close(new)
                    with self.assertRaises((OSError, ValueError)): observed.recheck()
                finally: observed.close()

    def test_profile_optin_schema_and_all_source_hashes_are_frozen(self):
        old = runtime.experiment_plan({'fixture': True})
        self.assertEqual(old['schema'], 'llm-runtime-public-pilot-plan-v1')
        self.assertNotIn('exit_observation', old)
        plan = runtime.experiment_plan({'fixture': True}, exit_observation=exits.PROFILE)
        self.assertEqual(runtime.validate_plan(plan)['schema'], 'llm-runtime-public-pilot-plan-v2')
        for field, value in [('profile','strict-v1'), ('maximum_drain_ns',100_000_001),
                             ('observer_source_sha256','0'*64), ('diagnostic_source_sha256','0'*64)]:
            changed = copy.deepcopy(plan); changed['exit_observation'][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'OBSERVER_BINDING'):
                runtime.validate_plan(changed)
        changed = copy.deepcopy(plan); changed['schema'] = old['schema']
        with self.assertRaisesRegex(ValueError, 'OBSERVER_PROFILE'): runtime.validate_plan(changed)
        changed = copy.deepcopy(plan); changed['exit_observation']['extra'] = True
        with self.assertRaisesRegex(ValueError, 'OBSERVER_BINDING'): runtime.validate_plan(changed)

    def test_borrowed_pidfd_is_neither_reopened_nor_closed_and_plain_call_is_strict(self):
        from test_llm_runtime_rss_owner import RssIdentityTests
        owner = runtime._RSS_OWNER_CONTEXT.set((501, 17, object()))
        try:
            with RssIdentityTests().proc() as (_, opened, closed):
                self.assertEqual(runtime.current_rss(501), 8192*1024)
                opened.assert_not_called(); closed.assert_not_called()
        finally: runtime._RSS_OWNER_CONTEXT.reset(owner)
        status = self.status()
        with RssIdentityTests().proc(overrides={'/proc/10001/status':status}), \
                patch.object(exits, 'ExitOnlyObservation', side_effect=AssertionError('no owner authority')) as capture:
            self.assertIsNone(runtime.current_rss(501))
            capture.assert_not_called()

    def test_same_sample_capture_cannot_be_sourced_from_later_diagnostic(self):
        from test_llm_runtime_rss_owner import RssIdentityTests
        with self.proc() as (_, held, token):
            context = runtime._RSS_OWNER_CONTEXT.set((501, held, token))
            candidate = runtime._RSS_EXIT_OBSERVATION.set(None)
            details = {}; trace = runtime._RSS_READ_TRACE.set(details)
            try:
                status = self.status()
                with RssIdentityTests().proc(overrides={'/proc/10001/status':status}) as (reads, opened, closed):
                    # Its proc fixture expects fd 17; only fdinfo path changes.
                    original = Path.open
                    def mapped(path, *args, **kwargs):
                        if str(path) == f'/proc/self/fdinfo/{held}': path = Path('/proc/self/fdinfo/17')
                        return original(path, *args, **kwargs)
                    with patch.object(Path, 'open', mapped):
                        self.assertIsNone(runtime.current_rss(501))
                    observed = runtime._RSS_EXIT_OBSERVATION.get()
                    self.assertIs(type(observed), exits.ExitOnlyObservation)
                    self.assertEqual(details['reason'], 'vmrss-missing')
                    self.assertGreaterEqual(observed.record['classification_completed_ns'], observed.sample_started_ns)
                    opened.assert_not_called(); closed.assert_not_called()
                    observed.close()
            finally:
                runtime._RSS_OWNER_CONTEXT.reset(context); runtime._RSS_EXIT_OBSERVATION.reset(candidate)
                runtime._RSS_READ_TRACE.reset(trace)

    def test_v2_terminal_wait4_caps_invalid_and_unknown_remain_authoritative(self):
        from test_llm_runtime_rss_owner import RssSupervisionTests
        helper = RssSupervisionTests()
        for mode, outcome, reason in [('valid','success',None),
                ('overcap','failed','rss-budget-exceeded'),
                ('invalid','failed','rss-exit-cleanup-observation-unavailable'),
                ('unknown','failed','rss-exit-cleanup-observation-unavailable'),
                ('late-classification','failed','rss-exit-cleanup-observation-unavailable'),
                ('owner-loss','failed','rss-exit-cleanup-observation-unavailable'),
                ('closed-candidate','failed','rss-exit-cleanup-observation-unavailable'),
                ('ordinary-gap','failed','rss-observation-unavailable')]:
            with self.subTest(mode=mode), self.proc() as (root, held, _):
                child = helper.child_control(); child.termination_fd = held
                usage = helper.usage(peak=256*1024 if mode == 'overcap' else 0 if mode == 'invalid' else 8192)
                waits = [(0,0,None)]
                if mode == 'ordinary-gap': waits += [(0,0,None)]
                if mode == 'unknown': waits += [OSError(errno.EIO, 'wait4 unknown')]
                waits += [(501,0,usage)]
                def observe(pid):
                    if mode != 'ordinary-gap':
                        _, descriptor, owner = runtime._RSS_OWNER_CONTEXT.get()
                        observed = self.observation(descriptor, owner)
                        if mode == 'late-classification':
                            observed.sample_started_ns -= exits.MAX_DRAIN_NS+1
                        if mode == 'owner-loss': observed.owner_token = object()
                        if mode == 'closed-candidate': observed.close()
                        runtime._RSS_EXIT_OBSERVATION.set(observed)
                    return None
                with patch.object(runtime, '_Wait4Child', return_value=child), \
                        patch.object(runtime.os, 'wait4', side_effect=waits), \
                        patch.object(runtime, 'current_rss', side_effect=observe), \
                        patch.object(runtime.signal, 'pidfd_send_signal'):
                    result = runtime.supervise(['explicit owned-child wait4 control'], root/'result',
                        helper.BUDGET, exit_observation=runtime.exit_observation_profile())
                self.assertEqual(result['outcome'], outcome)
                self.assertEqual(result['stop_reason'], reason)
                self.assertEqual(result['exit_code'], 0)
                self.assertEqual(result['sampled_peak_rss_bytes'], 0)
                self.assertTrue(result['waited_child_reaped'])
                if mode != 'ordinary-gap':
                    self.assertEqual(result['exit_cleanup_observation']['outcome'],
                                     'terminal-wait4' if mode in ['valid','overcap'] else 'failed')

    def test_bounded_drain_deadline_unknown_change_and_invalid_wait4_fail(self):
        for mode in ['deadline', 'wall', 'unknown', 'task-change', 'invalid-receipt', 'owner']:
            with self.subTest(mode=mode), self.proc() as (root, held, token):
                observed = self.observation(held, token)
                child = SimpleNamespace(pid=501, termination_fd=held, observation_error=None,
                    waited_peak_rss_bytes=8192, waited_cpu_ns=1500)
                child.reap = lambda: 'live'
                start = time.monotonic_ns()
                if mode == 'deadline': observed.sample_started_ns -= exits.MAX_DRAIN_NS+1
                if mode == 'wall': start -= 3*10**9
                if mode == 'unknown': child.reap = lambda: 'unknown'
                if mode == 'task-change': (root/'task/10003').mkdir()
                if mode == 'invalid-receipt':
                    child.reap = lambda: 'terminal'; child.waited_cpu_ns = None
                try:
                    reason, record = runtime._drain_exit_cleanup(child, observed,
                        object() if mode == 'owner' else token, start, dict(wall_seconds=2))
                    self.assertEqual(reason, 'rss-exit-cleanup-observation-unavailable')
                    self.assertEqual(record['outcome'], 'failed')
                finally: observed.close()

    def test_capture_frontier_changes_task_bound_and_original_owner_reuse_refuse(self):
        for mode in ['frontier-flags', 'frontier-start', 'task-bound', 'pidfd-identity', 'pidfd-reuse']:
            with self.subTest(mode=mode), self.proc() as (root, held, token):
                if mode == 'task-bound':
                    for pid in range(10003,10035): (root/'task'/str(pid)).mkdir()
                    with self.assertRaises(exits.ExitObservationError): self.observation(held, token)
                    continue
                if mode.startswith('frontier-'):
                    original = exits.ExitOnlyObservation._frontier
                    calls = 0
                    def changed(value):
                        nonlocal calls
                        result = original(value); calls += 1
                        if calls == 1:
                            (root/'task/10002/stat').write_text(self.stat(10002, 'R',
                                flags=0 if mode == 'frontier-flags' else 4,
                                start=999 if mode == 'frontier-start' else 12345))
                        return result
                    with patch.object(exits.ExitOnlyObservation, '_frontier', changed), \
                            self.assertRaises(exits.ExitObservationError): self.observation(held, token)
                    continue
                observed = self.observation(held, token)
                try:
                    if mode == 'pidfd-reuse':
                        descriptor = os.open(root/'task/10002/stat', os.O_RDONLY)
                        try: os.dup2(descriptor, held)
                        finally: os.close(descriptor)
                        self.assertFalse(observed.belongs_to(501, held, token))
                        with self.assertRaises(exits.ExitObservationError): observed.recheck()
                    else:
                        with patch.object(exits, '_pidfd_identity', return_value=(10003,10000,(10003,503))), \
                                self.assertRaises(exits.ExitObservationError): observed.recheck()
                finally: observed.close()

    def test_late_wait4_does_not_extend_one_hundred_millisecond_limit(self):
        with self.proc() as (_, held, token):
            observed = self.observation(held, token)
            start = observed.sample_started_ns
            values = iter([start+1, start+exits.MAX_DRAIN_NS+1])
            def clock(): return next(values, start+exits.MAX_DRAIN_NS+1)
            child = SimpleNamespace(pid=501, termination_fd=held, observation_error=None,
                waited_peak_rss_bytes=8192, waited_cpu_ns=1500, reap=lambda:'terminal')
            try:
                with patch.object(runtime.time, 'monotonic_ns', side_effect=clock):
                    reason, record = runtime._drain_exit_cleanup(child, observed, token, start,
                                                                 dict(wall_seconds=2))
                self.assertEqual(reason, 'rss-exit-cleanup-observation-unavailable')
                self.assertEqual(record['outcome'], 'failed')
            finally: observed.close()

    def test_v2_plain_none_or_trace_dict_cannot_authorize_success(self):
        for forged in [None, {'profile': exits.PROFILE, 'outcome': 'terminal-wait4'}]:
            with self.subTest(forged=forged), tempfile.TemporaryDirectory() as temporary:
                def missing(pid):
                    runtime._RSS_EXIT_OBSERVATION.set(forged)
                    return None
                with patch.object(runtime, 'current_rss', side_effect=missing):
                    result = runtime.supervise([sys.executable,'-c','import time;time.sleep(5)'],
                        Path(temporary)/'refuse', dict(wall_seconds=2,rss_bytes=128*1024**2),
                        exit_observation=runtime.exit_observation_profile())
                self.assertEqual(result['outcome'], 'failed')
                self.assertEqual(result['stop_reason'], 'rss-observation-unavailable')

    def test_real_zombie_leader_with_live_userspace_thread_is_refused(self):
        program = ('import ctypes,threading,time;'
            'threading.Thread(target=lambda:time.sleep(5),daemon=True).start();'
            'ctypes.CDLL(None).pthread_exit(None)')
        with tempfile.TemporaryDirectory() as temporary:
            result = runtime.supervise([sys.executable,'-c',program], Path(temporary)/'live-thread',
                dict(wall_seconds=2,rss_bytes=128*1024**2), exit_observation=runtime.exit_observation_profile())
        self.assertEqual(result['outcome'], 'failed')
        self.assertEqual(result['stop_reason'], 'rss-observation-unavailable')
        self.assertEqual(result['rss_gap_diagnostic']['leader_state'], 'Z')


if __name__ == '__main__': unittest.main()
