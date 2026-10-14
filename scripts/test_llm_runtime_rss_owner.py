"""Owned-process RSS controls; fixtures are not native performance evidence."""
import contextlib
import errno
import io
import json
from pathlib import Path
import signal
import select
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import llm_runtime_pilot as runtime


class RssIdentityTests(unittest.TestCase):
    @contextlib.contextmanager
    def proc(self, nested=True, overrides=None, second_identity=None):
        parent = 10000 if nested else 500
        child = 10001 if nested else 501
        parent_ns = f'{parent} 500' if nested else '500'
        child_ns = f'{child} 501' if nested else '501'
        identity = f'Pid:\t{child}\nNSpid:\t{child_ns}\n'
        values = {
            '/proc/self/status': f'Pid:\t{parent}\nNSpid:\t{parent_ns}\nVmRSS:\t4096 kB\n',
            '/proc/self/fdinfo/17': identity,
            f'/proc/{child}/status': f'Pid:\t{child}\nPPid:\t{parent}\nNSpid:\t{child_ns}\nVmRSS:\t8192 kB\n',
        }
        values.update(overrides or {})
        reads = []

        def open_proc(path, *args, **kwargs):
            name = str(path)
            reads.append(name)
            if second_identity is not None and name == '/proc/self/fdinfo/17' and reads.count(name) == 2:
                return io.StringIO(second_identity)
            value = values[name]
            if isinstance(value, Exception):
                raise value
            return io.StringIO(value)

        with patch.object(runtime.os, 'getpid', return_value=500), \
                patch.object(runtime.os, 'pidfd_open', return_value=17, create=True) as opened, \
                patch.object(runtime.os, 'close') as closed, \
                patch.object(Path, 'open', open_proc):
            yield reads, opened, closed

    def test_supported_normal_and_nested_pid_views_bind_owned_child(self):
        for nested in (False, True):
            with self.subTest(nested=nested), self.proc(nested) as (_, opened, closed):
                self.assertEqual(runtime.current_rss(501), 8192 * 1024)
                opened.assert_called_once_with(501, 0)
                closed.assert_called_once_with(17)

    def test_wrong_parent_pid_and_namespace_never_provide_rss(self):
        for status in (
                'Pid: 10001\nPPid: 9999\nNSpid: 10001 501\nVmRSS: 8192 kB\n',
                'Pid: 10002\nPPid: 10000\nNSpid: 10001 501\nVmRSS: 8192 kB\n',
                'Pid: 10001\nPPid: 10000\nNSpid: 10001 502\nVmRSS: 8192 kB\n'):
            with self.subTest(status=status), self.proc(overrides={'/proc/10001/status': status}) as (_, _, closed):
                self.assertIsNone(runtime.current_rss(501))
                closed.assert_called_once_with(17)

    def test_wrong_pidfd_coordinate_never_reads_a_numeric_process_path(self):
        for identity in ('Pid: 10001\nNSpid: 10001 502\n', 'Pid: -1\nNSpid: -1\n',
                         'Pid: 10002\nNSpid: 10001 501\n'):
            with self.subTest(identity=identity), self.proc(overrides={'/proc/self/fdinfo/17': identity}) as (reads, _, closed):
                self.assertIsNone(runtime.current_rss(501))
                self.assertFalse(any(name.startswith('/proc/100') for name in reads))
                closed.assert_called_once_with(17)

    def test_changed_pidfd_identity_during_sample_refuses_rss(self):
        with self.proc(second_identity='Pid: -1\nNSpid: -1\n') as (_, _, closed):
            self.assertIsNone(runtime.current_rss(501))
            closed.assert_called_once_with(17)

    def test_missing_malformed_or_overbound_observations_fail_closed(self):
        for value in (FileNotFoundError('owned proc entry disappeared'), 'x' * 65537,
                      'Pid: 10001\nPid: 10001\nPPid: 10000\nNSpid: 10001 501\nVmRSS: 8192 kB\n',
                      'Pid: 10001\nPPid: 10000\nNSpid: 10001 501\n',
                      'Pid: 10001\nPPid: 10000\nNSpid: 10001 501\nVmRSS: -1 kB\n',
                      'Pid: 10001\nPPid: 10000\nNSpid: 10001 501\nVmRSS: 8 MB\n'):
            with self.subTest(value=str(value)[:80]), self.proc(overrides={'/proc/10001/status': value}) as (_, _, closed):
                self.assertIsNone(runtime.current_rss(501))
                closed.assert_called_once_with(17)

    def test_unsupported_pidfd_does_not_fall_back_to_numeric_local_pid(self):
        with self.proc() as (reads, opened, closed):
            opened.side_effect = OSError(errno.ENOSYS, 'pidfd unavailable')
            self.assertIsNone(runtime.current_rss(501))
            self.assertEqual(reads, ['/proc/self/status'])
            closed.assert_not_called()

    def test_parent_namespace_mismatch_never_opens_a_child(self):
        with self.proc(overrides={'/proc/self/status': 'Pid: 10000\nNSpid: 10000 999\n'}) as (_, opened, closed):
            self.assertIsNone(runtime.current_rss(501))
            opened.assert_not_called()
            closed.assert_not_called()


class RssSupervisionTests(unittest.TestCase):
    BUDGET = dict(wall_seconds=2, rss_bytes=128 * 1024**2)

    def assert_receipt(self, directory, result):
        self.assertEqual(json.loads((directory / 'supervisor.json').read_text()), result)
        self.assertEqual(result['budget'], self.BUDGET)
        self.assertEqual(result['sample_interval_ms'], 50)

    def test_persistent_none_terminates_and_reaps_actual_owned_child(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / 'none'
            with patch.object(runtime, 'current_rss', return_value=None) as observed:
                result = runtime.supervise([sys.executable, '-c', 'import time;time.sleep(5)'], directory, self.BUDGET)
            self.assertEqual(result['outcome'], 'failed')
            self.assertEqual(result['stop_reason'], 'rss-observation-unavailable')
            self.assertEqual(result['sampled_peak_rss_bytes'], 0)
            self.assertLess(result['exit_code'], 0)
            self.assertEqual(observed.call_count, 1)
            self.assert_receipt(directory, result)

    def test_mid_run_loss_retains_real_sample_but_never_success(self):
        original_observer = runtime.current_rss
        samples = []

        def observe(pid):
            value = original_observer(pid) if not samples else None
            samples.append(value)
            return value

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / 'loss'
            with patch.object(runtime, 'current_rss', side_effect=observe):
                result = runtime.supervise([sys.executable, '-c', 'import time;time.sleep(5)'], directory, self.BUDGET)
            self.assertGreater(samples[0], 0)
            self.assertEqual(samples[1:], [None])
            self.assertEqual(result['outcome'], 'failed')
            self.assertEqual(result['stop_reason'], 'rss-observation-unavailable')
            self.assertEqual(result['sampled_peak_rss_bytes'], samples[0])
            self.assertLess(result['exit_code'], 0)
            self.assert_receipt(directory, result)

    def child_control(self):
        child = object.__new__(runtime._Wait4Child)
        child.pid = 501
        child.returncode = None
        child.reaped = False
        child.reap_resolved = False
        child.no_waitable_child_observed = False
        child.owned_exit_observed = False
        child.cleanup_method = 'wait4'
        child.waited_peak_rss_bytes = None
        child.waited_cpu_ns = None
        child.observation_error = None
        child.termination_fd = 17
        return child

    def usage(self, peak=8192, user=0.01, system=0.005):
        return SimpleNamespace(ru_maxrss=peak, ru_utime=user, ru_stime=system)

    @contextlib.contextmanager
    def control(self, child, waits, samples=()):
        with patch.object(runtime, '_Wait4Child', return_value=child), \
                patch.object(runtime.os, 'wait4', side_effect=waits) as waited, \
                patch.object(runtime, 'current_rss', side_effect=samples) as observed, \
                patch.object(runtime.signal, 'pidfd_send_signal') as signalled, \
                patch.object(runtime.os, 'kill') as killed, \
                patch.object(runtime.os, 'waitpid', return_value=(0, 0)), \
                patch.object(runtime.select, 'select', return_value=([], [], [])), \
                patch.object(runtime.os, 'close') as closed, \
                patch.object(runtime.time, 'sleep'), \
                patch.object(runtime.resource, 'getrusage', side_effect=AssertionError('global rusage forbidden')), \
                patch.object(runtime.subprocess.Popen, 'poll', side_effect=AssertionError('Popen poll forbidden')), \
                patch.object(runtime.subprocess.Popen, 'wait', side_effect=AssertionError('Popen wait forbidden')), \
                patch.object(runtime.subprocess.Popen, 'send_signal', side_effect=AssertionError('Popen signal forbidden')), \
                patch.object(runtime.subprocess.Popen, 'kill', side_effect=AssertionError('Popen kill forbidden')):
            yield waited, observed, signalled, killed, closed

    def test_zero_exit_does_not_erase_missing_or_lost_live_observation(self):
        for samples in ([None], [4096, None]):
            child = self.child_control()
            waits = [(0, 0, None)] * (len(samples) + 1) + [(child.pid, 0, self.usage())]
            with self.subTest(samples=samples), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary) / 'zero-exit-live-loss'
                with self.control(child, waits, samples) as (waited, _, signalled, killed, closed):
                    result = runtime.supervise(['deterministic-owned-process-control'], directory, self.BUDGET)
                self.assertEqual(result['exit_code'], 0)
                self.assertEqual(result['outcome'], 'failed')
                self.assertEqual(result['stop_reason'], 'rss-observation-unavailable')
                self.assertEqual(result['sampled_peak_rss_bytes'], 4096 if len(samples) == 2 else 0)
                self.assertEqual(result['waited_child_peak_rss_bytes'], 8192 * 1024)
                self.assertTrue(result['waited_child_reaped'])
                self.assertTrue(all(call.args[0] == child.pid for call in waited.call_args_list))
                signalled.assert_called_once_with(17, signal.SIGTERM)
                killed.assert_not_called()
                closed.assert_called_once_with(17)
                self.assert_receipt(directory, result)

    def test_terminal_zero_sample_uses_exact_waited_peak_and_never_global_rusage(self):
        for peak, outcome, reason in ((8192, 'success', None), (256 * 1024, 'failed', 'rss-budget-exceeded')):
            child = self.child_control()
            with self.subTest(peak=peak), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary) / 'already-exited'
                with self.control(child, [(child.pid, 0, self.usage(peak))]) as (waited, observed, signalled, killed, _):
                    result = runtime.supervise(['deterministic-already-exited-child-control'], directory, self.BUDGET)
                self.assertEqual(result['exit_code'], 0)
                self.assertEqual(result['outcome'], outcome)
                self.assertEqual(result['stop_reason'], reason)
                self.assertEqual(result['sampled_peak_rss_bytes'], 0)
                self.assertEqual(result['waited_child_peak_rss_bytes'], peak * 1024)
                self.assertEqual(result['child_cpu_ns'], 15_000_000)
                self.assertTrue(result['waited_child_reaped'])
                waited.assert_called_once_with(child.pid, runtime.os.WNOHANG)
                observed.assert_not_called()
                signalled.assert_not_called()
                killed.assert_not_called()
                self.assert_receipt(directory, result)

    def test_none_at_exact_exit_race_uses_only_terminal_owned_measurement(self):
        child = self.child_control()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / 'exit-race'
            with self.control(child, [(0, 0, None), (child.pid, 0, self.usage())], [None]) as (waited, _, signalled, _, _):
                result = runtime.supervise(['deterministic-exit-race-control'], directory, self.BUDGET)
            self.assertEqual(result['outcome'], 'success')
            self.assertIsNone(result['stop_reason'])
            self.assertEqual(result['sampled_peak_rss_bytes'], 0)
            self.assertEqual(result['waited_child_peak_rss_bytes'], 8192 * 1024)
            self.assertEqual(waited.call_count, 2)
            signalled.assert_not_called()
            self.assert_receipt(directory, result)

    def test_terminal_receipt_cannot_bypass_wall_deadline(self):
        child = self.child_control()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / 'late-terminal'
            with self.control(child, [(child.pid, 0, self.usage())]), \
                    patch.object(runtime.time, 'monotonic_ns', side_effect=[0, 3_000_000_000, 3_000_000_000]):
                result = runtime.supervise(['deterministic-late-terminal-control'], directory, self.BUDGET)
            self.assertEqual(result['exit_code'], 0)
            self.assertEqual(result['outcome'], 'failed')
            self.assertEqual(result['stop_reason'], 'wall-budget-exceeded')
            self.assertTrue(result['waited_child_reaped'])

    def test_wrong_pid_and_wait_errors_stay_failed_after_owned_cleanup(self):
        for first in ((999, 0, self.usage()), OSError(errno.EIO, 'injected wait4 failure'),
                      (True, 0, self.usage()), None):
            child = self.child_control()
            with self.subTest(first=first), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary) / 'wait-error'
                with self.control(child, [first, (child.pid, 0, self.usage())]) as (waited, observed, signalled, killed, _):
                    result = runtime.supervise(['deterministic-wait-error-control'], directory, self.BUDGET)
                self.assertEqual(result['exit_code'], 0)
                self.assertEqual(result['outcome'], 'failed')
                self.assertEqual(result['stop_reason'], 'waited-child-observation-unavailable')
                self.assertIsNotNone(result['waited_child_observation_error'])
                self.assertTrue(result['waited_child_reaped'])
                self.assertTrue(all(call.args[0] == child.pid for call in waited.call_args_list))
                observed.assert_not_called()
                signalled.assert_called_once_with(17, signal.SIGTERM)
                killed.assert_not_called()
                self.assert_receipt(directory, result)

    def test_malformed_terminal_receipts_never_succeed_or_double_reap(self):
        malformed = [(0, self.usage(peak=value)) for value in (0, -1, True, float('nan'), float('inf'))]
        malformed += [(0, self.usage(user=value)) for value in (True, -1, float('nan'), float('inf'))]
        malformed += [(0, None)]
        for status, usage in malformed:
            child = self.child_control()
            with self.subTest(status=status, usage=usage), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary) / 'malformed-terminal'
                with self.control(child, [(child.pid, status, usage)]) as (waited, observed, signalled, killed, _):
                    result = runtime.supervise(['deterministic-malformed-terminal-control'], directory, self.BUDGET)
                self.assertEqual(result['outcome'], 'failed')
                self.assertEqual(result['stop_reason'], 'waited-child-observation-unavailable')
                self.assertIsNone(result['waited_child_peak_rss_bytes'])
                self.assertIsNone(result['child_cpu_ns'])
                self.assertEqual(result['waited_child_observation_error'], 'wait4:invalid-terminal-receipt')
                self.assertTrue(result['waited_child_reaped'])
                waited.assert_called_once_with(child.pid, runtime.os.WNOHANG)
                observed.assert_not_called()
                signalled.assert_not_called()
                killed.assert_not_called()
                self.assert_receipt(directory, result)

    def test_stopped_or_invalid_status_retains_owner_until_terminal_cleanup(self):
        for status in ('wrong-status', 0x7f, -1, 1 << 80):
            child = self.child_control()
            with self.subTest(status=status), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary) / 'stopped-control'
                with self.control(child, [(child.pid, status, self.usage()), (child.pid, 0, self.usage())]) as (waited, _, signalled, _, closed):
                    result = runtime.supervise(['deterministic-stopped-control'], directory, self.BUDGET)
                self.assertEqual(result['outcome'], 'failed')
                self.assertEqual(result['waited_child_observation_error'], 'wait4:nonterminal-or-invalid-status')
                self.assertEqual(waited.call_count, 2)
                self.assertTrue(result['waited_child_reaped'])
                self.assertTrue(result['owned_child_exit_observed'])
                signalled.assert_called_once_with(17, signal.SIGTERM)
                closed.assert_called_once_with(17)

    def test_waitpid_fallback_only_cleans_up_and_never_earns_rss_credit(self):
        child = self.child_control()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / 'waitpid-cleanup'
            with self.control(child, [OSError(errno.EIO, 'wait4 unavailable')] * 2), \
                    patch.object(runtime.os, 'waitpid', return_value=(child.pid, 0)) as fallback:
                result = runtime.supervise(['deterministic-waitpid-cleanup-control'], directory, self.BUDGET)
            self.assertEqual(result['exit_code'], 0)
            self.assertEqual(result['outcome'], 'failed')
            self.assertIsNone(result['waited_child_peak_rss_bytes'])
            self.assertIsNone(result['child_cpu_ns'])
            self.assertTrue(result['waited_child_reaped'])
            self.assertTrue(result['owned_child_exit_observed'])
            self.assertEqual(result['cleanup_method'], 'waitpid-after-wait4-fault')
            fallback.assert_called_once_with(child.pid, runtime.os.WNOHANG)
            self.assert_receipt(directory, result)

    def test_exit_between_cleanup_poll_and_pidfd_readiness_is_actually_reaped(self):
        child = self.child_control()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / 'cleanup-readiness-race'
            waits = [(0, 0, None)] * 3 + [(child.pid, 0, self.usage())]
            with self.control(child, waits, [None]) as (waited, _, _, _, closed), \
                    patch.object(runtime.select, 'select', return_value=([17], [], [])):
                result = runtime.supervise(['deterministic-cleanup-readiness-race'], directory, self.BUDGET)
            self.assertEqual(result['outcome'], 'failed')
            self.assertEqual(result['stop_reason'], 'rss-observation-unavailable')
            self.assertEqual(result['exit_code'], 0)
            self.assertTrue(result['waited_child_reaped'])
            self.assertTrue(result['owned_child_exit_observed'])
            self.assertEqual(result['cleanup_method'], 'wait4')
            self.assertEqual(result['waited_child_peak_rss_bytes'], 8192 * 1024)
            self.assertIsNone(result['waited_child_observation_error'])
            self.assertEqual(waited.call_count, 4)
            self.assertTrue(all(call.args == (child.pid, runtime.os.WNOHANG) for call in waited.call_args_list))
            closed.assert_called_once_with(17)
            self.assert_receipt(directory, result)

    def test_unresolved_cleanup_retains_unknown_and_owned_handle(self):
        child = self.child_control()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / 'unresolved-cleanup'
            with self.control(child, [(999, 0, self.usage())]) as (waited, _, signalled, killed, closed), \
                    patch.object(runtime.time, 'monotonic', side_effect=[0, 6, 6, 8]):
                with self.assertRaises(runtime._OwnedChildCleanupRequired) as caught:
                    runtime.supervise(['deterministic-unresolved-cleanup-control'], directory, self.BUDGET)
            result = caught.exception.receipt
            self.assertIs(caught.exception.child, child)
            self.assertEqual(child.termination_fd, 17)
            self.assertEqual(result['outcome'], 'failed')
            self.assertEqual(result['stop_reason'], 'waited-child-observation-unavailable')
            self.assertIsNone(result['exit_code'])
            self.assertIsNone(result['waited_child_peak_rss_bytes'])
            self.assertFalse(result['waited_child_reaped'])
            self.assertFalse(result['owned_child_exit_observed'])
            self.assertEqual([call.args for call in signalled.call_args_list], [(17, signal.SIGTERM), (17, signal.SIGKILL)])
            waited.assert_called_once_with(child.pid, runtime.os.WNOHANG)
            killed.assert_not_called()
            closed.assert_not_called()
            self.assert_receipt(directory, result)

    def test_unsupported_owner_fails_before_any_child_spawn(self):
        for rejection in ('auto-reap', 'pidfd-denied'):
            with self.subTest(rejection=rejection), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary) / rejection
                with patch.object(runtime.subprocess.Popen, '__init__', side_effect=AssertionError('must not spawn')) as spawn, \
                        patch.object(runtime.signal, 'getsignal', return_value=(signal.SIG_IGN if rejection == 'auto-reap' else signal.SIG_DFL)), \
                        patch.object(runtime.os, 'pidfd_open', side_effect=PermissionError('pidfd unavailable')):
                    result = runtime.supervise(['must-not-spawn'], directory, self.BUDGET)
                spawn.assert_not_called()
                self.assertEqual(result['outcome'], 'failed')
                self.assertEqual(result['stop_reason'], 'rss-owner-unsupported')
                self.assertFalse(result['child_spawned'])
                self.assertIsNone(result['exit_code'])
                self.assertIsNone(result['waited_child_peak_rss_bytes'])
                self.assert_receipt(directory, result)

    def test_actual_external_reap_is_unknown_but_pidfd_confirms_owned_exit(self):
        original_waitpid = runtime.os.waitpid
        stolen = False

        def externally_reaped(pid, options):
            nonlocal stolen
            if not stolen:
                stolen = True
                waited, _ = original_waitpid(pid, 0)
                self.assertEqual(waited, pid)
            raise ChildProcessError(errno.ECHILD, 'injected external reaper')

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / 'external-reap'
            with patch.object(runtime.os, 'wait4', side_effect=externally_reaped), \
                    patch.object(runtime.os, 'kill', side_effect=AssertionError('numeric PID signal forbidden')):
                result = runtime.supervise([sys.executable, '-c', 'print("done")'], directory, self.BUDGET)
            self.assertEqual(result['outcome'], 'failed')
            self.assertFalse(result['waited_child_reaped'])
            self.assertTrue(result['owned_child_exit_observed'])
            self.assertIsNone(result['exit_code'])
            self.assertIsNone(result['waited_child_peak_rss_bytes'])
            self.assertIsNone(result['child_cpu_ns'])
            self.assertEqual(result['cleanup_method'], 'pidfd-terminal-without-waited-status')
            self.assert_receipt(directory, result)

    def test_signal_denied_without_exit_keeps_failed_receipt_and_live_handle(self):
        child = self.child_control()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / 'signal-denied'
            with self.control(child, [(0, 0, None)] * 2, [None]) as (_, _, signalled, killed, closed), \
                    patch.object(runtime.time, 'monotonic', side_effect=[0, 6, 6, 8]):
                signalled.side_effect = PermissionError(errno.EPERM, 'injected signal denial')
                with self.assertRaises(runtime._OwnedChildCleanupRequired) as caught:
                    runtime.supervise(['deterministic-signal-denied-control'], directory, self.BUDGET)
            result = caught.exception.receipt
            self.assertEqual(result['outcome'], 'failed')
            self.assertIsNone(result['exit_code'])
            self.assertFalse(result['owned_child_exit_observed'])
            self.assertIs(caught.exception.child, child)
            self.assertEqual(child.termination_fd, 17)
            self.assertEqual([call.args for call in signalled.call_args_list], [(17, signal.SIGTERM), (17, signal.SIGKILL)])
            killed.assert_not_called()
            closed.assert_not_called()
            self.assert_receipt(directory, result)

    def test_actual_post_spawn_pidfd_failure_never_signals_a_numeric_pid(self):
        original_open = runtime.os.pidfd_open

        def capability_then_failure(pid, flags):
            if pid == runtime.os.getpid():
                return original_open(pid, flags)
            raise PermissionError(errno.EPERM, 'injected post-spawn pidfd failure')

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / 'post-spawn-pidfd-failure'
            with patch.object(runtime.os, 'pidfd_open', side_effect=capability_then_failure), \
                    patch.object(runtime.os, 'kill', side_effect=AssertionError('numeric PID signal forbidden')):
                result = runtime.supervise([sys.executable, '-c', 'print("done")'], directory, self.BUDGET)
            self.assertEqual(result['exit_code'], 0)
            self.assertEqual(result['outcome'], 'failed')
            self.assertTrue(result['owned_child_exit_observed'])
            self.assertTrue(result['waited_child_reaped'])
            self.assertTrue(result['waited_child_observation_error'].startswith('pidfd-open-after-spawn:'))
            self.assert_receipt(directory, result)

    def test_readable_dead_child_with_permission_failure_retains_unreaped_owner(self):
        child = self.child_control()
        denial = PermissionError(errno.EPERM, 'injected reap denial')
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / 'dead-unreaped-permission-error'
            with self.control(child, [denial] * 3) as (waited, _, signalled, killed, closed), \
                    patch.object(runtime.os, 'waitpid', side_effect=denial) as fallback, \
                    patch.object(runtime.select, 'select', return_value=([17], [], [])):
                with self.assertRaises(runtime._OwnedChildCleanupRequired) as caught:
                    runtime.supervise(['deterministic-dead-unreaped-control'], directory, self.BUDGET)
                result = caught.exception.receipt
                self.assertEqual(result['outcome'], 'failed')
                self.assertTrue(result['owned_child_exit_observed'])
                self.assertFalse(result['owned_child_reap_resolved'])
                self.assertFalse(result['owned_child_echild_observed'])
                self.assertFalse(result['waited_child_reaped'])
                self.assertIsNone(result['exit_code'])
                self.assertIsNone(result['waited_child_peak_rss_bytes'])
                self.assertIs(caught.exception.child, child)
                self.assertEqual(child.termination_fd, 17)
                self.assertEqual(waited.call_count, 3)
                self.assertEqual(fallback.call_count, 2)
                signalled.assert_called_once_with(17, signal.SIGTERM)
                killed.assert_not_called()
                closed.assert_not_called()
                self.assert_receipt(directory, result)
                # The retained original owner can later finish cleanup without
                # a new spawn/signal or upgrading the already failed receipt.
                with patch.object(runtime.os, 'wait4', return_value=(child.pid, 0, self.usage())) as retry:
                    child.finish()
                retry.assert_called_once_with(child.pid, runtime.os.WNOHANG)
                closed.assert_called_once_with(17)
                self.assertTrue(child.reaped)
                self.assertTrue(child.reap_resolved)
                self.assertIsNone(child.termination_fd)
                self.assertEqual(result['outcome'], 'failed')
                self.assertIsNone(result['waited_child_peak_rss_bytes'])

    def test_readable_dead_echild_resolves_cleanup_without_rss_success(self):
        for source in ('wait4', 'waitpid'):
            child = self.child_control()
            no_child = ChildProcessError(errno.ECHILD, 'injected already-reaped child')
            denial = PermissionError(errno.EPERM, 'injected wait4 unavailability')
            waits = [no_child] if source == 'wait4' else [denial] * 2
            with self.subTest(source=source), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary) / source
                with self.control(child, waits) as (waited, _, _, killed, closed), \
                        patch.object(runtime.os, 'waitpid', side_effect=no_child) as fallback, \
                        patch.object(runtime.select, 'select', return_value=([17], [], [])):
                    result = runtime.supervise(['deterministic-dead-echild-control'], directory, self.BUDGET)
                self.assertEqual(result['outcome'], 'failed')
                self.assertTrue(result['owned_child_exit_observed'])
                self.assertTrue(result['owned_child_reap_resolved'])
                self.assertTrue(result['owned_child_echild_observed'])
                self.assertFalse(result['waited_child_reaped'])
                self.assertIsNone(result['exit_code'])
                self.assertIsNone(result['waited_child_peak_rss_bytes'])
                self.assertIsNone(result['child_cpu_ns'])
                self.assertEqual(waited.call_count, 1 if source == 'wait4' else 2)
                self.assertEqual(fallback.call_count, 0 if source == 'wait4' else 1)
                killed.assert_not_called()
                closed.assert_called_once_with(17)
                self.assert_receipt(directory, result)

    def test_actual_early_exit_and_unsampled_high_rss_use_exact_wait4(self):
        original_wait4 = runtime.os.wait4
        for label, command, budget, outcome, reason in (
                ('quick', [sys.executable, '-c', 'print("done")'], self.BUDGET, 'success', None),
                ('high', [sys.executable, '-c', 'x=bytearray(100*1024**2);print("done")'],
                 dict(wall_seconds=2, rss_bytes=32 * 1024**2), 'failed', 'rss-budget-exceeded')):
            first = True

            def wait_for_actual_terminal(pid, options):
                nonlocal first
                if first:
                    first = False
                    descriptor = runtime.os.pidfd_open(pid, 0)
                    try:
                        readable, _, _ = select.select([descriptor], [], [], 2)
                        if not readable:
                            raise TimeoutError('owned child did not become terminal')
                    finally:
                        runtime.os.close(descriptor)
                return original_wait4(pid, options)

            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary) / label
                with patch.object(runtime.os, 'wait4', side_effect=wait_for_actual_terminal), \
                        patch.object(runtime, 'current_rss', side_effect=AssertionError('child must already be terminal')):
                    result = runtime.supervise(command, directory, budget)
                self.assertEqual(result['exit_code'], 0)
                self.assertEqual(result['outcome'], outcome)
                self.assertEqual(result['stop_reason'], reason)
                self.assertEqual(result['sampled_peak_rss_bytes'], 0)
                self.assertGreater(result['waited_child_peak_rss_bytes'], 0)
                self.assertTrue(result['waited_child_reaped'])
                self.assertIsNone(result['waited_child_observation_error'])
                self.assertIn('done', (directory / 'process.log').read_text())
                if label == 'high':
                    self.assertGreater(result['waited_child_peak_rss_bytes'], budget['rss_bytes'])


if __name__ == '__main__':
    unittest.main()
