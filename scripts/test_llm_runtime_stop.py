"""Real-child cancellation controls; these do not execute or qualify a model."""
import contextlib
import errno
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import llm_runtime_pilot as runtime
import llm_neural_read_worker as worker

BUDGET = dict(wall_seconds=5, rss_bytes=64*1024**2)
COMMAND = [sys.executable, '-c', 'import time;time.sleep(30)']


class StopRequestTests(unittest.TestCase):
    def test_signal_request_is_sticky_and_restores_handlers_on_error(self):
        previous = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
        with self.assertRaisesRegex(ValueError, 'fixture'):
            with runtime.cooperative_supervisor_stop() as stop:
                self.assertFalse(stop.requested)
                os.kill(os.getpid(), signal.SIGINT)
                os.kill(os.getpid(), signal.SIGTERM)
                self.assertTrue(stop.requested)
                stop.request()
                self.assertTrue(stop.requested)
                raise ValueError('fixture')
        self.assertEqual(previous, {number: signal.getsignal(number) for number in previous})
        with runtime.cooperative_supervisor_stop() as fresh:
            self.assertFalse(fresh.requested)

    def test_background_scope_refuses_before_modifying_main_thread_handlers(self):
        previous = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
        failures = []
        entered = []
        def background():
            try:
                with runtime.cooperative_supervisor_stop():
                    entered.append(True)
            except ValueError as error:
                failures.append(str(error))
        with patch.object(signal, 'signal', wraps=signal.signal) as install:
            thread = threading.Thread(target=background)
            thread.start()
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            install.assert_not_called()
        self.assertEqual((entered, failures), ([], ['RUNTIME_STOP_MAIN_THREAD']))
        self.assertEqual(previous, {number: signal.getsignal(number) for number in previous})

    def test_partial_handler_install_failure_restores_the_exact_original(self):
        previous = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
        original = signal.signal
        calls = []
        def install(number, handler):
            self.assertIs(threading.current_thread(), threading.main_thread())
            calls.append((number, handler))
            if number == signal.SIGTERM:
                raise OSError('fixture install failed before mutation')
            return original(number, handler)
        with patch.object(signal, 'signal', install):
            with self.assertRaisesRegex(OSError, 'fixture install failed'):
                with runtime.cooperative_supervisor_stop():
                    self.fail('failed partial installation entered its body')
        self.assertEqual([number for number, _ in calls],
                         [signal.SIGINT, signal.SIGTERM, signal.SIGINT])
        self.assertIs(calls[-1][1], previous[signal.SIGINT])
        self.assertEqual(previous, {number: signal.getsignal(number) for number in previous})

    def test_pre_requested_stop_never_spawns_or_invents_accounting(self):
        with tempfile.TemporaryDirectory() as temporary, runtime.cooperative_supervisor_stop() as stop:
            stop.request()
            directory = Path(temporary)/'run'
            with patch.object(subprocess.Popen, '__init__', side_effect=AssertionError('no spawn')) as spawn:
                result = runtime.supervise(COMMAND, directory, BUDGET, stop_request=stop)
            spawn.assert_not_called()
            self.assertEqual(result, json.loads((directory/'supervisor.json').read_text()))
            self.assertEqual(result['stop_reason'], 'stop-requested')
            self.assertEqual(result['outcome'], 'failed')
            self.assertFalse(result['child_spawned'])
            self.assertFalse(result['waited_child_reaped'])
            self.assertIsNone(result['waited_child_peak_rss_bytes'])
            self.assertIsNone(result['child_cpu_ns'])

    def test_untyped_stop_is_rejected_before_side_effects(self):
        with tempfile.TemporaryDirectory() as temporary:
            for value in (True, {}, SimpleNamespace(requested=True)):
                directory = Path(temporary)/'run'
                with self.assertRaisesRegex(ValueError, 'RUNTIME_STOP_INTERFACE'):
                    runtime.supervise(COMMAND, directory, BUDGET, stop_request=value)
                self.assertFalse(directory.exists())


@unittest.skipUnless(sys.platform == 'linux' and hasattr(os, 'pidfd_open'), 'Linux owned child required')
class RealStopTests(unittest.TestCase):
    @contextlib.contextmanager
    def observe(self, point, signum=signal.SIGINT, repeat_in_finish=False, ready=None):
        held, waits, finishes = [], [], []
        original_popen = subprocess.Popen.__init__
        original_owner = runtime._Wait4Child.__init__
        original_rss = runtime.current_rss
        original_finish = runtime._Wait4Child.finish
        original_wait4 = os.wait4
        original_sleep = time.sleep
        def spawned(child, *args, **kwargs):
            original_popen(child, *args, **kwargs)
            held.append(child)
            if ready is not None:
                deadline = time.monotonic()+2
                while not ready.exists() and time.monotonic() < deadline:
                    original_sleep(0.001)
                self.assertTrue(ready.exists(), 'child must install TERM ignore before cancellation')
            if point == 'after-fork-before-pidfd':
                os.kill(os.getpid(), signum)
        def adopted(child, *args, **kwargs):
            original_owner(child, *args, **kwargs)
            if point == 'pidfd-before-caller-assignment':
                os.kill(os.getpid(), signum)
        def rss(pid):
            if point == 'after-caller-adoption':
                os.kill(os.getpid(), signum)
            return original_rss(pid)
        def finish(child):
            finishes.append(child)
            if repeat_in_finish:
                os.kill(os.getpid(), signal.SIGINT)
                os.kill(os.getpid(), signal.SIGTERM)
            original_finish(child)
        def wait4(pid, options):
            result = original_wait4(pid, options)
            waits.append((pid, result[0]))
            return result
        try:
            with patch.object(subprocess.Popen, '__init__', spawned), \
                 patch.object(runtime._Wait4Child, '__init__', adopted), \
                 patch.object(runtime, 'current_rss', rss), \
                 patch.object(runtime._Wait4Child, 'finish', finish), \
                 patch.object(os, 'wait4', wait4):
                yield held, waits, finishes
        finally:
            # Fixture-owned fallback only on an assertion failure; never leave
            # the reproducer's child live if the production regression returns.
            for child in held:
                if not child.reap_resolved:
                    if child.termination_fd is None:
                        child.termination_fd = os.pidfd_open(child.pid, 0)
                    original_finish(child)

    def assert_terminal_stop(self, result, directory, held, waits, finishes):
        self.assertEqual(len(held), 1)
        child = held[0]
        self.assertEqual(finishes, [child])
        self.assertEqual(result['outcome'], 'failed')
        self.assertEqual(result['stop_reason'], 'stop-requested')
        self.assertTrue(result['child_spawned'])
        self.assertTrue(result['waited_child_reaped'])
        self.assertTrue(result['owned_child_reap_resolved'])
        self.assertTrue(result['owned_child_exit_observed'])
        self.assertEqual(result['cleanup_method'], 'wait4')
        self.assertIsNone(result['waited_child_observation_error'])
        self.assertIsInstance(result['child_cpu_ns'], int)
        self.assertGreater(result['waited_child_peak_rss_bytes'], 0)
        self.assertTrue(waits)
        self.assertTrue(all(pid == child.pid for pid, _ in waits))
        self.assertEqual(sum(returned == child.pid for _, returned in waits), 1)
        self.assertIsNone(child.termination_fd)
        with self.assertRaises(ChildProcessError):
            os.wait4(child.pid, os.WNOHANG)
        self.assertEqual(result, json.loads((directory/'supervisor.json').read_text()))

    def test_real_int_and_term_at_each_handoff_have_one_original_terminal_owner(self):
        for point in ('after-fork-before-pidfd', 'pidfd-before-caller-assignment', 'after-caller-adoption'):
            for signum in (signal.SIGINT, signal.SIGTERM):
                with self.subTest(point=point, signum=signum), tempfile.TemporaryDirectory() as temporary, \
                     runtime.cooperative_supervisor_stop() as stop, self.observe(point, signum) as observed:
                    directory = Path(temporary)/'run'
                    result = runtime.supervise(COMMAND, directory, BUDGET, stop_request=stop)
                    self.assert_terminal_stop(result, directory, *observed)

    def test_repeated_signals_cannot_interrupt_original_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary, runtime.cooperative_supervisor_stop() as stop, \
             self.observe('after-fork-before-pidfd', repeat_in_finish=True) as observed:
            directory = Path(temporary)/'run'
            result = runtime.supervise(COMMAND, directory, BUDGET, stop_request=stop)
            self.assert_terminal_stop(result, directory, *observed)

    def test_second_term_inside_original_grace_keeps_the_kill_and_reap_owner(self):
        original_sleep = time.sleep
        original_signal = runtime._Wait4Child.signal_owned
        child_signals = []
        second_term = []
        def signal_child(child, number):
            child_signals.append(number)
            return original_signal(child, number)
        def during_grace(seconds):
            if child_signals == [signal.SIGTERM] and not second_term:
                second_term.append(time.monotonic())
                os.kill(os.getpid(), signal.SIGTERM)
            return original_sleep(seconds)
        with tempfile.TemporaryDirectory() as temporary, runtime.cooperative_supervisor_stop() as stop:
            ready = Path(temporary)/'ready'
            command = [sys.executable, '-c',
                'import pathlib,signal,sys,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);'
                'pathlib.Path(sys.argv[1]).touch();time.sleep(30)', str(ready)]
            with self.observe('after-fork-before-pidfd', signum=signal.SIGTERM, ready=ready) as observed, \
                 patch.object(runtime._Wait4Child, 'signal_owned', signal_child), \
                 patch.object(time, 'sleep', during_grace):
                directory = Path(temporary)/'run'
                result = runtime.supervise(command, directory, BUDGET, stop_request=stop)
                self.assert_terminal_stop(result, directory, *observed)
            self.assertEqual(child_signals, [signal.SIGTERM, signal.SIGKILL])
            self.assertEqual(len(second_term), 1)
            self.assertEqual(result['exit_code'], -signal.SIGKILL)
            self.assertGreaterEqual(time.monotonic()-second_term[0], 4.8)

    def test_stop_never_turns_unresolved_cleanup_into_success(self):
        original_finish = runtime._Wait4Child.finish
        previous = signal.getsignal(signal.SIGTERM)
        restored_signals = []
        def original_handler(number, _frame):
            restored_signals.append(number)
        signal.signal(signal.SIGTERM, original_handler)
        child = None
        try:
            with tempfile.TemporaryDirectory() as temporary, \
                 self.observe('after-fork-before-pidfd') as (held, _, _):
                directory = Path(temporary)/'run'
                with self.assertRaises(runtime._OwnedChildCleanupRequired) as caught:
                    with runtime.cooperative_supervisor_stop() as stop:
                        with patch.object(runtime._Wait4Child, 'finish', return_value=None):
                            runtime.supervise(COMMAND, directory, BUDGET, stop_request=stop)
                child = caught.exception.child
                result = caught.exception.receipt
                self.assertIs(child, held[0])
                self.assertIsNotNone(child.termination_fd)
                original_fd = child.termination_fd
                original_identity = os.fstat(original_fd)
                self.assertEqual(result['stop_reason'], 'stop-requested')
                self.assertEqual(result['outcome'], 'failed')
                self.assertFalse(result['owned_child_reap_resolved'])
                self.assertFalse(result['waited_child_reaped'])
                self.assertEqual(result, json.loads((directory/'supervisor.json').read_text()))
                self.assertIs(signal.getsignal(signal.SIGTERM), original_handler)
                os.kill(os.getpid(), signal.SIGTERM)
                self.assertEqual(restored_signals, [signal.SIGTERM])
                self.assertEqual((child.termination_fd, os.fstat(original_fd)),
                                 (original_fd, original_identity))
                self.assertFalse(child.reap_resolved)
                original_finish(child)
                self.assertTrue(child.reaped)
                self.assertTrue(child.reap_resolved)
                self.assertIsNone(child.termination_fd)
        finally:
            if child is not None and not child.reap_resolved:
                original_finish(child)
            signal.signal(signal.SIGTERM, previous)

    def test_terminal_exit_zero_after_stop_still_cannot_succeed(self):
        original_owner = runtime._Wait4Child.__init__
        held = []
        with tempfile.TemporaryDirectory() as temporary, runtime.cooperative_supervisor_stop() as stop:
            def before_return(child, *args, **kwargs):
                original_owner(child, *args, **kwargs)
                held.append(child)
                deadline = time.monotonic()+2
                while child.reap() == 'live' and time.monotonic() < deadline:
                    time.sleep(0.001)
                self.assertEqual(child.returncode, 0)
                os.kill(os.getpid(), signal.SIGINT)
            with patch.object(runtime._Wait4Child, '__init__', before_return):
                result = runtime.supervise([sys.executable, '-c', 'print("done")'],
                    Path(temporary)/'run', BUDGET, stop_request=stop)
            self.assertEqual(result['exit_code'], 0)
            self.assertEqual(result['stop_reason'], 'stop-requested')
            self.assertEqual(result['outcome'], 'failed')
            self.assertTrue(result['waited_child_reaped'])

    def test_neural_serve_entry_passes_stop_through_real_supervision(self):
        original = runtime.supervise
        seen = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)/'owner'
            args = SimpleNamespace(output=str(root), threads=1, parent='fixture-parent', parent_sha256='x',
                actions='fixture-actions', actions_sha256='y', materials='fixture-materials',
                runtime_snapshot='fixture-snapshot', runtime_snapshot_sha256='z',
                source_pins='fixture-pins', source_pins_sha256='w')
            inherited = SimpleNamespace(validate_parent=lambda x:x, read_parent=lambda x:None,
                checked_json=lambda *args: {})
            def supervised(command, directory, budget, *, stop_request):
                seen.append(command)
                self.assertIs(type(stop_request), runtime.SupervisorStopRequest)
                with self.observe('after-fork-before-pidfd') as observed:
                    result = original(COMMAND, directory, BUDGET, stop_request=stop_request)
                    self.assert_terminal_stop(result, directory, *observed)
                return result
            with patch.object(worker, 'runtime', runtime, create=True), \
                 patch.object(worker, 'inherited', inherited, create=True), \
                 patch.object(worker, 'action_profile', return_value=[]), \
                 patch.object(worker, 'worker_sources', return_value={}), \
                 patch.object(runtime, 'verify_materials', return_value=({}, [])), \
                 patch.object(runtime, 'experiment_plan', return_value={'inference_budget': BUDGET}), \
                 patch.object(runtime, 'supervise', supervised), \
                 patch.object(sys, 'pycache_prefix', str(Path(temporary)/'cache')):
                with self.assertRaisesRegex(ValueError, 'NEURAL_READ_WORKER_FAILED'):
                    worker.serve(args)
            self.assertEqual(len(seen), 1)
            self.assertEqual(seen[0][1:4], ['-I', '-S', '-B'])
            self.assertTrue((root/'worker'/'supervisor.json').exists())


class StopObservationTests(unittest.TestCase):
    def test_sticky_stop_aborts_existing_exit_reconciliation_without_authority(self):
        stop = runtime.SupervisorStopRequest()
        child = SimpleNamespace(termination_fd=17, reap=lambda:'live')
        diagnostic = {}
        with patch.object(runtime, 'owned_exit_cleanup_proof', return_value={'fixture': True}), \
             patch.object(runtime.select, 'select', side_effect=lambda *args:(stop.request() or ([], [], []))) as poll:
            self.assertFalse(runtime.reconcile_unobserved_exit(
                child, time.monotonic_ns()+10**9, diagnostic, stop_request=stop))
        self.assertEqual(poll.call_count, 1)
        self.assertTrue(diagnostic['stop_requested'])
        self.assertEqual(diagnostic['terminal_reap'], 'not-polled-pidfd-not-ready')


if __name__ == '__main__':
    unittest.main()
