#!/usr/bin/env python3
"""Real filesystem lifecycle controls for the finite component build monitor.

No Cargo build, prepared bundle, native qualification or historical attribution.
fwalk hooks choose real unlink/rmdir interleavings. Filesystem errors, child
birth/exit/wait and signals remain real. Temporary fixtures are not retained;
bounded JSON observations and original test stdout/stderr are the evidence.
"""
from copy import deepcopy
import errno
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'scripts'))
sys.path.insert(0, str(ROOT/'scripts/ci'))
sys.path.insert(0, str(ROOT/'formal/pon-nakamoto-v1'))
import run_pon_native_io_component as c


def proc_identity(pid):
    try:
        text = Path('/proc/'+str(pid)+'/stat').read_text()
    except FileNotFoundError:
        return None
    fields = text[text.rfind(')')+2:].split()
    return dict(pid=pid, ppid=int(fields[1]), birth_ticks=int(fields[19]),
                boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip())


class BuildMonitorLifecycleControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pn1-monitor-lifecycle-')
        self.root = Path(self.temp.name)
        self.target_path = self.root/'target'
        self.target_path.mkdir()
        (self.target_path/'stable-output.o').write_bytes(b's'*8192)
        self.parent = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.target = os.open(self.target_path, os.O_RDONLY | os.O_DIRECTORY)
        self.monitor = c.BuildStop(self.target, self.parent, 'target', None)
        self.events = []
        self.observation = dict(case=self._testMethodName,
            actual_nice=os.getpriority(os.PRIO_PROCESS, 0),
            actual_AS=list(resource.getrlimit(resource.RLIMIT_AS)),
            real_Cargo_build=False, historical_ec0_build_cause='UNKNOWN',
            physical_quota_or_instantaneous_peak_proven=False)
        self.assertEqual(c.TARGET_BYTES, 6*1024**3)
        self.assertEqual(c.TARGET_RESERVE, 512*1024**2)

    def tearDown(self):
        self.observation.update(events=self.events,
            monitor=self.monitor.monitor_observation(),
            held_root_identity_unchanged=c.identity(os.fstat(self.target)) == self.monitor.identity)
        print(json.dumps(self.observation, sort_keys=True), flush=True)
        os.close(self.target)
        os.close(self.parent)
        self.temp.cleanup()

    def error_row(self, error):
        return dict(type=type(error).__name__, errno=getattr(error, 'errno', None),
                    filename=str(getattr(error, 'filename', '')), text=str(error))

    def assert_rescan_recorded(self):
        self.assertGreaterEqual(self.monitor.scan_retries, 1)
        self.assertGreaterEqual(self.monitor.vanished_entries, 1)
        self.assertTrue(any(event.get('errno') == errno.ENOENT for event in self.events))
        self.assertEqual(c.identity(os.fstat(self.target)), self.monitor.identity)

    def test_unlink_after_yield_completes_a_fresh_full_scan(self):
        (self.target_path/'cargo-temporary.o').write_bytes(b't'*128)
        original_fwalk, original_stat = os.fwalk, os.stat
        deleted = False
        def fwalk(*args, **kwargs):
            nonlocal deleted
            for item in original_fwalk(*args, **kwargs):
                parent, dirs, files, fd = item
                if parent == '.' and 'cargo-temporary.o' in files and not deleted:
                    os.unlink('cargo-temporary.o', dir_fd=fd)
                    deleted = True
                    self.events.append(dict(operation='real-unlink-after-yield'))
                yield item
        def observed_stat(*args, **kwargs):
            try:
                return original_stat(*args, **kwargs)
            except FileNotFoundError as error:
                self.events.append(dict(operation='real-stat-ENOENT', **self.error_row(error)))
                raise
        with patch.object(c.os, 'fwalk', fwalk), patch.object(c.os, 'stat', observed_stat):
            total = self.monitor.measure()
        self.assertTrue(deleted)
        self.assertEqual(total, 8192)
        self.assert_rescan_recorded()
        self.assertGreaterEqual(self.monitor.peak, 8192)

    def test_rmdir_before_descent_completes_a_fresh_full_scan(self):
        (self.target_path/'cargo-temporary-dir').mkdir()
        original_fwalk = os.fwalk
        deleted = False
        def fwalk(*args, **kwargs):
            nonlocal deleted
            original_onerror = kwargs.get('onerror')
            def observed_onerror(error):
                self.events.append(dict(operation='real-descend-ENOENT', **self.error_row(error)))
                return original_onerror(error)
            kwargs['onerror'] = observed_onerror
            for item in original_fwalk(*args, **kwargs):
                yield item
                parent, dirs, files, fd = item
                if parent == '.' and 'cargo-temporary-dir' in dirs and not deleted:
                    os.rmdir('cargo-temporary-dir', dir_fd=fd)
                    deleted = True
                    self.events.append(dict(operation='real-rmdir-before-descent'))
        with patch.object(c.os, 'fwalk', fwalk):
            total = self.monitor.measure()
        self.assertTrue(deleted)
        self.assertEqual(total, 8192)
        self.assert_rescan_recorded()

    def test_watch_rescans_and_real_child_exits_naturally(self):
        (self.target_path/'cargo-temporary.o').write_bytes(b't'*128)
        original_fwalk, original_stat = os.fwalk, os.stat
        original_popen, original_killpg = subprocess.Popen, os.killpg
        spawned, owner, deleted = threading.Event(), {}, False
        self.observation['actual_child_owner'] = owner
        def fwalk(*args, **kwargs):
            nonlocal deleted
            for item in original_fwalk(*args, **kwargs):
                parent, dirs, files, fd = item
                if threading.current_thread() is not threading.main_thread() and parent == '.' \
                        and 'cargo-temporary.o' in files and not deleted:
                    self.assertTrue(spawned.wait(.1))
                    os.unlink('cargo-temporary.o', dir_fd=fd)
                    deleted = True
                    self.events.append(dict(operation='real-watch-unlink-after-yield'))
                yield item
        def observed_stat(*args, **kwargs):
            try:
                return original_stat(*args, **kwargs)
            except FileNotFoundError as error:
                self.events.append(dict(operation='real-watch-stat-ENOENT', **self.error_row(error)))
                raise
        def observed_killpg(pid, sig):
            self.events.append(dict(operation='real-killpg-call', pid=pid, signal=int(sig),
                thread=threading.current_thread().name, monitor_pending=self.monitor.pending,
                monitor_error=self.monitor.error))
            return original_killpg(pid, sig)
        def observed_popen(*args, **kwargs):
            child = original_popen(*args, **kwargs)
            owner.update(proc_identity(child.pid))
            owner.update(spawn_count=1, observer_parent_pid=os.getpid(), reaped=False)
            actual_wait = child.wait
            def observed_wait(*args, **kwargs):
                code = actual_wait(*args, **kwargs)
                identity = {key:owner[key] for key in ('pid', 'ppid', 'birth_ticks', 'boot_id')}
                owner.update(wait_returncode=code, reaped=True,
                    original_identity_alive_after_wait=proc_identity(child.pid) == identity)
                try:
                    os.waitpid(child.pid, os.WNOHANG)
                    owner['second_wait_result'] = 'unexpected-waitable-child'
                except ChildProcessError:
                    owner['second_wait_result'] = 'ECHILD-after-actual-wait'
                return code
            child.wait = observed_wait
            spawned.set()
            return child
        class ActualChildIO:
            def build_step(inner, command, env, target):
                return c.bounded_process.run_bounded(command, b'', timeout=3,
                    stdout_limit=1048576, stderr_limit=1048576, env=env)
        self.monitor.io = ActualChildIO()
        with patch.object(c.os, 'fwalk', fwalk), patch.object(c.os, 'stat', observed_stat), \
                patch.object(c.os, 'killpg', observed_killpg), \
                patch.object(c.bounded_process.subprocess, 'Popen', observed_popen):
            result = self.monitor.run([sys.executable, '-u', '-c',
                'import os,time; print("real-child-start",os.getpid(),flush=True); time.sleep(.75)'], dict(os.environ))
        self.observation.update(actual_child_owner=owner,
            actual_child_stdout=result.stdout.decode('utf-8'), actual_child_stderr=result.stderr.decode('utf-8'))
        self.assertTrue(deleted)
        self.assert_rescan_recorded()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(owner['wait_returncode'], 0)
        self.assertTrue(owner['reaped'])
        self.assertEqual(owner['ppid'], os.getpid())
        self.assertGreater(owner['birth_ticks'], 0)
        self.assertFalse(owner['original_identity_alive_after_wait'])
        self.assertEqual(owner['second_wait_result'], 'ECHILD-after-actual-wait')
        self.assertIsNone(self.monitor.error)
        self.assertFalse(self.monitor.pending)
        self.assertIsNone(self.monitor.child)
        # bounded_process retains its original final group signal before wait,
        # even after natural exit. It must not be mistaken for a monitor kill.
        self.assertFalse(any(event.get('operation') == 'real-killpg-call'
            and (event['monitor_pending'] or event['monitor_error'] is not None)
            for event in self.events))
        self.assertGreaterEqual(self.monitor.peak, 8320)
        # This invokes only the actual monitor-shape predicate. It is not a
        # prepared bundle, source proof or public preparation qualification.
        actual = dict(build_monitor_observation=self.monitor.monitor_observation(),
            build_target_observed_logical_peak_bytes=self.monitor.peak)
        binding, observed_owner = {'identity': self.monitor.identity}, {'pid': owner['pid']}
        c.validate_build_monitor(actual, binding, observed_owner)
        mutations = [('physical_or_instantaneous_quota_claimed', True),
            ('sample_seconds', 6), ('last_scan_entries', 200001),
            ('pending_stop', True), ('watch_thread_alive', True)]
        for key, bad in mutations:
            with self.subTest(monitor_claim=key):
                altered = deepcopy(actual)
                altered['build_monitor_observation'][key] = bad
                with self.assertRaises(ValueError):
                    c.validate_build_monitor(altered, binding, observed_owner)
        altered = deepcopy(actual)
        altered['build_monitor_observation']['observed_logical_peak_bytes'] = c.TARGET_BYTES
        altered['build_target_observed_logical_peak_bytes'] = c.TARGET_BYTES
        with self.assertRaises(ValueError):
            c.validate_build_monitor(altered, binding, observed_owner)
        altered = deepcopy(actual)
        altered['build_monitor_observation']['actual_last_wait']['returncode'] = False
        with self.assertRaises(ValueError):
            c.validate_build_monitor(altered, binding, observed_owner)
        self.observation['actual_monitor_shape_partial_predicate_and_seven_mutations_checked'] = True

    def test_hard_watch_error_keeps_actual_child_and_reason_in_terminal(self):
        # The real ComponentIO output is disjoint from the monitored target.
        output = self.root/'component-output'
        output.mkdir()
        io = c.ComponentIO(output)
        self.monitor.io = io
        original_fwalk = os.fwalk
        original_identity = c.NativeChildOwner.process_identity
        birth_seen, actual_birth, inserted = threading.Event(), {}, False
        def observed_identity(pid):
            birth, ppid = original_identity(pid)
            actual_birth.update(pid=pid, birth_ticks=birth, observed_ppid=ppid)
            birth_seen.set()
            return birth, ppid
        def fwalk(*args, **kwargs):
            nonlocal inserted
            if threading.current_thread() is not threading.main_thread() \
                    and birth_seen.is_set() and not inserted:
                # The target still contains the real symlink when the final
                # scan runs; both hard refusals must retain the first reason.
                os.symlink('stable-output.o', 'hard-unknown-object', dir_fd=self.target)
                inserted = True
                self.events.append(dict(operation='real-watch-symlink-after-observed-birth',
                    actual_birth=deepcopy(actual_birth)))
            yield from original_fwalk(*args, **kwargs)
        env = dict(os.environ, CARGO_TARGET_DIR='/proc/self/fd/'+str(self.target))
        try:
            with patch.object(c.os, 'fwalk', fwalk), \
                    patch.object(c.NativeChildOwner, 'process_identity', staticmethod(observed_identity)):
                with self.assertRaisesRegex(ValueError, 'UNKNOWN_BUILD_TARGET_OBJECT') as caught:
                    self.monitor.run([sys.executable, '-u', '-c',
                        'import os,time; print("real-hard-monitor-child",os.getpid(),flush=True); time.sleep(30)'], env)
            self.assertTrue(inserted)
            self.assertTrue(birth_seen.is_set())
            # Both rows are actually published by ComponentIO/V2Writer, not
            # reconstructed fixtures or a private/fabricated prepared record.
            step = json.loads((output/'build.step.json').read_text())
            context = io.writer.failure_context
            self.assertIsNotNone(context)
            self.assertEqual(step['returncode'], -9)
            self.assertFalse(step['complete_success'])
            self.assertEqual(context['returncode'], step['returncode'])
            owner = step['native_process_owner']
            self.assertEqual(context['native_process_owner'], owner)
            c.validate_owner_record(owner, -9)
            self.assertEqual(owner['spawn_count'], 1)
            self.assertEqual(owner['pid'], actual_birth['pid'])
            self.assertEqual(owner['birth_ticks'], actual_birth['birth_ticks'])
            self.assertEqual(owner['observed_ppid'], os.getpid())
            self.assertTrue(owner['reaped'])
            self.assertEqual(owner['wait_returncode'], -9)
            self.assertFalse(owner['original_identity_alive_after_wait'])
            monitor = context['build_monitor']
            self.assertEqual(monitor['first_monitor_error_type'], 'ValueError')
            self.assertEqual(monitor['first_monitor_error'], 'UNKNOWN_BUILD_TARGET_OBJECT')
            self.assertIsNone(monitor['first_monitor_errno'])
            self.assertTrue(monitor['pending_stop'])
            self.assertFalse(monitor['child_active'])
            self.assertFalse(monitor['watch_thread_alive'])
            self.assertGreaterEqual(monitor['kill_attempts'], 1)
            self.assertGreaterEqual(monitor['kill_delivered'], 1)
            self.assertEqual(monitor['actual_last_wait'], dict(pid=owner['pid'], returncode=-9))
            self.assertEqual(context['build_boundary_error'], 'UNKNOWN_BUILD_TARGET_OBJECT')
            self.assertEqual(io.writer.failure, 'COMPONENT_NATIVE_NONZERO')
            for flag in c.FULL_FLAGS:
                self.assertIs(context[flag], False)
            retained_context = deepcopy(context)
            io.writer.terminal('hard-build-monitor-diagnostic', caught.exception)
            terminal = json.loads((output/'outer-terminal.json').read_text())
            self.assertEqual(terminal['observed_step'], retained_context)
            self.assertEqual(terminal['first_error'], 'COMPONENT_NATIVE_NONZERO')
            self.assertFalse(terminal['qualification'])
            self.assertFalse(terminal['physical_enospc_terminal_guaranteed'])
            self.assertEqual(terminal['sync_calls_added'], 0)
            self.assertEqual(io.writer.failure, 'COMPONENT_NATIVE_NONZERO')
            self.observation.update(actual_native_process_owner=owner,
                actual_ComponentIO_step=step, actual_terminal=terminal,
                component_output_is_disjoint_from_target=True)
        finally:
            # Preserve actual available diagnostic rows even when an assertion
            # fails before the explicit terminal-publication checks above.
            self.observation.update(actual_failure_context=deepcopy(io.writer.failure_context),
                actual_first_writer_failure=io.writer.failure)
            for name in ('build.step.json', 'outer-terminal.json'):
                path = output/name
                if path.exists():
                    self.observation[name] = json.loads(path.read_text())
            io.writer.close()

    def test_continuous_real_create_unlink_exhausts_original_scan_bound(self):
        (self.target_path/'cargo-churn-a').write_bytes(b'a')
        original_fwalk, original_stat = os.fwalk, os.stat
        changes, vanished = 0, 0
        def fwalk(*args, **kwargs):
            nonlocal changes
            for item in original_fwalk(*args, **kwargs):
                parent, dirs, files, fd = item
                if parent == '.':
                    current = next((name for name in files if name.startswith('cargo-churn-')), None)
                    if current is not None:
                        other = 'cargo-churn-b' if current.endswith('-a') else 'cargo-churn-a'
                        os.unlink(current, dir_fd=fd)
                        fresh = os.open(other, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600, dir_fd=fd)
                        try:
                            os.write(fresh, b'x')
                        finally:
                            os.close(fresh)
                        changes += 1
                yield item
        def observed_stat(*args, **kwargs):
            nonlocal vanished
            try:
                return original_stat(*args, **kwargs)
            except FileNotFoundError as error:
                vanished += 1
                if vanished <= 4:
                    self.events.append(dict(operation='real-continuous-stat-ENOENT', **self.error_row(error)))
                raise
        started = time.monotonic()
        with patch.object(c.os, 'fwalk', fwalk), patch.object(c.os, 'stat', observed_stat):
            with self.assertRaisesRegex(ValueError, 'COMPONENT_BUILD_SCAN_BOUND_REACHED'):
                self.monitor.measure()
        self.observation.update(real_create_unlink_cycles=changes, actual_stat_ENOENT_count=vanished,
            measure_elapsed_seconds=time.monotonic()-started)
        self.assertGreater(changes, 1)
        self.assertGreater(vanished, 1)
        self.assert_rescan_recorded()

    def test_successful_empty_rescan_retains_real_partial_high_water(self):
        os.unlink('stable-output.o', dir_fd=self.target)
        size = 1024*1024
        (self.target_path/'large-output.o').write_bytes(b'b'*size)
        (self.target_path/'vanishing-output.o').write_bytes(b'v'*128)
        original_fwalk, original_stat = os.fwalk, os.stat
        removed, observed_large = False, 0
        def fwalk(*args, **kwargs):
            for parent, dirs, files, fd in original_fwalk(*args, **kwargs):
                # Enumeration order is unspecified. Choose an order containing
                # exactly the real names, so a large stat precedes the fault.
                ordered = sorted(files, key=lambda name: (name != 'large-output.o', name))
                yield parent, dirs, ordered, fd
        def observed_stat(name, *args, **kwargs):
            nonlocal removed, observed_large
            if name == 'vanishing-output.o' and observed_large and not removed:
                os.unlink('large-output.o', dir_fd=kwargs['dir_fd'])
                os.unlink('vanishing-output.o', dir_fd=kwargs['dir_fd'])
                removed = True
                self.events.append(dict(operation='real-delete-after-large-stat', actual_large_bytes=observed_large))
            try:
                info = original_stat(name, *args, **kwargs)
                if name == 'large-output.o':
                    observed_large = info.st_size
                return info
            except FileNotFoundError as error:
                self.events.append(dict(operation='real-partial-stat-ENOENT', **self.error_row(error)))
                raise
        with patch.object(c.os, 'fwalk', fwalk), patch.object(c.os, 'stat', observed_stat):
            total = self.monitor.measure()
        self.observation.update(large_actual_stat_bytes=observed_large, final_complete_scan_bytes=total)
        self.assertTrue(removed)
        self.assertEqual(observed_large, size)
        self.assertEqual(total, 0)
        self.assert_rescan_recorded()
        self.assertGreaterEqual(self.monitor.peak, size)

    def test_real_symlink_and_fifo_are_rejected_without_ENOENT_retry(self):
        for kind in ('symlink', 'fifo'):
            with self.subTest(kind=kind):
                path = self.target_path/'unknown-object'
                if kind == 'symlink':
                    os.symlink('stable-output.o', path)
                else:
                    os.mkfifo(path, 0o600)
                previous_retries = self.monitor.scan_retries
                previous_vanished = self.monitor.vanished_entries
                try:
                    with self.assertRaisesRegex(ValueError, 'UNKNOWN_BUILD_TARGET_OBJECT'):
                        self.monitor.measure()
                finally:
                    path.unlink()
                self.assertEqual(self.monitor.scan_retries, previous_retries)
                self.assertEqual(self.monitor.vanished_entries, previous_vanished)


if __name__ == '__main__':
    unittest.main(verbosity=2)
