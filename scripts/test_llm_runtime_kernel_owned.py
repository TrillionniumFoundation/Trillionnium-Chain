"""Controlled native build/refusal and owner-composition units; no model/cgroup setup.

Synthetic operation fixtures below test the Python owner's real wait4 only.
They do not qualify native birth placement or ordinary Hepta/FinalUse.
"""
import ctypes
import builtins
from contextlib import ExitStack
import errno
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import llm_runtime_pilot as runtime
import llm_runtime_kernel_owned as kernel


@unittest.skipUnless(sys.platform == 'linux' and sys.implementation.name == 'cpython'
    and sys.version_info[:3] == (3, 12, 3), 'controlled native requires CPython 3.12.3')
class KernelOwnedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = kernel.build_controlled_native()

    @classmethod
    def tearDownClass(cls):
        cls.native.close()

    def synthetic_cap(self):
        cap = object.__new__(kernel._ControlledOperation)
        cap.memory = 8*1024**3; cap.native = self.native; cap.spawn_owner = None
        return cap

    def bind_spawn(self, cap, pid, fd):
        def bind(command, output, owner):
            cap.spawn_owner = owner
            owner._kernel_handoff[:] = (pid, fd, -1, -1)
        cap.spawn = Mock(side_effect=bind)

    def native_fixture(self, cap, children):
        """Synthetic native output backed by tiny own children, never cgroups."""
        cap.consumed = False; cap._verify_locked = Mock(); cap.nodes = [(None, -1, None, None)]
        cap.allow_exec = Mock(side_effect=lambda owner, deadline: owner._close_kernel_handoff(12))
        cap.terminal_record = Mock()
        def spawn(group, output, exe, argv, env, result):
            self.assertIs(result, cap.spawn_owner._kernel_handoff)
            ack = os.pipe2(os.O_CLOEXEC); error = os.pipe2(os.O_CLOEXEC)
            child = subprocess.Popen([sys.executable, '-c', f'import os; os.read({ack[0]}, 1)'],
                pass_fds=(ack[0], error[1]), stdout=subprocess.DEVNULL)
            children.append(child)
            result[:] = (child.pid, os.pidfd_open(child.pid), ack[1], error[0])
            os.close(ack[0]); os.close(error[1])
            return 0
        return spawn

    def assert_collected(self, cap, children):
        owner = cap.spawn_owner
        self.assertTrue(owner.reaped)
        self.assertEqual(list(owner._kernel_handoff)[1:], [-1, -1, -1])
        for child in children:
            with self.assertRaises(ChildProcessError): os.waitpid(child.pid, os.WNOHANG)
            child.returncode = 0

    def test_build_binds_actual_sources_and_sealed_library_not_caller_hash(self):
        self.assertEqual(self.native.sources, kernel._sources())
        self.assertIn('llm_runtime_kernel_spawn.c', self.native.sources)
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        self.assertEqual(fcntl.fcntl(self.native.fd, fcntl.F_GET_SEALS), seals)
        with self.assertRaises(OSError): os.write(self.native.fd, b'changed')
        with self.assertRaisesRegex(ValueError, 'native-constructor'):
            kernel._Native(object(), b'not a trusted library', {})

    def test_ordinary_path_never_imports_native_kernel_module(self):
        original = builtins.__import__
        def reject(name, *args, **kwargs):
            if name == 'llm_runtime_kernel_owned': raise AssertionError('ordinary dependency changed')
            return original(name, *args, **kwargs)
        with tempfile.TemporaryDirectory() as temporary, patch.object(builtins, '__import__', side_effect=reject):
            result = runtime.supervise(['/bin/true'], Path(temporary)/'ordinary',
                dict(wall_seconds=2, rss_bytes=8*1024**3))
        self.assertEqual(result['outcome'], 'success')
        self.assertNotIn('controlled_kernel_spawn', result)

    def test_actual_native_invalid_cgroup_fd_refuses_without_child_or_fallback(self):
        # Real syscall, invalid FD: no child can enter user code or a resource group.
        result = (ctypes.c_int*4)()
        argv = (ctypes.c_char_p*2)(b'/bin/true', None)
        env = (ctypes.c_char_p*1)(None)
        with open(os.devnull, 'wb') as output:
            error = self.native.spawn(-1, output.fileno(), b'/bin/true', argv, env, result)
        self.assertGreater(error, 0)
        self.assertEqual(tuple(result), (0, 0, 0, 0))

    def test_dto_constructor_boolean_memory_and_missing_unit_environment_refuse(self):
        args = dict(unit='controlled.service', invocation='1'*32,
            operation='/not-a-group', memory_bytes=8*1024**3, owner=object())
        with self.assertRaisesRegex(ValueError, 'capability-constructor'):
            kernel.acquire_controlled_operation({}, **args)
        for memory in (True, 16*1024**3+1):
            with self.subTest(memory=memory), self.assertRaisesRegex(ValueError, 'memory-ceiling'):
                kernel.acquire_controlled_operation(self.native, **dict(args, memory_bytes=memory))
        with patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(ValueError, 'kernel-invocation'):
            kernel.acquire_controlled_operation(self.native, **args)

    def fixture(self, directory):
        cap = object.__new__(kernel._ControlledOperation)
        cap.native = self.native; cap.memory = 8*1024**3
        cap.closed = False
        cap.failed = cap.consumed = False; cap.child = None; cap.owner = object()
        cap.unit = 'fixture.service'; cap.invocation = '1'*32
        cap.membership = Path('/proc/self/cgroup').read_text()
        cap.boot = Path('/proc/sys/kernel/random/boot_id').read_text()
        cap.unit_path = kernel._ROOT/'fixture.service'
        cap.operation = Path(directory)
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        values = {'memory.max': str(cap.memory)+'\n'}
        for name, value in values.items(): (cap.operation/name).write_text(value)
        cap.nodes = [(cap.operation, fd, kernel.proc._signature(fd), values)]
        fields = dict(InvocationID=cap.invocation, ControlGroup='/fixture.service',
            MainPID=str(os.getpid()), Delegate='yes', DelegateSubgroup='supervisor')
        observed = SimpleNamespace(returncode=0, stdout=''.join(k+'='+v+'\n' for k,v in fields.items()))
        return cap, observed

    def test_unit_invocation_change_is_sticky_and_cannot_be_repaired_by_later_dto(self):
        with tempfile.TemporaryDirectory() as temporary:
            cap, observed = self.fixture(temporary)
            bad = SimpleNamespace(returncode=0, stdout=observed.stdout.replace('1'*32, '2'*32))
            with patch.object(kernel.subprocess, 'run', return_value=bad), self.assertRaisesRegex(ValueError, 'unit-identity'):
                cap.verify()
            with patch.object(kernel.subprocess, 'run', return_value=observed), self.assertRaisesRegex(ValueError, 'sticky'):
                cap.verify()

    def test_changed_limit_or_same_name_directory_replacement_refuses(self):
        for mode in ('limit', 'directory', 'fd'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary)/'operation'; path.mkdir()
                cap, observed = self.fixture(path)
                if mode == 'limit': (path/'memory.max').write_text('max\n')
                elif mode == 'directory': path.rename(Path(temporary)/'old'); path.mkdir()
                else:
                    other = Path(temporary)/'other'; other.mkdir()
                    replace = os.open(other, os.O_RDONLY | os.O_DIRECTORY)
                    try: os.dup2(replace, cap.nodes[0][1])
                    finally: os.close(replace)
                with patch.object(kernel.subprocess, 'run', return_value=observed), self.assertRaises(ValueError):
                    cap.verify()
                self.assertTrue(cap.failed)

    def test_wrong_waited_owner_or_descendants_cannot_emit_empty_terminal_record(self):
        for wrong_owner in (True, False):
            with self.subTest(wrong_owner=wrong_owner), tempfile.TemporaryDirectory() as temporary:
                cap, observed = self.fixture(temporary)
                fd = cap.nodes[0][1]
                cap.child = (1, fd, kernel.proc._signature(fd))
                (cap.operation/'cgroup.procs').write_text('123\n')
                with patch.object(kernel.subprocess, 'run', return_value=observed), self.assertRaisesRegex(
                        ValueError, 'owner-changed' if wrong_owner else 'descendants-remain'):
                    cap.terminal_record(2 if wrong_owner else 1, fd)
                self.assertTrue(cap.failed)

    def test_live_native_source_change_is_sticky_even_if_restored(self):
        with tempfile.TemporaryDirectory() as temporary:
            cap, observed = self.fixture(temporary)
            changed = dict(self.native.sources, **{'llm_runtime_kernel_spawn.c': '0'*64})
            with patch.object(kernel, '_sources', return_value=changed), \
                    patch.object(kernel.subprocess, 'run', return_value=observed), \
                    self.assertRaisesRegex(ValueError, 'source-or-owner-moved'):
                cap.verify()
            with self.assertRaisesRegex(ValueError, 'sticky'): cap.verify()

    def test_original_python_owner_reaps_real_child_and_outer_result_stays_failed(self):
        # Controlled fixture for composition only. Native valid-cgroup spawn is NOT_RUN here.
        child = subprocess.Popen([sys.executable, '-c', 'pass'], stdout=subprocess.DEVNULL)
        fd = os.pidfd_open(child.pid)
        cap = self.synthetic_cap(); self.bind_spawn(cap, child.pid, fd)
        cap.allow_exec = Mock()
        cap.terminal_record = Mock(return_value=dict(reservation='RETAINED', outer_reconciliation='UNKNOWN'))
        try:
            with tempfile.TemporaryDirectory() as temporary, \
                    patch.object(subprocess.Popen, '__init__', side_effect=AssertionError('no Popen fallback')):
                result = runtime.supervise([sys.executable, '-c', 'pass'], Path(temporary)/'run',
                    dict(wall_seconds=2, rss_bytes=cap.memory), _controlled_operation=cap)
            self.assertEqual(result['exit_code'], 0)
            self.assertTrue(result['waited_child_reaped'])
            self.assertGreater(result['waited_child_peak_rss_bytes'], 0)
            self.assertEqual(result['outcome'], 'failed')
            self.assertEqual(result['stop_reason'], 'kernel-outer-reconciliation-required')
            self.assertEqual(result['controlled_kernel_spawn']['reservation'], 'RETAINED')
            cap.terminal_record.assert_called_once_with(child.pid, fd)
        finally:
            # On assertion/setup failure still collect only our fixture child.
            try:
                if os.waitpid(child.pid, os.WNOHANG)[0] == 0:
                    child.kill(); os.waitpid(child.pid, 0)
            except ChildProcessError: pass  # Exact _Wait4Child already owns the receipt.
            child.returncode = 0
            try: os.close(fd)
            except OSError: pass

    def test_unknown_or_cleanup_only_wait_never_calls_kernel_terminal(self):
        for fault in ('unknown', 'waitpid', 'invalid-receipt'):
            with self.subTest(fault=fault):
                owner = object.__new__(runtime._Wait4Child)
                owner.owned_exit_observed = owner.reap_resolved = True
                owner.reaped = fault != 'unknown'
                owner.cleanup_method = 'waitpid-after-wait4-fault' if fault == 'waitpid' else 'wait4'
                owner.observation_error = 'invalid-terminal-receipt' if fault == 'invalid-receipt' else None
                owner.termination_fd = owner.kernel_evidence = None
                owner.kernel_operation = SimpleNamespace(terminal_record=Mock())
                owner.finish()
                owner.kernel_operation.terminal_record.assert_not_called()

    def test_failed_gate_keeps_original_owner_for_real_child_cleanup(self):
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(1)'], stdout=subprocess.DEVNULL)
        fd = os.pidfd_open(child.pid)
        cap = self.synthetic_cap(); self.bind_spawn(cap, child.pid, fd)
        cap.allow_exec = Mock(side_effect=ValueError('refused membership'))
        cap.terminal_record = Mock()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                result = runtime.supervise(['/bin/true'], Path(temporary)/'run',
                    dict(wall_seconds=2, rss_bytes=cap.memory), _controlled_operation=cap)
            self.assertTrue(result['waited_child_reaped'])
            self.assertEqual(result['outcome'], 'failed')
            self.assertEqual(result['waited_child_observation_error'], 'kernel-spawn-handoff-failed')
            cap.terminal_record.assert_not_called()
        finally:
            try:
                if os.waitpid(child.pid, os.WNOHANG)[0] == 0:
                    child.kill(); os.waitpid(child.pid, 0)
            except ChildProcessError: pass
            child.returncode = 0
            try: os.close(fd)
            except OSError: pass

    def test_spawn_refusal_and_dto_never_start_ordinary_popen(self):
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(subprocess.Popen, '__init__', side_effect=AssertionError('no fallback')):
            with self.assertRaisesRegex(ValueError, 'KERNEL_BUDGET_INTERFACE'):
                runtime.supervise(['/bin/true'], Path(temporary)/'dto', dict(wall_seconds=1,rss_bytes=8*1024**3),
                    _controlled_operation={'pid':123})
            cap = self.synthetic_cap()
            cap.spawn = Mock(side_effect=OSError(13, 'actual native refusal'))
            for wall in (True, 601, 0):
                with self.subTest(wall=wall), self.assertRaisesRegex(ValueError, 'KERNEL_BUDGET_INTERFACE'):
                    runtime.supervise(['/bin/true'], Path(temporary)/str(wall),
                        dict(wall_seconds=wall, rss_bytes=cap.memory), _controlled_operation=cap)
            with self.assertRaises(OSError):
                runtime.supervise(['/bin/true'], Path(temporary)/'refuse', dict(wall_seconds=1,rss_bytes=cap.memory),
                    _controlled_operation=cap)

    def test_spawn_handoff_fault_matrix_keeps_real_child_owned_and_closes_all_fds(self):
        stages = ('native-return', 'spawn-return', 'pid-assignment', 'fd-assignment',
                  'gate-enter', 'gate-return', 'constructor-return')
        for stage in stages:
            for problem in (KeyboardInterrupt, MemoryError, BaseException):
                with self.subTest(stage=stage, problem=problem.__name__), tempfile.TemporaryDirectory() as temporary:
                    before = set(os.listdir('/proc/self/fd'))
                    cap = self.synthetic_cap(); children = []
                    native = self.native_fixture(cap, children)
                    original_spawn = cap.spawn; original_adopt = runtime._Wait4Child._adopt_kernel_handoff
                    original_init = runtime._Wait4Child.__init__; calls = []
                    def injected_native(*args):
                        result = native(*args)
                        if stage == 'native-return': raise problem('after native result')
                        return result
                    def injected_spawn(*args):
                        original_spawn(*args)
                        raise problem('after spawn return')
                    def injected_adopt(owner):
                        calls.append(True)
                        if len(calls) == 1:
                            owner.pid = owner._kernel_handoff[0]
                            if stage == 'fd-assignment': original_adopt(owner)
                            raise problem('field assignment')
                        original_adopt(owner)
                    def injected_gate(owner, deadline):
                        if stage == 'gate-return': owner._close_kernel_handoff(12)
                        raise problem('gate')
                    def injected_init(owner, *args, **kwargs):
                        original_init(owner, *args, **kwargs)
                        raise problem('constructor return')
                    try:
                        with ExitStack() as stack:
                            stack.enter_context(patch.object(self.native, 'spawn', side_effect=injected_native))
                            if stage == 'spawn-return': cap.spawn = injected_spawn
                            if stage in ('pid-assignment', 'fd-assignment'):
                                stack.enter_context(patch.object(runtime._Wait4Child, '_adopt_kernel_handoff', injected_adopt))
                            if stage.startswith('gate-'): cap.allow_exec.side_effect = injected_gate
                            if stage == 'constructor-return':
                                stack.enter_context(patch.object(runtime._Wait4Child, '__init__', injected_init))
                            try:
                                result = runtime.supervise(['/bin/true'], Path(temporary)/'run',
                                    dict(wall_seconds=2, rss_bytes=cap.memory), _controlled_operation=cap)
                                self.assertEqual(result['outcome'], 'failed')
                            except BaseException as error:
                                self.assertIsInstance(error, problem)
                        self.assert_collected(cap, children)
                        self.assertEqual(set(os.listdir('/proc/self/fd')), before)
                        print(json.dumps(dict(scope='synthetic-native-output-real-own-child',
                            stage=stage, exception=problem.__name__, owner_reaped=True,
                            native_fd_slots_closed=True, fd_inventory_unchanged=True), sort_keys=True))
                    finally:
                        if cap.spawn_owner is not None and not cap.spawn_owner.reap_resolved:
                            cap.spawn_owner._rollback_kernel_handoff()
                        for child in children: child.returncode = 0

    def test_persistent_allocation_failure_throws_prebuilt_owner_then_reconciles(self):
        cap = self.synthetic_cap(); children = []; before = set(os.listdir('/proc/self/fd'))
        native = self.native_fixture(cap, children)
        with tempfile.TemporaryDirectory() as temporary, patch.object(self.native, 'spawn', side_effect=native), \
                patch.object(runtime._Wait4Child, '_adopt_kernel_handoff', side_effect=MemoryError('persistent')):
            with self.assertRaises(runtime._OwnedChildCleanupRequired) as caught:
                runtime.supervise(['/bin/true'], Path(temporary)/'run',
                    dict(wall_seconds=2, rss_bytes=cap.memory), _controlled_operation=cap)
        self.assertIs(caught.exception, cap.spawn_owner._kernel_cleanup_required)
        self.assertIs(caught.exception.child, cap.spawn_owner)
        self.assertEqual(caught.exception.receipt['reservation'], 'RETAINED')
        self.assertGreater(cap.spawn_owner._kernel_handoff[1], 0)
        print(json.dumps(dict(stage='persistent-adopt-allocation', retained_exception_owner=True,
            capability_strong_owner=True, pidfd_retained=True, reservation='RETAINED')))
        cap.spawn_owner._rollback_kernel_handoff()
        self.assert_collected(cap, children)
        self.assertEqual(set(os.listdir('/proc/self/fd')), before)

    def test_persistent_unknown_wait_keeps_terminal_child_and_pidfd_with_original_owner(self):
        cap = self.synthetic_cap(); children = []; before = set(os.listdir('/proc/self/fd'))
        native = self.native_fixture(cap, children)
        cap.allow_exec.side_effect = MemoryError('after native success')
        with tempfile.TemporaryDirectory() as temporary, patch.object(self.native, 'spawn', side_effect=native), \
                patch.object(runtime.os, 'wait4', side_effect=OSError(errno.EIO, 'unknown wait4')), \
                patch.object(runtime.os, 'waitpid', side_effect=OSError(errno.EIO, 'unknown cleanup')):
            with self.assertRaises(runtime._OwnedChildCleanupRequired) as caught:
                runtime.supervise(['/bin/true'], Path(temporary)/'run',
                    dict(wall_seconds=2, rss_bytes=cap.memory), _controlled_operation=cap)
        owner = cap.spawn_owner
        self.assertIs(caught.exception.child, owner)
        self.assertFalse(owner.reap_resolved)
        self.assertTrue(owner.owned_exit_observed)
        os.fstat(owner._kernel_handoff[1])
        self.assertEqual(owner.waited_peak_rss_bytes, None)
        print(json.dumps(dict(stage='persistent-unknown-wait4', kernel_exit_observed=True,
            exact_terminal_wait='UNKNOWN', pidfd_retained=True, waited_rss_credit=None,
            capability_strong_owner=True, reservation='RETAINED')))
        owner._rollback_kernel_handoff()
        self.assert_collected(cap, children)
        self.assertEqual(set(os.listdir('/proc/self/fd')), before)

    def test_signal_after_native_gate_close_cannot_close_reused_descriptor(self):
        for interrupted_mask in (12, 2):
            with self.subTest(mask=interrupted_mask):
                cap = self.synthetic_cap(); children = []; replacements = []
                native = self.native_fixture(cap, children); close = self.native.close_handoff
                def interrupted_close(result, mask):
                    target = result[2 if mask == 12 else 1]
                    error = close(result, mask)
                    if mask == interrupted_mask and target >= 0 and not replacements:
                        fresh = os.open(os.devnull, os.O_RDONLY)
                        if fresh != target: os.dup2(fresh, target); os.close(fresh)
                        replacements.append(target)
                        raise KeyboardInterrupt('close completed before pending signal')
                    return error
                try:
                    with tempfile.TemporaryDirectory() as temporary, patch.object(self.native, 'spawn', side_effect=native), \
                            patch.object(self.native, 'close_handoff', side_effect=interrupted_close):
                        with self.assertRaises((KeyboardInterrupt, runtime._OwnedChildCleanupRequired)):
                            runtime.supervise(['/bin/true'], Path(temporary)/'run',
                                dict(wall_seconds=2, rss_bytes=cap.memory), _controlled_operation=cap)
                    cap.spawn_owner._rollback_kernel_handoff()
                    self.assert_collected(cap, children)
                    os.fstat(replacements[0])
                    print(json.dumps(dict(stage='signal-after-native-close', mask=interrupted_mask,
                        original_child_collected=True, reused_exact_fd_still_open=True)))
                finally:
                    if cap.spawn_owner is not None and not cap.spawn_owner.reap_resolved:
                        cap.spawn_owner._rollback_kernel_handoff()
                    for child in children: child.returncode = 0
                    for fd in replacements: os.close(fd)


if __name__ == '__main__': unittest.main()
