"""Controlled native build/refusal and owner-composition units; no model/cgroup setup.

Synthetic operation fixtures below test the Python owner's real wait4 only.
They do not qualify native birth placement or ordinary Hepta/FinalUse.
"""
import ctypes
import builtins
import fcntl
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


@unittest.skipUnless(sys.platform == 'linux', 'Linux-only controlled native interface')
class KernelOwnedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = kernel.build_controlled_native()

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
        cap = object.__new__(kernel._ControlledOperation); cap.memory = 8*1024**3
        cap.spawn = Mock(return_value=(child.pid, fd, -1, -1))
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
        cap = object.__new__(kernel._ControlledOperation); cap.memory = 8*1024**3
        cap.spawn = Mock(return_value=(child.pid, fd, -1, -1))
        cap.allow_exec = Mock(side_effect=ValueError('refused membership'))
        cap.terminal_record = Mock()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                result = runtime.supervise(['/bin/true'], Path(temporary)/'run',
                    dict(wall_seconds=2, rss_bytes=cap.memory), _controlled_operation=cap)
            self.assertTrue(result['waited_child_reaped'])
            self.assertEqual(result['outcome'], 'failed')
            self.assertEqual(result['waited_child_observation_error'], 'kernel-spawn:ValueError')
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
            cap = object.__new__(kernel._ControlledOperation); cap.memory = 8*1024**3
            cap.spawn = Mock(side_effect=OSError(13, 'actual native refusal'))
            for wall in (True, 601, 0):
                with self.subTest(wall=wall), self.assertRaisesRegex(ValueError, 'KERNEL_BUDGET_INTERFACE'):
                    runtime.supervise(['/bin/true'], Path(temporary)/str(wall),
                        dict(wall_seconds=wall, rss_bytes=cap.memory), _controlled_operation=cap)
            with self.assertRaises(OSError):
                runtime.supervise(['/bin/true'], Path(temporary)/'refuse', dict(wall_seconds=1,rss_bytes=cap.memory),
                    _controlled_operation=cap)


if __name__ == '__main__': unittest.main()
