"""Owned ordinary FDs and invalid-cgroup refusal only; valid placement NOT_RUN."""
import ctypes
from concurrent.futures import ThreadPoolExecutor
import errno
import inspect
import os
from pathlib import Path
import sys
import signal
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import llm_runtime_kernel_owned as kernel
import llm_runtime_pilot as runtime


@unittest.skipUnless(sys.platform == 'linux' and sys.implementation.name == 'cpython'
    and sys.version_info[:3] == (3, 12, 3), 'controlled native requires CPython 3.12.3')
class KernelCloseTests(unittest.TestCase):
    def setUp(self):
        self.native = kernel.build_controlled_native()
        self.temporary = tempfile.TemporaryDirectory()
        self.cap = None
        self.addCleanup(self.cleanup_fixture)

    def cleanup_fixture(self):
        # Synthetic fixtures never create a child or cgroup. Resolve their own
        # remaining ordinary FDs without pretending this is an outer receipt.
        if self.cap is not None:
            for slot in self.cap._fd_owners:
                if slot[1] >= 0:
                    self.native.release_owned(slot)
            self.native.operation = None
        if self.native.fd >= 0:
            self.native.release_owned(self.native._fd_owner)
        self.temporary.cleanup()

    def fixture(self, count=2, kind=kernel._ControlledOperation):
        cap = object.__new__(kind)
        cap.native = self.native; cap.owner = object()
        cap.closed = cap.consumed = cap.native_refused_without_child = False
        cap.spawn_owner = None; cap.nodes = []; cap._verify_locked = Mock()
        cap._fd_owners = [(ctypes.c_int*4)(0, -1, -1, -1) for _ in range(16)]
        for i in range(count):
            path = Path(self.temporary.name)/str(i); path.mkdir(exist_ok=True)
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            cap._fd_owners[i][1] = fd
            cap.nodes.append((path, fd, kernel.proc._signature(fd), {}))
        self.native.operation = self.cap = cap
        return cap

    def test_unconsumed_close_is_idempotent_and_native_cannot_close_first(self):
        cap = self.fixture()
        with self.assertRaisesRegex(ValueError, 'close-owner'): cap.close(object())
        with self.assertRaisesRegex(ValueError, 'operation-retained'): self.native.close()
        for _, fd, _, _ in cap.nodes: os.fstat(fd)
        cap.close(cap.owner); cap.close(cap.owner)
        self.assertTrue(cap.closed); self.assertIsNone(self.native.operation)
        self.assertTrue(all(slot[1] == -1 for slot in cap._fd_owners))
        self.native.close(); self.native.close()
        self.assertEqual(self.native.fd, -1)

    def test_one_fixed_native_slot_refuses_another_capability(self):
        cap = self.fixture()
        with self.assertRaisesRegex(ValueError, 'operation-retained'):
            kernel.acquire_controlled_operation(self.native, unit='other.service',
                invocation='1'*32, operation='/not-a-cgroup', memory_bytes=8*1024**3, owner=object())
        self.assertIs(self.native.operation, cap)

    def test_actual_invalid_group_refusal_proves_no_child_then_closes(self):
        cap = self.fixture(1)
        child_owner = SimpleNamespace(kernel_operation=cap,
            _kernel_handoff=(ctypes.c_int*4)(-1, -1, -1, -1))
        with open(os.devnull, 'wb') as output, self.assertRaises(OSError):
            cap.spawn(['/bin/true'], output, child_owner)
        self.assertTrue(cap.consumed)
        self.assertTrue(cap.native_refused_without_child)
        self.assertEqual(list(child_owner._kernel_handoff), [-1]*4)
        cap.close(cap.owner)
        self.assertTrue(cap.closed); self.assertIsNone(cap.spawn_owner)

    def test_consumed_unknown_or_terminal_dto_never_permits_close(self):
        cap = self.fixture()
        cap.consumed = True
        cap.spawn_owner = SimpleNamespace(_kernel_handoff=(ctypes.c_int*4)(123, -1, -1, -1),
            reaped=True, reap_resolved=True, outer_reconciliation='success', reservation='RELEASED')
        for _ in range(2):
            with self.assertRaisesRegex(ValueError, 'outer-reconciliation-required'): cap.close(cap.owner)
        self.assertIs(self.native.operation, cap)
        self.assertIsNotNone(cap.spawn_owner)
        self.assertFalse(cap.closed)
        for _, fd, _, _ in cap.nodes: os.fstat(fd)

    def test_interrupted_native_return_does_not_invent_no_child_proof(self):
        cap = self.fixture(1)
        child_owner = SimpleNamespace(kernel_operation=cap,
            _kernel_handoff=(ctypes.c_int*4)(-1, -1, -1, -1))
        with patch.object(self.native, 'spawn', side_effect=KeyboardInterrupt), \
                open(os.devnull, 'wb') as output, self.assertRaises(KeyboardInterrupt):
            cap.spawn(['/bin/true'], output, child_owner)
        self.assertFalse(cap.native_refused_without_child)
        with self.assertRaisesRegex(ValueError, 'outer-reconciliation-required'): cap.close(cap.owner)
        self.assertIs(cap.spawn_owner, child_owner)

    def test_cap_close_after_native_signal_or_allocation_fault_never_closes_reused_fd(self):
        for fault, position in ((f, n) for f in (KeyboardInterrupt, MemoryError, BaseException) for n in (1, 2)):
            with self.subTest(fault=fault.__name__, position=position):
                cap = self.fixture()
                real = self.native.release_owned; replacement = []; calls = []
                def interrupted(slot):
                    old = slot[1]; real(slot)
                    calls.append(old)
                    if len(calls) != position: return
                    other = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
                    if other != old:
                        os.dup2(other, old); os.close(other)
                    replacement.append(old)
                    raise fault('after-native-close')
                with patch.object(self.native, 'release_owned', side_effect=interrupted), self.assertRaises(fault):
                    cap.close(cap.owner)
                self.assertIs(self.native.operation, cap)
                cap.close(cap.owner)
                self.assertTrue(cap.closed)
                for fd in replacement: os.fstat(fd); os.close(fd)

    def native_close_fault(self, fault):
        real = self.native.release_owned; old = self.native.fd
        def interrupted(slot):
            real(slot)
            other = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
            if other != old:
                os.dup2(other, old); os.close(other)
            raise fault('after-native-memfd-close')
        try:
            with patch.object(self.native, 'release_owned', side_effect=interrupted), self.assertRaises(fault):
                self.native.close()
            self.assertEqual(self.native.fd, -1)
            self.native.close(); os.fstat(old)
        finally:
            os.close(old)

    def test_native_memfd_close_keyboardinterrupt_is_idempotent(self):
        self.native_close_fault(KeyboardInterrupt)

    def test_native_memfd_close_memoryerror_is_idempotent(self):
        self.native_close_fault(MemoryError)

    def test_native_memfd_close_baseexception_is_idempotent(self):
        self.native_close_fault(BaseException)

    def test_replaced_ancestor_or_native_fd_refuses_without_closing_replacement(self):
        cap = self.fixture()
        other = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
        try:
            os.dup2(other, cap.nodes[0][1])
            with self.assertRaisesRegex(ValueError, 'fd-replaced'): cap.close(cap.owner)
            self.assertIs(self.native.operation, cap)
            os.fstat(cap.nodes[1][1]); os.fstat(cap.nodes[0][1])
        finally:
            os.close(other)
        # Native owns a memfd, so a different ordinary file must never be closed.
        self.native.operation = None
        other = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
        try:
            os.dup2(other, self.native.fd)
            with self.assertRaisesRegex(ValueError, 'native-fd-replaced'): self.native.close()
            os.fstat(self.native.fd)
        finally:
            os.close(other)

    def test_persistent_close_errno_keeps_slot_and_native_owner_reachable(self):
        cap = self.fixture(); real = self.native.release_owned
        def failed(slot):
            real(slot); slot[0] = errno.EIO
            raise MemoryError('after-persisted-close-error')
        with patch.object(self.native, 'release_owned', side_effect=failed), self.assertRaises(MemoryError):
            cap.close(cap.owner)
        self.assertEqual(cap._fd_owners[0][0], errno.EIO)
        with self.assertRaisesRegex(ValueError, 'owned-close-failed'): cap.close(cap.owner)
        self.assertIs(self.native.operation, cap); self.assertFalse(cap.closed)
        os.fstat(cap._fd_owners[1][1])

    def test_native_close_errno_is_sticky_after_slot_is_cleared(self):
        real = self.native.release_owned
        def failed(slot):
            real(slot); slot[0] = errno.EIO
            raise MemoryError('after-persisted-native-close-error')
        with patch.object(self.native, 'release_owned', side_effect=failed), self.assertRaises(MemoryError):
            self.native.close()
        self.assertEqual(self.native.fd, -1)
        with self.assertRaisesRegex(ValueError, 'native-close-failed'): self.native.close()

    def test_signal_after_closed_mark_can_finish_same_slot_without_double_close(self):
        class FaultCap(kernel._ControlledOperation):
            def __setattr__(self, name, value):
                object.__setattr__(self, name, value)
                if name == 'closed' and value and not getattr(self, 'fired', False):
                    object.__setattr__(self, 'fired', True)
                    raise KeyboardInterrupt('after-closed-mark')
        cap = self.fixture(kind=FaultCap)
        with self.assertRaises(KeyboardInterrupt): cap.close(cap.owner)
        self.assertTrue(cap.closed); self.assertIs(self.native.operation, cap)
        cap.close(cap.owner)
        self.assertIsNone(self.native.operation)

    def acquisition(self):
        return kernel.acquire_controlled_operation(self.native, unit='unit.service',
            invocation='1'*32, operation='/sys/fs/cgroup/user.slice/unit.service/operation-'+'2'*32,
            memory_bytes=8*1024**3, owner=object())

    def test_review_double_acquire_race_foreign_threads_refuse_before_any_io(self):
        # Original review red: both crossed the empty-slot check during proc IO,
        # then one live cap was overwritten. New ABI refuses before that IO.
        fd = self.native.fd
        with patch.object(Path, 'read_text', side_effect=AssertionError('no foreign IO')), \
                patch.object(kernel.os, 'open', side_effect=AssertionError('no foreign FD')), \
                ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(self.acquisition) for _ in range(2)]
            for future in futures:
                with self.assertRaisesRegex(ValueError, 'owner-thread'): future.result(timeout=2)
        self.assertIsNone(self.native.operation); self.assertEqual(self.native.fd, fd)
        os.fstat(fd)

    def test_review_close_acquire_race_cannot_register_during_owner_close(self):
        # Original review red: Native.close passed None, then an acquisition
        # registered before signature returned; close destroyed its memfd.
        original = kernel.proc._signature
        with ThreadPoolExecutor(max_workers=1) as pool:
            def paused(fd):
                future = pool.submit(self.acquisition)
                with self.assertRaisesRegex(ValueError, 'owner-thread'): future.result(timeout=2)
                self.assertIsNone(self.native.operation)
                return original(fd)
            with patch.object(kernel.proc, '_signature', side_effect=paused): self.native.close()
        self.assertEqual(self.native.fd, -1); self.assertIsNone(self.native.operation)

    def test_foreign_cap_and_native_operations_reject_without_slot_mutation(self):
        cap = self.fixture(); before = [list(slot) for slot in cap._fd_owners]
        operations = [self.native.close, cap.verify, lambda: cap.close(cap.owner),
            lambda: cap.spawn(['/bin/true'], None, None), lambda: cap.allow_exec(None, 1.0),
            lambda: cap.terminal_record(0, 0)]
        with ThreadPoolExecutor(max_workers=1) as pool:
            for operation in operations:
                with self.assertRaisesRegex(ValueError, 'owner-thread'):
                    pool.submit(operation).result(timeout=2)
        self.assertEqual([list(slot) for slot in cap._fd_owners], before)
        self.assertIs(self.native.operation, cap); self.assertFalse(cap.closed or cap.consumed)

    def test_process_identity_change_refuses_inherited_native_handle(self):
        with patch.object(kernel.os, 'getpid', return_value=os.getpid()+1):
            with self.assertRaisesRegex(ValueError, 'owner-thread'): self.native.close()
            with self.assertRaisesRegex(ValueError, 'owner-thread'): self.acquisition()
        os.fstat(self.native.fd); self.assertIsNone(self.native.operation)

    def signal_reentry(self):
        errors = []
        def handler(signum, frame):
            for action in (self.native.close, self.acquisition):
                try: action()
                except kernel.KernelBudgetError as error: errors.append(str(error))
                else: self.fail('signal handler changed lifecycle state')
        return errors, handler

    def test_real_signal_during_acquisition_refuses_reentry_and_cleanup_uses_same_lock(self):
        errors, handler = self.signal_reentry(); original = Path.read_text
        def synthetic_read(path, *args, **kwargs):
            if str(path) == '/proc/self/cgroup':
                os.kill(os.getpid(), signal.SIGUSR1)
                return '0::/user.slice/unit.service/supervisor\n'
            if str(path) == '/proc/sys/kernel/random/boot_id': return 'synthetic-boot\n'
            return original(path, *args, **kwargs)
        previous = signal.signal(signal.SIGUSR1, handler)
        try:
            with patch.dict(os.environ, {'INVOCATION_ID':'1'*32}), \
                    patch.object(Path, 'read_text', synthetic_read), \
                    patch.object(kernel.os, 'open', side_effect=OSError('stop before real FD')), \
                    self.assertRaisesRegex(OSError, 'stop before real FD'):
                self.acquisition()
        finally: signal.signal(signal.SIGUSR1, previous)
        self.assertEqual(errors, ['kernel-native-lifecycle-busy']*2)
        self.assertIsNone(self.native.operation); os.fstat(self.native.fd)
        self.native.close()  # Failed acquisition did not leave the guard busy.

    def test_real_signal_during_native_close_refuses_nested_acquire_and_close(self):
        errors, handler = self.signal_reentry(); original = kernel.proc._signature
        def paused(fd):
            os.kill(os.getpid(), signal.SIGUSR1)
            return original(fd)
        previous = signal.signal(signal.SIGUSR1, handler)
        try:
            with patch.object(kernel.proc, '_signature', side_effect=paused): self.native.close()
        finally: signal.signal(signal.SIGUSR1, previous)
        self.assertEqual(errors, ['kernel-native-lifecycle-busy']*2)
        self.assertIsNone(self.native.operation); self.assertEqual(self.native.fd, -1)

    def test_cap_close_and_spawn_share_the_same_nonreentrant_guard(self):
        cap = self.fixture()
        cap._verify_locked.side_effect = lambda: cap.close(cap.owner)
        with patch.object(self.native, 'spawn') as spawn, self.assertRaisesRegex(ValueError, 'lifecycle-busy'):
            cap.spawn(['/bin/true'], None, None)
        spawn.assert_not_called()
        self.assertFalse(cap.consumed or cap.closed)
        self.assertIs(self.native.operation, cap)
        cap.close(cap.owner)

    def interrupt_first_native_with_body(self, method, action):
        lines, start = inspect.getsourcelines(method)
        protected_line = start + next(i for i, line in enumerate(lines) if 'with ' in line) + 1
        fired = False
        def trace(frame, event, arg):
            nonlocal fired
            if frame.f_code is method.__code__ and event == 'line' and frame.f_lineno == protected_line:
                self.assertEqual(self.native._busy._recursion_count(), 1)
                fired = True
                raise KeyboardInterrupt('first-protected-native-with-line')
            return trace
        previous = sys.gettrace(); sys.settrace(trace)
        try:
            with self.assertRaises(KeyboardInterrupt): action()
        finally: sys.settrace(previous)
        self.assertTrue(fired)
        self.assertEqual(self.native._busy._recursion_count(), 0)

    def test_native_with_interruption_releases_guard_and_normal_close_retries(self):
        self.interrupt_first_native_with_body(kernel._Native.close, self.native.close)
        os.fstat(self.native.fd); self.assertIsNone(self.native.operation)
        self.native.close(); self.assertEqual(self.native.fd, -1)

    def test_cap_with_interruption_keeps_original_fds_then_normal_close_retries(self):
        cap = self.fixture()
        self.interrupt_first_native_with_body(kernel._ControlledOperation.close, lambda: cap.close(cap.owner))
        self.assertIs(self.native.operation, cap); self.assertFalse(cap.closed)
        for _, fd, _, _ in cap.nodes: os.fstat(fd)
        cap.close(cap.owner); self.native.close()

    def test_constructor_with_interruption_keeps_free_slot_and_normal_close_works(self):
        self.interrupt_first_native_with_body(kernel._ControlledOperation.__init__, self.acquisition)
        self.assertIsNone(self.native.operation); os.fstat(self.native.fd)
        self.native.close()


@unittest.skipUnless(sys.platform == 'linux', 'Linux runtime control')
class KernelAbiTests(unittest.TestCase):
    def test_unsupported_version_refuses_before_source_compiler_or_memfd(self):
        with patch.object(kernel.sys, 'version_info', (3, 14, 4)), \
                patch.object(kernel, '_sources', side_effect=AssertionError('source IO')), \
                patch.object(kernel.subprocess, 'run', side_effect=AssertionError('compiler')), \
                patch.object(kernel.os, 'memfd_create', side_effect=AssertionError('memfd')), \
                self.assertRaisesRegex(ValueError, 'controlled-cpython-3123-required'):
            kernel.build_controlled_native()

    @unittest.skipUnless(sys.version_info[:3] == (3, 12, 3), 'native ABI refusal control requires 3.12.3')
    def test_python_rlock_fallback_refuses_before_controlled_preparation(self):
        class PythonLock:
            __module__ = '_thread'
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def _recursion_count(self): return 0
        real = kernel._thread.RLock()
        class RLock:
            __module__ = '_thread'
            __enter__ = real.__enter__
            __exit__ = real.__exit__
            _recursion_count = real._recursion_count
        for kind in (PythonLock, RLock):
            with self.subTest(kind=kind.__name__), patch.object(kernel._thread, 'RLock', kind), \
                    patch.object(kernel, '_sources', side_effect=AssertionError('source IO')), \
                    patch.object(kernel.os, 'memfd_create', side_effect=AssertionError('memfd')), \
                    self.assertRaisesRegex(ValueError, 'native-rlock-required'):
                kernel.build_controlled_native()

    def test_default_runtime_does_not_query_controlled_abi(self):
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(kernel, '_native_rlock', side_effect=AssertionError('ordinary ABI dependency')):
            result = runtime.supervise(['/bin/true'], Path(temporary)/'ordinary',
                dict(wall_seconds=2, rss_bytes=128*1024**2))
        self.assertEqual(result['outcome'], 'success')
        self.assertNotIn('controlled_kernel_spawn', result)


if __name__ == '__main__': unittest.main()
