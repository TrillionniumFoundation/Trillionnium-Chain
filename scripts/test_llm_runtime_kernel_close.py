"""Owned ordinary FDs and invalid-cgroup refusal only; valid placement NOT_RUN."""
import ctypes
import errno
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import llm_runtime_kernel_owned as kernel


@unittest.skipUnless(sys.platform == 'linux', 'Linux native FD ownership')
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
        cap.spawn_owner = None; cap.nodes = []; cap.verify = Mock()
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


if __name__ == '__main__': unittest.main()
