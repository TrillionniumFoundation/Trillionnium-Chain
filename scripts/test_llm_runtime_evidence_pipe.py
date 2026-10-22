"""Source-bound native ordinary FIFO ownership only; no cgroup/unit/model."""
import ctypes
import errno
from concurrent.futures import ThreadPoolExecutor
import fcntl
import os
from pathlib import Path
import stat
import signal
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import llm_runtime_kernel_owned as kernel
import llm_runtime_kernel_aggregate as aggregate
import llm_runtime_pilot as runtime


@unittest.skipUnless(sys.implementation.name == 'cpython' and sys.version_info[:3] == (3,12,3),
    'controlled native ABI requires3.12.3')
class EvidencePipeOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.native = kernel.build_controlled_native()
        self.temporary = tempfile.TemporaryDirectory()
        self.cap = None
        self.addCleanup(self.cleanup)

    def cleanup(self):
        if self.cap is not None:
            for slot in self.cap._fd_owners:
                if slot[1] >= 0: self.native.release_owned(slot)
            self.native.operation = None
        self.native.close()
        self.temporary.cleanup()

    def fixture(self):
        cap = object.__new__(aggregate._AggregateOperation)
        cap.native = self.native; cap.owner = object(); cap._verify_locked = Mock()
        cap.closed = cap.failed = cap.consumed = cap.native_refused_without_child = False
        cap.spawn_owner = cap.evidence_pipe = None
        cap._fd_owners = [(ctypes.c_int*4)(0,-1,-1,-1) for _ in range(18)]
        path = Path(self.temporary.name)
        fd = os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
        cap.nodes = [(path,fd,kernel.proc._signature(fd),{})];cap._fd_owners[0][1] = fd
        self.native.operation = self.cap = cap
        return cap

    def prepare(self,cap):
        from llm_runtime_evidence_pipe import prepare_evidence_pipe
        return prepare_evidence_pipe(cap,cap.owner)

    def test_native_helper_fills_preheld_slots_flags_signatures_and_status(self):
        read = (ctypes.c_int*4)(0,-1,-1,-1);write = (ctypes.c_int*4)(0,-1,-1,-1)
        identity = (ctypes.c_uint64*6)();status = ctypes.c_int(-1)
        try:
            self.assertEqual(self.native.prepare_pipe(read,write,identity,ctypes.byref(status)),0)
            self.assertEqual(status.value,0)
            for index,slot in enumerate((read,write)):
                self.assertGreaterEqual(slot[1],3)
                self.assertTrue(stat.S_ISFIFO(os.fstat(slot[1]).st_mode))
                self.assertEqual(kernel.proc._signature(slot[1]),tuple(identity[index*3:index*3+3]))
                self.assertTrue(fcntl.fcntl(slot[1],fcntl.F_GETFL)&os.O_NONBLOCK)
                self.assertTrue(fcntl.fcntl(slot[1],fcntl.F_GETFD)&fcntl.FD_CLOEXEC)
        finally:
            for slot in (read,write):
                if slot[1]>=0:self.native.release_owned(slot)

    def test_prepare_registers_fixed_slot_source_and_cap_close_resolves_all(self):
        cap = self.fixture();pipe = self.prepare(cap)
        self.assertIs(cap.evidence_pipe,pipe)
        self.assertEqual(len(cap._fd_owners),18)
        self.assertIs(pipe.read_slot,cap._fd_owners[16]);self.assertIs(pipe.write_slot,cap._fd_owners[17])
        self.assertIn('llm_runtime_evidence_pipe.py',self.native.sources)
        descriptors=[slot[1] for slot in cap._fd_owners if slot[1]>=0]
        cap.close(cap.owner);self.assertIsNone(self.native.operation)
        for descriptor in descriptors:
            with self.assertRaises(OSError):os.fstat(descriptor)

    def test_pending_native_return_keeps_prebound_fds_and_identity_reachable(self):
        for fault in (KeyboardInterrupt,MemoryError):
            cap=self.fixture();original=self.native.prepare_pipe
            def interrupted(*args):
                original(*args)
                raise fault
            with patch.object(self.native,'prepare_pipe',interrupted),self.assertRaises(fault):self.prepare(cap)
            pipe=cap.evidence_pipe
            self.assertIs(self.native.operation,cap)
            for index,slot in enumerate((pipe.read_slot,pipe.write_slot)):
                self.assertEqual(kernel.proc._signature(slot[1]),tuple(pipe.identities[index*3:index*3+3]))
            cap.close(cap.owner)

    def test_wrong_owner_consumed_or_refusal_without_proof_never_mutates_fd(self):
        cap=self.fixture();pipe=self.prepare(cap)
        original=[tuple(slot) for slot in cap._fd_owners]
        with self.assertRaisesRegex(ValueError,'close-owner'):cap.close(object())
        self.assertEqual(original,[tuple(slot) for slot in cap._fd_owners])
        cap.consumed=True
        for claimed in (False,True):
            cap.native_refused_without_child=claimed
            with self.assertRaisesRegex(ValueError,'outer-reconciliation'):cap.close(cap.owner)
            self.assertEqual(original,[tuple(slot) for slot in cap._fd_owners])
        self.assertIs(cap.evidence_pipe,pipe);self.assertIs(self.native.operation,cap)

    def test_replaced_fifo_rejects_before_any_ancestor_or_other_slot_close(self):
        cap=self.fixture();pipe=self.prepare(cap);descriptor=pipe.read_slot[1]
        os.close(descriptor);replacement=os.open(os.devnull,os.O_RDONLY|os.O_CLOEXEC)
        if replacement!=descriptor:os.dup2(replacement,descriptor);os.close(replacement)
        try:
            with self.assertRaisesRegex(ValueError,'pipe-fd-replaced'):cap.close(cap.owner)
            os.fstat(cap.nodes[0][1]);os.fstat(pipe.write_slot[1]);os.fstat(descriptor)
            self.assertIs(self.native.operation,cap)
        finally:
            os.close(descriptor);pipe.read_slot[1]=-1

    def test_partial_native_close_errno_retains_fixed_cap_and_other_fifo(self):
        cap=self.fixture();pipe=self.prepare(cap);release=self.native.release_owned
        def failed(slot):
            if slot is pipe.read_slot:
                release(slot);slot[0]=errno.EIO;return errno.EIO
            return release(slot)
        with patch.object(self.native,'release_owned',failed),self.assertRaisesRegex(ValueError,'close-failed'):
            cap.close(cap.owner)
        self.assertEqual(pipe.read_slot[1],-1);self.assertEqual(pipe.read_slot[0],errno.EIO)
        self.assertIs(self.native.operation,cap);self.assertFalse(cap.closed)
        os.fstat(pipe.write_slot[1])
        with self.assertRaisesRegex(ValueError,'close-failed'):cap.close(cap.owner)
        os.fstat(pipe.write_slot[1])

    def test_fileno_uses_current_native_guard_without_recursive_enter(self):
        cap=self.fixture();pipe=self.prepare(cap)
        with self.assertRaisesRegex(ValueError,'pipe-guard'):pipe.fileno()
        child=object.__new__(runtime._Wait4Child);child._evidence_pipe_owner=pipe
        cap.consumed=True;cap.spawn_owner=child
        with self.native._lock_for_owner():
            self.assertEqual(self.native._busy._recursion_count(),1)
            self.assertEqual(pipe.fileno(),pipe.write_slot[1])
            self.assertEqual(self.native._busy._recursion_count(),1)

    def test_actual_invalid_group_refusal_preserves_child_link_then_nochild_close(self):
        cap=self.fixture();pipe=self.prepare(cap)
        child=object.__new__(runtime._Wait4Child)
        child.kernel_operation=cap;child._kernel_handoff=(ctypes.c_int*4)(-1,-1,-1,-1)
        with self.assertRaises(OSError):cap.spawn(['/bin/true'],pipe,child)
        self.assertIs(child._evidence_pipe_owner,pipe)
        self.assertTrue(cap.native_refused_without_child)
        self.assertEqual(list(child._kernel_handoff),[-1]*4)
        cap.close(cap.owner);self.assertIsNone(self.native.operation)

    def test_wrong_sink_or_nonoriginal_child_refuses_before_consuming(self):
        cap=self.fixture();pipe=self.prepare(cap)
        with open(os.devnull,'wb') as wrong:
            for output,child in ((wrong,object.__new__(runtime._Wait4Child)),
                (pipe,SimpleNamespace(kernel_operation=cap))):
                child.kernel_operation=cap
                with self.assertRaisesRegex(ValueError,'pipe-interface'):cap.spawn(['/bin/true'],output,child)
                self.assertFalse(cap.consumed);self.assertIsNone(cap.spawn_owner)

    def test_single_slot_wrong_preparation_owner_and_changed_sources_refuse(self):
        from llm_runtime_evidence_pipe import prepare_evidence_pipe
        with self.assertRaisesRegex(ValueError,'pipe-capability'):prepare_evidence_pipe({},object())
        cap=self.fixture()
        with self.assertRaisesRegex(ValueError,'close-owner'):prepare_evidence_pipe(cap,object())
        self.assertIsNone(cap.evidence_pipe)
        pipe=self.prepare(cap)
        with self.assertRaisesRegex(ValueError,'single-slot'):self.prepare(cap)
        self.assertIs(cap.evidence_pipe,pipe)
        child=object.__new__(runtime._Wait4Child);child._evidence_pipe_owner=pipe
        cap.consumed=True;cap.spawn_owner=child
        with self.native._lock_for_owner(),patch.object(kernel,'_sources',return_value={}):
            with self.assertRaisesRegex(ValueError,'pipe-source-changed'):pipe.fileno()

    def test_signal_after_native_pipe_close_does_not_close_reused_descriptor(self):
        cap=self.fixture();pipe=self.prepare(cap);release=self.native.release_owned
        descriptor=pipe.read_slot[1]
        def interrupted(slot):
            result=release(slot)
            if slot is pipe.read_slot:raise KeyboardInterrupt
            return result
        with patch.object(self.native,'release_owned',interrupted),self.assertRaises(KeyboardInterrupt):
            cap.close(cap.owner)
        self.assertEqual(pipe.read_slot[1],-1);self.assertIs(self.native.operation,cap)
        replacement=os.open(os.devnull,os.O_RDONLY|os.O_CLOEXEC)
        if replacement!=descriptor:os.dup2(replacement,descriptor);os.close(replacement)
        try:
            cap.close(cap.owner);os.fstat(descriptor)
        finally:os.close(descriptor)

    def test_foreign_thread_and_signal_reentry_refuse_without_registration(self):
        cap=self.fixture()
        with ThreadPoolExecutor(max_workers=1) as pool:
            with self.assertRaisesRegex(ValueError,'owner-thread'):pool.submit(self.prepare,cap).result()
        self.assertIsNone(cap.evidence_pipe)
        with self.native._lock_for_owner(),self.assertRaisesRegex(ValueError,'lifecycle-busy'):self.prepare(cap)
        self.assertIsNone(cap.evidence_pipe)

    def test_real_signal_reentry_keeps_fixed_slot_unregistered(self):
        cap=self.fixture();observed=[];previous=signal.getsignal(signal.SIGUSR1)
        def reenter(signum,frame):
            try:self.prepare(cap)
            except kernel.KernelBudgetError as error:observed.append(str(error))
        signal.signal(signal.SIGUSR1,reenter)
        try:
            with self.native._lock_for_owner():signal.raise_signal(signal.SIGUSR1)
        finally:signal.signal(signal.SIGUSR1,previous)
        self.assertEqual(observed,['kernel-native-lifecycle-busy'])
        self.assertIsNone(cap.evidence_pipe)
        self.assertEqual(self.native._busy._recursion_count(),0)

    def test_native_setup_refusal_does_not_touch_preexisting_fd(self):
        read=(ctypes.c_int*4)(0,-1,-1,-1);write=(ctypes.c_int*4)(0,-1,-1,-1)
        identities=(ctypes.c_uint64*6)();status=ctypes.c_int(-1)
        descriptor=os.open(os.devnull,os.O_RDONLY|os.O_CLOEXEC);write[1]=descriptor
        try:
            self.assertEqual(self.native.prepare_pipe(read,write,identities,ctypes.byref(status)),errno.EINVAL)
            self.assertEqual(status.value,errno.EINVAL);os.fstat(descriptor)
            self.assertEqual(read[1],-1);self.assertEqual(write[1],descriptor)
        finally:os.close(descriptor)

    def test_native_below_stdio_fd_refuses_and_releases_both_inside_C(self):
        read=(ctypes.c_int*4)(0,-1,-1,-1);write=(ctypes.c_int*4)(0,-1,-1,-1)
        identities=(ctypes.c_uint64*6)();status=ctypes.c_int(-1);saved=os.dup(0)
        try:
            os.close(0)
            self.assertEqual(self.native.prepare_pipe(read,write,identities,ctypes.byref(status)),errno.EBADF)
            self.assertEqual(status.value,errno.EBADF)
            self.assertEqual(read[1],-1);self.assertEqual(write[1],-1)
            self.assertEqual(read[0],0);self.assertEqual(write[0],0)
        finally:os.dup2(saved,0);os.close(saved)

    def test_before_native_failure_retains_registration_for_nochild_close(self):
        cap=self.fixture();cap._verify_locked.side_effect=MemoryError
        with patch.object(self.native,'prepare_pipe') as native,self.assertRaises(MemoryError):self.prepare(cap)
        native.assert_not_called();self.assertIs(self.native.operation,cap)
        self.assertIsNotNone(cap.evidence_pipe)
        cap.close(cap.owner);self.assertIsNone(self.native.operation)

    def test_unregistered_pipe_slot_is_never_closed_as_an_ancestor(self):
        cap=self.fixture();descriptor=os.open(os.devnull,os.O_RDONLY|os.O_CLOEXEC)
        cap._fd_owners[16][1]=descriptor
        with self.assertRaisesRegex(ValueError,'unregistered-slots'):cap.close(cap.owner)
        os.fstat(descriptor);os.fstat(cap.nodes[0][1]);self.assertIs(self.native.operation,cap)

    def test_registered_pipe_cannot_bypass_not_yet_integrated_terminal_transport(self):
        import test_llm_runtime_kernel_aggregate as fixtures
        cap=self.fixture();pipe=self.prepare(cap)
        cap.child=cap.fact=None
        child=fixtures.AggregateTests.owned_terminal(self,cap)
        with patch.object(aggregate,'_raw') as raw,self.assertRaisesRegex(ValueError,'transport-not-integrated'):
            cap.terminal_record(child.pid,child.termination_fd)
        raw.assert_not_called();self.assertIsNone(cap.fact);self.assertIs(cap.evidence_pipe,pipe)
        self.assertIs(self.native.operation,cap)

    def test_same_pipe_endpoint_swap_rejects_direction_before_any_close(self):
        cap=self.fixture();pipe=self.prepare(cap)
        pipe.read_slot[1],pipe.write_slot[1]=pipe.write_slot[1],pipe.read_slot[1]
        with self.assertRaisesRegex(ValueError,'pipe-fd-direction'):cap.close(cap.owner)
        for slot in cap._fd_owners:
            if slot[1]>=0:os.fstat(slot[1])
        self.assertIs(self.native.operation,cap)

    def test_full16_ancestors_keep_two_distinct_FIFO_slots_and_close_all18(self):
        cap=self.fixture()
        for index in range(1,16):
            path=Path(self.temporary.name)/str(index);path.mkdir()
            fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
            cap._fd_owners[index][1]=fd;cap.nodes.append((path,fd,kernel.proc._signature(fd),{}))
        pipe=self.prepare(cap);self.assertEqual(len(cap.nodes),16)
        self.assertTrue(all(stat.S_ISDIR(os.fstat(slot[1]).st_mode) for slot in cap._fd_owners[:16]))
        self.assertTrue(all(stat.S_ISFIFO(os.fstat(slot[1]).st_mode) for slot in cap._fd_owners[16:]))
        descriptors=[slot[1] for slot in cap._fd_owners]
        with patch.object(aggregate.os,'open') as opened,self.assertRaisesRegex(ValueError,'ancestor-bound'):
            cap._open(Path(self.temporary.name)/'extra',{})
        opened.assert_not_called();cap.close(cap.owner)
        for descriptor in descriptors:
            with self.assertRaises(OSError):os.fstat(descriptor)


if __name__=='__main__':unittest.main()
