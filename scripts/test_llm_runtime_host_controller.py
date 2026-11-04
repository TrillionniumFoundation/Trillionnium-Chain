"""Ordinary-FD/mock namespace controls only; no native cgroup/controller grant."""
import copy
import os
import subprocess
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

import llm_runtime_host_controller as controller
import llm_runtime_host_scope as host
import llm_runtime_kernel_owned as kernel
import llm_runtime_pilot as runtime
import test_llm_runtime_host_children as children
import test_llm_runtime_host_scope as legacy


class ControllerMechanicsTests(unittest.TestCase):
    fixture = legacy.HostScopeTests.fixture

    def prepared(self):
        cap, paths, writes, fact = children.ChildPreparationTests.consumed(self)
        cap.prepare_fresh_child_groups()
        for role in ('operation', 'controller'):
            (paths[role]/'memory.events').write_text('low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n')
        self.addCleanup(lambda: setattr(cap._native, 'operation', None))  # Ordinary fixture only.
        return cap, paths, writes, fact

    def binding(self):
        cap, paths, writes, fact = self.prepared()
        op = controller._HostControllerOperation(controller._TOKEN, cap, time.monotonic()+8.)
        return op, cap, paths, writes, fact

    def test_same_original_owner_and_borrowed_C_fd_without_authority_factory(self):
        op, cap, paths, writes, fact = self.binding()
        self.assertIs(op.owner, cap)
        self.assertIs(op.native, cap._native)
        self.assertIs(op.native.operation, op)
        self.assertEqual(op.nodes[0][1:3], cap._groups['controller'][2:])
        self.assertIs(cap._leaf_fact, fact)
        self.assertFalse(cap._ready)
        self.assertEqual(cap._leaf_phase, 'CONTROLLER_PREPARED')
        self.assertEqual(op._meters['operation'][0], 516096)
        self.assertEqual((paths['operation']/'memory.peak').read_text(), '516096\n')
        self.assertEqual([row[0] for row in writes if row[1]=='cgroup.procs'], ['host','observer'])
        for invoke in (copy.copy, copy.deepcopy):
            with self.assertRaises(TypeError): invoke(op)
        for name in ('spawn','settle','refund','terminal_record'):
            self.assertFalse(hasattr(cap, name))
        self.assertFalse(any(not name.startswith('_') and callable(value)
            and getattr(value, '__module__', None)==controller.__name__
            for name,value in vars(controller).items()))

    def test_no_boolean_DTO_legacy_or_stale_phase_can_acquire_binding(self):
        cap, _, _, _ = self.prepared()
        for token in (True, {}, object()):
            with self.assertRaisesRegex(ValueError, 'private-mechanics'):
                controller._HostControllerOperation(token, cap, time.monotonic()+8.)
        for deadline in (True, 1., time.monotonic()+9.):
            with self.assertRaisesRegex(ValueError, 'original-deadline'):
                controller._HostControllerOperation(controller._TOKEN, cap, deadline)
        cap._leaf_phase='LEAF_PROOF_CONSUMED'
        with self.assertRaisesRegex(ValueError, 'not-complete|phase-or-sticky'):
            controller._HostControllerOperation(controller._TOKEN, cap, time.monotonic()+8.)
        self.assertIsNone(cap._native.operation)

    def test_actual_limits_identity_A_pristine_and_historical_rewind_stay_closed(self):
        cases=[('controller','memory.max','max\n'),('aggregate','memory.peak','1\n'),
               ('operation','memory.current',str(16*1024**3+1)+'\n'),
               ('operation','memory.peak','0\n'),('controller','memory.events','oom 0\n'),
               ('operation','memory.events','low 0\nhigh 0\nmax 1\noom 0\noom_kill 0\n')]
        for role,key,value in cases:
            with self.subTest(role=role,key=key):
                op,cap,paths,_,_=self.binding()
                held=legacy.owned_slot_snapshot(cap)
                (paths[role]/key).write_text(value)
                with self.assertRaises(ValueError):op._verify_locked()
                self.assertTrue(op.failed)
                self.assertEqual(cap._leaf_phase,'UNKNOWN_RETAINED')
                self.assertEqual(legacy.owned_slot_snapshot(cap),held)
                with self.assertRaises(ValueError):cap.close_before_effect()

    def test_task_threads_remain_charged_without_mistaking_procs_for_thread_count(self):
        op,cap,paths,_,_=self.binding()
        owner=object.__new__(runtime._Wait4Child);owner.kernel_operation=op
        op.consumed=True;op.spawn_owner=owner;cap._leaf_phase='CONTROLLER_RUNNING'
        (paths['controller']/'cgroup.procs').write_text('1234\n')
        for role in ('operation','controller'):
            (paths[role]/'pids.current').write_text('2\n')
            (paths[role]/'cgroup.events').write_text('populated 1\nfrozen 0\n')
        self.assertEqual(op._verify_locked()['controller']['pids.current'],'2\n')
        (paths['operation']/'pids.current').write_text('3\n')
        with self.assertRaisesRegex(ValueError,'task-population'):op._verify_locked()
        self.assertEqual(cap._leaf_phase,'UNKNOWN_RETAINED')

    def test_private_wait4_selector_refuses_bool_without_ordinary_Popen_fallback(self):
        with patch.object(subprocess.Popen,'__init__') as ordinary:
            for value in (True, {}, object()):
                with self.assertRaisesRegex(ValueError,'HOST_CONTROLLER_SPAWN_INTERFACE'):
                    runtime._Wait4Child(['/bin/true'],stdout=None,stderr=subprocess.STDOUT,
                        _host_controller_operation=value,_kernel_deadline=time.monotonic()+8.)
            ordinary.assert_not_called()

    def test_native_refusal_retains_same_wait4_slots_and_never_retries_or_falls_back(self):
        op,cap,_,_,_=self.binding()
        held=legacy.owned_slot_snapshot(cap)
        with tempfile.TemporaryFile('wb') as log, patch.object(op.native,'spawn',return_value=1) as spawn, \
             patch.object(subprocess.Popen,'__init__') as ordinary:
            with self.assertRaises(OSError):
                runtime._Wait4Child(['/bin/true'],stdout=log,stderr=subprocess.STDOUT,
                    _host_controller_operation=op,_kernel_deadline=op.deadline)
            self.assertEqual(spawn.call_count,1)
            self.assertEqual(spawn.call_args.args[0],cap._groups['controller'][2])
            self.assertIs(op.native.operation,op)
            self.assertIsInstance(op.spawn_owner,runtime._Wait4Child)
            self.assertEqual(tuple(op.spawn_owner._kernel_handoff),(-1,-1,-1,-1))
            self.assertTrue(op.native_refused_without_child)
            self.assertEqual(cap._leaf_phase,'UNKNOWN_RETAINED')
            self.assertEqual(legacy.owned_slot_snapshot(cap),held)
            with self.assertRaises(ValueError):op.spawn(['/bin/true'],log,op.spawn_owner)
            self.assertEqual(spawn.call_count,1)
            ordinary.assert_not_called()

    def test_native_entry_exception_retains_first_error_owner_and_no_new_attempt(self):
        for error in (MemoryError('pending allocation'), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__):
                op,cap,_,_,_=self.binding()
                with tempfile.TemporaryFile('wb') as log, patch.object(op.native,'spawn',side_effect=error) as spawn:
                    with self.assertRaises(type(error)):
                        runtime._Wait4Child(['/bin/true'],stdout=log,stderr=subprocess.STDOUT,
                            _host_controller_operation=op,_kernel_deadline=op.deadline)
                    self.assertIs(op._first_error,error)
                    self.assertIs(op.native.operation,op)
                    self.assertEqual(tuple(op.spawn_owner._kernel_handoff),(-1,-1,-1,-1))
                    with self.assertRaises(ValueError):op.spawn(['/bin/true'],log,op.spawn_owner)
                    self.assertIs(op._first_error,error)
                    self.assertEqual(spawn.call_count,1)
                    self.assertEqual(cap._leaf_phase,'UNKNOWN_RETAINED')

    def test_original_wait4_reaps_real_ordinary_child_with_no_WholeU_or_refund_claim(self):
        op,cap,_,_,_=self.binding()
        retained=[]
        def ordinary_handoff(group, output, exe, argv, env, slots):
            # Real direct ordinary child, not clone3/cgroup qualification. Keep
            # Popen alive so its destructor cannot steal the original wait4.
            process=subprocess.Popen(['/bin/true'],stdout=output,stderr=subprocess.STDOUT)
            retained.append(process)
            slots[:]=(process.pid,os.pidfd_open(process.pid,0),-1,-1)
            return 0
        def ordinary_gate(owner,deadline):
            self.assertEqual(deadline,op.deadline)
            op.child=(owner.pid,owner.termination_fd,kernel.proc._signature(owner.termination_fd))
            cap._leaf_phase='CONTROLLER_RUNNING'
        with tempfile.TemporaryFile('wb') as log, patch.object(op.native,'spawn',side_effect=ordinary_handoff), \
             patch.object(op,'allow_exec',side_effect=ordinary_gate):
            child=runtime._Wait4Child(['/bin/true'],stdout=log,stderr=subprocess.STDOUT,
                _host_controller_operation=op,_kernel_deadline=op.deadline)
            child.finish()
        for process in retained:process.returncode=child.returncode
        self.assertTrue(child.reaped and child.reap_resolved and child.owned_exit_observed)
        self.assertEqual(child.cleanup_method,'wait4')
        self.assertIsNone(child.observation_error)
        self.assertGreater(child.waited_peak_rss_bytes,0)
        self.assertIsInstance(child.waited_cpu_ns,int)
        self.assertEqual(child.kernel_evidence['scope'],'original-O-exact-wait4-C-only')
        self.assertFalse(child.kernel_evidence['whole_u_terminal'])
        self.assertFalse(child.kernel_evidence['resource_return_proven'])
        self.assertFalse(child.kernel_evidence['authorization'])
        self.assertEqual(child.kernel_evidence['reservation'],'RETAINED')
        self.assertEqual(cap._leaf_phase,'CONTROLLER_EXIT_OBSERVED')
        self.assertFalse(cap._ready)
        self.assertIsNone(child.termination_fd)
        with self.assertRaises(ChildProcessError):os.wait4(child.pid,os.WNOHANG)

    def test_pidfd_readiness_or_cleanup_receipt_cannot_emit_controller_terminal(self):
        for mode in ('unadmitted','readiness','waitpid','cutoff','wrong-pidfd'):
            with self.subTest(mode=mode):
                op,cap,_,_,_=self.binding()
                child=object.__new__(runtime._Wait4Child)
                child.kernel_operation=op
                child.reaped=child.reap_resolved=child.owned_exit_observed=True
                child.cleanup_method='wait4';child.observation_error=None;child._kernel_admitted=True
                child.pid=123;child.waited_cpu_ns=1;child.returncode=0
                fd=os.pidfd_open(os.getpid(),0);self.addCleanup(os.close,fd)
                child.termination_fd=fd;op.spawn_owner=child;op.consumed=True
                op.child=(123,fd,kernel.proc._signature(fd))
                if mode=='unadmitted':child._kernel_admitted=False
                elif mode=='readiness':child.reaped=False
                elif mode=='waitpid':child.cleanup_method='waitpid-after-wait4-fault'
                elif mode=='cutoff':op.deadline=1.
                else:op.child=(123,-1,kernel.proc._signature(fd))
                with self.assertRaisesRegex(ValueError,'exact-wait4-before-cutoff'):
                    op.terminal_record(child.pid,fd)
                self.assertEqual(cap._leaf_phase,'UNKNOWN_RETAINED')
                self.assertTrue(op.failed)


if __name__=='__main__':unittest.main(verbosity=2)
