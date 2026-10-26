"""Modeled namespace/transport controls for the private exact-terminal gate.

Native effects are independently exercised on real own ordinary directories.
Synthetic C receipts here do not qualify cgroup birth/retirement or Whole-U.
"""
import ctypes
import errno
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

import llm_runtime_host_aggregate as aggregate
import llm_runtime_host_scope as host
import llm_runtime_kernel_owned as kernel
import llm_runtime_pilot as runtime
import test_llm_runtime_host_aggregate as previous


class HostRetirementTests(unittest.TestCase):
    fixture = previous.HostAggregateTests.fixture
    prepared = previous.HostAggregateTests.prepared
    binding = previous.HostAggregateTests.binding
    launch = previous.HostAggregateTests.launch

    def terminal(self):
        launch,op,cap,paths=self.launch()
        processes=[]
        def handoff(cgroup,agroup,output,record,exe,argv,env,deadline,slots):
            self.assertEqual(deadline,int(op.deadline*10**9))
            code='import os,struct;os.write('+str(record)+',struct.pack("<8Q",'+str(aggregate._MAGIC)+',os.getpid(),123,3,0,1,2,0))'
            process=subprocess.Popen(['/usr/bin/python3.12','-c',code],pass_fds=(record,),stdout=output,
                stderr=subprocess.STDOUT)
            processes.append(process)
            slots[:]=(process.pid,os.pidfd_open(process.pid),-1,-1)
            return 0
        def gate(owner,deadline):
            op.child=(owner.pid,owner.termination_fd,kernel.proc._signature(owner.termination_fd))
            cap._leaf_phase='CONTROLLER_RUNNING'
        with (tempfile.TemporaryFile('wb') as log,patch.object(op.native,'spawn_controller',side_effect=handoff),
              patch.object(op,'allow_exec',side_effect=gate)):
            child=runtime._Wait4Child(['/bin/true'],stdout=log,stderr=subprocess.STDOUT,
                _host_controller_operation=op,_kernel_deadline=op.deadline)
            while child.reap()=='live' and time.monotonic()<op.deadline:time.sleep(.001)
            child.finish()
        for process in processes:process.returncode=child.returncode
        self.assertIsNone(child.observation_error)
        self.assertIs(op._retirement_terminal,launch._terminal_fact)
        self.assertIs(launch._terminal_fact.child,child)
        with self.assertRaises(ChildProcessError):os.wait4(child.pid,os.WNOHANG)
        cap._owner_identity=Mock() # Explicit modeled namespace, never native qualification.
        return launch,op,cap,paths,child

    def test_missing_terminal_and_boolean_tuple_substitution_refuse_before_native_effect(self):
        for substitute in (None,True,{},(True,)):
            with self.subTest(substitute=substitute):
                launch,op,cap,paths=self.launch()
                launch._terminal_fact=substitute;op._retirement_terminal=substitute
                op.native.activate_retirement=Mock()
                with self.assertRaises(TypeError):launch._activate_retirement_locked({'pristine':True})
                with self.assertRaisesRegex(ValueError,'exact-terminal-required'):op._retire_children()
                op.native.activate_retirement.assert_not_called()
                self.assertIsNone(getattr(cap,'_retirement_attempt',None))
                self.assertTrue(op.failed)

    def test_original_exact_wait_pair_and_fresh_live_checks_bind_original_arrays_before_entry(self):
        launch,op,cap,paths,child=self.terminal()
        saved=tuple((id(slot),tuple(slot),sig) for slot,sig in cap._fds)
        native=Mock()
        def activate(parent,a,c,original,identities,deadline,out):
            self.assertIs(host._retained_aggregate_owner(),cap)
            self.assertIs(cap._retirement_attempt,launch)
            self.assertIs(launch._retirement_attempt[0],op._retirement_terminal)
            self.assertIs(original,child._kernel_handoff)
            self.assertIs(a,launch._retirement_attempt[1]);self.assertIs(c,launch._retirement_attempt[2])
            self.assertEqual((parent,deadline),(cap._groups['operation'][2],int(op.deadline*10**9)))
            self.assertEqual(tuple(identities),cap._groups['operation'][3]+cap._groups['aggregate'][3]+
                cap._groups['controller'][3]+op.child[2])
            out[0]=6;out[19]=1
            return 0
        op.native.activate_retirement=native
        native.side_effect=activate
        result=op._retire_children()
        self.assertEqual(native.call_count,1)
        self.assertEqual(tuple((id(slot),tuple(slot),sig) for slot,sig in cap._fds),saved)
        self.assertFalse(result['child_unlink_and_close_proven'])
        self.assertFalse(result['whole_u_terminal']);self.assertFalse(result['resource_return_proven'])
        self.assertEqual(result['reservation'],'RETAINED')
        with self.assertRaisesRegex(ValueError,'single-attempt'):op._retire_children()
        self.assertEqual(native.call_count,1)
        # Invoke the actual live verifier, even though this fixture normally
        # models _owner. Its new guard must precede all synthetic proc IO.
        with self.assertRaisesRegex(ValueError,'live-observation-forbidden'):
            host.HostScopeAdmission._owner(cap)

    def test_pending_native_return_keeps_original_root_arrays_and_reentry_closed(self):
        launch,op,cap,paths,child=self.terminal()
        failure=MemoryError('retirement-native-return')
        def activate(*args):
            self.assertIs(cap._retirement_attempt,launch)
            raise failure
        op.native.activate_retirement=Mock(side_effect=activate)
        saved=tuple(tuple(slot) for slot,_ in cap._fds)
        with self.assertRaises(MemoryError):op._retire_children()
        self.assertIs(op._first_error,failure)
        self.assertIs(host._retained_aggregate_owner(),cap)
        self.assertEqual(tuple(tuple(slot) for slot,_ in cap._fds),saved)
        self.assertGreater(child._kernel_handoff[1],2)
        with self.assertRaises(ValueError):op._retire_children()
        self.assertEqual(op.native.activate_retirement.call_count,1)

    def test_fresh_quiescence_limit_rewind_and_original_deadline_never_reach_activation(self):
        for mode in ('tasks','limit','rewind','late','wait-status','different-pidfd'):
            with self.subTest(mode=mode):
                launch,op,cap,paths,child=self.terminal()
                if mode=='tasks':
                    for role in ('operation','aggregate'):
                        (paths[role]/'pids.current').write_text('1\n')
                        (paths[role]/'cgroup.events').write_text('populated 1\nfrozen 0\n')
                    (paths['aggregate']/'cgroup.procs').write_text('123\n')
                elif mode=='limit':(paths['controller']/'memory.max').write_text('max\n')
                elif mode=='rewind':op._meters['operation']=(516097,0)
                elif mode=='late':launch.deadline_ns=1
                elif mode=='wait-status':child.cleanup_method='waitpid-after-wait4-fault'
                else:op.child=(child.pid,child.termination_fd,(-1,-1,-1))
                op.native.activate_retirement=Mock()
                with self.assertRaises(ValueError):op._retire_children()
                op.native.activate_retirement.assert_not_called()
                self.assertIsNone(getattr(cap,'_retirement_attempt',None))
                self.assertTrue(op.failed)

    def test_unknown_native_progress_does_not_scan_or_close_remaining_original_arrays(self):
        launch,op,cap,paths,child=self.terminal()
        def activate(*args):
            launch._retirement[0]=6;launch._retirement[19]=1
            return 0
        op.native.activate_retirement=Mock(side_effect=activate)
        op._retire_children()
        launch._retirement[0]=4;launch._retirement[1]=errno.ETIMEDOUT;launch._retirement[20]=1;launch._retirement[23]=0x80000001
        # While native is blocked, no caller may scan mutable original slot
        # contents. A signature spy would fail if the phase verifier did so.
        with patch.object(kernel.proc,'_signature',side_effect=AssertionError('inflight slot scan')):
            result=op._retirement_status()
        self.assertFalse(result['child_unlink_and_close_proven'])
        self.assertEqual((result['progress'],result['reservation']),(1,'RETAINED'))
        self.assertTrue(op.failed);self.assertIs(host._retained_aggregate_owner(),cap)

    def test_completed_modeled_phase_retains_raw_U_charge_dying_history_and_original_root(self):
        launch,op,cap,paths,child=self.terminal()
        before_peak=op._meters['operation'][0]
        original_binding=op.child
        def activate(parent,a,c,original,identities,deadline,out):
            # This test substitutes native dispatch only. Actual remove/close
            # ordering and errno/timeout behavior have separate real controls.
            for name,slot in [('aggregate',a),('controller',c)]:
                for file in paths[name].iterdir():file.unlink()
                paths[name].rmdir();op.native.release_owned(slot)
            op.native.close_handoff(original,2)
            for role,count in [('scope',3),('host',2),('operation',0)]:
                (paths[role]/'cgroup.stat').write_text('nr_descendants '+str(count)+'\nnr_dying_descendants 1\n')
            out[0]=7;out[17]=1;out[19]=1;out[20]=31;out[21]=1;out[23]=5
            return 0
        op.native.activate_retirement=Mock(side_effect=activate)
        result=op._retire_children()
        self.assertTrue(result['child_unlink_and_close_proven'])
        self.assertFalse(result['whole_u_terminal']);self.assertFalse(result['resource_return_proven'])
        self.assertFalse(result['authorization']);self.assertEqual(result['reservation'],'RETAINED')
        self.assertEqual(result['counters']['memory.current'],'516096\n')
        self.assertEqual(result['counters']['cgroup.stat'],'nr_descendants 0\nnr_dying_descendants 1\n')
        self.assertEqual(op._meters['operation'][0],before_peak)
        self.assertEqual(op.child,original_binding)
        self.assertIsNone(child.termination_fd)
        self.assertIs(host._retained_aggregate_owner(),cap)
        self.assertGreater(launch._retirement[9],0)
        with self.assertRaises(ValueError):cap.close_before_effect()
        with self.assertRaises(ValueError):op._retire_children()
        self.assertEqual(op.native.activate_retirement.call_count,1)

    def test_pending_entry_and_retention_latch_failure_keep_original_first_error(self):
        launch,op,cap,paths,child=self.terminal()
        first=MemoryError('original-pending-return')
        later=KeyboardInterrupt('retain-latch-return')
        op.native.activate_retirement=Mock(side_effect=first)
        op.native.retain_retirement=Mock(side_effect=later)
        saved=tuple(tuple(slot) for slot,_ in cap._fds)
        with self.assertRaises(MemoryError):op._retire_children()
        self.assertIs(op._first_error,first)
        self.assertIs(op._retirement_latch_failure,later)
        op.native.retain_retirement.assert_called_once_with(launch._retirement)
        self.assertEqual(tuple(tuple(slot) for slot,_ in cap._fds),saved)
        self.assertIs(host._retained_aggregate_owner(),cap)
        self.assertTrue(op.failed);self.assertEqual(cap._leaf_phase,'UNKNOWN_RETAINED')


if __name__=='__main__':unittest.main(verbosity=2)
