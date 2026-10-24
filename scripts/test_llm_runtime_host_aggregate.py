"""Private C→A controls. Native successful cgroup birth/whole-U remains NOT_RUN.

Ordinary direct children qualify only the actual native wait4/FD subroutines.
Synthetic pipe producers below cannot qualify A membership or resource return.
"""
import copy
import ctypes
import errno
import fcntl
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import llm_runtime_host_aggregate as aggregate
import llm_runtime_kernel_owned as kernel
import llm_runtime_pilot as runtime
import test_llm_runtime_host_controller as original
import test_llm_runtime_host_scope as legacy


class HostAggregateTests(unittest.TestCase):
    fixture = legacy.HostScopeTests.fixture
    prepared = original.ControllerMechanicsTests.prepared
    binding = original.ControllerMechanicsTests.binding

    def launch(self):
        op, cap, paths, writes, fact = self.binding()
        launch = aggregate._AggregateLaunch(aggregate._TOKEN, op, ['/bin/true'])
        for role in ('operation', 'controller', 'aggregate'):
            (paths[role]/'memory.events').write_text('low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n')
        def cleanup():
            for slot in (launch.read_slot, launch.write_slot):
                if slot[1] >= 0: op.native.release_owned(slot)
        self.addCleanup(cleanup)
        return launch, op, cap, paths

    def owner(self, op):
        owner = object.__new__(runtime._Wait4Child)
        owner.kernel_operation = op
        owner._kernel_handoff = (ctypes.c_int*4)(-1,-1,-1,-1)
        return owner

    def terminal_owner(self, op):
        owner = self.owner(op)
        owner.pid = os.getpid()
        owner.termination_fd = os.pidfd_open(owner.pid, 0)
        self.addCleanup(os.close, owner.termination_fd)
        owner.reaped = owner.reap_resolved = owner.owned_exit_observed = owner._kernel_admitted = True
        owner.cleanup_method = 'wait4'; owner.observation_error = None
        owner.returncode = 0; owner.waited_cpu_ns = 1
        op.spawn_owner = owner; op.consumed = True
        op.child = (owner.pid, owner.termination_fd, kernel.proc._signature(owner.termination_fd))
        op.cap._leaf_phase = 'CONTROLLER_RUNNING'
        return owner

    def send(self, launch, fields):
        os.write(launch.write_slot[1], fields if type(fields) is bytes else struct.pack('<8Q', *fields))
        launch.native.release_owned(launch.write_slot)

    def test_private_single_slot_immutable_command_same_original_deadline_and_owner(self):
        launch, op, cap, paths = self.launch()
        self.assertIs(launch.operation, op)
        self.assertIs(launch.native, cap._native)
        self.assertIs(op.native.operation, op)
        self.assertEqual(launch.deadline_ns, int(op.deadline*10**9))
        self.assertEqual(launch.command, ('/bin/true',))
        self.assertEqual(op._meters['operation'][0], 516096)
        self.assertEqual((paths['operation']/'memory.current').read_text(), '516096\n')
        for invoke in (copy.copy, copy.deepcopy):
            with self.assertRaises(TypeError): invoke(launch)
        with self.assertRaisesRegex(ValueError, 'before-C-birth'):
            aggregate._AggregateLaunch(aggregate._TOKEN, op, ['/bin/true'])
        self.assertFalse(any(not name.startswith('_') and callable(value) and
            getattr(value, '__module__', None) == aggregate.__name__ for name,value in vars(aggregate).items()))

    def test_boolean_DTO_and_unbounded_command_never_create_pipe(self):
        op, _, _, _, _ = self.binding()
        with patch.object(op.native, 'prepare_pipe') as pipe:
            for token in (True, {}, object()):
                with self.assertRaisesRegex(ValueError, 'private-mechanics'):
                    aggregate._AggregateLaunch(token, op, ['/bin/true'])
            for command in (True, [], ['relative'], ['/bin/true', '\0'], ['/bin/true']*257,
                            ['/bin/true', 'x'*(1024**2)]):
                with self.assertRaisesRegex(ValueError, 'command-bound'):
                    aggregate._AggregateLaunch(aggregate._TOKEN, op, command)
            pipe.assert_not_called()

    def test_actual_native_ordinary_group_fd_refuses_before_child_no_fallback(self):
        launch, op, cap, _ = self.launch()
        held = legacy.owned_slot_snapshot(cap)
        with (tempfile.TemporaryFile('wb') as log, patch.object(subprocess.Popen, '__init__') as ordinary,
              patch.object(op.native, 'spawn', side_effect=AssertionError('old C exec path'))):
            with self.assertRaisesRegex(OSError, 'host-aggregate-clone3-refused'):
                runtime._Wait4Child(['/bin/true'], stdout=log, stderr=subprocess.STDOUT,
                    _host_controller_operation=op, _kernel_deadline=op.deadline)
            ordinary.assert_not_called()
        self.assertEqual(tuple(op.spawn_owner._kernel_handoff), (-1,-1,-1,-1))
        self.assertTrue(op.native_refused_without_child)
        self.assertEqual(legacy.owned_slot_snapshot(cap), held)
        self.assertIs(op.native.operation, op)
        self.assertEqual(cap._leaf_phase, 'UNKNOWN_RETAINED')
        self.assertGreater(launch.read_slot[1], 2)
        self.assertGreater(launch.write_slot[1], 2)

    def test_native_pending_exception_and_changed_command_keep_original_four_slots(self):
        for mode in ('pending', 'changed-command'):
            with self.subTest(mode=mode):
                launch, op, cap, _ = self.launch()
                failure = MemoryError('pending after native entry')
                with tempfile.TemporaryFile('wb') as log, patch.object(op.native, 'spawn_controller',
                        side_effect=failure) as spawn:
                    with self.assertRaises(MemoryError if mode == 'pending' else ValueError):
                        runtime._Wait4Child(['/bin/true' if mode == 'pending' else '/bin/false'],
                            stdout=log, stderr=subprocess.STDOUT, _host_controller_operation=op,
                            _kernel_deadline=op.deadline)
                    self.assertEqual(spawn.call_count, 1 if mode == 'pending' else 0)
                    if mode == 'pending':
                        self.assertIs(op._first_error, failure)
                        self.assertEqual(tuple(op.spawn_owner._kernel_handoff), (-1,-1,-1,-1))
                    self.assertFalse(op.native_refused_without_child)
                    self.assertEqual(cap._leaf_phase, 'UNKNOWN_RETAINED')
                    with self.assertRaises(ValueError): op.spawn(['/bin/true'], log, self.owner(op))
                    self.assertEqual(spawn.call_count, 1 if mode == 'pending' else 0)

    def test_C_and_A_threads_sum_in_U_and_all_three_raw_histories_remain_charged(self):
        launch, op, cap, paths = self.launch()
        self.terminal_owner(op)
        for role,pid,tasks,current in [('controller',1234,2,1024), ('aggregate',2345,3,2048)]:
            (paths[role]/'cgroup.procs').write_text(str(pid)+'\n')
            (paths[role]/'pids.current').write_text(str(tasks)+'\n')
            (paths[role]/'cgroup.events').write_text('populated 1\nfrozen 0\n')
            (paths[role]/'memory.current').write_text(str(current)+'\n')
            (paths[role]/'memory.peak').write_text(str(current)+'\n')
        (paths['operation']/'pids.current').write_text('5\n')
        (paths['operation']/'cgroup.events').write_text('populated 1\nfrozen 0\n')
        with op.native._lock_for_owner(): raw = op._verify_locked()
        self.assertEqual(set(raw), {'operation','controller','aggregate'})
        self.assertEqual(raw['operation']['memory.current'], '516096\n')
        self.assertEqual(raw['aggregate']['memory.current'], '2048\n')
        (paths['operation']/'pids.current').write_text('4\n')
        with op.native._lock_for_owner(), self.assertRaisesRegex(ValueError, 'task-population'):
            op._verify_locked()
        self.assertTrue(op.failed)
        self.assertEqual(cap._leaf_phase, 'UNKNOWN_RETAINED')

    def test_A_limit_event_identity_pipe_and_historical_rewind_are_sticky(self):
        for mode in ('limit','event','rewind','pipe'):
            with self.subTest(mode=mode):
                launch, op, cap, paths = self.launch()
                self.terminal_owner(op)
                if mode == 'limit': (paths['aggregate']/'memory.max').write_text('max\n')
                elif mode == 'event': (paths['aggregate']/'memory.events').write_text('oom 1\n')
                elif mode == 'rewind': op._meters['aggregate'] = (1, 0)
                else: fcntl.fcntl(launch.read_slot[1], fcntl.F_SETFL, 0)
                with op.native._lock_for_owner(), self.assertRaises(ValueError): op._verify_locked()
                self.assertTrue(op.failed)
                self.assertEqual(cap._leaf_phase, 'UNKNOWN_RETAINED')

    def test_synthetic_C_pipe_record_with_exact_O_wait4_never_claims_WholeU(self):
        # Synthetic C transport producer only: the native wait4 subroutine is
        # independently tested below. No native cgroup C/A birth is claimed.
        launch, op, cap, paths = self.launch()
        processes = []
        def handoff(cgroup, agroup, output, record, exe, argv, env, deadline, slots):
            self.assertEqual((cgroup, agroup), (cap._groups['controller'][2], cap._groups['aggregate'][2]))
            self.assertEqual(deadline, int(op.deadline*10**9))
            code = 'import os,struct;os.write('+str(record)+',struct.pack("<8Q",'+str(aggregate._MAGIC)+',os.getpid(),123,3,0,1,2,0))'
            process = subprocess.Popen([sys.executable,'-c',code], pass_fds=(record,), stdout=output,
                stderr=subprocess.STDOUT)
            processes.append(process)
            slots[:] = (process.pid, os.pidfd_open(process.pid,0), -1,-1)
            return 0
        def gate(owner, deadline):
            self.assertEqual(deadline, op.deadline)
            op.child = (owner.pid, owner.termination_fd, kernel.proc._signature(owner.termination_fd))
            cap._leaf_phase = 'CONTROLLER_RUNNING'
            (paths['aggregate']/'memory.current').write_text('4096\n')
            (paths['aggregate']/'memory.peak').write_text('4096\n')
        with (tempfile.TemporaryFile('wb') as log, patch.object(op.native,'spawn_controller',side_effect=handoff),
              patch.object(op,'allow_exec',side_effect=gate)):
            child = runtime._Wait4Child(['/bin/true'], stdout=log, stderr=subprocess.STDOUT,
                _host_controller_operation=op, _kernel_deadline=op.deadline)
            while child.reap() == 'live' and time.monotonic() < op.deadline: time.sleep(.001)
            child.finish()
        for process in processes: process.returncode = child.returncode
        self.assertIsNone(child.observation_error)
        result = child.kernel_evidence
        self.assertEqual(result['aggregate_wait4_transport']['exit_code'], 0)
        self.assertEqual(result['counters']['operation']['memory.current'], '516096\n')
        self.assertEqual(result['counters']['aggregate']['memory.current'], '4096\n')
        self.assertFalse(result['whole_u_terminal'])
        self.assertFalse(result['resource_return_proven'])
        self.assertFalse(result['authorization'])
        self.assertEqual(result['reservation'], 'RETAINED')
        self.assertEqual(cap._leaf_phase, 'CONTROLLER_EXIT_OBSERVED')
        with self.assertRaises(ChildProcessError): os.wait4(child.pid, os.WNOHANG)

    def test_bad_missing_extra_foreign_unwaited_or_late_record_never_succeeds(self):
        for mode in ('missing','short','extra','foreign-C','no-wait4','error','late','C-waitpid','A-tasks'):
            with self.subTest(mode=mode):
                launch, op, cap, paths = self.launch()
                child = self.terminal_owner(op)
                fields = [aggregate._MAGIC,child.pid,123,3,0,1,2,0]
                if mode == 'foreign-C': fields[1] += 1
                elif mode == 'no-wait4': fields[3] = 2
                elif mode == 'error': fields[7] = errno.ECHILD
                raw = struct.pack('<8Q', *fields)
                if mode == 'missing': raw = b''
                elif mode == 'short': raw = raw[:-1]
                elif mode == 'extra': raw += b'x'
                elif mode == 'C-waitpid': child.cleanup_method = 'waitpid-after-wait4-fault'
                elif mode == 'late': op.deadline = 1.
                elif mode == 'A-tasks':
                    for role in ('operation','aggregate'):
                        (paths[role]/'pids.current').write_text('1\n')
                        (paths[role]/'cgroup.events').write_text('populated 1\nfrozen 0\n')
                    (paths['aggregate']/'cgroup.procs').write_text('123\n')
                self.send(launch, raw)
                with self.assertRaises(ValueError): op.terminal_record(child.pid, child.termination_fd)
                self.assertTrue(op.failed)
                self.assertEqual(cap._leaf_phase, 'UNKNOWN_RETAINED')
                self.assertGreater(launch.read_slot[1], 2)


class NativeControllerSubroutineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='trnm-native-C-subroutine-test-')
        source = kernel._bytes(kernel._C)
        wrapper = b'''
int trnm_test_wait4(int pid, int pidfd, uint64_t deadline, uint64_t record[8]) {
    return trnm_controller_wait4(pid, pidfd, deadline, record);
}
int trnm_test_closed_world(int aggregate, int record, int unexpected) {
    int pid = fork();
    if (pid) return pid;
    int error = trnm_controller_sanitize(aggregate, record);
    uint64_t values[8] = {0};
    values[0] = (uint64_t)error;
    values[1] = (uint64_t)(fcntl(3, F_GETFD) == FD_CLOEXEC);
    values[2] = (uint64_t)(fcntl(4, F_GETFD) == FD_CLOEXEC);
    values[3] = (uint64_t)(fcntl(unexpected, F_GETFD) < 0 && errno == EBADF);
    if (write(4, values, sizeof(values)) != sizeof(values)) _exit(1);
    _exit(error ? 1 : 0);
}
int trnm_test_closed_world_exec(int aggregate, int record, int output, const char *exe, char *const argv[]) {
    int pid = fork();
    if (pid) return pid;
    if (dup2(output, 1) < 0 || trnm_controller_sanitize(aggregate, record)) _exit(125);
    char *env[] = {NULL};
    execve(exe, argv, env);
    _exit(127);
}
'''
        output = Path(cls.temporary.name)/'subroutine.so'
        built = subprocess.run(['/usr/bin/cc','-std=c11','-shared','-fPIC','-O2','-Wall','-Wextra','-Werror',
            '-x','c','-','-o',str(output)],input=source+wrapper,capture_output=True)
        if built.returncode: raise AssertionError(built.stderr.decode())
        if kernel._bytes(kernel._C) != source: raise AssertionError('source changed during test build')
        cls.library = ctypes.CDLL(str(output))
        cls.wait = cls.library.trnm_test_wait4
        cls.wait.argtypes = [ctypes.c_int,ctypes.c_int,ctypes.c_uint64,ctypes.POINTER(ctypes.c_uint64)]
        cls.wait.restype = ctypes.c_int
        cls.probe = cls.library.trnm_test_closed_world
        cls.probe.argtypes = [ctypes.c_int,ctypes.c_int,ctypes.c_int]
        cls.probe.restype = ctypes.c_int
        cls.exec_probe = cls.library.trnm_test_closed_world_exec
        cls.exec_probe.argtypes = [ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_char_p)]
        cls.exec_probe.restype = ctypes.c_int

    @classmethod
    def tearDownClass(cls): cls.temporary.cleanup()

    def test_real_native_exact_wait4_of_own_direct_child_retains_nonzero_exit(self):
        child = subprocess.Popen([sys.executable,'-c','raise SystemExit(7)'])
        fd = os.pidfd_open(child.pid,0)
        try:
            record = (ctypes.c_uint64*8)()
            error = self.wait(child.pid,fd,time.monotonic_ns()+8*10**9,record)
            self.assertEqual(error,0)
            self.assertEqual(record[3],1)
            self.assertEqual(os.waitstatus_to_exitcode(record[4]),7)
            self.assertGreater(record[5]+record[6],0)
            with self.assertRaises(ChildProcessError): os.wait4(child.pid,os.WNOHANG)
            child.returncode = 7
        finally:
            os.close(fd)
            if child.returncode is None: child.kill();child.wait()

    def test_original_native_deadline_kills_only_original_pidfd_and_exact_reaps(self):
        child = subprocess.Popen([sys.executable,'-c','import time;time.sleep(5)'])
        unrelated = subprocess.Popen([sys.executable,'-c','import time;time.sleep(5)'])
        fd = os.pidfd_open(child.pid,0)
        try:
            record = (ctypes.c_uint64*8)()
            error = self.wait(child.pid,fd,time.monotonic_ns()+10**6,record)
            self.assertEqual(error,errno.ETIMEDOUT)
            self.assertEqual(record[3],1)
            self.assertEqual(os.waitstatus_to_exitcode(record[4]),-signal.SIGKILL)
            child.returncode = -signal.SIGKILL
            self.assertIsNone(unrelated.poll())
            with self.assertRaises(ChildProcessError): os.wait4(child.pid,os.WNOHANG)
        finally:
            os.close(fd)
            if child.returncode is None: child.kill();child.wait()
            unrelated.kill();unrelated.wait()

    def test_foreign_nonchild_cannot_generate_native_wait4_flag(self):
        fd = os.pidfd_open(os.getpid(),0)
        try:
            record = (ctypes.c_uint64*8)()
            self.assertEqual(self.wait(os.getpid(),fd,time.monotonic_ns()+8*10**9,record),errno.ECHILD)
            self.assertEqual(tuple(record),(0,)*8)
        finally: os.close(fd)

    def test_real_child_closes_inherited_private_handles_and_sets_only_A_and_record_CLOEXEC(self):
        read, write = os.pipe2(os.O_CLOEXEC|os.O_NONBLOCK)
        group = os.open(os.devnull,os.O_RDONLY|os.O_CLOEXEC)
        unexpected = fcntl.fcntl(group,fcntl.F_DUPFD,180)
        try:
            self.assertTrue(os.get_inheritable(unexpected))
            pid = self.probe(group,write,unexpected)
            self.assertGreater(pid,0)
            waited,status,_ = os.wait4(pid,0)
            self.assertEqual(waited,pid)
            self.assertEqual(os.waitstatus_to_exitcode(status),0)
            self.assertEqual(struct.unpack('=8Q',os.read(read,65)),(0,1,1,1,0,0,0,0))
            os.fstat(unexpected)  # Parent's original handles were not touched.
        finally:
            for fd in (read,write,group,unexpected): os.close(fd)

    def test_actual_exec_cannot_retain_A_record_or_unexpected_inheritable_handles(self):
        read, write = os.pipe2(os.O_CLOEXEC|os.O_NONBLOCK)
        group = os.open(os.devnull,os.O_RDONLY|os.O_CLOEXEC)
        unexpected = fcntl.fcntl(group,fcntl.F_DUPFD,180)
        code = ('import errno,fcntl,os;closed=[]\nfor fd in (3,4,'+str(unexpected)+'):\n'
            ' try:fcntl.fcntl(fd,fcntl.F_GETFD)\n except OSError as e:closed.append(e.errno==errno.EBADF)\n'
            'os.write(1,str(closed).encode())')
        values = [os.fsencode(sys.executable),b'-c',code.encode()]
        argv = (ctypes.c_char_p*4)(*values,None)
        try:
            with tempfile.TemporaryFile('w+b') as log:
                pid = self.exec_probe(group,write,log.fileno(),values[0],argv)
                self.assertGreater(pid,0)
                waited,status,_ = os.wait4(pid,0)
                self.assertEqual(waited,pid)
                self.assertEqual(os.waitstatus_to_exitcode(status),0)
                log.seek(0)
                self.assertEqual(log.read(),b'[True, True, True]')
            os.fstat(unexpected)
        finally:
            for fd in (read,write,group,unexpected): os.close(fd)


if __name__ == '__main__': unittest.main(verbosity=2)
