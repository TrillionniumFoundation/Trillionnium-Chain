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
import select
import signal
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

import llm_runtime_host_aggregate as aggregate
import llm_runtime_host_scope as host
import llm_runtime_kernel_owned as kernel
import llm_runtime_pilot as runtime
import test_llm_runtime_host_controller as original
import test_llm_runtime_host_scope as legacy


def _cleanup_fixture_aggregate(launch):
    # Test isolation only: never clear a production owner or a live real child.
    op = launch.operation
    assert isinstance(op.cap._owner, Mock), 'only ordinary/mock namespace fixtures may reset the root'
    child = op.spawn_owner
    if child is not None and child._kernel_handoff[0] > 0:
        assert child.reaped and child.reap_resolved, 'test must exact-wait its real C first'
        with unittest.TestCase().assertRaises(ChildProcessError):
            os.wait4(child.pid, os.WNOHANG)
    for slot in (launch.read_slot, launch.write_slot):
        if slot[1] >= 0: op.native.release_owned(slot)
    if child is not None and child._kernel_handoff[1] >= 0:
        op.native.close_handoff(child._kernel_handoff, 2)
    if host._AGGREGATE_OWNER_ROOT is not None and host._AGGREGATE_OWNER_ROOT[2] is op.cap:
        host._AGGREGATE_OWNER_ROOT = None


class HostAggregateTests(unittest.TestCase):
    fixture = legacy.HostScopeTests.fixture
    prepared = original.ControllerMechanicsTests.prepared
    binding = original.ControllerMechanicsTests.binding

    def launch(self):
        if host._AGGREGATE_OWNER_ROOT is not None:
            _cleanup_fixture_aggregate(host._retained_aggregate_owner()._native.operation._aggregate)
        op, cap, paths, writes, fact = self.binding()
        launch = aggregate._AggregateLaunch(aggregate._TOKEN, op, ['/bin/true'])
        for role in ('operation', 'controller', 'aggregate'):
            (paths[role]/'memory.events').write_text('low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n')
        self.addCleanup(_cleanup_fixture_aggregate, launch)
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


class NativeControllerFaultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='trnm-native-C-fault-test-')
        # Same fault interposition as the independent fixed-622 review. Only
        # this test library replaces calls; production has no fallback/hook.
        prefix = b'#define syscall review_syscall\n#define poll review_poll\n#define wait4 review_wait4_call\n'
        suffix = b'''
#undef syscall
#undef poll
#undef wait4
extern long syscall(long, ...);
extern int poll(struct pollfd *, nfds_t, int);
extern pid_t wait4(pid_t, int *, int, struct rusage *);
static int review_mode = 0;
static int review_slots[4] = {-1,-1,-1,-1};
long review_syscall(long number, ...) {
    if (number == SYS_pidfd_send_signal) { errno = EPERM; return -1; }
    errno = ENOSYS; return -1;
}
int review_poll(struct pollfd *fds, nfds_t count, int timeout) {
    if (review_mode == 2) { errno = ENOMEM; return -1; }
    return poll(fds, count, timeout);
}
pid_t review_wait4_call(pid_t pid, int *status, int options, struct rusage *usage) {
    if (review_mode == 3) { errno = EIO; return -1; }
    pid_t got = wait4(pid, status, options, usage);
    if (review_mode == 4 && got == pid) usage->ru_utime.tv_usec = 1000000;
    return got;
}
int review_wait(int mode, int pid, int pidfd, uint64_t deadline, uint64_t record[8]) {
    review_mode = mode;
    return trnm_controller_wait4(pid, pidfd, deadline, record);
}
static void review_cleanup(int signum) {
    (void)signum;
    int status;
    long got;
    do { got = wait4(review_slots[0], &status, 0, NULL); } while (got < 0 && errno == EINTR);
    if (got != review_slots[0]) _exit(89);
    trnm_kernel_close_v1(review_slots, 2U);
    _exit(88); /* Test-only failed cleanup, never a product success record. */
}
static void review_child_owner(int mode, int info, int gate_read, int gate_write, uint64_t deadline) {
    close(gate_write);
    struct sigaction action = {0};
    action.sa_handler = review_cleanup;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, NULL)) _exit(125);
    int child = fork();
    if (!child) {
        close(info);
        char permission;
        ssize_t count;
        do { count = read(gate_read, &permission, 1); } while (count < 0 && errno == EINTR);
        _exit(count == 1 && permission == 'G' ? 7 : 8);
    }
    close(gate_read);
    if (child < 0) _exit(125);
    review_slots[0] = child;
    review_slots[1] = (int)syscall(SYS_pidfd_open, child, 0);
    uint32_t identity[2] = {(uint32_t)child, (uint32_t)review_slots[1]};
    if (review_slots[1] < 0 || write(info, identity, sizeof(identity)) != sizeof(identity)) {
        int status;
        syscall(SYS_pidfd_send_signal, review_slots[1], SIGKILL, NULL, 0);
        wait4(child, &status, 0, NULL);
        _exit(125);
    }
    close(info);
    review_mode = mode;
    uint64_t record[8] = {0};
    trnm_controller_reap_or_retain(review_slots, deadline, record);
    _exit(90); /* Returning before an actual A reap is the regression. */
}
int review_start_owner(int mode, int info, int gate_read, int gate_write, uint64_t deadline) {
    int controller = fork();
    if (controller) return controller;
    review_child_owner(mode, info, gate_read, gate_write, deadline);
    _exit(125);
}
int review_start_gated_owner(int info, int gate_read, int gate_write, int ack_read, int ack_write,
        int error_read, int error_write, uint64_t deadline) {
    int controller = fork();
    if (controller) return controller;
    close(ack_write); close(error_read);
    char permission;
    ssize_t count;
    do { count = read(ack_read, &permission, 1); } while (count < 0 && errno == EINTR);
    close(ack_read);
    if (count != 1 || permission != 'G') _exit(126);
    close(error_write);
    review_child_owner(0, info, gate_read, gate_write, deadline);
    _exit(125);
}
'''
        source = kernel._bytes(kernel._C)
        cls.output = Path(cls.temporary.name)/'faults.so'
        built = subprocess.run(['/usr/bin/cc','-std=c11','-shared','-fPIC','-O2','-Wall','-Wextra','-Werror',
            '-x','c','-','-o',str(cls.output)],input=prefix+source+suffix,capture_output=True)
        if built.returncode: raise AssertionError(built.stderr.decode())
        if kernel._bytes(kernel._C) != source: raise AssertionError('source changed during fault build')
        cls.library = ctypes.CDLL(str(cls.output))
        cls.wait = cls.library.review_wait
        cls.wait.argtypes = [ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_uint64,
            ctypes.POINTER(ctypes.c_uint64)]
        cls.wait.restype = ctypes.c_int

    @classmethod
    def tearDownClass(cls): cls.temporary.cleanup()

    def test_real_C_retains_exact_A_pidfd_on_signal_poll_and_wait_fault_even_after_A_exit(self):
        # A separate ordinary test process is subreaper only for its own test
        # children, so even a failing regression cannot strand an orphan. The
        # product C remains native and never returns to a Python interpreter.
        script = r'''
import ctypes,errno,os,pathlib,select,signal,struct,sys,time
libc=ctypes.CDLL(None,use_errno=True)
assert libc.prctl(36,1,0,0,0)==0
lib=ctypes.CDLL(sys.argv[1]);start=lib.review_start_owner
start.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_uint64]
start.restype=ctypes.c_int
mode=int(sys.argv[2]);info_r,info_w=os.pipe();gate_r,gate_w=os.pipe()
deadline=1 if mode==1 else time.monotonic_ns()+8*10**9
controller=start(mode,info_w,gate_r,gate_w,deadline)
assert controller>0
os.close(info_w);os.close(gate_r)
cfd=os.pidfd_open(controller,0);afd=None;child=None;reaped=False
try:
 assert select.select([info_r],[],[],1)[0]
 raw=os.read(info_r,8);assert len(raw)==8
 child,held_fd=struct.unpack('=2I',raw);afd=os.pidfd_open(child,0)
 until=time.monotonic()+1
 while time.monotonic()<until:
  if pathlib.Path('/proc/'+str(controller)+'/wchan').read_text().strip() in ('__do_sys_pause','do_sys_pause'):break
  time.sleep(.001)
 assert not select.select([cfd],[],[],0)[0], 'C exited before actual A wait4'
 assert os.wait4(controller,os.WNOHANG)[0]==0
 assert 'Pid:\t'+str(child)+'\n' in pathlib.Path('/proc/'+str(controller)+'/fdinfo/'+str(held_fd)).read_text()
 try:os.wait4(child,os.WNOHANG)
 except ChildProcessError:pass
 else:raise AssertionError('O improperly became A wait owner')
 os.write(gate_w,b'G');os.close(gate_w);gate_w=-1
 assert select.select([afd],[],[],1)[0]
 assert not select.select([cfd],[],[],0)[0], 'late A exit unlocked C UNKNOWN'
 assert 'Pid:\t'+str(child)+'\n' in pathlib.Path('/proc/'+str(controller)+'/fdinfo/'+str(held_fd)).read_text()
 signal.pidfd_send_signal(cfd,signal.SIGUSR1)
 waited,status,_=os.wait4(controller,0);reaped=True
 assert waited==controller and os.waitstatus_to_exitcode(status)==88
 try:os.wait4(child,os.WNOHANG)
 except ChildProcessError:pass
 else:raise AssertionError('test cleanup lost exact C wait4(A)')
 print('ordinary-C/A-fault mode='+str(mode)+' retained-original-A-pidfd; late-exit-not-success; exact-test-cleanup')
finally:
 if gate_w>=0:os.close(gate_w)
 if not reaped:
  try:signal.pidfd_send_signal(cfd,signal.SIGUSR1)
  except ProcessLookupError:pass
  os.wait4(controller,0)
 if child is not None:
  try:
   if os.wait4(child,os.WNOHANG)[0]==0:
    signal.pidfd_send_signal(afd,signal.SIGKILL);os.wait4(child,0)
  except ChildProcessError:pass
 for fd in (info_r,cfd,afd):
  if fd is not None:os.close(fd)
'''
        for mode in (1,2,3):
            with self.subTest(mode=mode):
                result = subprocess.run([sys.executable,'-c',script,str(self.output),str(mode)],
                    capture_output=True,text=True,timeout=8)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                self.assertIn('late-exit-not-success; exact-test-cleanup',result.stdout)
                print(result.stdout.strip())

    def test_late_actual_wait_and_bad_rusage_never_become_timely_success_or_lose_cleanup_fact(self):
        for mode in ('late','bad-rusage'):
            with self.subTest(mode=mode):
                child = subprocess.Popen([sys.executable,'-c','raise SystemExit(7)'])
                fd = os.pidfd_open(child.pid,0)
                try:
                    if mode == 'late': self.assertTrue(select.select([fd],[],[],1)[0])
                    record = (ctypes.c_uint64*8)()
                    error = self.wait(4 if mode == 'bad-rusage' else 0,child.pid,fd,
                        time.monotonic_ns()+8*10**9 if mode == 'bad-rusage' else 1,record)
                    self.assertEqual(error,errno.EOVERFLOW if mode == 'bad-rusage' else errno.ETIMEDOUT)
                    self.assertEqual(record[3],1)
                    self.assertEqual(os.waitstatus_to_exitcode(record[4]),7)
                    child.returncode = 7
                    with self.assertRaises(ChildProcessError):os.wait4(child.pid,os.WNOHANG)
                finally:
                    os.close(fd)
                    if child.returncode is None:child.kill();child.wait()

    def _run_original_O_owner_probe(self, modes):
        script = r'''
import ctypes,gc,os,pathlib,select,signal,struct,sys,tempfile,threading,time,weakref
from unittest.mock import patch
sys.path.insert(0,sys.argv[2])
import llm_runtime_kernel_owned as kernel
import llm_runtime_pilot as runtime
import llm_runtime_host_aggregate as aggregate
import llm_runtime_host_scope as host
from test_llm_runtime_host_aggregate import HostAggregateTests
libc=ctypes.CDLL(None,use_errno=True);assert libc.prctl(36,1,0,0,0)==0
lib=ctypes.CDLL(sys.argv[1]);start=lib.review_start_gated_owner
start.argtypes=[ctypes.c_int]*7+[ctypes.c_uint64];start.restype=ctypes.c_int
fixture=HostAggregateTests('test_private_single_slot_immutable_command_same_original_deadline_and_owner')
launch,op,cap,paths=fixture.launch()
mode=sys.argv[3];info_r,info_w=os.pipe();gate_r,gate_w=os.pipe()
controller=None;cfd=None;afd=None;child=None;owner=None;reaped=False;ack_write=None
original_read=pathlib.Path.read_text;original_write=os.write;original_signal=signal.pidfd_send_signal
def handoff(cgroup,agroup,output,record,exe,argv,env,deadline,slots):
 global controller,cfd,ack_write
 ack_read,ack_write=os.pipe2(os.O_CLOEXEC);error_read,error_write=os.pipe2(os.O_CLOEXEC)
 controller=start(info_w,gate_r,gate_w,ack_read,ack_write,error_read,error_write,deadline)
 assert controller>0
 cfd=os.pidfd_open(controller,0);slots[:]=(controller,cfd,ack_write,error_read)
 os.close(ack_read);os.close(error_write)
 return 0
def membership(path,*args,**kwargs):
 if controller is not None and path==pathlib.Path('/proc/'+str(controller)+'/cgroup'):
  return '0::/'+str(op.operation.relative_to(kernel._ROOT))+'\n'
 return original_read(path,*args,**kwargs)
def pending_write(fd,raw):
 count=original_write(fd,raw)
 if mode in ('pending-G','gc-drop-all') and fd==ack_write and raw==b'G':raise MemoryError('after actual C G write')
 return count
try:
 with open(os.devnull,'wb') as log,patch.object(op.native,'spawn_controller',side_effect=handoff),patch.object(pathlib.Path,'read_text',membership),patch.object(kernel.os,'write',side_effect=pending_write):
  if mode in ('pending-G','gc-drop-all'):
   try:runtime._Wait4Child(['/bin/true'],stdout=log,stderr=runtime.subprocess.STDOUT,_host_controller_operation=op,_kernel_deadline=op.deadline)
   except runtime._OwnedChildCleanupRequired as failure:owner=failure.child
   else:raise AssertionError('pending G did not retain original cleanup owner')
  else:owner=runtime._Wait4Child(['/bin/true'],stdout=log,stderr=runtime.subprocess.STDOUT,_host_controller_operation=op,_kernel_deadline=op.deadline)
 os.close(info_w);info_w=-1;os.close(gate_r);gate_r=-1
 assert select.select([info_r],[],[],1)[0]
 raw=os.read(info_r,8);assert len(raw)==8
 child,held_fd=struct.unpack('=2I',raw);afd=os.pidfd_open(child,0)
 assert owner is op.spawn_owner and owner._aggregate_wait_role is launch._wait_role
 if mode=='gc-drop-all':
  expected_slots=tuple(owner._kernel_handoff)
  expected_fds=tuple((fd,kernel.proc._signature(fd)) for fd in
   [cap._native.fd,cfd,launch.read_slot[1]]+[entry[0][1] for entry in cap._fds])
  refs=[weakref.ref(value) for value in (owner,op,cap,cap._native,launch,owner._kernel_handoff)]
  fixture._cleanups[:]=[entry for entry in fixture._cleanups if
   isinstance(getattr(entry[0],'__self__',None),tempfile.TemporaryDirectory)]
  callbacks=fixture._cleanups[:]
  del owner,op,cap,launch,paths,fixture
  gc.collect();gc.collect()
  assert all(ref() is not None for ref in refs), 'original C/A owner graph collected'
  cap=host._retained_aggregate_owner();op=cap._native.operation;launch=op._aggregate;owner=op.spawn_owner
  assert tuple(owner._kernel_handoff)==expected_slots
  assert all(kernel.proc._signature(fd)==signature for fd,signature in expected_fds)
  assert host._AGGREGATE_OWNER_ROOT==(os.getpid(),threading.current_thread(),cap)
  with patch.object(kernel,'build_controlled_native') as build,patch.object(host.bus,'UserManager') as manager:
   for prepare in (host.prepare_host_scope,lambda:host.HostScopeAdmission(host._TOKEN)):
    try:prepare()
    except ValueError as error:assert 'owner-retained' in str(error)
    else:raise AssertionError('second prepare passed retained root')
   build.assert_not_called();manager.assert_not_called()
  with patch.object(op.native,'prepare_pipe') as pipe,patch.object(kernel,'_bytes') as source:
   try:aggregate._AggregateLaunch(aggregate._TOKEN,op,['/bin/true'])
   except ValueError as error:assert 'owner-retained' in str(error)
   else:raise AssertionError('second aggregate passed retained root')
   pipe.assert_not_called();source.assert_not_called()
  foreign=[]
  def other_thread():
   try:host._retained_aggregate_owner()
   except ValueError as error:foreign.append(str(error))
  thread=threading.Thread(target=other_thread);thread.start();thread.join()
  assert foreign==['host-aggregate-root-original-pid-thread']
  assert host._retained_aggregate_owner() is cap
 if mode=='deadline':
  assert not select.select([cfd],[],[],max(0,op.deadline-time.monotonic()+.01))[0]
  assert time.monotonic()>=op.deadline
 with patch.object(runtime.signal,'pidfd_send_signal',wraps=original_signal) as signals:
  if mode=='rollback':
   try:owner._rollback_kernel_handoff()
   except runtime._OwnedChildCleanupRequired as failure:assert failure is owner._kernel_cleanup_required
   else:raise AssertionError('live C rollback lost its owner')
  elif mode=='direct-signal':owner.signal_owned(signal.SIGKILL)
  else:owner.finish()
  assert signals.call_count==0, 'O signalled C while C still owns A'
 assert owner.termination_fd==cfd and owner._kernel_handoff[1]==cfd
 assert not select.select([cfd],[],[],0)[0]
 assert 'Pid:\t'+str(child)+'\n' in pathlib.Path('/proc/'+str(controller)+'/fdinfo/'+str(held_fd)).read_text()
 assert op.native.operation is op and op.spawn_owner is owner and launch.record is None
 assert owner.kernel_evidence is None and owner.observation_error is not None
 try:owner._close_kernel_handoff(2)
 except runtime._OwnedChildCleanupRequired as failure:assert failure is owner._kernel_cleanup_required
 else:raise AssertionError('ordinary close released retained C pidfd')
 os.fstat(cfd)
 # Enter test-only exact C cleanup while A is still gated. Releasing A first
 # races a legitimate normal native C wait4/exit against the cleanup handler.
 original_signal(cfd,signal.SIGUSR1)
 original_write(gate_w,b'G');os.close(gate_w);gate_w=-1
 assert select.select([afd],[],[],1)[0]
 assert owner.reap(0)=='terminal';reaped=True
 assert owner.reaped and owner.reap_resolved and owner.returncode==88
 if mode=='gc-drop-all':
  assert host._retained_aggregate_owner() is cap, 'C exit improperly released the root'
  from test_llm_runtime_host_aggregate import _cleanup_fixture_aggregate
  _cleanup_fixture_aggregate(launch) # Only after real C exact-reaped its A, then O exact-reaped C.
  assert host._AGGREGATE_OWNER_ROOT is None
  print('all-caller-references-dropped; GC retained same owner and exact FDs; second prepare/aggregate denied before IO')
 print('original-O-cleanup '+mode+' real-G; no-C-signal; original-C/A-handles-retained; no-WholeU')
finally:
 if gate_w>=0:os.close(gate_w)
 if controller is not None and not reaped:
  try:original_signal(cfd,signal.SIGUSR1)
  except ProcessLookupError:pass
  os.wait4(controller,0)
 if child is not None:
  try:
   if os.wait4(child,os.WNOHANG)[0]==0:
    original_signal(afd,signal.SIGKILL);os.wait4(child,0)
  except ChildProcessError:pass
 for fd in (info_r,info_w,gate_r,afd):
  if fd is not None and fd>=0:os.close(fd)
 if mode=='gc-drop-all':
  for callback,args,kwargs in reversed(callbacks):callback(*args,**kwargs)
 else:fixture.doCleanups()
'''
        for mode in modes:
            with self.subTest(mode=mode):
                result = subprocess.run([sys.executable,'-c',script,str(self.output),str(Path(__file__).parent),mode],
                    capture_output=True,text=True,timeout=15)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                self.assertIn('no-C-signal; original-C/A-handles-retained; no-WholeU',result.stdout)
                if mode == 'gc-drop-all':
                    self.assertIn('all-caller-references-dropped; GC retained same owner and exact FDs',result.stdout)
                print(result.stdout.strip())

    def test_original_O_pending_G_rollback_finish_deadline_and_signal_keep_real_C_wait_owner(self):
        self._run_original_O_owner_probe(('pending-G','rollback','finish','deadline','direct-signal'))

    def test_pending_G_all_caller_references_dropped_keeps_fixed_original_owner_root(self):
        self._run_original_O_owner_probe(('gc-drop-all',))


if __name__ == '__main__': unittest.main(verbosity=2)
