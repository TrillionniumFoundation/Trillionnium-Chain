"""Private fixed native C→A handoff, subordinate to the original O capability.

No funding/grant producer or public acquisition path. The C record is bounded
transport after C's exact wait4(A); O's separate exact wait4(C) and actual raw
U/C/A observations remain mandatory. Private child retirement grants no Whole-U
or refund authority and never clears the original process-lifetime owner root.
"""
import ctypes
import fcntl
import os
from pathlib import Path
import stat
import struct
import threading
import time

import llm_runtime_kernel_owned as kernel

_TOKEN = object()
_MAGIC = 0x31574134544e5243
require = kernel.require


class _ExactTerminal:
    """One internal fact, emitted only after the original two exact waits."""
    __slots__ = ('launch', 'child', 'record', 'binding')

    def __init__(self, token, launch, child):
        require(token is _TOKEN and launch.record is not None,
                'host-retirement-exact-terminal-required')
        self.launch, self.child, self.record = launch, child, launch.record
        self.binding = launch.operation.child

    def __reduce_ex__(self, protocol):
        raise TypeError('host-retirement-terminal-not-serializable')

    def __copy__(self):
        raise TypeError('host-retirement-terminal-not-copyable')

    def __deepcopy__(self, memo):
        raise TypeError('host-retirement-terminal-not-copyable')


class _ControllerWaitRole:
    """A retention-only role, installed before native C can possibly run A.

    No release/unlock operation exists in this slice. Even timely C/A exit keeps
    the original C pidfd for the still-open original-owner retirement protocol.
    """
    __slots__ = ('launch', 'child')

    def __init__(self, token, launch, child):
        from llm_runtime_pilot import _Wait4Child
        require(token is _TOKEN and type(launch) is _AggregateLaunch and type(child) is _Wait4Child and
            child.kernel_operation is launch.operation and launch.operation.spawn_owner is child and
            launch.operation.native.operation is launch.operation, 'host-aggregate-retained-wait-role')
        self.launch, self.child = launch, child

    def __reduce_ex__(self, protocol):
        raise TypeError('host-aggregate-wait-role-not-serializable')

    def __copy__(self):
        raise TypeError('host-aggregate-wait-role-not-copyable')

    def __deepcopy__(self, memo):
        raise TypeError('host-aggregate-wait-role-not-copyable')


class _AggregateLaunch:
    def __init__(self, token, operation, command):
        from llm_runtime_host_controller import _HostControllerOperation
        require(token is _TOKEN and type(operation) is _HostControllerOperation,
                'host-aggregate-private-mechanics')
        from llm_runtime_host_scope import _require_aggregate_root_empty, _retain_aggregate_owner
        _require_aggregate_root_empty()  # Before command/source/slot or native-pipe work.
        require(type(command) is list and 0 < len(command) <= 256 and
            all(type(v) is str and '\0' not in v for v in command) and
            Path(command[0]).is_absolute() and sum(len(os.fsencode(v)) for v in command) <= 1024**2,
            'host-aggregate-command-bound')
        self.operation, self.command = operation, tuple(command)
        self.native = operation.native
        self.deadline_ns = int(operation.deadline * 10**9)  # Same absolute clock, never renewed.
        self.read_slot = (ctypes.c_int*4)(0, -1, -1, -1)
        self.write_slot = (ctypes.c_int*4)(0, -1, -1, -1)
        self._slots = (self.read_slot, self.write_slot)
        self.identities = (ctypes.c_uint64*6)()
        self.status = ctypes.c_int(-1)
        self.record = None
        self._terminal_fact = self._retirement_attempt = None
        self._wait_role = None
        self._retirement = (ctypes.c_uint64*24)()  # Original fixed output before native effect.
        self.source = kernel._digest(kernel._bytes(Path(__file__)))
        with self.native._lock_for_owner():
            require(self.native._busy._recursion_count() == 1, 'kernel-native-lifecycle-busy')
            require(operation._aggregate is None and not operation.consumed and
                operation.cap._leaf_phase == 'CONTROLLER_PREPARED', 'host-aggregate-before-C-birth')
            operation._verify_locked()
            operation._aggregate = self  # Strong registration precedes native pipe creation.
            try:
                _retain_aggregate_owner(self)  # Survives loss/GC of every caller reference.
                self._prepare_retirement_locked()
                returned = self.native.prepare_pipe(self.read_slot, self.write_slot,
                    self.identities, ctypes.byref(self.status))
                require(returned == self.status.value == 0, 'host-aggregate-pipe-refused')
                self._verify_locked()
            except BaseException as error:
                operation._refuse(error)
                raise

    def __reduce_ex__(self, protocol):
        raise TypeError('host-aggregate-not-serializable')

    def __copy__(self):
        raise TypeError('host-aggregate-not-copyable')

    def __deepcopy__(self, memo):
        raise TypeError('host-aggregate-not-copyable')

    def _prepare_retirement_locked(self):
        cap = self.operation.cap
        observer = cap._groups['observer']
        identity = (ctypes.c_uint64*3)(*observer[3])
        membership = os.fsencode('0::'+cap._groups['scope'][1]+'/host/observer\n')
        error = self.native.prepare_retirement(observer[2], identity, membership,
            len(membership), self.deadline_ns, self._retirement)
        require(error == 0, 'host-retirement-preparation-refused')
        # Worker is already born under the original observer before C/A or the
        # receipt pipe. Readiness consumes the SAME absolute deadline.
        while self._retirement[0] in (1, 2):
            require(time.monotonic_ns() < self.deadline_ns, 'host-retirement-readiness-cutoff')
            require(self.native.snapshot_retirement(self._retirement) == 0,
                    'host-retirement-original-worker-slot')
            if self._retirement[0] in (1, 2): time.sleep(.001)
        self._verify_retirement_locked()

    def _verify_retirement_locked(self):
        require(self.native.snapshot_retirement(self._retirement) == 0,
                'host-retirement-original-worker-slot')
        words = tuple(self._retirement)
        page = words[13]
        require(words[0] == 3 and words[1] == 0 and words[2] == os.getpid() and
            words[3] == threading.get_native_id() and 0 < words[4] < 2**31 and words[4] != words[3] and
            words[5:8] == self.operation.cap._groups['observer'][3] and words[8] == self.deadline_ns and
            4096 <= page <= 65536 and page & (page-1) == 0 and words[9] >= page and
            words[10] == 1024**2+2*page and words[11] == words[9]+page and words[12] == 1024**2 and
            words[14] == 0 and words[15] == 2**64-1 and words[16] == 1 and words[17] == 0 and
            words[11] <= words[18] < words[11]+words[12] and not any(words[19:]) and
            time.monotonic_ns() < self.deadline_ns, 'host-retirement-worker-preparation-only')

    def _verify_locked(self):
        op = self.operation
        self.native._lock_for_owner()
        require(self.native._busy._recursion_count() == 1 and op.native is self.native and
            self.native.operation is op and op._aggregate is self and not op.failed and
            not op.closed and self.deadline_ns == int(op.deadline*10**9) and
            self.read_slot is self._slots[0] and self.write_slot is self._slots[1] and
            kernel._digest(kernel._bytes(Path(__file__))) == self.source,
            'host-aggregate-original-owner-or-source')
        self._verify_retirement_locked()
        for index, slot in enumerate((self.read_slot, self.write_slot)):
            require(slot[0] == 0, 'kernel-owned-close-failed')
            if slot[1] >= 0:
                identity = tuple(self.identities[index*3:index*3+3])
                flags = fcntl.fcntl(slot[1], fcntl.F_GETFL)
                require(kernel.proc._signature(slot[1]) == identity and stat.S_ISFIFO(identity[2]) and
                    flags & os.O_NONBLOCK and flags & os.O_ACCMODE ==
                    (os.O_RDONLY if index == 0 else os.O_WRONLY) and
                    fcntl.fcntl(slot[1], fcntl.F_GETFD) & fcntl.FD_CLOEXEC,
                    'host-aggregate-pipe-identity-or-flags')

    def _spawn_locked(self, command, stdout, owner):
        op = self.operation
        self._verify_locked()
        require(type(command) is list and tuple(command) == self.command and not op.consumed and
            op.spawn_owner is None and owner.kernel_operation is op and
            time.monotonic_ns() < self.deadline_ns, 'host-aggregate-original-command-or-reuse')
        values = [os.fsencode(v) for v in self.command]
        environment = [os.fsencode(k+'='+v) for k, v in os.environ.items()]
        require(sum(map(len, values+environment)) <= 1024**2, 'kernel-exec-bound')
        array = lambda v: (ctypes.c_char_p*(len(v)+1))(*v, None)
        op.consumed, op.spawn_owner = True, owner  # Before native entry/pending signals.
        role = _ControllerWaitRole(_TOKEN, self, owner)
        self._wait_role = role
        owner._aggregate_wait_role = role  # Persistent before C birth or any G write.
        error = self.native.spawn_controller(op.nodes[0][1], op.cap._groups['aggregate'][2],
            stdout.fileno(), self.write_slot[1], values[0], array(values), array(environment),
            self.deadline_ns, owner._kernel_handoff)
        if error:
            op.native_refused_without_child = all(value == -1 for value in owner._kernel_handoff)
            raise OSError(error, 'host-aggregate-clone3-refused')
        self.native.release_owned(self.write_slot)
        require(self.write_slot[0] == 0 and self.write_slot[1] == -1, 'kernel-owned-close-failed')

    def _terminal_locked(self, child):
        self._verify_locked()
        op = self.operation
        require(op.spawn_owner is child and child.kernel_operation is op and child.reaped and
            child.reap_resolved and child.owned_exit_observed and child.cleanup_method == 'wait4' and
            child.observation_error is None and child.returncode == 0 and
            self.record is None and self.write_slot[1] == -1 and self.read_slot[1] >= 3 and
            time.monotonic_ns() < self.deadline_ns, 'host-aggregate-exact-C-wait4-before-cutoff')
        # C emitted once, after exact wait4(A), before its own exit. O has now
        # actually reaped C. One bounded nonblocking read plus EOF; no retries.
        raw = os.read(self.read_slot[1], 65)
        require(len(raw) == 64 and os.read(self.read_slot[1], 1) == b'',
                'host-aggregate-record-size-or-eof')
        magic, controller_pid, aggregate_pid, flags, status, user_us, system_us, error = struct.unpack('<8Q', raw)
        require(magic == _MAGIC and controller_pid == child.pid and 0 < aggregate_pid < 2**31 and
            aggregate_pid != child.pid and flags == 3 and error == 0 and status <= 65535 and
            (os.WIFEXITED(status) or os.WIFSIGNALED(status)) and
            user_us <= (2**64-1)//1000 and system_us <= (2**64-1)//1000 and
            time.monotonic_ns() < self.deadline_ns, 'host-aggregate-native-A-wait4-record')
        self.record = (aggregate_pid, os.waitstatus_to_exitcode(status), user_us, system_us)
        self.native.release_owned(self.read_slot)
        require(self.read_slot[0] == 0 and self.read_slot[1] == -1, 'kernel-owned-close-failed')
        require(time.monotonic_ns() < self.deadline_ns, 'host-retirement-original-cutoff')
        self._terminal_fact = _ExactTerminal(_TOKEN, self, child)
        return dict(scope='native-C-exact-wait4-A-transport-only', pid=aggregate_pid,
            exit_code=self.record[1], waited_user_us=user_us, waited_system_us=system_us,
            whole_u_terminal=False, resource_return_proven=False, reservation='RETAINED')

    def _activate_retirement_locked(self):
        op, cap = self.operation, self.operation.cap
        self.native._lock_for_owner()
        require(self.native._busy._recursion_count() == 1 and
            getattr(cap, '_retirement_attempt', None) is None,
            'host-retirement-original-single-attempt')
        raw = op._verify_locked()  # Fresh original observations; no caller-supplied DTO.
        fact, child = self._terminal_fact, op.spawn_owner
        require(type(fact) is _ExactTerminal and op._retirement_terminal is fact and
            fact.launch is self and fact.child is child and fact.record is self.record and
            fact.binding == op.child and cap._leaf_phase == 'CONTROLLER_EXIT_OBSERVED' and
            child.reaped and child.reap_resolved and child.owned_exit_observed and
            child.cleanup_method == 'wait4' and child.observation_error is None and
            child.returncode == 0 and self._wait_role is child._aggregate_wait_role and
            self._wait_role.child is child and self._wait_role.launch is self and
            time.monotonic_ns() < self.deadline_ns, 'host-retirement-exact-terminal-required')
        from llm_runtime_host_scope import _fields
        require(all(raw[role]['cgroup.procs'] == '' and raw[role]['pids.current'] == '0\n' and
            _fields(raw[role]['cgroup.events']).get('populated') == 0
            for role in ('operation', 'controller', 'aggregate')),
            'host-retirement-original-quiescence')
        handoff = child._kernel_handoff
        require(tuple(handoff) == (child.pid, child.termination_fd, -1, -1) and
            op.child == (child.pid, child.termination_fd, kernel.proc._signature(handoff[1])) and
            self.read_slot[1] == self.write_slot[1] == -1,
            'host-retirement-original-C-slots')
        owners = []
        for role in ('aggregate', 'controller'):
            parent, name, fd, identity = cap._groups[role]
            matches = [slot for slot, signature in cap._fds if slot[1] == fd and signature == identity]
            require(parent == cap._groups['operation'][2] and name == role and len(matches) == 1,
                    'host-retirement-original-group-slots')
            owners.append(matches[0])
        identities = (ctypes.c_uint64*12)(*(cap._groups['operation'][3]+
            cap._groups['aggregate'][3]+cap._groups['controller'][3]+op.child[2]))
        # Strongly retain the exact original arrays BEFORE native entry/pending
        # Python signals. No caller DTO, release switch or second owner exists.
        self._retirement_attempt = (fact, owners[0], owners[1], handoff, identities)
        cap._retirement_attempt = self
        cap._leaf_phase = 'CHILDREN_RETIRING'
        error = self.native.activate_retirement(cap._groups['operation'][2],
            owners[0], owners[1], handoff, identities, self.deadline_ns, self._retirement)
        require(error == 0, 'host-retirement-native-activation-refused')
        return self._retirement_status_locked()

    def _retirement_status_locked(self):
        # This verifier is distinct from the original live/EMPTY verifier. It
        # never reads arrays concurrently close-cleared by the worker.
        import llm_runtime_host_scope as host
        import llm_runtime_host_controller as controller
        op, cap = self.operation, self.operation.cap
        require(self.native._busy._recursion_count() == 1 and self.native.operation is op and
            op._aggregate is self and cap._retirement_attempt is self and
            self._retirement_attempt is not None and host._retained_aggregate_owner() is cap and
            kernel._digest(kernel._bytes(Path(__file__))) == self.source and
            kernel._digest(kernel._bytes(Path(controller.__file__))) == op._source,
            'host-retirement-original-retained-owner')
        cap._owner_identity()
        require(self.native.snapshot_retirement(self._retirement) == 0,
                'host-retirement-original-worker-slot')
        words = tuple(self._retirement)
        require(words[2] == cap._pid and words[3] == threading.get_native_id() and
            words[8] == self.deadline_ns and words[19] == 1 and words[20] <= 31,
            'host-retirement-original-effect-identity')
        result = dict(scope='original-O-child-retirement-only', phase=words[0],
            native_error=words[1], progress=words[20], child_unlink_and_close_proven=False,
            whole_u_terminal=False, resource_return_proven=False, reservation='RETAINED',
            outer_reconciliation='UNKNOWN', authorization=False)
        if words[0] in (4, 5) or words[1] or time.monotonic_ns() >= self.deadline_ns:
            op._refuse(kernel.KernelBudgetError('host-retirement-unknown-retained'))
            return result
        if words[0] != 7 or not words[17] or op.failed:
            return result
        require(words[20:23] == (31, 1, 0), 'host-retirement-incomplete-native-progress')
        _, aggregate, controller, child, _ = self._retirement_attempt
        require(tuple(aggregate) == tuple(controller) == (0, -1, -1, -1) and
            tuple(child) == (op.spawn_owner.pid, -1, -1, -1),
            'host-retirement-original-close-facts')
        op.spawn_owner._adopt_kernel_handoff()  # Project the original cleared pidfd, never a new owner.
        # DONE release-publishes stable close-cleared arrays. Other retained
        # handles, source, namespaces, original manager and limits stay exact.
        for slot, identity in cap._fds:
            if slot is aggregate or slot is controller: continue
            require(slot[0] == 0 and slot[1] >= 0 and kernel.proc._signature(slot[1]) == identity,
                    'host-retirement-retained-fd-changed')
        control = cap._manager_readback()
        require(kernel._text(cap._proc, 'cgroup') == '0::'+control+'/host/observer\n',
                'host-observer-membership')
        for fd, values in cap._ancestors:
            require(all(kernel._text(fd, key) == value for key, value in values.items()),
                    'host-ancestor-ceiling-changed')
        for role in ('scope', 'host', 'observer', 'operation'):
            parent, name, fd, identity = cap._groups[role]
            if parent is not None:
                fresh = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=parent)
                try: require(kernel.proc._signature(fresh) == identity, 'host-group-replaced')
                finally: os.close(fresh)
            cap._check_mount(fd)
            require(kernel._text(fd, 'cgroup.type') == 'domain\n' and
                all(kernel._text(fd, key) == value for key, value in host._limits(role).items()),
                'host-exact-budget-required')
            expected_names = {'scope': frozenset(('host',)),
                'host': frozenset(('observer', cap._operation_name))}.get(role, frozenset())
            require(host._directory_names(fd) == expected_names, 'host-retirement-exact-topology')
            tree = host._fields(kernel._text(fd, 'cgroup.stat'))
            require(tree.get('nr_descendants') == {'scope': 3, 'host': 2}.get(role, 0),
                    'host-retirement-descendant-mismatch')
            controls = kernel._text(fd, 'cgroup.subtree_control').split()
            expected = frozenset() if role == 'observer' else host._CONTROLLERS
            require(len(controls) == len(expected) and frozenset(controls) == expected,
                    'host-subtree-controllers')
            require(kernel._text(fd, 'cgroup.procs') == (str(cap._pid)+'\n' if role == 'observer' else ''),
                    'host-original-only-observer')
        from llm_runtime_host_controller import _RAW
        raw = {key: kernel._text(cap._groups['operation'][2], key) for key in _RAW}
        require(sum(map(len, raw.values())) <= 65536, 'host-controller-observation-bound')
        current, peak = (host._decimal(raw[key]) for key in ('memory.current', 'memory.peak'))
        cpu, events = host._fields(raw['cpu.stat']), host._fields(raw['memory.events'])
        old_peak, old_cpu = op._meters['operation']
        require('usage_usec' in cpu and {'low', 'high', 'max', 'oom', 'oom_kill'} <= set(events) and
            not any(events.values()) and raw['memory.swap.current'] == '0\n' and
            0 <= current <= peak <= host._BUDGETS['operation'][0] and
            peak >= old_peak and cpu['usage_usec'] >= old_cpu and
            raw['pids.current'] == '0\n' and raw['cgroup.procs'] == '' and
            host._fields(raw['cgroup.events']).get('populated') == 0,
            'host-retirement-U-history-or-quiescence')
        op._meters['operation'] = (peak, cpu['usage_usec'])
        require(time.monotonic_ns() < self.deadline_ns, 'host-retirement-original-cutoff')
        result.update(child_unlink_and_close_proven=True, counters=raw)
        return result  # Raw U.current/dying may remain positive. Never a Whole-U/refund fact.
