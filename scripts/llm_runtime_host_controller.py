"""Internal PN4 C mechanics under original O, not a funded execution factory.

No CLI, public acquisition function or signed/opaque authorization producer is
provided. Existing Hepta funded/FinalUse owners must gate any future call site.
This object owns no manager, namespace, journal, refund or whole-U authority.
"""
import os
from pathlib import Path
import re
import time

import llm_runtime_host_scope as host
import llm_runtime_kernel_owned as kernel

_TOKEN = object()
_RAW = ('memory.current', 'memory.swap.current', 'memory.peak', 'memory.events',
        'cpu.stat', 'cgroup.events', 'cgroup.stat', 'pids.current', 'cgroup.procs')
_PHASES = ('CONTROLLER_PREPARED', 'CONTROLLER_STARTING', 'CONTROLLER_RUNNING',
           'CONTROLLER_EXIT_OBSERVED')
require = kernel.require


class _HostControllerOperation:
    """Private mechanics only; original HostScopeAdmission retains all ancestry.

    The unchanged native fixed slot retains this binding and the original
    _Wait4Child before clone3; no new reaper, authority issuer or manager exists.
    Missing funding/FinalUse producers deliberately leave this without a factory.
    """
    spawn = kernel._ControlledOperation.spawn
    allow_exec = kernel._ControlledOperation.allow_exec

    def __init__(self, token, cap, deadline):
        require(token is _TOKEN and type(cap) is host.HostScopeAdmission,
                'host-controller-private-mechanics')
        require(type(deadline) is float and 0 < deadline-time.monotonic() <= 8,
                'host-controller-original-deadline')
        self.cap, self.native, self.deadline = cap, cap._native, deadline
        with self.native._lock_for_owner():
            require(self.native._busy._recursion_count() == 1,
                    'kernel-native-lifecycle-busy')
            with cap._lock:
                cap.verify_child_preparation()
                require(self.native.operation is None, 'kernel-native-operation-retained')
                control = cap._groups['scope'][1]
                self.operation = kernel._ROOT/control.lstrip('/')/'host'/cap._operation_name/'controller'
                fd = cap._groups['controller'][2]
                self.nodes = [(self.operation, fd, cap._groups['controller'][3], None)]
                self.owner = cap  # Original namespace owner, never a supplied DTO.
                self.failed = self.consumed = self.closed = False
                self.native_refused_without_child = False
                self.spawn_owner = self.child = None
                self._aggregate = None  # One private subordinate native launch, never a grant.
                self._retirement_terminal = None
                self._retirement_latch_failure = None
                self._first_error = None
                self._meters = {'operation': (0, 0), 'controller': (0, 0), 'aggregate': (0, 0)}
                self._source = kernel._digest(kernel._bytes(Path(__file__)))
                self.native.operation = self  # Retain before any subsequent fallible observation.
                cap._leaf_phase = 'CONTROLLER_PREPARED'
                self._verify_locked()

    def __reduce_ex__(self, protocol):
        raise TypeError('host-controller-not-serializable')

    def __copy__(self):
        raise TypeError('host-controller-not-copyable')

    def __deepcopy__(self, memo):
        raise TypeError('host-controller-not-copyable')

    def _refuse(self, error):
        if self._first_error is None:
            self._first_error = error  # Same exception object, no formatting/copy or retry.
        self.failed = True
        self.cap._leaf_phase, self.cap._failed, self.cap._ready = 'UNKNOWN_RETAINED', True, False
        if self._aggregate is not None and getattr(self.cap, '_retirement_attempt', None) is self._aggregate:
            try:
                self.native.retain_retirement(self._aggregate._retirement)
            except BaseException as failure:
                # Preserve the original first failure even at this error path.
                # One fixed retained diagnostic, no retry/helper/clear action.
                if self._retirement_latch_failure is None:
                    self._retirement_latch_failure = failure

    def _verify_locked(self):
        try:
            cap = self.cap
            require(not self.failed and not self.closed and self.native.operation is self and
                cap._leaf_phase in _PHASES and cap._started and not cap._ready and not cap._failed,
                'host-controller-phase-or-sticky-failure')
            require(kernel._digest(kernel._bytes(Path(__file__))) == self._source,
                    'host-controller-source-changed')
            if self.consumed:
                from llm_runtime_pilot import _Wait4Child
                require(type(self.spawn_owner) is _Wait4Child and
                    self.spawn_owner.kernel_operation is self, 'host-controller-original-child-owner')
            cap._owner()
            control = cap._manager_readback()
            require(kernel._text(cap._proc, 'cgroup') == '0::'+control+'/host/observer\n',
                    'host-observer-membership')
            require(tuple(cap._groups) == ('scope', 'host', 'observer', 'operation', 'controller', 'aggregate'),
                    'host-children-exact-registered-groups')
            for fd, values in cap._ancestors:
                require(all(kernel._text(fd, key) == value for key, value in values.items()),
                        'host-ancestor-ceiling-changed')
            for role, (parent, name, fd, identity) in cap._groups.items():
                if parent is not None:
                    fresh = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                    dir_fd=parent)
                    try:
                        require(kernel.proc._signature(fresh) == identity, 'host-group-replaced')
                    finally:
                        os.close(fresh)
                cap._check_mount(fd)
                require(kernel._text(fd, 'cgroup.type') == 'domain\n' and
                    all(kernel._text(fd, key) == value for key, value in host._limits(role).items()),
                    'host-exact-budget-required')
                names = {'scope': frozenset(('host',)),
                    'host': frozenset(('observer', cap._operation_name)),
                    'operation': frozenset(('controller', 'aggregate'))}.get(role, frozenset())
                require(host._directory_names(fd) == names, 'host-controller-exact-topology')
                tree = host._fields(kernel._text(fd, 'cgroup.stat'))
                require(tree.get('nr_descendants') == {'scope': 5, 'host': 4, 'operation': 2}.get(role, 0)
                    and tree.get('nr_dying_descendants') == 0 and
                    all(value == 0 for key, value in tree.items() if key.startswith('nr_dying_')),
                    'host-descendant-or-dying-mismatch')
                actual = kernel._text(fd, 'cgroup.subtree_control').split()
                expected = host._CONTROLLERS if role in ('scope', 'host', 'operation') else frozenset()
                require(len(actual) == len(expected) and frozenset(actual) == expected,
                        'host-subtree-controllers')
            for role in ('scope', 'host', 'operation'):
                require(kernel._text(cap._groups[role][2], 'cgroup.procs') == '',
                        'host-original-only-observer')
            require(kernel._text(cap._groups['observer'][2], 'cgroup.procs') == str(cap._pid)+'\n',
                    'host-original-only-observer')
            launch = self._aggregate
            if launch is not None:
                from llm_runtime_host_aggregate import _AggregateLaunch
                require(type(launch) is _AggregateLaunch and launch.operation is self,
                        'host-aggregate-private-mechanics')
                launch._verify_locked()
            if launch is None or not self.consumed:
                cap._require_pristine('aggregate', cap._groups['aggregate'][2])
            roles = ('operation', 'controller', 'aggregate') if launch is not None and self.consumed else (
                'operation', 'controller')
            raw = {role: {key: kernel._text(cap._groups[role][2], key) for key in _RAW}
                   for role in roles}
            require(sum(len(v) for group in raw.values() for v in group.values()) <= 65536,
                    'host-controller-observation-bound')
            for role, values in raw.items():
                current, peak = (host._decimal(values[key]) for key in ('memory.current', 'memory.peak'))
                cpu = host._fields(values['cpu.stat'])
                events = host._fields(values['memory.events'])
                tasks = host._decimal(values['pids.current'])
                require('usage_usec' in cpu and {'low', 'high', 'max', 'oom', 'oom_kill'} <= set(events)
                    and not any(events.values()) and values['memory.swap.current'] == '0\n' and
                    0 <= current <= peak <= host._BUDGETS[role][0] and
                    tasks <= host._BUDGETS[role][2], 'host-controller-active-budget')
                old_peak, old_cpu = self._meters[role]
                require(peak >= old_peak and cpu['usage_usec'] >= old_cpu,
                        'host-controller-historical-meter-rewind')
                self._meters[role] = (peak, cpu['usage_usec'])
            task_counts = {}
            for role in roles[1:]:
                procs = raw[role]['cgroup.procs']
                require(procs == '' or re.fullmatch(r'(?:[1-9][0-9]{0,9}\n){1,'+
                    str(host._BUDGETS[role][2])+r'}', procs), 'host-controller-task-format')
                pids = procs.splitlines()
                tasks = host._decimal(raw[role]['pids.current'])
                # pids.current counts tasks/threads; procs lists thread groups.
                require(len(pids) == len(set(pids)) and all(int(pid) < 2**31 for pid in pids) and
                    len(pids) <= tasks, 'host-controller-task-population')
                task_counts[role] = tasks
            task_counts['operation'] = sum(task_counts.values())
            require(host._decimal(raw['operation']['pids.current']) == task_counts['operation'],
                    'host-controller-task-population')
            for role in roles:
                require(host._fields(raw[role]['cgroup.events']).get('populated') ==
                    (1 if task_counts[role] else 0),
                        'host-controller-task-population')
            if not self.consumed:
                cap._require_pristine('controller', cap._groups['controller'][2])
            return raw
        except BaseException as error:
            self._refuse(error)
            raise

    def _spawn_locked(self, command, stdout, owner):
        from llm_runtime_pilot import _Wait4Child
        try:
            require(type(owner) is _Wait4Child and owner.kernel_operation is self and
                time.monotonic() < self.deadline, 'host-controller-original-child-owner')
            self.cap._leaf_phase = 'CONTROLLER_STARTING'
            if self._aggregate is None:
                kernel._ControlledOperation._spawn_locked(self, command, stdout, owner)
            else:
                self._verify_locked()
                self._aggregate._spawn_locked(command, stdout, owner)
        except BaseException as error:
            self._refuse(error)
            raise

    def _allow_exec_locked(self, owner, deadline):
        try:
            require(deadline == self.deadline and time.monotonic() < deadline,
                    'host-controller-original-deadline')
            kernel._ControlledOperation._allow_exec_locked(self, owner, deadline)
            self.cap._leaf_phase = 'CONTROLLER_RUNNING'
        except BaseException as error:
            self._refuse(error)
            raise

    def terminal_record(self, pid, pidfd):
        with self.native._lock_for_owner():
            require(self.native._busy._recursion_count() == 1, 'kernel-native-lifecycle-busy')
            try:
                from llm_runtime_pilot import _Wait4Child
                child = self.spawn_owner
                require(type(child) is _Wait4Child and child.kernel_operation is self and
                    child._kernel_admitted is True and child.reaped and child.reap_resolved and child.owned_exit_observed and
                    child.cleanup_method == 'wait4' and child.observation_error is None and
                    self.child == (pid, pidfd, kernel.proc._signature(pidfd)) and
                    child.pid == pid and child.termination_fd == pidfd and
                    time.monotonic() < self.deadline, 'host-controller-exact-wait4-before-cutoff')
                raw = self._verify_locked()
                require(raw['controller']['cgroup.procs'] == '' and
                    raw['controller']['pids.current'] == raw['operation']['pids.current'] == '0\n',
                    'host-controller-descendants-remain')
                aggregate_record = None
                if self._aggregate is not None:
                    require(raw['aggregate']['cgroup.procs'] == '' and
                        raw['aggregate']['pids.current'] == '0\n', 'host-controller-descendants-remain')
                    aggregate_record = self._aggregate._terminal_locked(child)
                    self._retirement_terminal = self._aggregate._terminal_fact
                self.cap._leaf_phase = 'CONTROLLER_EXIT_OBSERVED'
                result = dict(scope='original-O-exact-wait4-C-only', counters=raw,
                    waited_cpu_ns=child.waited_cpu_ns, exit_code=child.returncode,
                    whole_u_terminal=False, resource_return_proven=False,
                    reservation='RETAINED', outer_reconciliation='UNKNOWN', authorization=False)
                if aggregate_record is not None:
                    result['aggregate_wait4_transport'] = aggregate_record
                return result
            except BaseException as error:
                self._refuse(error)
                raise

    def _retire_children(self):
        """One private original-owner effect; no Whole-U or settlement fact."""
        with self.native._lock_for_owner():
            require(self.native._busy._recursion_count() == 1, 'kernel-native-lifecycle-busy')
            try:
                from llm_runtime_host_aggregate import _AggregateLaunch
                require(type(self._aggregate) is _AggregateLaunch and
                    getattr(self.cap, '_retirement_attempt', None) is None,
                    'host-retirement-original-single-attempt')
                return self._aggregate._activate_retirement_locked()
            except BaseException as error:
                self._refuse(error)
                raise

    def _retirement_status(self):
        with self.native._lock_for_owner():
            require(self.native._busy._recursion_count() == 1 and self._aggregate is not None,
                    'host-retirement-original-single-attempt')
            try:
                return self._aggregate._retirement_status_locked()
            except BaseException as error:
                self._refuse(error)
                raise
