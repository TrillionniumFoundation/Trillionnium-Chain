"""Private controlled aggregate mechanics v2, not a grant or whole-unit receipt.

An external original wait4 owner stays in U/controller; its Python supervisor
and every payload participant belong to leaf A. No group/unit is created or
deleted here. No Store, FinalUse, refund or physical-RSS authority is supplied.
"""
import os
from pathlib import Path
import re
import stat
import subprocess
from types import MappingProxyType
from typing import NamedTuple

import llm_runtime_kernel_owned as kernel

_TOKEN = object()
_PARENT_MEMORY = 16*1024**3
_RAW = ('memory.current', 'memory.swap.current', 'memory.peak', 'memory.events',
        'cpu.stat', 'cgroup.events', 'cgroup.stat', 'pids.current', 'cgroup.procs')
require = kernel.require


def _source():
    return kernel._digest(kernel._bytes(Path(__file__)))


class _CounterDiagnostic(NamedTuple):
    filename: str
    raw: str
    reason: str


class AggregateCounterError(kernel.KernelBudgetError):
    """Bounded original parse input only; no capability or release authority."""
    def __init__(self, code, filename, raw):
        _counter_input(raw, filename)
        require(type(code) is str and code in ('aggregate-counter-format',
            'aggregate-counter-overflow', 'aggregate-counter-fields', 'aggregate-counter-scalar'),
            'aggregate-counter-reason')
        super().__init__(code)
        self._counter_diagnostic = _CounterDiagnostic(filename, raw, code)

    @property
    def counter_diagnostic(self):
        return self._counter_diagnostic


def _counter_input(raw, filename):
    # Match the existing _text read bound before retaining diagnostic text.
    require(type(raw) is str and len(raw) <= 65536, 'aggregate-counter-bound')
    require(type(filename) is str and filename in
            tuple('aggregate/'+name for name in _RAW) + ('unit/cgroup.stat',),
            'aggregate-counter-filename')


def _counter_require(condition, code, filename, raw):
    if not condition:
        raise AggregateCounterError(code, filename, raw)


def _numbers(raw, filename):
    _counter_input(raw, filename)
    fields = {}
    for line in raw.splitlines():
        values = line.split()
        _counter_require(len(values) == 2 and values[0] not in fields and
            (re.fullmatch(r'[a-z_]+', values[0]) or values[0] == 'core_sched.force_idle_usec')
            and re.fullmatch(r'[0-9]{1,20}', values[1]), 'aggregate-counter-format', filename, raw)
        fields[values[0]] = int(values[1])
        _counter_require(fields[values[0]] < 2**64, 'aggregate-counter-overflow', filename, raw)
    _counter_require(0 < len(fields) <= 64, 'aggregate-counter-fields', filename, raw)
    return fields


def _scalar(raw, filename):
    _counter_input(raw, filename)
    _counter_require(re.fullmatch(r'[0-9]{1,20}\n', raw), 'aggregate-counter-scalar', filename, raw)
    value = int(raw)
    _counter_require(value < 2**64, 'aggregate-counter-overflow', filename, raw)
    return value


def _raw(fd):
    raw = {name: kernel._text(fd, name) for name in _RAW}
    require(raw['cgroup.procs'] == '' and _scalar(raw['pids.current'], 'aggregate/pids.current') == 0 and
        _numbers(raw['cgroup.events'], 'aggregate/cgroup.events').get('populated') == 0, 'aggregate-not-empty')
    tree = _numbers(raw['cgroup.stat'], 'aggregate/cgroup.stat')
    require(tree.get('nr_descendants') == 0 and tree.get('nr_dying_descendants') == 0,
            'aggregate-descendants-or-dying')
    require(all(value == 0 for key, value in tree.items() if key.startswith('nr_dying_')),
            'aggregate-dying-charge')
    require(_scalar(raw['memory.current'], 'aggregate/memory.current') == 0 and
            _scalar(raw['memory.swap.current'], 'aggregate/memory.swap.current') == 0,
            'aggregate-charge-retained')
    _scalar(raw['memory.peak'], 'aggregate/memory.peak')
    _numbers(raw['memory.events'], 'aggregate/memory.events')
    require('usage_usec' in _numbers(raw['cpu.stat'], 'aggregate/cpu.stat'), 'aggregate-cpu-counter-missing')
    return raw


class _TerminalAggregateFact:
    __slots__ = ('operation', 'counters', 'waited_cpu_ns', 'exit_code')

    def __init__(self, token, counters, waited_cpu_ns, exit_code=None, operation=None):
        require(token is _TOKEN and type(operation) is _AggregateOperation, 'aggregate-private-fact')
        self.operation, self.counters = operation, MappingProxyType(dict(counters))
        self.waited_cpu_ns, self.exit_code = waited_cpu_ns, exit_code


class _AggregateOperation:
    # Same native spawn, pre-exec membership gate, signal-safe owner handoff and
    # no-child-only descriptor closure. This is NOT a ControlledOperation subtype.
    spawn = kernel._ControlledOperation.spawn
    _spawn_locked = kernel._ControlledOperation._spawn_locked
    allow_exec = kernel._ControlledOperation.allow_exec
    _allow_exec_locked = kernel._ControlledOperation._allow_exec_locked
    close = kernel._ControlledOperation.close
    _close_locked = kernel._ControlledOperation._close_locked
    verify = kernel._ControlledOperation.verify

    def __init__(self, token, native, unit, invocation, operation, memory, controller, owner):
        require(token is _TOKEN and type(native) is kernel._Native and owner is not None,
                'aggregate-live-constructor')
        with native._lock_for_owner():
            require(native._busy._recursion_count() == 1, 'kernel-native-lifecycle-busy')
            self._initialize_locked(native, unit, invocation, operation, memory, controller, owner)

    def _initialize_locked(self, native, unit, invocation, operation, memory, controller, owner):
        require(native.fd >= 0 and native.operation is None, 'kernel-native-operation-retained')
        require(type(memory) is int and memory in (8*1024**3, _PARENT_MEMORY), 'aggregate-memory')
        require(type(controller) is dict, 'aggregate-controller-finite-budget')
        controller = controller.copy()  # Never reread a caller's mutable budget after IO.
        bounds = {'memory_bytes': _PARENT_MEMORY, 'cpu_quota_us': 400000, 'tasks': 256}
        require(set(controller) == set(bounds) and
            all(type(controller[k]) is int and 0 < controller[k] <= bounds[k] for k in bounds),
            'aggregate-controller-finite-budget')
        require(memory + controller['memory_bytes'] <= _PARENT_MEMORY and
            controller['cpu_quota_us'] < bounds['cpu_quota_us'] and controller['tasks'] < bounds['tasks'],
            'aggregate-controller-headroom')
        require(re.fullmatch(r'[A-Za-z0-9_-]+\.service', unit) and
            re.fullmatch(r'[0-9a-f]{32}', invocation) and
            os.environ.get('INVOCATION_ID') == invocation, 'aggregate-invocation')
        own = Path('/proc/self/cgroup').read_text()
        require(own.startswith('0::/user.slice/') and own.endswith('/'+unit+'/controller\n'),
                'aggregate-controller-membership')
        self.unit_path = kernel._ROOT/own[3:].strip().removesuffix('/controller').lstrip('/')
        self.operation = Path(operation)
        require(self.operation.parent == self.unit_path and
            re.fullmatch(r'aggregate-[0-9a-f]{32}', self.operation.name), 'aggregate-direct-leaf')
        self.native, self.unit, self.invocation, self.owner = native, unit, invocation, owner
        self.memory, self.membership, self.nodes = memory, own, []
        self.source = _source()
        self.boot = Path('/proc/sys/kernel/random/boot_id').read_text()
        self.failed = self.consumed = self.closed = self.native_refused_without_child = False
        self.child = self.spawn_owner = self.fact = None
        import ctypes
        self._fd_owners = [(ctypes.c_int*4)(0, -1, -1, -1) for _ in range(16)]
        self._close_required = kernel.KernelOwnedCloseRequired(self)
        native.operation = self  # Same fixed strong slot before any group FD opens.
        try:
            finite = dict(kernel._FIXED, **{'memory.max': str(memory)+'\n',
                'cpu.max': str(bounds['cpu_quota_us']-controller['cpu_quota_us'])+' 100000\n',
                'pids.max': str(bounds['tasks']-controller['tasks'])+'\n',
                'cgroup.max.descendants': '0\n', 'cgroup.subtree_control': ''})
            control = dict(finite, **{'memory.max': str(controller['memory_bytes'])+'\n',
                'cpu.max': str(controller['cpu_quota_us'])+' 100000\n',
                'pids.max': str(controller['tasks'])+'\n'})
            unit_fields = dict(kernel._FIXED, **{'memory.max': str(_PARENT_MEMORY)+'\n',
                'cgroup.max.descendants': '2\n', 'cgroup.max.depth': '1\n'})
            self._open(self.operation, finite)
            self._open(self.unit_path/'controller', control)
            path = self.unit_path
            while path != kernel._ROOT:
                self._open(path, unit_fields if path == self.unit_path else None)
                path = path.parent
            mount = next((line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines()
                          if line.split()[4] == str(kernel._ROOT)), [])
            require('cgroup2' in mount and '-' in mount and
                mount[mount.index('-')+1] == 'cgroup2', 'aggregate-cgroup2-mount')
            for _, fd, signature, _ in self.nodes:
                info = dict(row.split(':', 1) for row in Path(f'/proc/self/fdinfo/{fd}').read_text().splitlines())
                require(signature[0] == kernel._ROOT.stat().st_dev and
                    info['mnt_id'].strip() == mount[0], 'aggregate-shadow-mount')
            initial = _raw(self.nodes[0][1])
            require(_scalar(initial['memory.peak'], 'aggregate/memory.peak') == 0 and
                all(value == 0 for name in ('cpu.stat', 'memory.events')
                    for value in _numbers(initial[name], 'aggregate/'+name).values()), 'aggregate-not-fresh')
            self._verify_locked()
        except BaseException:
            try: self._close_locked(owner)
            except BaseException: raise self._close_required
            raise

    def _open(self, path, expected):
        require(len(self.nodes) < 16 and path.resolve() == path, 'aggregate-ancestor-bound')
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self._fd_owners[len(self.nodes)][1] = fd
        signature = kernel.proc._signature(fd)
        self.nodes.append((path, fd, signature, None))
        names = expected if expected is not None else (*kernel._FIXED, 'memory.max')
        fields = {name: kernel._text(fd, name) for name in names}
        if expected is not None:
            require(fields == expected and os.fstat(fd).st_uid == os.getuid(), 'aggregate-finite-limits')
        else:
            quota, period = fields['cpu.max'].split()
            require(fields['cgroup.type'] == 'domain\n' and
                (quota == 'max' or int(quota) >= 4*int(period)) and
                (fields['memory.max'] == 'max\n' or int(fields['memory.max']) >= _PARENT_MEMORY) and
                (fields['pids.max'] == 'max\n' or int(fields['pids.max']) >= 256), 'aggregate-tighter-ancestor')
        self.nodes[-1] = (path, fd, signature, fields)

    def _verify_locked(self):
        require(not self.closed and not self.failed, 'aggregate-closed-or-sticky')
        try:
            require(self.native.sources == kernel._sources() and self.source == _source() and
                Path('/proc/self/cgroup').read_text() == self.membership and
                Path('/proc/sys/kernel/random/boot_id').read_text() == self.boot,
                'aggregate-source-or-owner-moved')
            observation = subprocess.run(['/usr/bin/systemctl', '--user', 'show', self.unit,
                '--property=InvocationID', '--property=ControlGroup', '--property=MainPID',
                '--property=Delegate', '--property=DelegateSubgroup'], capture_output=True, text=True, timeout=2)
            require(observation.returncode == 0 and len(observation.stdout) < 8192, 'aggregate-unit-observation')
            actual = dict(row.split('=', 1) for row in observation.stdout.splitlines())
            require(actual == dict(InvocationID=self.invocation,
                ControlGroup='/'+str(self.unit_path.relative_to(kernel._ROOT)), MainPID=str(os.getpid()),
                Delegate='yes', DelegateSubgroup='controller'), 'aggregate-unit-identity')
            for path, fd, signature, expected in self.nodes:
                meta = path.lstat()
                require(stat.S_ISDIR(meta.st_mode) and
                    (meta.st_dev, meta.st_ino, meta.st_mode) == signature == kernel.proc._signature(fd),
                    'aggregate-path-or-fd-replaced')
                require({name: kernel._text(fd, name) for name in expected} == expected,
                        'aggregate-limits-changed')
            unit_fd = self.nodes[2][1]
            tree = _numbers(kernel._text(unit_fd, 'cgroup.stat'), 'unit/cgroup.stat')
            require(kernel._text(unit_fd, 'cgroup.procs') == '' and
                tree.get('nr_descendants') == 2 and tree.get('nr_dying_descendants') == 0 and
                all(value == 0 for key, value in tree.items() if key.startswith('nr_dying_')),
                'aggregate-parent-participants-or-dying')
        except BaseException:
            self.failed = True
            raise

    def terminal_record(self, pid, pidfd):
        with self.native._lock_for_owner():
            require(self.native._busy._recursion_count() == 1, 'kernel-native-lifecycle-busy')
            try:
                from llm_runtime_pilot import _Wait4Child
                self._verify_locked()
                child = self.spawn_owner
                require(type(child) is _Wait4Child and child.kernel_operation is self and
                    self.child == (pid, pidfd, kernel.proc._signature(pidfd)) and child.pid == pid and
                    child.termination_fd == pidfd and child.reaped and child.reap_resolved and
                    child.owned_exit_observed and not child.no_waitable_child_observed and
                    child.cleanup_method == 'wait4' and child.observation_error is None and
                    type(child.waited_cpu_ns) is int and child.waited_cpu_ns >= 0 and
                    type(child.returncode) is int,
                    'aggregate-exact-owned-wait4-required')
                raw = _raw(self.nodes[0][1])
                self._verify_locked()
                require(raw == _raw(self.nodes[0][1]), 'aggregate-counter-snapshot-changed')
                fact = _TerminalAggregateFact(_TOKEN, raw, child.waited_cpu_ns, child.returncode, self)
                result = dict(scope='controlled-aggregate-mechanics-v2-charge-not-RSS', counters=raw,
                    aggregate_observed=True, supervisor_exit_code=child.returncode,
                    outer_reconciliation='UNKNOWN', reservation='RETAINED',
                    authorization=False, adoption=False)
                self.fact = fact
                return result
            except BaseException:
                self.failed = True
                raise


def acquire_aggregate_mechanics(native, *, unit, invocation, operation, memory_bytes, controller_budget, owner):
    """Bind pre-existing live finite groups. Paths/limits do not grant authority."""
    return _AggregateOperation(_TOKEN, native, unit, invocation, operation, memory_bytes, controller_budget, owner)
