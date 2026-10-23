"""Fresh PN4 host namespace and subsequent-charge boundary, not an execution grant.

S is the original manager scope. H is its create-only delegated child. O is the
existing caller, moved by its original request S -> H -> H/observer.
Existing charged pages DO NOT migrate with O. These finite limits
therefore do not bound O's complete RSS or reserve/fund H. No C birth, whole-U
terminal fact, refund, installation or adoption of an old capability exists.
An uncertain effect retains this original object/FDs; it is never rolled back
by deleting groups, stopping a scope, resetting counters or moving O back.
"""
import ctypes
import json
import os
from pathlib import Path
import re
import stat
import threading
import uuid

import llm_runtime_kernel_owned as kernel
import llm_runtime_host_scope_io as bus

_TOKEN = object()
_LEAF_FACT_TOKEN = object()
_ROOT = Path('/sys/fs/cgroup')
_CONTROLLERS = frozenset(('cpu', 'memory', 'pids'))
_NAMESPACES = ('mnt', 'cgroup', 'pid', 'user')
_PROFILE = 'linux-fresh-host-namespace-charge-boundary-v1'
_BUDGETS = {'scope': (17*1024**3, 500000, 272), 'host': (17*1024**3, 500000, 272),
    'observer': (1024**3, 100000, 16), 'operation': (16*1024**3, 400000, 256),
    'controller': (128*1024**2, 100000, 16), 'aggregate': (8*1024**3, 300000, 240)}


def _source():
    paths = (Path(__file__), Path(bus.__file__), Path(kernel.__file__), kernel._C,
             Path(kernel.proc.__file__))
    return tuple((p.name, kernel._digest(kernel._bytes(p))) for p in paths)


def _decimal(raw):
    kernel.require(type(raw) is str and re.fullmatch(r'(0|[1-9][0-9]{0,19})\n', raw),
                   'host-counter-format')
    value = int(raw)
    kernel.require(value < 2**64, 'host-counter-overflow')
    return value


def _fields(raw):
    kernel.require(type(raw) is str and len(raw) <= 65536, 'host-fields-bound')
    rows = raw.splitlines()
    kernel.require(0 < len(rows) <= 64, 'host-fields-count')
    values = {}
    for row in rows:
        parts = row.split()
        kernel.require(len(parts) == 2 and (re.fullmatch(r'[a-z_]+', parts[0]) or
            parts[0] == 'core_sched.force_idle_usec') and
            parts[0] not in values, 'host-fields-format')
        values[parts[0]] = _decimal(parts[1]+'\n')
    return values


def _directory_names(fd):
    # cgroup interface files occupy the same namespace; bound the whole scan.
    result = []
    with os.scandir(fd) as entries:
        for count, entry in enumerate(entries, 1):
            kernel.require(count <= 128, 'host-directory-entry-bound')
            if entry.is_dir(follow_symlinks=False):
                result.append(entry.name)
    return frozenset(result)


def _limits(role):
    memory, cpu, tasks = _BUDGETS[role]
    depth, descendants = {'host': (2, 4), 'operation': (1, 2)}.get(role, (0, 0))
    result = {'memory.max': str(memory)+'\n', 'memory.swap.max': '0\n',
        'cpu.max': str(cpu)+' 100000\n', 'cpu.max.burst': '0\n',
        'pids.max': str(tasks)+'\n', 'cgroup.max.depth': str(depth)+'\n',
        'cgroup.max.descendants': str(descendants)+'\n'}
    if role == 'scope':
        # These S controls are manager-owned and NOT delegated by systemd255.
        del result['cgroup.max.depth'], result['cgroup.max.descendants']
    return result


def _ancestor_allows(values):
    # Compatible ceilings are not a reservation or a CPU-service guarantee.
    # Dynamic current charges are deliberately not treated as available money.
    kernel.require(set(values) == {'memory.max', 'cpu.max', 'pids.max'},
                   'host-ancestor-fields')
    for name, minimum in (('memory.max', 17*1024**3), ('pids.max', 272)):
        kernel.require(values[name] == 'max\n' or _decimal(values[name]) >= minimum,
                       'host-ancestor-insufficient-ceiling')
    parts = values['cpu.max'].split()
    kernel.require(len(parts) == 2, 'host-ancestor-cpu-format')
    period = _decimal(parts[1]+'\n')
    kernel.require(0 < period <= 1000000 and (parts[0] == 'max' or
        _decimal(parts[0]+'\n') >= 5*period), 'host-ancestor-insufficient-cpu-ceiling')


def _pristine_message(failure):
    role, field, raw, reason, unit, operation, fd, identity = failure
    data = {'schema': 'host-pristine-first-read-v1', 'role': role, 'field': field,
        'original_reason': reason, 'unit': unit, 'operation': operation,
        'stored_fd': fd, 'stored_identity': identity, 'raw': raw,
        'raw_characters': len(raw) if raw is not None else None,
        'raw_sha256_utf8': kernel._digest(raw.encode('utf-8')) if raw is not None else None,
        'raw_truncated_in_message': False, 'read_again': False}
    prefix = reason+'; host-pristine-diagnostic='
    message = prefix+json.dumps(data, sort_keys=True, separators=(',', ':'))
    # The original native probe exports at most4096 exception characters.
    # Keep identity/length/hash first-class and mark any omitted raw suffix;
    # failure itself retains the complete first returned <=65536-character raw.
    while len(message) > 3900 and data['raw']:
        data['raw'] = data['raw'][:len(data['raw'])//2]
        data['raw_truncated_in_message'] = True
        message = prefix+json.dumps(data, sort_keys=True, separators=(',', ':'))
    return message


class _FreshULeafFact:
    """One nontransferable preparation fact, owned by the existing original cap."""
    __slots__ = ('_owner', '_generation', '_binding')

    def __init__(self, token, owner):
        kernel.require(token is _LEAF_FACT_TOKEN and type(owner) is HostScopeAdmission,
                       'host-leaf-private-fact')
        self._owner, self._generation = owner, owner._leaf_generation
        self._binding = owner._leaf_binding()

    def __reduce_ex__(self, protocol):
        raise TypeError('host-leaf-fact-not-serializable')

    def __copy__(self):
        raise TypeError('host-leaf-fact-not-copyable')

    def __deepcopy__(self, memo):
        raise TypeError('host-leaf-fact-not-copyable')


class HostScopeAdmission:
    """One original namespace request. Call admit once; retain it before any effect.

    This is intentionally not ControlledOperation or a FinalUse capability.
    Native admission remains NOT_RUN until a reviewed fresh-host test executes.
    """
    def __init__(self, token):
        kernel.require(token is _TOKEN, 'host-private-constructor')
        self._lock = kernel._native_rlock()
        self._pid, self._thread = os.getpid(), threading.current_thread()
        self._fds, self._groups, self._namespaces, self._ancestors = [], {}, {}, []
        self._started = self._ready = self._failed = self._closed = False
        self._first_pristine_failure = None
        self._leaf_generation = self._leaf_phase = self._leaf_fact = None
        self._unit = 'trnm-host-'+uuid.uuid4().hex+'.scope'
        self._operation_name = 'operation-'+uuid.uuid4().hex
        self._source = _source()
        self._manager = self._unit_path = self._invocation = self._job = None
        self._native = None
        try:
            # Reuse the unchanged original native close-and-clear ABI. This
            # preparation compiles a sealed helper; it never calls its spawn.
            self._native = kernel.build_controlled_native()
            self._proc = self._hold('/proc/'+str(self._pid))
            self._start = kernel.proc._stat(kernel._text(self._proc, 'stat'))['starttime']
            self._boot = kernel._bytes(Path('/proc/sys/kernel/random/boot_id'), 65536)
            self._original_membership = kernel._text(self._proc, 'cgroup')
            kernel.require(re.fullmatch(r'0::/user\.slice/[^\n]{1,4096}\n',
                           self._original_membership), 'host-original-user-membership')
            for name in _NAMESPACES:
                # proc namespace handles are intentional kernel magic links.
                fd = os.open('ns/'+name, os.O_RDONLY | os.O_CLOEXEC, dir_fd=self._proc)
                self._retain(fd)
                self._namespaces[name] = (fd, kernel.proc._signature(fd))
            self._root = self._hold(str(_ROOT))
            mountinfo = kernel._text(self._proc, 'mountinfo')
            mounts = [line.split() for line in mountinfo.splitlines()
                      if len(line.split()) > 6 and line.split()[4] == str(_ROOT)]
            kernel.require(len(mounts) == 1 and mounts[0][3] == '/' and '-' in mounts[0]
                and mounts[0][mounts[0].index('-')+1] == 'cgroup2', 'host-cgroup2-mount')
            self._mount = mounts[0][0]
            self._check_mount(self._root)
            self._manager = bus.UserManager()
        except BaseException:
            try:
                self.close_before_effect()
            except BaseException:
                # Preserve the same partially acquired owner, including failed
                # close status, rather than losing it behind a plain OSError.
                raise kernel.KernelOwnedCloseRequired(self)
            raise

    def __reduce_ex__(self, protocol):
        raise TypeError('host-original-owner-not-serializable')

    def __copy__(self):
        raise TypeError('host-original-owner-not-copyable')

    def __deepcopy__(self, memo):
        raise TypeError('host-original-owner-not-copyable')

    def _retain(self, fd):
        if len(self._fds) >= 64:
            os.close(fd)
            raise kernel.KernelBudgetError('host-held-descriptor-bound')
        entry = [(ctypes.c_int*4)(0, fd, -1, -1), None]
        self._fds.append(entry)  # Track before the first fallible fstat.
        entry[1] = kernel.proc._signature(fd)
        return fd

    def _hold(self, name, parent=None):
        return self._retain(os.open(name, os.O_RDONLY | os.O_DIRECTORY |
            os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent))

    def _check_mount(self, fd):
        info = dict(row.split(':', 1) for row in
                    Path('/proc/self/fdinfo/'+str(fd)).read_text().splitlines())
        kernel.require(info.get('mnt_id', '').strip() == self._mount and
            os.fstat(fd).st_dev == os.fstat(self._root).st_dev, 'host-cgroup-shadow-mount')

    def _owner(self):
        kernel.require(os.getpid() == self._pid and threading.current_thread() is self._thread,
                       'host-original-pid-thread-required')
        kernel.require(not self._closed, 'host-closed')
        kernel.require(kernel.proc._stat(kernel._text(self._proc, 'stat'))['starttime'] == self._start
            and kernel._bytes(Path('/proc/sys/kernel/random/boot_id'), 65536) == self._boot
            and _source() == self._source, 'host-owner-source-changed')
        for name, (fd, signature) in self._namespaces.items():
            fresh = os.open('ns/'+name, os.O_RDONLY | os.O_CLOEXEC, dir_fd=self._proc)
            try:
                kernel.require(kernel.proc._signature(fd) == signature ==
                    kernel.proc._signature(fresh), 'host-owner-namespace-changed')
            finally:
                os.close(fresh)
        kernel.require(self._native.sources == kernel._sources(), 'host-native-source-changed')
        for slot, signature in self._fds:
            kernel.require(slot[0] == 0 and slot[1] >= 0 and signature is not None and
                kernel.proc._signature(slot[1]) == signature, 'host-held-fd-changed')

    def close_before_effect(self):
        kernel.require(os.getpid() == self._pid and threading.current_thread() is self._thread,
                       'host-original-pid-thread-required')
        with self._lock:
            kernel.require(not self._started, 'host-original-effect-retained')
            if not self._closed:
                for slot, signature in reversed(self._fds):
                    kernel.require(slot[0] == 0, 'host-native-close-failed')
                    if slot[1] < 0:
                        continue
                    if signature is not None:
                        kernel.require(kernel.proc._signature(slot[1]) == signature, 'host-held-fd-changed')
                    self._native.release_owned(slot)
                    kernel.require(slot[0] == 0, 'host-native-close-failed')
                self._fds.clear()
                if self._native is not None:
                    self._native.close()
                self._closed = True

    def _write(self, directory, name, value):
        fd = os.open(name, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        try:
            kernel.require(stat.S_ISREG(os.fstat(fd).st_mode), 'host-cgroup-file-type')
            raw = value.encode('ascii')
            kernel.require(os.write(fd, raw) == len(raw), 'host-cgroup-short-write')
        finally:
            os.close(fd)

    def _group(self, role, parent, name):
        os.mkdir(name, dir_fd=parent)  # EEXIST refuses; never adopt a previous group.
        fd = self._hold(name, parent)
        self._groups[role] = (parent, name, fd, kernel.proc._signature(fd))
        self._check_mount(fd)
        return fd

    def _configure(self, role, fd):
        kernel.require(kernel._text(fd, 'cgroup.type') == 'domain\n', 'host-domain-only')
        for name, value in _limits(role).items():
            self._write(fd, name, value)
            kernel.require(kernel._text(fd, name) == value, 'host-limit-write-readback')

    def _manager_readback(self):
        self._manager.verify()
        path = self._manager.call('GetUnit', 's', [self._unit], 'o')
        kernel.require(path == self._unit_path, 'host-original-unit-object-changed')
        checks = [('Id', 's', self._unit), ('Transient', 'b', True),
                  ('ActiveState', 's', 'active'), ('LoadState', 's', 'loaded')]
        for name, signature, expected in checks:
            kernel.require(self._manager.property(path, bus.UNIT_INTERFACE,
                name, signature) == expected, 'host-manager-unit-readback')
        invocation = self._manager.property(path, bus.UNIT_INTERFACE, 'InvocationID', 'ay')
        kernel.require(type(invocation) is list and len(invocation) == 16 and
            all(type(x) is int and 0 <= x <= 255 for x in invocation) and any(invocation),
            'host-invocation-required')
        if self._invocation is None:
            self._invocation = tuple(invocation)
        kernel.require(tuple(invocation) == self._invocation, 'host-invocation-changed')
        for name, signature, expected in [('Delegate', 'b', True),
            ('MemoryMax', 't', 17*1024**3), ('MemorySwapMax', 't', 0),
            ('CPUQuotaPerSecUSec', 't', 5000000), ('CPUQuotaPeriodUSec', 't', 100000),
            ('TasksMax', 't', 272)]:
            kernel.require(self._manager.property(path, bus.SCOPE_INTERFACE,
                name, signature) == expected, 'host-manager-budget-readback')
        delegated = self._manager.property(path, bus.SCOPE_INTERFACE, 'DelegateControllers', 'as')
        kernel.require(type(delegated) is list and len(delegated) == 3 and
            frozenset(delegated) == _CONTROLLERS, 'host-exact-delegation-required')
        control = self._manager.property(path, bus.SCOPE_INTERFACE, 'ControlGroup', 's')
        kernel.require(type(control) is str and
            re.fullmatch(r'/user\.slice/(?:[A-Za-z0-9_.@-]+/){1,24}'+
                         re.escape(self._unit), control), 'host-manager-control-group')
        self._manager.verify()
        return control

    def _open_original_scope(self, control):
        parts = control.strip('/').split('/')
        kernel.require(len(parts) <= 26 and parts[-1] == self._unit, 'host-cgroup-path-bound')
        fd = self._root
        for index, name in enumerate(parts):
            fd = self._hold(name, fd)
            self._check_mount(fd)
            if index != len(parts)-1:
                values = {key: kernel._text(fd, key) for key in
                          ('memory.max', 'cpu.max', 'pids.max')}
                _ancestor_allows(values)
                self._ancestors.append((fd, values))
        self._groups['scope'] = (None, control, fd, kernel.proc._signature(fd))
        return fd

    def admit(self):
        """Perform one real namespace request, without native birth or paid authority."""
        with self._lock:
            self._owner()
            kernel.require(getattr(self, '_leaf_generation', None) is None,
                           'host-leaf-profile-not-legacy-admit')
            kernel.require(not self._started and not self._failed, 'host-one-original-request')
            kernel.require(kernel._text(self._proc, 'cgroup') == self._original_membership,
                           'host-membership-changed-before-request')
            self._started = True  # Retain before any potentially ambiguous manager effect.
            try:
                self._job = self._manager.call('StartTransientUnit', 'ssa(sv)a(sa(sv))',
                    bus.scope_request(self._unit, self._pid), 'o')
                kernel.require(type(self._job) is str and re.fullmatch(
                    r'/org/freedesktop/systemd1/job/[1-9][0-9]*', self._job), 'host-original-start-job')
                self._unit_path = self._manager.call('GetUnit', 's', [self._unit], 'o')
                control = self._manager_readback()
                scope = self._open_original_scope(control)
                kernel.require(kernel._text(self._proc, 'cgroup') == '0::'+control+'\n'
                    and kernel._text(scope, 'cgroup.procs') == str(self._pid)+'\n'
                    and not _directory_names(scope) and
                    kernel._text(scope, 'cgroup.subtree_control') == '', 'host-original-fresh-scope')
                # S is manager-owned. Its child H is newly created by O and
                # has ordinary delegate-owned control files, including actual
                # hard depth/descendant bounds. Never write S's topology limits.
                host = self._group('host', scope, 'host')
                self._write(host, 'cgroup.procs', str(self._pid)+'\n')
                kernel.require(kernel._text(scope, 'cgroup.procs') == '', 'host-scope-no-internal-process')
                self._write(scope, 'cgroup.subtree_control', '+cpu +memory +pids\n')
                self._configure('host', host)
                # Move O out before distributing domain controllers. Pre-existing
                # memory remains charged at its old cgroup and is never refunded.
                observer = self._group('observer', host, 'observer')
                self._write(observer, 'cgroup.procs', str(self._pid)+'\n')
                kernel.require(kernel._text(host, 'cgroup.procs') == '', 'host-no-internal-process')
                self._write(host, 'cgroup.subtree_control', '+cpu +memory +pids\n')
                self._configure('observer', observer)
                operation = self._group('operation', host, self._operation_name)
                self._configure('operation', operation)
                self._write(operation, 'cgroup.subtree_control', '+cpu +memory +pids\n')
                for role in ('controller', 'aggregate'):
                    self._configure(role, self._group(role, operation, role))
                self._ready = True
                self._verify_locked()
            except BaseException:
                self._failed = True
                self._ready = False
                raise

    def _leaf_binding(self):
        return (self._leaf_generation, self._pid, self._unit, self._invocation,
                self._operation_name, self._groups['operation'][2:], self._source)

    def admit_fresh_leaf(self):
        """Prepare S/H/O/U only; prove original zero counters before C/A exist."""
        with self._lock:
            self._owner()
            kernel.require(getattr(self, '_leaf_generation', None) is not None and self._leaf_phase == 'PREPARED'
                and not self._started and not self._failed, 'host-leaf-one-original-request')
            kernel.require(kernel._text(self._proc, 'cgroup') == self._original_membership,
                           'host-membership-changed-before-request')
            self._started = True
            try:
                self._job = self._manager.call('StartTransientUnit', 'ssa(sv)a(sa(sv))',
                    bus.scope_request(self._unit, self._pid), 'o')
                kernel.require(type(self._job) is str and re.fullmatch(
                    r'/org/freedesktop/systemd1/job/[1-9][0-9]*', self._job), 'host-original-start-job')
                self._unit_path = self._manager.call('GetUnit', 's', [self._unit], 'o')
                control = self._manager_readback()
                scope = self._open_original_scope(control)
                kernel.require(kernel._text(self._proc, 'cgroup') == '0::'+control+'\n'
                    and kernel._text(scope, 'cgroup.procs') == str(self._pid)+'\n'
                    and not _directory_names(scope) and
                    kernel._text(scope, 'cgroup.subtree_control') == '', 'host-original-fresh-scope')
                host = self._group('host', scope, 'host')
                self._write(host, 'cgroup.procs', str(self._pid)+'\n')
                kernel.require(kernel._text(scope, 'cgroup.procs') == '', 'host-scope-no-internal-process')
                self._write(scope, 'cgroup.subtree_control', '+cpu +memory +pids\n')
                self._configure('host', host)
                observer = self._group('observer', host, 'observer')
                self._write(observer, 'cgroup.procs', str(self._pid)+'\n')
                kernel.require(kernel._text(host, 'cgroup.procs') == '', 'host-no-internal-process')
                self._write(host, 'cgroup.subtree_control', '+cpu +memory +pids\n')
                self._configure('observer', observer)
                operation = self._group('operation', host, self._operation_name)
                self._configure('operation', operation)
                self._write(operation, 'cgroup.subtree_control', '+cpu +memory +pids\n')
                self._leaf_phase, self._ready = 'FRESH_U_LEAF', True
                self._verify_fresh_leaf_locked()
                self._leaf_fact = _FreshULeafFact(_LEAF_FACT_TOKEN, self)
                return self._leaf_fact
            except BaseException:
                self._leaf_phase, self._failed, self._ready = 'UNKNOWN_RETAINED', True, False
                raise

    def _verify_fresh_leaf_locked(self):
        self._owner()
        kernel.require(self._leaf_generation is not None and self._leaf_phase == 'FRESH_U_LEAF'
            and self._ready and not self._failed, 'host-leaf-phase-or-sticky-failure')
        control = self._manager_readback()
        kernel.require(type(self._invocation) is tuple and len(self._invocation) == 16
            and all(type(value) is int and 0 <= value <= 255 for value in self._invocation)
            and any(self._invocation), 'host-leaf-original-invocation-required')
        kernel.require(tuple(self._groups) == ('scope', 'host', 'observer', 'operation'),
                       'host-leaf-exact-registered-groups')
        kernel.require(kernel._text(self._proc, 'cgroup') == '0::'+control+'/host/observer\n',
                       'host-observer-membership')
        for fd, values in self._ancestors:
            kernel.require(all(kernel._text(fd, key) == value for key, value in values.items()),
                           'host-ancestor-ceiling-changed')
        for role, (parent, name, fd, signature) in self._groups.items():
            if parent is not None:
                fresh = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=parent)
                try:
                    kernel.require(kernel.proc._signature(fresh) == signature, 'host-group-replaced')
                finally:
                    os.close(fresh)
            self._check_mount(fd)
            kernel.require(kernel._text(fd, 'cgroup.type') == 'domain\n', 'host-domain-only')
            for key, value in _limits(role).items():
                kernel.require(kernel._text(fd, key) == value, 'host-exact-budget-required')
            names = {'scope': frozenset(('host',)),
                     'host': frozenset(('observer', self._operation_name))}.get(role, frozenset())
            kernel.require(_directory_names(fd) == names, 'host-leaf-exact-topology')
            tree = _fields(kernel._text(fd, 'cgroup.stat'))
            kernel.require(tree.get('nr_descendants') == {'scope': 3, 'host': 2}.get(role, 0)
                and tree.get('nr_dying_descendants') == 0 and
                all(value == 0 for key, value in tree.items() if key.startswith('nr_dying_')),
                'host-descendant-or-dying-mismatch')
            controllers = kernel._text(fd, 'cgroup.subtree_control').split()
            kernel.require(len(controllers) == (0 if role == 'observer' else 3) and
                frozenset(controllers) == (frozenset() if role == 'observer' else _CONTROLLERS),
                'host-subtree-controllers')
        for role in ('scope', 'host'):
            kernel.require(kernel._text(self._groups[role][2], 'cgroup.procs') == '',
                           'host-original-only-observer')
        kernel.require(kernel._text(self._groups['observer'][2], 'cgroup.procs') == str(self._pid)+'\n',
                       'host-original-only-observer')
        self._require_pristine('operation', self._groups['operation'][2])

    def consume_fresh_leaf(self, fact):
        """Consume this original preparation fact once; create no C/A or grant."""
        with self._lock:
            try:
                self._owner()
                kernel.require(type(fact) is _FreshULeafFact and fact is self._leaf_fact and
                    fact._owner is self and fact._generation == self._leaf_generation and
                    fact._binding == self._leaf_binding(), 'host-leaf-original-fact-required')
                self._verify_fresh_leaf_locked()
                self._leaf_phase, self._ready = 'LEAF_PROOF_CONSUMED', False
            except BaseException:
                self._leaf_phase, self._failed, self._ready = 'UNKNOWN_RETAINED', True, False
                raise

    def _verify_locked(self):
        self._owner()
        kernel.require(self._ready and not self._failed, 'host-not-ready-or-sticky-failure')
        control = self._manager_readback()
        scope = self._groups['scope'][2]
        host = self._groups['host'][2]
        kernel.require(kernel._text(self._proc, 'cgroup') == '0::'+control+'/host/observer\n',
                       'host-observer-membership')
        for fd, values in self._ancestors:
            kernel.require(all(kernel._text(fd, key) == value for key, value in values.items()),
                           'host-ancestor-ceiling-changed')
        for role, (parent, name, fd, signature) in self._groups.items():
            if parent is not None:
                fresh = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                                os.O_CLOEXEC, dir_fd=parent)
                try:
                    kernel.require(kernel.proc._signature(fresh) == signature, 'host-group-replaced')
                finally:
                    os.close(fresh)
            self._check_mount(fd)
            kernel.require(kernel._text(fd, 'cgroup.type') == 'domain\n', 'host-domain-only')
            for key, value in _limits(role).items():
                # S resource limits are manager-owned: inspect, never write.
                kernel.require(kernel._text(fd, key) == value, 'host-exact-budget-required')
            expected_names = {'scope': frozenset(('host',)),
                'host': frozenset(('observer', self._operation_name)),
                'operation': frozenset(('controller', 'aggregate'))}.get(role, frozenset())
            kernel.require(_directory_names(fd) == expected_names, 'host-exact-topology-required')
            tree = _fields(kernel._text(fd, 'cgroup.stat'))
            kernel.require(tree.get('nr_descendants') == {'scope': 5, 'host': 4, 'operation': 2}.get(role, 0)
                and tree.get('nr_dying_descendants') == 0 and
                all(value == 0 for key, value in tree.items() if key.startswith('nr_dying_')),
                'host-descendant-or-dying-mismatch')
            controllers = kernel._text(fd, 'cgroup.subtree_control').split()
            kernel.require(len(controllers) == (3 if role in ('scope', 'host', 'operation') else 0)
                and frozenset(controllers) == (_CONTROLLERS if role in ('scope', 'host', 'operation')
                                               else frozenset()), 'host-subtree-controllers')
            if role not in ('scope', 'host', 'observer'):
                self._require_pristine(role, fd)
        kernel.require(kernel._text(scope, 'cgroup.procs') == '' and
            kernel._text(host, 'cgroup.procs') == '' and
            kernel._text(self._groups['observer'][2], 'cgroup.procs') == str(self._pid)+'\n',
            'host-original-only-observer')

    def _require_pristine(self, role, fd):
        field, raw = None, None
        def text(name):
            nonlocal field, raw
            field, raw = name, None
            raw = kernel._text(fd, name)  # The original guard's one read.
            return raw
        try:
            kernel.require(text('cgroup.procs') == '' and
                _decimal(text('pids.current')) == 0 and
                _fields(text('cgroup.events')).get('populated') == 0 and
                _decimal(text('memory.current')) == 0 and
                _decimal(text('memory.swap.current')) == 0 and
                _decimal(text('memory.peak')) == 0 and
                _fields(text('cpu.stat')).get('usage_usec') == 0,
                'host-operation-not-pristine')
        except kernel.KernelBudgetError as error:
            if getattr(self, '_first_pristine_failure', None) is None:
                identity = self._groups[role][3]
                self._first_pristine_failure = (role, field, raw, str(error),
                    self._unit, self._operation_name, fd, identity)
            raise kernel.KernelBudgetError(_pristine_message(self._first_pristine_failure)) from error

    def verify(self):
        with self._lock:
            try:
                self._verify_locked()
            except BaseException:
                self._failed = True
                self._ready = False
                raise


def prepare_host_scope():
    """Allocate an original owner before effects; caller must retain this object."""
    return HostScopeAdmission(_TOKEN)


def prepare_fresh_host_leaf():
    """Opt-in staged preparation on the same owner; no caller pristine claims."""
    owner = prepare_host_scope()
    try:
        owner._owner()
        kernel.require(type(owner) is HostScopeAdmission and not owner._started and
            not owner._failed and not owner._closed and getattr(owner, '_leaf_generation', None) is None,
            'host-leaf-fresh-original-owner-required')
        owner._leaf_generation = uuid.uuid4().hex
        owner._leaf_phase = 'PREPARED'
        owner._leaf_fact = None
        return owner
    except BaseException:
        try:
            owner.close_before_effect()
        except BaseException:
            raise kernel.KernelOwnedCloseRequired(owner)
        raise
