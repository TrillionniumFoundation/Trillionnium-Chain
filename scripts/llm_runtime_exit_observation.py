"""Linux exit-only observation, never a measurement of zero or released RSS.

An owned, unreaped child may have a zombie leader and still-running kernel exit
cleanup. This opt-in observer retains task directory FDs across both frontiers.
Its private object permits bounded terminal waiting, not inference, installation,
resource-credit release, or success without the original exact wait4 receipt.
"""
import itertools
import os
from pathlib import Path
import stat
import time

PROFILE = 'linux-owned-exit-cleanup-v2'
MAX_DRAIN_NS = 100_000_000
MAX_TASKS = 32
PF_EXITING = 0x00000004
PF_KTHREAD = 0x00200000


class ExitObservationError(ValueError):
    pass


def _require(value, reason):
    if not value:
        raise ExitObservationError(reason)


def _decimal(value, minimum=0, maximum=(1 << 64) - 1):
    _require(type(value) is str and value.isascii() and value.isdecimal(), 'exit-integer')
    number = int(value)
    _require(str(number) == value and minimum <= number <= maximum, 'exit-integer')
    return number


def _one(fields, key, minimum=1):
    value, = fields[key]
    return _decimal(value, minimum)


def _namespace(fields, key):
    values = fields[key]
    _require(type(values) is list and 1 <= len(values) <= 32, 'exit-namespace')
    return [_decimal(value, 1, (1 << 31) - 1) for value in values]


def _signature(fd):
    value = os.fstat(fd)
    return value.st_dev, value.st_ino, value.st_mode


def _read(directory, name):
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = os.open(name, flags, dir_fd=directory)
    with os.fdopen(descriptor) as handle:
        _require(stat.S_ISREG(os.fstat(handle.fileno()).st_mode), 'exit-nonregular-proc')
        raw = handle.read(65537)
    _require(0 < len(raw) <= 65536 and raw.endswith('\n'), 'exit-proc-bound')
    return raw


def _status(raw):
    fields = {}
    seen = set()
    allowed = {'Pid', 'PPid', 'Tgid', 'NSpid', 'NStgid', 'State', 'Threads', 'VmRSS'}
    for line in raw.splitlines():
        key, separator, value = line.partition(':')
        _require(separator and key and key not in seen, 'exit-status-syntax')
        seen.add(key)
        if separator and key in allowed:
            _require(key not in fields, 'exit-duplicate-status')
            fields[key] = value.split()
    return fields


def _proc_fields(path):
    with path.open() as handle:
        raw = handle.read(65537)
    _require(0 < len(raw) <= 65536 and raw.endswith('\n'), 'exit-proc-bound')
    return _status(raw)


def _stat(raw):
    _require(') ' in raw, 'exit-stat-syntax')
    prefix, suffix = raw.rsplit(') ', 1)
    pid, separator, _ = prefix.partition(' (')
    values = suffix.split()
    _require(separator and len(values) == 50 and len(values[0]) == 1 and values[0] in 'RSDTtXZPI', 'exit-stat-fields')
    for value in values[1:]:
        _require(value.lstrip('-').isascii() and value.lstrip('-').isdecimal() and
                 str(int(value)) == value and -(1 << 63) <= int(value) < (1 << 64), 'exit-stat-number')
    return dict(pid=_decimal(pid, 1, (1 << 31) - 1), state=values[0],
        ppid=_decimal(values[1], 1, (1 << 31) - 1), flags=_decimal(values[6], 0, (1 << 32) - 1),
        starttime=_decimal(values[19], 1), vsize=_decimal(values[20]), rss=_decimal(values[21]))


def _task_names(directory):
    with os.scandir(directory) as entries:
        names = [item.name for item in itertools.islice(entries, MAX_TASKS + 1)]
    _require(0 < len(names) <= MAX_TASKS and len(set(names)) == len(names), 'exit-task-count')
    for name in names:
        _decimal(name, 1, (1 << 31) - 1)
    return tuple(sorted(names, key=int))


def _pidfd_identity(pid, held_pidfd):
    parent = _proc_fields(Path('/proc/self/status'))
    parent_pid = _one(parent, 'Pid')
    parent_namespace = _namespace(parent, 'NSpid')
    _require(parent_namespace[0] == parent_pid and parent_namespace[-1] == os.getpid(), 'exit-parent')
    identity = _proc_fields(Path(f'/proc/self/fdinfo/{held_pidfd}'))
    visible = _one(identity, 'Pid')
    namespace = _namespace(identity, 'NSpid')
    coordinate = len(parent_namespace) - 1
    _require(namespace[0] == visible and len(namespace) > coordinate and namespace[coordinate] == pid,
             'exit-held-pidfd')
    return visible, parent_pid, tuple(namespace)


def _open_group(visible):
    return os.open(f'/proc/{visible}', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)


class ExitOnlyObservation:
    """Private held-FD observation; no JSON/trace-dictionary constructor exists."""

    def __init__(self, pid, held_pidfd, owner_token, initial_leader, missing_sample_ns):
        self.pid, self.held_pidfd, self.owner_token = pid, held_pidfd, owner_token
        self.group_fd, self.tasks_fd, self.task_fds = None, None, {}
        self.task_signatures, self.starts = {}, {}
        self.closed, self.record = False, {}
        self.sample_started_ns = missing_sample_ns
        try:
            _require(type(pid) is int and pid > 0 and type(held_pidfd) is int and held_pidfd >= 0 and
                     owner_token is not None and type(missing_sample_ns) is int and
                     0 < missing_sample_ns <= time.monotonic_ns(), 'exit-owner-context')
            self.held_signature = _signature(held_pidfd)
            self.identity = _pidfd_identity(pid, held_pidfd)
            self.visible, self.parent, self.namespace = self.identity
            self._leader(initial_leader)
            self.group_fd = _open_group(self.visible)
            self.group_signature = _signature(self.group_fd)
            self.tasks_fd = os.open('task', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                    dir_fd=self.group_fd)
            self.tasks_signature = _signature(self.tasks_fd)
            self.names = _task_names(self.tasks_fd)
            _require(str(self.visible) in self.names, 'exit-leader-not-in-task-set')
            for name in self.names:
                descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                     dir_fd=self.tasks_fd)
                self.task_fds[name] = descriptor
                self.task_signatures[name] = _signature(descriptor)
            self.recheck()
        except BaseException:
            self.close()
            raise

    def _leader(self, fields):
        _require(_one(fields, 'Pid') == self.visible and _one(fields, 'Tgid') == self.visible and
                 _one(fields, 'PPid') == self.parent and tuple(_namespace(fields, 'NSpid')) == self.namespace and
                 fields['State'][0] == 'Z' and len(fields['State'][0]) == 1 and
                 tuple(_namespace(fields, 'NStgid')) == self.namespace and
                 'VmRSS' not in fields, 'exit-leader')
        count = _one(fields, 'Threads')
        _require(count <= MAX_TASKS, 'exit-task-count')
        return count

    def _frontier(self):
        count = self._leader(_status(_read(self.group_fd, 'status')))
        _require(_task_names(self.tasks_fd) == self.names and count == len(self.names), 'exit-task-set')
        result = {}
        for name, descriptor in self.task_fds.items():
            _require(_signature(descriptor) == self.task_signatures[name], 'exit-task-fd-reused')
            fields = _status(_read(descriptor, 'status'))
            observed = _stat(_read(descriptor, 'stat'))
            _require(_one(fields, 'Pid') == int(name) and _one(fields, 'Tgid') == self.visible and
                     _one(fields, 'PPid') == self.parent and _one(fields, 'Threads') == count and
                     tuple(_namespace(fields, 'NStgid')) == self.namespace,
                     'exit-task-identity')
            task_namespace = _namespace(fields, 'NSpid')
            _require(task_namespace[0] == int(name) and len(task_namespace) == len(self.namespace), 'exit-task-namespace')
            _require(len(fields['State'][0]) == 1 and fields['State'][0] in 'RSDTtXZPI' and 'VmRSS' not in fields and
                     observed['pid'] == int(name) and observed['ppid'] == self.parent and
                     observed['flags'] & PF_EXITING and not observed['flags'] & PF_KTHREAD and
                     observed['vsize'] == 0 and observed['rss'] == 0, 'exit-task-not-exit-only')
            if int(name) == self.visible:
                _require(fields['State'][0] == observed['state'] == 'Z', 'exit-leader-state')
            result[name] = observed
        _require(_task_names(self.tasks_fd) == self.names and
                 self._leader(_status(_read(self.group_fd, 'status'))) == count, 'exit-task-set')
        return result

    def recheck(self):
        _require(not self.closed and _signature(self.held_pidfd) == self.held_signature and
                 _signature(self.group_fd) == self.group_signature and
                 _signature(self.tasks_fd) == self.tasks_signature and
                 _pidfd_identity(self.pid, self.held_pidfd) == self.identity, 'exit-owner-changed')
        before, after = self._frontier(), self._frontier()
        starts = {name: value['starttime'] for name, value in before.items()}
        _require(starts == {name: value['starttime'] for name, value in after.items()} and
                 (not self.starts or self.starts == starts), 'exit-task-starttime')
        _require(_signature(self.held_pidfd) == self.held_signature and
                 _pidfd_identity(self.pid, self.held_pidfd) == self.identity, 'exit-owner-changed')
        self.starts = starts
        self.record = dict(profile=PROFILE, sample_started_ns=self.sample_started_ns,
            classification_completed_ns=time.monotonic_ns(), tasks=list(self.names),
            frontier_before=before, frontier_after=after,
            scope='exit-only cleanup with no observable attached user-mm; not zero or physically released RSS')
        return self.record

    def belongs_to(self, pid, held_pidfd, owner_token):
        try:
            return (not self.closed and self.pid == pid and self.held_pidfd == held_pidfd and
                    self.owner_token is owner_token and _signature(held_pidfd) == self.held_signature)
        except (OSError, TypeError, ValueError):
            return False

    def close(self):
        if self.closed:
            return
        self.closed = True
        descriptors = list(self.task_fds.values()) + [self.tasks_fd, self.group_fd]
        self.task_fds.clear()
        error = None
        for descriptor in descriptors:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError as fault:
                    error = fault
        if error is not None:
            raise error
