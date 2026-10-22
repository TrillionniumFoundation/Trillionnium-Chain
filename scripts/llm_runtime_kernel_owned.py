"""Internal Linux controlled spawn capability; never a serialized grant or RSS.

This slice cannot settle its outer reservation, install a model or stop a unit.
Same-administrator source/toolchain scope only; no hostile same-UID isolation.
"""
import ctypes
import fcntl
import hashlib
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import tempfile
import time

import llm_runtime_exit_observation as proc

_TOKEN = object()
_ROOT = Path('/sys/fs/cgroup')
_C = Path(__file__).with_name('llm_runtime_kernel_spawn.c')
_FIXED = {'cpu.max': '400000 100000\n', 'cpu.max.burst': '0\n',
          'memory.swap.max': '0\n', 'pids.max': '256\n', 'cgroup.type': 'domain\n'}


class KernelBudgetError(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise KernelBudgetError(code)


def _bytes(path, maximum=4*1024**2):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, 'kernel-source-file')
        raw = stream.read(maximum+1)
        after = os.fstat(stream.fileno())
        fingerprint = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        require(len(raw) <= maximum and fingerprint(before) == fingerprint(after),
            'kernel-source-changed')
        return raw


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _sources():
    return {p.name: _digest(_bytes(p)) for p in
        (_C, Path(__file__), Path(proc.__file__), Path(__file__).with_name('llm_runtime_pilot.py'))}


class _Native:
    def __init__(self, token, raw, sources):
        require(token is _TOKEN, 'kernel-native-constructor')
        self.sources, self.binary_sha256 = sources, _digest(raw)
        self.fd = os.memfd_create('trnm-controlled-spawn-abi1', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            with os.fdopen(os.dup(self.fd), 'wb') as stream: stream.write(raw)
            seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
            fcntl.fcntl(self.fd, fcntl.F_ADD_SEALS, seals)
            require(fcntl.fcntl(self.fd, fcntl.F_GET_SEALS) == seals, 'kernel-native-seals')
            self.library = ctypes.CDLL(f'/proc/self/fd/{self.fd}')
            self.spawn = self.library.trnm_kernel_spawn_v1
            strings = ctypes.POINTER(ctypes.c_char_p)
            self.spawn.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_char_p, strings, strings,
                                   ctypes.POINTER(ctypes.c_int)]
            self.spawn.restype = ctypes.c_int
        except BaseException:
            os.close(self.fd)
            raise


def build_controlled_native():
    """Explicit preparation, not automatic compilation or a caller-hash loader."""
    require(os.uname().sysname == 'Linux', 'kernel-linux-only')
    sources = _sources(); raw = _bytes(_C)
    require(_digest(raw) == sources[_C.name], 'kernel-source-changed')
    with tempfile.TemporaryDirectory(prefix='trnm-controlled-build-') as temporary:
        output = Path(temporary)/'spawn.so'
        built = subprocess.run(['/usr/bin/cc', '-std=c11', '-shared', '-fPIC', '-O2',
            '-Wall', '-Wextra', '-Werror', '-x', 'c', '-', '-o', str(output)],
            input=raw, capture_output=True, timeout=30)
        require(built.returncode == 0 and _sources() == sources, 'kernel-native-build')
        return _Native(_TOKEN, _bytes(output), sources)


def _text(fd, name):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
    with os.fdopen(descriptor) as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), 'kernel-file-type')
        value = stream.read(65537)
    require(len(value) <= 65536, 'kernel-file-bound')
    return value


class _ControlledOperation:
    def __init__(self, token, native, unit, invocation, operation, memory, owner):
        require(token is _TOKEN and type(native) is _Native and owner is not None,
                'kernel-capability-constructor')
        require(type(memory) is int and memory in (8*1024**3, 16*1024**3), 'kernel-memory-ceiling')
        require(re.fullmatch(r'[A-Za-z0-9_-]+\.service', unit) and
                re.fullmatch(r'[0-9a-f]{32}', invocation) and
                os.environ.get('INVOCATION_ID') == invocation, 'kernel-invocation')
        own = Path('/proc/self/cgroup').read_text()
        require(own.startswith('0::/user.slice/') and own.endswith('/'+unit+'/supervisor\n'),
                'kernel-supervisor-membership')
        self.unit_path = _ROOT/own[3:].strip().removesuffix('/supervisor').lstrip('/')
        self.operation = Path(operation)
        require(self.operation.parent == self.unit_path and
                re.fullmatch(r'operation-[0-9a-f]{32}', self.operation.name), 'kernel-operation-name')
        self.native, self.unit, self.invocation, self.owner = native, unit, invocation, owner
        self.memory, self.membership, self.nodes = memory, own, []
        self.boot = Path('/proc/sys/kernel/random/boot_id').read_text()
        self.failed = self.consumed = False
        self.child = None
        try:
            path = self.operation
            while path != _ROOT:
                require(len(self.nodes) < 16 and path.resolve() == path, 'kernel-ancestor-bound')
                fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                self.nodes.append((path, fd, proc._signature(fd), None))
                fields = {name: _text(fd, name) for name in (*_FIXED, 'memory.max')}
                require(fields['cgroup.type'] == 'domain\n', 'kernel-threaded-domain')
                quota, period = fields['cpu.max'].split()
                require((quota == 'max' or int(quota) >= 4*int(period)) and
                    (fields['memory.max'] == 'max\n' or int(fields['memory.max']) >= memory) and
                    (fields['pids.max'] == 'max\n' or int(fields['pids.max']) >= 256), 'kernel-tighter-ancestor')
                if path in (self.operation, self.unit_path):
                    expected = dict(_FIXED, **{'memory.max': str(memory if path == self.operation else 16*1024**3)+'\n'})
                    require(fields == expected and os.fstat(fd).st_uid == os.getuid(), 'kernel-finite-limits')
                self.nodes[-1] = (path, fd, proc._signature(fd), fields)
                path = path.parent
            # Verify this is the actual cgroup2 mount, not an arbitrary directory DTO.
            mount = next((line for line in Path('/proc/self/mountinfo').read_text().splitlines()
                          if line.split()[4] == str(_ROOT)), '')
            require(' - cgroup2 ' in mount, 'kernel-cgroup2-mount')
            for _, fd, signature, _ in self.nodes:
                info = dict(row.split(':', 1) for row in
                            Path(f'/proc/self/fdinfo/{fd}').read_text().splitlines())
                require(signature[0] == _ROOT.stat().st_dev and
                        info['mnt_id'].strip() == mount.split()[0], 'kernel-shadow-mount')
            require(_text(self.nodes[0][1], 'cgroup.procs') == '' and
                    _text(self.nodes[0][1], 'pids.current') == '0\n' and
                    _text(self.nodes[0][1], 'cgroup.subtree_control') == '', 'kernel-operation-not-empty')
            self.verify()
        except BaseException:
            for _, fd, _, _ in self.nodes: os.close(fd)
            raise

    def verify(self):
        require(not self.failed, 'kernel-sticky-failure')
        try:
            require(self.native.sources == _sources() and
                    Path('/proc/self/cgroup').read_text() == self.membership and
                    Path('/proc/sys/kernel/random/boot_id').read_text() == self.boot,
                    'kernel-source-or-owner-moved')
            fields = subprocess.run(['/usr/bin/systemctl', '--user', 'show', self.unit,
                '--property=InvocationID', '--property=ControlGroup', '--property=MainPID',
                '--property=Delegate', '--property=DelegateSubgroup'], capture_output=True,
                text=True, timeout=2)
            require(fields.returncode == 0 and len(fields.stdout) < 8192, 'kernel-unit-observation')
            unit = dict(row.split('=', 1) for row in fields.stdout.splitlines())
            require(unit == dict(InvocationID=self.invocation,
                ControlGroup='/'+str(self.unit_path.relative_to(_ROOT)), MainPID=str(os.getpid()),
                Delegate='yes', DelegateSubgroup='supervisor'), 'kernel-unit-identity')
            for path, fd, signature, expected in self.nodes:
                info = path.lstat()
                require(stat.S_ISDIR(info.st_mode) and
                    (info.st_dev, info.st_ino, info.st_mode) == signature == proc._signature(fd),
                    'kernel-path-or-fd-replaced')
                require({name: _text(fd, name) for name in expected} == expected, 'kernel-limits-changed')
        except BaseException:
            self.failed = True
            raise

    def spawn(self, command, stdout):
        self.verify()
        require(not self.consumed and type(command) is list and 0 < len(command) <= 256 and
            all(type(v) is str and '\0' not in v for v in command) and
            Path(command[0]).is_absolute(), 'kernel-command-or-reuse')
        self.consumed = True
        values = [os.fsencode(v) for v in command]
        environment = [os.fsencode(k+'='+v) for k, v in os.environ.items()]
        require(sum(map(len, values+environment)) <= 1024**2, 'kernel-exec-bound')
        array = lambda v: (ctypes.c_char_p*(len(v)+1))(*v, None)
        result = (ctypes.c_int*4)()
        error = self.native.spawn(self.nodes[0][1], stdout.fileno(), values[0],
                                  array(values), array(environment), result)
        if error: raise OSError(error, 'kernel-clone3-refused')
        return tuple(result)

    def allow_exec(self, pid, pidfd, ack, error_fd, deadline):
        try:
            self.verify()
            visible, parent, _ = proc._pidfd_identity(pid, pidfd)
            fields = proc._proc_fields(Path(f'/proc/{visible}/status'))
            require(proc._one(fields, 'PPid') == parent and
                Path(f'/proc/{visible}/cgroup').read_text() ==
                '0::/'+str(self.operation.relative_to(_ROOT))+'\n', 'kernel-child-membership')
            self.child = (pid, pidfd, proc._signature(pidfd))
            require(os.write(ack, b'G') == 1, 'kernel-gate-ack')
            ready, _, _ = select.select([error_fd], [], [], max(0, deadline-time.monotonic()))
            require(ready and os.read(error_fd, 4) == b'', 'kernel-exec-failed-or-deadline')
        except BaseException:
            self.failed = True
            raise
        finally:
            os.close(ack); os.close(error_fd)

    def terminal_record(self, pid, pidfd):
        try:
            self.verify()
            require(self.child == (pid, pidfd, proc._signature(pidfd)), 'kernel-child-owner-changed')
            fd = self.nodes[0][1]
            require(_text(fd, 'cgroup.procs') == '' and _text(fd, 'pids.current') == '0\n' and
                    'populated 0\n' in _text(fd, 'cgroup.events'), 'kernel-descendants-remain')
            return dict(scope='controlled-kernel-charge-not-RSS', native_binary=self.native.binary_sha256,
                sources=self.native.sources, counters={name: _text(fd, name) for name in
                ('memory.peak', 'memory.events', 'cpu.stat')}, operation_empty=True,
                outer_reconciliation='UNKNOWN', reservation='RETAINED', adoption=False)
        except BaseException:
            self.failed = True
            raise


def acquire_controlled_operation(native, *, unit, invocation, operation, memory_bytes, owner):
    """Internal live-handle acquisition; no unit/cgroup creation or FinalUse grant."""
    return _ControlledOperation(_TOKEN, native, unit, invocation, operation, memory_bytes, owner)
