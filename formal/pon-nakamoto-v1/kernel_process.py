"""Explicit Linux/systemd isolation around the existing bounded native exchange.

The administrator provisions ONE fixed parent slice. This module only attaches;
it never creates/refills/replaces a parent. All child units and their descendants
share its kernel ceilings even if a child changes session or is restarted.
This is NOT a consensus proof, a CPU-credit journal, or a public command service.
The trusted caller chooses/pins the executable and args; guests provide only bytes.
"""
from __future__ import annotations
import hashlib
import math
import os
import re
import stat
import subprocess
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from bounded_process import run_bounded, Result


class KernelFailure(ValueError):
    """Preserve an observed native outcome even if later cleanup is uncertain."""
    def __init__(self, message, *, native=None, unit=None):
        super().__init__(message)
        self.native = native
        self.unit = unit


@dataclass(frozen=True)
class Limits:
    cpu_quota_us: int
    cpu_period_us: int
    memory_bytes: int
    tasks: int

    def validate(self):
        if (any(type(x) is not int for x in (self.cpu_quota_us, self.cpu_period_us,
                                            self.memory_bytes, self.tasks)) or
            not 1000 <= self.cpu_quota_us <= 200000 or
            not 1000 <= self.cpu_period_us <= 1000000 or
            self.cpu_quota_us > self.cpu_period_us * 2 or
            not 32*1024*1024 <= self.memory_bytes <= 2*1024*1024*1024 or
            not 4 <= self.tasks <= 256):
            raise KernelFailure('KERNEL_LIMITS')


@dataclass(frozen=True)
class PinnedExecutable:
    path: str
    sha256: str

    def checked_path(self):
        if not re.fullmatch(r'[0-9a-f]{64}', self.sha256):
            raise KernelFailure('KERNEL_EXECUTABLE_HASH')
        original = Path(self.path)
        if not original.is_absolute():
            raise KernelFailure('KERNEL_EXECUTABLE_PATH')
        path = original.resolve(strict=True)
        # Caller/admin input only. No attacker-writable executable or ancestor.
        for entry in [path, *path.parents]:
            meta = entry.stat()
            if meta.st_uid != 0 or meta.st_mode & 0o022:
                raise KernelFailure('KERNEL_EXECUTABLE_OWNER')
        meta = path.stat()
        if not stat.S_ISREG(meta.st_mode) or not meta.st_mode & 0o111 or meta.st_nlink != 1:
            raise KernelFailure('KERNEL_EXECUTABLE_TYPE')
        with path.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        if digest != self.sha256:
            raise KernelFailure('KERNEL_EXECUTABLE_CHANGED')
        return str(path)


@dataclass(frozen=True)
class ParentIdentity:
    """Already provisioned parent identity retained by the existing trusted owner.

    Never refresh this from an incoming request or silently after parent loss.
    This does not assert disk-rollback resistance or an OS-reboot migration.
    """
    boot: str
    device: int
    inode: int


@dataclass(frozen=True)
class KernelResult:
    native: Result
    unit: str
    aggregate_before: dict
    aggregate_after: dict
    cleanup_confirmed: bool


def _systemctl(*args):
    return subprocess.run(['/usr/bin/systemctl', *args], check=True,
                          capture_output=True, text=True, timeout=5,
                          env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})


def _fields(text):
    pairs = [line.split() for line in text.splitlines()]
    if any(len(pair) != 2 for pair in pairs) or len({p[0] for p in pairs}) != len(pairs):
        raise KernelFailure('KERNEL_COUNTER_FORMAT')
    result = {name: int(value) for name, value in pairs}
    if any(value < 0 for value in result.values()):
        raise KernelFailure('KERNEL_COUNTER_FORMAT')
    return result


class KernelEnvelope:
    """Administrator-only handle to a fixed boot + parent inode + exact limits.

    Keep the parent active across ALL child launches and supervisor reconnects.
    A missing/replaced parent or changed limit is unavailable, never auto-repaired.
    Linux fair-scheduler quotas bound aggregate service CPU; kernel scheduling
    granularity is not a nanosecond-exact token bucket or a hard-real-time promise.
    """
    def __init__(self, slice_name: str, limits: Limits, expected: ParentIdentity):
        limits.validate()
        if os.name != 'posix' or not hasattr(os, 'geteuid') or os.geteuid() != 0 or not Path('/sys/fs/cgroup/cgroup.controllers').is_file():
            raise KernelFailure('KERNEL_PRIVILEGED_CGROUP2_REQUIRED')
        if not re.fullmatch(r'trnmpon[a-z0-9]{1,48}\.slice', slice_name):
            raise KernelFailure('KERNEL_PARENT_NAME')
        group = _systemctl('show', slice_name, '--property=ControlGroup', '--value').stdout.strip()
        active = _systemctl('show', slice_name, '--property=ActiveState', '--value').stdout.strip()
        if group != '/' + slice_name or active != 'active':
            raise KernelFailure('KERNEL_PARENT_INACTIVE')
        self.slice_name = slice_name
        self.limits = limits
        self.path = Path('/sys/fs/cgroup') / slice_name
        self.boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.identity = (os.fstat(self.fd).st_dev, os.fstat(self.fd).st_ino)
        self.unavailable = threading.Event()
        try:
            if not isinstance(expected, ParentIdentity) or expected != ParentIdentity(self.boot, *self.identity):
                raise KernelFailure('KERNEL_PARENT_IDENTITY')
            self.snapshot()
        except BaseException:
            os.close(self.fd)
            self.fd = -1
            raise

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _read(self, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)
        try:
            raw = os.read(fd, 4097)
            if len(raw) > 4096:
                raise KernelFailure('KERNEL_COUNTER_LENGTH')
            return raw.decode('ascii').strip()
        finally:
            os.close(fd)

    def snapshot(self):
        if self.unavailable.is_set() or self.fd < 0:
            raise KernelFailure('KERNEL_ENVELOPE_UNAVAILABLE')
        try:
            meta = self.path.stat()
            if (meta.st_dev, meta.st_ino) != self.identity or meta.st_uid != 0:
                raise KernelFailure('KERNEL_PARENT_REPLACED')
            if Path('/proc/sys/kernel/random/boot_id').read_text().strip() != self.boot:
                raise KernelFailure('KERNEL_BOOT_CHANGED')
            expected = {'cpu.max': f'{self.limits.cpu_quota_us} {self.limits.cpu_period_us}',
                        'cpu.max.burst': '0', 'memory.max': str(self.limits.memory_bytes),
                        'memory.swap.max': '0', 'pids.max': str(self.limits.tasks)}
            actual = {name: self._read(name) for name in expected}
            if actual != expected:
                raise KernelFailure('KERNEL_LIMITS_CHANGED')
            return {'boot': self.boot, 'parent_inode': self.identity[1], 'limits': actual,
                    'cpu': _fields(self._read('cpu.stat')),
                    'memory_current': int(self._read('memory.current')),
                    'memory_events': _fields(self._read('memory.events')),
                    'pids_current': int(self._read('pids.current')),
                    'pids_events': _fields(self._read('pids.events'))}
        except (OSError, ValueError):
            self.unavailable.set()
            raise

    def command(self, unit, executable, args, runtime):
        # No caller-provided systemd properties, user, slice or environment.
        properties = [
            'DynamicUser=yes', 'NoNewPrivileges=yes', 'CapabilityBoundingSet=',
            'AmbientCapabilities=', 'ProtectSystem=strict', 'ProtectHome=yes',
            'PrivateDevices=yes', 'PrivateNetwork=yes', 'PrivateMounts=yes',
            'ProtectControlGroups=yes', 'ProtectKernelTunables=yes',
            'ProtectKernelModules=yes', 'ProtectKernelLogs=yes', 'ProtectClock=yes',
            'ProtectProc=invisible', 'ProcSubset=pid', 'RestrictNamespaces=yes',
            'RestrictRealtime=yes', 'RestrictSUIDSGID=yes', 'LockPersonality=yes',
            'SystemCallArchitectures=native', 'Delegate=no', 'KillMode=control-group',
            'SendSIGKILL=yes', 'TimeoutStopSec=500ms', 'LimitCORE=0', 'LimitNOFILE=64',
            'Restart=no', f'RuntimeMaxSec={runtime}s', 'WorkingDirectory=/',
            'InaccessiblePaths=-/run/user -/run/dbus -/run/systemd/private -/var/lib -/var/spool',
            'TemporaryFileSystem=/tmp:rw,size=16M,mode=1777 /var/tmp:rw,size=16M,mode=1777',
        ]
        argv = ['/usr/bin/systemd-run', '--quiet', '--wait', '--pipe', '--collect', '--service-type=exec',
                f'--unit={unit}', f'--slice={self.slice_name}']
        for prop in properties:
            argv += ['--property', prop]
        return [*argv, '--', executable, *args]

    def run(self, executable: PinnedExecutable, args=(), data=b'', *, runtime=10.0,
            stdout_limit=65536, stderr_limit=8192):
        if (type(runtime) not in (int, float) or not math.isfinite(runtime) or not 0 < runtime <= 30 or
            not isinstance(data, bytes) or len(data) > 65536 or
            not isinstance(args, (list, tuple)) or len(args) > 20 or
            any(not isinstance(a, str) or '\x00' in a or len(a) > 16384 for a in args) or
            any(type(n) is not int or not 0 <= n <= 1024*1024 for n in (stdout_limit, stderr_limit))):
            raise KernelFailure('KERNEL_REQUEST_BOUNDS')
        path = executable.checked_path()
        before = self.snapshot()
        unit = 'trnmponjob' + uuid.uuid4().hex + '.service'
        group = self.path / unit
        result = None
        failure = None
        try:
            result = run_bounded(self.command(unit, path, args, runtime), data,
                                 timeout=runtime+5, stdout_limit=stdout_limit,
                                 stderr_limit=stderr_limit, cwd='/',
                                 env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
        except BaseException as error:
            failure = error
        finally:
            # systemd owns the complete cgroup, not just the original POSIX group.
            # RuntimeMaxSec still stops it if THIS controller dies during exchange.
            try:
                try:
                    _systemctl('stop', unit)
                except subprocess.CalledProcessError:
                    # A successful short-lived unit may already be collected.
                    # Resolve actual unit absence AND cgroup absence; never waive
                    # permission errors, a still-loaded unit or live descendants.
                    state = _systemctl('show', unit, '--property=LoadState', '--value').stdout.strip()
                    if state != 'not-found' or group.exists():
                        raise
                if group.exists() and _fields((group/'cgroup.events').read_text()).get('populated') != 0:
                    raise KernelFailure('KERNEL_DESCENDANTS_ALIVE')
                after = self.snapshot()
            except BaseException as cleanup:
                self.unavailable.set()
                raise KernelFailure('KERNEL_CLEANUP_UNCERTAIN', native=result if result is not None else failure, unit=unit) from cleanup
        if failure is not None:
            # The pipe broker may have lost StartTransientUnit's acknowledgement.
            # A momentarily absent unit is not proof that no delayed manager job
            # exists. Preserve the bounded exchange failure and fence this owner;
            # do not turn uncertain launch into a clean failure/free redispatch.
            self.unavailable.set()
            raise KernelFailure('KERNEL_EXCHANGE_UNCERTAIN', native=failure, unit=unit) from failure
        return KernelResult(result, unit, before, after, True)
