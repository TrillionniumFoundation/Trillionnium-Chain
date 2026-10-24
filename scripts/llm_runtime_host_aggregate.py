"""Private fixed native C→A handoff, subordinate to the original O capability.

No funding/grant producer or public acquisition path. The C record is bounded
transport after C's exact wait4(A); O's separate exact wait4(C) and actual raw
U/C/A observations remain mandatory. No retirement/whole-U/refund authority.
"""
import ctypes
import fcntl
import os
from pathlib import Path
import stat
import struct
import time

import llm_runtime_kernel_owned as kernel

_TOKEN = object()
_MAGIC = 0x31574134544e5243
require = kernel.require


class _AggregateLaunch:
    def __init__(self, token, operation, command):
        from llm_runtime_host_controller import _HostControllerOperation
        require(token is _TOKEN and type(operation) is _HostControllerOperation,
                'host-aggregate-private-mechanics')
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
        self.source = kernel._digest(kernel._bytes(Path(__file__)))
        with self.native._lock_for_owner():
            require(self.native._busy._recursion_count() == 1, 'kernel-native-lifecycle-busy')
            require(operation._aggregate is None and not operation.consumed and
                operation.cap._leaf_phase == 'CONTROLLER_PREPARED', 'host-aggregate-before-C-birth')
            operation._verify_locked()
            operation._aggregate = self  # Strong registration precedes native pipe creation.
            try:
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

    def _verify_locked(self):
        op = self.operation
        self.native._lock_for_owner()
        require(self.native._busy._recursion_count() == 1 and op.native is self.native and
            self.native.operation is op and op._aggregate is self and not op.failed and
            not op.closed and self.deadline_ns == int(op.deadline*10**9) and
            self.read_slot is self._slots[0] and self.write_slot is self._slots[1] and
            kernel._digest(kernel._bytes(Path(__file__))) == self.source,
            'host-aggregate-original-owner-or-source')
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
        return dict(scope='native-C-exact-wait4-A-transport-only', pid=aggregate_pid,
            exit_code=self.record[1], waited_user_us=user_us, waited_system_us=system_us,
            whole_u_terminal=False, resource_return_proven=False, reservation='RETAINED')
