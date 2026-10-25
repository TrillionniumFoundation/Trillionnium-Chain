"""Private tiny transport under the original aggregate and wait4 owners.

No pipe frame grants authority, proves exit/empty/raw counters or releases a
reservation. Actual buffer-page charge attribution is not supplied by FD birth.
"""
import ctypes
import fcntl
import io
import os
import select
import stat
from time import monotonic_ns

import llm_runtime_kernel_owned as kernel

_TOKEN = object()
require = kernel.require


class _EvidencePipeOwner:
    def __init__(self, token, capability, owner):
        from llm_runtime_kernel_aggregate import _AggregateOperation
        from llm_runtime_pilot import _Wait4Child
        require(token is _TOKEN and type(capability) is _AggregateOperation,
                'evidence-pipe-capability')
        self.capability = capability
        native = capability.native
        with native._lock_for_owner():
            require(native._busy._recursion_count() == 1, 'kernel-native-lifecycle-busy')
            require(owner is capability.owner, 'kernel-close-owner')
            require(native.operation is capability and not capability.closed and
                not capability.failed and not capability.consumed and capability.spawn_owner is None,
                'evidence-pipe-before-spawn')
            require(capability.evidence_pipe is None and len(capability._fd_owners) == 18,
                    'evidence-pipe-single-slot')
            self.read_slot, self.write_slot = capability._fd_owners[16:18]
            require(tuple(self.read_slot) == (0,-1,-1,-1) and
                tuple(self.write_slot) == (0,-1,-1,-1), 'evidence-pipe-slots-not-fresh')
            self.identities = (ctypes.c_uint64*6)()
            self.status = ctypes.c_int(-1)
            self.child_type = _Wait4Child
            from llm_runtime_evidence_frames import _TinyFrames
            self.frames = _TinyFrames()
            self.deadline_ns = self.log = self.log_signature = None
            self.eof = self.terminal_complete = False
            capability.evidence_pipe = self  # Strong registration before native FD creation.
            capability._verify_locked()
            returned = native.prepare_pipe(self.read_slot, self.write_slot, self.identities,
                ctypes.byref(self.status))
            require(returned == self.status.value == 0, 'evidence-pipe-native-refused')
            self._validate_slots_locked()

    def _validate_slots_locked(self):
        cap = self.capability
        require(cap.native.operation is cap or cap.closed, 'evidence-pipe-owner')
        require(cap.evidence_pipe is self and len(cap._fd_owners) == 18 and
            self.read_slot is cap._fd_owners[16] and self.write_slot is cap._fd_owners[17],
            'evidence-pipe-slot-replaced')
        for index, slot in enumerate((self.read_slot, self.write_slot)):
            require(slot[0] == 0, 'kernel-owned-close-failed')
            if slot[1] >= 0:
                expected = tuple(self.identities[index*3:index*3+3])
                actual = kernel.proc._signature(slot[1])
                require(actual == expected and stat.S_ISFIFO(actual[2]), 'evidence-pipe-fd-replaced')
                require(fcntl.fcntl(slot[1], fcntl.F_GETFL) & os.O_NONBLOCK and
                    fcntl.fcntl(slot[1], fcntl.F_GETFD) & fcntl.FD_CLOEXEC,
                    'evidence-pipe-fd-flags')
                require(fcntl.fcntl(slot[1], fcntl.F_GETFL) & os.O_ACCMODE ==
                    (os.O_RDONLY if index == 0 else os.O_WRONLY), 'evidence-pipe-fd-direction')

    def fileno(self):
        # Original spawn calls this under count1. Never reenter the guard here.
        native = self.capability.native
        native._lock_for_owner()  # Creating PID/concrete Thread check only.
        require(native._busy._recursion_count() == 1, 'evidence-pipe-guard')
        cap = self.capability
        require(cap.consumed and type(cap.spawn_owner) is self.child_type and
            getattr(cap.spawn_owner, '_evidence_pipe_owner', None) is self, 'evidence-pipe-child-owner')
        require(native.sources == kernel._sources(), 'evidence-pipe-source-changed')
        self._validate_slots_locked()
        require(self.status.value == 0 and self.write_slot[1] >= 3, 'evidence-pipe-not-ready')
        return self.write_slot[1]

    def configure(self, deadline_ns, log):
        native, cap = self.capability.native, self.capability
        with native._lock_for_owner():
            require(native._busy._recursion_count() == 1, 'kernel-native-lifecycle-busy')
            cap._verify_locked()
            require(not cap.consumed and cap.spawn_owner is None and self.deadline_ns is None and
                type(deadline_ns) is int and 0 < deadline_ns-monotonic_ns() <= 8*10**9 and
                type(log) is io.BufferedWriter and stat.S_ISREG(os.fstat(log.fileno()).st_mode),
                'evidence-pipe-original-deadline-or-log')
            self._validate_slots_locked()
            self.log_signature = kernel.proc._signature(log.fileno())
            self.log, self.deadline_ns = log, deadline_ns  # Original supervise start; never reset.

    def _child_locked(self, child):
        cap = self.capability
        require(not cap.failed and cap.native.operation is cap and cap.evidence_pipe is self and
            cap.consumed and type(child) is self.child_type and cap.spawn_owner is child and
            child.kernel_operation is cap and getattr(child, '_evidence_pipe_owner', None) is self and
            child._kernel_admitted is True and cap.child == (child.pid, child.termination_fd,
                kernel.proc._signature(child.termination_fd)), 'evidence-pipe-child-owner')
        self._validate_slots_locked()

    def adopted(self, child):
        native = self.capability.native
        with native._lock_for_owner():
            require(native._busy._recursion_count() == 1, 'kernel-native-lifecycle-busy')
            self._child_locked(child)
            require(self.deadline_ns is not None and self.write_slot[1] >= 3,
                    'evidence-pipe-original-deadline-or-log')
            native.release_owned(self.write_slot)
            require(self.write_slot[0] == 0, 'kernel-owned-close-failed')

    def _read_locked(self):
        from llm_runtime_evidence_frames import READ_SIZE, MAX_TOTAL
        if self.frames.failure is not None: self.frames.bad(self.frames.failure)
        if self.deadline_ns is None or monotonic_ns() >= self.deadline_ns:
            self.frames.bad('evidence-pipe-original-deadline')
        require(self.write_slot[1] == -1 and self.write_slot[0] == 0 and self.read_slot[1] >= 3 and
            type(self.log) is io.BufferedWriter and not self.log.closed and
            kernel.proc._signature(self.log.fileno()) == self.log_signature, 'evidence-pipe-close-or-log-state')
        if self.eof: return
        try: raw = os.read(self.read_slot[1], READ_SIZE)
        except BlockingIOError: return
        if raw:
            if self.frames.received+len(raw) > MAX_TOTAL: self.frames.bad('evidence-pipe-total-bound',raw)
            require(self.log.write(raw) == len(raw), 'evidence-pipe-parent-log')
            self.frames.feed(raw)
        else:
            self.eof = True
            self.frames.complete()

    def drain(self, child):
        native = self.capability.native
        with native._lock_for_owner():
            require(native._busy._recursion_count() == 1, 'kernel-native-lifecycle-busy')
            try:
                self._child_locked(child)
                self._read_locked()  # One <=4KiB read per original loop pass.
            except BaseException:
                self.capability.failed = True
                raise

    def _finish_locked(self, child):
        native = self.capability.native
        native._lock_for_owner()
        require(native._busy._recursion_count() == 1, 'evidence-pipe-guard')
        self._child_locked(child)
        require(child.reaped and child.reap_resolved and child.owned_exit_observed and
            child.cleanup_method == 'wait4' and child.observation_error is None,
            'evidence-pipe-exact-wait4-required')
        poll = select.poll(); poll.register(self.read_slot[1], select.POLLIN|select.POLLHUP)
        for _ in range(226):  # Finite reads/waits under the unchanged original8s deadline.
            self._read_locked()
            if self.eof: break
            poll.poll(max(1,min(50,(self.deadline_ns-monotonic_ns()+999999)//1000000)))
        require(self.eof, 'evidence-pipe-eof-unknown')
        payload, inner, outer = self.frames.records
        relative = str(self.capability.operation.relative_to(kernel._ROOT))
        member = '0::/'+('' if relative == '.' else relative)+'\n'
        require(inner['supervisor_pid'] == outer['pid'] == child.pid and outer['ppid'] == os.getpid() and
            payload['ppid'] == child.pid and inner['owned_child_pid'] == payload['pid'] and
            payload['membership'] == outer['membership_before'] == outer['membership_after'] == member and
            inner['result'] == outer['result'], 'evidence-pipe-reported-context')
        self._validate_slots_locked()
        native.release_owned(self.read_slot)
        require(self.read_slot[0] == 0 and self.read_slot[1] == -1, 'kernel-owned-close-failed')
        self.terminal_complete = True  # Transport only; every original raw predicate still follows.


def prepare_evidence_pipe(capability, owner):
    """Private fixed-slot preparation only; no supervision/terminal success API."""
    return _EvidencePipeOwner(_TOKEN, capability, owner)
