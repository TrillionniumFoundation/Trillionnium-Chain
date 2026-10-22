"""Private ordinary FIFO ownership prelude; transport is not yet integrated.

No pipe frame grants authority, proves exit/empty/raw counters or releases a
reservation. Actual buffer-page charge attribution is not supplied by FD birth.
"""
import ctypes
import fcntl
import os
import stat

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


def prepare_evidence_pipe(capability, owner):
    """Private fixed-slot preparation only; no supervision/terminal success API."""
    return _EvidencePipeOwner(_TOKEN, capability, owner)
