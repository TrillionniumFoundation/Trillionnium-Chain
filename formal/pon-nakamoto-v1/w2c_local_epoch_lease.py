"""RESEARCH ONLY: one local live W2-C receiver epoch per pinned lock namespace.

A kernel flock plus noninherited process ownership avoids same-machine cloned
receiver epochs and forces a fresh secret/epoch after process restart. This
does NOT authenticate physical nodes, protect against root/same-UID hostile
processes, create a cross-host lock, charge CPU, or grant W1/Chainwork.
"""
from __future__ import annotations
import fcntl
import hashlib
import os
from pathlib import Path
import secrets
import stat
import threading
import time
from w2c_stateless_receiver import StatelessReceiverAdmission
from w2c_receiver_admission import bytes32


def epoch_lock_path(private_directory, receiver):
    receiver = bytes32(receiver, 'RECEIVER')
    root = Path(private_directory)
    if not root.is_absolute():
        raise ValueError('EPOCH_ABSOLUTE_DIRECTORY')
    return root / ('trnm-w2c-receiver-' + hashlib.sha256(receiver).hexdigest() + '.lock')


class LocalEpochLeasedReceiver:
    """Host-scoped process experiment. Caller auth is delegated to the V3 owner."""

    def __init__(self, lock_path, receiver, *, policy_bits, capacity=64):
        receiver = bytes32(receiver, 'RECEIVER')
        # Price policy belongs to the trusted receiver operator, never to
        # caller-supplied work bytes or a remote request's selected bits.
        if type(policy_bits) is not int or not 8 <= policy_bits <= 24:
            raise ValueError('EPOCH_BITS_POLICY')
        self._policy_bits = policy_bits
        path = Path(lock_path)
        if path != epoch_lock_path(path.parent, receiver):
            raise ValueError('EPOCH_LOCK_IDENTITY')
        directory = path.parent
        if str(directory) != os.path.realpath(str(directory)):
            raise ValueError('EPOCH_PARENT_SYMLINK')
        parent = os.stat(directory, follow_symlinks=False)
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid()
                or stat.S_IMODE(parent.st_mode) != 0o700):
            raise ValueError('EPOCH_PARENT_UNTRUSTED')
        flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW
        fd = os.open(path, flags, 0o600)
        try:
            fstat = os.fstat(fd)
            named = os.stat(path, follow_symlinks=False)
            if (not stat.S_ISREG(fstat.st_mode) or fstat.st_nlink != 1
                    or stat.S_IMODE(fstat.st_mode) != 0o600
                    or fstat.st_uid != os.geteuid()
                    or (fstat.st_dev, fstat.st_ino) != (named.st_dev, named.st_ino)):
                raise ValueError('EPOCH_LOCK_UNTRUSTED')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ValueError('EPOCH_ALREADY_OWNED') from exc
            # Never reuse secret or epoch from disk. Both come directly from
            # system CSPRNG while the one existing lock is held.
            secret, epoch = secrets.token_bytes(32), secrets.token_bytes(32)
            if secret == epoch:
                raise ValueError('EPOCH_ENTROPY')
            inner = StatelessReceiverAdmission(receiver, secret, epoch,
                                               capacity=capacity)
        except BaseException:
            os.close(fd)
            raise
        self._fd = fd
        self._fingerprint = (fstat.st_dev, fstat.st_ino)
        self._parent_fingerprint = (parent.st_dev, parent.st_ino)
        self._path = path
        self._pid = os.getpid()
        self._inner = inner
        self._lifecycle = threading.RLock()
        if hasattr(os, 'register_at_fork'):
            os.register_at_fork(after_in_child=self._after_fork_child)

    def _after_fork_child(self):
        # Child inherits an open-description flock; merely checking the PID
        # is not sufficient because it can hold the parent's lease open after
        # the parent dies. Close, NEVER unlock the shared flock description.
        fd = self._fd
        self._fd = None
        self._pid = -1
        if fd is not None:
            os.close(fd)

    def _require_owner(self):
        if os.getpid() != self._pid or self._fd is None:
            raise ValueError('EPOCH_PROCESS_OWNER')
        original = os.fstat(self._fd)
        try:
            name = os.stat(self._path, follow_symlinks=False)
        except OSError as exc:
            raise ValueError('EPOCH_LOCK_REPLACED') from exc
        if ((original.st_dev, original.st_ino) != self._fingerprint
                or (name.st_dev, name.st_ino) != self._fingerprint
                or original.st_nlink != 1):
            raise ValueError('EPOCH_LOCK_REPLACED')
        if (not stat.S_ISREG(name.st_mode) or name.st_uid != os.geteuid()
                or stat.S_IMODE(name.st_mode) != 0o600):
            raise ValueError('EPOCH_LOCK_UNTRUSTED')
        parent = os.stat(self._path.parent, follow_symlinks=False)
        if ((parent.st_dev, parent.st_ino) != self._parent_fingerprint
                or not stat.S_ISDIR(parent.st_mode)
                or parent.st_uid != os.geteuid()
                or stat.S_IMODE(parent.st_mode) != 0o700):
            raise ValueError('EPOCH_PARENT_UNTRUSTED')

    @staticmethod
    def _now_ms():
        # This implementation never accepts a client-provided wall clock.
        return time.monotonic_ns() // 1_000_000

    @property
    def epoch(self):
        with self._lifecycle:
            self._require_owner()
            return self._inner.epoch

    def offer(self, proposal, authenticated_caller, bits):
        with self._lifecycle:
            self._require_owner()
            if type(bits) is not int or bits != self._policy_bits:
                raise ValueError('EPOCH_BITS_POLICY')
            return self._inner.offer(proposal, authenticated_caller,
                                     self._policy_bits, self._now_ms())

    def consume(self, grant, proposal, authenticated_caller, nonce):
        with self._lifecycle:
            self._require_owner()
            return self._inner.consume(grant, proposal, authenticated_caller,
                                       nonce, self._now_ms())

    def paid_count(self):
        with self._lifecycle:
            self._require_owner()
            return self._inner.pending_paid()

    def close(self):
        lock = getattr(self, '_lifecycle', None)
        if lock is None:
            return
        with lock:
            fd = getattr(self, '_fd', None)
            if fd is None:
                return
            self._fd = None
            if os.getpid() == self._pid:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                finally:
                    os.close(fd)
            else:
                os.close(fd)

    def __enter__(self):
        self._require_owner()
        return self

    def __exit__(self, *_):
        self.close()

    def __del__(self):
        self.close()
