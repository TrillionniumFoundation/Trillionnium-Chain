"""Research-only W2-C receiver epoch owner. No consensus or V3 authority.

A single local process holds one original private epoch log inode and an
exclusive flock. Every accepted startup appends and fsyncs an independently
fresh 32-byte nonce before publishing an epoch. Absent file is created with
O_EXCL; an existing empty/corrupt log is rejected, not reset.

This relies on OS filesystem durability, a trusted same-UID process, fresh
CSPRNG output and an administrator refusing state rollback or cloned hosts.
It is NOT rollback-resistant or independent proof of secure deployment.
"""
from __future__ import annotations
import fcntl
import hashlib
import os
import stat
import struct

NAME = "w2c-epoch-owner-v1.log"
MAGIC = b"W2ER"
DOMAIN = b"TRNM-W2C-EPOCH-OWNER-V1\0"
RECORD_BYTES = 4 + 8 + 32 + 32 + 32
MAX_RECORDS = 4096
ZERO = bytes(32)


class EpochOwnerError(ValueError):
    pass


def _hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _record(counter: int, nonce: bytes, previous: bytes) -> bytes:
    if not 1 <= counter <= MAX_RECORDS or type(nonce) is not bytes or len(nonce) != 32:
        raise EpochOwnerError("EPOCH_RECORD_INPUT")
    if type(previous) is not bytes or len(previous) != 32:
        raise EpochOwnerError("EPOCH_PREVIOUS")
    prefix = MAGIC + struct.pack('<Q', counter) + nonce + previous
    return prefix + _hash(DOMAIN + b"record" + prefix)


def _read_exact_records(data: bytes) -> tuple[int, bytes]:
    if not data or len(data) % RECORD_BYTES or len(data) > MAX_RECORDS * RECORD_BYTES:
        raise EpochOwnerError("EPOCH_CORRUPT")
    prev, latest = ZERO, 0
    for off in range(0, len(data), RECORD_BYTES):
        chunk = data[off:off+RECORD_BYTES]
        number = int.from_bytes(chunk[4:12], 'little')
        if number != latest + 1 or chunk != _record(number, chunk[12:44], prev):
            raise EpochOwnerError("EPOCH_CORRUPT")
        latest, prev = number, _hash(DOMAIN + b"link" + chunk)
    return latest, prev


class DurableEpochOwner:
    """One local fail-closed process lease, NOT a W1/ledger capability."""
    def __init__(self, private_directory: str, *, entropy=os.urandom):
        self._pid = os.getpid()
        self._pathname = os.path.abspath(private_directory)
        self._fd = None
        self._dirfd = None
        self._epoch = None
        try:
            self._dirfd = os.open(private_directory,
                                  os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            folder = os.fstat(self._dirfd)
            if (not stat.S_ISDIR(folder.st_mode) or folder.st_uid != os.geteuid()
                    or folder.st_mode & 0o077):
                raise EpochOwnerError("EPOCH_DIRECTORY_OWNER")
            created = False
            try:
                self._fd = os.open(NAME, os.O_RDWR | os.O_CREAT | os.O_EXCL
                                   | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self._dirfd)
                created = True
            except FileExistsError:
                self._fd = os.open(NAME, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
                                   dir_fd=self._dirfd)
            meta = os.fstat(self._fd)
            if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.geteuid()
                    or meta.st_nlink != 1 or meta.st_mode & 0o077):
                raise EpochOwnerError("EPOCH_FILE_OWNER")
            try:
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise EpochOwnerError("EPOCH_OWNER_BUSY") from exc
            size = os.fstat(self._fd).st_size
            if size > MAX_RECORDS * RECORD_BYTES:
                raise EpochOwnerError("EPOCH_CAPACITY")
            os.lseek(self._fd, 0, os.SEEK_SET)
            raw = bytearray()
            while len(raw) < size:
                fragment = os.read(self._fd, min(65536, size - len(raw)))
                if not fragment:
                    raise EpochOwnerError("EPOCH_READ_SHORT")
                raw.extend(fragment)
            if created and not raw:
                counter, prev = 0, ZERO
            else:
                counter, prev = _read_exact_records(bytes(raw))
            if counter >= MAX_RECORDS:
                raise EpochOwnerError("EPOCH_CAPACITY")
            fresh = entropy(32)
            if type(fresh) is not bytes or len(fresh) != 32:
                raise EpochOwnerError("EPOCH_RANDOM_UNAVAILABLE")
            entry = _record(counter+1, fresh, prev)
            # Append while the original inode is locked; NO rewrite/truncation.
            os.lseek(self._fd, 0, os.SEEK_END)
            if os.write(self._fd, entry) != len(entry):
                raise EpochOwnerError("EPOCH_WRITE_SHORT")
            os.fsync(self._fd)
            os.fsync(self._dirfd)
            # The epoch is disclosed only after both durability barriers.
            self._epoch = _hash(DOMAIN + b"epoch" + entry)
        except Exception:
            self.close()
            raise

    def epoch(self) -> bytes:
        self.assert_live()
        return self._epoch

    def assert_live(self) -> None:
        if (self._fd is None or self._dirfd is None or self._pid != os.getpid()
                or self._epoch is None):
            raise EpochOwnerError("EPOCH_OWNER_NOT_LIVE")
        if os.fstat(self._fd).st_nlink != 1:
            raise EpochOwnerError("EPOCH_FILE_REPLACED")
        # Unlike a record-only check, this forbids replacement of the original
        # pathname with a fresh inode while the old lock remains held.
        try:
            active_parent = os.stat(self._pathname, follow_symlinks=False)
        except OSError as exc:
            raise EpochOwnerError("EPOCH_DIRECTORY_REPLACED") from exc
        opened_parent = os.fstat(self._dirfd)
        if ((active_parent.st_ino, active_parent.st_dev) !=
                (opened_parent.st_ino, opened_parent.st_dev)):
            raise EpochOwnerError("EPOCH_DIRECTORY_REPLACED")
        if (opened_parent.st_uid != os.geteuid() or opened_parent.st_mode & 0o077):
            raise EpochOwnerError("EPOCH_DIRECTORY_OWNER")
        try:
            current = os.stat(NAME, dir_fd=self._dirfd, follow_symlinks=False)
        except OSError as exc:
            raise EpochOwnerError("EPOCH_FILE_REPLACED") from exc
        original = os.fstat(self._fd)
        if (current.st_ino, current.st_dev) != (original.st_ino, original.st_dev):
            raise EpochOwnerError("EPOCH_FILE_REPLACED")
        if original.st_uid != os.geteuid() or original.st_mode & 0o077:
            raise EpochOwnerError("EPOCH_FILE_OWNER")

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
        if self._dirfd is not None:
            os.close(self._dirfd)
            self._dirfd = None
        self._epoch = None

    def __enter__(self):
        self.assert_live()
        return self

    def __exit__(self, *_):
        self.close()

    def __del__(self):
        self.close()


class ScopedResearchReceiver:
    """Attach an existing stateless research receiver to one live disk epoch.

    Not a public admission listener; old direct constructors intentionally
    remain research inputs to the cloned-epoch counterexample.
    """
    def __init__(self, owner: DurableEpochOwner, receiver: bytes, secret: bytes, *,
                 lifetime_ms=2000, capacity=64, entropy=None):
        from w2c_stateless_receiver import StatelessReceiverAdmission
        self.owner = owner
        self.impl = StatelessReceiverAdmission(receiver, secret, owner.epoch(),
                                               lifetime_ms=lifetime_ms,
                                               capacity=capacity, entropy=entropy)

    def offer(self, proposal, caller, bits, now_ms):
        self.owner.assert_live()
        return self.impl.offer(proposal, caller, bits, now_ms)

    def consume(self, grant, proposal, caller, nonce, now_ms):
        self.owner.assert_live()
        return self.impl.consume(grant, proposal, caller, nonce, now_ms)
