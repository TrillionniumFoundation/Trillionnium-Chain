#!/usr/bin/env python3
"""Original PN1 outer writer, isolated from candidate runtime imports.

This module owns only the existing held directory and byte ledger. Loading it
is not trusted bootstrap, source admission, a capsule loader, preparation, or
native qualification. A parent must independently pin this module and every
runtime origin before using it as its bootstrap owner. After capsule admission,
that loader must bind this same module/class object rather than execute a copy.
"""
from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

MIB = 1024**2


def require(value, message):
    if not value:
        raise ValueError(message)


def held_directory(path):
    """Open every absolute component without following links; caller owns the FD."""
    path = Path(path)
    require(path.is_absolute() and os.path.abspath(path) == str(path), 'CANONICAL_ABSOLUTE_DIRECTORY_REQUIRED')
    current = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def publish_new(directory_fd, temporary, destination):
    """One Linux NOREPLACE operation; unsupported backends fail without fallback."""
    require(sys.platform.startswith('linux'), 'V2_LINUX_PUBLICATION_REQUIRED')
    library = ctypes.CDLL(None, use_errno=True)
    try:
        operation = library.renameat2
    except AttributeError as error:
        raise OSError(errno.ENOSYS, 'renameat2 unavailable') from error
    operation.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    operation.restype = ctypes.c_int
    if operation(directory_fd, os.fsencode(temporary), directory_fd, os.fsencode(destination), 1):
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), destination)


def json_chunks(value):
    encoder = json.JSONEncoder(indent=2, sort_keys=True, allow_nan=False)
    for text in encoder.iterencode(value):
        for offset in range(0, len(text), 65536):
            yield text[offset:offset + 65536].encode('utf-8')
    yield b'\n'


class V2Writer:
    """An owned outer ledger, not the missing SQLite whole-I/O boundary.

    Reservations precede opens/children. No fsync is added to the old Python
    collector's zero-sync policy; this does not claim crash durability. Terminal
    bytes are reserved inside outer128MiB, not guaranteed against physical ENOSPC.
    The caller must retain this single owner until all native writers stop.
    """
    TERMINAL_BYTES = 65536

    def __init__(self, root, *, limits=None):
        self.root = Path(root)
        self.limits = dict(outer=128*MIB-self.TERMINAL_BYTES, terminal=self.TERMINAL_BYTES,
                           binary=192*MIB, inventory=31*MIB)
        if limits is not None:  # Only narrower component controls may be selected.
            require(set(limits) == set(self.limits) and all(type(n) is int and 0 <= n <= self.limits[k]
                    for k, n in limits.items()), 'V2_COMPONENT_LIMITS_CANNOT_EXPAND_PROFILE')
            self.limits = dict(limits)
        self.used = dict.fromkeys(self.limits, 0)
        self.held = dict.fromkeys(self.limits, 0)
        self.failure = None
        self.failure_context = None
        self.terminal_attempted = False
        self.fd = held_directory(self.root)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def poison(self, error):
        if self.failure is None:
            self.failure = str(error)[:2048]

    def reserve(self, bucket, amount, *, terminal=False):
        try:
            require(terminal or self.failure is None, 'V2_WRITER_POISONED')
            require(type(amount) is int and 0 <= amount <= self.limits[bucket]
                    and self.used[bucket] + self.held[bucket] + amount <= self.limits[bucket],
                    'V2_WRITE_BUCKET_CAP:' + bucket)
            self.held[bucket] += amount
            return [bucket, amount, True]
        except (OSError, ValueError, KeyError) as error:
            self.poison(error)
            raise

    def cancel(self, reservation):
        if reservation[2]:
            self.held[reservation[0]] -= reservation[1]
            reservation[2] = False

    def parent(self, name):
        parts = Path(name).parts
        require(parts and not Path(name).is_absolute() and all(p not in ('.', '..') for p in parts)
                and Path(*parts).as_posix() == name, 'V2_OWNED_OUTPUT_PATH_REQUIRED')
        current = os.dup(self.fd)
        try:
            for part in parts[:-1]:
                try:
                    os.mkdir(part, dir_fd=current)
                except FileExistsError:
                    pass
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
                os.close(current)
                current = child
            return current, parts[-1]
        except BaseException:
            os.close(current)
            raise

    def open_reserved(self, name, *, reject_existing_final=False):
        directory, leaf = self.parent(name)
        try:
            if reject_existing_final:
                try:
                    os.stat(leaf, dir_fd=directory, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise FileExistsError(errno.EEXIST, 'final output already exists', leaf)
            descriptor = os.open(leaf + '.partial.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=directory)
            return [directory, leaf, descriptor]
        except BaseException:
            os.close(directory)
            raise

    def chunks(self, name, pieces, reservation, *, exact_bytes=None, terminal=False, opened=None):
        bucket, amount, active = reservation
        directory, written = None, 0
        try:
            require(active and (terminal or self.failure is None), 'V2_WRITER_POISONED_OR_UNRESERVED')
            opened = opened or self.open_reserved(name)
            directory, leaf, descriptor = opened
            temporary = leaf + '.partial.json'
            opened[2] = None
            with os.fdopen(descriptor, 'wb', buffering=0) as stream:
                for piece in pieces:
                    require(isinstance(piece, bytes) and written + len(piece) <= amount,
                            'V2_RESERVED_STREAM_SIZE_EXCEEDED')
                    view = memoryview(piece)
                    while view:
                        count = stream.write(view)
                        require(count is not None and count > 0, 'V2_SHORT_WRITE_WITHOUT_PROGRESS')
                        written += count
                        view = view[count:]
                require(exact_bytes is None or written == exact_bytes, 'V2_SOURCE_LENGTH_CHANGED')
            publish_new(directory, temporary, leaf)
            return written
        except (OSError, ValueError, TypeError) as error:
            self.poison(error)
            raise
        finally:
            self.cancel(reservation)
            self.used[bucket] += written  # A failed partial remains charged and retained.
            if directory is not None:
                os.close(directory)
                opened[0] = None

    def json(self, name, value, *, bucket='outer', terminal=False, reservation=None):
        try:
            require(terminal or self.failure is None, 'V2_WRITER_POISONED')
            size = 0
            ceiling = min(self.limits[bucket], 16*MIB if bucket == 'outer' else self.limits[bucket])
            if reservation is not None: ceiling = min(ceiling, reservation[1])
            for piece in json_chunks(value):
                size += len(piece)
                require(size <= ceiling, 'V2_JSON_FILE_CAP:' + bucket)
            token = reservation or self.reserve(bucket, size, terminal=terminal)
            require(size <= token[1], 'V2_JSON_RESERVATION_EXCEEDED')
            return self.chunks(name, json_chunks(value), token, exact_bytes=size, terminal=terminal)
        except (OSError, ValueError, TypeError) as error:
            self.poison(error)
            raise

    def copy(self, name, source, *, bucket='outer', expected=None, source_directory_fd=None):
        try:
            with os.fdopen(os.open(source, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=source_directory_fd), 'rb') as stream:
                before = os.fstat(stream.fileno())
                require(stat.S_ISREG(before.st_mode), 'V2_REGULAR_SOURCE_REQUIRED')
                ceiling = 16*MIB if bucket == 'outer' else self.limits[bucket]
                require(before.st_size <= ceiling, 'V2_COPY_FILE_CAP:' + bucket)
                token = self.reserve(bucket, before.st_size)
                fingerprint = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
                def pieces():
                    digest = hashlib.sha256()
                    for data in iter(lambda: stream.read(65536), b''):
                        digest.update(data)
                        yield data
                    require(fingerprint(os.fstat(stream.fileno())) == fingerprint(before),
                            'V2_SOURCE_CHANGED_DURING_COPY')
                    require(expected is None or digest.hexdigest() == expected, 'V2_COPY_SHA_MISMATCH')
                return self.chunks(name, pieces(), token, exact_bytes=before.st_size)
        except (OSError, ValueError, TypeError) as error:
            self.poison(error)
            raise

    def terminal(self, phase, error):
        self.poison(error)
        require(not self.terminal_attempted, 'V2_TERMINAL_ALREADY_ATTEMPTED')
        self.terminal_attempted = True
        return self.json('outer-terminal.json', dict(schema='pon-identity-outer-terminal-v2',
            phase=str(phase)[:128], first_error=self.failure, qualification=False,
            observed_step=self.failure_context,
            used_bytes=dict(self.used), reserved_bytes=dict(self.held), limits=dict(self.limits),
            physical_enospc_terminal_guaranteed=False, sync_calls_added=0), bucket='terminal', terminal=True)
