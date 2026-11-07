"""Bound one source read to checked directory entries and a regular-file fd.

This is a local source-integrity check, not an immutable checkout snapshot or
protection against a privileged filesystem/same-UID writer changing the tree
between separate reads. No cryptographic or runtime qualification is granted.
"""
from __future__ import annotations

import errno
import os
from pathlib import Path
import stat


class SourceReadError(ValueError):
    pass


def _directory_identity(metadata):
    # Directory timestamps also change when unrelated entries are created
    # (notably under /tmp). Bind the directory inode and its type/permissions;
    # do not claim that its entire contents form a stable snapshot.
    return metadata.st_dev, metadata.st_ino, metadata.st_mode


def _file_identity(metadata):
    return (*_directory_identity(metadata), metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns)


def read_regular(root: Path, relative: str, ceiling: int) -> bytes:
    if (type(relative) is not str or not relative or "\\" in relative
            or any(part in ("", ".", "..") for part in relative.split("/"))):
        raise SourceReadError("unsafe path")
    if type(ceiling) is not int or ceiling < 0:
        raise SourceReadError("invalid source byte limit")
    descriptors = []
    entries = []
    try:
        root = Path(root).absolute()
        if root.anchor != "/" or ".." in root.parts:
            raise SourceReadError("unsafe repository root")
        # Start at /, not at a pathname-opened checkout: otherwise a symlink or
        # replacement in an ancestor of the checkout can redirect the read.
        directories = [root.anchor, *root.parts[1:], *relative.split("/")[:-1]]
        leaf = relative.split("/")[-1]
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        directory_flags = flags | os.O_DIRECTORY
        parent_fd = None
        for component in directories:
            expected = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
            if stat.S_ISLNK(expected.st_mode):
                raise SourceReadError("symlink source refused: " + relative)
            if not stat.S_ISDIR(expected.st_mode):
                raise SourceReadError("non-directory source ancestor: " + relative)
            fd = os.open(component, directory_flags, dir_fd=parent_fd)
            descriptors.append(fd)
            opened = os.fstat(fd)
            if _directory_identity(expected) != _directory_identity(opened):
                raise SourceReadError("changing source directory: " + relative)
            entries.append((parent_fd, component, fd, opened))
            parent_fd = fd

        expected = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        if stat.S_ISLNK(expected.st_mode):
            raise SourceReadError("symlink source refused: " + relative)
        if not stat.S_ISREG(expected.st_mode) or not 0 <= expected.st_size <= ceiling:
            raise SourceReadError("nonregular/oversize source: " + relative)
        # NONBLOCK prevents a raced FIFO from hanging in open before fstat.
        fd = os.open(leaf, flags, dir_fd=parent_fd)
        descriptors.append(fd)
        before = os.fstat(fd)
        if _file_identity(expected) != _file_identity(before):
            raise SourceReadError("changing source: " + relative)

        chunks = []
        total = 0
        while True:
            chunk = os.read(fd, min(65536, ceiling + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > ceiling:
                raise SourceReadError("oversize/changing source: " + relative)
        after = os.fstat(fd)
        named = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        if (total != before.st_size
                or _file_identity(before) != _file_identity(after)
                or _file_identity(after) != _file_identity(named)):
            raise SourceReadError("changing source: " + relative)
        # Walk back through every held parent, including checkout ancestors.
        # A hardlinked leaf can keep its identity while a directory is replaced.
        for parent_fd, component, directory_fd, before in reversed(entries):
            after = os.fstat(directory_fd)
            named = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
            if (_directory_identity(before) != _directory_identity(after)
                    or _directory_identity(after) != _directory_identity(named)):
                raise SourceReadError("changing source directory: " + relative)
        return b"".join(chunks)
    except OSError as error:
        if error.errno == errno.ENOENT:
            reason = "missing source: "
        elif error.errno in (errno.ELOOP, errno.ENOTDIR):
            reason = "symlink/non-directory source refused: "
        else:
            reason = "unreadable source: "
        raise SourceReadError(reason + relative) from error
    except (AttributeError, NotImplementedError) as error:
        # There is deliberately no pathname-read fallback on unsupported hosts.
        raise SourceReadError("descriptor source checks unavailable") from error
    finally:
        close_error = None
        for fd in reversed(descriptors):
            try:
                os.close(fd)
            except OSError as error:
                close_error = error
        if close_error is not None:
            raise SourceReadError("source descriptor close failed: " + relative) from close_error
