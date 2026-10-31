"""Explicit root-installed ELF profile for a nonprivileged ordinary host caller.

Root installation, stable version paths, the kernel and system loader/libraries
remain trusted. This is not the anonymous sealed-image profile and never serves
as its fallback. No identity, capability, sandbox or deployment is changed here.
"""
import errno
import hashlib
import os
from pathlib import Path
import stat
import sys

PROFILE = "protected-installed-elf-v1"
MAXIMUM_BYTES = 512 * 1024**2
CAPABILITY_FIELDS = ("CapEff", "CapPrm", "CapAmb", "CapInh")


class ProfileUnavailable(ValueError):
    pass


def validate_subject_status(raw, uid):
    fields = {}
    for line in raw.decode("ascii").splitlines():
        name, separator, value = line.partition(":")
        if separator:
            if name in fields:
                raise ProfileUnavailable("duplicate process identity/capability field")
            fields[name] = value.strip()
    try:
        identities = tuple(int(value) for value in fields["Uid"].split())
        capabilities = {name: int(fields[name], 16) for name in CAPABILITY_FIELDS}
    except (KeyError, ValueError) as error:
        raise ProfileUnavailable("complete process identity/capability observation required") from error
    if uid == 0 or identities != (uid, uid, uid, uid):
        raise ProfileUnavailable("protected installed execution requires one nonroot process identity")
    if any(capabilities.values()):
        raise ProfileUnavailable("protected installed execution requires zero CapEff/CapPrm/CapAmb/CapInh")
    # CapBnd is intentionally not an active or inheritable privilege grant.


def require_subject():
    if not sys.platform.startswith("linux") or os.getuid() != os.geteuid() or os.geteuid() == 0:
        raise ProfileUnavailable("protected installed execution requires an ordinary nonroot Linux caller")
    if os.access not in os.supports_effective_ids:
        raise ProfileUnavailable("effective-identity permission checks are unavailable")
    # Linux capabilities belong to the calling thread, not necessarily its leader.
    with open("/proc/thread-self/status", "rb") as stream:
        raw = stream.read(65_537)
    if len(raw) > 65_536:
        raise ProfileUnavailable("process identity/capability observation exceeds its bound")
    validate_subject_status(raw, os.geteuid())


def verify_installed_path(path, image):
    path = Path(path)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError("installed ELF requires an exact canonical absolute path")
    for directory in path.parents:
        info = directory.stat(follow_symlinks=False)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                or os.access(directory, os.W_OK, effective_ids=True)):
            raise ValueError("installed ELF ancestors must be root-owned and caller-nonwritable")
    info = os.fstat(image.fileno())
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
            or info.st_mode & (0o022 | stat.S_ISUID | stat.S_ISGID) or not info.st_mode & 0o111
            or not 0 < info.st_size <= MAXIMUM_BYTES
            or os.access(path, os.W_OK, effective_ids=True)
            or not os.access(path, os.X_OK, effective_ids=True)):
        raise ValueError("installed ELF must be root-owned, unaliased, bounded, executable and caller-nonwritable without SUID/SGID")
    reopened = path.stat(follow_symlinks=False)
    if (reopened.st_dev, reopened.st_ino) != (info.st_dev, info.st_ino):
        raise ValueError("installed ELF path no longer names the pinned image")
    try:
        os.getxattr(image.fileno(), "security.capability")
    except OSError as error:
        if error.errno != errno.ENODATA:
            raise ProfileUnavailable("installed ELF file-capability absence cannot be verified") from error
    else:
        raise ValueError("installed ELF file capabilities are forbidden")


def prepare(path, expected_sha256):
    require_subject()
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    image = os.fdopen(fd, "rb")
    try:
        verify_installed_path(path, image)
        if image.read(4) != b"\x7fELF":
            raise ValueError("installed native ELF required")
        image.seek(0)
        digest, total = hashlib.sha256(), 0
        while raw := image.read(min(1024**2, MAXIMUM_BYTES + 1 - total)):
            total += len(raw)
            if total > MAXIMUM_BYTES:
                raise ValueError("installed ELF exceeds its bound")
            digest.update(raw)
        if digest.hexdigest() != expected_sha256:
            raise ValueError("installed ELF differs from independent owner pin")
        image.seek(0)
        verify_installed_path(path, image)
        return image
    except BaseException:
        image.close()
        raise
