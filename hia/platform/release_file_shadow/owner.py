"""Synthetic Release streaming qualification; Python retains the Unix FD."""
from dataclasses import dataclass
import fcntl
import os
from pathlib import Path
import stat
import struct
import threading
import time

SRC = Path(__file__).resolve().parents[2] / "src/release_bundle"
RAC1 = SRC / "artifact_header.hepta"
CCH1 = SRC / "content_claim_frame.hepta"
BOOT = SRC / "sha512_transcript_bootstrap.hepta"
SHA256 = SRC / "raw_artifact_sha256.hepta"
SHA512 = SRC.parent / "crypto/sha512_stream.hepta"
DESCRIPTOR = SRC / "file_descriptor.hepta"
STREAM = (RAC1, CCH1, BOOT, SHA256, SHA512)
BLOCK, CCH_LEN, SHA256_STATE, SHA512_STATE = 8192, 149, 1224, 131232
MAX_SHADOW_BYTES, MAX_SHADOW_CALLS = 64 * 1024, 16
SENTINEL, WORK = b"\xa5", b"\xc7"
LIMIT, SPENT, IO = 110, 111, 4
FILE_IDENTITY = 101
MAX_U64 = (1 << 64) - 1
STAT = struct.Struct("<QQI4xQqqqq")


@dataclass(frozen=True)
class Candidate:
    size: int
    locator: bytes
    name: bytes
    media: bytes
    platform: bytes
    source_path: bytes
    profile: bytes
    instance: bytes
    generation: int
    kind: int
    executable: bool = True

    def __post_init__(self):
        if (any(type(value) is not bytes or len(value) != width for value, width in
                ((self.locator, 32), (self.platform, 32), (self.source_path, 32),
                 (self.profile, 64), (self.instance, 64)))
                or any(type(value) is not bytes or len(value) > 65535 for value in (self.name, self.media))
                or any(type(value) is not int or not 0 <= value <= MAX_U64 for value in
                       (self.size, self.generation))
                or type(self.executable) is not bool or type(self.kind) is not int):
            raise ValueError("noncanonical private release candidate")

    def rac1_request(self):
        return (struct.pack("<HHQB", len(self.name), len(self.media), self.size, self.executable)
                + self.locator + self.platform + self.source_path + self.name + self.media)

    def cch1_request(self, header_size, digest=None):
        return (b"CCF1" + bytes([digest is not None, 2]) + self.profile + self.instance
                + struct.pack("<QQH", self.generation, self.size, header_size)
                + (digest if digest is not None else b""))


class Budget:
    """One in-process monotone reservation ledger, not a real CPU or I/O quota."""
    def __init__(self, max_reads, max_bytes):
        if not (0 < max_reads <= MAX_U64 and 0 < max_bytes <= MAX_U64):
            raise ValueError("invalid original budget bounds")
        self._max_reads, self._max_bytes = max_reads, max_bytes
        self._reads = self._bytes = 0
        self._exhausted = False

    @property
    def counts(self):
        return self._exhausted, self._reads, self._bytes

    def reserve(self, encoded_length):
        if self._exhausted or self._reads >= self._max_reads or encoded_length >= self._max_bytes - self._bytes:
            self._exhausted, self._reads, self._bytes = True, self._max_reads, self._max_bytes
            return False
        self._reads += 1
        self._bytes += encoded_length + 1
        return True


@dataclass(frozen=True)
class Observation:
    status: int
    exhausted: bool
    reads_reserved: int
    bytes_reserved: int
    consumed: int
    requested: tuple[int, ...]
    claim: bytes = b""
    initial_offset: int = 0

    def transcript_record(self):
        return (struct.pack("<BBQQQH", self.status, self.exhausted, self.reads_reserved,
                            self.bytes_reserved, self.consumed, len(self.requested))
                + b"".join(struct.pack("<H", width) for width in self.requested) + self.claim)


def record(info):
    secs, nanos = divmod(info.st_mtime_ns, 1_000_000_000)
    changed, changed_nanos = divmod(info.st_ctime_ns, 1_000_000_000)
    return STAT.pack(info.st_dev, info.st_ino, info.st_mode, info.st_size, secs, nanos, changed, changed_nanos)


def before_frame(expected, position, snapshot):
    return b"RFD1" + struct.pack("<IQQ", 1, expected, position) + snapshot


def after_frame(before, after):
    return b"RFD1\x02\0\0\0" + before + after


def _invoke(modules, source, frame, output, state, want=0):
    result = modules[source].call("f0", [frame, output, state]).require_returned()
    if result.arguments[0] != frame or (want is not None and result.value != want):
        raise ValueError("Native release stage disagreed with its contract")
    return result.value, *result.arguments[1:]


def _descriptor(modules, frame):
    status, out, work = _invoke(modules, DESCRIPTOR, frame, SENTINEL, WORK, None)
    if status not in (0, FILE_IDENTITY) or (out, work) != (SENTINEL, WORK):
        raise ValueError("Unexpected descriptor observation")
    return status


def _stream(modules, item, budget, read, *, initial=0, max_calls=MAX_SHADOW_CALLS, deadline=None):
    """The single framing/streaming implementation used by both qualification routes."""
    if type(item) is not Candidate or type(budget) is not Budget:
        raise ValueError("untyped release stream input")
    calls, consumed = [], initial

    def done(status, claim=b""):
        return Observation(status, *budget.counts, consumed, tuple(calls), claim, initial)

    def expired():
        return deadline is not None and time.monotonic() >= deadline

    if item.kind != 2:
        return done(1)
    if expired():
        return done(LIMIT)
    meta = item.rac1_request()
    size, out, scratch = _invoke(modules, RAC1, meta, SENTINEL * 900, WORK * 9, None)
    if scratch != WORK * 9:
        raise ValueError("RAC1 changed scratch")
    if size == 0xFFFFFFFF:
        if out != SENTINEL * 900:
            raise ValueError("RAC1 wrote on refusal")
        return done(1)
    if not 127 <= size <= 893 or out[size:] != SENTINEL * (900 - size):
        raise ValueError("Unexpected RAC1 extent")
    if not budget.reserve(size + item.size):
        return done(2)
    if expired() or item.size > MAX_SHADOW_BYTES:
        return done(LIMIT)

    _, cch, rest = _invoke(modules, CCH1, item.cch1_request(size), SENTINEL * CCH_LEN, scratch, CCH_LEN)
    if rest != scratch:
        raise ValueError("CCH1 changed scratch")
    _, _, sha512 = _invoke(modules, BOOT, cch + out[:size], b"", WORK * SHA512_STATE)
    _, _, sha256 = _invoke(modules, SHA256, b"\0" + struct.pack("<Q", item.size), b"", WORK * SHA256_STATE)
    remaining = item.size
    while True:
        if expired() or len(calls) >= max_calls:
            return done(LIMIT)
        requested = min(remaining, BLOCK) if remaining else 1
        calls.append(requested)
        try:
            part = read(requested)
        except OSError:
            return done(IO)
        if type(part) is not bytes or len(part) > requested:
            return done(IO)
        consumed += len(part)
        if not remaining:
            if part:
                return done(5)
            break
        if not part:
            return done(3)
        remaining -= len(part)
        _, untouched, sha512 = _invoke(modules, SHA512,
                struct.pack("<QQQ", 2, 24, len(part)) + part, SENTINEL * 64, sha512)
        if untouched != SENTINEL * 64:
            raise ValueError("SHA-512 published before EOF")
        _, _, sha256 = _invoke(modules, SHA256, b"\1" + part, b"", sha256)

    _, strong, _ = _invoke(modules, SHA512, struct.pack("<Q", 4), SENTINEL * 64, sha512)
    _, legacy, _ = _invoke(modules, SHA256, b"\2", SENTINEL * 32, sha256)
    if legacy != item.locator:
        return done(6)
    _, claim, rest = _invoke(modules, CCH1, item.cch1_request(size, strong), SENTINEL * 213, scratch, 213)
    if rest != scratch or claim != cch + strong:
        raise ValueError("Unexpected native claim message")
    return done(LIMIT) if expired() else done(0, claim)


class HeldReleaseOwner:
    """Single-use shadow observation. Only the retained OS descriptor is read.

    The caller passes a selected synthetic descriptor and does not read, seek,
    close, or reassign its underlying open file description during the call.
    The private duplicate closes on every path; dup preserves the underlying
    offset rather than creating a second independent view.
    """
    def __init__(self, descriptor):
        self._mutex = threading.Lock()
        self._fd = os.dup(descriptor)

    def _take(self):
        with self._mutex:
            fd, self._fd = self._fd, None
            return fd

    def close(self):
        fd = self._take()
        if fd is not None:
            os.close(fd)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def observe(self, modules, candidate, budget, *, max_calls=MAX_SHADOW_CALLS, allowance=45):
        if (type(candidate) is not Candidate or type(budget) is not Budget
                or type(max_calls) is not int or not 0 < max_calls <= MAX_SHADOW_CALLS
                or not 0 < allowance <= 45):
            raise ValueError("invalid bounded qualification policy")
        fd = self._take()

        def result(status, start=0):
            return Observation(status, *budget.counts, start, (), initial_offset=start)

        if fd is None:
            return result(SPENT)
        deadline = time.monotonic() + allowance
        try:
            before = os.fstat(fd)
            if fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY:
                return result(FILE_IDENTITY)
            # Mirror original short-circuit: never seek a nonregular or mismatched extent.
            start = os.lseek(fd, 0, os.SEEK_CUR) if stat.S_ISREG(before.st_mode) and before.st_size == candidate.size else 0
            first = record(before)
            if _descriptor(modules, before_frame(candidate.size, start, first)):
                return result(FILE_IDENTITY, start)
            observed = _stream(modules, candidate, budget, lambda size: os.read(fd, size),
                               initial=start, max_calls=max_calls, deadline=deadline)
            if not observed.status:
                try:
                    last = record(os.fstat(fd))
                except OSError:
                    return Observation(IO, *budget.counts, observed.consumed, observed.requested, initial_offset=start)
                if _descriptor(modules, after_frame(first, last)):
                    return Observation(FILE_IDENTITY, *budget.counts, observed.consumed, observed.requested,
                                       initial_offset=start)
                if time.monotonic() >= deadline:
                    return Observation(LIMIT, *budget.counts, observed.consumed, observed.requested,
                                       initial_offset=start)
            return observed
        except OSError:
            return result(IO)
        finally:
            os.close(fd)
