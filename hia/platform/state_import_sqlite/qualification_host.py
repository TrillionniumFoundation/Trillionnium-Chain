"""Private qualification transport for a native SQLite continuation.

The continuation chooses every SQLite operation, SQL text and publication.
This process transports exact private spans and retains the provider owner.
It has no production entry and accepts only disposable test-directory files.
"""
from contextlib import contextmanager
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import struct
import subprocess
import sys

EXTENT = 1 << 20


@contextmanager
def sealed_library(path, digest):
    raw = Path(path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError("Native artifact identity changed")
    fd = os.memfd_create("trnm-m13-test-image", os.MFD_ALLOW_SEALING)
    try:
        with os.fdopen(os.dup(fd), "wb") as stream:
            stream.write(raw)
        fcntl.fcntl(fd, getattr(fcntl, "F_ADD_SEALS", 1033), 15)
        yield ctypes.CDLL(f"/proc/self/fd/{fd}")
    finally:
        os.close(fd)


def bind(loaded, name, result, *args):
    f = getattr(loaded, name)
    f.argtypes, f.restype = args, result
    return f


def run(message, reader, provider):
    ptr = ctypes.c_void_p
    u64 = ctypes.c_uint64
    step = bind(reader, "f0", u64, ptr, u64, ptr, u64, ptr, u64)
    fetch = bind(provider, "trnm_task_provider", u64, ptr, u64, ptr, u64, ptr, u64)
    make = bind(provider, "trnm_task_provider_new", ptr)
    free = bind(provider, "trnm_task_provider_free", None, ptr)
    reset = bind(provider, "trnm_task_provider_reset", u64, ptr)
    directory, db = Path(message["directory"]), Path(message["database"])
    checked_digest = message.get("checked_digest") is True
    if directory.resolve(strict=True) != directory or directory.stat().st_mode & 0o077:
        raise ValueError("Owned canonical disposable test directory required")
    if checked_digest:
        if (not directory.parent.name.startswith("m13-sqlite-checked-digest-") or directory.name != "owned"
                or not db.is_absolute() or not db.is_relative_to(directory) or db == directory
                or ".." in db.parts):
            raise ValueError("Owned checked-digest fixture required")
    elif db.parent != directory or db.is_symlink() or not db.is_file():
        raise ValueError("Owned canonical disposable test database required")
    state = ctypes.create_string_buffer(EXTENT)
    response = ctypes.create_string_buffer(EXTENT)
    hash_work = ctypes.create_string_buffer(EXTENT)
    handoff = message.get("handoff") is True
    if checked_digest and handoff:
        raise ValueError("Separate read profiles are not interchangeable")
    if handoff and (not directory.parent.name.startswith("m13-sqlite-handoff-") or directory.name != "owned"):
        raise ValueError("Handoff qualification only uses its own named disposable directory")
    raw = os.fsencode(db) if handoff else bytes.fromhex(message["expected"]).hex().upper().encode() + os.fsencode(db)
    proposal_hex = message.get("empty_delta")
    writes = proposal_hex is not None
    if (handoff or checked_digest) and writes:
        raise ValueError("Handoff qualification is read only")
    if writes:
        proposal = bytes.fromhex(proposal_hex)
        mode = {
            1042: "m13-sqlite-empty-delta-",
            1298: "m13-sqlite-delete-delta-",
            1434: "m13-sqlite-insert-delta-",
            2226: "m13-sqlite-mixed-delta-",
        }.get(len(proposal))
        if 1450 <= len(proposal) <= 4194 and proposal[:8] == b"VEC1M13!":
            mode = "m13-sqlite-vector-delta-"
        if len(proposal) == 1434 and proposal[:8] == b"UPD1M13!":
            mode = "m13-sqlite-update-delta-"
        if mode is None or message["advance"] or (len(proposal) == 2226 and proposal[:8] != b"BAT1M13!"):
            raise ValueError("Exact private single-delta replay input required")
        if not directory.parent.name.startswith(mode) or directory.name != "owned":
            raise ValueError("Write qualification only uses its own named disposable directory")
        raw = proposal + raw
    ops = (2, 3, 5, 6, 7, 8, 9, 10) if writes else (2, 3, 5, 7, 8, 9)
    wire_db = os.fsencode(db)
    path_calls = []
    open_calls = 0
    if checked_digest:
        ops += (15,)
        allowed = ({wire_db, *(os.fsencode(parent) for parent in db.parents)}
                   | {wire_db + suffix for suffix in (b"-wal", b"-shm", b"-journal")})
    owner = make()
    if not owner:
        raise MemoryError("Provider allocation failed")
    status, transcript, result, advanced = None, [], None, False
    row_changes_seen = 0
    try:
        for _ in range(85000):
            argument = ctypes.create_string_buffer(raw)
            status = step(argument, len(raw), state, EXTENT, hash_work, EXTENT)
            phase, op, length, published = struct.unpack_from("<QQQQ", state)
            if status != 198:
                if handoff and status == 0 and phase == 18 and published in (423, 455, 799, 831):
                    result = ctypes.string_at(ctypes.addressof(state) + 4096, published).hex()
                elif not handoff and status == 0 and phase == 18 and 489 <= published <= EXTENT - 4096:
                    result = ctypes.string_at(ctypes.addressof(state) + 4096, published).decode("ascii")
                elif status != 100 or published:
                    raise ValueError("Unexpected terminal status or private-output publication")
                break
            if published or op not in ops or not 8 <= length <= 1544:
                raise ValueError("Native request escaped the private mechanical ABI")
            advance_mode = "advance"
            if handoff:
                advance_mode = message.get("handoff_advance", "project")
                if advance_mode not in ("project", "install-installed", "cas-installed", "fence"):
                    raise ValueError("Expected a retained fixed disposable handoff fixture")
            advance_cut = (7, 8) if handoff else (11, 5)
            if message["advance"] and (phase, op) == advance_cut:
                if advanced:
                    raise ValueError("Unexpected duplicate qualification interleave")
                child = subprocess.run([message["advance"], advance_mode, str(db)],
                                       capture_output=True, check=True, timeout=25)
                if child.stdout or child.stderr:
                    raise ValueError("Original writer did not finish cleanly")
                advanced = True
            if message.get("kill_before_empty_readback_commit") and (phase, op) == (15, 5):
                if not writes or mode != "m13-sqlite-empty-delta-" or row_changes_seen or any(
                    (p, code) == (28, 10) for p, code, _ in transcript
                ):
                    raise ValueError("Expected a held empty replay without writes before termination")
                os.kill(os.getpid(), signal.SIGKILL)
            call = ctypes.addressof(state) + 256
            if checked_digest and op == 15:
                follow, unused, span = struct.unpack_from("<QQQ", state, 256)
                path = ctypes.string_at(call + 24, span) if 0 < span <= 520 else b""
                if follow or unused or length != 24 + span or path not in allowed or open_calls:
                    raise ValueError("Checked-digest fixture lstat scope escaped")
                path_calls.append((op, path.hex()))
            if checked_digest and op == 2:
                flags, span = struct.unpack_from("<QQ", state, 256)
                path = ctypes.string_at(call + 16, span) if 0 < span <= 512 else b""
                if flags != 16777217 or length != 16 + span or path != wire_db or open_calls:
                    raise ValueError("Checked-digest fixture SQLite OPEN scope escaped")
                # No host policy decision: this confines the native request to its owned input.
                path_calls.append((op, path.hex()))
                open_calls += 1
            amount = fetch(owner, op, call, length, response, EXTENT)
            transcript.append((phase, op, amount))
            stopped_after_metadata = message.get("kill_after_update") and (phase, op) == (28, 10)
            row_changes = (phase, op) == (35, 10)
            if row_changes:
                row_changes_seen += 1
            stopped_after_row = row_changes and (
                message.get("kill_after_delete") or message.get("kill_after_row")
                or message.get("kill_after_row_index") == row_changes_seen
            )
            if writes and (stopped_after_metadata or stopped_after_row):
                if amount != 24 or struct.unpack_from("<QQ", response) != (0, 1):
                    raise ValueError("Expected a real one-row uncommitted update before termination")
                os.kill(os.getpid(), signal.SIGKILL)
            # Huge provider lengths and sentinel errors are not interpreted
            # and cannot cause access outside the mechanically owned response.
            if amount > EXTENT:
                raw = b""
            else:
                raw = ctypes.string_at(response, amount)
        else:
            raise ValueError("Bounded qualification loop did not terminate")
        resources = reset(owner)
        result_data = {"status": status, "result": result, "advanced": advanced,
                       "transcript": transcript, "released": resources}
        if checked_digest:
            result_data["path_calls"] = path_calls
        return result_data
    finally:
        free(owner)



def path_preflight(message, reader, provider):
    ptr, u64 = ctypes.c_void_p, ctypes.c_uint64
    step = bind(reader, "f0", u64, ptr, u64, ptr, u64, ptr, u64)
    fetch = bind(provider, "trnm_task_provider", u64, ptr, u64, ptr, u64, ptr, u64)
    make = bind(provider, "trnm_task_provider_new", ptr)
    free = bind(provider, "trnm_task_provider_free", None, ptr)
    reset = bind(provider, "trnm_task_provider_reset", u64, ptr)
    directory, path = Path(message["directory"]), Path(message["database"])
    if (directory.name != "owned" or not directory.parent.name.startswith("m13-sqlite-path-")
            or directory.resolve(strict=True) != directory or directory.stat().st_mode & 0o077
            or not path.is_absolute() or not path.is_relative_to(directory) or path == directory
            or ".." in path.parts):
        raise ValueError("Expected a normalized path in an owned disposable fixture")
    path_raw = os.fsencode(path)
    allowed = ({path_raw, *(os.fsencode(parent) for parent in path.parents)}
               | {path_raw + suffix for suffix in (b"-wal", b"-shm", b"-journal")})
    mem = ctypes.create_string_buffer(8192)
    work = ctypes.create_string_buffer(1)
    response = ctypes.create_string_buffer(32)
    owner = make()
    if not owner:
        raise MemoryError("Provider allocation failed")
    raw, observations = path_raw, []
    try:
        for _ in range(520):
            argument = ctypes.create_string_buffer(raw)
            status = step(argument, len(raw), mem, 8192, work, 1)
            phase, op, length, published = struct.unpack_from("<QQQQ", mem)
            if published:
                raise ValueError("Path check has no data publication")
            if status in (0, 100):
                return {"status": status, "released": reset(owner), "observations": observations}
            if status != 198 or op != 15 or not 25 <= length <= 544 or not 1 <= phase <= 5:
                raise ValueError("Unexpected native lstat request")
            follow, unused, size = struct.unpack_from("<QQQ", mem, 256)
            path_bytes = ctypes.string_at(ctypes.addressof(mem) + 280, size) if 0 < size <= 520 else b""
            if (follow or unused or length != 24 + size or not path_bytes or path_bytes not in allowed):
                raise ValueError("Refusing any path outside the exact owned fixture and its ancestors")
            count = fetch(owner, op, ctypes.addressof(mem) + 256, length, response, 32)
            if count != 24:
                raise ValueError("Incomplete native provider lstat response")
            raw = ctypes.string_at(response, count)
            errno, mode, _ = struct.unpack("<QQQ", raw)
            observations.append((phase, path_bytes.hex(), errno, mode))
        raise ValueError("Bounded lstat qualification did not terminate")
    finally:
        free(owner)

def main():
    if len(sys.argv) != 1:
        raise SystemExit("Expected private request on stdin")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (256 << 20, 256 << 20))
    request = json.load(sys.stdin)
    with sealed_library(*request["reader"]) as reader, sealed_library(*request["provider"]) as provider:
        worker = path_preflight if request.get("path_preflight") is True else run
        result = worker(request, reader, provider)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
