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
    if (directory.resolve(strict=True) != directory or db.parent != directory
            or db.is_symlink() or not db.is_file() or directory.stat().st_mode & 0o077):
        raise ValueError("Owned canonical disposable test database required")
    state = ctypes.create_string_buffer(EXTENT)
    response = ctypes.create_string_buffer(EXTENT)
    hash_work = ctypes.create_string_buffer(EXTENT)
    raw = bytes.fromhex(message["expected"]).hex().upper().encode() + os.fsencode(db)
    proposal_hex = message.get("empty_delta")
    writes = proposal_hex is not None
    if writes:
        proposal = bytes.fromhex(proposal_hex)
        mode = {
            1042: "m13-sqlite-empty-delta-",
            1298: "m13-sqlite-delete-delta-",
            1434: "m13-sqlite-insert-delta-",
            2226: "m13-sqlite-mixed-delta-",
        }.get(len(proposal))
        if len(proposal) == 1434 and proposal[:8] == b"UPD1M13!":
            mode = "m13-sqlite-update-delta-"
        if mode is None or message["advance"] or (len(proposal) == 2226 and proposal[:8] != b"BAT1M13!"):
            raise ValueError("Exact private single-delta replay input required")
        if not directory.parent.name.startswith(mode) or directory.name != "owned":
            raise ValueError("Write qualification only uses its own named disposable directory")
        raw = proposal + raw
    ops = (2, 3, 5, 6, 7, 8, 9, 10) if writes else (2, 3, 5, 7, 8, 9)
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
                if status == 0 and phase == 18 and 489 <= published <= EXTENT - 4096:
                    result = ctypes.string_at(ctypes.addressof(state) + 4096, published).decode("ascii")
                elif status != 100 or published:
                    raise ValueError("Unexpected terminal status or private-output publication")
                break
            if published or op not in ops or not 8 <= length <= 1544:
                raise ValueError("Native request escaped the private mechanical ABI")
            if message["advance"] and phase == 11 and op == 5:
                if advanced:
                    raise ValueError("Unexpected duplicate qualification interleave")
                child = subprocess.run([message["advance"], "advance", str(db)],
                                       capture_output=True, check=True, timeout=25)
                if child.stdout or child.stderr:
                    raise ValueError("Original writer did not finish cleanly")
                advanced = True
            call = ctypes.addressof(state) + 256
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
        return {"status": status, "result": result, "advanced": advanced,
                "transcript": transcript, "released": resources}
    finally:
        free(owner)


def main():
    if len(sys.argv) != 1:
        raise SystemExit("Expected private request on stdin")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (256 << 20, 256 << 20))
    request = json.load(sys.stdin)
    with sealed_library(*request["reader"]) as reader, sealed_library(*request["provider"]) as provider:
        result = run(request, reader, provider)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
