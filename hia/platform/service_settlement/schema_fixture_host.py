"""Private test transport for the M12 native read-only schema continuation."""
import ctypes
import json
import os
from pathlib import Path
import resource
import struct
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from hia.platform.state_import_sqlite.qualification_host import bind, sealed_library

EXTENT = 1 << 20


def run(request, uri_image, reader, provider):
    db = Path(request["database"])
    directory = Path(request["directory"])
    if (db.parent != directory or directory.resolve(strict=True) != directory
            or directory.stat().st_mode & 0o077 or db.is_symlink() or not db.is_file()):
        raise ValueError("Only owned disposable databases are allowed")
    expected_hex = request.get("metadata_config")
    metadata = expected_hex is not None
    operation_hex = request.get("operation_id")
    operation = operation_hex is not None
    marker_hex = request.get("marker_binding")
    marker = marker_hex is not None
    if int(metadata) + int(operation) + int(marker) > 1:
        raise ValueError("Choose one private continuation")
    projected = metadata or operation or marker
    with db.open("rb") as stream:
        header = stream.read(20)
    if len(header) != 20:
        # Preserve the actual short header without treating pathname bytes as header.
        refused = {"status": 100, "transcript": [], "released": 0, "held": False}
        if projected:
            refused["projection"] = None
        return refused
    ptr, u64 = ctypes.c_void_p, ctypes.c_uint64
    signature = (ptr, u64, ptr, u64, ptr, u64)
    step = bind(reader, "f0", u64, *signature)
    uri = bind(uri_image, "f0", u64, *signature)
    fetch = bind(provider, "trnm_task_provider", u64, ptr, u64, ptr, u64, ptr, u64)
    make = bind(provider, "trnm_task_provider_new", ptr)
    free = bind(provider, "trnm_task_provider_free", None, ptr)
    reset = bind(provider, "trnm_task_provider_reset", u64, ptr)

    path = os.fsencode(db)
    borrowed = ctypes.create_string_buffer(path)
    encoded = ctypes.create_string_buffer(1536)
    work = ctypes.create_string_buffer(EXTENT)
    n = uri(borrowed, len(path), encoded, len(encoded), work, len(work))
    if not 13 <= n <= len(encoded):
        raise ValueError("Owned fixture URI escaped the private ABI")
    initial = header + encoded.raw[:n]
    state, response = (ctypes.create_string_buffer(EXTENT) for _ in range(2))
    if projected:
        expected = bytes.fromhex(expected_hex if metadata else operation_hex if operation else marker_hex)
        config = ctypes.create_string_buffer(expected)
        if step(config, len(expected), state, EXTENT, work, EXTENT) != 196:
            raise ValueError("Native fixture did not accept the private binding")
    raw = initial
    owner = make()
    if not owner:
        raise MemoryError("Provider allocation failed")
    transcript = []
    held = False
    projection = None
    end_phase = 34 if metadata else 31 if operation else 25 if marker else 15
    hold_phase = 21 if metadata or marker else 22 if operation else 7
    sizes = (147,) if metadata else (8, 80) if operation else (40,) if marker else (0,)
    allowed_ops = (2, 3, 4, 5, 6, 7, 8, 9) if operation else (2, 3, 4, 5, 7, 8, 9)
    try:
        for _ in range(1024 if marker else 64 if projected else 32):
            borrowed = ctypes.create_string_buffer(raw)
            status = step(borrowed, len(raw), state, EXTENT, work, EXTENT)
            phase, op, length, publication = struct.unpack_from("<QQQQ", state)
            if status == 0:
                if (phase, op, len(raw)) != (end_phase, 3, 24) or publication not in sizes:
                    raise ValueError("Success requires a real closed transaction and exact private output")
                if projected:
                    projection = ctypes.string_at(ctypes.addressof(state) + 4096, publication).hex()
                break
            if publication:
                raise ValueError("Early or refused metadata must never be published")
            if status == 100:
                break
            if status != 198 or op not in allowed_ops or not 8 <= length <= 1552:
                raise ValueError("Unexpected read-only request")
            payload = ctypes.addressof(state) + 256
            amount = fetch(owner, op, payload, length, response, EXTENT)
            transcript.append([phase, op, amount])
            if amount > EXTENT:
                raw = b""
            else:
                raw = response.raw[:amount]
            if request.get("writer") and not held and (phase, op) == (hold_phase, 7):
                if len(raw) != 24 or struct.unpack_from("<Q", raw)[0] != 100:
                    raise ValueError("Original writer must interleave after actual SQLite ROW")
                check = subprocess.run([request["writer"], "try-write", str(db)],
                                       capture_output=True, check=True, timeout=15)
                if (check.stdout, check.stderr) != (b"BUSY\n", b""):
                    raise ValueError("Rollback reader did not hold the original writer off commit")
                held = True
        else:
            raise ValueError("Bounded schema check did not finish")
        result = {"status": status, "transcript": transcript, "held": held, "released": reset(owner)}
        if projected:
            result["projection"] = projection
        return result
    finally:
        free(owner)


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (256 << 20, 256 << 20))
    message = json.load(sys.stdin)
    with sealed_library(*message["uri"]) as uri, sealed_library(*message["reader"]) as reader, \
            sealed_library(*message["provider"]) as provider:
        print(json.dumps(run(message, uri, reader, provider)))


if __name__ == "__main__":
    main()
