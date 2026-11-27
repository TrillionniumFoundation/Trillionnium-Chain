"""Private test transport for the M12 native read-only schema continuation."""
from contextlib import ExitStack
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
    terminal_hex = request.get("terminal_binding")
    terminal = terminal_hex is not None
    journal_hex = request.get("journal_binding")
    journal = journal_hex is not None
    replay_image = request.get("first_replay_engine")
    replay_control = request.get("first_replay_fixture_control")
    replay = replay_image is not None
    stream = request.get("variable_stream_fixture", False)
    linear_stream = request.get("linear_stream_fixture", False)
    replay_limit = request.get("receipt_replay_limit", 8 if linear_stream else 4 if stream else 1)
    same_block = request.get("same_block_fixture", False)
    variable_first = request.get("variable_first_fixture", False)
    variable_pair = request.get("variable_pair_fixture", False)
    variable_settle = request.get("variable_settle_fixture", False)
    variable_rows = 1 if variable_first else 2 if variable_pair else 4 if variable_settle else 0
    replay_control_step = request.get("first_replay_fixture_control_step", replay_limit)
    if ((replay and (not journal or len(replay_image) != 2))
            or type(replay_limit) is not int or replay_limit not in ((8,) if linear_stream else (1, 2, 3, 4))
            or type(linear_stream) is not bool or (linear_stream and not stream)
            or type(stream) is not bool
            or (stream and (not replay or "receipt_replay_limit" in request or variable_rows or same_block))
            or type(variable_first) is not bool or type(variable_pair) is not bool
            or type(variable_settle) is not bool
            or sum((bool(variable_first), bool(variable_pair), bool(variable_settle))) > 1
            or (variable_rows and (not replay or replay_limit != variable_rows or same_block))
            or type(same_block) is not bool or (same_block and (not replay or replay_limit != 2))
            or type(replay_control_step) is not int or not 1 <= replay_control_step <= replay_limit
            or (replay_control is None and replay_control_step != replay_limit)
            or (not replay and (replay_control is not None or replay_limit != 1))
            or replay_control not in (None, "count", "id", "root", "state")):
        raise ValueError("Wrong finite first replay fixture profile")
    joined = terminal or journal
    if int(metadata) + int(operation) + int(marker) + int(terminal) + int(journal) > 1:
        raise ValueError("Choose one private continuation")
    projected = metadata or operation or marker or joined
    with db.open("rb") as header_file:
        header = header_file.read(20)
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
        expected = bytes.fromhex(
            expected_hex if metadata else operation_hex if operation else marker_hex if marker else terminal_hex if terminal else journal_hex
        )
        config = ctypes.create_string_buffer(expected)
        if step(config, len(expected), state, EXTENT, work, EXTENT) != (195 if joined else 196):
            raise ValueError("Native fixture did not accept the private binding")
        if joined:
            config_bytes = expected[104:]
            config = ctypes.create_string_buffer(config_bytes)
            if step(config, len(config_bytes), state, EXTENT, work, EXTENT) != 196:
                raise ValueError("Native joined fixture did not bind expected configuration")
    raw = initial
    owner = make()
    if not owner:
        raise MemoryError("Provider allocation failed")
    transcript = []
    held = False
    projection = None
    replay_calls = 0
    replay_held = False
    requested_replay = 0
    selected_rows = None
    engine = None
    replay_owners = ExitStack()
    replay_locks = 0
    end_phase = 56 if journal else 45 if terminal else 34 if metadata else 31 if operation else 25 if marker else 15
    hold_phase = 21 if metadata or marker or joined else 22 if operation else 7
    sizes = (219,) if journal else (187,) if terminal else (147,) if metadata else (8, 80) if operation else (40,) if marker else (0,)
    allowed_ops = (2, 3, 4, 5, 6, 7, 8, 9) if operation or journal else (2, 3, 4, 5, 7, 8, 9)
    try:
        for _ in range(2000 if journal else 1056 if terminal else 1024 if marker else 64 if projected else 32):
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
            if status == 199:
                if not replay or requested_replay >= replay_limit or (phase, op, length) != (52, 7, 8):
                    raise ValueError("Unexpected exact Engine continuation")
                requested_replay += 1
                if stream:
                    profile, = struct.unpack_from("<Q", state, 349024)
                    if linear_stream:
                        native_rows, = struct.unpack_from("<Q", state, 7002)
                        rows = native_rows if profile == 10 and 5 <= native_rows <= 8 else None
                    else:
                        rows = {6: 1, 7: 2, 8: 4, 9: 3}.get(profile)
                    if (rows is None or requested_replay > rows
                            or selected_rows not in (None, rows)):
                        raise ValueError("Unexpected verified native stream selection")
                    selected_rows = rows
                active_rows = selected_rows if stream else replay_limit
                if request.get("writer"):
                    check = subprocess.run([request["writer"], "try-write", str(db)],
                                           capture_output=True, check=True, timeout=15)
                    if (check.stdout, check.stderr) != (b"BUSY\n", b""):
                        raise ValueError("The actual journal snapshot was not held during replay")
                    replay_held = True
                    replay_locks += 1
                from hia.platform.service_settlement.first_replay_fixture_engine import FixtureReplay
                size, = struct.unpack_from("<Q", state, 349016)
                lane_widths = (1921, 2811) if same_block else (1921, 1953, 3742, 1293)
                if stream or variable_rows:
                    if not 40 <= size <= 20642:
                        raise ValueError("Native continuation returned an unbounded variable request")
                elif size != lane_widths[requested_replay - 1]:
                    raise ValueError("Native continuation returned a different request shape")
                payload = ctypes.string_at(ctypes.addressof(state) + 360000, size)
                if engine is None:
                    engine = FixtureReplay.open(replay_owners, *replay_image, same_block=same_block,
                                                variable_rows=active_rows if stream else variable_rows)
                raw = engine.apply(payload)
                if raw and (active_rows == 4 or same_block or linear_stream or (stream and active_rows == 3)):
                    if engine.last_parent_root is None:
                        raise ValueError("Missing observed native predecessor root")
                    raw += engine.last_parent_root
                replay_calls = engine.calls.applies
                if replay_control is not None and raw and requested_replay == replay_control_step:
                    where = {"count": 0, "id": 8, "root": 40, "state": 72}[replay_control]
                    raw = raw[:where] + bytes([raw[where] ^ 1]) + raw[where + 1:]
                continue
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
        if replay:
            result.update(replay_calls=replay_calls, replay_held=replay_held, replay_locks=replay_locks)
            if status == 0 and replay_calls != (selected_rows if stream else replay_limit):
                raise ValueError("Success without exact Engine observation")
        if projected:
            result["projection"] = projection
        return result
    finally:
        try:
            replay_owners.close()
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
