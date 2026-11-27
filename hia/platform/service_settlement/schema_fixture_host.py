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


def native_path_preflight(path, image, provider):
    ptr, u64 = ctypes.c_void_p, ctypes.c_uint64
    step = bind(image, "f0", u64, ptr, u64, ptr, u64, ptr, u64)
    fetch = bind(provider, "trnm_task_provider", u64, ptr, u64, ptr, u64, ptr, u64)
    make = bind(provider, "trnm_task_provider_new", ptr)
    free = bind(provider, "trnm_task_provider_free", None, ptr)
    state, work = (ctypes.create_string_buffer(8192) for _ in range(2))
    response = ctypes.create_string_buffer(24)
    checks = []
    owner = make()
    if not owner:
        raise ValueError("Cannot allocate owned native path observer")
    raw = path
    try:
        for _ in range(5):
            inp = ctypes.create_string_buffer(raw)
            status = step(inp, len(raw), state, len(state), work, len(work))
            if status in (0, 100, 101):
                if status == 0 and len(checks) != 4:
                    raise ValueError("Original path admission needs all four real lstat calls")
                return status, checks
            stage, length = struct.unpack_from("<QQ", state)
            if (status != 198 or stage != len(checks) + 1
                    or stage > 4 or not 25 <= length <= 4128):
                raise ValueError("Unexpected exact native lstat continuation")
            amount = fetch(owner, 15, ctypes.addressof(state) + 256, length, response, len(response))
            if amount != 24:
                raise ValueError("Original lstat response has inconsistent framing")
            checks.append([stage, 15, amount])
            raw = response.raw
        raise ValueError("Original native path preflight did not terminate")
    finally:
        free(owner)


def native_store_header(path, image, provider):
    ptr, u64 = ctypes.c_void_p, ctypes.c_uint64
    step = bind(image, "f0", u64, ptr, u64, ptr, u64, ptr, u64)
    fetch = bind(provider, "trnm_task_provider", u64, ptr, u64, ptr, u64, ptr, u64)
    make = bind(provider, "trnm_task_provider_new", ptr)
    reset = bind(provider, "trnm_task_provider_reset", u64, ptr)
    free = bind(provider, "trnm_task_provider_free", None, ptr)
    state, work = (ctypes.create_string_buffer(8192) for _ in range(2))
    response = ctypes.create_string_buffer(44)
    owner = make()
    if not owner:
        raise ValueError("Cannot allocate owned native header observer")
    trace, raw, previous = [], path, 0
    try:
        for _ in range(67):  # open, at most 64 reads, close, terminal
            inp = ctypes.create_string_buffer(raw)
            status = step(inp, len(raw), state, len(state), work, len(work))
            stage, length = struct.unpack_from("<QQ", state)
            if status in (0, 100):
                leaked = reset(owner)
                if ((status == 0 and stage != 4)
                        or (stage == 4 and (previous != 3 or leaked))):
                    raise ValueError("Native store header requires actual descriptor close")
                return (state.raw[128:148] if status == 0 else b""), trace
            if (status != 198 or stage not in ({1} if previous == 0 else
                                              {2} if previous == 1 else
                                              {2, 3} if previous == 2 else set())
                    or not ({1: 25 <= length <= 4120, 2: length == 16, 3: length == 8}[stage])):
                raise ValueError("Unexpected native store header continuation")
            op = {1: 17, 2: 29, 3: 18}[stage]
            amount = fetch(owner, op, ctypes.addressof(state) + 256, length, response, len(response))
            if not 24 <= amount <= (44 if op == 29 else 24):
                raise ValueError("Native store header provider returned invalid framing")
            trace.append([op, amount])
            raw, previous = response.raw[:amount], stage
        raise ValueError("Bounded native store header read did not terminate")
    finally:
        free(owner)


def native_post_open_path(path, image, fetch, owner, open_response):
    # Forward the successful scalar and only the two permitted native requests
    # with the same SQLite provider context. Native owns the capability bytes.
    ptr, u64 = ctypes.c_void_p, ctypes.c_uint64
    step = bind(image, "f0", u64, ptr, u64, ptr, u64, ptr, u64)
    state, work = (ctypes.create_string_buffer(8192) for _ in range(2))
    response = ctypes.create_string_buffer(24)
    borrowed = ctypes.create_string_buffer(path)
    status = step(borrowed, len(path), state, len(state), work, len(work))
    if status != 196 or struct.unpack_from("<Q", state)[0] != 1:
        raise ValueError("Post-open path must request the actual SQLite-open result")
    borrow_open = ctypes.create_string_buffer(open_response)
    status = step(borrow_open, len(open_response), state, len(state), work, len(work))
    observations = []
    for expected, opcode in ((2, 15), (3, 3)):
        phase, size = struct.unpack_from("<QQ", state)
        valid_size = 25 <= size <= 4120 if expected == 2 else size == 8
        if expected == 3 and status == 0 and phase == 4:
            return status, observations
        if status != 198 or phase != expected or not valid_size:
            raise ValueError("Unexpected native post-open filesystem or SQLite request")
        amount = fetch(owner, opcode, ctypes.addressof(state) + 256, size, response, len(response))
        if amount != 24:
            raise ValueError("Post-open provider response has inconsistent framing")
        observations.append([opcode, amount])
        status = step(response, amount, state, len(state), work, len(work))
    if status != 100 or struct.unpack_from("<Q", state)[0] != 4:
        raise ValueError("Native post-open refusal must acknowledge explicit SQLite close")
    return status, observations


def native_open_lifecycle(path, image, open_sqlite, fetch, owner):
    """Broker only the sealed private lifecycle requests for one provider owner."""
    ptr, u64 = ctypes.c_void_p, ctypes.c_uint64
    step = bind(image, "f0", u64, ptr, u64, ptr, u64, ptr, u64)
    state, work = (ctypes.create_string_buffer(8192) for _ in range(2))
    response = ctypes.create_string_buffer(44)
    trace, raw, opened = [], path, None
    for _ in range(76):
        borrowed = ctypes.create_string_buffer(raw)
        status = step(borrowed, len(raw), state, len(state), work, len(work))
        phase, _, op = struct.unpack_from("<QQQ", state, 4400)
        size, = struct.unpack_from("<Q", state, 8)
        if phase == 7 and status in (0, 100, 101):
            if status == 0 and (opened is None or not trace or trace[-1] != [6, 15, 24]):
                raise ValueError("A successful native lifecycle must retain the checked SQLite open")
            return status, opened, trace
        if status == 196 and phase in (2, 4) and op == 0:
            raw = path
            continue
        if status == 197 and phase == 5 and op == 2 and opened is None:
            opened = open_sqlite(state.raw[128:148])
            trace.append([phase, op, len(opened)])
            raw = opened
            continue
        extent_ok = (25 <= size <= 4128 if op in (15, 17)
                     else size == 16 if op == 29 else size == 8)
        if (status != 198 or not extent_ok
                or (phase, op) not in ((1, 15), (3, 17), (3, 29), (3, 18), (6, 15), (6, 3))):
            raise ValueError("Unexpected native ownership continuation")
        amount = fetch(owner, op, ctypes.addressof(state) + 256, size, response, len(response))
        if not 24 <= amount <= (44 if op == 29 else 24):
            raise ValueError("Malformed native lifecycle provider result")
        trace.append([phase, op, amount])
        raw = response.raw[:amount]
    raise ValueError("Bounded native ownership continuation did not terminate")


def run(request, uri_image, reader, provider, gate=None, header_reader=None, post_open=None, lifecycle=None, preview=None, genesis_preview=None):
    db = Path(request["database"])
    directory = Path(request["directory"])
    if (db.parent != directory or directory.resolve(strict=True) != directory
            or directory.stat().st_mode & 0o077
            or (gate is None and lifecycle is None and (db.is_symlink() or not db.is_file()))):
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
    cursor_stream = request.get("cursor_stream_fixture", False)
    bank_stream = request.get("bank_stream_fixture", False)
    mixed_plan = request.get("mixed_plan_fixture", False)
    wide_stream = linear_stream or cursor_stream or bank_stream
    wide_limit = 9 if bank_stream else 8
    replay_limit = request.get("receipt_replay_limit", wide_limit if wide_stream else 4 if stream else 1)
    same_block = request.get("same_block_fixture", False)
    variable_first = request.get("variable_first_fixture", False)
    variable_pair = request.get("variable_pair_fixture", False)
    variable_settle = request.get("variable_settle_fixture", False)
    variable_rows = 1 if variable_first else 2 if variable_pair else 4 if variable_settle else 0
    replay_control_step = request.get("first_replay_fixture_control_step", replay_limit)
    if ((replay and (not journal or len(replay_image) != 2))
            or type(replay_limit) is not int or replay_limit not in ((wide_limit,) if wide_stream else (1, 2, 3, 4))
            or type(linear_stream) is not bool or type(cursor_stream) is not bool
            or type(bank_stream) is not bool or type(mixed_plan) is not bool
            or (mixed_plan and (not stream or wide_stream))
            or (wide_stream and not stream) or sum((bool(linear_stream), bool(cursor_stream), bool(bank_stream))) > 1
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
            or (replay_control == "parent" and not mixed_plan)
            or replay_control not in (None, "count", "id", "root", "state", "parent")):
        raise ValueError("Wrong finite first replay fixture profile")
    joined = terminal or journal
    if int(metadata) + int(operation) + int(marker) + int(terminal) + int(journal) > 1:
        raise ValueError("Choose one private continuation")
    projected = metadata or operation or marker or joined
    if lifecycle is not None and any(image is not None for image in (gate, header_reader, post_open)):
        raise ValueError("Do not combine independent and composed native open ownership")
    if post_open is not None and (gate is None or header_reader is None):
        raise ValueError("Post-open path requires the sealed native pre-open gate and header")
    if header_reader is not None and gate is None:
        raise ValueError("Native store header requires original pathname admission")
    preview_frames = None
    if preview is not None:
        frames = request.get("preview_frames")
        if not mixed_plan or not isinstance(frames, list) or not 1 <= len(frames) <= 8:
            raise ValueError("Expected finite preview decisions over actual native mixed profile")
        preview_frames = [bytes.fromhex(frame) for frame in frames]
        if any(not 219 <= len(frame) <= 8410 for frame in preview_frames):
            raise ValueError("Original preview decision frame exceeded the fixture domain")
    genesis_inputs = None
    if genesis_preview is not None:
        if not journal or replay or preview is not None:
            raise ValueError("Prospective genesis preview requires the independently audited empty journal")
        frame, command = (bytes.fromhex(request[k]) for k in ("genesis_frame", "genesis_command"))
        engine_image = request["genesis_engine"]
        if not (219 <= len(frame) <= 8410 and 112 <= len(command) <= 8192 and len(engine_image) == 2):
            raise ValueError("Wrong bounded genesis preview request")
        genesis_inputs = frame, command, engine_image
    path_checks = header_checks = None
    if gate is not None:
        gate_status, path_checks = native_path_preflight(os.fsencode(db), gate, provider)
        if gate_status:
            return {"status": gate_status, "path_checks": path_checks, "held": False,
                    "released": 0, "transcript": [], **({"projection": None} if projected else {})}
    if lifecycle is not None:
        header = b""
    elif header_reader is None:
        with db.open("rb") as header_file:
            header = header_file.read(20)
    else:
        header, header_checks = native_store_header(os.fsencode(db), header_reader, provider)
    if lifecycle is None and len(header) != 20:
        # Preserve the actual short header without treating pathname bytes as header.
        refused = {"status": 100, "transcript": [], "released": 0, "held": False}
        if projected:
            refused["projection"] = None
        if path_checks is not None:
            refused["path_checks"] = path_checks
        if header_checks is not None:
            refused["header_checks"] = header_checks
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
    post_open_checks = lifecycle_checks = None
    held = False
    projection = None
    replay_calls = 0
    replay_held = False
    requested_replay = 0
    selected_rows = None
    selected_profile = None
    engine = None
    replay_owners = ExitStack()
    replay_locks = 0
    end_phase = 56 if journal else 45 if terminal else 34 if metadata else 31 if operation else 25 if marker else 15
    hold_phase = 21 if metadata or marker or joined else 22 if operation else 7
    sizes = (219,) if journal else (187,) if terminal else (147,) if metadata else (8, 80) if operation else (40,) if marker else (0,)
    allowed_ops = (2, 3, 4, 5, 6, 7, 8, 9) if operation or journal else (2, 3, 4, 5, 7, 8, 9)
    try:
        if lifecycle is not None:
            def open_sqlite(original_header):
                frame = original_header + encoded.raw[:n]
                payload = ctypes.create_string_buffer(frame)
                result = step(payload, len(frame), state, EXTENT, work, EXTENT)
                phase, op, length, publication = struct.unpack_from("<QQQQ", state)
                if result != 198 or (phase, op, publication) != (1, 2, 0) or length != 16 + n:
                    raise ValueError("Native held reader must issue the original open exactly once")
                amount = fetch(owner, op, ctypes.addressof(state) + 256, length, response, EXTENT)
                if amount != 24:
                    raise ValueError("Original SQLite open scalar is malformed")
                transcript.append([phase, op, amount])
                return response.raw[:amount]

            status, raw, lifecycle_checks = native_open_lifecycle(path, lifecycle, open_sqlite, fetch, owner)
            transcript.extend([1, opcode, amount] for phase, opcode, amount in lifecycle_checks if phase == 6)
            if status:
                return {"status": status, "transcript": transcript, "held": False, "released": reset(owner),
                        "open_lifecycle": lifecycle_checks, **({"projection": None} if projected else {})}
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
                    if wide_stream:
                        native_rows, = struct.unpack_from("<Q", state, 7002)
                        if bank_stream:
                            rows = native_rows if (profile, native_rows) == (12, 9) else None
                        elif profile == 10 and 5 <= native_rows <= 8:
                            rows = native_rows
                        elif cursor_stream and (profile, native_rows) in ((6, 1), (5, 2), (11, 2), (7, 2), (9, 3), (8, 4)):
                            rows = native_rows
                        else:
                            rows = None
                    elif mixed_plan:
                        rows = 4 if profile == 13 else None
                    else:
                        rows = {6: 1, 7: 2, 8: 4, 9: 3}.get(profile)
                    if (rows is None or requested_replay > rows
                            or selected_rows not in (None, rows)
                            or selected_profile not in (None, profile)):
                        raise ValueError("Unexpected verified native stream selection")
                    selected_rows = rows
                    selected_profile = profile
                active_same = same_block or (cursor_stream and selected_profile in (5, 11))
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
                lane_widths = (1921, 2811) if active_same else (1921, 1953, 3742, 1293)
                measured = (stream and (not active_same or selected_profile == 11)) or variable_rows
                if measured:
                    if not 40 <= size <= 20642:
                        raise ValueError("Native continuation returned an unbounded variable request")
                elif size != lane_widths[requested_replay - 1]:
                    raise ValueError("Native continuation returned a different request shape")
                payload = ctypes.string_at(ctypes.addressof(state) + 360000, size)
                if engine is None:
                    engine = FixtureReplay.open(replay_owners, *replay_image, same_block=active_same,
                                                variable_rows=active_rows if measured and stream else variable_rows)
                raw = engine.apply(payload)
                predecessor_root = (active_rows == 4 or active_same or linear_stream
                                    or ((cursor_stream or bank_stream) and active_rows >= 3)
                                    or (stream and active_rows == 3))
                if raw and predecessor_root:
                    if engine.last_parent_root is None:
                        raise ValueError("Missing observed native predecessor root")
                    raw += engine.last_parent_root
                replay_calls = engine.calls.applies
                if replay_control is not None and raw and requested_replay == replay_control_step:
                    if replay_control == "parent" and not predecessor_root:
                        raise ValueError("Missing native Engine parent-root observation")
                    where = {"count": 0, "id": 8, "root": 40, "state": 72, "parent": len(raw) - 32}[replay_control]
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
            if post_open is not None and (phase, op) == (1, 2):
                if len(raw) != 24:
                    raise ValueError("Post-open path needs exact SQLite open framing")
                if struct.unpack_from("<Q", raw)[0] == 0:
                    status, post_open_checks = native_post_open_path(path, post_open, fetch, owner, raw)
                    transcript.extend([phase, opcode, size] for opcode, size in post_open_checks)
                    if status:
                        break
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
        if path_checks is not None:
            result["path_checks"] = path_checks
        if header_checks is not None:
            result["header_checks"] = header_checks
        if post_open_checks is not None:
            result["post_open_checks"] = post_open_checks
        if lifecycle_checks is not None:
            result["open_lifecycle"] = lifecycle_checks
        if replay:
            result.update(replay_calls=replay_calls, replay_held=replay_held, replay_locks=replay_locks)
            if status == 0 and replay_calls != (selected_rows if stream else replay_limit):
                raise ValueError("Success without exact Engine observation")
        if cursor_stream or bank_stream or mixed_plan:
            result["replay_profile"] = selected_profile
        if preview_frames is not None and status == 0:
            if result["released"] != 0:
                raise ValueError("Preview decision requires an explicitly closed original snapshot")
            decide = bind(preview, "f0", u64, *signature)
            decisions = []
            for frame in preview_frames:
                candidate = ctypes.create_string_buffer(frame)
                output = ctypes.create_string_buffer(b"\xa5" * 112, 112)
                code = decide(candidate, len(frame), state, EXTENT, output, len(output))
                if code not in (0, 100, 101) or (code and output.raw != b"\xa5" * 112):
                    raise ValueError("Native preview decision leaked or lacked exact live custody")
                decisions.append([code, output.raw.hex() if code == 0 else None])
            result["preview_decisions"] = decisions
        if genesis_inputs is not None and status == 0:
            if result["released"] != 0:
                raise ValueError("Genesis preview requires explicit native SQLite close")
            from hia.platform.service_settlement.first_replay_fixture_engine import FixtureReplay

            def buffer(raw):
                return ctypes.create_string_buffer(raw, len(raw))

            frame, command, engine_image = genesis_inputs
            receipt_image, command_image = genesis_preview
            native_preview = bind(receipt_image, "f0", u64, *signature)
            strict = bind(command_image, "f0", u64, *signature)
            pending = buffer(b"\xa5" * 112)
            final = buffer(b"\xa5" * 261)
            candidate = buffer(frame)
            code = native_preview(candidate, len(frame), state, EXTENT, pending, len(pending))
            calls = 0
            if code == 0:
                command_frame = buffer(command)
                checked = buffer(b"\xa5" * (34 + len(command)))
                scratch = buffer(b"\xa5" * (2304 + len(command)))
                code = strict(command_frame, len(command), checked, len(checked), scratch, len(scratch))
                if code == len(checked):
                    if checked.raw[:2] != b"\x18\0" or checked.raw[34:] != command:
                        raise ValueError("Prospective command changed in strict native traversal")
                    trust = bytes.fromhex(journal_hex)[104 + 32:]
                    engine = FixtureReplay.open(replay_owners, *engine_image)
                    actual = engine.preview_genesis_receipt(
                        trust, pending.raw[8:40], struct.unpack_from("<Q", frame)[0], command)
                    calls = engine.calls.applies
                    if actual is None:
                        code = 103
                    else:
                        parent, identity, root = actual
                        if identity != checked.raw[2:34]:
                            raise ValueError("Engine and strict native command disagree")
                        packed = pending.raw + parent + identity + frame[42:74] + frame[:40] + root
                        finish_input = buffer(packed)
                        work = buffer(b"\xc3" * 261)
                        code = native_preview(finish_input, len(packed), final, len(final), work, len(work))
                elif code == 0:
                    raise ValueError("Strict prospective command returned invalid success width")
            elif pending.raw != b"\xa5" * 112:
                raise ValueError("Genesis precheck leaked a rejected diagnostic")
            if code and final.raw != b"\xa5" * 261:
                raise ValueError("Genesis preview leaked a rejected diagnostic")
            result["genesis_preview"] = [code, final.raw.hex() if code == 0 else None, calls]
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
    with ExitStack() as owners:
        uri, reader, provider = (owners.enter_context(sealed_library(*message[key]))
                                 for key in ("uri", "reader", "provider"))
        gate = owners.enter_context(sealed_library(*message["path_gate"])) if "path_gate" in message else None
        header_reader = owners.enter_context(sealed_library(*message["header_reader"])) if "header_reader" in message else None
        post_open = owners.enter_context(sealed_library(*message["post_open_path"])) if "post_open_path" in message else None
        lifecycle = owners.enter_context(sealed_library(*message["open_lifecycle"])) if "open_lifecycle" in message else None
        preview = owners.enter_context(sealed_library(*message["preview_decision"])) if "preview_decision" in message else None
        genesis_preview = None
        if "genesis_preview" in message:
            genesis_preview = tuple(owners.enter_context(sealed_library(*message[key]))
                                    for key in ("genesis_preview", "genesis_receipt_command"))
        print(json.dumps(run(message, uri, reader, provider, gate, header_reader, post_open, lifecycle, preview,
                             genesis_preview)))


if __name__ == "__main__":
    main()
