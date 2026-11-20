"""Observe actual original private functions and the actual HIA codec/replay."""
from pathlib import Path
import ctypes
import fcntl
import hashlib
import json
import os
import resource
import signal
import struct
import subprocess
import sys
import time
import traceback

request = json.loads(Path(sys.argv[1]).read_bytes())
out = Path(request["output"])
out.mkdir(mode=0o700)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
resource.setrlimit(resource.RLIMIT_AS, (512 << 20, 512 << 20))
resource.setrlimit(resource.RLIMIT_CPU, (240, 240))
started = time.monotonic_ns()
deadline = time.monotonic() + 240
report = {"status": "FAIL", "cases": {}, "original_calls": [],
          "host_business_logic_used": False, "original_functions_replaced": False,
          "whole_payload_owner_qualified": False, "original_service_budget_qualified": False}
descriptors = []


def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def checked(key):
    value = request[key]
    path = Path(value["path"])
    assert path.is_file() and not path.is_symlink()
    raw = path.read_bytes()
    assert identity(raw) == value["identity"], key
    return raw


def load(key):
    raw = checked(key)
    fd = os.memfd_create("payload-primitives-" + key, os.MFD_ALLOW_SEALING)
    at = 0
    while at < len(raw):
        count = os.write(fd, raw[at:])
        assert count > 0
        at += count
    os.fchmod(fd, 0o500)
    fcntl.fcntl(fd, getattr(fcntl, "F_ADD_SEALS", 1033), 15)
    descriptors.append(fd)
    module = ctypes.CDLL("/proc/self/fd/" + str(fd))
    module.f0.argtypes = [ctypes.c_void_p, ctypes.c_uint64] * 3
    module.f0.restype = ctypes.c_uint64
    return module


def parse(raw, count):
    assert len(raw) >= 8 and struct.unpack_from("<Q", raw)[0] == count
    rows, at = [], 8
    for _ in range(count):
        assert at + 16 <= len(raw)
        code, size = struct.unpack_from("<QQ", raw, at)
        at += 16
        assert size <= 4096 and at + size <= len(raw)
        rows.append((code, raw[at:at + size]))
        at += size
    assert at == len(raw)
    return rows


def original(kind, raw):
    directory = out / (kind + "-original")
    directory.mkdir(mode=0o700)
    (directory / "stdin.raw").write_bytes(raw)
    image = checked("original")
    argv = [request["original"]["path"], str(directory / "private-store")]
    row = {"argv": argv, "input": identity(raw), "executable": identity(image),
           "timed_out": False, "cleanup": None}
    child = None
    tick = time.monotonic_ns()
    try:
        with (directory / "stdin.raw").open("rb") as stdin, \
                (directory / "stdout.raw").open("xb") as stdout, \
                (directory / "stderr.raw").open("xb") as stderr:
            child = subprocess.Popen(argv, stdin=stdin, stdout=stdout, stderr=stderr,
                cwd=directory, env={"PATH": ""}, start_new_session=True, umask=0o077)
            row["pid"] = child.pid
            child.wait(timeout=max(0, deadline - time.monotonic()))
            row["exit_code"] = child.returncode
            assert child.returncode == 0
    except subprocess.TimeoutExpired:
        row["timed_out"] = True
        raise
    finally:
        if child is not None and child.poll() is None:
            begin = time.monotonic_ns()
            end = begin + 3_000_000_000
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=max(0, (end - time.monotonic_ns()) / 1e9))
            finally:
                row["cleanup"] = {"windows": 1, "limit_seconds": 3,
                    "complete": child.poll() is not None, "elapsed_ns": time.monotonic_ns() - begin}
        row["elapsed_ns"] = time.monotonic_ns() - tick
        row["reaped"] = child is not None and child.poll() is not None
        for name in ("stdout", "stderr"):
            path = directory / (name + ".raw")
            if path.is_file():
                row[name] = identity(path.read_bytes())
        (directory / "process.json").write_text(json.dumps(row, sort_keys=True, indent=2) + "\n")
        report["original_calls"].append(row)
    return (directory / "stdout.raw").read_bytes()


def invoke(module, raw):
    prefix, suffix = b"\x6d" * 64 + b"!", b"\xd6" * 64
    initial = [raw, b"\xa5" * 4096, b"\x73" * 137]
    buffers, args = [], []
    for value in initial:
        buffer = ctypes.create_string_buffer(prefix + value + suffix)
        buffers.append(buffer)
        args += [ctypes.addressof(buffer) + len(prefix), len(value)]
    begin = time.monotonic_ns()
    result = module.f0(*args)
    elapsed = time.monotonic_ns() - begin
    after = [bytes(buffer.raw[:-1]) for buffer in buffers]
    assert all(raw[:len(prefix)] == prefix and raw[-len(suffix):] == suffix for raw in after)
    assert after[0][len(prefix):-len(suffix)] == initial[0]
    assert after[2][len(prefix):-len(suffix)] == initial[2] and result >> 32 == 0
    output = after[1][len(prefix):-len(suffix)]
    if result:
        assert output == initial[1]
        return result, b"", elapsed
    size = struct.unpack_from("<Q", output)[0]
    assert size <= 4088 and output[8 + size:] == initial[1][8 + size:]
    return result, output[8:8 + size], elapsed


try:
    codec, replay = load("codec"), load("replay")
    with (out / "calls.jsonl").open("x") as retained:
        for kind, count, module in (("codec", 4472, codec), ("priority", 8, codec), ("replay", 840, replay)):
            rows = json.loads(checked(kind + "_cases"))
            assert len(rows) == count
            encoded = struct.pack("<Q", count)
            for row in rows:
                payload = bytes.fromhex(row["payload_hex"])
                encoded += struct.pack("<QQ", row["op"], len(payload)) + payload
            wanted_raw = original(kind, encoded)
            wanted = parse(wanted_raw, count)
            answer = bytearray(struct.pack("<Q", count))
            report["cases"][kind] = {"expected": count, "completed": 0}
            for row, expected in zip(rows, wanted):
                assert time.monotonic() < deadline
                payload = bytes.fromhex(row["payload_hex"])
                code, value, elapsed = invoke(module, struct.pack("<Q", 1 if kind == "replay" else row["op"]) + payload)
                observed = {"kind": kind, "name": row["name"], "code": code, "output_hex": value.hex(),
                            "input": identity(payload), "native_elapsed_ns": elapsed}
                retained.write(json.dumps(observed, sort_keys=True) + "\n")
                retained.flush()
                assert (code, value) == expected, (kind, row["name"], observed, expected)
                answer.extend(struct.pack("<QQ", code, len(value)) + value)
                report["cases"][kind]["completed"] += 1
            (out / (kind + "-native.raw")).write_bytes(answer)
            assert bytes(answer) == wanted_raw
            report["cases"][kind].update(input=identity(encoded), output=identity(bytes(answer)))
    for key in ("codec", "replay", "original", "codec_cases", "replay_cases", "priority_cases"):
        checked(key)
    assert not any(name.startswith("hepta") for name in sys.modules)
    report.update(status="PASS", codec_pairs=4472, priority_pairs=8, replay_pairs=840, native_calls=5320)
except BaseException as error:
    report.update(failure=repr(error), traceback=traceback.format_exc())
    raise
finally:
    report["elapsed_ns"] = time.monotonic_ns() - started
    (out / "report.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "traceback"}, sort_keys=True))
    for fd in descriptors:
        os.close(fd)
