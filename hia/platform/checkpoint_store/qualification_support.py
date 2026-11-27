"""Retain actual native/original process I/O for independent qualification.

This module is a test controller, never a storage implementation or runtime
fallback. Every request is executed by both independently built executables.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import select
import signal
import struct
import subprocess
import time


def need(condition, message):
    if not condition:
        raise AssertionError(message)


def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def append_raw(path, fragment):
    # Each API process owns a fresh evidence directory. Append only newly
    # transferred bytes, so a timed call never rewrites its prior transcript.
    with path.open("ab", buffering=0) as stream:
        need(stream.write(fragment) == len(fragment), ("Incomplete raw API evidence", path))


def error_code(kind, text):
    kinds = {"config": 1, "log": 2, "io": 3, "protocol": 4,
             "compare": 5, "unavailable": 6, "ledger_path": 7,
             "ledger_state": 8, "ledger_source": 9, "ledger_target": 10,
             "ledger_third": 11, "ledger_io": 12, "store": 13}
    digest = hashlib.sha256((kind + ":" + text).encode()).digest()
    return (kinds[kind] << 32) | int.from_bytes(digest[:4], "big")


def terminal(process, timeout=5):
    cleanup = None
    if process.poll() is None:
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)
            cleanup = {"signal": "SIGKILL", "complete": True}
    return cleanup


class API:
    def __init__(self, suite, executable, label):
        self.suite = suite
        self.path = suite.output / ("process-" + str(len(suite.processes)))
        self.path.mkdir(mode=0o700)
        self.executable = Path(executable).absolute()
        self.before = identity(self.executable.read_bytes())
        self.label = label
        self.stdin = bytearray()
        self.stdout = bytearray()
        self.calls = 0
        self.stderr = (self.path / "stderr.raw").open("xb")
        self.start = time.monotonic_ns()
        self.p = subprocess.Popen([str(self.executable)], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=self.stderr,
                                  start_new_session=True)
        self.closed = False
        suite.processes.append(self)

    def read(self, n):
        result = bytearray()
        end = time.monotonic() + 15
        while len(result) < n:
            ready = select.select([self.p.stdout], [], [], max(0, end - time.monotonic()))[0]
            need(bool(ready), ("API response deadline", self.label, self.p.poll()))
            part = os.read(self.p.stdout.fileno(), n - len(result))
            need(bool(part), ("API response EOF", self.label, self.p.poll()))
            result.extend(part)
            self.stdout.extend(part)
            append_raw(self.path / "stdout.raw", part)
        return bytes(result)

    def call(self, op, body=b""):
        started = time.monotonic_ns()
        self.calls += 1
        raw = b"HCSAPI01" + struct.pack("<QQQ", op, len(body), 0) + body
        self.stdin.extend(raw)
        append_raw(self.path / "stdin.raw", raw)
        self.p.stdin.write(raw)
        self.p.stdin.flush()
        header = self.read(48)
        need(header[:8] == b"HCSAPO01", ("API response header", self.label, header.hex()))
        values = struct.unpack("<5Q", header[8:])
        need(values[3] <= 16 * 1024 * 1024, "Qualification response bound exceeded")
        result = self.read(values[3])
        need(values[4] == op, ("API method echo", op, values))
        self.last_elapsed_ns = time.monotonic_ns() - started
        return values, result

    def close(self, *, require_success=True):
        if self.closed:
            return
        self.closed = True
        try:
            self.p.stdin.close()
        except BrokenPipeError:
            pass
        cleanup = terminal(self.p)
        trailing = self.p.stdout.read()
        self.stdout.extend(trailing)
        self.stderr.close()
        (self.path / "stdin.raw").write_bytes(self.stdin)
        (self.path / "stdout.raw").write_bytes(self.stdout)
        stderr = (self.path / "stderr.raw").read_bytes()
        row = {"label": self.label, "argv": [str(self.executable)],
               "executable_before": self.before,
               "executable_after": identity(self.executable.read_bytes()),
               "stdin": identity(self.stdin), "stdout": identity(self.stdout),
               "stderr": identity(stderr), "exit_code": self.p.returncode,
               "cleanup": cleanup, "elapsed_ns": time.monotonic_ns() - self.start}
        save(self.path / "receipt.json", row)
        if require_success:
            need(self.before == row["executable_after"] and self.p.returncode == 0
                 and cleanup is None and not stderr and not trailing,
                 ("API process termination", row, stderr.hex(), trailing.hex()))


class Pair:
    def __init__(self, suite, name):
        self.suite, self.name = suite, name
        self.na, self.nb = suite.root / (name + "-native"), suite.root / (name + "-original")
        self.na.mkdir(mode=0o700)
        self.nb.mkdir(mode=0o700)
        self.a = API(suite, suite.native / "checkpoint-store-api", name + ":native")
        self.b = API(suite, suite.original_api, name + ":original")

    def call(self, op, a=b"", b=None, label="", normalize_path=False):
        b = a if b is None else b
        native, original = self.a.call(op, a), self.b.call(op, b)
        row = {"kind": "api-pair", "case": self.name, "label": label, "op": op,
               "native_input": a.hex(), "original_input": b.hex(),
               "native": {"header": native[0], "body": native[1].hex()},
               "original": {"header": original[0], "body": original[1].hex()},
               "normalize_path": normalize_path,
               "native_process": self.a.path.relative_to(self.suite.output).as_posix(),
               "original_process": self.b.path.relative_to(self.suite.output).as_posix(),
               "native_call": self.a.calls, "original_call": self.b.calls,
               "native_root": str(self.na), "original_root": str(self.nb),
               "native_elapsed_ns": self.a.last_elapsed_ns,
               "original_elapsed_ns": self.b.last_elapsed_ns}
        x, y = native, original
        if normalize_path:
            need(op in (13, 32) and native[0][0] == original[0][0] == 0,
                 "Path normalization is limited to successful original path accessors")
            nx = native[1].replace(bytes(self.na), b"$ROOT")
            ny = original[1].replace(bytes(self.nb), b"$ROOT")
            x = native[0][:3] + (len(nx),) + native[0][4:], nx
            y = original[0][:3] + (len(ny),) + original[0][4:], ny
        row["status"] = "PASS" if x == y else "FAIL"
        self.suite.emit(row)
        need(x == y, row)
        return native

    def path(self, op, suffix, prefix=b"", **kwargs):
        return self.call(op, prefix + bytes(self.na / suffix),
                         prefix + bytes(self.nb / suffix), **kwargs)

    def close(self):
        self.a.close()
        self.b.close()


class Suite:
    def __init__(self, native, original_cli, original_api, output):
        self.native = Path(native).absolute()
        self.original_cli = Path(original_cli).absolute()
        self.original_api = Path(original_api).absolute()
        self.output = Path(output).absolute()
        self.output.mkdir(mode=0o700)
        self.root = self.output / "files"
        self.root.mkdir(mode=0o700)
        self.rows, self.processes = [], []
        self.group = None
        save(self.output / "observations.json", self.rows)

    def pair(self, name):
        return Pair(self, name)

    def cli_one(self, kind, args, label, *, timeout=15):
        executable = self.native / "trnm-external-node-checkpoint-v2" if kind == "native" else self.original_cli
        folder = self.output / ("cli-" + str(len(self.rows)) + "-" + kind)
        folder.mkdir(mode=0o700)
        argv = [str(executable), *map(os.fspath, args)]
        before = identity(executable.read_bytes())
        started = time.monotonic_ns()
        with (folder / "stdout.raw").open("xb") as out, (folder / "stderr.raw").open("xb") as err:
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                       start_new_session=True)
            cleanup = terminal(process, timeout)
        result = {"exit": process.returncode,
                  "stdout": (folder / "stdout.raw").read_bytes().hex(),
                  "stderr": (folder / "stderr.raw").read_bytes().hex()}
        receipt = {"label": label, "argv_hex": [os.fsencode(a).hex() for a in argv],
                   "result": result, "executable": before,
                   "elapsed_ns": time.monotonic_ns() - started, "cleanup": cleanup}
        save(folder / "receipt.json", receipt)
        self.last_cli_path = folder.relative_to(self.output).as_posix()
        need(cleanup is None and identity(executable.read_bytes()) == before,
             ("CLI termination or executable changed", receipt))
        return result

    def cli(self, label, native_args, original_args=None):
        native = self.cli_one("native", native_args, label)
        native_process = self.last_cli_path
        original = self.cli_one("original", native_args if original_args is None else original_args, label)
        row = {"kind": "cli-pair", "case": label, "native": native, "original": original,
               "native_process": native_process, "original_process": self.last_cli_path,
               "status": "PASS" if native == original else "FAIL"}
        self.emit(row)
        need(native == original, row)
        return native

    def emit(self, row):
        row = {**row, "group": self.group, "ordinal": len(self.rows)}
        self.rows.append(row)
        save(self.output / "observations.json", self.rows)
        print(json.dumps({k: row[k] for k in ("kind", "case", "label", "op", "status") if k in row}), flush=True)

    def close(self, *, require_success=True):
        errors = []
        for process in self.processes:
            try:
                process.close(require_success=require_success)
            except BaseException as error:
                errors.append(repr(error))
        need(not errors, errors)
