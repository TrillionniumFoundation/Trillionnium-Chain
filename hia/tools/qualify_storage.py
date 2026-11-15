"""Build and exercise the actual native HIA StoreOwner in fresh directories.

Python supplies test input and independently checks disk bytes. It never services
an owner operation or substitutes for native persistence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import select
import shutil
import signal
import stat
import struct
import subprocess
import time
import traceback

from hia.platform.build import new_output, sealed_executable, write_json
from hia.storage.build import Build, digest

U64_MAX = (1 << 64) - 1
CONTEXT = hashlib.sha256(b"native-HIA-storage-qualification-context-v1").digest()
RECORD = struct.Struct("<8sQQQ32s")
BOOT = struct.Struct("<8sQQ32sQQQ")
MAX_PAYLOAD = 16 * 1024 * 1024
CHUNK = 32768
TIMEOUT = 30.0
CLEANUP = 3.0


def genesis(context: bytes = CONTEXT) -> bytes:
    return hashlib.sha256(b"HIAGEN01" + context).digest()


def committed(sequence: int, payload: bytes, previous: bytes, context: bytes = CONTEXT) -> bytes:
    value = hashlib.sha256(b"HIAHASH1" + context + struct.pack("<QQ", sequence, len(payload)) + previous).digest()
    for start in range(0, len(payload), CHUNK):
        part = payload[start:start + CHUNK]
        value = hashlib.sha256(b"HIAHASH2" + value + struct.pack("<Q", len(part)) + part).digest()
    return value


def decode_response(raw: bytes) -> dict:
    magic, kind, sequence, length, value = RECORD.unpack(raw)
    if magic != b"HIARSP01" or kind not in (0, 1, 2):
        raise ValueError("Invalid native response")
    return {"kind": kind, "sequence": sequence, "length": length, "digest": value}


def disk_chain(directory: Path, context: bytes = CONTEXT) -> dict:
    """Independent complete on-disk oracle, using hashlib and fixed encoding."""
    fmt = (directory / "FORMAT").read_bytes()
    assert fmt == b"HIAFMT01" + context + struct.pack("<QQQ", MAX_PAYLOAD, 4096, CHUNK)
    head = (directory / "HEAD").read_bytes()
    assert len(head) == 128 and head[:8] == b"HIAHD001" and head[24:56] == context and head[120:] == bytes(8)
    sequence, length = struct.unpack_from("<QQ", head, 8)
    assert sequence <= 4096 and length <= MAX_PAYLOAD
    previous = genesis(context)
    latest = b""
    for index in range(1, sequence + 1):
        raw = (directory / f"txn.{index:016x}").read_bytes()
        header, payload = raw[:128], raw[128:]
        assert len(header) == 128 and header[:8] == b"HIAHD001"
        number, count = struct.unpack_from("<QQ", header, 8)
        assert number == index and count == len(payload) and count <= MAX_PAYLOAD
        assert header[24:56] == context and header[88:120] == previous and header[120:] == bytes(8)
        current = committed(index, payload, previous, context)
        assert header[56:88] == current
        previous, latest = current, payload
        if index == sequence:
            assert header == head
    if sequence == 0:
        assert length == 0 and head[88:120] == bytes(32)
    assert head[56:88] == previous and len(latest) == length
    return {"sequence": sequence, "length": length, "digest": previous, "payload": latest}


class Session:
    """Only an external launcher/controller for the static native owner."""
    def __init__(self, image: bytes, directory: Path, evidence: Path, *, mode: int,
                 context: bytes = CONTEXT, gates: bool = False, file_limit: int | None = None,
                 bootstrap: bool = True):
        self.directory, self.evidence = directory, evidence
        evidence.mkdir(mode=0o700)
        self.image_sha256 = digest(image)
        self.stdout, self.stdin = bytearray(), bytearray()
        self.stderr = b""
        self.gate_records = []
        self.notify = self.go = None
        self.finished = False
        self.current = None
        self.context, self.gates = context, gates
        self.started = time.monotonic_ns()
        executable = sealed_executable(image, "hia-storage-owner")
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        held = [directory_fd, executable]
        notify_write = go_read = U64_MAX
        if gates:
            self.notify, notify_write = os.pipe()
            go_read, self.go = os.pipe()
            held += [notify_write, go_read]

        def limit_child():
            # A real kernel file-size limit; no I/O response emulation.
            resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)

        try:
            self.process = subprocess.Popen(["/proc/self/fd/" + str(executable)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                bufsize=0, cwd=evidence, env={"PATH": ""}, pass_fds=tuple(held),
                start_new_session=True, umask=0o077,
                preexec_fn=limit_child if file_limit is not None else None)
        finally:
            for fd in held:
                os.close(fd)
        self.bootstrap = BOOT.pack(b"HIAST001", directory_fd, mode, context, notify_write, go_read, 0)
        self.file_limit = file_limit
        os.set_blocking(self.process.stdin.fileno(), False)
        if bootstrap:
            self.write(self.bootstrap)

    def __enter__(self):
        return self

    def __exit__(self, kind, value, tb):
        if not self.finished:
            self.kill("exception-or-unfinished-cleanup")

    def write(self, raw: bytes, timeout: float = TIMEOUT) -> None:
        end = time.monotonic() + timeout
        cursor = 0
        while cursor < len(raw):
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Test controller input deadline")
            _, ready, _ = select.select([], [self.process.stdin], [], remaining)
            if not ready:
                raise TimeoutError("Test controller input deadline")
            try:
                count = os.write(self.process.stdin.fileno(), raw[cursor:cursor + 65536])
            except (BlockingIOError, InterruptedError):
                continue
            if count <= 0:
                raise OSError("Native stdin made no progress")
            self.stdin.extend(raw[cursor:cursor + count])
            cursor += count

    def read(self, count: int, *, gate: bool = False, timeout: float = TIMEOUT) -> bytes:
        fd = self.notify if gate else self.process.stdout.fileno()
        result = bytearray()
        end = time.monotonic() + timeout
        while len(result) < count:
            remaining = end - time.monotonic()
            if remaining <= 0 or not select.select([fd], [], [], max(0, remaining))[0]:
                raise TimeoutError("Native output deadline")
            try:
                chunk = os.read(fd, count - len(result))
            except InterruptedError:
                continue
            if not chunk:
                raise EOFError(f"Native output ended at {len(result)}/{count}")
            result.extend(chunk)
            if not gate:
                self.stdout.extend(chunk)
        return bytes(result)

    def resume(self) -> None:
        assert self.go is not None
        assert os.write(self.go, b"\x01") == 1

    def pause(self, target: int) -> dict:
        assert self.gates
        while True:
            tag, sequence, partials, eintr = struct.unpack("<QQQQ", self.read(32, gate=True))
            record = {"tag": tag, "sequence": sequence, "positive_partial_results": partials, "eintr_results": eintr, "observed_monotonic_ns": time.monotonic_ns()}
            self.gate_records.append(record)
            if tag == target:
                return record
            assert tag in {1, 2, 3, 4, 10, 11, 12, 13, 14, 15, 16, 20}
            self.resume()

    def ready(self) -> dict:
        if self.gates:
            self.pause(20)
            self.resume()
        result = decode_response(self.read(64))
        assert result["kind"] == 0
        self.current = result
        return result

    def request(self, operation: int, payload: bytes = b"", *, sequence: int | None = None,
                value: bytes | None = None, declared: int | None = None) -> None:
        assert self.current is not None
        seq = self.current["sequence"] if sequence is None else sequence
        expected = self.current["digest"] if value is None else value
        self.write(RECORD.pack(b"HIACMD01", operation, len(payload) if declared is None else declared, seq, expected))
        if payload:
            self.write(payload)

    def commit(self, payload: bytes) -> dict:
        before = self.current
        self.request(1, payload)
        if self.gates:
            self.pause(16)
            self.resume()
        result = decode_response(self.read(64))
        assert result == {"kind": 1, "sequence": before["sequence"] + 1, "length": len(payload),
                          "digest": committed(before["sequence"] + 1, payload, before["digest"], self.context)}
        self.current = result
        return result

    def get(self) -> bytes:
        self.request(2)
        result = decode_response(self.read(64))
        assert result == {**self.current, "kind": 2}
        return self.read(result["length"])

    def close(self) -> dict:
        self.request(3)
        return self.finish(0)

    def finish(self, expected: int | None = None, *, cleanup: dict | None = None) -> dict:
        if self.finished:
            return self.row
        if self.process.stdin is not None:
            self.process.stdin.close()
            self.process.stdin = None
        try:
            extra, self.stderr = self.process.communicate(timeout=CLEANUP)
        except subprocess.TimeoutExpired:
            start = time.monotonic_ns()
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
                outcome = "sent"
            except ProcessLookupError:
                outcome = "already_exited"
            extra, self.stderr = self.process.communicate(timeout=CLEANUP)
            cleanup = {"reason": "finish-timeout", "signal": "SIGKILL", "signal_outcome": outcome,
                       "elapsed_ns": time.monotonic_ns() - start, "complete": self.process.returncode is not None}
        self.stdout.extend(extra or b"")
        for name in ("notify", "go"):
            fd = getattr(self, name)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)
        self.finished = True
        self.row = {"schema": "trnm.hia.storage-process.v1", "pid": self.process.pid,
                    "executable_sha256": self.image_sha256, "namespace": str(self.directory),
                    "exit_code": self.process.returncode, "stdout_bytes": len(self.stdout),
                    "stdout_sha256": digest(bytes(self.stdout)), "stderr_hex": self.stderr.hex(),
                    "input_bytes": len(self.stdin), "input_sha256": digest(bytes(self.stdin)),
                    "explicit_gate": self.gates, "gate_observations": self.gate_records,
                    "rlimit_fsize": self.file_limit, "cleanup": cleanup,
                    "started_monotonic_ns": self.started, "finished_monotonic_ns": time.monotonic_ns()}
        (self.evidence / "stdin.raw").write_bytes(self.stdin)
        (self.evidence / "stdout.raw").write_bytes(self.stdout)
        (self.evidence / "stderr.raw").write_bytes(self.stderr)
        if len(self.stderr) == 40:
            code, phase, raw_result, uncertain, ack = struct.unpack("<QQQQQ", self.stderr)
            self.row["diagnostic"] = {"code": code, "phase": phase, "syscall_result_bits": raw_result,
                                      "uncertain": uncertain, "private_committed_sequence": ack}
        write_json(self.evidence / "result.json", self.row)
        if expected is not None:
            assert self.process.returncode == expected, self.row
        return self.row

    def kill(self, reason: str = "actual-process-crash") -> dict:
        start = time.monotonic_ns()
        try:
            os.killpg(self.process.pid, signal.SIGKILL)
            outcome = "sent"
        except ProcessLookupError:
            outcome = "already_exited"
        return self.finish(cleanup={"reason": reason, "signal": "SIGKILL", "signal_outcome": outcome,
                                   "signal_monotonic_ns": start, "physical_power_loss": False})

    def wait_read(self, count: int) -> dict:
        end = time.monotonic() + 5
        while time.monotonic() < end:
            raw = Path(f"/proc/{self.process.pid}/syscall").read_text().strip()
            parts = raw.split()
            if len(parts) >= 4 and parts[0] == "0" and int(parts[1], 0) == 0 and int(parts[3], 0) == count:
                row = {"raw": raw, "count": count, "observed_monotonic_ns": time.monotonic_ns()}
                with (self.evidence / "blocked-reads.jsonl").open("a") as stream:
                    stream.write(json.dumps(row) + "\n")
                return row
            if self.process.poll() is not None:
                raise RuntimeError("Native owner exited before read readiness")
            time.sleep(0.001)
        raise TimeoutError("Actual native blocked read not observed")


class Qualification:
    def __init__(self, output: Path):
        if not __debug__:
            raise RuntimeError("Storage qualification requires active assertions")
        self.output = output
        self.builder = Build(output / "build")
        self.build = self.builder.build()
        self.image = self.builder.executable
        self.results = []
        self.cases = output / "cases"
        self.cases.mkdir(mode=0o700)

    def case(self, name: str, run) -> None:
        root = self.cases / name
        root.mkdir(mode=0o700)
        try:
            details = run(root) or {}
            row = {"case": name, "status": "PASS", **details}
        except Exception as error:
            row = {"case": name, "status": "FAIL", "error": repr(error), "traceback": traceback.format_exc()}
        write_json(root / "case.json", row)
        self.results.append(row)

    def fresh(self, root: Path, payloads: tuple[bytes, ...] = ()) -> tuple[Path, dict]:
        directory = root / "namespace"
        directory.mkdir(mode=0o700)
        with Session(self.image, directory, root / "seed", mode=1) as owner:
            owner.ready()
            for payload in payloads:
                owner.commit(payload)
            current = owner.current
            owner.close()
        return directory, current

    def roundtrip(self, root: Path, payload: bytes) -> dict:
        directory, current = self.fresh(root, (payload,))
        oracle = disk_chain(directory)
        assert oracle["payload"] == payload and oracle["digest"] == current["digest"]
        for suffix in ("reopen", "reopen-again"):
            with Session(self.image, directory, root / suffix, mode=2) as owner:
                assert owner.ready()["digest"] == oracle["digest"]
                assert owner.get() == payload
                owner.close()
        return {"payload_bytes": len(payload), "payload_sha256": digest(payload), "sequence": oracle["sequence"]}

    def corrupt(self, root: Path, action) -> dict:
        directory, _ = self.fresh(root, (b"first retained payload", b"second retained payload"))
        action(directory)
        with Session(self.image, directory, root / "refused", mode=2) as owner:
            row = owner.finish(66)
        assert not (root / "refused/stdout.raw").read_bytes()
        return {"exit_code": row["exit_code"]}

    def crash(self, root: Path, tag: int) -> dict:
        old, new = b"old committed bytes", bytes(range(256)) * 257
        directory, prior = self.fresh(root, (old,))
        with Session(self.image, directory, root / "interrupted", mode=2, gates=True) as owner:
            owner.ready()
            owner.request(1, new)
            observation = owner.pause(tag)
            row = owner.kill()
            assert row["exit_code"] == -signal.SIGKILL
        expected = new if tag >= 15 else old
        expected_seq = 2 if tag >= 15 else 1
        oracle = disk_chain(directory)
        assert oracle["payload"] == expected and oracle["sequence"] == expected_seq
        with Session(self.image, directory, root / "recovery", mode=2) as owner:
            assert owner.ready()["sequence"] == expected_seq
            assert owner.get() == expected
            if tag < 15:
                # Removes only unreferenced successor/temp artifacts, then
                # publishes the same requested payload under the same CAS.
                owner.commit(new)
                assert owner.get() == new
            owner.close()
        return {"observed_gate": observation, "recovered_sequence": expected_seq,
                "process_crash": True, "physical_power_loss": False,
                "pre_crash_ack_digest": prior["digest"].hex()}

    def run(self) -> dict:
        for length in (0, 1, 32767, 32768, 32769, 2 * 1024 * 1024, MAX_PAYLOAD):
            payload = (bytes(range(256)) * ((length + 255) // 256))[:length]
            self.case("roundtrip-" + str(length), lambda root, payload=payload: self.roundtrip(root, payload))

        for tag in (10, 11, 12, 13, 14, 15, 16):
            self.case("sigkill-stage-" + str(tag), lambda root, tag=tag: self.crash(root, tag))

        def initialize_cut(root, tag):
            directory = root / "namespace"; directory.mkdir(mode=0o700)
            with Session(self.image, directory, root / "interrupted", mode=1, gates=True) as owner:
                observation = owner.pause(tag)
                row = owner.kill()
                assert row["exit_code"] == -signal.SIGKILL
            if tag in (2, 3):
                before = {p.name: p.read_bytes() for p in directory.iterdir()}
                with Session(self.image, directory, root / "existing-refused", mode=2) as owner:
                    owner.finish(66)
                with Session(self.image, directory, root / "fresh-refused", mode=1) as owner:
                    owner.finish(65)
                assert {p.name: p.read_bytes() for p in directory.iterdir()} == before
                outcome = "unacknowledged partial initialization refused without overwrite"
            else:
                with Session(self.image, directory, root / "recovery", mode=1 if tag == 1 else 2) as owner:
                    assert owner.ready()["sequence"] == 0
                    assert owner.get() == b""
                    owner.close()
                assert disk_chain(directory)["sequence"] == 0
                outcome = "lock-only fresh retry" if tag == 1 else "complete visible genesis reopened"
            return {"observed_gate": observation, "outcome": outcome, "physical_power_loss": False}
        for tag in (1, 2, 3, 4, 20):
            self.case("initialization-sigkill-" + str(tag), lambda root, tag=tag: initialize_cut(root, tag))

        def flip(path: Path, offset: int):
            raw = bytearray(path.read_bytes()); raw[offset] ^= 1; path.write_bytes(raw)

        changes = {
            "format": lambda d: flip(d / "FORMAT", 0),
            "payload": lambda d: flip(d / "txn.0000000000000002", 128),
            "historical-payload": lambda d: flip(d / "txn.0000000000000001", 128),
            "head": lambda d: flip(d / "HEAD", 56),
            "transaction-header": lambda d: flip(d / "txn.0000000000000002", 127),
            "truncated": lambda d: (d / "txn.0000000000000002").write_bytes((d / "txn.0000000000000002").read_bytes()[:-1]),
            "extended": lambda d: (d / "txn.0000000000000002").write_bytes((d / "txn.0000000000000002").read_bytes() + b"x"),
            "missing-history": lambda d: (d / "txn.0000000000000001").unlink(),
            "file-mode": lambda d: (d / "txn.0000000000000002").chmod(0o644),
            "hardlink": lambda d: os.link(d / "txn.0000000000000002", d.parent / "second-link"),
        }
        for name, action in changes.items():
            self.case("reject-" + name, lambda root, action=action: self.corrupt(root, action))

        def symlink(root):
            directory, _ = self.fresh(root, (b"payload",))
            head = directory / "HEAD"; target = root / "old-head"; head.rename(target); head.symlink_to(target)
            with Session(self.image, directory, root / "refused", mode=2) as owner:
                owner.finish(66)
        self.case("reject-symlink-head", symlink)

        def fifo_reference(root, name):
            directory, _ = self.fresh(root, (b"historical payload", b"current payload"))
            target = directory / name
            target.unlink()
            os.mkfifo(target, 0o600)

            def snapshot():
                result = {}
                for path in directory.iterdir():
                    metadata = path.lstat()
                    result[path.name] = {"mode": metadata.st_mode, "uid": metadata.st_uid,
                                         "links": metadata.st_nlink, "size": metadata.st_size,
                                         "inode": metadata.st_ino,
                                         "sha256": digest(path.read_bytes()) if stat.S_ISREG(metadata.st_mode) else None}
                return result

            before = snapshot()
            # With no writer, a blocking read-only open would hang. The owner
            # must reject this actual FIFO promptly with the corruption code.
            with Session(self.image, directory, root / "no-writer", mode=2) as owner:
                row = owner.finish(66)
                assert row["cleanup"] is None and not owner.stdout
            assert snapshot() == before

            reader = os.open(target, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
            writer = None
            marker = b"unconsumed-required-file-FIFO-data:" + bytes(range(256))
            try:
                writer = os.open(target, os.O_WRONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
                assert os.write(writer, marker) == len(marker)
                # A writer makes blocking open succeed. Queued data proves the
                # native type refusal occurs before any read from this FD.
                with Session(self.image, directory, root / "queued-bytes", mode=2) as owner:
                    row = owner.finish(66)
                    assert row["cleanup"] is None and not owner.stdout
                assert os.read(reader, len(marker) + 1) == marker
            finally:
                if writer is not None:
                    os.close(writer)
                os.close(reader)
            assert snapshot() == before
            return {"required_file": name, "actual_type": "FIFO", "exit_code": 66,
                    "no_writer_refused_without_controller_kill": True,
                    "queued_fifo_bytes_untouched": len(marker), "namespace_unchanged": True,
                    "ordinary_file_hard_deadline_claimed": False}

        for name in ("FORMAT", "HEAD", "txn.0000000000000002", "txn.0000000000000001"):
            self.case("reject-required-fifo-" + name,
                      lambda root, name=name: fifo_reference(root, name))

        def namespace(root, kind):
            directory = root / "namespace"; directory.mkdir(mode=0o700)
            if kind == "mode": directory.chmod(0o755)
            else: (directory / kind).write_bytes(b"untouched original bytes")
            with Session(self.image, directory, root / "refused", mode=1) as owner:
                owner.finish(65)
            if kind != "mode": assert (directory / kind).read_bytes() == b"untouched original bytes"
        for kind in ("mode", "native.sqlite", "unrelated"):
            self.case("reject-namespace-" + kind, lambda root, kind=kind: namespace(root, kind))

        def context(root):
            directory, _ = self.fresh(root)
            before = (directory / "HEAD").read_bytes()
            with Session(self.image, directory, root / "refused", mode=2, context=bytes(32)) as owner:
                owner.finish(65)
            assert (directory / "HEAD").read_bytes() == before
        self.case("reject-context", context)

        def locking(root):
            directory, _ = self.fresh(root)
            with Session(self.image, directory, root / "holder", mode=2) as first:
                first.ready()
                with Session(self.image, directory, root / "contender", mode=2) as second:
                    second.finish(67)
                first.commit(b"still exclusive")
                first.close()
        self.case("actual-two-process-lock", locking)

        def wrong_cas(root, part):
            directory, _ = self.fresh(root, (b"original",))
            before = (directory / "HEAD").read_bytes()
            with Session(self.image, directory, root / "refused", mode=2) as owner:
                owner.ready()
                if part == "sequence": owner.request(1, sequence=2, declared=1)
                elif part == "digest": owner.request(1, value=bytes(32), declared=1)
                else: owner.request(1, declared=U64_MAX)
                owner.finish(68 if part == "capacity" else 69)
            assert (directory / "HEAD").read_bytes() == before
        for part in ("sequence", "digest", "capacity"):
            self.case("reject-" + part, lambda root, part=part: wrong_cas(root, part))

        def gate_error(root, tag):
            directory, _ = self.fresh(root, (b"old",))
            with Session(self.image, directory, root / "gate-error", mode=2, gates=True) as owner:
                owner.ready(); owner.request(1, b"new"); owner.pause(tag)
                os.close(owner.go); owner.go = None
                row = owner.finish(71 if tag == 15 else 70)
                assert row["diagnostic"]["uncertain"] == (1 if tag == 15 else 0)
            assert disk_chain(directory)["payload"] == (b"new" if tag == 15 else b"old")
            return {"actual_failure": "explicit gate input EOF", "filesystem_eio_injected": False,
                    "commit_unknown": tag == 15}
        for tag in (14, 15):
            self.case("gate-io-error-" + str(tag), lambda root, tag=tag: gate_error(root, tag))

        def lost_receipt(root):
            payload = b"committed despite an undeliverable response"
            directory, prior = self.fresh(root, (b"previously acknowledged",))
            with Session(self.image, directory, root / "closed-stdout", mode=2) as owner:
                owner.ready()
                # Close the real receiving pipe after READY, before COMMIT.
                # The native owner must observe EPIPE on its durable receipt.
                owner.process.stdout.close()
                owner.process.stdout = None
                owner.request(1, payload)
                row = owner.finish(70)
                assert row["diagnostic"]["syscall_result_bits"] == U64_MAX - 31  # -EPIPE
                assert row["diagnostic"]["uncertain"] == 0
                assert row["diagnostic"]["private_committed_sequence"] == prior["sequence"] + 1
                assert len(owner.stdout) == 64  # READY only; no COMMIT receipt.
            oracle = disk_chain(directory)
            assert oracle["sequence"] == prior["sequence"] + 1 and oracle["payload"] == payload
            with Session(self.image, directory, root / "recovered", mode=2) as owner:
                assert owner.ready()["digest"] == oracle["digest"]
                assert owner.get() == payload
                owner.close()
            return {"actual_errno": "EPIPE", "commit_receipt_delivered": False,
                    "recovered_sequence": oracle["sequence"], "code_70_implies_rollback": False}
        self.case("actual-lost-durable-receipt", lost_receipt)

        def limited(root):
            directory, _ = self.fresh(root, (b"durable old",))
            with Session(self.image, directory, root / "limited", mode=2, file_limit=65536) as owner:
                owner.ready()
                try:
                    owner.request(1, bytes(131072))
                except BrokenPipeError:
                    pass
                row = owner.finish(70)
                assert row["diagnostic"]["syscall_result_bits"] == U64_MAX - 26  # -EFBIG
            assert disk_chain(directory)["payload"] == b"durable old"
            with Session(self.image, directory, root / "recovered", mode=2) as owner:
                owner.ready(); owner.commit(b"after file limit"); owner.close()
            return {"real_rlimit_fsize": 65536, "actual_errno": "EFBIG", "enospc_claimed": False}
        self.case("actual-file-size-limit", limited)

        def partial(root):
            directory = root / "namespace"; directory.mkdir(mode=0o700)
            with Session(self.image, directory, root / "partial", mode=1, bootstrap=False) as owner:
                first = owner.wait_read(80)
                owner.write(owner.bootstrap[:1]); second = owner.wait_read(79)
                owner.write(owner.bootstrap[1:3]); third = owner.wait_read(77)
                owner.write(owner.bootstrap[3:]); owner.ready(); owner.commit(b"partial input works"); owner.close()
            assert int(second["raw"].split()[2], 0) == int(first["raw"].split()[2], 0) + 1
            assert int(third["raw"].split()[2], 0) == int(first["raw"].split()[2], 0) + 3
            return {"actual_pending_read_lengths": [80, 79, 77], "native_pointer_progress": [0, 1, 3]}
        self.case("actual-short-stdin-reads", partial)

        def interrupted(root):
            directory = root / "namespace"; directory.mkdir(mode=0o700)
            with Session(self.image, directory, root / "eintr", mode=1, gates=True, bootstrap=False) as owner:
                owner.wait_read(80)
                status = Path(f"/proc/{owner.process.pid}/status").read_text()
                caught = next(line.split()[1] for line in status.splitlines() if line.startswith("SigCgt:"))
                assert int(caught, 16) & (1 << (signal.SIGUSR1 - 1))
                fd = os.pidfd_open(owner.process.pid)
                try: signal.pidfd_send_signal(fd, signal.SIGUSR1)
                finally: os.close(fd)
                owner.wait_read(80)
                owner.write(owner.bootstrap); owner.ready(); owner.close()
                assert owner.gate_records[-1]["eintr_results"] >= 1
            return {"actual_signal": "SIGUSR1", "actual_handler_observed": True, "continued_native_read": True}
        self.case("actual-eintr", interrupted)

        self.builder.check_pin()
        trace = self.trace()
        self.builder.check_pin()
        report = {"schema": "trnm.hia.storage-qualification.v1",
                  "status": "PASS" if all(row["status"] == "PASS" for row in self.results) else "FAIL",
                  "scope": "bounded generic transaction payload StoreOwner; not typed Node integration",
                  "build": self.build, "controls": self.results,
                  "passed": sum(row["status"] == "PASS" for row in self.results), "total": len(self.results),
                  "syscall_trace": trace,
                  "not_qualified": ["physical power loss", "regular-file/fsync hard deadline", "ENOSPC", "filesystem EIO",
                                    "network filesystems", "hostile same-UID mutation", "whole-directory rollback",
                                    "4096-commit exhaustion", "automatic incomplete initialization repair", "compaction", "full State limit", "whole Node", "cross-target", "original service budget"],
                  "runtime_proxy": False, "old_stack_retirement_authorized": False}
        write_json(self.output / "report.json", report)
        return report

    def trace(self) -> dict:
        root = self.output / "syscall-trace"; root.mkdir(mode=0o700)
        tool = shutil.which("strace")
        if tool is None:
            row = {"status": "NOT_RUN", "reason": "strace unavailable", "executable_sha256": digest(self.image)}
            write_json(root / "result.json", row)
            return row
        directory = root / "namespace"; directory.mkdir(mode=0o700)
        d = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        f = sealed_executable(self.image, "storage-trace")
        raw = BOOT.pack(b"HIAST001", d, 1, CONTEXT, U64_MAX, U64_MAX, 0)
        raw += RECORD.pack(b"HIACMD01", 3, 0, 0, genesis())
        try:
            process = subprocess.Popen([tool, "-f", "-qq", "-o", str(root / "trace.txt"), "/proc/self/fd/" + str(f)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=(d, f),
                env={"PATH": ""}, cwd=root, start_new_session=True, umask=0o077)
        finally:
            os.close(d); os.close(f)
        cleanup = None
        try:
            stdout, stderr = process.communicate(raw, timeout=10)
        except subprocess.TimeoutExpired:
            try: os.killpg(process.pid, signal.SIGKILL); outcome = "sent"
            except ProcessLookupError: outcome = "already_exited"
            stdout, stderr = process.communicate(timeout=CLEANUP)
            cleanup = {"signal": "SIGKILL", "signal_outcome": outcome, "complete": process.returncode is not None}
        denied = b"Operation not permitted" in stderr or b"PTRACE" in stderr and b"permitted" in stderr
        row = {"status": "UNKNOWN" if denied else "PASS" if process.returncode == 0 and cleanup is None else "FAIL",
               "exit_code": process.returncode, "stderr": stderr.decode(errors="replace"),
               "reason": "PTRACE_EPERM" if denied else "actual trace invocation", "cleanup": cleanup,
               "executable_sha256": digest(self.image), "stdout_sha256": digest(stdout)}
        (root / "stdin.raw").write_bytes(raw); (root / "stdout.raw").write_bytes(stdout); (root / "stderr.raw").write_bytes(stderr)
        write_json(root / "result.json", row)
        return row


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = new_output(args.output)
    report = Qualification(output).run()
    print(json.dumps({"status": report["status"], "passed": report["passed"], "total": report["total"],
                      "trace": report["syscall_trace"]["status"], "report": str(output / "report.json")}))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
