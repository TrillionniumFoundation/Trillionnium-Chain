"""Bounded stdin writes against real pipes, with explicit deadline fault controls.

Run with python3 -B -m unittest -v hia.platform.mempool_node.test_io_deadline.
These fixtures use short local deadlines; the native qualification's 240-second
process deadline and 3-second cleanup budget are unchanged.
"""
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
import errno
import fcntl
import hashlib
import json
import os
import select
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from . import suite_smoke as suite


class WriteDeadline(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="node-pool-io-deadline-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.cleanup_errors = []
        patcher = mock.patch.object(suite, "cleanup_errors", self.cleanup_errors, create=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def child(self, reads=False):
        script = "import os,time; os.write(1,b'R'); time.sleep(30)"
        if reads:
            script = """import hashlib,json,os,time
os.write(1,b'R')
digest=hashlib.sha256(); count=0
while True:
    block=os.read(0,4096)
    if not block: break
    digest.update(block); count+=len(block); time.sleep(0.0005)
os.write(1,json.dumps({"bytes":count,"sha256":digest.hexdigest()}).encode())
"""
        session = suite.Session.__new__(suite.Session)
        session.directory = self.directory / "process"
        session.directory.mkdir()
        session.owned = session.directory
        session.frames = []
        session.input = bytearray()
        session.output = bytearray()
        session.finished = False
        session.argv = [sys.executable, "-B", "-c", script]
        session.p = subprocess.Popen(
            session.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=True,
        )
        self.addCleanup(session.abort)
        self.assertTrue(select.select([session.p.stdout], [], [], 3)[0], "Child readiness")
        self.assertEqual(os.read(session.p.stdout.fileno(), 1), b"R")
        session.started = time.monotonic()
        session.deadline = session.started + 5
        return session

    @staticmethod
    def payload(session):
        capacity = fcntl.fcntl(session.p.stdin.fileno(), fcntl.F_GETPIPE_SZ)
        size = capacity * 4 + 37
        raw = (bytes(range(251)) * ((size + 250) // 251))[:size]
        return raw, capacity

    def bounded_write(self, session, raw, watchdog=2):
        result = {}

        def run():
            started = time.monotonic()
            try:
                session.write(raw)
            except BaseException as error:
                result["error"] = error
            finally:
                result["elapsed_seconds"] = time.monotonic() - started

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        worker.join(watchdog)
        missed = worker.is_alive()
        if missed and session.p.poll() is None:
            os.killpg(session.p.pid, signal.SIGKILL)
        if missed:
            worker.join(3)
        self.assertFalse(worker.is_alive(), "Write remained blocked after owned child cleanup")
        self.assertFalse(missed, "Session.write crossed the external watchdog")
        return result

    def finish_reader(self, session, raw):
        session.p.stdin.close()
        session.p.stdin = None
        stdout, stderr = session.p.communicate(timeout=3)
        session.finished = True
        self.assertEqual(session.p.returncode, 0)
        self.assertEqual(stderr, b"")
        self.assertEqual(json.loads(stdout), {
            "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
        })
        self.assertEqual(bytes(session.input), raw)

    @contextmanager
    def pipe_session(self):
        read_fd, write_fd = os.pipe()
        writer = os.fdopen(write_fd, "wb", buffering=0)
        session = suite.Session.__new__(suite.Session)
        session.p = SimpleNamespace(stdin=writer)
        session.input = bytearray()
        session.deadline = 1.0
        try:
            yield session, read_fd, write_fd
        finally:
            writer.close()
            os.close(read_fd)

    def test_nonreading_child_large_write_hits_deadline_and_cleans_up(self):
        session = self.child()
        raw, capacity = self.payload(session)
        session.deadline = time.monotonic() + 0.2
        result = self.bounded_write(session, raw)
        self.assertIsInstance(result.get("error"), AssertionError)
        self.assertEqual(str(result["error"]), "Native stdin deadline")
        self.assertGreater(len(raw), capacity)
        self.assertEqual(bytes(session.input), raw)
        self.assertIsNone(session.p.poll())
        self.assertFalse(os.get_blocking(session.p.stdin.fileno()))
        with mock.patch.object(session.p, "communicate", wraps=session.p.communicate) as communicate:
            session.abort()
            session.abort()
        communicate.assert_called_once_with(timeout=3)
        self.assertEqual(session.p.returncode, -signal.SIGKILL)
        self.assertTrue(session.finished)
        self.assertEqual(self.cleanup_errors, [])
        self.assertEqual((session.directory / "stdin.raw").read_bytes(), raw)
        receipt = json.loads((session.directory / "failure-receipt.json").read_text())
        self.assertEqual(receipt["exit_code"], -signal.SIGKILL)
        print(json.dumps({
            "control": "nonreading-child", "status": "PASS",
            "pipe_capacity_bytes": capacity, "input_bytes": len(raw),
            "fixture_deadline_seconds": 0.2,
            "observed_seconds": result["elapsed_seconds"],
            "cleanup_timeout_seconds": 3, "exit_code": session.p.returncode,
        }, sort_keys=True), flush=True)

    def test_complete_large_write_matches_real_reader_bytes(self):
        session = self.child(reads=True)
        raw, _ = self.payload(session)
        result = self.bounded_write(session, raw)
        self.assertNotIn("error", result)
        self.finish_reader(session, raw)

    def test_short_writes_eagain_and_eintr_preserve_complete_input(self):
        session = self.child(reads=True)
        raw, _ = self.payload(session)
        original_write = os.write
        calls = []

        def short_write(fd, value):
            calls.append(len(value))
            if len(calls) == 1:
                raise BlockingIOError(errno.EAGAIN, "injected full pipe")
            if len(calls) == 2:
                raise InterruptedError(errno.EINTR, "injected interrupted write")
            return original_write(fd, value[:1021])

        with mock.patch.object(suite.os, "write", side_effect=short_write):
            result = self.bounded_write(session, raw)
        self.assertNotIn("error", result)
        self.assertGreater(len(calls), 3)
        self.assertEqual(calls[:3], [len(raw)] * 3)
        self.finish_reader(session, raw)

    def test_interrupted_select_retries_with_remaining_absolute_time(self):
        with self.pipe_session() as (session, read_fd, write_fd):
            with mock.patch.object(suite.time, "monotonic", side_effect=[0.1, 0.2, 0.3]):
                with mock.patch.object(suite.select, "select", side_effect=[
                    InterruptedError(errno.EINTR, "injected interrupted select"),
                    ([], [write_fd], []),
                ]) as wait:
                    session.write(b"complete")
            self.assertEqual(os.read(read_fd, 8), b"complete")
            self.assertEqual(wait.call_count, 2)
            self.assertAlmostEqual(wait.call_args_list[0].args[3], 0.9)
            self.assertAlmostEqual(wait.call_args_list[1].args[3], 0.8)

    def test_expired_deadline_does_not_select_or_write(self):
        with self.pipe_session() as (session, _, __):
            with mock.patch.object(suite.time, "monotonic", return_value=1.0):
                with mock.patch.object(suite.select, "select") as wait:
                    with mock.patch.object(suite.os, "write") as write:
                        with self.assertRaisesRegex(AssertionError, "Native stdin deadline"):
                            session.write(b"expired")
            wait.assert_not_called()
            write.assert_not_called()
            self.assertEqual(session.input, b"expired")

    def test_readiness_at_deadline_does_not_write(self):
        with self.pipe_session() as (session, _, write_fd):
            with mock.patch.object(suite.time, "monotonic", side_effect=[0.9, 1.0]):
                with mock.patch.object(suite.select, "select", return_value=([], [write_fd], [])):
                    with mock.patch.object(suite.os, "write") as write:
                        with self.assertRaisesRegex(AssertionError, "Native stdin deadline"):
                            session.write(b"too-late")
            write.assert_not_called()

    def test_repeated_eagain_does_not_reset_deadline(self):
        with self.pipe_session() as (session, _, write_fd):
            with mock.patch.object(suite.time, "monotonic", side_effect=[0.1, 0.2, 0.3, 0.4, 1.0]):
                with mock.patch.object(suite.select, "select", return_value=([], [write_fd], [])) as wait:
                    with mock.patch.object(suite.os, "write", side_effect=BlockingIOError(errno.EAGAIN, "full")) as write:
                        with self.assertRaisesRegex(AssertionError, "Native stdin deadline"):
                            session.write(b"unchanged")
            self.assertEqual(write.call_count, 2)
            self.assertEqual(wait.call_count, 2)
            self.assertAlmostEqual(wait.call_args_list[0].args[3], 0.9)
            self.assertAlmostEqual(wait.call_args_list[1].args[3], 0.7)
            self.assertEqual(session.input, b"unchanged")

    def test_zero_progress_and_broken_pipe_are_not_retried(self):
        for result, expected in ((0, AssertionError), (BrokenPipeError(errno.EPIPE, "closed"), BrokenPipeError)):
            with self.subTest(result=repr(result)):
                with self.pipe_session() as (session, _, write_fd):
                    behavior = {"side_effect": result} if isinstance(result, BaseException) else {"return_value": result}
                    with mock.patch.object(suite.time, "monotonic", return_value=0.5):
                        with mock.patch.object(suite.select, "select", return_value=([], [write_fd], [])):
                            with mock.patch.object(suite.os, "write", **behavior) as write:
                                with self.assertRaises(expected):
                                    session.write(b"refused")
                    write.assert_called_once()

    def test_cleanup_after_expired_deadline_keeps_three_second_budget(self):
        session = self.child()
        session.deadline = session.started - 1
        with mock.patch.object(session.p, "communicate", wraps=session.p.communicate) as communicate:
            session.abort()
            session.abort()
        communicate.assert_called_once_with(timeout=3)
        self.assertEqual(session.p.returncode, -signal.SIGKILL)
        self.assertTrue(session.finished)
        self.assertEqual(self.cleanup_errors, [])

    def test_cleanup_timeout_is_preserved_as_failure(self):
        session = self.child()
        error = subprocess.TimeoutExpired(session.argv, 3)
        with mock.patch.object(session.p, "communicate", side_effect=error) as communicate:
            session.abort()
        communicate.assert_called_once_with(timeout=3)
        self.assertFalse(session.finished)
        self.assertEqual(len(self.cleanup_errors), 1)
        self.assertIn("TimeoutExpired", self.cleanup_errors[0]["error"])
        # The fault was injected only into observation; reap the real owned child.
        session.abort()
        self.assertTrue(session.finished)
        self.assertEqual(session.p.returncode, -signal.SIGKILL)


if __name__ == "__main__":
    unittest.main()
