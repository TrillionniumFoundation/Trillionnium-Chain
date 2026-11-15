"""Hosted reactor driver cleanup races; not native I/O or trace qualification.

The witness child really exits and produces its output before the controlled
TimeoutExpired/ESRCH event. EPERM remains an error. No sleep estimates readiness.
"""
import errno
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hia.platform.reactor import qualify
from hia.tests.test_platform_cleanup import (
    CHILD_EXIT, CHILD_INPUT, CHILD_STDERR, CHILD_STDOUT, TimeoutAfterActualExit,
)


class ReactorCleanupTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="trnm-reactor-cleanup-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.shell_image = Path("/bin/sh").resolve(strict=True).read_bytes()
        self.tracer_fixture = self.root / "tracer-fixture"
        self.tracer_fixture.write_bytes(b"#!/bin/sh\n" + CHILD_INPUT)
        self.tracer_fixture.chmod(0o500)

    def trace_race(self, error, refusal=False):
        injected = TimeoutAfterActualExit(error)
        suite = object.__new__(qualify.Suite)
        suite.output = self.root
        suite.elf = self.shell_image
        with patch.object(subprocess, "Popen", injected.popen), \
                patch.object(os, "killpg", injected.killpg), \
                patch.object(qualify.shutil, "which", return_value=str(self.tracer_fixture)):
            if refusal:
                with self.assertRaises(PermissionError) as caught:
                    suite.trace()
                self.assertEqual(caught.exception.errno, errno.EPERM)
            else:
                row = suite.trace()
                self.assertTrue(row["timed_out"])
                self.assertEqual(row["exit_code"], CHILD_EXIT)
                self.assertTrue(row["cleanup"]["complete"])
                self.assertEqual(row["cleanup"]["signal_outcome"], "already_exited")
                self.assertEqual(row["status"], "UNKNOWN")
                self.assertEqual(bytes.fromhex(row["stdout_hex"]), CHILD_STDOUT)
                self.assertEqual(bytes.fromhex(row["stderr_hex"]), CHILD_STDERR)
                self.assertEqual((self.root / "syscall-trace/stdout.raw").read_bytes(), CHILD_STDOUT)
                self.assertEqual((self.root / "syscall-trace/stderr.raw").read_bytes(), CHILD_STDERR)
                self.assertEqual(json.loads((self.root / "syscall-trace/result.json").read_text()), row)
        self.assertEqual(injected.child.returncode, CHILD_EXIT)
        self.assertEqual(injected.raw, (CHILD_STDOUT, CHILD_STDERR))

    def test_trace_esrch_preserves_actual_exit_timeout_and_raw_receipt(self):
        self.trace_race(ProcessLookupError(errno.ESRCH, "actual child already exited"))

    def test_trace_eperm_propagates(self):
        self.trace_race(PermissionError(errno.EPERM, "permission denied"), refusal=True)

    def child_race(self, error, refusal=False):
        owner = qualify.Child(self.root, self.shell_image, args=[])
        raw = owner.p.communicate(CHILD_INPUT, timeout=5)
        owner.input = CHILD_INPUT
        self.assertEqual(raw, (CHILD_STDOUT, CHILD_STDERR))
        self.assertEqual(owner.p.returncode, CHILD_EXIT)
        real_communicate = owner.p.communicate
        calls = []

        def timeout_once(*args, **kwargs):
            calls.append(kwargs.get("timeout"))
            if len(calls) == 1:
                raise subprocess.TimeoutExpired(owner.p.args, 1, output=raw[0], stderr=raw[1])
            return real_communicate(*args, **kwargs)

        def signal_after_exit(fd, number):
            self.assertEqual(fd, owner.pidfd)
            self.assertEqual(number, signal.SIGKILL)
            self.assertEqual(owner.p.returncode, CHILD_EXIT)
            raise error

        with patch.object(owner.p, "communicate", timeout_once), \
                patch.object(signal, "pidfd_send_signal", signal_after_exit):
            if refusal:
                with self.assertRaises(PermissionError) as caught:
                    owner.__exit__(None, None, None)
                self.assertEqual(caught.exception.errno, errno.EPERM)
            else:
                owner.__exit__(None, None, None)
        row = json.loads((self.root / "cleanup.json").read_text())
        self.assertEqual(row["exit_code"], CHILD_EXIT)
        self.assertTrue(row["complete"])
        self.assertTrue(row["external_cleanup_used"])
        self.assertFalse(row["counts_as_native_deadline_success"])
        self.assertEqual((self.root / "cleanup.stdout.raw").read_bytes(), CHILD_STDOUT)
        self.assertEqual((self.root / "cleanup.stderr.raw").read_bytes(), CHILD_STDERR)
        if refusal:
            self.assertIn("PermissionError", row["exception"])
            self.assertEqual(calls, [1])
        else:
            self.assertIsNone(row["exception"])
            self.assertEqual(row["actions"], ["ALREADY_EXITED_BEFORE_SIGKILL"])
            self.assertEqual(calls, [1, 2])

    def test_child_esrch_preserves_reaped_output_and_cleanup_receipt(self):
        self.child_race(ProcessLookupError(errno.ESRCH, "actual child already exited"))

    def test_child_eperm_propagates_and_records_failure(self):
        self.child_race(PermissionError(errno.EPERM, "permission denied"), refusal=True)


if __name__ == "__main__":
    unittest.main()
