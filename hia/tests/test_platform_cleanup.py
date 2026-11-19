"""Deterministic hosted cleanup regressions, separate from native OS controls.

Each real child emits known stdout/stderr and exits before TimeoutExpired is
injected. ESRCH then models the cleanup/exit race; EPERM must still propagate.
The short-lived shell and tracer-shaped shell fixture are test witnesses only.
These tests do not qualify the HIA runtime, syscall instrumentation or deadlines.
"""
from __future__ import annotations

import errno
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hia.platform import build
from hia.tools import qualify_platform

CHILD_INPUT = b"printf 'cleanup-stdout\\n'; printf 'cleanup-stderr\\n' >&2; exit 23\n"
CHILD_STDOUT = b"cleanup-stdout\n"
CHILD_STDERR = b"cleanup-stderr\n"
CHILD_EXIT = 23


class TimeoutAfterActualExit:
    """Inject a timeout only after real communicate/reap has finished."""
    def __init__(self, error):
        self.error = error
        self.real_popen = subprocess.Popen
        self.child = None
        self.raw = None
        self.communicate_calls = 0

    def popen(self, *args, **kwargs):
        child = self.real_popen(*args, **kwargs)
        self.child = child
        communicate = child.communicate

        def observed_timeout(*args, **kwargs):
            self.communicate_calls += 1
            if self.communicate_calls == 1:
                self.raw = communicate(*args, **kwargs)
                if child.returncode is None:
                    raise AssertionError("Race injection requires an actually exited child")
                raise subprocess.TimeoutExpired(child.args, kwargs.get("timeout"),
                    output=self.raw[0], stderr=self.raw[1])
            return communicate(*args, **kwargs)

        child.communicate = observed_timeout
        return child

    def killpg(self, pid, number):
        if (self.child is None or self.child.pid != pid
                or self.child.returncode is None or number != signal.SIGKILL):
            raise AssertionError("Cleanup injection must target the exited owned child")
        raise self.error


class PlatformCleanupTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="trnm-platform-cleanup-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        # This is an explicitly hosted cleanup witness, not a native HIA build.
        self.shell_image = Path("/bin/sh").resolve(strict=True).read_bytes()
        self.tracer_fixture = self.root / "tracer-fixture"
        self.tracer_fixture.write_bytes(b"#!/bin/sh\n" + CHILD_INPUT)
        self.tracer_fixture.chmod(0o500)

    def injection(self, error):
        injected = TimeoutAfterActualExit(error)
        self.addCleanup(lambda: self.assertIsNotNone(injected.child.returncode)
                        if injected.child is not None else None)
        return injected

    def assert_real_output(self, injected):
        self.assertEqual(injected.child.returncode, CHILD_EXIT)
        self.assertEqual(injected.raw, (CHILD_STDOUT, CHILD_STDERR))

    def test_run_native_esrch_retains_timeout_exit_raw_and_receipt(self):
        injected = self.injection(ProcessLookupError(errno.ESRCH, "exited child"))
        with patch.object(subprocess, "Popen", injected.popen), \
                patch.object(os, "killpg", injected.killpg):
            stdout, receipt = build.run_native(self.shell_image, CHILD_INPUT, self.root, "stage")
        self.assert_real_output(injected)
        self.assertEqual(injected.communicate_calls, 2)
        self.assertTrue(receipt["timed_out"])
        self.assertEqual(receipt["exit_code"], CHILD_EXIT)
        self.assertEqual(receipt["cleanup"]["signal_outcome"], "already_exited")
        self.assertTrue(receipt["cleanup"]["complete"])
        self.assertEqual(stdout, CHILD_STDOUT)
        self.assertEqual((self.root / "stage/stdout.raw").read_bytes(), CHILD_STDOUT)
        self.assertEqual((self.root / "stage/stderr.raw").read_bytes(), CHILD_STDERR)
        self.assertEqual((self.root / "stage/stdin.raw").read_bytes(), CHILD_INPUT)
        self.assertEqual(json.loads((self.root / "stage/receipt.json").read_text()), receipt)
        with self.assertRaises(RuntimeError):
            build.require_success(receipt)

    def test_run_native_permission_error_is_not_swallowed(self):
        injected = self.injection(PermissionError(errno.EPERM, "permission denied"))
        with patch.object(subprocess, "Popen", injected.popen), \
                patch.object(os, "killpg", injected.killpg):
            with self.assertRaises(PermissionError) as caught:
                build.run_native(self.shell_image, CHILD_INPUT, self.root, "stage")
        self.assertEqual(caught.exception.errno, errno.EPERM)
        self.assert_real_output(injected)
        self.assertEqual(injected.communicate_calls, 1)

    def trace(self):
        qualification = object.__new__(qualify_platform.Qualification)
        qualification.output = self.root
        qualification.build = SimpleNamespace(executable=self.shell_image)
        return qualification.trace()

    def test_trace_esrch_retains_timeout_exit_raw_and_receipt(self):
        injected = self.injection(ProcessLookupError(errno.ESRCH, "exited child"))
        with patch.object(subprocess, "Popen", injected.popen), \
                patch.object(os, "killpg", injected.killpg), \
                patch.object(qualify_platform.shutil, "which", return_value=str(self.tracer_fixture)):
            receipt = self.trace()
        self.assert_real_output(injected)
        self.assertEqual(injected.communicate_calls, 2)
        self.assertTrue(receipt["timed_out"])
        self.assertEqual(receipt["exit_code"], CHILD_EXIT)
        self.assertEqual(receipt["cleanup"]["signal_outcome"], "already_exited")
        self.assertTrue(receipt["cleanup"]["complete"])
        self.assertEqual(receipt["status"], "UNKNOWN")
        self.assertEqual((self.root / "syscall-trace/stdout.raw").read_bytes(), CHILD_STDOUT)
        self.assertEqual((self.root / "syscall-trace/stderr.raw").read_bytes(), CHILD_STDERR)
        self.assertEqual(json.loads((self.root / "syscall-trace/result.json").read_text()), receipt)

    def test_trace_permission_error_is_not_swallowed(self):
        injected = self.injection(PermissionError(errno.EPERM, "permission denied"))
        with patch.object(subprocess, "Popen", injected.popen), \
                patch.object(os, "killpg", injected.killpg), \
                patch.object(qualify_platform.shutil, "which", return_value=str(self.tracer_fixture)):
            with self.assertRaises(PermissionError) as caught:
                self.trace()
        self.assertEqual(caught.exception.errno, errno.EPERM)
        self.assert_real_output(injected)
        self.assertEqual(injected.communicate_calls, 1)

    def owned_cleanup(self, error, expect_error):
        with qualify_platform.Owned(self.root, self.shell_image) as owner:
            raw = owner.process.communicate(CHILD_INPUT, timeout=5)
            self.assertEqual(raw, (CHILD_STDOUT, CHILD_STDERR))
            self.assertEqual(owner.process.returncode, CHILD_EXIT)
            communicate = owner.process.communicate
            calls = []

            def observed_timeout(*args, **kwargs):
                calls.append(kwargs.get("timeout"))
                if len(calls) == 1:
                    raise subprocess.TimeoutExpired(owner.process.args, 1,
                        output=raw[0], stderr=raw[1])
                return communicate(*args, **kwargs)

            with patch.object(owner.process, "communicate", observed_timeout), \
                    patch.object(owner, "signal", side_effect=error):
                if expect_error:
                    with self.assertRaises(PermissionError) as caught:
                        owner.cleanup()
                    self.assertEqual(caught.exception.errno, errno.EPERM)
                    self.assertEqual(len(calls), 1)
                else:
                    result = owner.cleanup()
                    self.assertEqual(len(calls), 2)
                    self.assertEqual(result, raw)
                    self.assertEqual(owner.cleanup_record["exit_code"], CHILD_EXIT)
                    self.assertTrue(owner.cleanup_record["complete"])
                    self.assertEqual(owner.cleanup_record["signals"], [])
                    self.assertEqual(owner.cleanup_record["already_exited_before_signal"], ["SIGKILL"])
                    self.assertEqual((self.root / "stdout.raw").read_bytes(), CHILD_STDOUT)
                    self.assertEqual((self.root / "stderr.raw").read_bytes(), CHILD_STDERR)
                    self.assertEqual(json.loads((self.root / "cleanup.json").read_text()),
                                     owner.cleanup_record)

    def test_owned_cleanup_esrch_retains_exit_raw_and_receipt(self):
        self.owned_cleanup(ProcessLookupError(errno.ESRCH, "exited child"), False)

    def test_owned_cleanup_permission_error_is_not_swallowed(self):
        self.owned_cleanup(PermissionError(errno.EPERM, "permission denied"), True)


if __name__ == "__main__":
    unittest.main()
