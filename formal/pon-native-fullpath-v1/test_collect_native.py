"""Process-lifecycle regressions; synthetic children make no native-work claim."""
import contextlib
import ctypes
import errno
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "native_fullpath_collector", Path(__file__).with_name("collect_native.py"))
driver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(driver)

TERMINATE_ZERO = (
    "import json,signal,sys,time; "
    "signal.signal(signal.SIGTERM, lambda *_: sys.exit(0)); "
    "print(json.dumps({'event':'produce_complete'}), flush=True); time.sleep(30)"
)


class UnreapedProcess:
    """No OS process exists: fault injection exercises an unconfirmed wait."""
    pid = 999_999_999
    returncode = None
    stdin = None

    def __init__(self):
        self.stdout = io.BytesIO(b'{"event":"produce_complete"}\n')

    def wait(self, timeout=None):
        raise subprocess.TimeoutExpired("injected-unreaped-owner", timeout)

    def poll(self):
        return None


class CollectorLifecycleTests(unittest.TestCase):
    def collector(self, root):
        return driver.Collector(Path(sys.executable), root, time.monotonic_ns(), 1)

    def assert_terminal(self, root, row):
        retained = json.loads((root / (row["id"] + ".process.json")).read_text())
        self.assertEqual(retained, row)
        self.assertLessEqual(row["start_ns"], row["end_ns"])
        self.assertTrue(all(row["start_ns"] <= e["at_ns"] <= row["end_ns"]
                            for e in row["events"]))

    def test_timeout_exit_zero_is_not_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collector = self.collector(root)
            row = collector.run("timeout-zero", ["-u", "-c", TERMINATE_ZERO])
            self.assertTrue(row["timed_out"])
            self.assertEqual(row["exit_code"], 0)
            self.assertTrue(row["process_reaped"])
            self.assertTrue(row["process_group_resolved"])
            self.assertFalse(row["owner_unresolved"])
            self.assertEqual(len(row["events"]), 1)
            self.assertIsNone(driver.final_event(row, "produce_complete"))
            self.assert_terminal(root, row)

    def test_process_lookup_race_still_waits_and_retains_the_row(self):
        actual_killpg = os.killpg

        def exit_during_signal(pid, sig):
            actual_killpg(pid, sig)
            if sig == signal.SIGTERM:
                raise ProcessLookupError(errno.ESRCH, "injected exit/signal race")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(driver.os, "killpg", side_effect=exit_during_signal):
                row = self.collector(root).run("lookup-race", ["-u", "-c", TERMINATE_ZERO])
            self.assertTrue(row["process_reaped"])
            self.assertEqual(row["exit_code"], 0)
            self.assertFalse(row["owner_unresolved"])
            self.assertTrue(any("ProcessLookupError" in note for note in row["cleanup_notes"]))
            self.assertIsNone(driver.final_event(row, "produce_complete"))
            self.assert_terminal(root, row)

    def test_incomplete_stdin_does_not_promote_a_zero_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            row = self.collector(root).run("closed-input", ["-u", "-c",
                "print('{\"event\":\"produce_complete\"}', flush=True)"], b"x" * driver.MAX_PACKET)
            self.assertEqual(row["exit_code"], 0)
            self.assertTrue(row["feeder_errors"])
            self.assertLess(row["stdin_bytes_written"], driver.MAX_PACKET)
            self.assertIsNone(driver.final_event(row, "produce_complete"))
            self.assert_terminal(root, row)

    def test_complete_event_cannot_hide_error_on_either_stream(self):
        for stream in (None, "stdout", "stderr"):
            with self.subTest(stream=stream), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                program = "import sys; print('{\"event\":\"produce_complete\"}', flush=True)"
                if stream:
                    program += f"; print('{{\"event\":\"error\",\"status\":\"error\"}}', file=sys.{stream}, flush=True)"
                row = self.collector(root).run("mixed", ["-u", "-c", program])
                self.assertEqual(row["exit_code"], 0)
                self.assertFalse(row["timed_out"])
                self.assertTrue(row["process_reaped"])
                self.assertEqual(driver.final_event(row, "produce_complete") is not None, stream is None)
                self.assertEqual(row["stderr_error_event"], stream == "stderr")
                self.assert_terminal(root, row)

    @unittest.skipUnless(sys.platform == "linux", "Linux process groups/subreaper fixture")
    def test_exited_leader_with_inherited_pipe_keeps_evidence_and_stops_dispatch(self):
        # Adopt the real grandchild in this test process, so even its zombie is
        # reaped here rather than relying on a container's PID 1 cleanup policy.
        libc = ctypes.CDLL(None, use_errno=True)
        previous = ctypes.c_int()
        if libc.prctl(37, ctypes.byref(previous), 0, 0, 0) != 0:
            self.skipTest("PR_GET_CHILD_SUBREAPER unavailable")
        if libc.prctl(36, 1, 0, 0, 0) != 0:
            self.skipTest("PR_SET_CHILD_SUBREAPER unavailable")
        descendant = None
        pid_file = tempfile.NamedTemporaryFile(prefix="fullpath-descendant-", delete=False)
        pid_path = Path(pid_file.name)
        pid_file.close()
        try:
            program = (
                "import json,os,time\npid=os.fork()\n"
                "if pid == 0:\n time.sleep(30)\n os._exit(0)\n"
                f"open({str(pid_path)!r}, 'w').write(str(pid))\n"
                "print(json.dumps({'event':'produce_complete','descendant_pid':pid}), flush=True)\n"
                "os._exit(0)\n"
            )
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                collector = self.collector(root)
                with patch.object(driver, "CLEANUP_TIMEOUT", 0.05):
                    row = collector.run("inherited-pipe", ["-u", "-c", program])
                descendant = row["events"][0]["value"]["descendant_pid"]
                self.assertEqual(row["exit_code"], 0)
                self.assertTrue(row["process_reaped"])
                self.assertTrue(row["cleanup_attempted"])
                self.assertTrue(row["pipes_resolved"])
                self.assertTrue(row["owner_unresolved"], "the unreaped adopted zombie still owns its group")
                self.assertIsNone(driver.final_event(row, "produce_complete"))
                blocked = collector.run("blocked-after-descendant", ["-c", "raise SystemExit(99)"])
                self.assertFalse(blocked["process_started"])
                self.assertEqual(blocked["dispatch_blocked_by"], "inherited-pipe")
                self.assert_terminal(root, row)
                self.assert_terminal(root, blocked)
        finally:
            try:
                # Also clean up if a regression raises before returning its row.
                if descendant is None and pid_path.read_text().strip():
                    descendant = int(pid_path.read_text())
                if descendant is not None:
                    try:
                        os.kill(descendant, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    until = time.monotonic() + 2
                    while os.waitpid(descendant, os.WNOHANG)[0] == 0:
                        if time.monotonic() >= until:
                            self.fail("test descendant did not become reapable after SIGKILL")
                        time.sleep(0.01)
            finally:
                pid_path.unlink()
                self.assertEqual(libc.prctl(36, previous.value, 0, 0, 0), 0)

    def test_cleanup_failure_never_invents_reap_and_blocks_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collector = self.collector(root)
            with (patch.object(driver.subprocess, "Popen", return_value=UnreapedProcess()) as launch,
                  patch.object(driver.os, "killpg", side_effect=PermissionError("injected cleanup refusal")),
                  patch.object(driver, "CLEANUP_TIMEOUT", 0.01)):
                row = collector.run("unresolved", [])
                blocked = collector.run("must-not-start", [])
            self.assertEqual(launch.call_count, 1)
            self.assertIsNone(row["exit_code"])
            self.assertFalse(row["process_reaped"])
            self.assertTrue(row["owner_unresolved"])
            self.assertFalse(row["resource_accounting_complete"])
            self.assertTrue(row["cleanup_errors"])
            for artifact in (row["stdout"], row["stderr"]):
                self.assertFalse(artifact["complete"])
                self.assertIsNone(artifact["sha256"])
            self.assertFalse(blocked["process_started"])
            self.assertIsNone(blocked["pid"])
            self.assertIsNone(blocked["exit_code"])
            self.assertEqual(blocked["dispatch_blocked_by"], "unresolved")
            self.assertIsNone(driver.final_event(row, "produce_complete"))
            self.assertIsNone(driver.final_event(blocked, "produce_complete"))
            self.assert_terminal(root, row)
            self.assert_terminal(root, blocked)

    def collect_with_fault(self, unresolved, postflight_error=False):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repo = base / "source"
            repo.mkdir()
            output = base / "evidence"
            source = "a" * 40
            args = SimpleNamespace(repo=repo, output=output, binary=Path(sys.executable),
                                   expected_source=source, process_timeout=1)
            native_context = {"packet_limit": driver.MAX_PACKET,
                              "parent_hex": "b" * 64, "task_hex": "c" * 64}
            context = subprocess.CompletedProcess([], 0, driver.canonical(native_context), b"")

            def source_git(_repo, *arguments):
                return "" if arguments[0] == "status" else "d" * 40 if arguments[-1] == "HEAD^{tree}" else source

            fault = ({"return_value": UnreapedProcess()} if unresolved else
                     {"side_effect": OSError(errno.EAGAIN, "injected process startup failure")})
            snapshot = {"tested_commit": source, "tested_tree": "d" * 40}
            audited = [snapshot, ValueError("injected raw-source mutation")] if postflight_error else None
            with (patch.object(driver, "git", side_effect=source_git),
                  patch.object(driver, "verify_source", return_value=snapshot, side_effect=audited),
                  patch.object(driver.subprocess, "run", return_value=context),
                  patch.object(driver.subprocess, "Popen", **fault) as launch,
                  patch.object(driver.os, "killpg", side_effect=PermissionError("injected cleanup refusal")),
                  patch.object(driver, "CLEANUP_TIMEOUT", 0.01),
                  contextlib.redirect_stdout(io.StringIO())):
                code = driver.collect(args)
            self.assertEqual(code, 2)
            self.assertEqual(launch.call_count, 1)
            manifest = json.loads((output / "preregistration.json").read_text())
            report = json.loads((output / "process-observations.json").read_text())
            self.assertEqual([row["id"] for row in report["attempts"]],
                             [row["id"] for row in manifest["schedule"]])
            self.assertEqual(len(report["attempts"]), 4)
            self.assertTrue(all(row["status"] == "error" for row in report["attempts"]))
            self.assertEqual(report["qualification"], "HOLD")
            self.assertEqual(report["manifest_sha256"], driver.digest((output / "preregistration.json").read_bytes()))
            self.assertEqual(len(report["processes"]), 1)
            row = report["processes"][0]
            self.assertIsNone(row["exit_code"])
            self.assertFalse(row["process_reaped"])
            self.assertEqual(report["owner_unresolved"], unresolved)
            self.assertEqual(report["resource_accounting_complete"], not unresolved)
            binding = json.loads((output / "source-binding.json").read_text())
            self.assertEqual(binding["schema"], driver.SOURCE_BINDING_SCHEMA)
            self.assertEqual(binding["observations"]["sha256"],
                             driver.digest((output / "process-observations.json").read_bytes()))
            self.assertFalse(binding["execution_attested"])
            self.assertFalse(binding["binary_build_provenance_qualified"])
            self.assertFalse(binding["original_host_contract_qualified"])
            self.assertEqual(binding["qualification"], "HOLD")
            self.assertEqual(binding["source_before"]["sha256"],
                             driver.digest((output / "source-before.json").read_bytes()))
            if postflight_error:
                after = json.loads((output / "source-after.json").read_text())
                self.assertIsNone(after["snapshot"])
                self.assertEqual(after["error"]["message"], "injected raw-source mutation")
                self.assertFalse(report["source_and_binary_unchanged"])
                self.assertIsNone(binding["source_after"])
                self.assertTrue(any("SOURCE_AUDIT" in e for e in report["collection_errors"]))
            elif unresolved:
                self.assertIsNone(binding["source_after"])
            else:
                self.assertEqual(binding["source_after"]["sha256"],
                                 driver.digest((output / "source-after.json").read_bytes()))
            self.assert_terminal(output, row)

    def test_startup_oserror_keeps_every_frozen_attempt(self):
        self.collect_with_fault(unresolved=False)

    def test_cleanup_failure_keeps_every_frozen_attempt(self):
        self.collect_with_fault(unresolved=True)

    def test_failed_raw_source_postflight_keeps_every_frozen_attempt(self):
        self.collect_with_fault(unresolved=False, postflight_error=True)

    def test_preflight_context_failure_saves_logs_without_freezing_a_schedule(self):
        stdout, stderr = b'{"event":"context-error"}\n', b"context diagnostic\n"
        for failure in (
            subprocess.CalledProcessError(2, ["context"], output=stdout, stderr=stderr),
            subprocess.TimeoutExpired(["context"], 30, output=stdout, stderr=stderr),
        ):
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                repo, output = root / "source", root / "evidence"
                repo.mkdir()
                source = "a" * 40
                args = SimpleNamespace(repo=repo, output=output, binary=Path(sys.executable),
                                       expected_source=source, process_timeout=1)
                with (patch.object(driver, "git", side_effect=lambda _repo, *a: "" if a[0] == "status" else source),
                      patch.object(driver, "verify_source", return_value={"tested_commit": source, "tested_tree": "d" * 40}),
                      patch.object(driver.subprocess, "run", side_effect=failure),
                      patch.object(driver.subprocess, "Popen") as launch,
                      self.assertRaises(type(failure)) as caught):
                    driver.collect(args)
                self.assertIs(caught.exception, failure)
                launch.assert_not_called()
                self.assertEqual((output / "context.stdout.json").read_bytes(), stdout)
                self.assertEqual((output / "context.stderr.txt").read_bytes(), stderr)
                self.assertFalse((output / "preregistration.json").exists())
                self.assertFalse((output / "process-observations.json").exists())


class RawSourceAuditTests(unittest.TestCase):
    """Actual Git counterexamples; no fake measurements or native-work claims."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.repo, self.out = root / "source", root / "evidence"
        self.repo.mkdir()
        self.out.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "reader-test")
        self.git("config", "user.email", "reader-test@example.invalid")
        (self.repo / "tracked.txt").write_text("original\n")
        self.git("add", "tracked.txt")
        self.git("commit", "-qm", "fixture")
        self.commit = self.git("rev-parse", "HEAD").strip()

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.repo, text=True, stderr=subprocess.PIPE)

    def audit(self):
        return driver.audit_source(self.repo, self.commit, self.out, "before")

    def assert_rejected(self, message):
        with self.assertRaisesRegex(ValueError, message):
            self.audit()
        receipt = json.loads((self.out / "source-before.json").read_text())
        self.assertEqual(receipt["schema"], driver.SOURCE_AUDIT_SCHEMA)
        self.assertIsNone(receipt["snapshot"])
        self.assertEqual(receipt["error"]["type"], "ValueError")
        self.assertFalse(receipt["execution_attested"])
        self.assertFalse(receipt["original_host_contract_qualified"])
        self.assertFalse((self.out / "preregistration.json").exists())

    def test_clean_source_captures_actual_tree_and_raw_entry_count(self):
        snapshot, reference = self.audit()
        self.assertEqual(snapshot["tested_commit"], self.commit)
        self.assertEqual(snapshot["tested_tree"], self.git("rev-parse", "HEAD^{tree}").strip())
        self.assertEqual(snapshot["tracked_entries"], 1)
        self.assertEqual(snapshot["tracked_bytes"], len(b"original\n"))
        self.assertEqual(reference["sha256"], driver.digest((self.out / reference["path"]).read_bytes()))

    def test_assume_unchanged_cannot_hide_changed_source(self):
        self.git("update-index", "--assume-unchanged", "tracked.txt")
        (self.repo / "tracked.txt").write_text("mutated\n")
        self.assertEqual(self.git("status", "--porcelain", "--untracked-files=all"), "")
        self.assert_rejected("index hides tracked worktree entries")

    def test_skip_worktree_cannot_hide_changed_source(self):
        self.git("update-index", "--skip-worktree", "tracked.txt")
        (self.repo / "tracked.txt").write_text("mutated\n")
        self.assertEqual(self.git("status", "--porcelain", "--untracked-files=all"), "")
        self.assert_rejected("index hides tracked worktree entries")

    def test_clean_filter_cannot_hide_changed_raw_source(self):
        (self.repo / ".gitattributes").write_text("tracked.txt filter=constant\n")
        self.git("config", "filter.constant.clean", "sed s/modified/original/g")
        self.git("add", ".gitattributes", "tracked.txt")
        self.git("commit", "-qm", "filter fixture")
        self.commit = self.git("rev-parse", "HEAD").strip()
        (self.repo / "tracked.txt").write_text("modified\n")
        self.git("add", "tracked.txt")  # The clean filter preserves the original index blob.
        self.assertEqual(self.git("status", "--porcelain", "--untracked-files=all"), "")
        self.assert_rejected("tracked source bytes differ from commit")

    def test_wrong_head_does_not_freeze_an_experiment_schedule(self):
        self.commit = "a" * 40
        self.assert_rejected("head identity mismatch")

    def test_invalid_raw_source_precedes_native_context_execution(self):
        self.git("update-index", "--assume-unchanged", "tracked.txt")
        root = Path(self.directory.name)
        marker = root / "native-context-was-run"
        binary = root / "context-marker"
        binary.write_text("#!/bin/sh\n: > '" + str(marker) + "'\nexit 4\n")
        binary.chmod(0o700)
        output = root / "collection"
        args = SimpleNamespace(repo=self.repo, output=output, binary=binary,
                               expected_source=self.commit, process_timeout=1)
        with self.assertRaisesRegex(ValueError, "index hides tracked worktree entries"):
            driver.collect(args)
        self.assertFalse(marker.exists())
        self.assertTrue((output / "source-before.json").is_file())
        self.assertFalse((output / "preregistration.json").exists())
        self.assertFalse((output / "process-observations.json").exists())



if __name__ == "__main__":
    unittest.main()
