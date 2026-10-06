#!/usr/bin/env python3
"""Python execution-owner regressions; fake Cargo output is NOT native evidence."""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import run_from_zero_service as runner


class FromZeroRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.receipts = self.root / "receipts"
        self.receipts.mkdir()
        ci = self.root / "scripts/ci"
        ci.mkdir(parents=True)
        shutil.copyfile(Path(runner.__file__).with_name("check_required_native_test.py"),
                        ci / "check_required_native_test.py")
        self.fake = self.root / "cargo"
        self.fake.write_text("#!" + sys.executable + "\n" + '''
import json, os, pathlib, sys
root = pathlib.Path(os.environ["TRNM_CI_RECEIPT_DIR"])
name = sys.argv[sys.argv.index("--test") + 2]
mode = os.environ.get("FAKE_MODE", "ok")
with (root / "invocations").open("a") as f: f.write(name + "\\n")
count = "0" if mode == "zero" else "1"
printed_name = "wrong_identity" if mode == "wrong" else name
print("running " + count + " tests", flush=True)
if count == "1": print("test " + printed_name + " ... ok", flush=True)
print("test result: ok. " + count + " passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s", flush=True)
if name == "from_zero_service_shares_cpu_with_honest_work_and_reopened_owner":
    if mode != "missing":
        p = pathlib.Path(os.environ["TRNM_PUBLIC_V3_FROM_ZERO_DIR"])
        p.mkdir()
        report = {"schema": "public-v3-local-from-zero-service-v2", "finite_target_met": True,
                  "reopen_state_equal": True, "cpu_domain_retained_across_owner_reopen": True}
        for key in ("public_network_ready", "independent_accepted", "work_profile_qualified",
                    "resource_fairness_qualified", "physical_power_loss", "production_activation"):
            report[key] = False
        if mode == "promoted": report["production_activation"] = True
        if mode == "false": report["finite_target_met"] = False
        if mode == "bool_alias": report["finite_target_met"] = 1
        (p / "report.json").write_text(json.dumps(report))
    if mode == "tamper":
        with (root / "from-zero-service/00.log").open("a") as f: f.write("late mutation\\n")
    if mode == "source_changed":
        source = root / "source.json"
        source.write_text(source.read_text() + " ")
if mode == "nonzero": sys.exit(7)
''')
        self.fake.chmod(0o700)
        env = {"PATH": str(self.root) + os.pathsep + os.environ.get("PATH", ""),
               "TRNM_CI_RECEIPT_DIR": str(self.receipts)}
        self.enterContext(patch.dict(os.environ, env))
        self.enterContext(patch.object(runner, "ROOT", self.root))
        for key in ("GITHUB_ACTIONS", "TRNM_EXPECTED_SOURCE_SHA", "FAKE_MODE"):
            os.environ.pop(key, None)

    def execute(self, mode="ok"):
        os.environ["FAKE_MODE"] = mode
        with contextlib.redirect_stdout(io.StringIO()):
            code = runner.main()
        report = json.loads((self.receipts / "from-zero-service/results.json").read_text())
        return code, report

    def test_fixture_owner_closes_all_three_commands_and_binds_bytes(self):
        code, report = self.execute()
        self.assertEqual(code, 0)
        self.assertEqual(report["result"], "PASS")
        self.assertTrue(report["complete"])
        self.assertEqual([row["test"] for row in report["results"]], list(runner.TESTS))
        for row in report["results"]:
            self.assertTrue(row["direct_child_reaped"])
            self.assertEqual(row["timeout_seconds"], 600)
            log = self.receipts / "from-zero-service" / row["log"]
            self.assertEqual(row["log_sha256"], runner.digest(log.read_bytes()))
        self.assertFalse(report["source_before"]["available"])
        self.assertFalse(report["public_network_qualification"])
        self.assertFalse(report["compute_qualification"])
        self.assertIn("sha256", report["native_report"])

    def test_zero_execution_never_passes(self):
        code, report = self.execute("zero")
        self.assertEqual(code, 1)
        self.assertEqual(len(report["results"]), 3)
        self.assertFalse(any(row["passed"] for row in report["results"]))

    def test_wrong_named_test_never_passes(self):
        code, report = self.execute("wrong")
        self.assertEqual(code, 1)
        self.assertFalse(any(row["passed"] for row in report["results"]))

    def test_nonzero_exit_is_preserved_despite_success_shaped_stdout(self):
        code, report = self.execute("nonzero")
        self.assertEqual(code, 1)
        self.assertEqual([row["exit_code"] for row in report["results"]], [7, 7, 7])
        self.assertTrue(all(row["named_execution_check_exit"] is None for row in report["results"]))

    def test_missing_native_report_is_not_filled_by_libtest_success(self):
        code, report = self.execute("missing")
        self.assertEqual(code, 1)
        self.assertTrue(all(row["passed"] for row in report["results"]))
        self.assertEqual(report["result"], "INCOMPLETE_OR_FAILED")
        self.assertIsNone(report["native_report"])

    def test_promoted_native_scope_is_refused(self):
        code, report = self.execute("promoted")
        self.assertEqual(code, 1)
        self.assertIn("promote acceptance", report["error"])

    def test_false_native_outcome_is_refused(self):
        self.assertEqual(self.execute("false")[0], 1)

    def test_integer_is_not_a_boolean_native_success(self):
        self.assertEqual(self.execute("bool_alias")[0], 1)

    def test_later_command_cannot_rewrite_a_completed_log(self):
        code, report = self.execute("tamper")
        self.assertEqual(code, 1)
        self.assertIn("log changed", report["error"])

    def test_existing_campaign_is_preserved_without_another_execution(self):
        self.execute()
        output = self.receipts / "from-zero-service/results.json"
        original = output.read_bytes()
        invocations = (self.receipts / "invocations").read_bytes()
        with self.assertRaises(FileExistsError):
            self.execute()
        self.assertEqual(output.read_bytes(), original)
        self.assertEqual((self.receipts / "invocations").read_bytes(), invocations)

    def test_symlinked_campaign_is_refused_without_following_target(self):
        target = self.root / "untouched"
        target.mkdir()
        (self.receipts / "from-zero-service").symlink_to(target, target_is_directory=True)
        with self.assertRaises(FileExistsError):
            self.execute()
        self.assertEqual(list(target.iterdir()), [])
        self.assertFalse((self.receipts / "invocations").exists())

    def test_missing_hosted_source_refuses_before_cargo(self):
        os.environ["GITHUB_ACTIONS"] = "true"
        code, report = self.execute()
        self.assertEqual(code, 1)
        self.assertEqual(report["results"], [])
        self.assertFalse(report["complete"])
        self.assertFalse((self.receipts / "invocations").exists())

    def make_source(self):
        def git(*args):
            return subprocess.check_output(["git", *args], cwd=self.root, text=True).strip()
        git("init", "-q")
        (self.root / "fixture.txt").write_text("Python test fixture, not Rust source\n")
        git("add", "fixture.txt")
        git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
            "commit", "-qm", "fixture")
        data = {"schema": "trnm-ci-source-v1", "kind": "head",
                "tested_commit": git("rev-parse", "HEAD"),
                "tested_tree": git("rev-parse", "HEAD^{tree}"),
                "tracked_worktree_verified": True}
        (self.receipts / "source.json").write_text(json.dumps(data))
        return data

    def test_actual_git_commit_and_tree_are_bound_separately(self):
        source = self.make_source()
        code, report = self.execute()
        self.assertEqual(code, 0)
        for key in ("tested_commit", "tested_tree"):
            self.assertEqual(report["source_before"][key], source[key])
        self.assertEqual(report["source_before"], report["source_after"])

    def test_wrong_tree_refuses_before_native_invocation(self):
        data = self.make_source()
        data["tested_tree"] = "0" * 40
        (self.receipts / "source.json").write_text(json.dumps(data))
        code, report = self.execute()
        self.assertEqual(code, 1)
        self.assertIn("tested_tree", report["error"])
        self.assertFalse((self.receipts / "invocations").exists())

    def test_changed_source_bytes_never_finalize_pass(self):
        self.make_source()
        code, report = self.execute("source_changed")
        self.assertEqual(code, 1)
        self.assertIn("source identity changed", report["error"])

    def test_duplicate_and_nonfinite_json_are_rejected(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                runner.unique_json(raw)

    def test_regular_file_limits_and_symlinks_are_checked(self):
        original = self.root / "data"
        original.write_bytes(b"abcd")
        self.assertEqual(runner.read_retained(original, 4), b"abcd")
        with self.assertRaises(ValueError):
            runner.read_retained(original, 3)
        link = self.root / "link"
        link.symlink_to(original)
        with self.assertRaises(OSError):
            runner.read_retained(link, 4)
        with self.assertRaises(ValueError):
            runner.read_retained(self.root, 4096)

    def test_launch_failure_has_no_invented_exit_or_execution(self):
        row = runner.run_owned([str(self.root / "missing")], self.root / "missing.log", dict(os.environ), 1)
        self.assertEqual(row["error_kind"], "launch")
        self.assertIsNone(row["exit_code"])
        self.assertFalse(row["direct_child_reaped"])

    def test_timeout_kills_same_group_descendant_and_retains_partial_stdout(self):
        marker = self.root / "child-write"
        child_pid_file = self.root / "child.pid"
        child = ("import os,time,pathlib; "
                 f"pathlib.Path({str(child_pid_file)!r}).write_text(str(os.getpid())); "
                 "time.sleep(10); "
                 f"pathlib.Path({str(marker)!r}).write_text('must not execute')")
        parent = ("import subprocess,sys,time,pathlib; "
                  f"subprocess.Popen([sys.executable, '-c', {child!r}]); "
                  "print('partial-owned-output', flush=True); time.sleep(60)")
        log = self.root / "timeout.log"
        real_popen = subprocess.Popen
        def ready_popen(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            # Test-only handshake: force the descendant to exist before testing
            # wait-timeout cleanup. Do not depend on Python startup in 300 ms.
            deadline = time.monotonic() + 10
            while not child_pid_file.exists() or b"partial-owned-output" not in log.read_bytes():
                if time.monotonic() >= deadline:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
                    self.fail("fixture descendant did not become ready")
                time.sleep(0.01)
            return process
        with patch.object(runner.subprocess, "Popen", ready_popen):
            row = runner.run_owned([sys.executable, "-c", parent], log, dict(os.environ), 0.1)
        self.assertTrue(row["timed_out"])
        self.assertEqual(row["error_kind"], "timeout")
        self.assertTrue(row["timeout_group_kill_sent"])
        self.assertTrue(row["direct_child_reaped"])
        self.assertNotEqual(row["exit_code"], 0)
        self.assertIn(b"partial-owned-output", log.read_bytes())
        self.assertTrue(child_pid_file.exists())
        pid = int(child_pid_file.read_text())
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            proc = Path(f"/proc/{pid}/stat")
            if not proc.exists() or proc.read_text().rsplit(")", 1)[1].split()[0] == "Z":
                break
            time.sleep(0.01)
        else:
            self.fail("owned descendant remained runnable after timeout cleanup")
        self.assertFalse(marker.exists())

    def test_initial_incomplete_receipt_exists_before_launch(self):
        actual = runner.run_owned
        observations = []
        def checked(*args, **kwargs):
            observations.append(json.loads((self.receipts / "from-zero-service/results.json").read_text())["result"])
            return actual(*args, **kwargs)
        with patch.object(runner, "run_owned", checked):
            self.assertEqual(self.execute()[0], 0)
        self.assertTrue(observations)
        self.assertEqual(set(observations), {"INCOMPLETE_OR_FAILED"})
        self.assertFalse((self.receipts / "from-zero-service/results.pending").exists())


if __name__ == "__main__":
    unittest.main()
