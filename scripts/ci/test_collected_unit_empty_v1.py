#!/usr/bin/env python3
"""Read-only cleanup controls; no host systemd/cgroup is created or modified."""
import errno
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

import check_collected_unit_empty_v1 as fixture
from bounded_process import Result

ROOT = Path(__file__).resolve().parents[2]
UNIT = "trnm-native-campaign-40995210492-1.service"
WORKFLOWS = {"pon-pure-history-raw-joint.yml": 2,
             "pon-native-campaign-qualification.yml": 2,
             "pon-pure-admission-daa-v2.yml": 1,
             "pon-history-epoch-v1-native.yml": 1}


class ReadControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.cgroup = self.base / "cgroup"
        self.runtime = self.base / "systemd"
        (self.cgroup / "system.slice").mkdir(parents=True)
        (self.runtime / "transient").mkdir(parents=True)
        self.enterContext(patch.object(fixture, "CGROUP_ROOT", self.cgroup))
        self.enterContext(patch.object(fixture, "SYSTEMD_ROOT", self.runtime))
        self.enterContext(patch.object(fixture.time, "sleep"))
        # Keep the true Result constructor independent of the runner mock.
        self.Result = Result

    def success(self, argv, data, **kwargs):
        self.assertEqual(data, b"")
        if argv[0] == "/usr/bin/systemctl":
            self.assertEqual(argv, fixture.loaded_command(UNIT))
            return self.Result(0, b"[]\n", b"")
        if argv[0] == "/usr/bin/stat":
            self.assertEqual(argv, ["/usr/bin/stat", "--file-system", "--format=%t", "--", str(self.cgroup)])
            return self.Result(0, b"63677270\n", b"")
        self.assertEqual(argv, fixture.files_command(UNIT))
        return self.Result(0, b"a(ss) 0\n", b"")

    def run_observer(self, runner=None):
        with patch.object(fixture, "run_bounded", side_effect=runner or self.success) as child:
            result = fixture.Observer(UNIT).run()
        return result, child

    def assert_unknown(self, result):
        self.assertFalse(result["complete"])
        self.assertEqual(result["state"], "UNRESOLVED")
        self.assertTrue(result["failure"])
        self.assertTrue(result["read_only"])

    def test_exact_supported_run_attempt_names(self):
        for value in (UNIT, "trnm-native-history-lifeline-42-1.service",
                      "trnm-history-graph-v1-42-1.service",
                      "trnm-pure-admission-daa-42-1-x64.service",
                      "trnm-pure-admission-daa-42-1-arm64.service"):
            self.assertEqual(fixture.unit_name(value), value)

    def test_globs_paths_options_and_unbounded_identity_are_rejected(self):
        for value in ("*.service", "../" + UNIT, "--user", "sshd.service", UNIT + "\n",
                      "trnm-native-campaign-0-1.service", "trnm-native-campaign-1-0.service",
                      "trnm-native-campaign-" + "1" * 21 + "-1.service",
                      "trnm-pure-admission-daa-42-1-foreign.service"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                fixture.Observer(value)

    def test_fresh_empty_and_repeated_observation_are_read_only(self):
        before = sorted(str(p.relative_to(self.base)) for p in self.base.rglob("*"))
        for _ in range(2):
            result, child = self.run_observer()
            self.assertTrue(result["complete"])
            self.assertEqual(result["state"], "EMPTY")
            self.assertEqual(len(result["paths"]), 7)
            self.assertTrue(all(row["absent"] for row in result["paths"]))
            self.assertEqual(child.call_count, 4)
            self.assertEqual([row["label"] for row in result["commands"]],
                             ["manager-before", "cgroup-filesystem", "unit-files", "manager-after"])
        self.assertEqual(before, sorted(str(p.relative_to(self.base)) for p in self.base.rglob("*")))

    def test_queries_use_only_local_system_absolute_tools_and_fixed_environment(self):
        hostile = {"DBUS_SYSTEM_BUS_ADDRESS": "unix:path=/foreign", "DBUS_SESSION_BUS_ADDRESS": "foreign",
                   "SYSTEMD_BUS_ADDRESS": "foreign", "SYSTEMD_HOST": "foreign", "SYSTEMD_PAGER": "foreign"}
        with patch.dict(os.environ, hostile):
            result, child = self.run_observer()
        self.assertTrue(result["complete"])
        for call in child.call_args_list:
            argv = call.args[0]
            self.assertTrue(argv[0].startswith("/usr/bin/"))
            if argv[0] != "/usr/bin/stat":
                self.assertIn("--system", argv)
                self.assertNotIn("--user", argv)
                self.assertNotIn("--host", argv)
            self.assertEqual(call.kwargs["env"], fixture.COMMAND_ENV)
            self.assertLessEqual(call.kwargs["timeout"], fixture.QUERY_SECONDS)
            self.assertEqual(call.kwargs["stdout_limit"], fixture.STDOUT_LIMIT)
            self.assertEqual(call.kwargs["stderr_limit"], fixture.STDERR_LIMIT)
            self.assertNotIn("DBUS_SYSTEM_BUS_ADDRESS", call.kwargs["env"])

    def test_exit_five_silent_failure_signal_and_noninteger_are_not_absence(self):
        for code in (1, 5, -9, None, False):
            with self.subTest(code=code):
                result, child = self.run_observer(lambda *a, **kw: self.Result(code, b"[]\n", b""))
                self.assert_unknown(result)
                self.assertEqual(child.call_count, 1)
                self.assertEqual(result["commands"][0]["returncode"], code)

    def test_diagnostics_invalid_encoding_and_malformed_json_remain_unknown(self):
        cases = [(b"[]\n", b"Access denied\n"), (b"[]\xff", b""), (b"", b""),
                 (b"{}", b""), (b"null", b""), (b"[", b""), (b"[{}]", b""),
                 (b"[] trailing", b"")]
        for stdout, stderr in cases:
            with self.subTest(stdout=stdout, stderr=stderr):
                result, child = self.run_observer(lambda *a, **kw: self.Result(0, stdout, stderr))
                self.assert_unknown(result)
                self.assertEqual(child.call_count, 1)
                self.assertEqual(result["commands"][0]["stderr"], stderr.decode())

    def test_preexisting_same_name_unit_is_never_stopped_or_removed(self):
        foreign = self.runtime / "transient" / UNIT
        foreign.write_text("foreign unit owner\n")
        raw = json.dumps([{"unit": UNIT, "load": "loaded", "active": "active",
                           "sub": "running", "description": "somebody else"}]).encode()
        result, child = self.run_observer(lambda *a, **kw: self.Result(0, raw, b""))
        self.assert_unknown(result)
        self.assertEqual(child.call_count, fixture.MAX_OBSERVATIONS)
        self.assertTrue(all(call.args[0] == fixture.loaded_command(UNIT) for call in child.call_args_list))
        self.assertEqual(foreign.read_text(), "foreign unit owner\n")

    def test_known_collection_in_progress_can_be_observed_again(self):
        first = json.dumps([{"unit": UNIT, "load": "loaded", "active": "inactive",
                             "sub": "dead", "description": "finite service"}]).encode()
        calls = 0
        def runner(argv, data, **kwargs):
            nonlocal calls
            calls += 1
            return self.Result(0, first, b"") if calls == 1 else self.success(argv, data, **kwargs)
        result, _ = self.run_observer(runner)
        self.assertTrue(result["complete"])
        self.assertEqual(len(result["observations"]), 2)
        self.assertIn("residual", result["observations"][0])

    def test_kernel_residual_even_empty_cgroup_cannot_be_empty(self):
        residual = self.cgroup / "system.slice" / UNIT
        residual.mkdir()
        for raw in ("populated 0\n", "populated 1\n"):
            (residual / "cgroup.events").write_text(raw)
            result, _ = self.run_observer()
            self.assert_unknown(result)
            self.assertEqual((residual / "cgroup.events").read_text(), raw)

    def test_dangling_leaf_symlink_is_presence_and_parent_symlink_is_refused(self):
        residual = self.cgroup / "system.slice" / UNIT
        residual.symlink_to(self.base / "nonexistent")
        result, _ = self.run_observer()
        self.assert_unknown(result)
        self.assertTrue(residual.is_symlink())
        residual.unlink()  # Test fixture only; the observer never removes it.
        (self.cgroup / "system.slice").rmdir()
        (self.cgroup / "system.slice").symlink_to(self.runtime, target_is_directory=True)
        result, _ = self.run_observer()
        self.assert_unknown(result)
        self.assertEqual(len(result["observations"]), 1)

    def test_runtime_file_or_dropin_residual_is_retained(self):
        for name in (UNIT, UNIT + ".d"):
            residual = self.runtime / "transient" / name
            residual.write_text("must not be removed\n")
            result, _ = self.run_observer()
            self.assert_unknown(result)
            self.assertEqual(residual.read_text(), "must not be removed\n")
            residual.unlink()  # Test fixture only.

    def test_permission_io_and_not_directory_errors_do_not_become_enoent(self):
        original = fixture.os.stat
        for code in (errno.EACCES, errno.EIO, errno.ENOTDIR):
            def denied(path, *args, **kwargs):
                if path == UNIT and "dir_fd" in kwargs:
                    raise OSError(code, os.strerror(code), path)
                return original(path, *args, **kwargs)
            with self.subTest(errno=code), patch.object(fixture.os, "stat", side_effect=denied):
                result, _ = self.run_observer()
            self.assert_unknown(result)
            self.assertEqual(len(result["observations"]), 1)
            self.assertFalse(result["paths"][0]["absent"])

    def test_missing_or_denied_required_base_is_unknown(self):
        for error in (PermissionError(errno.EACCES, "denied"), FileNotFoundError(errno.ENOENT, "missing base")):
            with self.subTest(error=error), patch.object(fixture, "open_directory", side_effect=error):
                result, _ = self.run_observer()
            self.assert_unknown(result)

    def test_non_cgroup_filesystem_is_not_kernel_evidence(self):
        def runner(argv, data, **kwargs):
            return self.Result(0, b"1021994\n", b"") if argv[0] == "/usr/bin/stat" else self.success(argv, data, **kwargs)
        result, _ = self.run_observer(runner)
        self.assert_unknown(result)
        self.assertEqual(result["paths"], [])

    def test_unit_file_lookup_requires_zero_exit_and_exact_typed_empty(self):
        for code, stdout in ((1, b"a(ss) 0\n"), (0, b""), (0, b"as 0\n"),
                             (0, b"a(ss) 0 trailing\n"), (0, b'a(ss) 1 "/etc/foreign" "enabled"\n')):
            def runner(argv, data, **kwargs):
                return self.Result(code, stdout, b"") if argv[0] == "/usr/bin/busctl" else self.success(argv, data, **kwargs)
            with self.subTest(code=code, stdout=stdout):
                result, _ = self.run_observer(runner)
                self.assert_unknown(result)
                self.assertEqual(result["commands"][-1]["stdout"], stdout.decode())

    def test_final_manager_error_cannot_be_hidden_by_prior_empty_paths(self):
        count = 0
        def runner(argv, data, **kwargs):
            nonlocal count
            count += 1
            return self.Result(1, b"", b"D-Bus disconnected\n") if count == 4 else self.success(argv, data, **kwargs)
        result, child = self.run_observer(runner)
        self.assert_unknown(result)
        self.assertEqual(child.call_count, 4)
        self.assertTrue(all(row["absent"] for row in result["paths"]))
        self.assertIn("D-Bus disconnected", result["commands"][-1]["stderr"])

    def test_expired_observation_never_spawns_an_unbounded_query(self):
        observer = fixture.Observer(UNIT)
        observer.deadline = fixture.time.monotonic() - 1
        with patch.object(fixture, "run_bounded") as child:
            result = observer.run()
        self.assert_unknown(result)
        child.assert_not_called()


class ActualBoundedChildControls(unittest.TestCase):
    def test_actual_nonzero_query_keeps_original_stderr(self):
        observer = fixture.Observer(UNIT)
        argv = [sys.executable, "-B", "-c", "import sys;sys.stdout.write('[]\\n');sys.stderr.write('denied\\n');sys.exit(5)"]
        with self.assertRaises(ValueError):
            observer.query("negative-control", argv)
        row = observer.report["commands"][0]
        self.assertEqual((row["returncode"], row["stdout"], row["stderr"]), (5, "[]\n", "denied\n"))

    def test_actual_output_overflow_is_capped_and_is_not_empty(self):
        observer = fixture.Observer(UNIT)
        argv = [sys.executable, "-B", "-c", "import os;os.write(1,b'[]'+b'x'*100000)"]
        with patch.object(fixture, "STDOUT_LIMIT", 64), self.assertRaises(ValueError):
            observer.query("negative-control", argv)
        row = observer.report["commands"][0]
        self.assertTrue(row["stdout_truncated"])
        self.assertEqual(len(row["stdout"]), 64)
        self.assertIn("NATIVE_STDOUT_LIMIT", row["error"])

    def test_actual_stalled_query_times_out_without_claiming_absence(self):
        observer = fixture.Observer(UNIT)
        argv = [sys.executable, "-B", "-c", "import time;time.sleep(10)"]
        with patch.object(fixture, "QUERY_SECONDS", 0.1), self.assertRaises(ValueError):
            observer.query("negative-control", argv)
        self.assertIn("NATIVE_EXECUTOR_TIMEOUT", observer.report["commands"][0]["error"])


class WorkflowExitControls(unittest.TestCase):
    def test_every_actual_trap_propagates_cleanup_failure_and_preserves_native_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            helper = root / "scripts/ci/check_collected_unit_empty_v1.py"
            helper.parent.mkdir(parents=True)
            helper.write_text("import json,os,sys\nstatus=int(os.environ['TEST_CLEANUP_EXIT'])\n"
                              "print(json.dumps({'complete':status==0}))\nsys.exit(status)\n")
            tested = 0
            for workflow, expected in WORKFLOWS.items():
                text = (ROOT / ".github/workflows" / workflow).read_text()
                traps = re.findall(r"          cleanup\(\) \{\n.*?          trap 'exit 143' TERM", text, re.S)
                self.assertEqual(len(traps), expected, workflow)
                for trap in traps:
                    self.assertNotIn("systemctl stop", trap)
                    self.assertIn("check_collected_unit_empty_v1.py", trap)
                    body = "\n".join(line[10:] for line in trap.splitlines())
                    for original, cleanup, expected_exit in ((0, 0, 0), (1, 0, 1), (0, 1, 1),
                                                              (0, 5, 5), (1, 5, 1), (143, 1, 143)):
                        tested += 1
                        out = root / str(tested)
                        out.mkdir()
                        env = {**fixture.COMMAND_ENV, "OUT": str(out), "GITHUB_WORKSPACE": str(root),
                               "PYTHONDONTWRITEBYTECODE": "1", "TEST_CLEANUP_EXIT": str(cleanup)}
                        script = 'set -euo pipefail\nunit="' + UNIT + '"\n' + body + "\nexit " + str(original)
                        result = fixture.run_bounded(["/bin/bash", "-c", script], b"", timeout=3,
                                                     stdout_limit=8192, stderr_limit=8192, env=env)
                        self.assertEqual(result.returncode, expected_exit, (workflow, original, cleanup, result.stderr))
                        log = next(out.glob("*-cleanup.log")).read_text()
                        self.assertEqual(log, f"original_exit={original}\ncleanup_exit={cleanup}\n")
            self.assertEqual(tested, 36)


if __name__ == "__main__":
    unittest.main()
