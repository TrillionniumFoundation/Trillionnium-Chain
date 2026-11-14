#!/usr/bin/env python3
"""Reader/orchestration controls only; these do not execute Cargo or qualify SQLite."""

import contextlib
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import check_sqlite_build_requalification as subject


class RequalificationReaderTests(unittest.TestCase):
    def output(self, *, qualified=False, reason=None, mtime=2):
        return {"watches_rustc": True, "qualified": qualified,
                "unqualified_reason": reason, "mtime_ns": mtime}

    def test_zero_exit_without_actual_witness_cannot_qualify(self):
        self.assertFalse(subject.phase_passed(0, [self.output()], True, None, None))
        self.assertFalse(subject.phase_passed(0, [], True, None, None))
        witnessed = self.output(qualified=True)
        self.assertFalse(subject.phase_passed(0, [witnessed, witnessed], True, None, None))

    def test_foreign_path_requires_that_path_and_a_loader_rejection(self):
        foreign = Path("/retained/foreign-loader")
        for reason in (None, "UNQUALIFIED: RUSTC must be absolute",
                       "UNQUALIFIED: normal Cargo loader directory set incomplete",
                       "UNQUALIFIED: unknown or duplicate Cargo loader directory: /elsewhere"):
            self.assertFalse(subject.phase_passed(
                0, [self.output(reason=reason)], False, foreign, None))
        reason = f"UNQUALIFIED: extra Cargo loader directory: observed={foreign}"
        self.assertTrue(subject.phase_passed(
            0, [self.output(reason=reason)], False, foreign, None))
        self.assertFalse(subject.phase_passed(
            1, [self.output(reason=reason)], False, foreign, None))

    def test_cache_transition_must_emit_a_fresh_output(self):
        previous = [self.output(mtime=20)]
        stale = [self.output(qualified=True, mtime=20)]
        self.assertFalse(subject.phase_passed(0, stale, True, None, previous))
        fresh = [self.output(qualified=True, mtime=21)]
        self.assertTrue(subject.phase_passed(0, fresh, True, None, previous))

    def test_restore_preserves_absent_empty_and_existing_loader_values(self):
        for original in ({}, {"LD_LIBRARY_PATH": ""},
                         {"LD_LIBRARY_PATH": "/existing:/another:"}):
            base = {"PATH": "/bin", **original}
            saved = copy.deepcopy(base)
            refused = subject.phase_environment(base, "/toolchain/bin/rustc", "/foreign")
            restored = subject.phase_environment(base, "/toolchain/bin/rustc")
            self.assertEqual(base, saved)
            self.assertEqual(restored, {**saved, "RUSTC": "/toolchain/bin/rustc"})
            expected = original["LD_LIBRARY_PATH"] + ":/foreign" if original else "/foreign"
            self.assertEqual(refused["LD_LIBRARY_PATH"], expected)


class RequalificationOrchestrationTests(unittest.TestCase):
    def run_fixture(self, *, fail_phase=None, ignore_foreign=False,
                    refuse_restore=False, mismatch=False, probe_timeout=False):
        """Retain synthetic build outputs to test the reader; never launch a compiler."""
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            root = parent / "source"
            root.mkdir()
            binary_dir = parent / "toolchain" / "bin"
            binary_dir.mkdir(parents=True)
            (binary_dir.parent / "lib").mkdir()
            binaries = {name: binary_dir / name for name in ("rustup", "cargo", "rustc")}
            for name, path in binaries.items():
                path.write_bytes(("synthetic-reader-control-" + name).encode())
            output, target = parent / "records", parent / "target"
            argv = ["check_sqlite_build_requalification.py", "--root", str(root),
                    "--output", str(output), "--target", str(target)]
            for name, path in binaries.items():
                argv.extend(["--" + name, str(path)])
            calls = []

            def execute(command, **kwargs):
                if command[1] == "--version":
                    if probe_timeout:
                        raise subprocess.TimeoutExpired(command, 20)
                    return SimpleNamespace(returncode=0, stdout="rustup fixture-version\n", stderr="")
                if command[1] == "which":
                    path = binaries[command[-1]]
                    if mismatch and command[-1] == "cargo":
                        path = parent / "different-cargo"
                    return SimpleNamespace(returncode=0, stdout=str(path) + "\n", stderr="")
                env = kwargs["env"].copy()
                calls.append({"argv": command, "environment": env})
                index = len(calls)
                relative = env["RUSTC"] == "rustc"
                foreign = str(output / "foreign-loader")
                injected = foreign in env.get("LD_LIBRARY_PATH", "")
                qualified = not relative and (not injected or ignore_foreign)
                reason = ""
                if relative:
                    reason = "RUSTC must be absolute"
                elif injected and not ignore_foreign:
                    reason = f"extra Cargo loader directory: observed={foreign}"
                elif index == 6 and refuse_restore:
                    qualified = False
                    reason = "normal Cargo loader directory set incomplete"
                raw = ("cargo:rerun-if-env-changed=RUSTC\n"
                       "cargo:rerun-if-env-changed=LD_LIBRARY_PATH\n")
                if qualified:
                    raw += "cargo:rustc-cfg=trnm_sqlite_layout_witness\n"
                if reason:
                    raw += "cargo:warning=trnm SQLite I/O boundary UNQUALIFIED: " + reason + "\n"
                build_output = (target / "debug/build" /
                                "trnm-sqlite-io-boundary-0123456789abcdef/output")
                build_output.parent.mkdir(parents=True, exist_ok=True)
                build_output.write_text(raw)
                os.utime(build_output, ns=(index * 1_000_000, index * 1_000_000))
                return SimpleNamespace(returncode=1 if index == fail_phase else 0)

            with mock.patch.object(sys, "argv", argv), \
                    mock.patch.dict(os.environ, {"PATH": "/usr/bin"}, clear=True), \
                    mock.patch.object(subject, "source_identity", return_value={"fixture": True}), \
                    mock.patch.object(subject.subprocess, "run", side_effect=execute), \
                    contextlib.redirect_stdout(io.StringIO()):
                code = subject.main()
            return (code, json.loads((output / "summary.json").read_text()),
                    json.loads((output / "launcher.json").read_text()), calls)

    def test_original_four_and_foreign_refusal_restore_have_separate_denominators(self):
        code, summary, launcher, calls = self.run_fixture()
        self.assertEqual(code, 0)
        self.assertEqual([row["label"] for row in summary["commands"]],
                         ["refuse-1", "qualify-1", "refuse-2", "qualify-2"])
        self.assertEqual([row["label"] for row in summary["loader_controls"]],
                         ["foreign-loader-refuse", "foreign-loader-restore"])
        self.assertEqual(len(calls), 6)
        self.assertEqual(summary["required_original_commands"], 4)
        self.assertEqual(summary["required_loader_controls"], 2)
        self.assertTrue(summary["executables_unchanged"])
        self.assertFalse(summary["target_cleaned_between_phases"])
        self.assertEqual(len({call["environment"]["CARGO_TARGET_DIR"] for call in calls}), 1)
        self.assertEqual(calls[0]["argv"][1:8],
                         ["run", "1.95.0", "cargo", "check", "--offline", "--locked", "--manifest-path"])
        expected_seed = str(Path(launcher["executables"]["rustc"]["resolved_path"]).parent.parent / "lib")
        self.assertEqual(launcher["selected_loader_path_seed"], expected_seed)
        self.assertEqual(launcher["inherited_loader_path"], {"present": False, "value": None})
        self.assertEqual(calls[3]["environment"]["LD_LIBRARY_PATH"], expected_seed)
        self.assertIn("foreign-loader", calls[4]["environment"]["LD_LIBRARY_PATH"])
        self.assertEqual(calls[5]["environment"]["LD_LIBRARY_PATH"], expected_seed)
        self.assertTrue(calls[4]["environment"]["LD_LIBRARY_PATH"].startswith(expected_seed + os.pathsep))
        self.assertEqual(launcher["commands"][0]["stdout"], "rustup fixture-version\n")
        self.assertEqual(len(launcher["executables"]["rustup"]["sha256"]), 64)

    def test_original_failure_remains_failure_and_later_attempts_are_retained(self):
        code, summary, _, calls = self.run_fixture(fail_phase=2)
        self.assertEqual(code, 1)
        self.assertEqual(len(calls), 6)
        self.assertFalse(summary["commands"][1]["passed"])
        self.assertFalse(summary["original_phases_passed"])
        self.assertTrue(summary["loader_controls_passed"])

    def test_silent_filtering_of_foreign_loader_is_a_failed_control(self):
        code, summary, _, calls = self.run_fixture(ignore_foreign=True)
        self.assertEqual(code, 1)
        self.assertEqual(len(calls), 6)
        self.assertTrue(summary["original_phases_passed"])
        self.assertFalse(summary["loader_controls"][0]["passed"])

    def test_restore_requires_actual_qualified_witness(self):
        code, summary, _, calls = self.run_fixture(refuse_restore=True)
        self.assertEqual(code, 1)
        self.assertEqual(len(calls), 6)
        self.assertTrue(summary["loader_controls"][0]["passed"])
        self.assertFalse(summary["loader_controls"][1]["passed"])

    def test_wrong_cargo_selection_is_retained_before_execution(self):
        code, summary, launcher, calls = self.run_fixture(mismatch=True)
        self.assertEqual(code, 1)
        self.assertEqual(calls, [])
        self.assertFalse(launcher["matched"])
        self.assertFalse(summary["launcher_matched"])
        self.assertEqual(summary["required_original_commands"], 4)
        self.assertEqual(summary["required_loader_controls"], 2)

    def test_probe_timeout_is_retained_and_cannot_qualify(self):
        code, summary, launcher, calls = self.run_fixture(probe_timeout=True)
        self.assertEqual(code, 1)
        self.assertEqual(calls, [])
        self.assertEqual(len(launcher["commands"]), 3)
        self.assertIn("error", launcher["commands"][0])
        self.assertFalse(summary["passed"])


if __name__ == "__main__":
    unittest.main()
