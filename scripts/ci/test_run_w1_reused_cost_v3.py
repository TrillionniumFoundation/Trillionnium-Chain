#!/usr/bin/env python3
"""Synthetic command-owner boundary tests; no native execution or cost evidence."""

from contextlib import redirect_stdout, redirect_stderr
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
import run_w1_reused_cost_v3 as runner


class ExecutionBoundaryTests(unittest.TestCase):
    def observe(self, *, before=None, after=None, environment=None, machine="x86_64",
                elf=62, campaign_exit=0, reader_error=None, alerts=None):
        with tempfile.TemporaryDirectory(prefix="reuse-v3-owner-test-") as directory:
            root = Path(directory)
            output, target = root / "receipt", root / "target"
            output.mkdir()
            commands = []
            native = target / "x86_64-unknown-linux-gnu/release/examples" / runner.EXAMPLE
            source = {"source_state": "committed-clean", "commit": "a" * 40}

            def capture(command, destination, name, *, timeout):
                commands.append(command)
                stdout, stderr = destination / (name + ".stdout"), destination / (name + ".stderr")
                stdout.write_text("synthetic boundary fixture\n")
                stderr.write_text("")
                if name == "rustc":
                    stdout.write_text("rustc\nrelease: 1.95.0\nhost: x86_64-unknown-linux-gnu\n")
                if name == "build":
                    native.parent.mkdir(parents=True)
                    native.write_bytes(b"\x7fELF\x02\x01" + bytes(12) + elf.to_bytes(2, "little"))
                return {"command": command, "exit_code": campaign_exit if name == "campaign" else 0,
                    "timed_out": False, "timeout_seconds": timeout,
                    "stdout": stdout.name, "stderr": stderr.name}

            actual_copy = runner.shutil.copyfile

            def copy(source, destination):
                if str(source) == "/proc/cpuinfo":
                    Path(destination).write_text("synthetic CPU identity, not hardware evidence\n")
                    return destination
                return actual_copy(source, destination)

            env = {"CARGO_TARGET_DIR": str(target), **(environment or {})}
            with mock.patch.dict(os.environ, env, clear=True), \
                 mock.patch.object(sys, "argv", ["runner", "--arch", "x64", "--local"]), \
                 mock.patch.object(runner, "receipt_root", return_value=output), \
                 mock.patch.object(runner, "source", side_effect=[before or source, after or source]), \
                 mock.patch.object(runner.platform, "system", return_value="Linux"), \
                 mock.patch.object(runner.platform, "machine", return_value=machine), \
                 mock.patch.object(runner, "capture", side_effect=capture), \
                 mock.patch.object(runner.shutil, "copyfile", side_effect=copy), \
                 mock.patch.object(runner, "analyze", side_effect=reader_error,
                    return_value={"semantic_alerts": alerts or []}), \
                 redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = runner.main()
            return code, json.loads((output / "manifest.json").read_text()), commands

    def test_explicit_original_release_command_and_selector_are_retained(self):
        code, report, commands = self.observe()
        self.assertEqual(code, 0)
        self.assertEqual(report["execution_context"], "local-native-preflight")
        self.assertIn(["cargo", "+1.95.0", "build", "--locked", "--release", "--manifest-path",
            "trillionnium/Cargo.toml", "--target", "x86_64-unknown-linux-gnu", "-p", "trnm-pon-node",
            "--example", runner.EXAMPLE], commands)
        self.assertEqual(commands[-1][-1], "--actual-reuse-v3")
        self.assertFalse(report["source_changed"])
        for flag in runner.FALSE_FLAGS:
            self.assertIs(report[flag], False)

    def test_local_mode_cannot_bypass_dirty_source(self):
        code, report, commands = self.observe(before={"source_state": "dirty-candidate"})
        self.assertNotEqual(code, 0)
        self.assertEqual(commands, [])
        self.assertIn("committed source", report["error"])

    def test_test_build_codegen_override_cannot_be_promoted_to_release(self):
        code, report, commands = self.observe(environment={"CARGO_PROFILE_RELEASE_CODEGEN_UNITS": "64"})
        self.assertNotEqual(code, 0)
        self.assertEqual(commands, [])
        self.assertIn("forbids overrides", report["error"])

    def test_requested_architecture_cannot_replace_observed_machine(self):
        code, _, commands = self.observe(machine="aarch64")
        self.assertNotEqual(code, 0)
        self.assertEqual(commands, [])

    def test_wrong_elf_is_refused_before_campaign(self):
        code, report, commands = self.observe(elf=183)
        self.assertNotEqual(code, 0)
        self.assertEqual(len(commands), 4)
        self.assertIn("ELF architecture", report["error"])

    def test_nonzero_native_campaign_is_retained(self):
        code, report, _ = self.observe(campaign_exit=1)
        self.assertNotEqual(code, 0)
        self.assertEqual(report["observations"][-1]["exit_code"], 1)

    def test_zero_or_incomplete_reader_observation_cannot_pass(self):
        code, report, _ = self.observe(reader_error=ValueError("fixed 13-arm/9-class reuse grid incomplete"))
        self.assertNotEqual(code, 0)
        self.assertIn("grid incomplete", report["error"])

    def test_source_change_after_complete_run_still_fails(self):
        code, report, _ = self.observe(after={"source_state": "committed-clean", "commit": "b" * 40})
        self.assertNotEqual(code, 0)
        self.assertTrue(report["source_changed"])

    def test_native_disagreement_cannot_pass_execution_owner(self):
        code, report, _ = self.observe(alerts=[{"outcome": "Product"}])
        self.assertNotEqual(code, 0)
        self.assertEqual(report["reader"]["semantic_alerts"], [{"outcome": "Product"}])


if __name__ == "__main__":
    unittest.main(verbosity=2)
