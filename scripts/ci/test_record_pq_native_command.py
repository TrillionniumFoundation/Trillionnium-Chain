"""Exercise real process failure and raw-source mutation of command records."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from record_pq_native_command import run


class CommandRecords(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="trnm-pq-command-control-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "source"
        self.root.mkdir()
        self.out = Path(self.temp.name) / "records"
        self.git("init", "-q", "-b", "candidate")
        self.git("config", "user.name", "Command record fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        (self.root / "source.rs").write_text("const VALUE: u64 = 1;\n")
        self.git("add", ".")
        self.git("commit", "-qm", "source")
        self.head = self.git("rev-parse", "HEAD")

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root,
                                       text=True).strip()

    def execute(self, source, native_executable_sha256=None):
        args = argparse.Namespace(kind="head", candidate=self.head,
                                  tested=self.head, base=None, label="control",
                                  output=self.out,
                                  command=[str(Path(sys.executable).resolve()), "-c", source],
                                  native_executable_sha256=native_executable_sha256)
        return run(args, self.root)

    def receipt(self):
        return json.loads((self.out / "control.json").read_text())

    def test_exact_source_and_log_are_recorded_without_an_acceptance_claim(self):
        self.assertEqual(self.execute("print('actual child output')"), 0)
        value = self.receipt()
        self.assertEqual(value["status"], "command_succeeded")
        self.assertEqual(value["before"], value["after"])
        self.assertEqual(value["before"]["tested_commit"], self.head)
        self.assertEqual(value["log_sha256"], hashlib.sha256(
            (self.out / "control.log").read_bytes()).hexdigest())
        self.assertFalse(value["whole_chain_quantum_security_qualified"])

    def test_real_child_failure_and_stderr_are_preserved(self):
        self.assertEqual(self.execute("import sys; print('real failure', file=sys.stderr); sys.exit(7)"), 7)
        value = self.receipt()
        self.assertEqual(value["status"], "command_failed")
        self.assertEqual(value["exit_code"], 7)
        self.assertIn("real failure", (self.out / "control.log").read_text())
        self.assertEqual(value["before"], value["after"])

    def test_successful_child_that_changes_raw_source_cannot_pass(self):
        self.assertNotEqual(self.execute("from pathlib import Path; Path('source.rs').write_text('changed\\n')"), 0)
        value = self.receipt()
        self.assertEqual(value["exit_code"], 0)
        self.assertEqual(value["status"], "record_failed")
        self.assertIn("error", value)

    def test_existing_receipt_is_not_replaced_by_a_later_success(self):
        self.assertEqual(self.execute("raise SystemExit(3)"), 3)
        original = (self.out / "control.json").read_bytes()
        with self.assertRaises(FileExistsError):
            self.execute("pass")
        self.assertEqual((self.out / "control.json").read_bytes(), original)

    def native_pin(self):
        return hashlib.sha256(Path(sys.executable).resolve().read_bytes()).hexdigest()

    @unittest.skipUnless(sys.platform == "linux", "Linux executable observation")
    def test_explicit_native_pin_is_observed_on_the_owned_child(self):
        self.assertEqual(self.execute("import time; print('native'); time.sleep(0.1)",
                                      self.native_pin()), 0)
        value = self.receipt()
        observation = value["native_execution"]
        self.assertEqual(observation["status"], "PINNED_AND_OBSERVED")
        self.assertTrue(observation["child_reaped"])
        self.assertEqual(observation["observation"]["sha256"], self.native_pin())
        self.assertEqual(observation["owned_pid"], observation["observation"]["process"]["pid"])
        self.assertIsNone(observation["loaded_memory_sha256"])
        self.assertFalse(observation["descendant_execution_verified"])
        self.assertFalse(observation["performance_measurement"])

    @unittest.skipUnless(sys.platform == "linux", "Linux executable observation")
    def test_bad_native_pin_refuses_before_the_child_runs(self):
        self.assertNotEqual(self.execute("from pathlib import Path; Path('ran').touch()",
                                         "0" * 64), 0)
        self.assertFalse((self.root / "ran").exists())
        self.assertIsNone(self.receipt()["exit_code"])
        self.assertEqual(self.receipt()["status"], "record_failed")
        self.assertEqual(self.receipt()["native_execution"]["expected_sha256"], "0" * 64)
        self.assertEqual(self.receipt()["native_execution"]["status"], "NOT_STARTED")

    @unittest.skipUnless(sys.platform == "linux", "Linux executable observation")
    def test_unavailable_process_observation_keeps_the_native_exit_separate(self):
        with mock.patch("pinned_native_process.observe_executable", side_effect=PermissionError("procfs unavailable")):
            self.assertNotEqual(self.execute("print('completed')", self.native_pin()), 0)
        value = self.receipt()
        self.assertEqual(value["exit_code"], 0)
        self.assertEqual(value["status"], "record_failed")
        self.assertEqual(value["native_execution"]["status"], "IDENTITY_INCOMPLETE")
        self.assertEqual(value["native_execution"]["observation"]["status"], "NOT_OBSERVED")
        self.assertTrue(value["native_execution"]["child_reaped"])
        self.assertEqual(value["before"], value["after"])

    @unittest.skipUnless(sys.platform == "linux", "Linux executable observation")
    def test_pinned_child_failure_remains_a_native_failure(self):
        self.assertEqual(self.execute("import time; time.sleep(0.1); raise SystemExit(7)",
                                      self.native_pin()), 7)
        value = self.receipt()
        self.assertEqual(value["exit_code"], 7)
        self.assertEqual(value["status"], "command_failed")
        self.assertEqual(value["native_execution"]["status"], "PINNED_AND_OBSERVED")

    @unittest.skipUnless(sys.platform == "linux", "Linux executable observation")
    def test_script_pin_cannot_be_relabelled_as_the_interpreter(self):
        script = self.root / "program"
        script.write_text("#!/usr/bin/env python3\nprint('not native')\n")
        script.chmod(0o755)
        self.git("add", "program")
        self.git("commit", "-qm", "script fixture")
        self.head = self.git("rev-parse", "HEAD")
        args = argparse.Namespace(kind="head", candidate=self.head, tested=self.head,
                                  base=None, label="control", output=self.out,
                                  command=[str(script)],
                                  native_executable_sha256=hashlib.sha256(script.read_bytes()).hexdigest())
        self.assertNotEqual(run(args, self.root), 0)
        value = self.receipt()
        self.assertEqual(value["status"], "record_failed")
        self.assertIsNone(value["exit_code"])
        self.assertIn("requires ELF", value["error"])


if __name__ == "__main__":
    unittest.main()
