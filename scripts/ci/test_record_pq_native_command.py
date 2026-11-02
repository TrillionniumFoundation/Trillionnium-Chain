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

    def execute(self, source):
        args = argparse.Namespace(kind="head", candidate=self.head,
                                  tested=self.head, base=None, label="control",
                                  output=self.out,
                                  command=[sys.executable, "-c", source])
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


if __name__ == "__main__":
    unittest.main()
