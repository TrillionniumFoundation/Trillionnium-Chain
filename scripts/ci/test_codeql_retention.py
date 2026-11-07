#!/usr/bin/env python3
"""Execute the real SARIF readback on control files, never a CodeQL qualification.

The workflow must retain parseable original files after remote upload failure
without hiding that failure. These local controls do not run CodeQL or GitHub
Actions, produce a substitute SARIF, or qualify a remote security check.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/codeql-real-exact-source.yml"


def step(text, name):
    return text.split(f"      - name: {name}\n", 1)[1].split("\n      - name:", 1)[0]


def field(text, key):
    return re.search(rf"^          {re.escape(key)}: (.+)$", text, re.MULTILINE).group(1)


class CodeqlRetentionTests(unittest.TestCase):
    def setUp(self):
        self.workflow = WORKFLOW.read_text(encoding="utf-8")
        self.verify = step(self.workflow, "Verify generated SARIF is present and parseable")
        script = self.verify.split("        run: |\n", 1)[1]
        self.script = "\n".join(line[10:] for line in script.splitlines()) + "\n"
        self.script = self.script.replace("${{ matrix.language }}", "python")

    def readback(self, directory):
        return subprocess.run(
            ["bash", "-c", self.script],
            env=dict(os.environ, SARIF_DIR=str(directory)),
            capture_output=True, text=True, check=False,
        )

    def test_failure_retention_does_not_hide_or_skip_remote_analysis(self):
        analyze = step(self.workflow, "Generate local exact-source SARIF for exact source SHA")
        retain = step(self.workflow, "Retain exact-source local SARIF for independent review")
        self.assertIn("        id: codeql\n", analyze)
        self.assertIn("uses: github/codeql-action/analyze@1fc58d04a4d4374f921bdac573c3811c240f9c26", analyze)
        self.assertEqual(field(analyze, "upload"), "always")
        self.assertNotIn("continue-on-error", self.workflow)
        self.assertNotIn("skip-queries:", self.workflow)
        self.assertIn("        id: sarif_verify\n", self.verify)
        self.assertIn("        if: always()\n", self.verify)
        self.assertIn("if: ${{ always() && steps.sarif_verify.outcome == 'success' }}", retain)
        output = field(analyze, "output")
        self.assertEqual(field(self.verify, "SARIF_DIR"), output)
        self.assertEqual(field(retain, "path"), output + "/*.sarif")
        self.assertEqual(field(retain, "if-no-files-found"), "error")
        self.assertNotIn("steps.codeql.outputs.sarif-output", self.verify + retain)
        self.assertIn("run: python3 -B scripts/ci/test_codeql_retention.py", self.workflow)

    def test_existing_parseable_files_are_read_without_rewriting_or_synthesizing(self):
        with tempfile.TemporaryDirectory(prefix="trnm-sarif-readback-") as directory:
            root = Path(directory)
            for name in ("python.sarif", "second.sarif"):
                (root / name).write_text(json.dumps({
                    "version": "2.1.0",
                    "runs": [{"tool": {"driver": {"name": "fixture-only"}}, "results": []}],
                }) + "\n", encoding="utf-8")
            before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir()}
            result = self.readback(root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("CODEQL_SARIF_FILES=2", result.stdout)
            self.assertEqual(before, {
                p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir()
            })

    def test_missing_original_output_is_explicit_failure_without_a_replacement(self):
        with tempfile.TemporaryDirectory(prefix="trnm-sarif-missing-") as directory:
            root = Path(directory)
            for candidate in (root / "absent", root):
                with self.subTest(candidate=candidate.name):
                    result = self.readback(candidate)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("CODEQL_SARIF_MISSING", result.stderr)
                    self.assertEqual(list(root.iterdir()), [])

    def test_malformed_or_incomplete_file_refuses_the_whole_set(self):
        controls = [b"{", b"null", b"[]", b"{}", b'{"version":"2.1.0","runs":[]}',
                    b'{"version":"2.0.0","runs":[{}]}',
                    b'{"version":"2.1.0","runs":{}}']
        for bad in controls:
            with self.subTest(bad=bad), tempfile.TemporaryDirectory(prefix="trnm-sarif-invalid-") as directory:
                root = Path(directory)
                (root / "valid.sarif").write_text('{"version":"2.1.0","runs":[{}]}\n')
                original = root / "invalid.sarif"
                original.write_bytes(bad)
                result = self.readback(root)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertNotIn("CODEQL_SARIF_FILES=", result.stdout)
                self.assertEqual(original.read_bytes(), bad)
                self.assertEqual(sorted(p.name for p in root.iterdir()), ["invalid.sarif", "valid.sarif"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
