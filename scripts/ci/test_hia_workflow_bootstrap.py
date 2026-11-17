"""Fail-closed tests for all thirty-five exact-source HIA native compiler bootstrap gates."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/hia-native-migration.yml"
COMPILER_SHA256 = "87c247e4d1c3c9a449d2947fd4227fdc186d519bffd203a04cafce7861a4ed54"
BOOTSTRAP = re.compile(
    r"(?ms)^ {10}python3 - \"\$RUNNER_TEMP/hia-bootstrap/bootstrap\.json\" \"\$GITHUB_ENV\" <<'PY'\n(?P<body>.*?)^ {10}PY$"
)


class BootstrapGuards(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        text = WORKFLOW.read_text(encoding="utf-8")
        cls.bodies = [textwrap.dedent(m.group("body")) for m in BOOTSTRAP.finditer(text)]
        if len(cls.bodies) != 35:
            raise AssertionError(
                f"expected thirty-five independent native bootstrap gates, found {len(cls.bodies)}"
            )

    def check_case(self, body, payload, *, python_args, succeed):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "bootstrap.json"
            output = Path(tmp) / "env"
            source.write_text(json.dumps(payload), encoding="utf-8")
            child = subprocess.run(
                [sys.executable, *python_args, "-", str(source), str(output)],
                input=body,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={**os.environ, "PYTHONOPTIMIZE": "2"},
                check=False,
                timeout=8,
            )
            self.assertEqual(child.returncode == 0, succeed, child.stderr)
            if succeed:
                self.assertEqual(
                    output.read_text(encoding="utf-8"),
                    "HIA_NATIVE_COMPILER=/tmp/test-native-compiler\n"
                    + f"HIA_NATIVE_COMPILER_SHA256={COMPILER_SHA256}\n",
                )
            else:
                self.assertFalse(
                    output.exists() and output.read_bytes(),
                    "rejected gate wrote compiler ENV",
                )

    def test_reject_failed_bootstrap_even_with_optimized_python(self):
        for i, body in enumerate(self.bodies):
            with self.subTest(gate=i):
                self.check_case(
                    body,
                    {"status": "FAIL", "compiler": "/tmp/test-native-compiler",
                     "compiler_sha256": COMPILER_SHA256},
                    python_args=["-O"], succeed=False,
                )

    def test_reject_wrong_compiler_identity_even_with_optimized_python(self):
        for i, body in enumerate(self.bodies):
            with self.subTest(gate=i):
                self.check_case(
                    body,
                    {"status": "PASS", "compiler": "/tmp/test-native-compiler",
                     "compiler_sha256": "0" * 64},
                    python_args=["-OO"], succeed=False,
                )

    def test_reject_missing_compiler_path(self):
        for i, body in enumerate(self.bodies):
            with self.subTest(gate=i):
                self.check_case(
                    body,
                    {"status": "PASS", "compiler": "", "compiler_sha256": COMPILER_SHA256},
                    python_args=["-OO"], succeed=False,
                )

    def test_accept_exact_compiler_result_in_optimized_mode(self):
        for i, body in enumerate(self.bodies):
            with self.subTest(gate=i):
                self.check_case(
                    body,
                    {"status": "PASS", "compiler": "/tmp/test-native-compiler",
                     "compiler_sha256": COMPILER_SHA256},
                    python_args=["-OO"], succeed=True,
                )


if __name__ == "__main__":
    unittest.main()
