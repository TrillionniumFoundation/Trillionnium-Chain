"""Fail-closed tests for thirteen HIA compiler bootstrap gates and frozen Rust reference wiring."""
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
ORIGINAL_CHAIN_SHA = "8690b8bbeb581b4ae1fdde577a2e4b98024dc999"
ORIGINAL_JOBS = {
    "native-executor": "qualify_executor_original.py",
    "native-node-settings": "qualify_settings_original.py",
}
BOOTSTRAP = re.compile(
    r"(?ms)^ {10}python3 - \"\$RUNNER_TEMP/hia-bootstrap/bootstrap\.json\" \"\$GITHUB_ENV\" <<'PY'\n(?P<body>.*?)^ {10}PY$"
)


class BootstrapGuards(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        text = WORKFLOW.read_text(encoding="utf-8")
        cls.bodies = [textwrap.dedent(m.group("body")) for m in BOOTSTRAP.finditer(text)]
        if len(cls.bodies) != 13:
            raise AssertionError(
                f"expected thirteen independent native bootstrap gates, found {len(cls.bodies)}"
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


class OriginalReferenceWiring(unittest.TestCase):
    def job(self, workflow, name):
        matches = list(re.finditer(
            r"(?ms)^  " + re.escape(name) + r":\n.*?(?=^  [A-Za-z0-9_-]+:|\Z)",
            workflow,
        ))
        self.assertEqual(len(matches), 1, name)
        return matches[0].group()

    def check_wiring(self, workflow):
        for name, tool in ORIGINAL_JOBS.items():
            job = self.job(workflow, name)
            self.assertEqual(re.findall(r"(?m)^      HIA_ORIGINAL_CHAIN_SHA: (.*)$", job),
                             [ORIGINAL_CHAIN_SHA])
            self.assertIn("        working-directory: chain\n", job)
            steps = re.split(r"(?m)^      - name: ", job)[1:]

            def one(fragment):
                found = [step for step in steps if fragment in step]
                self.assertEqual(len(found), 1, (name, fragment))
                return found[0]

            prepare = one("git clone ")
            self.assertIn('test ! -e "$original"', prepare)
            self.assertIn('original="$RUNNER_TEMP/hia-original-chain"', prepare)
            self.assertIn('git clone --shared --no-checkout "$GITHUB_WORKSPACE/chain" "$original"', prepare)
            self.assertIn('git -C "$original" remote set-url origin '
                          'https://github.com/TrillionniumFoundation/Trillionnium-Chain', prepare)
            self.assertIn('git -C "$original" checkout --detach "$HIA_ORIGINAL_CHAIN_SHA"', prepare)
            self.assertNotIn("sparse-checkout", prepare)
            self.assertNotIn("--depth", prepare)
            self.assertIn('cd "$original"\n            bash scripts/project-preflight.sh --audit', prepare)
            original_check = ('python3 scripts/ci/verify_ci_source.py --kind head '
                              '--expected-head "$HIA_ORIGINAL_CHAIN_SHA" --output '
                              '"$RUNNER_TEMP/hia-observations/original-source-')
            self.assertIn(original_check + 'before.json"', prepare)
            after = one(original_check + 'after.json"')
            self.assertIn("        if: always()\n", after)
            self.assertIn('cd "$RUNNER_TEMP/hia-original-chain"', after)

            compare = one("python3 -B hia/tools/" + tool)
            self.assertIn('python3 -B hia/tools/' + tool
                          + ' --repository "$RUNNER_TEMP/hia-original-chain"', compare)
            self.assertEqual(compare.count("--repository "), 1)
            self.assertNotIn("working-directory:", compare)
            self.assertNotIn("cd ", compare)
            self.assertLess(steps.index(prepare), steps.index(compare))
            self.assertLess(steps.index(compare), steps.index(after))

            candidate_check = ('python3 scripts/ci/verify_ci_source.py --kind head '
                               '--expected-head "$TRNM_EXPECTED_SOURCE_SHA"')
            candidate_steps = [step for step in steps if candidate_check in step]
            self.assertEqual(len(candidate_steps), 2)
            self.assertLess(steps.index(candidate_steps[0]), steps.index(prepare))
            self.assertGreater(steps.index(candidate_steps[1]), steps.index(compare))
            self.assertIn("        if: always()\n", candidate_steps[1])
            retention = one("uses: actions/upload-artifact@")
            self.assertIn("        if: always()\n", retention)
            self.assertIn("${{ runner.temp }}/hia-observations/", retention)

    def reject_change(self, name, old, new):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        job = self.job(workflow, name)
        self.assertIn(old, job)
        changed = workflow.replace(job, job.replace(old, new, 1), 1)
        with self.assertRaises(AssertionError):
            self.check_wiring(changed)

    def test_original_rust_is_fixed_separate_and_receipted(self):
        self.check_wiring(WORKFLOW.read_text(encoding="utf-8"))

    def test_current_source_cannot_replace_the_frozen_reference(self):
        for name in ORIGINAL_JOBS:
            for old, new in [
                ("HIA_ORIGINAL_CHAIN_SHA: " + ORIGINAL_CHAIN_SHA,
                 "HIA_ORIGINAL_CHAIN_SHA: ${{ env.TRNM_EXPECTED_SOURCE_SHA }}"),
                ('--repository "$RUNNER_TEMP/hia-original-chain"',
                 '--repository "$GITHUB_WORKSPACE/chain"'),
                ('--expected-head "$TRNM_EXPECTED_SOURCE_SHA"',
                 '--expected-head "$HIA_ORIGINAL_CHAIN_SHA"'),
            ]:
                with self.subTest(job=name, removed=old):
                    self.reject_change(name, old, new)

    def test_missing_readback_or_sparse_original_snapshot_is_rejected(self):
        for name in ORIGINAL_JOBS:
            for old, new in [
                ("original-source-before.json", "unbound-before.json"),
                ("original-source-after.json", "unbound-after.json"),
                ('git -C "$original" checkout --detach',
                 'git -C "$original" sparse-checkout init\n'
                 '          git -C "$original" checkout --detach'),
                ("Verify the frozen original Rust source remained unchanged\n        if: always()",
                 "Verify the frozen original Rust source remained unchanged\n        if: success()"),
            ]:
                with self.subTest(job=name, removed=old):
                    self.reject_change(name, old, new)

    def test_current_hia_execution_cannot_move_into_the_frozen_checkout(self):
        for name, tool in ORIGINAL_JOBS.items():
            command = "python3 -B hia/tools/" + tool
            with self.subTest(job=name):
                self.reject_change(name, command,
                                   'cd "$RUNNER_TEMP/hia-original-chain" && ' + command)


if __name__ == "__main__":
    unittest.main()
