"""Fail-closed tests for the native compiler bootstrap admissions."""
from __future__ import annotations

from collections import Counter
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
# GitHub does not start workflows larger than 500 KB. Reserve space for small
# future edits so this mandatory workflow cannot silently produce zero jobs.
WORKFLOW_MAX_BYTES = 490_000
ORIGINAL_RUST_PREP = "scripts/ci/build_original_rust_component_policies.sh"
ORIGINAL_RUST_PREP_JOBS = {
    "native-components",
    "native-components-general-b",
    "native-components-general-da",
    "native-components-general-c",
    "native-components-general-settlement",
    "native-components-general-state-import",
    "native-components-general-worker",
    "native-components-bench",
}
COMPILER_SHA256 = "87c247e4d1c3c9a449d2947fd4227fdc186d519bffd203a04cafce7861a4ed54"
BOOTSTRAP_HELPER = "scripts/ci/bootstrap_native_hia_compiler.sh"
BOOTSTRAP = re.compile(
    r"(?ms)^ {10}python3(?: -B)? - \"\$RUNNER_TEMP/hia-bootstrap/bootstrap\.json\" \"\$GITHUB_ENV\" <<'PY'\n(?P<body>.*?)^ {10}PY$"
)
SOURCE_BOOTSTRAP = re.compile(
    r"(?m)^      - name: Bootstrap and self-reproduce the native HIA compiler\n"
    rf"        run: source {re.escape(BOOTSTRAP_HELPER)}$"
)


# The workflow is committed hand-written YAML: unquoted job IDs have two
# spaces of indentation. Script lines inside run blocks are more indented.
JOB_HEADER = re.compile(r"(?m)^ {2}(?P<job>[a-z0-9][a-z0-9_-]*):[ \t]*(?:#[^\n]*)?$")
EXPECTED_BOOTSTRAP_JOBS = (
    "native-components",
    "native-components-general-b",
    "native-components-general-da",
    "native-components-general-c",
    "native-components-general-settlement",
    "native-components-general-state-import",
    "native-components-general-worker",
    "native-components-oracle",
    "native-components-bench",
    "native-components-crypto-types",
    "native-components-ml-dsa",
    "native-components-state-root",
    "native-components-research",
    "native-platform",
    "native-host",
    "native-executor",
    "native-rs46-original",
    "native-transport",
    "native-node-delta",
    "native-response",
    "native-node-settings",
    "native-typed-store",
    "native-typed-store-produce",
    "native-typed-store-cold",
    "native-typed-store-bounds",
    "native-host-resource",
    "native-continuity",
    "native-continuity-capacity",
    "native-thread-cpu",
    "native-genesis-semantic",
    "native-genesis-crash",
    "native-genesis-prefix",
    "native-genesis-namespace",
    "native-genesis-corruption",
    "native-paid-cpu",
    "native-execution-state",
    "native-prepare-semantic",
    "native-prepare-physical",
    "native-mempool-typed",
    "native-execution-application",
    "native-work-owner",
    "native-batch-semantic",
    "native-prefix-0",
    "native-prefix-1",
    "native-prefix-2",
    "native-prefix-3",
    "native-batch-physical",
    "native-prefix-scoped",
    "native-node-pool-smoke",
    "native-node-pool-boundaries",
    "native-node-pool-capacity",
    "native-node-pool-node",
    "native-node-pool-cross",
    "native-node-commitment",
    "native-peer-lease-store",
    "native-checkpoint-store",
    "native-additional-owners",
)
EXPECTED_BOOTSTRAP_COUNTS = Counter(EXPECTED_BOOTSTRAP_JOBS)
INLINE_BOOTSTRAP_COUNTS = Counter((
    "native-work-owner",
    "native-node-pool-smoke",
    "native-node-pool-boundaries",
    "native-node-pool-capacity",
    "native-node-pool-node",
    "native-node-pool-cross",
    "native-node-commitment",
    "native-peer-lease-store",
    "native-checkpoint-store",
    "native-additional-owners",
))
SOURCE_BOOTSTRAP_COUNTS = EXPECTED_BOOTSTRAP_COUNTS - INLINE_BOOTSTRAP_COUNTS


def bootstrap_bodies(text):
    _, separator, jobs = text.partition("\njobs:\n")
    if not separator:
        raise AssertionError("missing native workflow jobs section")
    script = (ROOT / BOOTSTRAP_HELPER).read_text(encoding="utf-8")
    admissions = list(BOOTSTRAP.finditer(textwrap.indent(script, " " * 10)))
    if len(admissions) != 1:
        raise AssertionError("expected exactly one compiler admission in the common helper")
    shared = textwrap.dedent(admissions[0].group("body"))
    headers = list(JOB_HEADER.finditer(jobs))
    bodies = []
    inline_counts, source_counts = Counter(), Counter()
    for i, header in enumerate(headers):
        end = headers[i + 1].start() if i + 1 < len(headers) else len(jobs)
        job = header.group("job")
        for match in BOOTSTRAP.finditer(jobs, header.end(), end):
            inline_counts[job] += 1
            bodies.append((job, textwrap.dedent(match.group("body"))))
        for _ in SOURCE_BOOTSTRAP.finditer(jobs, header.end(), end):
            source_counts[job] += 1
            bodies.append((job, shared))
    actual = Counter(job for job, _ in bodies)
    if actual != EXPECTED_BOOTSTRAP_COUNTS:
        raise AssertionError(
            "native bootstrap admission job inventory differs: "
            f"missing={dict(EXPECTED_BOOTSTRAP_COUNTS - actual)!r}, "
            f"unexpected={dict(actual - EXPECTED_BOOTSTRAP_COUNTS)!r}"
        )
    # Do not silently drop a recognizable block outside the job scopes.
    if (inline_counts != INLINE_BOOTSTRAP_COUNTS
            or source_counts != SOURCE_BOOTSTRAP_COUNTS
            or sum(inline_counts.values()) != len(list(BOOTSTRAP.finditer(text)))
            or sum(source_counts.values()) != text.count(BOOTSTRAP_HELPER)):
        raise AssertionError("native bootstrap admission block outside the job inventory")
    return bodies


class BootstrapGuards(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow_text = WORKFLOW.read_text(encoding="utf-8")
        cls.bodies = bootstrap_bodies(cls.workflow_text)

    def test_workflow_fits_hosted_admission_and_uses_exact_shared_prep_jobs(self):
        self.assertLessEqual(WORKFLOW.stat().st_size, WORKFLOW_MAX_BYTES)
        headers = list(JOB_HEADER.finditer(self.workflow_text, self.workflow_text.index("\njobs:\n")))
        step = ("      - name: Compile the original Rust reference policies\n"
                f"        run: source {ORIGINAL_RUST_PREP}\n")
        observed = Counter()
        for i, header in enumerate(headers):
            end = headers[i + 1].start() if i + 1 < len(headers) else len(self.workflow_text)
            observed[header.group("job")] += self.workflow_text[header.end():end].count(step)
        self.assertEqual(+observed, Counter(ORIGINAL_RUST_PREP_JOBS))
        self.assertEqual(self.workflow_text.count(ORIGINAL_RUST_PREP), len(ORIGINAL_RUST_PREP_JOBS))
        subprocess.run(["bash", "-n", str(ROOT / ORIGINAL_RUST_PREP)], check=True, timeout=8)

    def test_inventory_refuses_removed_or_reattributed_bench_guard(self):
        jobs = list(JOB_HEADER.finditer(self.workflow_text, self.workflow_text.index("\njobs:\n")))
        index = next(i for i, header in enumerate(jobs) if header.group("job") == "native-components-bench")
        header, following = jobs[index:index + 2]
        match = SOURCE_BOOTSTRAP.search(self.workflow_text, header.end(), following.start())
        self.assertIsNotNone(match)
        for kind, changed in (
            ("removed", self.workflow_text[:match.start()] + self.workflow_text[match.end():]),
            ("reattributed", self.workflow_text[:header.start("job")] + "native-unexpected-bench"
             + self.workflow_text[header.end("job"):]),
        ):
            with self.subTest(change=kind):
                with self.assertRaisesRegex(AssertionError, "missing=.*native-components-bench"):
                    bootstrap_bodies(changed)

    def test_shared_shell_preserves_compiler_environment_and_failure(self):
        # Tiny test double for the earlier cold emitter, not evidence of any
        # compiler build. Execute the actual Bash helper and its real gate.
        runner = (
            "import os, pathlib, sys\n"
            "destination = pathlib.Path(sys.argv[2])\n"
            "destination.mkdir()\n"
            "(destination / 'bootstrap.json').write_text(os.environ['FIXTURE_RECEIPT'])\n"
            "raise SystemExit(int(os.environ['FIXTURE_EXIT']))\n"
        )
        valid = {"status": "PASS", "compiler": "/test/actual-compiler",
                 "compiler_sha256": COMPILER_SHA256}
        for receipt, status, accepted in (
            (json.dumps(valid), 0, True),
            (json.dumps({**valid, "status": "FAIL"}), 0, False),
            (json.dumps({**valid, "compiler_sha256": "0" * 64}), 0, False),
            (json.dumps({**valid, "compiler": ""}), 0, False),
            ("malformed JSON", 0, False),
            (json.dumps(valid), 6, False),
        ):
            with self.subTest(receipt=receipt, status=status), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                witness = root / "hia/tools/bootstrap.py"
                witness.parent.mkdir(parents=True)
                witness.write_text(runner, encoding="utf-8")
                output = root / "github.env"
                output.write_bytes(b"PRIOR=test\n")
                child = subprocess.run(
                    ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail",
                     "-c", 'source "$1"', "test-helper", str(ROOT / BOOTSTRAP_HELPER)],
                    cwd=root, env={**os.environ, "PYTHONOPTIMIZE": "2",
                                   "RUNNER_TEMP": str(root), "GITHUB_ENV": str(output),
                                   "FIXTURE_RECEIPT": receipt, "FIXTURE_EXIT": str(status)},
                    capture_output=True, check=False, timeout=8,
                )
                self.assertEqual(child.returncode == 0, accepted, child.stderr)
                expected = b"PRIOR=test\n"
                if accepted:
                    expected += ("HIA_NATIVE_COMPILER=/test/actual-compiler\n"
                                 + f"HIA_NATIVE_COMPILER_SHA256={COMPILER_SHA256}\n").encode()
                self.assertEqual(output.read_bytes(), expected)

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
        for job, body in self.bodies:
            with self.subTest(gate=job):
                self.check_case(
                    body,
                    {"status": "FAIL", "compiler": "/tmp/test-native-compiler",
                     "compiler_sha256": COMPILER_SHA256},
                    python_args=["-O"], succeed=False,
                )

    def test_reject_wrong_compiler_identity_even_with_optimized_python(self):
        for job, body in self.bodies:
            with self.subTest(gate=job):
                self.check_case(
                    body,
                    {"status": "PASS", "compiler": "/tmp/test-native-compiler",
                     "compiler_sha256": "0" * 64},
                    python_args=["-OO"], succeed=False,
                )

    def test_reject_missing_compiler_path(self):
        for job, body in self.bodies:
            with self.subTest(gate=job):
                self.check_case(
                    body,
                    {"status": "PASS", "compiler": "", "compiler_sha256": COMPILER_SHA256},
                    python_args=["-OO"], succeed=False,
                )

    def test_accept_exact_compiler_result_in_optimized_mode(self):
        for job, body in self.bodies:
            with self.subTest(gate=job):
                self.check_case(
                    body,
                    {"status": "PASS", "compiler": "/tmp/test-native-compiler",
                     "compiler_sha256": COMPILER_SHA256},
                    python_args=["-OO"], succeed=True,
                )


if __name__ == "__main__":
    unittest.main()
