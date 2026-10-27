#!/usr/bin/env python3
"""PQ provider wiring and fail-closed controls; no synthetic success provider."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/trnm-required-baseline.yml"
SCRIPT = ROOT / "scripts/ci/prepare_pq_provider.sh"
PROVIDER = "scripts/ci/prepare_pq_provider.sh"
READER = "scripts/ci/test_pq_provider_ci.py"
PREPARE = """      - name: Prepare pinned OpenSSL 3.5.9 PQ provider
        shell: bash
        run: bash scripts/ci/prepare_pq_provider.sh
"""
MERGE_PREPARE = PREPARE.replace(
    "        shell:", "        if: matrix.lane == 'protocol-contract'\n        shell:")
READ = """      - name: Check PQ provider CI wiring and failure controls
        run: python3 scripts/ci/test_pq_provider_ci.py
"""
MERGE_READ = READ.replace(
    "        run:", "        if: matrix.lane == 'repository-truth'\n        run:")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def job_blocks(workflow: str) -> dict[str, str]:
    require(workflow.count("\njobs:\n") == 1, "workflow jobs boundary")
    workflow = workflow.split("\njobs:\n", 1)[1]
    matches = list(re.finditer(r"(?m)^  ([a-z][a-z0-9-]+):\n", workflow))
    require(len({m[1] for m in matches}) == len(matches), "duplicate job")
    return {m[1]: workflow[m.start():matches[i + 1].start() if i + 1 < len(matches) else len(workflow)]
            for i, m in enumerate(matches)}


def step_blocks(job: str) -> list[str]:
    matches = list(re.finditer(r"(?m)^      - name: ", job))
    return [job[m.start():matches[i + 1].start() if i + 1 < len(matches) else len(job)]
            for i, m in enumerate(matches)]


def validate_workflow(workflow: str) -> None:
    jobs = job_blocks(workflow)
    required = {
        "protocol-contract": (PREPARE, "      - name: Run actual protocol-contract checks\n"),
        "rust-baseline-shards": (PREPARE, "      - name: Run retained Rust shard\n"),
        "prospective-rust-shards": (PREPARE, "      - name: Run retained Rust shard\n"),
        "prospective-merge": (MERGE_PREPARE, "      - name: Execute the same lane on the prospective merge\n"),
    }
    require(set(required) <= set(jobs), "required provider job missing")
    require(workflow.count("run: bash " + PROVIDER) == 4, "provider invocation count")
    for name, block in jobs.items():
        found = [step for step in step_blocks(block) if PROVIDER in step]
        if name not in required:
            require(not found, "provider added to a non-PQ job")
            continue
        expected, consumer = required[name]
        require(found == [expected], "provider step missing, weakened, duplicated, or wrong condition")
        require(block.index("run: python3 scripts/ci/verify_ci_source.py") <
                block.index(expected) < block.index(consumer),
                "provider must follow source identity and precede feature consumers")
    for name, expected in (("repository-truth", READ), ("prospective-merge", MERGE_READ)):
        found = [step for step in step_blocks(jobs[name]) if READER in step]
        require(found == [expected], "provider wiring reader missing or weakened")
        consumer = ("      - name: Run actual repository-truth checks\n" if name == "repository-truth"
                    else "      - name: Execute the same lane on the prospective merge\n")
        require(jobs[name].index(expected) < jobs[name].index(consumer), "reader ordering")


def validate_script(script: str) -> None:
    for literal in (
        "readonly openssl_version='3.5.9'",
        "readonly openssl_sha256='603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a'",
        "https://github.com/openssl/openssl/releases/download/openssl-",
        "trap pq_record_exit EXIT",
        'test -f "$pq_prefix/lib/libcrypto.a"',
        'test -f "$pq_prefix/lib/libssl.a"',
        '"$pq_prefix/bin/openssl" "$@"',
        'OPENSSL_CONF=/dev/null',
        'mkdir "$pq_observations"',
    ):
        require(script.count(literal) == 1, "provider pin or isolation missing")
    ordered = [
        "set -euo pipefail",
        "curl --fail --location --retry 3 --connect-timeout 20 --max-time 300",
        "--proto '=https' --tlsv1.2",
        "sha256sum --check --strict",
        "tar --extract --gzip",
        './Configure no-shared no-tests --prefix="$pq_prefix"',
        'make -j "$pq_jobs"',
        "make install_sw",
        "pq_openssl genpkey -provider default -algorithm ML-DSA-65",
        "pq_openssl pkeyutl -provider default -sign -rawin",
        "pq_openssl pkeyutl -provider default -verify -rawin",
        "if pq_openssl pkeyutl -provider default -verify -rawin",
        '  -in "$pq_smoke/wrong-message" -sigfile "$pq_smoke/signature.bin"',
        "pq_smoke_passed=true",
        """printf 'OPENSSL_DIR=%s\\nOPENSSL_STATIC=1\\n' "$pq_prefix" >> "$GITHUB_ENV" """.rstrip(),
    ]
    positions = []
    for literal in ordered:
        require(literal in script, "provider verification or export missing")
        positions.append(script.index(literal))
    require(positions == sorted(set(positions)), "provider must verify before exporting")
    require("|| true" not in script and "|| :" not in script and "sudo " not in script,
            "provider failure fallback or system install")
    require(not re.search(r"(?m)^\s*(?:exit|return)\s+0\s*(?:#.*)?$", script),
            "provider success stub")


class ProviderWiringTests(unittest.TestCase):
    def setUp(self):
        self.workflow = WORKFLOW.read_text()
        self.script = SCRIPT.read_text()

    def test_exact_source_wiring_and_shell_syntax(self):
        validate_workflow(self.workflow)
        validate_script(self.script)
        subprocess.run(["bash", "-n", str(SCRIPT)], check=True)

    def test_each_provider_cannot_be_removed_weakened_duplicated_or_moved(self):
        blocks = job_blocks(self.workflow)
        for name in ("protocol-contract", "rust-baseline-shards", "prospective-rust-shards", "prospective-merge"):
            original = blocks[name]
            expected = MERGE_PREPARE if name == "prospective-merge" else PREPARE
            consumer = ("      - name: Run actual protocol-contract checks\n" if name == "protocol-contract"
                        else "      - name: Execute the same lane on the prospective merge\n"
                        if name == "prospective-merge" else "      - name: Run retained Rust shard\n")
            changes = {
                "removed": original.replace(expected, ""),
                "duplicate": original.replace(expected, expected * 2),
                "ignore failure": original.replace(expected, expected + "        continue-on-error: true\n"),
                "commented": original.replace("run: bash " + PROVIDER, "run: true # bash " + PROVIDER),
                "after tests": original.replace(expected, "").replace(consumer, consumer +
                    "        run: true\n" + expected),
                "conditional skip": original.replace(expected, expected.replace("        shell:",
                    "        if: false\n        shell:")),
            }
            for label, changed in changes.items():
                with self.subTest(job=name, change=label), self.assertRaises(ValueError):
                    validate_workflow(self.workflow.replace(original, changed))

    def test_prospective_matrix_is_protocol_only_and_other_jobs_do_not_build(self):
        for condition in ("matrix.lane == 'fuzz-smoke'", "always()", "false"):
            changed = self.workflow.replace(MERGE_PREPARE, MERGE_PREPARE.replace(
                "matrix.lane == 'protocol-contract'", condition))
            with self.subTest(condition=condition), self.assertRaises(ValueError):
                validate_workflow(changed)
        changed = self.workflow.replace("      - name: Run actual fuzz-smoke checks\n",
                                        PREPARE + "      - name: Run actual fuzz-smoke checks\n")
        with self.assertRaises(ValueError):
            validate_workflow(changed)
        for reader in (READ, MERGE_READ):
            with self.assertRaises(ValueError):
                validate_workflow(self.workflow.replace(reader, "", 1))

    def test_changed_pins_removed_smoke_and_premature_export_are_rejected(self):
        export = """printf 'OPENSSL_DIR=%s\\nOPENSSL_STATIC=1\\n' "$pq_prefix" >> "$GITHUB_ENV" """
        export = export.rstrip()
        changes = [
            self.script.replace("readonly openssl_version='3.5.9'", "readonly openssl_version='3.4.0'"),
            self.script.replace("603f5602e2eef00d", "003f5602e2eef00d"),
            self.script.replace("sha256sum --check --strict", "true"),
            self.script.replace("no-shared no-tests", "shared no-tests"),
            self.script.replace("pq_openssl genpkey -provider default -algorithm ML-DSA-65", "true #"),
            self.script.replace("pq_smoke_passed=true", ""),
            self.script.replace(export, "").replace("pq_stage='download'", export + "\npq_stage='download'"),
            self.script.replace("make install_sw", "make install_sw || true"),
            self.script.replace("make install_sw", "sudo make install_sw"),
        ]
        for changed in changes:
            with self.assertRaises(ValueError):
                validate_script(changed)


class PreparationFailureTests(unittest.TestCase):
    """Transport fault injection only; never a fake successful PQ provider."""
    def fail_download(self, curl_body: str, expected_stage: str):
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            env_file = temporary / "github-env"
            env_file.touch()
            fake_bin = temporary / "failure-injection-bin"
            fake_bin.mkdir()
            fake_curl = fake_bin / "curl"
            fake_curl.write_text("#!/usr/bin/env bash\nset -eu\n" + curl_body + "\n")
            fake_curl.chmod(0o700)
            env = dict(os.environ, RUNNER_TEMP=str(temporary), GITHUB_ENV=str(env_file),
                       TRNM_CI_RECEIPT_DIR=str(temporary / "observations"), CARGO_BUILD_JOBS="2",
                       PATH=str(fake_bin) + os.pathsep + os.environ["PATH"])
            result = subprocess.run(["bash", str(SCRIPT)], env=env, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(env_file.read_text(), "")
            receipt_path = temporary / "observations/pq-provider/provider.json"
            retained = receipt_path.read_bytes()
            receipt = json.loads(retained)
            self.assertEqual(receipt["exit_code"], result.returncode)
            self.assertEqual(receipt["result"], "FAILED")
            self.assertEqual(receipt["last_stage"], expected_stage)
            self.assertFalse(receipt["static_build"])
            self.assertFalse(receipt["ml_dsa_65_sign_verify_and_wrong_message_rejection"])
            again = subprocess.run(["bash", str(SCRIPT)], env=env, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(again.returncode, 0)
            self.assertEqual(receipt_path.read_bytes(), retained)
            self.assertEqual(env_file.read_text(), "")

    def test_failed_download_never_exports_or_overwrites_failure(self):
        self.fail_download("exit 7", "download")

    def test_wrong_archive_never_extracts_or_exports(self):
        self.fail_download(
            'while test "$#" -gt 0; do\n'
            '  if test "$1" = --output; then shift; printf "invalid archive" > "$1"; exit 0; fi\n'
            '  shift\n'
            'done\nexit 2', "archive-digest")


if __name__ == "__main__":
    unittest.main(verbosity=2)
