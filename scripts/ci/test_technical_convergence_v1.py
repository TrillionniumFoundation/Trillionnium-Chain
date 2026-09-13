#!/usr/bin/env python3
"""Retained false-pass mutants for the technical-convergence gate."""
from __future__ import annotations

import importlib.util
import json
import pathlib
import shutil
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts/ci/check_technical_convergence_v1.py"
spec = importlib.util.spec_from_file_location("convergence_checker", CHECKER)
if spec is None or spec.loader is None:
    raise RuntimeError("cannot load convergence checker")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
binding_spec = importlib.util.spec_from_file_location("documentation_binding", ROOT / "scripts/ci/check_documentation_reference_closure_v1.py")
if binding_spec is None or binding_spec.loader is None:
    raise RuntimeError("cannot load documentation binding checker")
binding_checker = importlib.util.module_from_spec(binding_spec)
binding_spec.loader.exec_module(binding_checker)


class Mutants(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        paths = [
            checker.CONTRACT,
            checker.PARAMETERS,
            checker.MACHINE_TRUTH,
            checker.MODULE_COVERAGE,
            pathlib.Path("docs/modules/README.md"),
            *checker.HELPER_BLOBS,
            *map(pathlib.Path, checker.EXPECTED_DETAILED_SPECS.values()),
        ]
        for relative in paths:
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, target)
        shutil.copytree(ROOT / checker.WORKFLOW_ROOT, self.root / checker.WORKFLOW_ROOT)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def reset(self) -> None:
        self.temp.cleanup()
        self.setUp()

    def replace(self, relative: pathlib.Path | str, old: str, new: str) -> None:
        path = self.root / relative
        text = path.read_text(encoding="utf-8")
        self.assertEqual(text.count(old), 1, old)
        path.write_text(text.replace(old, new), encoding="utf-8")

    def truth(self, mutate) -> None:
        path = self.root / checker.MACHINE_TRUTH
        value = json.loads(path.read_text(encoding="utf-8"))
        mutate(value)
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def step_remove(self, name: str, command: str) -> None:
        path = self.root / checker.BASELINE_WORKFLOW
        text = path.read_text(encoding="utf-8")
        marker = f"      - name: {name}\n"
        start = text.index(marker) + len(marker)
        tail = text[start:]
        stops = [tail.find(token) for token in (
            "\n      - name:", "\n  protocol-contract:", "\n  fuzz-smoke:",
            "\n  external-evidence-contract:", "\n  rust-baseline:",
        ) if tail.find(token) >= 0]
        end = start + (min(stops) if stops else len(tail))
        body = text[start:end]
        self.assertEqual(body.count(command), 1)
        path.write_text(text[:start] + body.replace(command, "# mutant", 1) + text[end:], encoding="utf-8")

    def rejected(self) -> None:
        with self.assertRaises(checker.ConvergenceError):
            checker.validate(self.root)

    def test_current_and_optional_projection(self) -> None:
        report = checker.validate(self.root)
        self.assertEqual(report["result"], "PASS")
        self.assertEqual(report["workflow_security"]["candidate_privileged_job_count"], 0)
        self.truth(lambda value: [value.pop(key, None) for key in checker.OPTIONAL_MACHINE_FALSE])
        self.assertEqual(checker.validate(self.root)["result"], "PASS")

    def test_helper_and_machine_truth_mutants(self) -> None:
        relative = next(iter(checker.HELPER_BLOBS))
        path = self.root / relative
        path.write_text(path.read_text(encoding="utf-8") + "\n# drift\n", encoding="utf-8")
        self.rejected()
        self.reset(); self.truth(lambda value: value.__setitem__("public_testnet_ready", True)); self.rejected()
        self.reset(); self.truth(lambda value: value.pop("production_candidate", None)); self.rejected()
        self.reset(); self.truth(lambda value: value["blockers"][0].__setitem__("id", "P0-TRUTH-999")); self.rejected()

    def test_contract_closed_sets(self) -> None:
        mutations = (
            ("production_candidate = false", "production_candidate = true"),
            (checker.EXPECTED_PARENT_INTEGRATION_HEAD, "0" * 40),
            ("large_models_and_nondeterministic_inference_off_chain = true", "large_models_and_nondeterministic_inference_off_chain = false"),
            ('reference_engine_role = "differential-oracle-only"', 'reference_engine_role = "production-fallback"'),
            ('non_authoritative_service = ["M14", "M16"]', 'non_authoritative_service = ["M14", "M16", "M04"]'),
            ('  "python3 scripts/ci/check_plan_manifest_pins_v1.py",', '  "python3 scripts/ci/check_plan_manifest_pins_v2.py",'),
            ("publisher_requires_expected_head_compare_and_swap = true", "publisher_requires_expected_head_compare_and_swap = false"),
            ("release_requires_sbom_and_provenance = true", "release_requires_sbom_and_provenance = false"),
            ('  "P2-NET-001",', '  "P2-NET-999",'),
            ('id = "EXT-REVIEW-001"\nstatus = "open-external"', 'id = "EXT-REVIEW-001"\nstatus = "closed"'),
        )
        for old, new in mutations:
            with self.subTest(old=old):
                self.reset(); self.replace(checker.CONTRACT, old, new); self.rejected()

    def test_prohibited_workflow_inventory_mutants(self) -> None:
        self.replace(checker.CONTRACT, f'  "{checker.EXPECTED_PROHIBITED_WORKFLOWS[0]}",\n', ""); self.rejected()
        self.reset(); self.replace(checker.CONTRACT, checker.EXPECTED_PROHIBITED_WORKFLOWS[1], ".github/workflows/substitute.yml"); self.rejected()
        self.reset(); path = self.root / checker.CONTRACT; text = path.read_text(); start = text.index("prohibited_candidate_workflows = ["); end = text.index("]\n", start) + 2; path.write_text(text[:start] + "prohibited_candidate_workflows = []\n" + text[end:]); self.rejected()

    def test_spec_and_module_coverage_mutants(self) -> None:
        path = self.root / checker.EXPECTED_DETAILED_SPECS["M04"]
        path.write_text("# M04 shallow\n", encoding="utf-8"); self.rejected()
        self.reset(); self.replace(checker.CONTRACT, 'id = "M04"\npath = "docs/modules/M04_P2P_TECHNICAL_SPEC_V1.md"\nstatus = "implementation-contract"', 'id = "M04"\npath = "docs/modules/M04_P2P_TECHNICAL_SPEC_V1.md"\nstatus = "accepted"'); self.rejected()
        for old in (
            'technical_convergence = "config/technical-convergence-v1.toml"\n',
            'detailed_spec_index = "docs/modules/README.md"\n',
        ):
            self.reset(); self.replace(checker.MODULE_COVERAGE, old, ""); self.rejected()
        self.reset(); self.replace(checker.MODULE_COVERAGE, "technical_convergence_must_remain_fail_closed = true", "technical_convergence_must_remain_fail_closed = false"); self.rejected()

    def test_required_baseline_invocation_mutants(self) -> None:
        cases = (
            ("Run separately bound prospective-merge regressions", "python3 scripts/ci/check_technical_convergence_v1.py"),
            ("Validate repository, development, module, node, and blocker truth", "python3 scripts/ci/check_plan_manifest_pins_v1.py"),
            ("Run retained module-documentation false-pass mutants", "python3 scripts/ci/test_technical_convergence_v1.py"),
        )
        for name, command in cases:
            with self.subTest(name=name):
                self.reset(); self.step_remove(name, command); self.rejected()

    def test_lifecycle_and_maturity_mutants(self) -> None:
        mutations = (
            ("repository_documentation_gap_closed_by_this_contract = false", "repository_documentation_gap_closed_by_this_contract = true"),
            ("vote_requires_block_finality = false", "vote_requires_block_finality = true"),
            ("receipt_requires_verified_finality = true", "receipt_requires_verified_finality = false"),
            ("legacy_stage_labels_supply_authority = false", "legacy_stage_labels_supply_authority = true"),
            ('signing_stages = ["Validated", "IntentDurable", "SignatureRecorded", "VotePublished"]', 'signing_stages = ["Validated", "VotePublished", "IntentDurable", "SignatureRecorded"]'),
            ('"FinalityVerified", "CommitIntentDurable"', '"ApplicationApplied", "CommitIntentDurable"'),
        )
        for old, new in mutations:
            with self.subTest(old=old):
                self.reset()
                self.replace(checker.CONTRACT, old, new)
                self.rejected()

    def test_durable_transaction_journal_execution_cannot_be_omitted(self) -> None:
        commands = (
            "cargo test -p trnm-tx-lifecycle-v0 --all-targets --locked",
            "cargo test -p trnm-durable-file-adapters-v0 --features candidate-tx-journal --all-targets --locked",
            "cargo clippy -p trnm-durable-file-adapters-v0 --features candidate-tx-journal --all-targets --locked -- -D warnings",
            "set -euo pipefail",
        )
        for command in commands:
            with self.subTest(command=command):
                self.reset()
                self.step_remove("Test durable transaction journal without production activation", command)
                self.rejected()

    def test_persistent_bridge_execution_cannot_be_omitted(self) -> None:
        commands = (
            "cargo test -p trnm-durable-file-adapters-v0 --features candidate-peer-replay --all-targets --locked",
            "cargo test -p trnm-poco-node-host --features candidate-networked-authority --all-targets --locked",
            "cargo clippy -p trnm-durable-file-adapters-v0 --features candidate-peer-replay --all-targets --locked -- -D warnings",
            "cargo clippy -p trnm-poco-node-host --features candidate-networked-authority --all-targets --locked -- -D warnings",
            'exit "$rc"',
        )
        for command in commands:
            with self.subTest(command=command):
                self.reset()
                self.step_remove("Test persistent peer-to-authority bridge without production activation", command)
                self.rejected()

    def test_workflow_trust_domain_mutants(self) -> None:
        workflows = {
            "write.yml": """name: write\non:\n  pull_request:\npermissions:\n  contents: write\njobs:\n  x:\n    runs-on: [self-hosted, Linux]\n    steps:\n      - run: git push origin HEAD:main\n""",
            "target.yml": """name: target\non:\n  pull_request_target:\npermissions:\n  contents: read\njobs:\n  x:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo x\n""",
            "secret.yml": """name: secret\non:\n  workflow_dispatch:\npermissions:\n  contents: read\njobs:\n  x:\n    runs-on: ubuntu-24.04\n    env:\n      GH_TOKEN: ${{ secrets.REPOSITORY_PAT }}\n    steps:\n      - run: echo x\n""",
            "inherit.yml": """name: inherit\non:\n  workflow_call:\npermissions:\n  contents: read\njobs:\n  x:\n    uses: owner/repo/.github/workflows/x.yml@main\n    secrets: inherit\n""",
            "implicit.yml": """name: implicit\non:\n  workflow_dispatch:\npermissions:\n  contents: read\njobs:\n  x:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: gh api --method POST repos/o/r/issues -f title=bad\n""",
        }
        for name, content in workflows.items():
            with self.subTest(name=name):
                self.reset(); (self.root / checker.WORKFLOW_ROOT / name).write_text(content); self.rejected()

    def test_strict_documentation_binding_and_retention_cannot_be_omitted(self) -> None:
        cases = (
            ("Validate repository, development, module, node, and blocker truth", "TRNM_DOC_BINDING_MODE: ${{ github.event_name == 'pull_request' && 'source' || 'local' }}"),
            ("Validate repository, development, module, node, and blocker truth", "TRNM_DOC_BINDING_OUTPUT: ${{ runner.temp }}/trnm-documentation-source-binding.json"),
            ("Run separately bound prospective-merge regressions", "TRNM_DOC_BINDING_MODE: merge"),
            ("Run separately bound prospective-merge regressions", "TRNM_DOC_BINDING_OUTPUT: ${{ runner.temp }}/trnm-documentation-merge-binding.json"),
            ("Retain strict source and prospective-merge documentation bindings", "if: always()"),
            ("Retain strict source and prospective-merge documentation bindings", "trnm-documentation-merge-binding.json"),
            ("Retain strict source and prospective-merge documentation bindings", "if-no-files-found: error"),
        )
        for name, token in cases:
            with self.subTest(token=token):
                self.reset(); self.step_remove(name, token); self.rejected()

    def test_hosted_candidate_commands_and_outcomes_cannot_be_omitted(self) -> None:
        step = "Test hosted candidate process recovery with explicit features"
        for token in (*checker._workflows.CANDIDATE_TEST_COMMANDS, checker._workflows.CANDIDATE_CLIPPY_COMMAND,
                      'timeout --signal=TERM --kill-after=10s 600s "$@"', 'exit "$rc"',
                      '--check-candidate-test-log "$root/$name.log"', 'if [[ "$kind" == "test" ]]',
                      'printf \'%s\\n\' "$rc" > "$root/$name.exit-code"', "x230_acceptance=false"):
            with self.subTest(token=token):
                self.reset(); self.step_remove(step, token); self.rejected()
        self.reset()
        self.replace(checker.BASELINE_WORKFLOW, "run_candidate test timeout-signing cargo", "run_candidate clippy timeout-signing cargo")
        self.rejected()
        for token in ("if: always()", "if-no-files-found: error", "${{ runner.temp }}/trnm-hosted-candidate-process"):
            self.reset(); self.step_remove("Retain hosted candidate process commands and outcomes", token); self.rejected()


class RuntimeEvidence(unittest.TestCase):
    def test_candidate_log_requires_nonempty_unfiltered_success(self) -> None:
        valid = "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n"
        self.assertEqual(checker._workflows.candidate_test_summary(valid)["passed"], 2)
        self.assertEqual(checker._workflows.candidate_test_summary(valid + valid.replace("2 passed", "0 passed"))["test_binaries"], 2)
        for text in ("", "running 2 tests\n", valid.replace("2 passed", "0 passed"), valid.replace("0 ignored", "1 ignored"),
                     valid.replace("0 filtered out", "1 filtered out"), valid.replace("0 failed", "1 failed"),
                     valid.replace("ok.", "FAILED."), valid + "test result: malformed\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                checker._workflows.candidate_test_summary(text)

    def test_strict_runtime_binding_rejects_missing_or_wrong_pr_evidence(self) -> None:
        head, base, merge = "a" * 40, "b" * 40, "c" * 40
        with tempfile.TemporaryDirectory() as temp:
            path = pathlib.Path(temp) / "event.json"
            def event(**changes):
                value = {"pull_request": {"number": 124, "head": {"sha": head}, "base": {"sha": base}}}
                value.update(changes); path.write_text(json.dumps(value))
            def git_value(*args):
                if args == ("rev-parse", "HEAD"):
                    return current[0]
                if args == ("rev-parse", "HEAD^{tree}"):
                    return "d" * 40
                return " ".join(parents)
            current = [head]; parents = [merge, base, head]
            with mock.patch.object(binding_checker, "git", side_effect=git_value), mock.patch.dict(binding_checker.os.environ, {}, clear=True):
                self.assertEqual(binding_checker.runtime_binding("local")["mode"], "local")
                for mode in ("source", "merge"):
                    with self.subTest(mode=mode), self.assertRaises(binding_checker.DocumentationTruthError):
                        binding_checker.runtime_binding(mode)
                binding_checker.os.environ.update(GITHUB_EVENT_PATH=str(path), GITHUB_SHA=merge)
                event(pull_request=None)
                for mode in ("source", "merge"):
                    with self.assertRaises(binding_checker.DocumentationTruthError):
                        binding_checker.runtime_binding(mode)
                event()
                self.assertEqual(binding_checker.runtime_binding("source")["source_commit"], head)
                current[0] = merge
                with self.assertRaises(binding_checker.DocumentationTruthError):
                    binding_checker.runtime_binding("source")
                self.assertEqual(binding_checker.runtime_binding("merge")["prospective_merge_commit"], merge)
                for invalid in ([merge, head, base], [merge, base, head, "e" * 40], [merge, base, "e" * 40]):
                    parents[:] = invalid
                    with self.subTest(parents=invalid), self.assertRaises(binding_checker.DocumentationTruthError):
                        binding_checker.runtime_binding("merge")
                parents[:] = [merge, base, head]
                binding_checker.os.environ["GITHUB_SHA"] = "e" * 40
                with self.assertRaises(binding_checker.DocumentationTruthError):
                    binding_checker.runtime_binding("merge")


if __name__ == "__main__":
    unittest.main()
