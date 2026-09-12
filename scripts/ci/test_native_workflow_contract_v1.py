#!/usr/bin/env python3
"""False-pass regressions on isolated copies of the actual native workflows."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from check_native_workflow_contract_v1 import (
    BASELINE, QUICK, RETIRED, ROOT, RUNTIME, ContractError, validate_contract,
)


class NativeWorkflowMutants(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        for relative in (BASELINE, RUNTIME, QUICK):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((ROOT / relative).read_bytes())

    def replace(self, relative: str, before: str, after: str) -> None:
        path = self.root / relative
        text = path.read_text()
        self.assertIn(before, text, "mutation must reach an actual workflow input")
        path.write_text(text.replace(before, after, 1))

    def rejected(self, reason: str) -> None:
        with self.assertRaisesRegex(ContractError, reason):
            validate_contract(self.root)

    def test_current_workflow_contract(self) -> None:
        self.assertEqual(validate_contract(self.root)["retained_guard_purposes"], 7)

    def test_native_scan_comment_or_echo_cannot_substitute_execution(self) -> None:
        command = "          python3 scripts/ci/check_native_consensus_only.py"
        self.replace(BASELINE, command, "          # python3 scripts/ci/check_native_consensus_only.py")
        self.rejected("complete execution commands differ")
        self.replace(BASELINE, "          # python3 scripts/ci/check_native_consensus_only.py",
                     '          echo "python3 scripts/ci/check_native_consensus_only.py"')
        self.rejected("complete execution commands differ")

    def test_native_scan_cannot_skip_or_mask_failure(self) -> None:
        marker = "      - name: Enforce native-only source and scanner regressions\n"
        self.replace(BASELINE, marker, marker + "        if: false\n")
        self.rejected("execution may not be conditional")
        self.replace(BASELINE, "        if: false\n", "        continue-on-error: true\n")
        self.rejected("must propagate failure")

    def test_native_scan_mutants_and_working_directory_are_required(self) -> None:
        command = "          python3 scripts/ci/test_native_consensus_only.py"
        self.replace(BASELINE, command, "          # no source mutants")
        self.rejected("complete execution commands differ")
        self.replace(BASELINE, "          # no source mutants", command)
        self.replace(BASELINE,
                     "      - name: Enforce native-only source and scanner regressions\n        working-directory: trillionnium-chain",
                     "      - name: Enforce native-only source and scanner regressions\n        working-directory: another-tree")
        self.rejected("working directory differs")

    def test_retired_lane_or_dangling_link_cannot_return(self) -> None:
        path = self.root / RETIRED[0]
        path.write_text("name: returned legacy lane\n")
        self.rejected("retired lane returned")
        path.unlink()
        path.symlink_to("missing-workflow.yml")
        self.rejected("retired lane returned")

    def test_environment_removal_or_shadowing_cannot_pass(self) -> None:
        self.replace(RUNTIME, "  TZ: UTC", "  TZ: UTC\n  TZ: local")
        self.rejected("duplicate TZ")

    def test_changed_environment_is_rejected(self) -> None:
        self.replace(BASELINE, '  PYTHONHASHSEED: "0"', '  PYTHONHASHSEED: "random"')
        self.rejected("deterministic PYTHONHASHSEED")

    def test_inline_environment_cannot_shadow_verified_block(self) -> None:
        self.replace(BASELINE, "\njobs:\n", "\nenv: {}\n\njobs:\n")
        self.rejected("one explicit env block")

    def test_runtime_job_cannot_shadow_timezone(self) -> None:
        self.replace(RUNTIME, "    env:\n", "    env:\n      TZ: local\n")
        self.rejected("local env shadows protected TZ")

    def test_runtime_job_cannot_shadow_source(self) -> None:
        self.replace(RUNTIME, "    env:\n", "    env:\n      TRNM_EXPECTED_SOURCE_SHA: main\n")
        self.rejected("local env shadows protected TRNM_EXPECTED_SOURCE_SHA")

    def test_quoted_local_environment_cannot_hide_source_override(self) -> None:
        self.replace(RUNTIME, "        env:\n", "        'env':\n          'TRNM_EXPECTED_SOURCE_SHA': main\n")
        self.rejected("local env shadows protected TRNM_EXPECTED_SOURCE_SHA")

    def test_runtime_step_cannot_override_offline_requirement(self) -> None:
        self.replace(RUNTIME, "        env:\n", "        env:\n          CARGO_NET_OFFLINE: false\n")
        self.rejected("local env shadows offline CARGO_NET_OFFLINE")

    def test_baseline_step_cannot_shadow_source(self) -> None:
        self.replace(BASELINE, "        env:\n", "        env:\n          TRNM_EXPECTED_SOURCE_SHA: main\n")
        self.rejected("local env shadows protected TRNM_EXPECTED_SOURCE_SHA")

    def test_soft_failure_and_conditional_required_job_are_rejected(self) -> None:
        self.replace(BASELINE, "  rust-baseline:\n", "  rust-baseline:\n    continue-on-error: true\n")
        self.rejected("soft failure promotion")
        self.replace(BASELINE, "    continue-on-error: true\n", "    if: false\n")
        self.rejected("required job rust-baseline is conditional")

    def test_required_baseline_cannot_filter_out_paths(self) -> None:
        self.replace(BASELINE, "  pull_request:\n", "  pull_request:\n    paths:\n      - 'docs/**'\n")
        self.rejected("cover every change")

    def test_native_path_must_be_covered_on_both_events(self) -> None:
        self.replace(RUNTIME, "      - 'trillionnium/crates/trnm-native-*/**'\n", "")
        self.rejected("native source trigger coverage")

    def test_native_offline_requirement_is_not_optional(self) -> None:
        self.replace(RUNTIME, '      CARGO_NET_OFFLINE: "true"', '      CARGO_NET_OFFLINE: "false"')
        self.rejected("offline CARGO_NET_OFFLINE")

    def test_commented_authority_command_cannot_satisfy_preflight(self) -> None:
        self.replace(RUNTIME, "          python3 scripts/ci/check_repository_truth_v1.py", "          # python3 scripts/ci/check_repository_truth_v1.py")
        self.rejected("native authority: missing")

    def test_offline_postcheck_must_run_even_on_failure(self) -> None:
        self.replace(RUNTIME, "        if: always()", "        if: success()")
        self.rejected("offline postcheck must run on failure")

    def test_workspace_failure_cannot_be_masked_after_tee(self) -> None:
        self.replace(BASELINE, '2>&1 | tee "$root/workspace.log"', '2>&1 | tee "$root/workspace.log" || true # masked')
        self.rejected("workspace execution: failure masking")

    def test_workspace_pipefail_cannot_be_disabled(self) -> None:
        self.replace(BASELINE, "          timeout --signal=TERM --kill-after=30s 1800s cargo test --workspace", "          set +o pipefail\n          timeout --signal=TERM --kill-after=30s 1800s cargo test --workspace")
        self.rejected("workspace execution: failure masking")

    def test_runtime_matrix_cannot_skip_and_publish_success(self) -> None:
        self.replace(RUNTIME, "      - name: Run finalization-intent SIGKILL matrix\n", "      - name: Run finalization-intent SIGKILL matrix\n        if: false\n")
        self.rejected("may not skip execution")

    def test_runtime_matrix_cannot_be_deleted(self) -> None:
        path = self.root / RUNTIME
        text = path.read_text()
        start = text.index("      - name: Run finalization-intent SIGKILL matrix\n")
        end = text.index("      - name:", start + 1)
        path.write_text(text[:start] + text[end:])
        self.rejected("missing or duplicate step Run finalization-intent")

    def test_runtime_matrix_name_and_echo_are_not_execution(self) -> None:
        path = self.root / RUNTIME
        text = path.read_text()
        start = text.index("      - name: Run finalization-intent SIGKILL matrix\n")
        end = text.index("      - name:", start + 1)
        path.write_text(text[:start] + "      - name: Run finalization-intent SIGKILL matrix\n        working-directory: trillionnium-chain\n        run: |\n          echo skipped\n\n" + text[end:])
        self.rejected("complete execution commands differ")

    def test_runtime_matrix_cannot_filter_out_its_tests(self) -> None:
        self.replace(RUNTIME, "--test finalization_intent_process_kill_matrix \\", "--test finalization_intent_process_kill_matrix nonexistent_test_filter \\")
        self.rejected("complete execution commands differ")

    def test_runtime_checkout_cannot_claim_another_source(self) -> None:
        self.replace(RUNTIME, "          ref: ${{ env.TRNM_EXPECTED_SOURCE_SHA }}", "          ref: main")
        self.rejected("checkout must use exact source")

    def test_runtime_artifact_must_bind_source_and_require_files(self) -> None:
        self.replace(RUNTIME, "name: runtime-fault-matrix-${{ env.TRNM_EXPECTED_SOURCE_SHA }}", "name: runtime-fault-matrix-latest")
        self.rejected("runtime artifact source binding")
        self.replace(RUNTIME, "name: runtime-fault-matrix-latest", "name: runtime-fault-matrix-${{ env.TRNM_EXPECTED_SOURCE_SHA }}")
        self.replace(RUNTIME, "if-no-files-found: error", "if-no-files-found: warn")
        self.rejected("runtime artifact absence must fail")

    def test_failed_execution_cannot_publish_success_evidence(self) -> None:
        self.replace(RUNTIME, "      - name: Build exact-source runtime evidence record\n", "      - name: Build exact-source runtime evidence record\n        if: always()\n")
        self.rejected("may not skip execution")

    def test_missing_workspace_failure_log_is_not_a_warning(self) -> None:
        self.replace(BASELINE, "name: trnm-workspace-execution-${{ env.TRNM_EXPECTED_SOURCE_SHA }}\n          path: ${{ runner.temp }}/trnm-rust-execution\n          if-no-files-found: error", "name: trnm-workspace-execution-${{ env.TRNM_EXPECTED_SOURCE_SHA }}\n          path: ${{ runner.temp }}/trnm-rust-execution\n          if-no-files-found: warn")
        self.rejected("workspace artifact absence must fail")

    def test_quick_check_cannot_drop_the_replacement_guard(self) -> None:
        self.replace(QUICK, "          python3 -B scripts/ci/check_native_workflow_contract_v1.py", "          # python3 -B scripts/ci/check_native_workflow_contract_v1.py")
        self.rejected("quick-check native contract invocation: missing")


if __name__ == "__main__":
    unittest.main()
