"""Exact workflow seams and mutation controls; not native execution evidence."""
from __future__ import annotations
from pathlib import Path
import json
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/pon-next-architecture-security.yml"
PYTHON_STEP = "Run all next-architecture Python controls and retained exact fixture"
NODE_STEP = "Run complete storage-owner module and exact new funding controls"
DA_STEP = "Run the complete default-feature P2P crate"
SOURCE_BEFORE_STEP = "Verify exact source and ordered prospective merge"
SOURCE_AFTER_STEP = "Reverify the complete measured source after all attempts"
OUTCOMES_STEP = "Retain stage outcomes and artifact digests"
UPLOAD_STEP = "Retain logs and failed or partial observations"
PYTHON_GUARD = "        if: ${{ always() && steps.source.outcome == 'success' && steps.preflight.outcome == 'success' }}"
NATIVE_GUARD = "        if: ${{ always() && steps.source.outcome == 'success' && steps.preflight.outcome == 'success' && steps.toolchain.outcome == 'success' }}"
PYTHON_RUN_BODY = """\
          set -euo pipefail
          status=0
          bash "$OUT/run-command.sh" next-python python3 -B -m unittest discover -s formal/next-architecture-security -p 'test_*.py' -v || status=1
          bash "$OUT/run-command.sh" counterexample-fixture python3 -B formal/next-architecture-security/counterexamples.py --check-fixture || status=1
          bash "$OUT/run-command.sh" complete-version-vector python3 -B scripts/cell_complete_version_vector.py --check || status=1
          bash "$OUT/run-command.sh" discovery-epoch-vector python3 -B scripts/cell_discovery_epoch_v3_vector.py --check || status=1
          bash "$OUT/run-command.sh" discovery-workflow-controls python3 -B scripts/ci/test_cell_discovery_v3_ci.py || status=1
          bash "$OUT/run-command.sh" complete-content-vector python3 -B scripts/cell_version_content_vector.py --check || status=1
          bash "$OUT/run-command.sh" version-retention-vector python3 -B scripts/cell_version_retention_v3_vector.py --check || status=1
          bash "$OUT/run-command.sh" storage-descriptor-vector python3 -B scripts/cell_storage_descriptor_reference.py --check || status=1
          bash "$OUT/run-command.sh" storage-convergence-workflow-controls python3 -B scripts/ci/test_cell_storage_convergence_ci.py || status=1
          exit "$status"
"""
NODE_RUN_BODY = """\
          set -euo pipefail
          status=0
          bash "$OUT/run-command.sh" native-storage-owner cargo +1.95.0 test --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib store::storage_service:: -- --test-threads=1 || status=1
          required=(
            store::storage_service::tests::version::native_version_reorg_keeps_custody_but_cannot_grant_new_funding_or_foreign_retirement
            store::storage_service::tests::version::native_version_scheduler_pending_metadata_accepts_only_new_funded_copy_then_reopens_done
            store::storage_service::tests::version::native_version_pending_monetary_effect_cannot_retry_copy_with_a_new_source
            store::storage_service::tests::version::native_version_scope_alias_and_late_funding_errors_precede_every_reservation
            store::storage_service::tests::version::native_version_outer_history_cannot_invent_missing_member_intents
            store::storage_service::tests::shard::native_shard_real_funding_target_readback_and_repair_keep_original_debits
            store::storage_service::tests::shard::native_shard_pending_initial_effect_cannot_dispatch_even_with_source_present
            store::storage_service::tests::shard::native_shard_unknown_repair_never_reissues_and_foreign_owner_cannot_retire
            store::storage_service::tests::version::shard_plan::native_complete_version_to_complete_local_shard_plan_reopens_without_sources_or_new_debits
            store::storage_service::tests::version::shard_plan::recovery::native_shard_plan_automatic_recovery_uses_four_targets_after_all_sources_are_deleted
            store::storage_service::tests::version::shard_plan::recovery::native_shard_plan_recovery_refuses_missing_quorum_without_spending_new_repairs_or_refunding_reads
            store::storage_service::tests::version::shard_plan::recovery::native_shard_plan_pending_repair_cannot_redispatch_and_needs_independent_new_funding
            store::storage_service::tests::version::shard_plan::recovery::native_shard_plan_recovery_preflight_cpu_and_metadata_fail_closed_without_hidden_copies
          )
          for selector in "${required[@]}"; do
            bash "$OUT/run-command.sh" "native-storage-$selector" cargo +1.95.0 test --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib "$selector" -- --exact --test-threads=1 || status=1
            python3 -B scripts/ci/check_required_native_test.py "$OUT/native-storage-$selector.log" --test "$selector" || status=1
          done
          exit "$status"
"""
DA_RUN_BODY = """\
          set -euo pipefail
          bash "$OUT/run-command.sh" p2p-complete cargo +1.95.0 test --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-data-availability -- --test-threads=1
"""
NODE_REQUIRED_NAMES = [
    "store::storage_service::tests::version::native_version_reorg_keeps_custody_but_cannot_grant_new_funding_or_foreign_retirement",
    "store::storage_service::tests::version::native_version_scheduler_pending_metadata_accepts_only_new_funded_copy_then_reopens_done",
    "store::storage_service::tests::version::native_version_pending_monetary_effect_cannot_retry_copy_with_a_new_source",
    "store::storage_service::tests::version::native_version_scope_alias_and_late_funding_errors_precede_every_reservation",
    "store::storage_service::tests::version::native_version_outer_history_cannot_invent_missing_member_intents",
    "store::storage_service::tests::shard::native_shard_real_funding_target_readback_and_repair_keep_original_debits",
    "store::storage_service::tests::shard::native_shard_pending_initial_effect_cannot_dispatch_even_with_source_present",
    "store::storage_service::tests::shard::native_shard_unknown_repair_never_reissues_and_foreign_owner_cannot_retire",
    "store::storage_service::tests::version::shard_plan::native_complete_version_to_complete_local_shard_plan_reopens_without_sources_or_new_debits",
    "store::storage_service::tests::version::shard_plan::recovery::native_shard_plan_automatic_recovery_uses_four_targets_after_all_sources_are_deleted",
    "store::storage_service::tests::version::shard_plan::recovery::native_shard_plan_recovery_refuses_missing_quorum_without_spending_new_repairs_or_refunding_reads",
    "store::storage_service::tests::version::shard_plan::recovery::native_shard_plan_pending_repair_cannot_redispatch_and_needs_independent_new_funding",
    "store::storage_service::tests::version::shard_plan::recovery::native_shard_plan_recovery_preflight_cpu_and_metadata_fail_closed_without_hidden_copies"
]
TRIGGERS = [
    "docs/development/specs/pon/CELL_STORAGE_CONVERGENCE_DEV_V1.md",
    "scripts/cell_version_retention_v3_vector.py",
    "scripts/cell_storage_descriptor_reference.py",
    "scripts/ci/test_cell_storage_convergence_ci.py",
    "formal/pon-nakamoto-v1/vectors/cell-version-retention-v3.json",
    "formal/pon-nakamoto-v1/vectors/cell-storage-owner-vectors-v1.json",
    "scripts/cell_sealed_bootstrap_v1.py",
    "scripts/llm_cell_sealed_worker_v1.py",
    "scripts/prepare_cell_sealed_research_v1.py",
    "scripts/test_llm_cell_sealed_worker_v1.py",
    "tests/fixtures/llm_material_runtime_bridge_v1/**"
]

COMPONENT_STEP = "Run exact sealed-handoff and complete shard-capacity controls"
SEALED_STEP = "Run real sealed-input Python controls and verify every frozen case"
COMPONENT_RUN_BODY = """\
          set -euo pipefail
          status=0
          required=(
            cell::host_handoff::tests::research_fds::research_fd_sender_transfers_actual_complete_sealed_pair_with_original_deadline
            cell::host_handoff::tests::research_fds::research_fd_sender_refuses_changed_pins_budget_task_parent_or_expiry_before_any_byte
            cell::version_retention::tests::shard_plan::capacity::retained_shard_plan_initial_128_profile_accepts_complete_65_and_128_chunk_catalogs
            cell::version_retention::tests::shard_plan::capacity::retained_shard_plan_initial_128_profile_refuses_129_complete_chunks_before_staging
            cell::version_retention::tests::shard_plan::capacity::retained_shard_plan_initial_128_profile_keeps_original_two_mib_wire_and_file_ceiling
          )
          for selector in "${required[@]}"; do
            bash "$OUT/run-command.sh" "native-storage-component-$selector" cargo +1.95.0 test --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-data-availability --lib "$selector" -- --exact --test-threads=1 || status=1
            python3 -B scripts/ci/check_required_native_test.py "$OUT/native-storage-component-$selector.log" --test "$selector" || status=1
          done
          exit "$status"
"""
SEALED_RUN_BODY = """\
          set -euo pipefail
          status=0
          bash "$OUT/run-command.sh" sealed-research-python-controls python3 -B -m unittest discover -s scripts -p test_llm_cell_sealed_worker_v1.py -v || status=1
          python3 -B scripts/ci/test_cell_storage_convergence_ci.py --check-sealed-controls "$OUT/sealed-research-python-controls.log" || status=1
          exit "$status"
"""
COMPONENT_REQUIRED_NAMES = [
    "cell::host_handoff::tests::research_fds::research_fd_sender_transfers_actual_complete_sealed_pair_with_original_deadline",
    "cell::host_handoff::tests::research_fds::research_fd_sender_refuses_changed_pins_budget_task_parent_or_expiry_before_any_byte",
    "cell::version_retention::tests::shard_plan::capacity::retained_shard_plan_initial_128_profile_accepts_complete_65_and_128_chunk_catalogs",
    "cell::version_retention::tests::shard_plan::capacity::retained_shard_plan_initial_128_profile_refuses_129_complete_chunks_before_staging",
    "cell::version_retention::tests::shard_plan::capacity::retained_shard_plan_initial_128_profile_keeps_original_two_mib_wire_and_file_ceiling"
]
SEALED_PYTHON_REQUIRED_NAMES = [
    "test_actual_scm_rights_keeps_seals_bytes_and_original_deadline",
    "test_both_sha256_and_stronger_payload_domain_are_checked",
    "test_complete_pair_reads_same_sealed_bytes_without_any_model_path",
    "test_complete_snapshot_ram_and_original_generation_refuse_before_read",
    "test_descriptor_bootstrap_and_owner_pin_cannot_be_replaced",
    "test_expiry_is_checked_before_input_use_and_is_not_reset",
    "test_explicit_material_bridge_uses_sealed_original_pair_and_complete_loaded_contract",
    "test_failed_supervisor_cancels_connector_before_handshake",
    "test_failed_supervisor_cancels_ready_wait_after_sealed_handoff",
    "test_fixed_bootstrap_executes_actual_independently_pinned_sealed_worker_bytes",
    "test_fixed_bootstrap_refuses_substituted_worker_before_any_entry",
    "test_fixed_bootstrap_refuses_unsealed_worker_before_any_entry",
    "test_independent_environment_pin_cannot_follow_supplied_new_bytes",
    "test_kernel_write_seals_and_cloexec_are_required",
    "test_missing_scope_or_swapped_role_refuses_the_complete_admission",
    "test_observation_publish_is_complete_before_visibility_and_cannot_replace",
    "test_original_modules_and_configurations_execute_only_same_admitted_fd_bytes",
    "test_project_source_compiler_preserves_original_annotation_semantics",
    "test_same_length_substituted_fd_fails_actual_content_digest",
    "test_unfinished_publication_remains_pending_without_successful_ready",
    "test_unknown_file_and_metadata_role_never_open_ambient_payload"
]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def exact_line(text: str, line: str) -> None:
    require(text.splitlines().count(line) == 1, "missing/duplicate/nonliteral workflow line: " + line.strip())


def step(text: str, name: str) -> str:
    marker = "      - name: " + name + "\n"
    require(text.count(marker) == 1, "missing/duplicate workflow step: " + name)
    return text.split(marker, 1)[1].split("\n      - name:", 1)[0].rstrip("\n") + "\n"


def run_body(block: str) -> str:
    marker = "        run: |\n"
    require(block.count(marker) == 1, "workflow run body missing/duplicate")
    return block.split(marker, 1)[1]


def validate(text: str) -> None:
    triggers = text.split("\npermissions:", 1)[0]
    for path in TRIGGERS:
        exact_line(triggers, "      - " + path)
    strategy_marker = "    strategy:\n"
    require(text.count(strategy_marker) == 1, "matrix strategy missing/duplicate")
    strategy = text.split(strategy_marker, 1)[1].split("\n    env:", 1)[0].rstrip("\n")
    require(strategy == "      fail-fast: false\n      matrix:\n"
            "        runner: [ubuntu-24.04, ubuntu-24.04-arm]\n"
            "        source: [head, prospective-merge]",
            "all four source/architecture combinations must run without matrix exclusions")
    require(text.count("  next-architecture:\n") == 1, "next-architecture job missing/duplicate")
    job_header = text.split("  next-architecture:\n", 1)[1].split("    steps:\n", 1)[0]
    require(not any(line.startswith(("    if:", "    continue-on-error:")) for line in job_header.splitlines()),
            "job-level skip/failure bypass")
    for line in (
        "        runner: [ubuntu-24.04, ubuntu-24.04-arm]",
        "        source: [head, prospective-merge]",
        "  cancel-in-progress: false",
        "    timeout-minutes: 90",
        '  CARGO_BUILD_JOBS: "2"',
        '  RUST_TEST_THREADS: "1"',
        "      EXPECTED_SOURCE: ${{ matrix.source == 'head' && github.event.pull_request.head.sha || github.sha }}",
    ):
        exact_line(text, line)
    checkout = step(text, "Checkout the immutable event source")
    exact_line(checkout, "          ref: ${{ env.EXPECTED_SOURCE }}")
    exact_line(checkout, "          fetch-depth: 0")
    exact_line(checkout, "          persist-credentials: false")
    preflight = step(text, "Retain original project preflight")
    exact_line(preflight, '        run: bash "$OUT/run-command.sh" preflight bash scripts/project-preflight.sh --audit')

    python = step(text, PYTHON_STEP)
    node = step(text, NODE_STEP)
    da = step(text, DA_STEP)
    components = step(text, COMPONENT_STEP)
    sealed = step(text, SEALED_STEP)
    for block, identifier, guard, body in ((python, "python", PYTHON_GUARD, PYTHON_RUN_BODY),
                                           (node, "storage_owner", NATIVE_GUARD, NODE_RUN_BODY),
                                           (da, "p2p", NATIVE_GUARD, DA_RUN_BODY),
                                           (components, "storage_components", NATIVE_GUARD, COMPONENT_RUN_BODY),
                                           (sealed, "sealed_python", PYTHON_GUARD, SEALED_RUN_BODY)):
        exact_line(block, guard)
        exact_line(block, "        shell: bash")
        require("continue-on-error:" not in block, "native/Python gate failure cannot be ignored")
        expected_header = "        id: " + identifier + "\n" + guard + "\n        shell: bash\n"
        require(block.split("        run: |\n", 1)[0] == expected_header,
                "runtime step source/environment/profile header changed")
        require(run_body(block) == body, "required command/body/roster or failure exit changed")
    exact_line(node, "        id: storage_owner")
    # The exact body retains the full module plus thirteen genuine one-test runs.
    # The existing checker deliberately accepts only an actual one-test log.
    require(len(NODE_REQUIRED_NAMES) == len(set(NODE_REQUIRED_NAMES)) == 13,
            "new native funding roster changed")
    for name in NODE_REQUIRED_NAMES:
        exact_line(node, "            " + name)
    require(len(COMPONENT_REQUIRED_NAMES) == len(set(COMPONENT_REQUIRED_NAMES)) == 5,
            "new DA component roster changed")
    require(len(SEALED_PYTHON_REQUIRED_NAMES) == len(set(SEALED_PYTHON_REQUIRED_NAMES)) == 21,
            "sealed Python controls roster changed")
    for name in COMPONENT_REQUIRED_NAMES:
        exact_line(components, "            " + name)

    for name, label in ((SOURCE_BEFORE_STEP, "source-before"), (SOURCE_AFTER_STEP, "source-after")):
        block = step(text, name)
        exact_line(block, '          args=(--kind "$SOURCE_KIND" --expected-head "$EXPECTED_HEAD")')
        exact_line(block, '          if test "$SOURCE_KIND" = prospective-merge; then')
        exact_line(block, '            args+=(--expected-base "$EXPECTED_BASE" --expected-merge "$EXPECTED_MERGE")')
        exact_line(block, '          bash "$OUT/run-command.sh" ' + label
                   + ' python3 -B scripts/ci/verify_ci_source.py "${args[@]}" --output "$OUT/' + label + '.json"')
    after = step(text, SOURCE_AFTER_STEP)
    exact_line(after, "        if: ${{ always() && steps.source.outcome == 'success' }}")
    exact_line(after, '          cmp "$OUT/source-before.json" "$OUT/source-after.json"')
    exact_line(after, '          cmp "$OUT/source-before.json" "$OUT/source.json"')

    outcomes = step(text, OUTCOMES_STEP)
    exact_line(outcomes, "        if: ${{ always() && steps.reserve.outcome == 'success' }}")
    exact_line(outcomes, '          stage_outcomes = json.loads(os.environ["STAGE_OUTCOMES"])')
    exact_line(outcomes, '          storage_owner_passed = stage_outcomes.get("storage_owner", {}).get("outcome") == "success"')
    exact_line(outcomes, '              "steps": stage_outcomes,')
    exact_line(outcomes, '              "storage_owner_required": True,')
    exact_line(outcomes, '              "storage_owner_passed": storage_owner_passed,')
    exact_line(outcomes, '          (root / "sha256sums.txt").write_text("\\n".join(records) + "\\n")')
    exact_line(outcomes, "          if not storage_owner_passed:")
    exact_line(outcomes, '              raise SystemExit("required storage-owner native stage did not succeed")')
    require(outcomes.index('          if not storage_owner_passed:')
            > outcomes.index('          (root / "sha256sums.txt").write_text'),
            "failure must retain summaries and hashes before rejecting the gate")
    exact_line(outcomes, "          storage_components_passed = stage_outcomes.get(\"storage_components\", {}).get(\"outcome\") == \"success\"")
    exact_line(outcomes, "          sealed_python_passed = stage_outcomes.get(\"sealed_python\", {}).get(\"outcome\") == \"success\"")
    exact_line(outcomes, "              \"storage_components_required\": True,")
    exact_line(outcomes, "              \"storage_components_passed\": storage_components_passed,")
    exact_line(outcomes, "              \"sealed_python_required\": True,")
    exact_line(outcomes, "              \"sealed_python_passed\": sealed_python_passed,")
    exact_line(outcomes, "          if not storage_components_passed or not sealed_python_passed:")
    exact_line(outcomes, "              raise SystemExit(\"required storage convergence component stages did not succeed\")")
    require(outcomes.index("          if not storage_components_passed or not sealed_python_passed:")
            > outcomes.index('          (root / "sha256sums.txt").write_text'),
            "new stage failures must retain summaries and hashes before rejection")
    upload = step(text, UPLOAD_STEP)
    exact_line(upload, "        if: always()")
    exact_line(upload, "          if-no-files-found: error")
    exact_line(upload, "          retention-days: 30")


def exact_sealed_python_execution(output: str) -> dict:
    """Require the genuine verbose unittest transcript for all fixed controls."""
    case = re.compile(
        r"^(test_[a-z0-9_]+) \(test_llm_cell_sealed_worker_v1"
        r"\.SealedHandoffControls\.(test_[a-z0-9_]+)\) \.\.\. ok$"
    )
    summary = re.compile(r"^Ran (\d+) tests in \d+(?:\.\d+)?s$")
    names = []
    reported = []
    successes = 0
    state = "cases"
    for line in output.splitlines():
        if not line:
            continue
        match = case.fullmatch(line)
        if match:
            require(
                state == "cases" and match.group(1) == match.group(2),
                "sealed Python case identity or order changed",
            )
            names.append(match.group(1))
            continue
        if line == "-" * 70:
            require(state == "cases" and bool(names), "unexpected Python harness boundary")
            state = "summary"
            continue
        match = summary.fullmatch(line)
        if match:
            require(state == "summary" and not reported, "unexpected Python summary")
            reported.append(int(match.group(1)))
            state = "result"
            continue
        if line == "OK":
            require(state == "result", "unexpected Python success marker")
            successes += 1
            state = "complete"
            continue
        require(False, "unexpected sealed Python output: " + line)
    require(
        state == "complete"
        and successes == 1
        and reported == [21]
        and len(names) == len(set(names)) == 21
        and set(names) == set(SEALED_PYTHON_REQUIRED_NAMES),
        "sealed Python controls were omitted, replaced, duplicated, or not run",
    )
    return {
        "passed": 21,
        "failed": 0,
        "ignored_or_skipped": 0,
        "test_names": names,
        "scope": "actual memfd/SCM_RIGHTS/bootstrap/source/parser controls; no model execution",
    }


class CellStorageConvergenceCiControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW.read_text()

    def rejected(self, changed: str) -> None:
        self.assertNotEqual(changed, self.text)
        with self.assertRaises(ValueError):
            validate(changed)

    def test_current_source_preserves_complete_runtime_and_failure_seams(self) -> None:
        validate(self.text)

    def test_new_commands_cannot_be_omitted_moved_duplicated_or_stubbed(self) -> None:
        blocks = (step(self.text, PYTHON_STEP), step(self.text, NODE_STEP))
        lines = [line + "\n" for block in blocks for line in block.splitlines()
                 if ("version-retention-vector" in line or "storage-descriptor-vector" in line
                     or "storage-convergence-workflow-controls" in line
                     or 'native-storage-owner cargo' in line
                     or '"native-storage-$selector" cargo' in line
                     or "check_required_native_test.py" in line)]
        self.assertEqual(len(lines), 6)
        for line in lines:
            for change in ("", line * 2, line.replace("bash ", "true # bash ", 1)
                           if "bash " in line else line.replace("python3 ", "true # python3 ", 1),
                           line.replace("|| status=1", "|| true")):
                with self.subTest(line=line, change=change):
                    self.rejected(self.text.replace(line, change, 1))
            self.rejected(self.text.replace(line, "", 1) + line)

    def test_native_compile_only_skip_ignored_filters_and_release_changes_reject(self) -> None:
        for step_name in (NODE_STEP, DA_STEP):
            original = step(self.text, step_name)
            for replacement in (" --no-run -- --test-threads=1", " -- --skip missing --test-threads=1",
                                " -- --ignored --test-threads=1", " bogus -- --test-threads=1"):
                changed = original.replace(" -- --test-threads=1", replacement, 1)
                self.rejected(self.text.replace(original.rstrip("\n"), changed.rstrip("\n"), 1))
            changed = original.replace(" --release", "", 1)
            self.rejected(self.text.replace(original.rstrip("\n"), changed.rstrip("\n"), 1))
        self.rejected(self.text.replace("--lib store::storage_service:: --", "--lib store::storage_service::tests::version:: --", 1))

    def test_all_thirteen_exact_names_are_mandatory_unique_and_executed(self) -> None:
        for name in NODE_REQUIRED_NAMES:
            line = "            " + name + "\n"
            for change in ("", line * 2, "            # " + name + "\n", line.replace(name, name + "_substitute")):
                with self.subTest(name=name, change=change):
                    self.rejected(self.text.replace(line, change, 1))
        self.rejected(self.text.replace('for selector in "${required[@]}";', 'for selector in "${required[0]}";', 1))
        self.rejected(self.text.replace('"$OUT/native-storage-$selector.log" --test', '"$OUT/native-storage-owner.log" --test', 1))
        self.rejected(self.text.replace('"$selector" -- --exact --test-threads=1', '"$selector" -- --test-threads=1', 1))

    def test_native_and_python_failure_exits_and_source_guards_cannot_be_skipped(self) -> None:
        for name in (PYTHON_STEP, NODE_STEP):
            original = step(self.text, name)
            for changed in (original.replace('exit "$status"', "exit 0", 1),
                            original.replace("${{ always() &&", "${{ false &&", 1),
                            original.replace("        shell: bash", "        continue-on-error: true\n        shell: bash", 1),
                            original.replace("steps.preflight.outcome == 'success'", "true", 1)):
                self.rejected(self.text.replace(original.rstrip("\n"), changed.rstrip("\n"), 1))

    def test_both_source_axes_and_both_architecture_axes_remain_required(self) -> None:
        for old, replacements in (
            ("runner: [ubuntu-24.04, ubuntu-24.04-arm]", ("runner: [ubuntu-24.04]", "runner: [ubuntu-24.04-arm]")),
            ("source: [head, prospective-merge]", ("source: [head]", "source: [prospective-merge]")),
            ("ref: ${{ env.EXPECTED_SOURCE }}", ("ref: main",)),
            ("--kind \"$SOURCE_KIND\"", ("--kind head",)),
            ("--expected-head \"$EXPECTED_HEAD\"", ("--expected-head HEAD",)),
        ):
            for new in replacements:
                self.rejected(self.text.replace(old, new, 1))
        self.rejected(self.text.replace('            args+=(--expected-base "$EXPECTED_BASE" --expected-merge "$EXPECTED_MERGE")\n', "", 1))

    def test_matrix_exclusions_job_skips_and_different_step_sources_reject(self) -> None:
        anchor = "        source: [head, prospective-merge]\n"
        for addition in ("        exclude:\n          - runner: ubuntu-24.04-arm\n            source: prospective-merge\n",
                         "        include:\n          - runner: ubuntu-24.04\n            source: head\n"):
            self.rejected(self.text.replace(anchor, anchor + addition, 1))
        self.rejected(self.text.replace("  next-architecture:\n", "  next-architecture:\n    if: false\n", 1))
        self.rejected(self.text.replace("      fail-fast: false", "      fail-fast: true", 1))
        node = step(self.text, NODE_STEP)
        for addition in ("        working-directory: another-checkout\n", "        env:\n          RUSTFLAGS: altered\n"):
            changed = node.replace("        shell: bash\n", addition + "        shell: bash\n", 1)
            self.rejected(self.text.replace(node.rstrip("\n"), changed.rstrip("\n"), 1))

    def test_new_path_triggers_and_original_resource_bounds_are_not_dropped(self) -> None:
        for path in TRIGGERS:
            self.rejected(self.text.replace("      - " + path + "\n", "", 1))
        for old, new in (("cancel-in-progress: false", "cancel-in-progress: true"),
                         ("timeout-minutes: 90", "timeout-minutes: 91"),
                         ('CARGO_BUILD_JOBS: "2"', 'CARGO_BUILD_JOBS: "4"'),
                         ('RUST_TEST_THREADS: "1"', 'RUST_TEST_THREADS: "2"')):
            self.rejected(self.text.replace(old, new, 1))

    def test_storage_outcome_participates_in_final_summary_and_exit(self) -> None:
        for old, new in (
            ('stage_outcomes.get("storage_owner", {}).get("outcome") == "success"', "True"),
            ('              "storage_owner_required": True,\n', ""),
            ('              "storage_owner_passed": storage_owner_passed,\n', ""),
            ("          if not storage_owner_passed:", "          if False:"),
            ('              raise SystemExit("required storage-owner native stage did not succeed")', "              pass"),
            ("        id: storage_owner", "        id: uncounted_storage_owner"),
        ):
            self.rejected(self.text.replace(old, new, 1))

    def test_failed_source_and_logs_still_have_unconditional_final_observation(self) -> None:
        original = step(self.text, SOURCE_AFTER_STEP)
        changed = original.replace("always()", "success()", 1)
        self.rejected(self.text.replace(original.rstrip("\n"), changed.rstrip("\n"), 1))
        self.rejected(self.text.replace('          cmp "$OUT/source-before.json" "$OUT/source-after.json"\n', "", 1))
        upload = step(self.text, UPLOAD_STEP)
        for changed in (upload.replace("if: always()", "if: success()"),
                        upload.replace("if-no-files-found: error", "if-no-files-found: ignore"),
                        upload.replace("retention-days: 30", "retention-days: 1")):
            self.rejected(self.text.replace(upload.rstrip("\n"), changed.rstrip("\n"), 1))

    def test_new_component_and_python_commands_cannot_move_or_be_stubbed(self) -> None:
        for name in (COMPONENT_STEP, SEALED_STEP):
            original = step(self.text, name)
            lines = [
                line + "\n"
                for line in original.splitlines()
                if '"$OUT/run-command.sh"' in line or "scripts/ci/" in line
            ]
            self.assertEqual(len(lines), 2)
            for line in lines:
                stub = line.replace("bash ", "true # bash ", 1) if "bash " in line else line.replace("python3 ", "true # python3 ", 1)
                for change in ("", line * 2, stub, line.replace("|| status=1", "|| true")):
                    with self.subTest(step=name, line=line, change=change):
                        self.rejected(self.text.replace(line, change, 1))
                self.rejected(self.text.replace(line, "", 1) + line)

    def test_all_five_native_component_names_and_exact_execution_are_required(self) -> None:
        self.assertEqual(len(COMPONENT_REQUIRED_NAMES), 5)
        for name in COMPONENT_REQUIRED_NAMES:
            line = "            " + name + "\n"
            for change in ("", line * 2, "            # " + name + "\n", line.replace(name, name + "_substitute")):
                self.rejected(self.text.replace(line, change, 1))
        original = step(self.text, COMPONENT_STEP)
        for old, new in (
            ('"${required[@]}"', '"${required[0]}"'),
            (" --release", ""),
            ('"$selector" -- --exact --test-threads=1', '"$selector" --no-run -- --exact --test-threads=1'),
            ('"$selector" -- --exact --test-threads=1', '"$selector" -- --ignored --exact --test-threads=1'),
            ('"$selector" -- --exact --test-threads=1', '"$selector" -- --skip omitted --exact --test-threads=1'),
            ('"$selector" -- --exact --test-threads=1', '"$selector" -- --test-threads=1'),
            ('"$OUT/native-storage-component-$selector.log"', '"$OUT/p2p-complete.log"'),
        ):
            changed = original.replace(old, new, 1)
            self.rejected(self.text.replace(original.rstrip("\n"), changed.rstrip("\n"), 1))

    def test_new_stages_retain_source_guards_environment_and_failure_exits(self) -> None:
        for name in (COMPONENT_STEP, SEALED_STEP):
            original = step(self.text, name)
            for changed in (
                original.replace('exit "$status"', "exit 0", 1),
                original.replace("${{ always() &&", "${{ false &&", 1),
                original.replace("steps.source.outcome == 'success'", "true", 1),
                original.replace("steps.preflight.outcome == 'success'", "true", 1),
                original.replace("        shell: bash", "        continue-on-error: true\n        shell: bash", 1),
                original.replace("        shell: bash", "        working-directory: another-checkout\n        shell: bash", 1),
                original.replace("        shell: bash", "        env:\n          RUSTFLAGS: altered\n        shell: bash", 1),
            ):
                self.rejected(self.text.replace(original.rstrip("\n"), changed.rstrip("\n"), 1))
        self.rejected(self.text.replace("-p test_llm_cell_sealed_worker_v1.py -v", "-p missing_controls.py -v", 1))
        self.rejected(self.text.replace("--check-sealed-controls", "--help", 1))

    def test_new_outcomes_are_required_after_preserving_summary_and_hashes(self) -> None:
        for identifier in ("storage_components", "sealed_python"):
            for old, new in (
                (f'          {identifier}_passed = stage_outcomes.get("{identifier}", {{}}).get("outcome") == "success"', f"          {identifier}_passed = True"),
                (f'              "{identifier}_required": True,\n', ""),
                (f'              "{identifier}_passed": {identifier}_passed,\n', ""),
                ("        id: " + identifier, "        id: uncounted_" + identifier),
            ):
                self.rejected(self.text.replace(old, new, 1))
        final = "          if not storage_components_passed or not sealed_python_passed:"
        self.rejected(self.text.replace(final, "          if False:", 1))
        self.rejected(self.text.replace(final, final.replace(" or ", " and "), 1))
        self.rejected(self.text.replace('              raise SystemExit("required storage convergence component stages did not succeed")', "              pass", 1))

    @staticmethod
    def sealed_python_fixture() -> str:
        return "\n".join(
            name + " (test_llm_cell_sealed_worker_v1.SealedHandoffControls." + name + ") ... ok"
            for name in SEALED_PYTHON_REQUIRED_NAMES
        ) + "\n\n" + "-" * 70 + "\nRan 21 tests in 0.172s\n\nOK\n"

    def test_exact_sealed_python_execution_accepts_complete_frozen_roster(self) -> None:
        observation = exact_sealed_python_execution(self.sealed_python_fixture())
        self.assertEqual(observation["passed"], 21)
        self.assertEqual(set(observation["test_names"]), set(SEALED_PYTHON_REQUIRED_NAMES))
        self.assertEqual(observation["ignored_or_skipped"], 0)

    def test_sealed_python_partial_empty_skipped_failed_or_substituted_runs_reject(self) -> None:
        good = self.sealed_python_fixture()
        first = good.splitlines()[0] + "\n"
        for changed in (
            "",
            "Ran 0 tests in 0.000s\n\nOK\n",
            good.replace(first, "", 1),
            good.replace(first, first * 2, 1),
            good.replace(SEALED_PYTHON_REQUIRED_NAMES[0], "test_substituted", 2),
            good.replace(" ... ok", " ... skipped 'unsupported'", 1),
            good.replace(" ... ok", " ... FAIL", 1),
            good.replace("\nOK\n", "\nFAILED (failures=1)\n", 1),
        ):
            with self.subTest(output=changed):
                with self.assertRaises(ValueError):
                    exact_sealed_python_execution(changed)

    def test_sealed_python_counts_class_and_single_harness_are_required(self) -> None:
        good = self.sealed_python_fixture()
        for changed in (
            good.replace("Ran 21 tests", "Ran 20 tests", 1),
            good.replace("Ran 21 tests", "Ran 22 tests", 1),
            good.replace("SealedHandoffControls.", "AnotherClass.", 1),
            good.replace(SEALED_PYTHON_REQUIRED_NAMES[0] + ")", SEALED_PYTHON_REQUIRED_NAMES[1] + ")", 1),
            good + good,
            "OK\n" + good,
            good + "OK\n",
            good.replace("-" * 70 + "\n", "", 1),
        ):
            with self.subTest(output=changed):
                with self.assertRaises(ValueError):
                    exact_sealed_python_execution(changed)


    def test_original_eighteen_alone_and_each_added_control_omission_reject(self) -> None:
        good = self.sealed_python_fixture()
        added_names = ['test_project_source_compiler_preserves_original_annotation_semantics', 'test_failed_supervisor_cancels_connector_before_handshake', 'test_failed_supervisor_cancels_ready_wait_after_sealed_handoff']
        retained_only = good
        for name in added_names:
            line = name + " (test_llm_cell_sealed_worker_v1.SealedHandoffControls." + name + ") ... ok\n"
            self.assertEqual(retained_only.count(line), 1)
            retained_only = retained_only.replace(line, "", 1)
        retained_only = retained_only.replace("Ran 21 tests", "Ran 18 tests", 1)
        with self.assertRaises(ValueError):
            exact_sealed_python_execution(retained_only)
        for name in added_names:
            with self.subTest(added=name):
                line = name + " (test_llm_cell_sealed_worker_v1.SealedHandoffControls." + name + ") ... ok\n"
                missing = good.replace(line, "", 1).replace("Ran 21 tests", "Ran 20 tests", 1)
                with self.assertRaises(ValueError):
                    exact_sealed_python_execution(missing)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--check-sealed-controls":
        print(json.dumps(exact_sealed_python_execution(Path(sys.argv[2]).read_text()), sort_keys=True))
    else:
        unittest.main()
