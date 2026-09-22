#!/usr/bin/env python3
"""Fail-closed contract for the actor-independent required baseline."""

from __future__ import annotations

import json
import pathlib
import re
import sys
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]
POLICY = ROOT / "config/repository-policy-v1.json"

CONVERGENCE_COMMANDS = (
    "bash scripts/ci/check_canonical_development_plan.sh",
    "python3 scripts/ci/check_required_baseline_closure_v1.py",
)
CONVERGENCE_REQUIRED_PATHS = (
    "config/technical-convergence-v1.toml",
    "docs/architecture/TRNM_TECHNICAL_CONVERGENCE_V1.md",
    "docs/modules/README.md",
    "docs/modules/M00_FOUNDATION_PROTOCOL_TECHNICAL_SPEC_V1.md",
    "docs/modules/M01_CRYPTO_IDENTITY_TECHNICAL_SPEC_V1.md",
    "docs/modules/M02_CONSENSUS_CORE_TECHNICAL_SPEC_V1.md",
    "docs/modules/M03_SAFETY_SIGNER_TECHNICAL_SPEC_V1.md",
    "docs/modules/M04_P2P_TECHNICAL_SPEC_V1.md",
    "docs/modules/M05_TX_LIFECYCLE_TECHNICAL_SPEC_V1.md",
    "docs/modules/M06_EXECUTION_TECHNICAL_SPEC_V1.md",
    "docs/modules/M07_STATE_STORAGE_TECHNICAL_SPEC_V1.md",
    "docs/modules/M08_FINALITY_RECOVERY_TECHNICAL_SPEC_V1.md",
    "docs/modules/M09_DATA_AVAILABILITY_TECHNICAL_SPEC_V1.md",
    "docs/modules/M10_AGENT_MARKET_TECHNICAL_SPEC_V1.md",
    "docs/modules/M11_VERIFICATION_CHALLENGE_TECHNICAL_SPEC_V1.md",
    "docs/modules/M12_SETTLEMENT_TECHNICAL_SPEC_V1.md",
    "docs/modules/M13_STATE_SYNC_MIGRATION_TECHNICAL_SPEC_V1.md",
    "docs/modules/M14_CLIENT_PLATFORM_TECHNICAL_SPEC_V1.md",
    "docs/modules/M15_NODE_RELEASE_TECHNICAL_SPEC_V1.md",
    "docs/modules/M16_CONTROL_PLANE_TECHNICAL_SPEC_V1.md",
    "docs/modules/M17_EVIDENCE_SECURITY_TECHNICAL_SPEC_V1.md",
    "scripts/ci/check_plan_manifest_pins_v1.py",
    "scripts/ci/check_technical_convergence_v1.py",
    "scripts/ci/technical_convergence_contract_v1.py",
    "scripts/ci/technical_convergence_workflows_v1.py",
    "scripts/ci/technical_convergence_coverage_v1.py",
    "scripts/ci/test_technical_convergence_v1.py",
    "scripts/ci/check_module_coverage_core_v1.py",
)


class BaselineClosureError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BaselineClosureError(message)


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BaselineClosureError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=strict_object,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BaselineClosureError(
            f"{path.relative_to(ROOT)}: invalid JSON: {error}"
        ) from error
    require(isinstance(value, dict), f"{path.relative_to(ROOT)}: object required")
    return value


def require_tokens(text: str, tokens: tuple[str, ...], label: str) -> None:
    missing = [token for token in tokens if token not in text]
    require(not missing, f"{label}: missing required tokens: {missing}")


def named_step(text: str, name: str) -> str:
    marker = f"      - name: {name}\n"
    start = text.find(marker)
    require(start >= 0, f"required workflow step missing: {name}")
    tail = text[start + len(marker) :]
    candidates = [
        index
        for token in (
            "\n      - name:",
            "\n  protocol-contract:",
            "\n  fuzz-smoke:",
            "\n  external-evidence-contract:",
            "\n  rust-baseline:",
        )
        if (index := tail.find(token)) >= 0
    ]
    end = min(candidates) if candidates else len(tail)
    return tail[:end]


RUST_FEEDBACK_GUARD = "if: ${{ !cancelled() && steps.rust_source_inventory.outcome == 'success' }}"
RUST_FEEDBACK_STEPS = (
    'Rust format',
    'Test PCC1 strict proof and durable read boundary',
    'Test native candidate shard contract',
    'Verify explicit incremental epoch execution candidate',
    'Compile every active workspace target',
    'Verify codec2 epoch host and journal10',
    'Verify default and explicit candidate ownership boundaries',
    'Test durable transaction journal without production activation',
    'Test persistent peer-to-authority bridge without production activation',
    'Replay original-listener socket replacement without masking failure',
    'Test hosted candidate process recovery with explicit features',
    'Test the unified workspace feature graph with a hard deadline',
    'Test every active workspace package with bounded execution',
    'Verify production and candidate dependency closures with Cargo',
    'Compile, test, and lint external contract workspace',
    'Strict Clippy for executable safety and production boundaries',
    'Prove dedicated production-shaped CLI remains fail-closed',
    'Run critical library regressions',
    'Require Rust and contract validation to leave checkout clean',
    'Lint incremental epoch execution candidate',
    'Verify codec2-only epoch host',
    'Verify all-feature epoch Core',
    'Lint epoch Core and Safety candidates',
    'Test ownership and state-sync compile-fail contracts',
    'Test durable authority library',
    'Test persistent authority host',
    'Test native handoff host composition',
    'Test predecessor Safety journal',
    'Test persistent authority coordinator',
    'Lint persistent authority composition',
    'Verify node epoch runtime shards',
    'Test node epoch runtime compile-fail contracts',
    'Lint node epoch runtime candidates',
    'Test locked Cargo archive collector',
    'Collect cached public Cargo inputs for offline diagnosis',
)


def validate_rust_feedback(workflow: str) -> None:
    require(workflow.count("  rust-baseline:\n") == 1, "exactly one Rust baseline required")
    body = workflow.split("  rust-baseline:\n", 1)[1]
    body = re.split(r"(?m)^  [A-Za-z0-9_-]+:\s*$", body, maxsplit=1)[0]
    names = re.findall(r"(?m)^      - name: (.+)$", body)
    require(len(names) == len(set(names)), "duplicate Rust step name")
    require("continue-on-error" not in body, "Rust failure masking is forbidden")
    admission = named_step(body, "Bind Cargo target inventory to the exact clean source")
    require(re.search(r"(?m)^        id: rust_source_inventory$", admission) is not None,
            "Rust source admission identity missing")
    require(not re.search(r"(?m)^        if:", admission), "Rust source admission may not be conditional")
    require(admission.count("        id: rust_source_inventory\n") == 1,
            "duplicate source admission identity")
    require("--source-only" not in admission and
            '          python3 scripts/ci/check_cargo_source_inventory_v1.py ' in admission and
            '--expected-commit "$TRNM_EXPECTED_SOURCE_SHA"' in admission,
            "initial source admission must run the full independently pinned inventory")
    for name in RUST_FEEDBACK_STEPS:
        step = named_step(body, name)
        conditions = re.findall(r"(?m)^        (if: .+)$", step)
        require(conditions == [RUST_FEEDBACK_GUARD], f"{name}: independent failure/cancellation guard changed")
        script = "../scripts/ci/check_cargo_source_inventory_v1.py" if "working-directory: trillionnium\n" in step else "scripts/ci/check_cargo_source_inventory_v1.py"
        # The fixed workflow checks tracked bytes before executing the mutable
        # checkout's checker. A failed test must not replace its own fence.
        expected = (
            '          set -euo pipefail\n'
            '          git --no-replace-objects diff --exit-code "$TRNM_EXPECTED_SOURCE_SHA" --\n'
            '          python3 ' + script
            + ' --source-only --expected-commit "$TRNM_EXPECTED_SOURCE_SHA" >/dev/null\n'
        )
        require("        run: |\n" + expected in step, f"{name}: initial source fence missing")
    require(body.index("      - name: Compile every active workspace target\n")
            < body.index("      - name: Test PCC1 strict proof and durable read boundary\n"),
            "full compilation must precede runtime campaigns")
    require(body.index("      - name: Strict Clippy for executable safety and production boundaries\n")
            < body.index("      - name: Verify explicit incremental epoch execution candidate\n"),
            "strict lint must precede slow runtime campaigns")


def main() -> int:
    policy = load_json(POLICY)
    workflow_relative = policy.get("baseline_workflow")
    require(
        isinstance(workflow_relative, str) and workflow_relative,
        "baseline_workflow path missing",
    )
    workflow_path = ROOT / workflow_relative
    require(
        workflow_path.is_file(),
        f"baseline workflow missing: {workflow_relative}",
    )
    workflow = workflow_path.read_text(encoding="utf-8")
    validate_rust_feedback(workflow)

    required_checks = policy.get("required_check_names")
    require(
        isinstance(required_checks, list)
        and required_checks
        and all(isinstance(item, str) and item for item in required_checks),
        "required_check_names missing",
    )
    require(
        len(set(required_checks)) == len(required_checks),
        "required check names duplicate",
    )
    for check in required_checks:
        require(
            len(
                re.findall(
                    rf"(?m)^\s+name:\s*{re.escape(check)}\s*$",
                    workflow,
                )
            )
            == 1,
            f"required job name missing or duplicated: {check}",
        )

    header = workflow.split("jobs:", 1)[0]
    require(
        re.search(r"(?m)^\s*pull_request:\s*$", header) is not None,
        "baseline workflow must run on every pull request",
    )
    require(
        "paths:" not in header,
        "baseline pull_request trigger may not use path filters",
    )
    require(
        "self-hosted" not in workflow,
        "required baseline may not depend on self-hosted runners",
    )
    require(
        "github.actor" not in workflow
        and "github.triggering_actor" not in workflow,
        "required baseline may not contain actor allowlists",
    )
    require(
        workflow.count("runs-on: ubuntu-24.04") == len(required_checks),
        "every required job must use the pinned hosted runner",
    )
    require(
        "runs-on: ubuntu-latest" not in workflow,
        "moving ubuntu-latest is forbidden",
    )

    exact_source = (
        "TRNM_EXPECTED_SOURCE_SHA: ${{ github.event_name == 'pull_request' && "
        "github.event.pull_request.head.sha || github.sha }}"
    )
    require(exact_source in workflow, "exact pull-request head binding missing")
    require(
        workflow.count("ref: ${{ env.TRNM_EXPECTED_SOURCE_SHA }}")
        == len(required_checks),
        "every required job must check out the exact source",
    )
    require(
        workflow.count("persist-credentials: false") == len(required_checks),
        "every required job must disable persisted checkout credentials",
    )
    require(
        workflow.count(
            'run: test "$(git rev-parse HEAD)" = "${TRNM_EXPECTED_SOURCE_SHA}"'
        )
        == len(required_checks),
        "every required job must assert exact source identity",
    )

    require(
        workflow.count("node scripts/test-playwright-installer.mjs") == 2,
        "Playwright installer contract must run on exact source and prospective merge",
    )
    require(
        workflow.count("python3 scripts/ci/test_codeql_default_setup_v1.py") == 2,
        "CodeQL default-setup contract must run on exact source and prospective merge",
    )

    require_tokens(
        workflow,
        (
            *CONVERGENCE_COMMANDS,
            "python3 scripts/ci/check_node_decomposition_v1.py",
            "python3 scripts/ci/check_build_closures_v1.py",
            "cargo test --workspace --all-targets --locked",
            "cargo check --manifest-path contracts/Cargo.toml --workspace --all-targets --locked",
            "cargo test --manifest-path contracts/Cargo.toml --workspace --all-targets --locked",
            "cargo clippy --manifest-path contracts/Cargo.toml --workspace --all-targets --locked -- -D warnings",
            "cargo test -p trnm-production-adapter-conformance-v0 --all-targets --locked",
            "cargo test -p trnm-durable-file-adapters-v0 --all-targets --locked",
            "-p trnm-poco-node-cli --bin trnm-poco-node-cli",
            "--locked -- status",
            "--locked -- start",
            '"start_permitted":false',
        ),
        "required baseline closure",
    )

    exact_step = named_step(
        workflow,
        "Validate repository, development, module, node, and blocker truth",
    )
    native_shard_step = named_step(
        workflow,
        "Verify explicit incremental epoch execution candidate",
    )
    native_shard_tests = named_step(
        workflow,
        "Test native candidate shard contract",
    )
    require_tokens(
        native_shard_tests,
        ("python3 ../scripts/ci/test_native_candidate_shards_v1.py",),
        "native candidate shard contract tests",
    )
    require_tokens(
        native_shard_step,
        (
            "python3 ../scripts/ci/run_native_candidate_shards_v1.py",
            "--deadline-seconds 900",
        ),
        "native candidate shard execution",
    )
    native_shard_artifact = named_step(
        workflow,
        "Retain exact-source native candidate shard evidence",
    )
    require_tokens(
        native_shard_artifact,
        (
            "trnm-native-candidate-shards-${{ env.TRNM_EXPECTED_SOURCE_SHA }}",
            "${{ runner.temp }}/trnm-native-candidate-shards",
            "if-no-files-found: error",
        ),
        "native candidate shard evidence",
    )
    prospective_step = named_step(
        workflow,
        "Run separately bound prospective-merge regressions",
    )
    mutant_step = named_step(
        workflow,
        "Run retained module-documentation false-pass mutants",
    )
    security_step = named_step(
        workflow,
        "Run repository security-boundary regressions",
    )
    compile_step = named_step(workflow, "Compile Python CI tooling")
    epoch_step = named_step(workflow, "Verify node epoch runtime shards")
    require_tokens(epoch_step, (
        "python3 ../scripts/ci/run_native_candidate_shards_v1.py",
        "--suite node-epoch",
        "--deadline-seconds 300",
        '--evidence-dir "$RUNNER_TEMP/trnm-node-epoch-shards"',
    ), "explicit epoch runtime test closure")
    # Independent execution, not merely relocated text in a failing run block.
    for name, command in (
        ("Lint incremental epoch execution candidate", "cargo clippy -p trnm-native-execution-v0"),
        ("Test predecessor Safety journal", "cargo test -p trnm-consensus-safety-store --features test-fixtures,candidate-epoch-host-v1 --test epoch_journal_v1 --locked"),
        ("Test node epoch runtime compile-fail contracts", "cargo test -p trnm-poco-node --features epoch-runtime-candidate --doc --locked"),
        ("Lint node epoch runtime candidates", "cargo clippy -p trnm-poco-node --features epoch-runtime-test-fixtures --all-targets --locked -- -D warnings"),
    ):
        require_tokens(named_step(workflow, name), (command,), name)
    safety_epoch_step = named_step(workflow, "Verify codec2 epoch host and journal10")
    require_tokens(safety_epoch_step, (
        "python3 ../scripts/ci/run_native_candidate_shards_v1.py",
        "--suite safety-epoch", "--deadline-seconds 900",
    ), "Safety epoch shard execution")
    safety_epoch_artifact = named_step(workflow, "Retain exact-source Safety epoch shard evidence")
    require_tokens(safety_epoch_artifact, (
        "trnm-safety-epoch-shards-${{ env.TRNM_EXPECTED_SOURCE_SHA }}",
        "${{ runner.temp }}/trnm-safety-epoch-shards",
        "if-no-files-found: error",
    ), "Safety epoch shard evidence")
    node_epoch_artifact = named_step(workflow, "Retain exact-source node epoch shard evidence")
    require_tokens(node_epoch_artifact, (
        "trnm-node-epoch-shards-${{ env.TRNM_EXPECTED_SOURCE_SHA }}",
        "${{ runner.temp }}/trnm-node-epoch-shards",
        "if-no-files-found: error",
    ), "node epoch shard evidence")
    require_tokens(exact_step, CONVERGENCE_COMMANDS + ("python3 scripts/ci/test_build_closures_v1.py",), "exact-source convergence closure")
    require_tokens(
        prospective_step,
        CONVERGENCE_COMMANDS + ("python3 scripts/ci/test_build_closures_v1.py",),
        "prospective-merge convergence closure",
    )
    require_tokens(
        mutant_step,
        (
            "python3 scripts/ci/test_main_protection_v1.py",
            "python3 scripts/ci/test_codeql_default_setup_v1.py",
        ),
        "required baseline retained mutants",
    )
    require_tokens(
        security_step,
        (
            "python3 scripts/min_faucet_server_test.py",
            "scripts/poco-fleet/stage0_direct_seven_bundle_v1_test.py",
            "--check-ordinary-advance --self-test-ordinary-advance-mutants",
            "--check-trust-path --self-test-trust-path-mutants",
        ),
        "required baseline security regressions",
    )
    for path in (
        "scripts/ci/test_build_closures_v1.py",
        "scripts/ci/check_plan_manifest_pins_v1.py",
        "scripts/ci/check_technical_convergence_v1.py",
        "scripts/ci/test_technical_convergence_v1.py",
        "scripts/ci/check_required_baseline_closure_v1.py",
        "scripts/admin/apply_main_protection_v1.py",
        "scripts/admin/apply_codeql_default_setup_v1.py",
        "scripts/ci/test_main_protection_v1.py",
        "scripts/ci/test_codeql_default_setup_v1.py",
        "scripts/min_faucet_server.py",
        "scripts/min_faucet_server_test.py",
        "scripts/poco-fleet/stage0_direct_seven_bundle_v1_test.py",
        "scripts/ci/check_poco_ai_native_v1_order_finality_light_client.py",
    ):
        require(path in compile_step, f"Python compile closure missing {path}")

    clippy_packages = (
        "trnm-state",
        "trnm-consensus-types",
        "trnm-consensus-crypto",
        "trnm-consensus-core",
        "trnm-consensus-safety-rules",
        "trnm-consensus-safety-store",
        "trnm-consensus-signer-journal",
        "trnm-native-application",
        "trnm-native-application-sqlite",
        "trnm-native-execution-v0",
        "trnm-durable-file-adapters-v0",
        "trnm-tx-lifecycle-v0",
        "trnm-state-sync-v0",
        "trnm-migration-v0",
        "trnm-control-plane-v0",
        "trnm-release-bundle-v0",
        "trnm-node-boundary-v0",
        "trnm-poco-node-production-v0",
        "trnm-production-adapter-conformance-v0",
        "trnm-poco-node",
        "trnm-poco-node-authority",
        "trnm-poco-node-io",
        "trnm-poco-node-host",
        "trnm-poco-node-cli",
    )
    for package in clippy_packages:
        require(
            package in workflow,
            f"strict Clippy package missing: {package}",
        )

    rust_job = re.search(
        r"(?ms)^  rust-baseline:\n(?P<body>.*)\Z",
        workflow,
    )
    require(rust_job is not None, "rust-baseline job missing")
    timeout = re.search(
        r"(?m)^\s{4}timeout-minutes:\s*(\d+)\s*$",
        rust_job.group("body"),
    )
    require(
        timeout is not None and int(timeout.group(1)) >= 120,
        "rust-baseline timeout too small",
    )

    required_paths = policy.get("required_paths")
    require(
        isinstance(required_paths, list),
        "repository policy required_paths missing",
    )
    closure_paths = (
        ".github/workflows/trnm-required-baseline.yml",
        "config/build-closures-v1.toml",
        "config/node-decomposition-v1.toml",
        "docs/architecture/TRNM_POCO_NODE_DECOMPOSITION_V1.md",
        "scripts/ci/check_build_closures_v1.py",
        "scripts/ci/check_node_decomposition_v1.py",
        "scripts/ci/check_required_baseline_closure_v1.py",
        "config/codeql-default-setup-v1.json",
        "docs/runbooks/TRNM_CODEQL_DEFAULT_SETUP_V1.md",
        "scripts/admin/apply_codeql_default_setup_v1.py",
        "scripts/ci/test_codeql_default_setup_v1.py",
        *CONVERGENCE_REQUIRED_PATHS,
        "trillionnium/crates/trnm-control-plane-v0/Cargo.toml",
        "trillionnium/crates/trnm-durable-file-adapters-v0/Cargo.toml",
        "trillionnium/crates/trnm-migration-v0/Cargo.toml",
        "trillionnium/crates/trnm-node-boundary-v0/Cargo.toml",
        "trillionnium/crates/trnm-poco-node-production-v0/Cargo.toml",
        "trillionnium/crates/trnm-production-adapter-conformance-v0/Cargo.toml",
        "trillionnium/crates/trnm-release-bundle-v0/Cargo.toml",
        "trillionnium/crates/trnm-state-sync-v0/Cargo.toml",
        "trillionnium/crates/trnm-tx-lifecycle-v0/Cargo.toml",
    )
    for path in closure_paths:
        require(
            path in required_paths,
            f"repository policy does not require {path}",
        )
        require(
            (ROOT / path).exists(),
            f"required closure input missing: {path}",
        )

    report = {
        "schema": "trnm-required-baseline-closure-v1",
        "required_checks": required_checks,
        "actor_independent": True,
        "hosted_runner": "ubuntu-24.04",
        "full_workspace_all_targets_test": True,
        "contract_workspace_checked": True,
        "node_decomposition_required": True,
        "technical_convergence_required": True,
        "technical_convergence_exact_source": True,
        "technical_convergence_prospective_merge": True,
        "technical_convergence_mutants_retained": True,
        "repository_core_overlay_required": True,
        "strict_clippy_package_count": len(clippy_packages),
        "production_candidate": False,
        "production_consensus_activation": False,
        "release_ready": False,
        "result": "PASS",
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BaselineClosureError as error:
        print(f"required baseline closure failed: {error}", file=sys.stderr)
        raise SystemExit(2)
