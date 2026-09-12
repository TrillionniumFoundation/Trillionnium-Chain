#!/usr/bin/env python3
"""Keep the seven retired lane guards' applicable checks on current native CI.

M17: nightly/merge environment -> native environment; nightly/merge paths ->
unfiltered required baseline plus native fault paths; nightly soft failures ->
hard execution failures; nightly artifacts -> exact-source native artifacts;
testnet preflight -> native authority and offline prerequisites. The retired
workflows stay absent. The two generic script-reference guards are separate
real scanner fixtures. This structural contract is not execution evidence.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import shlex
import sys

ROOT = Path(__file__).resolve().parents[2]
BASELINE = ".github/workflows/trnm-required-baseline.yml"
RUNTIME = ".github/workflows/trnm-native-poco-runtime-fault-matrix-v1.yml"
QUICK = ".github/workflows/trnm-gate-quick-check.yml"
RETIRED = (
    ".github/workflows/rust-l1-nightly-health.yml",
    ".github/workflows/rust-l1-testnet-preflight.yml",
    ".github/workflows/trnm-merge-gates.yml",
    ".github/workflows/trnm-live-devnet-package.yml",
)
ENVIRONMENT = {
    "CI": "true", "TZ": "UTC", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
    "PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1",
    "CARGO_INCREMENTAL": "0", "CARGO_TERM_COLOR": "never",
}
SOURCE = "${{ github.event_name == 'pull_request' && github.event.pull_request.head.sha || github.sha }}"
JOBS = {"repository-truth", "protocol-contract", "fuzz-smoke", "external-evidence-contract", "rust-baseline"}
OFFLINE = {"TRNM_CARGO_OFFLINE_POLICY": "required", "CARGO_NET_OFFLINE": "true", "CARGO_CACHE_AUTO_CLEAN_FREQUENCY": "never"}


def cargo(arguments: str, command: str = "test") -> str:
    return f"cargo {command} --manifest-path trillionnium/Cargo.toml {arguments}"


# These are actual commands, not names or greppable fragments. Deliberately
# bind the retained execution matrices, independent of the separately evolving
# capability audit step. New commands in a matrix require a reviewed contract.
RUNTIME_MATRICES = {
    "Run deployed-lab and process recovery library matrix": (
        cargo("-p trnm-poco-node --features lab-validator-runtime-test-support --lib --locked --offline"),
    ),
    "Run finalization-intent SIGKILL matrix": (
        cargo("-p trnm-poco-node --features lab-validator-runtime-test-support --test finalization_intent_process_kill_matrix --locked --offline"),
    ),
    "Run timeout-signing SIGKILL matrix": (
        cargo("-p trnm-poco-node --features recovery-process-test-support --test timeout_signing_process_kill_matrix --locked --offline"),
    ),
    "Run G1 process-host and effect-driver end-to-end matrix": (
        cargo("-p trnm-poco-node --features g1-process-test-support --test g1_process_host_e2e --locked --offline"),
        cargo("-p trnm-poco-node --features g1-process-test-support --test effect_driver_process_e2e --locked --offline"),
    ),
    "Run candidate pacemaker, authenticated P2P and persistent replay authority bridge": tuple(
        cargo(f"-p {package} --features {feature} --all-targets --locked --offline" + (" -- -D warnings" if command == "clippy" else ""), command)
        for command in ("test", "clippy")
        for package, feature in (
            ("trnm-poco-node-io", "candidate-pacemaker,candidate-authenticated-p2p"),
            ("trnm-durable-file-adapters-v0", "candidate-peer-replay"),
            ("trnm-poco-node-host", "candidate-networked-authority"),
        )
    ),
    "Run signer, raw-key and replay-to-Core boundaries": (
        cargo("-p trnm-poco-node --features external-signer-runtime --test external_signer_runtime --locked --offline"),
        cargo("-p trnm-poco-node --test raw_key_boundary --locked --offline"),
        cargo("-p trnm-poco-node --features replay-to-core-coordinator-test-support --lib --locked --offline"),
    ),
    "Run manifest-bound process matrix": (
        cargo("-p trnm-poco-node --test g2_manifest_bound_process_v2 --features ai-v1-candidate --locked --offline"),
    ),
}


class ContractError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def block(text: str, key: str, indent: int) -> str:
    """Accept the repository's explicit block form; reject duplicate keys."""
    lines = text.splitlines()
    name = re.escape(key)
    pattern = re.compile(rf"^{' ' * indent}(?:{name}|\"{name}\"|'{name}'):")
    starts = [i for i, line in enumerate(lines) if pattern.match(line)]
    require(len(starts) == 1, f"expected one explicit {key} block at indent {indent}")
    require(re.fullmatch(rf"{' ' * indent}{re.escape(key)}:\s*(?:#.*)?", lines[starts[0]]) is not None,
            f"{key} must use an explicit block")
    body = []
    for line in lines[starts[0] + 1:]:
        if line.strip() and not line.lstrip().startswith("#") and len(line) - len(line.lstrip()) <= indent:
            break
        body.append(line)
    return "\n".join(body)


def scalar(text: str, key: str, indent: int) -> str:
    pattern = re.compile(rf"^{' ' * indent}{re.escape(key)}:\s*(.*?)\s*$", re.M)
    values = pattern.findall(text)
    require(len(values) == 1, f"missing or duplicate {key} scalar")
    value = values[0]
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    return value


def step(text: str, name: str) -> str:
    lines = text.splitlines()
    marker = f"      - name: {name}"
    starts = [i for i, line in enumerate(lines) if line == marker]
    require(len(starts) == 1, f"missing or duplicate step {name}")
    body = []
    for line in lines[starts[0] + 1:]:
        if line.strip() and len(line) - len(line.lstrip()) <= 6:
            break
        body.append(line)
    return "\n".join(body)


def tokens(text: str, expected: tuple[str, ...], label: str) -> None:
    # Commented-out commands must not satisfy the contract.
    active = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    for token in expected:
        require(token in active, f"{label}: missing {token}")


def hard_step(body: str, label: str) -> None:
    require(not re.search(r"^        if:", body, re.M), f"{label}: execution may not be conditional")
    tokens(body, ("set -euo pipefail",), label)
    require(not re.search(r"\bset\s+\+|\|\||\bexit\s+0\b", body),
            f"{label}: failure masking is forbidden")


def reject_environment_shadowing(text: str, label: str) -> None:
    lines = text.splitlines()
    protected = set(ENVIRONMENT) | {"TRNM_EXPECTED_SOURCE_SHA"}
    for index, line in enumerate(lines):
        match = re.match(r"^( {4}| {8})(?:env|\"env\"|'env'):\s*(.*?)\s*$", line)
        if not match:
            continue
        indent = len(match.group(1))
        require(not match.group(2) or match.group(2).startswith("#"), f"{label}: local env must use explicit block form")
        seen = set()
        for child in lines[index + 1:]:
            if not child.strip() or child.lstrip().startswith("#"):
                continue
            width = len(child) - len(child.lstrip())
            if width <= indent:
                break
            require(width == indent + 2 and ":" in child, f"{label}: unsupported local env shape")
            key = child.strip().split(":", 1)[0].strip("\"'")
            require(key not in seen, f"{label}: duplicate local env {key}")
            seen.add(key)
            require(key not in protected, f"{label}: local env shadows protected {key}")
            require(key not in OFFLINE or (label == "runtime" and indent == 4), f"{label}: local env shadows offline {key}")


def exact_matrix_commands(body: str, expected: tuple[str, ...], name: str) -> None:
    require(scalar(body, "working-directory", 8) == "trillionnium-chain", f"{name}: working directory differs")
    require(scalar(body, "run", 8) == "|", f"{name}: expected explicit run block")
    run = body.split("        run: |", 1)[1]
    # Join only shell line continuations; inspect complete argv of every
    # command. Echoing, commenting, filtering or deleting a test cannot pass.
    run = re.sub(r"\\[ \t]*\n[ \t]*", " ", run)
    commands = []
    for line in run.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line == "set -euo pipefail":
            continue
        try:
            commands.append(shlex.split(line, comments=True))
        except ValueError as error:
            raise ContractError(f"{name}: invalid shell command") from error
    require(commands == [shlex.split(command) for command in expected], f"{name}: complete execution commands differ")


def validate_contract(root: Path) -> dict[str, object]:
    for path in RETIRED:
        require(not (root / path).exists() and not (root / path).is_symlink(), f"retired lane returned: {path}")
    baseline = (root / BASELINE).read_text()
    scan_name = "Enforce native-only source and scanner regressions"
    scan_step = step(baseline, scan_name)
    hard_step(scan_step, scan_name)
    require(not re.search(r"^        continue-on-error:", scan_step, re.M),
            "native source scan must propagate failure")
    exact_matrix_commands(scan_step, (
        "python3 scripts/ci/test_native_consensus_only.py",
        "python3 scripts/ci/check_native_consensus_only.py",
    ), scan_name)
    runtime = (root / RUNTIME).read_text()
    quick = (root / QUICK).read_text()
    for label, text in (("baseline", baseline), ("runtime", runtime)):
        env = block(text, "env", 0)
        for key, value in ENVIRONMENT.items():
            require(scalar(env, key, 2) == value, f"{label}: deterministic {key} differs")
        require(scalar(env, "TRNM_EXPECTED_SOURCE_SHA", 2) == SOURCE, f"{label}: source identity differs")
        reject_environment_shadowing(text, label)
        for line in text.splitlines():
            if re.match(r"^\s+continue-on-error:", line):
                require(line.split(":", 1)[1].strip() == "false", f"{label}: soft failure promotion is forbidden")
    events = block(baseline, "on", 0)
    for event in ("pull_request", "push"):
        block(events, event, 2)
    require(not re.search(r"^\s+paths(?:-ignore)?:", events, re.M), "required baseline must cover every change")
    jobs = block(baseline, "jobs", 0)
    actual_jobs = set(re.findall(r"^  ([a-z][a-z0-9-]*):$", jobs, re.M))
    require(actual_jobs == JOBS, "required baseline job set differs")
    for job in JOBS:
        require(not re.search(r"^    if:", block(jobs, job, 2), re.M), f"required job {job} is conditional")
    paths = {
        RUNTIME, "scripts/ci/**", "config/consensus-mainline.json",
        "trillionnium/Cargo.toml", "trillionnium/Cargo.lock",
        "trillionnium/crates/trnm-consensus-*/**", "trillionnium/crates/trnm-native-*/**",
        "trillionnium/crates/trnm-poco-node*/**",
    }
    runtime_events = block(runtime, "on", 0)
    for event in ("pull_request", "push"):
        path_block = block(block(runtime_events, event, 2), "paths", 4)
        supplied = {value.strip().strip("\"'") for value in re.findall(r"^      - (.+)$", path_block, re.M)}
        require(paths <= supplied, f"runtime {event}: native source trigger coverage is incomplete")
    runtime_job = block(block(runtime, "jobs", 0), "runtime-fault-matrix", 2)
    for name in re.findall(r"^      - name: (.+)$", runtime_job, re.M):
        body = step(runtime_job, name)
        if name != "Verify Cargo offline inputs remained unchanged":
            require(not re.search(r"^        if:", body, re.M), f"runtime step {name} may not skip execution")
            require(not re.search(r"\bset\s+\+|\|\||\bexit\s+0\b", body), f"runtime step {name} masks failure")
    for name, expected in RUNTIME_MATRICES.items():
        exact_matrix_commands(step(runtime, name), expected, name)
    checkout = step(runtime, "Check out exact source without persisted credentials")
    require(scalar(checkout, "ref", 10) == "${{ env.TRNM_EXPECTED_SOURCE_SHA }}", "runtime checkout must use exact source")
    require(scalar(checkout, "fetch-depth", 10) == "0", "runtime checkout must retain history")
    require(scalar(checkout, "persist-credentials", 10) == "false", "runtime checkout may not retain credentials")
    binding = step(runtime, "Bind exact source tree and formatting")
    hard_step(binding, "runtime source binding")
    tokens(binding, ('test "$(git rev-parse HEAD)" = "${TRNM_EXPECTED_SOURCE_SHA}"', 'git rev-parse \'HEAD^{tree}\' > "$RUNNER_TEMP/runtime-fault-source-tree"'), "runtime source binding")
    runtime_env = block(runtime_job, "env", 4)
    for key, value in OFFLINE.items():
        require(scalar(runtime_env, key, 6) == value, f"runtime: offline {key} differs")
    toolchain = step(runtime, "Verify runner-provisioned Rust toolchain")
    readiness = step(runtime, "Verify Cargo offline cache readiness")
    authority = step(runtime, "Validate canonical authority before execution")
    for label, body in (("toolchain", toolchain), ("offline readiness", readiness), ("native authority", authority)):
        hard_step(body, label)
    tokens(toolchain, ("./scripts/ci/check_preprovisioned_rust_toolchain.sh",), "toolchain")
    tokens(readiness, ("./scripts/ci/check_cargo_offline_ready.sh", "trillionnium/Cargo.toml:trillionnium/Cargo.lock"), "offline readiness")
    tokens(authority, ("bash scripts/ci/check_canonical_development_plan.sh", "python3 scripts/ci/check_repository_truth_v1.py", "python3 scripts/ci/check_build_closures_v1.py --verify-cargo-tree", "bash scripts/ci/check_poco_bft_mainline_truth.sh --pre-cutover"), "native authority")
    require(runtime.index("name: Verify Cargo offline cache readiness") < runtime.index("name: Validate canonical authority before execution") < runtime.index("name: Run deployed-lab and process recovery library matrix"), "native prerequisites must precede execution")
    unchanged = step(runtime, "Verify Cargo offline inputs remained unchanged")
    require(scalar(unchanged, "if", 8) == "always()", "offline postcheck must run on failure")
    tokens(unchanged, ("./scripts/ci/check_cargo_offline_unchanged.sh",), "offline postcheck")
    execution = step(baseline, "Test the unified workspace feature graph with a hard deadline")
    hard_step(execution, "workspace execution")
    tokens(execution, ("cargo test --workspace --all-targets --locked --no-fail-fast", "| tee", "timeout --signal=TERM", 'git rev-parse HEAD > "$root/HEAD"', 'git rev-parse \'HEAD^{tree}\' > "$root/TREE"'), "workspace execution")
    evidence = step(runtime, "Build exact-source runtime evidence record")
    hard_step(evidence, "runtime evidence")
    tokens(evidence, ('out="$RUNNER_TEMP/runtime-fault-matrix"', '"source_commit": os.environ["TRNM_EXPECTED_SOURCE_SHA"]', '"source_tree": os.environ["SOURCE_TREE"]', 'sha256sum "$out/evidence.json"'), "runtime evidence")
    require(not re.search(r"\bls\s+-[^\n]*t\b", evidence), "runtime evidence may not select the latest file")
    runtime_upload = step(runtime, "Upload exact-source runtime evidence")
    require(not re.search(r"^        if:", runtime_upload, re.M), "runtime evidence upload must follow successful execution")
    require(scalar(runtime_upload, "name", 10) == "runtime-fault-matrix-${{ env.TRNM_EXPECTED_SOURCE_SHA }}", "runtime artifact source binding differs")
    require(scalar(runtime_upload, "path", 10) == "${{ runner.temp }}/runtime-fault-matrix/", "runtime artifact path differs")
    require(scalar(runtime_upload, "if-no-files-found", 10) == "error", "runtime artifact absence must fail")
    workspace_upload = step(baseline, "Retain exact-source workspace execution log including failure")
    require(scalar(workspace_upload, "if", 8) == "always()", "workspace failure evidence must be retained")
    require(scalar(workspace_upload, "name", 10) == "trnm-workspace-execution-${{ env.TRNM_EXPECTED_SOURCE_SHA }}", "workspace artifact source binding differs")
    require(scalar(workspace_upload, "path", 10) == "${{ runner.temp }}/trnm-rust-execution", "workspace artifact path differs")
    require(scalar(workspace_upload, "if-no-files-found", 10) == "error", "workspace artifact absence must fail")
    tokens(quick, ("python3 -B scripts/ci/check_required_baseline_closure_v1.py", "python3 -B scripts/ci/check_native_workflow_contract_v1.py", "python3 -B scripts/ci/test_native_workflow_contract_v1.py"), "quick-check native contract invocation")
    return {"result": "PASS", "schema": "trnm-native-workflow-contract-v1", "retired_lanes_absent": len(RETIRED), "retained_guard_purposes": 7, "required_jobs": sorted(JOBS), "runtime_matrix_commands": sum(map(len, RUNTIME_MATRICES.values())), "scope": "workflow-contract-only-not-execution-or-activation"}


def main() -> int:
    try:
        print(json.dumps(validate_contract(ROOT), sort_keys=True))
        return 0
    except (ContractError, OSError, UnicodeError) as error:
        print(f"native workflow contract failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
