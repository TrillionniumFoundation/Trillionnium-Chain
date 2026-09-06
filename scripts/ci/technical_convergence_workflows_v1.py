#!/usr/bin/env python3
"""Required-baseline and complete workflow trust-domain checks."""
from __future__ import annotations

import pathlib
import re
from typing import Any, Callable

BASELINE = pathlib.Path(".github/workflows/trnm-required-baseline.yml")
WORKFLOWS = pathlib.Path(".github/workflows")
COMMANDS = (
    "bash scripts/ci/check_canonical_development_plan.sh",
    "python3 scripts/ci/check_plan_manifest_pins_v1.py",
    "python3 scripts/ci/check_technical_convergence_v1.py",
    "python3 scripts/ci/test_technical_convergence_v1.py",
    "python3 scripts/ci/check_module_coverage_v1.py",
    "python3 scripts/ci/check_required_baseline_closure_v1.py",
)
PROHIBITED = (
    ".github/workflows/trnm-plan-v2-repository-autofix-20260906b.yml",
    ".github/workflows/trnm-rustfmt-export-v1.yml",
    ".github/workflows/trnm-host-compile-repair-once.yml",
    ".github/workflows/trnm-plan-v2-contract-clippy-repair-once-20260906c.yml",
    ".github/workflows/trnm-plan-v2-contract-lint-finalizer-once.yml",
)
CREDENTIAL = re.compile(
    r"(?:secrets\.[A-Za-z0-9_]+|github\.token|GITHUB_TOKEN)|\bsecrets\s*:\s*inherit\b",
    re.IGNORECASE,
)
MUTATION = (
    re.compile(r"\bgit\s+(?:-[^\s]+\s+)*push\b", re.I),
    re.compile(r"\bgh\s+pr\s+merge\b", re.I),
    re.compile(r"\bgh\s+api\b[^\n]*(?:(?:--method|-X)\s*(?:POST|PUT|PATCH|DELETE)|-f\s)", re.I),
    re.compile(r"\bcurl\b[^\n]*(?:-X|--request)\s*(?:POST|PUT|PATCH|DELETE)[^\n]*api\.github\.com", re.I),
    re.compile(r"actions/create-github-app-token", re.I),
    re.compile(r"peter-evans/create-pull-request", re.I),
    re.compile(r"ad-m/github-push-action", re.I),
    re.compile(r"stefanzweifel/git-auto-commit-action", re.I),
)


def uncommented(text: str) -> list[str]:
    return [line for line in text.splitlines() if not line.lstrip().startswith("#")]


def block(lines: list[str], key: str, indent: int = 0) -> tuple[str, list[str]] | None:
    pattern = re.compile(rf"^{' ' * indent}{re.escape(key)}:\s*(.*?)\s*$")
    for index, line in enumerate(lines):
        match = pattern.match(line)
        if not match:
            continue
        body: list[str] = []
        for candidate in lines[index + 1:]:
            if not candidate.strip():
                body.append(candidate); continue
            if len(candidate) - len(candidate.lstrip(" ")) <= indent:
                break
            body.append(candidate)
        return match.group(1), body
    return None


def events(text: str, require: Callable[[bool, str], None]) -> set[str]:
    found = block(uncommented(text), "on")
    require(found is not None, "workflow missing top-level on")
    inline, body = found
    result = set(re.findall(r"[A-Za-z_][A-Za-z0-9_-]*", inline)) if inline and inline not in {"{}", "[]"} else set()
    for line in body:
        match = re.match(r"^\s{2}([A-Za-z_][A-Za-z0-9_-]*):", line)
        if match:
            result.add(match.group(1))
    return result


def permission_blocks(text: str) -> list[tuple[int, str, list[str]]]:
    lines = uncommented(text); result = []
    for index, line in enumerate(lines):
        match = re.match(r"^( *)(?:permissions):\s*(.*?)\s*$", line)
        if not match:
            continue
        indent = len(match.group(1))
        if indent not in {0, 4}:
            continue
        body: list[str] = []
        for candidate in lines[index + 1:]:
            if not candidate.strip():
                body.append(candidate); continue
            if len(candidate) - len(candidate.lstrip(" ")) <= indent:
                break
            body.append(candidate)
        result.append((indent, match.group(2), body))
    return result


def modes(inline: str, body: list[str], label: str, require: Callable[[bool, str], None]) -> dict[str, str]:
    inline = inline.split("#", 1)[0].strip().lower()
    if inline:
        require(inline in {"{}", "read-all", "write-all"}, f"{label}: invalid permissions")
        return {} if inline == "{}" else {"*": inline.removesuffix("-all")}
    result: dict[str, str] = {}
    for line in body:
        value = line.split("#", 1)[0].strip()
        if not value:
            continue
        match = re.fullmatch(r"([A-Za-z][A-Za-z0-9-]*):\s*(read|write|none)", value)
        require(match is not None, f"{label}: unparseable permissions entry")
        key, mode = match.groups()
        require(key not in result, f"{label}: duplicate permissions scope")
        result[key] = mode
    require(bool(result), f"{label}: empty permissions must use {{}}")
    return result


def named_step(text: str, name: str, require: Callable[[bool, str], None]) -> str:
    marker = f"      - name: {name}\n"; start = text.find(marker)
    require(start >= 0, f"required baseline missing step {name!r}")
    tail = text[start + len(marker):]
    stops = [tail.find(token) for token in ("\n      - name:", "\n  protocol-contract:", "\n  fuzz-smoke:", "\n  external-evidence-contract:", "\n  rust-baseline:") if tail.find(token) >= 0]
    return tail[:min(stops) if stops else len(tail)]


def validate(root: pathlib.Path, contract: dict[str, Any], require: Callable[[bool, str], None]) -> dict[str, Any]:
    ci = contract.get("ci")
    require(isinstance(ci, dict), "CI contract missing")
    expected_flags = {
        "exact_head_required": True, "prospective_merge_required": True,
        "non_empty_execution_required": True, "terminal_success_required": True,
        "skipped_or_action_required_is_success": False,
        "candidate_code_with_repository_write_token_forbidden": True,
        "persistent_runner_with_candidate_write_token_forbidden": True,
        "independent_final_push_review_required": True,
    }
    for key, value in expected_flags.items():
        require(ci.get(key) is value, f"CI safeguard drift: {key}")
    require(tuple(ci.get("commands", ())) == COMMANDS, "CI command set drift")

    supply = contract.get("supply_chain")
    require(isinstance(supply, dict), "supply-chain policy missing")
    require(tuple(supply.get("prohibited_candidate_workflows", ())) == PROHIBITED, "prohibited workflow set drift")
    for key, value in {
        "publisher_executes_candidate_code": False,
        "publisher_requires_expected_head_compare_and_swap": True,
        "release_requires_signed_artifact_manifest": True,
        "release_requires_sbom_and_provenance": True,
    }.items():
        require(supply.get(key) is value, f"supply-chain safeguard drift: {key}")
    for relative in PROHIBITED:
        require(not (root / relative).exists(), f"prohibited workflow present: {relative}")

    baseline = (root / BASELINE).read_text(encoding="utf-8")
    exact = named_step(baseline, "Validate repository, development, module, node, and blocker truth", require)
    merge = named_step(baseline, "Run separately bound prospective-merge regressions", require)
    mutants = named_step(baseline, "Run retained module-documentation false-pass mutants", require)
    compile_step = named_step(baseline, "Compile Python CI tooling", require)
    for command in COMMANDS:
        require(command in exact, f"exact-source baseline missing {command}")
        require(command in merge, f"prospective-merge baseline missing {command}")
    require(COMMANDS[3] in mutants, "convergence mutants not retained")
    for path in ("check_plan_manifest_pins_v1.py", "check_technical_convergence_v1.py", "test_technical_convergence_v1.py", "check_required_baseline_closure_v1.py"):
        require(path in compile_step, f"Python compile closure missing {path}")

    workflow_paths = sorted(path for path in (root / WORKFLOWS).iterdir() if path.is_file() and path.suffix in {".yml", ".yaml"})
    require(bool(workflow_paths), "workflow inventory empty")
    report = {"workflow_count": len(workflow_paths), "pull_request_workflow_count": 0, "self_hosted_workflow_count": 0, "checkout_step_count": 0}
    for path in workflow_paths:
        relative = path.relative_to(root).as_posix(); text = path.read_text(encoding="utf-8"); active = "\n".join(uncommented(text))
        event_set = events(text, require); pr = "pull_request" in event_set
        require("pull_request_target" not in event_set, f"{relative}: pull_request_target forbidden")
        report["pull_request_workflow_count"] += int(pr)
        blocks = permission_blocks(text); top = [item for item in blocks if item[0] == 0]
        if pr:
            require(len(top) == 1, f"{relative}: PR workflow needs explicit top-level permissions")
        write = any("write" in modes(item[1], item[2], relative, require).values() for item in blocks)
        require(not write, f"{relative}: write permission forbidden")
        require(not CREDENTIAL.search(active), f"{relative}: repository credential reference forbidden")
        hits = [item.pattern for item in MUTATION if item.search(active)]
        require(not hits, f"{relative}: repository mutation forbidden: {hits}")
        require("persist-credentials: true" not in active, f"{relative}: checkout persists credentials")
        self_hosted = re.search(r"(?m)^\s{4}runs-on:\s*.*\bself-hosted\b", active) is not None
        report["self_hosted_workflow_count"] += int(self_hosted)
        report["checkout_step_count"] += active.count("actions/checkout@")
        if pr and self_hosted:
            top_modes = modes(top[0][1], top[0][2], relative, require)
            require(all(value in {"read", "none"} for value in top_modes.values()), f"{relative}: self-hosted PR not read-only")
    require(report["pull_request_workflow_count"] > 0, "no PR workflow inspected")
    report.update({"candidate_privileged_job_count": 0, "repository_mutation_marker_count": 0, "custom_repository_credential_count": 0, "pull_request_target_count": 0})
    return report
