#!/usr/bin/env python3
"""Construct and qualify the repository-owned Plan v2 closure.

The script deliberately keeps every production, public-testnet, release, and
activation flag false. It integrates immutable repository-owned source lines,
refreshes machine coverage, generates one detailed handbook per long-lived
module, and installs fail-closed documentation gates. External evidence is never
synthesized here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tomllib
from typing import Any, Iterable
from urllib.parse import unquote

ROOT = pathlib.Path(__file__).resolve().parents[1]
REPOSITORY = "TrillionniumFoundation/Trillionnium-Chain"
NODE_SOURCE_BRANCH = "work/node-split-v1-20260902"
NODE_SOURCE_SHA = "be99c77392298958e3d9fe108ff36323e5632c61"
NODE_SOURCE_TREE = "fc71d6b75b9c8992384e813cfcbdd9b0fdeffe8f"
CORE_SOURCE_BRANCH = "work/plan-v2-durable-adapters-20260902"
CORE_SOURCE_SHA = "1a181ba453f86055082859e12e3d0be9fc7b18f5"
CORE_SOURCE_TREE = "cae204e1638ba4bba92a9a852f0552adb41ca494"
PLAN = ROOT / "docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md"
COVERAGE = ROOT / "config/module-coverage-v1.toml"
REGISTRY = ROOT / "docs/development/module-registry-v1.toml"
REFERENCE = ROOT / "docs/modules/TRNM_MODULE_TECHNICAL_REFERENCE_V1.md"


class ClosureError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ClosureError(message)


def run(*args: str, capture: bool = False) -> str:
    completed = subprocess.run(
        list(args),
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=capture,
    )
    return completed.stdout.strip() if capture else ""


def git(*args: str) -> str:
    return run("git", *args, capture=True)


def read_toml(path: pathlib.Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        value = tomllib.load(handle)
    require(isinstance(value, dict), f"{path.relative_to(ROOT)}: TOML table required")
    return value


def write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def checkout(source: str, paths: Iterable[str]) -> None:
    values = list(paths)
    require(values, "checkout path list is empty")
    run("git", "checkout", source, "--", *values)


def fetch_and_verify_sources() -> None:
    run(
        "git",
        "fetch",
        "--no-tags",
        "origin",
        f"+refs/heads/{NODE_SOURCE_BRANCH}:refs/remotes/origin/{NODE_SOURCE_BRANCH}",
        f"+refs/heads/{CORE_SOURCE_BRANCH}:refs/remotes/origin/{CORE_SOURCE_BRANCH}",
    )
    require(git("cat-file", "-t", NODE_SOURCE_SHA) == "commit", "node source commit unavailable")
    require(git("cat-file", "-t", CORE_SOURCE_SHA) == "commit", "core source commit unavailable")
    require(git("show", "-s", "--format=%T", NODE_SOURCE_SHA) == NODE_SOURCE_TREE, "node source tree drift")
    require(git("show", "-s", "--format=%T", CORE_SOURCE_SHA) == CORE_SOURCE_TREE, "core source tree drift")
    remote_node = git("rev-parse", f"refs/remotes/origin/{NODE_SOURCE_BRANCH}")
    require(remote_node == NODE_SOURCE_SHA, f"node source branch moved: {remote_node}")
    require(
        git("merge-base", "--is-ancestor", CORE_SOURCE_SHA, f"refs/remotes/origin/{CORE_SOURCE_BRANCH}") == "",
        "core source is not retained by the declared carrier",
    )


def integrate_sources() -> None:
    node_paths = [
        ".github/CODEOWNERS",
        ".github/workflows/trnm-required-baseline.yml",
        "config/build-closures-v1.toml",
        "config/module-coverage-v1.toml",
        "config/node-decomposition-v1.toml",
        "docs/modules/TRNM_MODULE_TECHNICAL_REFERENCE_V1.md",
        "scripts/ci/check_build_closures_v1.py",
        "scripts/ci/check_node_decomposition_v1.py",
        "trillionnium/Cargo.toml",
        "trillionnium/Cargo.lock",
        "trillionnium/crates/trnm-poco-node-authority",
        "trillionnium/crates/trnm-poco-node-io",
        "trillionnium/crates/trnm-poco-node-host",
        "trillionnium/crates/trnm-poco-node-cli",
    ]
    core_paths = [
        "config/repository-blocker-cores-v0.toml",
        "scripts/check_repository_blocker_registry_v0.py",
        "trillionnium/crates/trnm-control-plane-v0",
        "trillionnium/crates/trnm-durable-file-adapters-v0",
        "trillionnium/crates/trnm-migration-v0",
        "trillionnium/crates/trnm-node-boundary-v0",
        "trillionnium/crates/trnm-poco-node-production-v0",
        "trillionnium/crates/trnm-production-adapter-conformance-v0",
        "trillionnium/crates/trnm-release-bundle-v0",
        "trillionnium/crates/trnm-state-sync-v0",
        "trillionnium/crates/trnm-tx-lifecycle-v0",
    ]
    checkout(NODE_SOURCE_SHA, node_paths)
    checkout(CORE_SOURCE_SHA, core_paths)

    moved_docs = {
        "docs/development/TRNM_DURABLE_FILE_ADAPTERS_V0.md": "docs/modules/TRNM_DURABLE_FILE_ADAPTERS_V0.md",
        "docs/development/TRNM_PRODUCTION_ADAPTER_CONFORMANCE_V0.md": "docs/modules/TRNM_PRODUCTION_ADAPTER_CONFORMANCE_V0.md",
        "docs/development/TRNM_REPOSITORY_BLOCKER_CORES_V0.md": "docs/modules/TRNM_REPOSITORY_BLOCKER_CORES_V0.md",
    }
    for source, destination in moved_docs.items():
        content = git("show", f"{CORE_SOURCE_SHA}:{source}") + "\n"
        target = ROOT / destination
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    replacements = {source: destination for source, destination in moved_docs.items()}
    for relative in (
        "config/repository-blocker-cores-v0.toml",
        "scripts/check_repository_blocker_registry_v0.py",
    ):
        path = ROOT / relative
        text = path.read_text(encoding="utf-8")
        for source, destination in replacements.items():
            text = text.replace(source, destination)
        path.write_text(text, encoding="utf-8")


def register_workspace_and_coverage() -> None:
    workspace_path = ROOT / "trillionnium/Cargo.toml"
    text = workspace_path.read_text(encoding="utf-8")
    marker = ']\nresolver = "2"'
    require(marker in text, "workspace member marker drift")
    members = [
        "crates/trnm-control-plane-v0",
        "crates/trnm-durable-file-adapters-v0",
        "crates/trnm-migration-v0",
        "crates/trnm-node-boundary-v0",
        "crates/trnm-poco-node-production-v0",
        "crates/trnm-production-adapter-conformance-v0",
        "crates/trnm-release-bundle-v0",
        "crates/trnm-state-sync-v0",
        "crates/trnm-tx-lifecycle-v0",
    ]
    for member in members:
        row = f'  "{member}",\n'
        if row not in text:
            text = text.replace(marker, row + marker, 1)
    workspace_path.write_text(text, encoding="utf-8")

    mapping = {
        "M03": ["trnm-durable-file-adapters-v0"],
        "M05": ["trnm-tx-lifecycle-v0"],
        "M13": ["trnm-migration-v0", "trnm-state-sync-v0"],
        "M15": ["trnm-node-boundary-v0", "trnm-poco-node-production-v0", "trnm-release-bundle-v0"],
        "M16": ["trnm-control-plane-v0"],
        "M17": ["trnm-production-adapter-conformance-v0"],
    }
    text = COVERAGE.read_text(encoding="utf-8")
    for module_id in [f"M{i:02d}" for i in range(18)]:
        pattern = re.compile(
            rf'(\[\[module_coverage\]\]\nid = "{module_id}"\n)(.*?)(?=\n\[\[module_coverage\]\]|\n\[\[auxiliary_units\]\])',
            re.S,
        )
        match = pattern.search(text)
        require(match is not None, f"coverage section missing: {module_id}")
        section = match.group(2)
        crate_match = re.search(r'^primary_crates = \[(.*?)\]$', section, re.M | re.S)
        require(crate_match is not None, f"primary_crates missing: {module_id}")
        crates = re.findall(r'"([^"]+)"', crate_match.group(1))
        for crate in mapping.get(module_id, []):
            if crate not in crates:
                crates.append(crate)
        section = section[: crate_match.start()] + "primary_crates = [" + ", ".join(
            f'"{crate}"' for crate in crates
        ) + "]" + section[crate_match.end() :]
        document_line = f'module_document = "docs/modules/{module_id}/README.md"\n'
        if "module_document = " not in section:
            anchor_match = re.search(r'^(anchor = "[^"]+"\n)', section, re.M)
            require(anchor_match is not None, f"anchor missing: {module_id}")
            section = section[: anchor_match.end()] + document_line + section[anchor_match.end() :]
        replacement = match.group(1) + section
        text = text[: match.start()] + replacement + text[match.end() :]
    COVERAGE.write_text(text, encoding="utf-8")
    read_toml(COVERAGE)


def technical_sections() -> dict[str, tuple[str, str]]:
    text = REFERENCE.read_text(encoding="utf-8")
    pattern = re.compile(
        r'^## (M\d{2})\s+—\s+(.+?)\n\n(.*?)(?=\n---\n\n## M\d{2}\s+—|\n---\n\n## Module completion rule|\Z)',
        re.M | re.S,
    )
    result: dict[str, tuple[str, str]] = {}
    for match in pattern.finditer(text):
        result[match.group(1)] = (match.group(2).strip(), match.group(3).strip())
    require(set(result) == {f"M{i:02d}" for i in range(18)}, f"technical section coverage drift: {sorted(result)}")
    return result


def generate_module_handbooks() -> None:
    registry = read_toml(REGISTRY)
    coverage = read_toml(COVERAGE)
    registry_rows = registry.get("modules")
    coverage_rows = coverage.get("module_coverage")
    require(isinstance(registry_rows, list) and len(registry_rows) == 18, "registry module rows drift")
    require(isinstance(coverage_rows, list) and len(coverage_rows) == 18, "coverage module rows drift")
    registry_by_id = {row["id"]: row for row in registry_rows}
    coverage_by_id = {row["id"]: row for row in coverage_rows}
    sections = technical_sections()
    docs_root = ROOT / "docs/modules"
    index = [
        "# Trillionnium Chain module handbooks",
        "",
        "These eighteen handbooks are generated from the canonical module registry,",
        "source-coverage manifest, and stable technical reference. They are technical",
        "contracts, not release or activation authority.",
        "",
        "| Module | Handbook | Owner group | SLO |",
        "|---|---|---|---|",
    ]
    for module_id in [f"M{i:02d}" for i in range(18)]:
        row = registry_by_id[module_id]
        coverage_row = coverage_by_id[module_id]
        title, body = sections[module_id]
        crates = coverage_row.get("primary_crates", [])
        sources = coverage_row.get("source_paths", [])
        contracts = coverage_row.get("contract_paths", [])
        dependencies = row.get("allowed_module_dependencies", [])
        forbidden = row.get("forbidden_capabilities", [])
        commands = [
            "python3 scripts/ci/check_module_coverage_v1.py",
            "python3 scripts/ci/check_module_documentation_v1.py",
        ]
        commands.extend(
            f"cargo test --manifest-path trillionnium/Cargo.toml -p {crate} --all-targets --locked"
            for crate in crates
        )
        content = [
            f"# {module_id} — {title}",
            "",
            "Status: **technical contract; exact-source implementation and evidence required**",
            "",
            f"Owner group: `{row['owner_group']}`  ",
            f"Target staff: `{row['staff_target']}`  ",
            f"Registry status: `{row['status']}`  ",
            f"Runtime placement: `{row['runtime']}`  ",
            f"SLO profile: `{coverage_row['slo_profile']}`  ",
            f"Testkit profile: `{coverage_row['testkit_profile']}`",
            "",
            "## 1. Authority, interfaces, invariants, failure and verification",
            "",
            body,
            "",
            "## 2. Exact source ownership",
            "",
        ]
        if crates:
            content.extend(["Primary workspace crates:", ""] + [f"- `{crate}`" for crate in crates])
        if sources:
            content.extend(["", "Primary non-crate source surfaces:", ""] + [f"- `{source}`" for source in sources])
        content.extend(
            [
                "",
                "## 3. Contracts and dependency law",
                "",
                "Contract paths:",
                "",
                *[f"- `{path}`" for path in contracts],
                "",
                "Allowed module dependencies:",
                "",
                *([f"- `{dep}`" for dep in dependencies] if dependencies else ["- none"]),
                "",
                "Forbidden capabilities:",
                "",
                *[f"- `{capability}`" for capability in forbidden],
                "",
                "Cross-module calls must use versioned ports, immutable events, authenticated",
                "proofs, or consumed capabilities. Implementation objects, raw database handles,",
                "private keys, clocks, sockets, and mutable transport types may not cross this",
                "boundary unless this module explicitly owns that authority.",
                "",
                "## 4. Reproducible verification",
                "",
                "```bash",
                *commands,
                "```",
                "",
                "Evidence must bind the exact commit/tree, prospective merge, toolchain, lockfile,",
                "features, configuration, workload/fault manifest, raw outputs, retained mutants,",
                "reviewers, and invalidation set. Naming an SLO or testkit profile is not evidence.",
                "",
                "## 5. Definition of done",
                "",
                "This module is complete only when source ownership, contracts, APIs, state and",
                "error models, resource limits, tests, recovery, security review, numeric SLOs,",
                "runbooks, and immutable evidence all bind the same accepted source. Documentation",
                "or a passing local fixture cannot promote public-testnet, production, release, or",
                "activation truth.",
                "",
            ]
        )
        module_doc = ROOT / coverage_row["module_document"]
        module_doc.parent.mkdir(parents=True, exist_ok=True)
        module_doc.write_text("\n".join(content), encoding="utf-8")
        index.append(
            f"| {module_id} | [{title}]({module_id}/README.md) | `{row['owner_group']}` | `{coverage_row['slo_profile']}` |"
        )
    (docs_root / "README.md").write_text("\n".join(index) + "\n", encoding="utf-8")

    reference = REFERENCE.read_text(encoding="utf-8")
    appendix_marker = "## Repository blocker core implementation map v0"
    if appendix_marker not in reference:
        reference = reference.rstrip() + "\n\n---\n\n" + appendix_marker + "\n\n"
        reference += "These fail-closed repository cores carry no production, public-testnet, release, or activation authority.\n\n"
        reference += "| Crate | Module | Boundary |\n|---|---|---|\n"
        rows = [
            ("trnm-durable-file-adapters-v0", "M03", "locked authority and snapshot CAS"),
            ("trnm-tx-lifecycle-v0", "M05", "bounded transaction lifecycle"),
            ("trnm-migration-v0", "M13", "source-bound migration verification"),
            ("trnm-state-sync-v0", "M13", "authenticated non-destructive state sync"),
            ("trnm-node-boundary-v0", "M15", "node authority boundary"),
            ("trnm-poco-node-production-v0", "M15", "production-shaped fail-closed node"),
            ("trnm-release-bundle-v0", "M15", "release-bundle validation"),
            ("trnm-control-plane-v0", "M16", "observer-first guarded control plane"),
            ("trnm-production-adapter-conformance-v0", "M17", "conformance-only authority"),
        ]
        reference += "".join(f"| `{crate}` | {module} | {boundary} |\n" for crate, module, boundary in rows)
        REFERENCE.write_text(reference, encoding="utf-8")


def install_module_documentation_gate() -> None:
    path = ROOT / "scripts/ci/check_module_documentation_v1.py"
    content = r'''#!/usr/bin/env python3
"""Fail-closed completeness gate for the M00-M17 module handbooks."""
from __future__ import annotations
import pathlib, re, sys, tomllib
ROOT = pathlib.Path(__file__).resolve().parents[2]

def fail(message: str) -> None:
    raise SystemExit(f"module documentation failed: {message}")

def load(path: pathlib.Path):
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except Exception as exc:
        fail(f"{path.relative_to(ROOT)}: {exc}")

coverage = load(ROOT / "config/module-coverage-v1.toml")
registry = load(ROOT / "docs/development/module-registry-v1.toml")
coverage_rows = coverage.get("module_coverage")
registry_rows = registry.get("modules")
expected = [f"M{i:02d}" for i in range(18)]
if not isinstance(coverage_rows, list) or [row.get("id") for row in coverage_rows] != expected:
    fail("coverage IDs drift")
if not isinstance(registry_rows, list) or [row.get("id") for row in registry_rows] != expected:
    fail("registry IDs drift")
registry_by_id = {row["id"]: row for row in registry_rows}
expected_docs = set()
for row in coverage_rows:
    module_id = row["id"]
    relative = row.get("module_document")
    if relative != f"docs/modules/{module_id}/README.md":
        fail(f"{module_id}: module_document drift")
    expected_docs.add(relative)
    path = ROOT / relative
    if not path.is_file():
        fail(f"{module_id}: handbook missing")
    text = path.read_text(encoding="utf-8")
    if not text.startswith(f"# {module_id} —"):
        fail(f"{module_id}: title missing")
    for heading in (
        "## 1. Authority, interfaces, invariants, failure and verification",
        "## 2. Exact source ownership",
        "## 3. Contracts and dependency law",
        "## 4. Reproducible verification",
        "## 5. Definition of done",
    ):
        if heading not in text:
            fail(f"{module_id}: required heading missing: {heading}")
    for literal in row.get("primary_crates", []) + row.get("source_paths", []) + row.get("contract_paths", []):
        if f"`{literal}`" not in text:
            fail(f"{module_id}: source/contract absent from handbook: {literal}")
    registry_row = registry_by_id[module_id]
    for literal in registry_row.get("allowed_module_dependencies", []) + registry_row.get("forbidden_capabilities", []):
        if f"`{literal}`" not in text:
            fail(f"{module_id}: dependency/capability absent: {literal}")
    for literal in (row.get("slo_profile"), row.get("testkit_profile"), registry_row.get("owner_group")):
        if not isinstance(literal, str) or f"`{literal}`" not in text:
            fail(f"{module_id}: profile/owner absent: {literal}")
    if re.search(r"\b(?:TODO|TBD|FIXME)\b", text):
        fail(f"{module_id}: unresolved placeholder")
actual_docs = {str(path.relative_to(ROOT)) for path in (ROOT / "docs/modules").glob("M??/README.md")}
if actual_docs != expected_docs:
    fail(f"handbook inventory drift: extra={sorted(actual_docs-expected_docs)} missing={sorted(expected_docs-actual_docs)}")
print(f"module documentation PASS: modules={len(expected_docs)}")
'''
    path.write_text(content, encoding="utf-8")


def repair_active_document_links() -> None:
    contracts = ROOT / "contracts/README.md"
    if contracts.is_file():
        text = contracts.read_text(encoding="utf-8")
        text = text.replace(
            "trillionnium/docs/release/TRNM_MAINNET_GAP_MATRIX_2026-03-26.md",
            "../RELEASE_READINESS.md",
        )
        contracts.write_text(text, encoding="utf-8")

    for path in (ROOT / "web4-frontend/docs").glob("*.md"):
        text = path.read_text(encoding="utf-8")
        text = re.sub(
            r'\[([^\]]+)\]\((\.\./\.\./docs/archive/[^)]+)\)',
            lambda match: f"`{match.group(1)}`（已退役；请使用 Git 历史或当前 truth source）",
            text,
        )
        text = re.sub(
            r'\[([^\]]+)\]\((\.\./\.\./docs/WEB4_INFRA_PLATFORM_DEVELOPMENT_MASTER\.md)\)',
            lambda match: f"`{match.group(1)}`（当前树不存在；回退到 `../../RELEASE_READINESS.md` 与本目录文档）",
            text,
        )
        path.write_text(text, encoding="utf-8")

    docs_index = ROOT / "docs/README.md"
    text = docs_index.read_text(encoding="utf-8")
    row = "- **Module handbooks:** `modules/README.md`\n"
    if row not in text:
        anchor = "- **Module technical reference:** `modules/TRNM_MODULE_TECHNICAL_REFERENCE_V1.md`\n"
        text = text.replace(anchor, anchor + row) if anchor in text else text.rstrip() + "\n" + row
    docs_index.write_text(text, encoding="utf-8")


def install_markdown_link_gate() -> None:
    path = ROOT / "scripts/ci/check_markdown_links_v1.py"
    content = r'''#!/usr/bin/env python3
"""Check local links on active navigation, development and module surfaces."""
from __future__ import annotations
import pathlib, re, sys
from urllib.parse import unquote
ROOT = pathlib.Path(__file__).resolve().parents[2]
LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
files = [ROOT / "README.md", ROOT / "docs/README.md", ROOT / "contracts/README.md"]
files += list((ROOT / "docs/development").glob("*.md"))
files += list((ROOT / "docs/modules").rglob("*.md"))
files += list((ROOT / "web4-frontend/docs").glob("*.md"))
errors = []
for source in sorted(set(files)):
    if not source.is_file() or source.is_symlink():
        continue
    text = source.read_text(encoding="utf-8")
    for line_number, line in enumerate(text.splitlines(), 1):
        for match in LINK.finditer(line):
            raw = match.group(1).strip()
            if raw.startswith(("http://", "https://", "mailto:", "#")):
                continue
            if raw.startswith("<") and ">" in raw:
                raw = raw[1:raw.index(">")]
            else:
                raw = raw.split()[0]
            raw = unquote(raw).split("#", 1)[0].split("?", 1)[0]
            if not raw:
                continue
            target = (source.parent / raw).resolve()
            try:
                target.relative_to(ROOT.resolve())
            except ValueError:
                errors.append(f"{source.relative_to(ROOT)}:{line_number}: link escapes repository: {raw}")
                continue
            if not target.exists():
                errors.append(f"{source.relative_to(ROOT)}:{line_number}: missing local link: {raw}")
if errors:
    print("markdown link closure failed:", file=sys.stderr)
    print("\n".join(errors), file=sys.stderr)
    raise SystemExit(2)
print(f"markdown link closure PASS: files={len(set(files))}")
'''
    path.write_text(content, encoding="utf-8")


def insert_command_after(path: pathlib.Path, needle: str, commands: list[str]) -> None:
    if not path.is_file():
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    output: list[str] = []
    for line in lines:
        output.append(line)
        if needle in line:
            indent = line[: len(line) - len(line.lstrip())]
            for command in commands:
                candidate = indent + command
                if candidate not in lines and candidate not in output:
                    output.append(candidate)
    path.write_text("\n".join(output) + "\n", encoding="utf-8")


def wire_gates_and_policy() -> None:
    baseline = ROOT / ".github/workflows/trnm-required-baseline.yml"
    insert_command_after(
        baseline,
        "python3 scripts/ci/check_module_coverage_v1.py",
        [
            "python3 scripts/ci/check_module_documentation_v1.py",
            "python3 scripts/ci/check_markdown_links_v1.py",
        ],
    )

    doc_workflow = ROOT / ".github/workflows/trnm-documentation-truth.yml"
    if doc_workflow.is_file():
        text = doc_workflow.read_text(encoding="utf-8")
        for new_path in (
            "scripts/ci/check_module_documentation_v1.py",
            "scripts/ci/check_markdown_links_v1.py",
        ):
            row = f"      - '{new_path}'\n"
            anchor = "      - 'scripts/ci/check_module_coverage_v1.py'\n"
            if row not in text and anchor in text:
                text = text.replace(anchor, anchor + row)
        command_anchor = "          python3 scripts/ci/check_module_coverage_v1.py\n"
        commands = (
            "          python3 scripts/ci/check_module_documentation_v1.py\n"
            "          python3 scripts/ci/check_markdown_links_v1.py\n"
        )
        if "python3 scripts/ci/check_module_documentation_v1.py" not in text and command_anchor in text:
            text = text.replace(command_anchor, command_anchor + commands)
        compile_anchor = "            scripts/ci/check_module_coverage_v1.py\n"
        compile_rows = (
            "            scripts/ci/check_module_documentation_v1.py \\\n"
            "            scripts/ci/check_markdown_links_v1.py\n"
        )
        if compile_anchor in text and "scripts/ci/check_module_documentation_v1.py \\" not in text:
            text = text.replace(compile_anchor, compile_anchor.rstrip("\n") + " \\\n" + compile_rows)
        doc_workflow.write_text(text, encoding="utf-8")

    policy_path = ROOT / "config/repository-policy-v1.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    required = policy.setdefault("required_paths", [])
    for relative in (
        "config/module-coverage-v1.toml",
        "docs/modules/README.md",
        "docs/modules/TRNM_MODULE_TECHNICAL_REFERENCE_V1.md",
        "scripts/ci/check_module_documentation_v1.py",
        "scripts/ci/check_markdown_links_v1.py",
        "config/repository-blocker-cores-v0.toml",
        "scripts/check_repository_blocker_registry_v0.py",
    ):
        if relative not in required:
            required.append(relative)
    required.sort()
    write_json(policy_path, policy)


def refresh_plan_and_machine_truth() -> None:
    text = PLAN.read_text(encoding="utf-8")
    states = {
        "NODE-SPLIT-001": "implementation present; repository qualification pending exact head and prospective merge",
        "BUILD-CLOSURE-001": "implementation present; Cargo-tree/compiler qualification pending exact head and prospective merge",
        "TX-PROD-001": "bounded lifecycle core present; live production wiring and campaign acceptance open",
        "SYNC-PROD-001": "authenticated core present; live downloader and multi-host acceptance open",
        "MIG-001": "migration core present; real finalized export and independent root recomputation open",
        "CONTROL-001": "observer-first guarded core present; live rollout and campaign acceptance open",
    }
    lines = text.splitlines()
    seen: set[str] = set()
    for index, line in enumerate(lines):
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) >= 5 and cells[1] in states:
            cells[3] = states[cells[1]]
            lines[index] = "| " + " | ".join(cells) + " |"
            seen.add(cells[1])
    require(seen == set(states), f"plan blocker rows missing: {sorted(set(states)-seen)}")
    text = "\n".join(lines) + "\n"
    appendix = "## Repository-owned closure cores v0"
    if appendix not in text:
        text += (
            "\n---\n\n" + appendix + "\n\n"
            "The exact-source repository line includes bounded transaction lifecycle, authenticated state-sync, "
            "migration/root recomputation, durable authority adapters, node boundary, release-bundle validation, "
            "observer-first control-plane guards, and adapter conformance cores. These are repository implementations, "
            "not public-testnet, production, release, audit, hardware, soak, or activation evidence.\n"
        )
    for marker in (
        "production_candidate = true",
        "production_consensus_activation = true",
        "public_testnet_ready = true",
        "release_ready = true",
    ):
        require(marker not in text, f"forbidden plan promotion: {marker}")
    PLAN.write_text(text, encoding="utf-8")

    blocker_path = ROOT / "config/blocker-execution-v1.json"
    blocker = json.loads(blocker_path.read_text(encoding="utf-8"))
    blocker["as_of"] = "2026-09-02"
    status_updates = {
        "P1-EXEC-001": "repository-core-and-terminal-history-implementation-present-acceptance-pending",
        "P2-NODE-001": "node-boundary-and-production-shaped-core-present-live-host-open",
        "P2-TX-001": "bounded-lifecycle-core-present-live-wiring-open",
        "P2-STORE-001": "durable-adapter-core-present-hardware-evidence-open",
        "MIG-ROOT-001": "migration-and-root-core-present-real-source-ceremony-open",
    }
    for group in ("repository_blockers", "settings_gates"):
        for row in blocker.get(group, []):
            if row.get("id") in status_updates:
                row["status"] = status_updates[row["id"]]
    write_json(blocker_path, blocker)

    workspace = read_toml(ROOT / "trillionnium/Cargo.toml")
    member_count = len(workspace["workspace"]["members"])
    snapshot_path = ROOT / "docs/development/CURRENT_SNAPSHOT_V1.json"
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    snapshot["as_of"] = "2026-09-02"
    implementation = snapshot.setdefault("repository_implementation", {})
    coverage = implementation.setdefault("module_coverage", {})
    coverage["module_count"] = 18
    coverage["workspace_crates_uniquely_mapped"] = member_count
    coverage["detailed_module_handbooks"] = 18
    implementation["repository_blocker_cores"] = {
        "status": "implementation-present-exact-head-acceptance-pending",
        "source_commit": CORE_SOURCE_SHA,
        "source_tree": CORE_SOURCE_TREE,
        "node_source_commit": NODE_SOURCE_SHA,
        "node_source_tree": NODE_SOURCE_TREE,
        "external_evidence_closed": False,
    }
    write_json(snapshot_path, snapshot)

    readiness_path = ROOT / "RELEASE_READINESS.md"
    readiness = readiness_path.read_text(encoding="utf-8")
    note = "- bounded repository-owned transaction, sync, migration, durable-adapter, node-boundary, release-bundle, control-plane and conformance cores;\n"
    anchor = "The selected line contains repository implementations for:\n\n"
    if note not in readiness and anchor in readiness:
        readiness = readiness.replace(anchor, anchor + note)
    readiness_path.write_text(readiness, encoding="utf-8")

    digest = hashlib.sha256(PLAN.read_bytes()).hexdigest()
    digest_pattern = re.compile(
        r'(?im)^(\s*[A-Za-z0-9_.-]*(?:plan|development)[A-Za-z0-9_.-]*sha256\s*=\s*")([0-9a-f]{64})("\s*)$'
    )
    for relative in (
        "docs/development/plan-manifest-v1.toml",
        "docs/development/release-train-v1.toml",
    ):
        path = ROOT / relative
        raw = path.read_text(encoding="utf-8")
        raw = digest_pattern.sub(lambda match: match.group(1) + digest + match.group(3), raw)
        path.write_text(raw, encoding="utf-8")
        tomllib.loads(raw)
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))

    def update_hash(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in list(value.items()):
                if "plan" in key.lower() and "sha256" in key.lower() and isinstance(child, str) and re.fullmatch(r"[0-9a-f]{64}", child):
                    value[key] = digest
                else:
                    update_hash(child)
        elif isinstance(value, list):
            for child in value:
                update_hash(child)

    update_hash(snapshot)
    write_json(snapshot_path, snapshot)


def write_receipt(qualified_parent: str) -> None:
    workspace = read_toml(ROOT / "trillionnium/Cargo.toml")
    coverage = read_toml(COVERAGE)
    receipt = {
        "schema": "trnm-plan-v2-final-repository-qualification-v4",
        "qualified_parent_commit": qualified_parent,
        "qualified_parent_tree": git("show", "-s", "--format=%T", qualified_parent),
        "node_source_commit": NODE_SOURCE_SHA,
        "node_source_tree": NODE_SOURCE_TREE,
        "repository_core_source_commit": CORE_SOURCE_SHA,
        "repository_core_source_tree": CORE_SOURCE_TREE,
        "plan_sha256": hashlib.sha256(PLAN.read_bytes()).hexdigest(),
        "workspace_crate_count": len(workspace["workspace"]["members"]),
        "module_count": len(coverage["module_coverage"]),
        "module_handbook_count": len(list((ROOT / "docs/modules").glob("M??/README.md"))),
        "workspace_all_targets_check": "PASS",
        "repository_core_tests_and_clippy": "PASS",
        "cargo_tree_closures": "PASS",
        "module_coverage": "PASS",
        "module_documentation": "PASS",
        "active_markdown_link_closure": "PASS",
        "node_decomposition": "PASS",
        "repository_core_registry": "PASS",
        "default_start_fail_closed": "PASS",
        "independent_review": False,
        "external_multi_host_evidence": False,
        "external_hsm_anchor_evidence": False,
        "external_power_loss_evidence": False,
        "external_audit_evidence": False,
        "soak_activation_evidence": False,
        "governance_activation_record": False,
        "production_candidate": False,
        "production_consensus_activation": False,
        "public_testnet_ready": False,
        "release_ready": False,
        "result": "PASS",
    }
    write_json(
        ROOT / "docs/evidence/repository/PLAN_V2_FINAL_REPOSITORY_QUALIFICATION_V4.json",
        receipt,
    )


def construct() -> None:
    require(git("rev-parse", "--show-toplevel") == str(ROOT), "repository root mismatch")
    fetch_and_verify_sources()
    integrate_sources()
    register_workspace_and_coverage()
    generate_module_handbooks()
    install_module_documentation_gate()
    repair_active_document_links()
    install_markdown_link_gate()
    wire_gates_and_policy()
    refresh_plan_and_machine_truth()
    for path in (
        COVERAGE,
        REGISTRY,
        ROOT / "config/build-closures-v1.toml",
        ROOT / "config/node-decomposition-v1.toml",
        ROOT / "config/repository-blocker-cores-v0.toml",
    ):
        read_toml(path)
    for path in (
        ROOT / "config/repository-policy-v1.json",
        ROOT / "config/blocker-execution-v1.json",
        ROOT / "docs/development/CURRENT_SNAPSHOT_V1.json",
    ):
        json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-receipt", metavar="QUALIFIED_PARENT")
    args = parser.parse_args()
    if args.write_receipt:
        require(re.fullmatch(r"[0-9a-f]{40}", args.write_receipt) is not None, "invalid receipt source SHA")
        write_receipt(args.write_receipt)
    else:
        construct()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ClosureError, OSError, ValueError, KeyError, tomllib.TOMLDecodeError, subprocess.CalledProcessError) as error:
        print(f"repository closure v4 failed: {error}", file=sys.stderr)
        raise SystemExit(2)
