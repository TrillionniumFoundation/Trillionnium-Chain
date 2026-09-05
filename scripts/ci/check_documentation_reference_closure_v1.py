#!/usr/bin/env python3
"""Fail-closed authority, stale-reference, and relative-link gate for Chain docs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import urllib.parse
from typing import Any, Iterable

ROOT = pathlib.Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "config/documentation-truth-v1.json"

INLINE_LINK_RE = re.compile(
    r"""!?\[[^\]]*\]\(\s*<?([^)\s>]+)>?(?:\s+["'(][^)]*)?\s*\)"""
)
REFERENCE_LINK_RE = re.compile(r"""^\s*\[[^\]]+\]:\s*<?([^\s>]+)>?""")
FENCE_RE = re.compile(r"^\s*(```|~~~)")


class DocumentationTruthError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise DocumentationTruthError(message)


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DocumentationTruthError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def display_path(path: pathlib.Path) -> str:
    """Return a stable label for repository and GitHub event files."""

    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def load_json(path: pathlib.Path) -> dict[str, Any]:
    label = display_path(path)
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise DocumentationTruthError(f"{label}: invalid strict JSON: {error}") from error
    require(isinstance(value, dict), f"{label}: top level must be an object")
    return value


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout.strip()


def tracked_paths() -> list[str]:
    raw = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True
    ).stdout
    return [part.decode("utf-8") for part in raw.split(b"\0") if part]


def is_active_surface(path: str, policy: dict[str, Any]) -> bool:
    if path in policy["active_reference_files"]:
        return True
    return any(path == root or path.startswith(root + "/") for root in policy["active_reference_roots"])


def read_small_text(path: pathlib.Path) -> str | None:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 4 * 1024 * 1024:
            return None
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None


def verify_duplicate_key_self_test() -> None:
    hostile = (
        '{"production_candidate":false,"production_candidate":true}',
        '{"source":{"commit":"a","commit":"b"}}',
        '{"authoritative_docs":{"development_plan":"a","development_plan":"b"}}',
    )
    for sample in hostile:
        try:
            json.loads(sample, object_pairs_hook=strict_object)
        except DocumentationTruthError:
            continue
        raise DocumentationTruthError("duplicate-key self-test accepted hostile JSON")


def iter_markdown_targets(text: str) -> Iterable[tuple[int, str]]:
    """Yield repository-link candidates outside fenced code blocks."""

    in_fence = False
    fence_token: str | None = None
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = FENCE_RE.match(line)
        if match:
            token = match.group(1)
            if not in_fence:
                in_fence = True
                fence_token = token
            elif token == fence_token:
                in_fence = False
                fence_token = None
            continue
        if in_fence:
            continue
        for inline in INLINE_LINK_RE.finditer(line):
            yield line_number, inline.group(1)
        reference = REFERENCE_LINK_RE.match(line)
        if reference:
            yield line_number, reference.group(1)


def resolve_repository_link(document: pathlib.Path, raw_target: str) -> pathlib.Path | None:
    """Resolve a local Markdown target; external and fragment-only links return None."""

    target = raw_target.strip()
    if not target or target.startswith("#"):
        return None

    parsed = urllib.parse.urlsplit(target)
    if parsed.scheme or parsed.netloc:
        require(
            parsed.scheme in {"http", "https", "mailto", "tel"},
            f"{display_path(document)}: unsafe or unsupported Markdown link scheme: {raw_target}",
        )
        return None

    decoded_path = urllib.parse.unquote(parsed.path)
    if not decoded_path:
        return None

    if decoded_path.startswith("/"):
        candidate = ROOT / decoded_path.lstrip("/")
    else:
        candidate = document.parent / decoded_path

    root_resolved = ROOT.resolve()
    candidate_resolved = candidate.resolve(strict=False)
    require(
        candidate_resolved.is_relative_to(root_resolved),
        f"{display_path(document)}: repository-relative link escapes root: {raw_target}",
    )
    return candidate_resolved


def verify_relative_markdown_links(policy: dict[str, Any]) -> tuple[int, list[dict[str, Any]]]:
    configured = policy.get("relative_link_check_paths")
    require(
        isinstance(configured, list)
        and configured
        and all(isinstance(item, str) and item for item in configured),
        "relative_link_check_paths must be a non-empty string list",
    )

    documents: list[pathlib.Path] = []
    for relative in configured:
        path = ROOT / relative
        require(path.exists(), f"relative link check path missing: {relative}")
        if path.is_dir():
            documents.extend(sorted(item for item in path.rglob("*.md") if item.is_file()))
        else:
            require(path.is_file(), f"relative link check path is not a file: {relative}")
            documents.append(path)

    seen: set[pathlib.Path] = set()
    unique_documents: list[pathlib.Path] = []
    for document in documents:
        resolved = document.resolve()
        if resolved not in seen:
            seen.add(resolved)
            unique_documents.append(document)

    checked = 0
    errors: list[dict[str, Any]] = []
    for document in unique_documents:
        try:
            text = document.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise DocumentationTruthError(
                f"{display_path(document)}: cannot read Markdown for link validation: {error}"
            ) from error
        for line_number, raw_target in iter_markdown_targets(text):
            candidate = resolve_repository_link(document, raw_target)
            if candidate is None:
                continue
            checked += 1
            if not candidate.exists():
                errors.append(
                    {
                        "path": display_path(document),
                        "line": line_number,
                        "target": raw_target,
                        "resolved": display_path(candidate),
                    }
                )
    return checked, errors


def runtime_binding(mode: str) -> dict[str, Any]:
    head = git("rev-parse", "HEAD")
    tree = git("rev-parse", "HEAD^{tree}")
    binding: dict[str, Any] = {
        "schema": "trnm-document-candidate-runtime-binding-v1",
        "mode": mode,
        "source_commit": head,
        "source_tree": tree,
        "pull_request_number": None,
        "pull_request_head": None,
        "pull_request_base": None,
        "event_merge_commit": os.environ.get("GITHUB_SHA"),
        "prospective_merge_commit": None,
        "prospective_merge_tree": None,
    }
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if event_path and pathlib.Path(event_path).is_file():
        event = load_json(pathlib.Path(event_path))
        pull = event.get("pull_request")
        if isinstance(pull, dict):
            number = pull.get("number") or event.get("number")
            head_row = pull.get("head") if isinstance(pull.get("head"), dict) else {}
            base_row = pull.get("base") if isinstance(pull.get("base"), dict) else {}
            pr_head = head_row.get("sha")
            pr_base = base_row.get("sha")
            binding.update(
                pull_request_number=number,
                pull_request_head=pr_head,
                pull_request_base=pr_base,
            )
            require(isinstance(number, int) and number > 0, "pull-request number missing")
            require(isinstance(pr_head, str) and len(pr_head) == 40, "pull-request head missing")
            require(isinstance(pr_base, str) and len(pr_base) == 40, "pull-request base missing")
            if mode == "source":
                require(head == pr_head, f"source checkout mismatch: HEAD={head} PR={pr_head}")
            elif mode == "merge":
                parents = git("rev-list", "--parents", "-n", "1", "HEAD").split()
                require(len(parents) >= 3, "prospective merge must have at least two parents")
                require(parents[1] == pr_base, "prospective merge first parent is not PR base")
                require(pr_head in parents[2:], "prospective merge does not contain PR head as a parent")
                binding["prospective_merge_commit"] = head
                binding["prospective_merge_tree"] = tree
    return binding


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--binding-mode", choices=("local", "source", "merge"), default="local")
    parser.add_argument("--binding-output", type=pathlib.Path)
    args = parser.parse_args()

    policy = load_json(POLICY_PATH)
    require(policy.get("schema") == "trnm-documentation-truth-v1", "policy schema drift")
    require(policy.get("gate_revision") == 4, "documentation gate revision drift")
    verify_duplicate_key_self_test()

    tracked = tracked_paths()
    tracked_set = set(tracked)
    expected = set(policy["canonical_development_entries"])
    actual = {path for path in tracked if path.startswith("docs/development/")}
    require(
        actual == expected,
        f"docs/development allowlist drift: extra={sorted(actual-expected)} missing={sorted(expected-actual)}",
    )

    canonical_plan = policy["canonical_plan"]
    require(canonical_plan in tracked_set, "canonical plan is not tracked")
    regular_markdown = []
    for path in sorted(actual):
        candidate = ROOT / path
        if candidate.suffix.lower() == ".md" and not candidate.is_symlink():
            regular_markdown.append(path)
    require(
        regular_markdown == [canonical_plan],
        f"expected one regular Markdown plan, found {regular_markdown}",
    )

    aliases = policy.get("compatibility_aliases", {})
    require(isinstance(aliases, dict), "compatibility_aliases must be an object")
    for path, target in aliases.items():
        alias = ROOT / path
        require(alias.is_symlink(), f"compatibility alias is not a symlink: {path}")
        require(os.readlink(alias) == target, f"compatibility alias target drift: {path}")

    for tree in policy["forbidden_active_trees"]:
        require(not (ROOT / tree).exists(), f"forbidden historical tree exists: {tree}")
        require(
            not any(path == tree or path.startswith(tree + "/") for path in tracked),
            f"forbidden historical tree is tracked: {tree}",
        )

    for machine_path in (
        "docs/development/CURRENT_SNAPSHOT_V1.json",
        "config/consensus-mainline.json",
        "config/repository-policy-v1.json",
        "config/blocker-execution-v1.json",
        "PROJECT_BOUNDARY.json",
    ):
        load_json(ROOT / machine_path)

    exclusions = set(policy["reference_scan_exclusions"])
    exclusions.add(canonical_plan)
    exclusions.update(aliases)
    historical_roots = tuple(root + "/" for root in policy["historical_record_roots"])
    forbidden = tuple(policy["forbidden_active_references"])
    hits: list[dict[str, Any]] = []
    for relative in tracked:
        if relative in exclusions or relative.startswith(historical_roots):
            continue
        if not is_active_surface(relative, policy):
            continue
        text = read_small_text(ROOT / relative)
        if text is None:
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            for literal in forbidden:
                if literal in line:
                    hits.append(
                        {
                            "path": relative,
                            "line": line_number,
                            "literal": literal,
                            "context_sha256": hashlib.sha256(line.encode("utf-8")).hexdigest(),
                        }
                    )
    require(
        not hits,
        "active stale development references remain: " + json.dumps(hits, sort_keys=True),
    )

    for navigation in ("README.md", "docs/README.md", "AGENTS.md", "RELEASE_READINESS.md"):
        text = (ROOT / navigation).read_text(encoding="utf-8")
        for root in policy["historical_record_roots"]:
            require(
                root + "/" not in text,
                f"active navigation links historical record root: {navigation} -> {root}",
            )

    relative_link_count, relative_link_errors = verify_relative_markdown_links(policy)
    require(
        not relative_link_errors,
        "broken repository-relative Markdown links remain: "
        + json.dumps(relative_link_errors, sort_keys=True),
    )

    binding = runtime_binding(args.binding_mode)
    report = {
        "schema": "trnm-documentation-reference-closure-v1",
        "canonical_plan": canonical_plan,
        "canonical_development_entries": sorted(expected),
        "regular_markdown_count": len(regular_markdown),
        "forbidden_tree_count": len(policy["forbidden_active_trees"]),
        "active_stale_reference_count": len(hits),
        "relative_link_count": relative_link_count,
        "broken_relative_link_count": len(relative_link_errors),
        "duplicate_key_rejection": True,
        "runtime_binding": binding,
        "production_candidate": False,
        "production_consensus_activation": False,
        "release_ready": False,
        "result": "PASS",
    }
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.binding_output:
        output = args.binding_output if args.binding_output.is_absolute() else ROOT / args.binding_output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (DocumentationTruthError, subprocess.CalledProcessError) as error:
        print(f"documentation reference closure failed: {error}", file=sys.stderr)
        raise SystemExit(2)
