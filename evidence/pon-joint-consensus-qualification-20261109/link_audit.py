#!/usr/bin/env python3
"""Audit changed Markdown links against a pinned Git tree, including sparse paths.

This intentionally retains the inline-link and fenced-code parsing used for the
prepublication review. It checks relative path references in the full bodies of
changed Markdown files, plus their nonempty cross-document fragments. It does not
replace check_repository.py, render GitHub Markdown, or check external URLs.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import subprocess
import sys
import unicodedata
from urllib.parse import unquote, urlsplit


DEFAULT_BASE = "e2a02f9271b49f146e70806c8a66e161b5973971"
DEFAULT_HEAD = "73b5a70fc3f4ffa5a1a99da366591c243d384786"
DEFAULT_REPO = "/workspace/scratch/b6ec4f0afca8/chain-joint-daa"
INLINE_LINK = re.compile(r"\[[^\]]*\]\(([^\s)]+)\)")
FENCED_CODE = re.compile(r"^```[^\n]*\n.*?^```[^\n]*$", re.M | re.S)
EXPLICIT_ANCHOR = re.compile(
    r"<(?:a|h[1-6])\b[^>]*(?:id|name)=[\"\x27]([^\"\x27]+)", re.I
)
ATX_HEADING = re.compile(r"^ {0,3}#{1,6}\s+(.+?)\s*#*\s*$")


def outside_code(text: str) -> str:
    return FENCED_CODE.sub("", text)


def heading_anchors(text: str) -> set[str]:
    """Match the static heading/explicit-anchor algorithm used in this audit."""
    anchors = set(EXPLICIT_ANCHOR.findall(text))
    occurrences: dict[str, int] = {}
    for line in outside_code(text).splitlines():
        match = ATX_HEADING.match(line)
        if not match:
            continue
        slug = re.sub(r"<[^>]*>", "", match[1].lower())
        slug = "".join(
            char
            for char in slug
            if char in "-_ " or unicodedata.category(char)[0] in "LN"
        ).replace(" ", "-")
        occurrence = occurrences.get(slug, 0)
        occurrences[slug] = occurrence + 1
        anchors.add(slug + ("-" + str(occurrence) if occurrence else ""))
    return anchors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=DEFAULT_REPO)
    parser.add_argument("--base", default=DEFAULT_BASE)
    parser.add_argument("--head", default=DEFAULT_HEAD)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    repo = Path(args.repo).resolve()
    output = Path(args.output).resolve()
    if output == repo or repo in output.parents:
        parser.error("Write the audit result outside the frozen repository")

    env = dict(os.environ, GIT_OPTIONAL_LOCKS="0", GIT_NO_LAZY_FETCH="1")

    def git(*command: str) -> bytes:
        return subprocess.check_output(
            ["git", *command], cwd=repo, env=env, timeout=60
        )

    def commit(ref: str) -> str:
        return git("rev-parse", "--verify", ref + "^{commit}").decode().strip()

    head = commit(args.head)
    base = commit(args.base)
    tree = git("rev-parse", head + "^{tree}").decode().strip()
    working_head_before = commit("HEAD")
    status_before = git("status", "--porcelain=v1").decode()
    changed = [
        path.decode()
        for path in git("diff", "--name-only", "-z", base, head).split(b"\0")
        if path
    ]

    files: dict[str, tuple[str, str, str]] = {}
    directories = {"."}
    for entry in git("ls-tree", "-rz", "--full-tree", head).split(b"\0"):
        if not entry:
            continue
        metadata, raw_path = entry.split(b"\t", 1)
        mode, kind, oid = metadata.decode().split(" ")
        path = raw_path.decode()
        files[path] = mode, kind, oid
        parent = posixpath.dirname(path)
        while parent:
            directories.add(parent)
            parent = posixpath.dirname(parent)

    blob_cache: dict[str, str] = {}
    anchor_cache: dict[str, set[str]] = {}

    def blob(path: str) -> str:
        if path not in blob_cache:
            blob_cache[path] = git("show", head + ":" + path).decode()
        return blob_cache[path]

    issues: list[dict] = []
    documents: list[dict] = []
    references: list[dict] = []
    fragments: list[dict] = []
    for path in changed:
        if not path.endswith(".md"):
            continue
        if path not in files or files[path][1] != "blob":
            issues.append({"kind": "changed_document_absent", "document": path})
            continue
        raw = blob(path)
        document_references: list[dict] = []
        for target in INLINE_LINK.findall(outside_code(raw)):
            uri = urlsplit(target.strip("<>"))
            if uri.scheme or uri.netloc or not uri.path:
                continue
            resolved = posixpath.normpath(
                posixpath.join(posixpath.dirname(path), unquote(uri.path))
            )
            inside_tree = not (
                resolved == ".."
                or resolved.startswith("../")
                or resolved.startswith("/")
            )
            in_tree = inside_tree and (
                resolved in files or resolved in directories
            )
            materialized = in_tree and (repo / resolved).exists()
            row = {
                "document": path,
                "target": target,
                "resolved_path": resolved,
                "present_in_git_tree": in_tree,
                "materialized_in_worktree": materialized,
            }
            references.append(row)
            document_references.append(row)
            if not in_tree:
                issues.append({"kind": "relative_target_missing_or_escape", **row})
            if uri.fragment:
                fragment = unquote(uri.fragment)
                if in_tree and resolved in files and files[resolved][1] == "blob":
                    if resolved not in anchor_cache:
                        anchor_cache[resolved] = heading_anchors(blob(resolved))
                    matched = fragment in anchor_cache[resolved]
                else:
                    matched = False
                fragment_row = {
                    "document": path,
                    "target": target,
                    "resolved_path": resolved,
                    "fragment": fragment,
                    "found_heading_or_explicit_anchor": matched,
                }
                fragments.append(fragment_row)
                if not matched:
                    issues.append({"kind": "fragment_unmatched", **fragment_row})
        documents.append(
            {
                "document": path,
                "sha256": hashlib.sha256(raw.encode()).hexdigest(),
                "relative_path_references": len(document_references),
                "tree_present_unmaterialized_references": sum(
                    row["present_in_git_tree"]
                    and not row["materialized_in_worktree"]
                    for row in document_references
                ),
                "cross_document_fragment_references": sum(
                    row["document"] == path for row in fragments
                ),
            }
        )

    working_head_after = commit("HEAD")
    status_after = git("status", "--porcelain=v1").decode()
    if working_head_before != head or working_head_after != head:
        issues.append({"kind": "working_head_does_not_match_target"})
    if status_before or status_after:
        issues.append({"kind": "worktree_not_clean"})

    counts = {
        "changed_paths": len(changed),
        "changed_markdown_documents": len(documents),
        "relative_path_references": len(references),
        "tree_present_unmaterialized_references": sum(
            row["present_in_git_tree"] and not row["materialized_in_worktree"]
            for row in references
        ),
        "cross_document_fragment_references": len(fragments),
        "matched_fragments": sum(
            row["found_heading_or_explicit_anchor"] for row in fragments
        ),
        "issues": len(issues),
    }
    result = {
        "audit": "changed-markdown-git-tree-relative-targets-and-static-anchors",
        "audit_version": 1,
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "result": "PASS" if not issues else "FAIL",
        "repository": str(repo),
        "source_base": base,
        "source_commit": head,
        "source_tree": tree,
        "working_head_before": working_head_before,
        "working_head_after": working_head_after,
        "worktree_clean_before": not status_before,
        "worktree_clean_after": not status_after,
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "scope": {
            "documents": "Full bodies of Markdown files changed from base to head",
            "targets": "Inline relative path links, resolved against exact Git tree",
            "sparse": "Unmaterialized references count occurrences, not unique paths",
            "anchors": "Nonempty fragments with relative paths; static ATX heading slugs or explicit a/h1-h6 id/name anchors",
            "not_checked": [
                "external HTTP URLs",
                "pure same-document fragment links",
                "reference-style Markdown links",
                "browser rendering and full GitHub slug equivalence",
                "whole-repository check_repository.py or other repository gates",
                "native consensus execution or probabilistic security",
            ],
        },
        "counts": counts,
        "changed_paths": [
            {"path": path, "mode": files[path][0] if path in files else None}
            for path in changed
        ],
        "documents": documents,
        "relative_references": references,
        "fragments": fragments,
        "issues": issues,
        "reproduce": [
            "python3", str(Path(__file__).resolve()), "--repo", str(repo),
            "--base", base, "--head", head, "--output", str(output),
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"result": result["result"], "source_commit": head,
                      "source_tree": tree, "counts": counts,
                      "output": str(output)}, ensure_ascii=False))
    return 0 if not issues else 1


if __name__ == "__main__":
    sys.exit(main())
