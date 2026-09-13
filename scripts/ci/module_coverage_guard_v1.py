#!/usr/bin/env python3
"""M17 structural documentation checks; never an implementation acceptance oracle."""
from __future__ import annotations

import pathlib
import re
from typing import Any


class ContractError(ValueError):
    """A repository contract could not be validated without guessing."""


def repository_path(root: pathlib.Path, relative: Any, label: str) -> pathlib.Path:
    """Resolve an existing, canonical, repository-contained POSIX path.

    Internal symlinks are allowed (the plan has a deliberate compatibility link),
    but symlink escape, Windows paths, parent traversal and aliases are not.
    This is a CI check, not a race-free filesystem authority primitive.
    """
    if not isinstance(relative, str) or not relative or "\x00" in relative:
        raise ContractError(f"{label}: nonempty relative path required")
    if "\\" in relative or ":" in relative:
        raise ContractError(f"{label}: POSIX repository path required: {relative!r}")
    parts = relative.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ContractError(f"{label}: noncanonical repository path: {relative!r}")
    try:
        base = root.resolve(strict=True)
        resolved = (base / relative).resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as error:
        raise ContractError(f"{label}: missing or unresolvable path: {relative!r}") from error
    if not resolved.is_relative_to(base) or resolved == base:
        raise ContractError(f"{label}: path escapes repository: {relative!r}")
    if not (resolved.is_file() or resolved.is_dir()):
        raise ContractError(f"{label}: regular file or directory required: {relative!r}")
    return resolved


def module_sections(text: str) -> dict[str, str]:
    """Read visible module sections, excluding comments and fenced examples.

    Duplicate module headings are errors. Any peer level-two heading terminates
    a section, so the final module cannot borrow length/markers from a footer.
    This intentionally checks structure only, not adequacy of technical design.
    """
    text = re.sub(r"<!--.*?(?:-->|\Z)", "", text, flags=re.DOTALL)
    sections: dict[str, list[str]] = {}
    current: str | None = None
    fence_char: str | None = None
    fence_length = 0
    for line in text.splitlines(keepends=True):
        fence = re.match(r"^ {0,3}(`{3,}|~{3,})(.*)$", line.rstrip("\r\n"))
        if fence_char is not None:
            if (fence and fence.group(1)[0] == fence_char
                    and len(fence.group(1)) >= fence_length
                    and not fence.group(2).strip()):
                fence_char = None
            continue
        if fence:
            fence_char = fence.group(1)[0]
            fence_length = len(fence.group(1))
            continue
        if re.match(r"^##\s+", line):
            current = None
            heading = re.match(r"^## (M\d{2})\s+—[^\n]*", line)
            if heading:
                current = heading.group(1)
                if current in sections:
                    raise ContractError(f"duplicate technical module section: {current}")
                sections[current] = []
        if current is not None:
            sections[current].append(line)
    if fence_char is not None:
        raise ContractError("unterminated Markdown fence in technical reference")
    return {key: "".join(lines) for key, lines in sections.items()}


def active_codeowners(text: str) -> set[str]:
    """Collect exact GitHub user/team tokens from active ownership rules.

    This does not prove reviewer eligibility, team provisioning, independence,
    effective per-path coverage or two independent approvals.
    """
    owners: set[str] = set()
    for line in text.splitlines():
        tokens = line.partition("#")[0].split()
        if len(tokens) < 2:
            continue
        # Owner tokens without a path are not a valid ownership rule.
        if tokens[0].startswith("@"):
            continue
        for token in tokens[1:]:
            if re.fullmatch(r"@[A-Za-z0-9][A-Za-z0-9-]*(?:/[A-Za-z0-9_.-]+)?", token):
                owners.add(token[1:])
    return owners


def dependency_graph(graph: dict[str, list[str]]) -> None:
    """Validate the declared graph only; Cargo-resolved closure is separate."""
    for source, targets in graph.items():
        if not isinstance(source, str) or not isinstance(targets, list):
            raise ContractError("module dependency graph requires string keys and lists")
        if any(not isinstance(target, str) for target in targets):
            raise ContractError(f"{source}: dependency IDs must be strings")
        if len(set(targets)) != len(targets):
            raise ContractError(f"{source}: duplicate allowed dependency")
        for target in targets:
            if target not in graph:
                raise ContractError(f"{source}: unknown allowed dependency {target}")
    visited: set[str] = set()
    stack: list[str] = []

    def visit(source: str) -> None:
        if source in stack:
            raise ContractError("module dependency cycle: " + " -> ".join(stack + [source]))
        if source in visited:
            return
        stack.append(source)
        for target in graph[source]:
            visit(target)
        stack.pop()
        visited.add(source)

    for source in graph:
        visit(source)
