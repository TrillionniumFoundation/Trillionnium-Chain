#!/usr/bin/env python3
"""Fail-closed documentation integrity checks for Trillionnium Chain."""

from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[2]
ROOT_README = ROOT / "README.md"
WORKSPACE = ROOT / "trillionnium" / "Cargo.toml"
CATALOG = ROOT / "docs" / "MODULE_CATALOG.md"

REQUIRED_ROOT_HEADINGS = (
    "# Trillionnium Chain (TRNM)",
    "## Repository map",
    "## Maturity and scope",
    "## Build and test",
    "## Module documentation",
    "## Documentation entry points",
    "## Contribution and evidence rules",
    "## Security",
)

REQUIRED_MODULE_HEADINGS = (
    "## Responsibilities",
    "## Non-responsibilities and production boundary",
    "## Source layout",
    "## Required invariants",
    "## Build and test",
    "## Failure, recovery, and observability",
    "## Change rules",
    "## Known gaps / activation conditions",
    "## References",
)

REQUIRED_METADATA = ("status", "owner", "last_verified", "applies_to")

CANONICAL_ENTRYPOINTS = (
    "README.md",
    "docs/README.md",
    "docs/DOCUMENTATION_STANDARD.md",
    "docs/MODULE_CATALOG.md",
    "docs/architecture/README.md",
    "docs/protocol/README.md",
    "docs/runbooks/README.md",
    "docs/release/README.md",
    "trillionnium/README.md",
    "trillionnium/crates/README.md",
    "contracts/README.md",
    "web4-frontend/README.md",
    "web4-frontend/docs/README.md",
)

LINK_RE = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")


def error(errors: list[str], message: str) -> None:
    errors.append(message)


def read_text(path: Path, errors: list[str]) -> str:
    if not path.is_file():
        error(errors, f"missing file: {path.relative_to(ROOT)}")
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        error(errors, f"non-UTF-8 file: {path.relative_to(ROOT)}: {exc}")
        return ""


def parse_frontmatter(path: Path, text: str, errors: list[str]) -> dict[str, str]:
    if not text.startswith("---\n"):
        error(errors, f"missing front matter: {path.relative_to(ROOT)}")
        return {}
    end = text.find("\n---\n", 4)
    if end < 0:
        error(errors, f"unterminated front matter: {path.relative_to(ROOT)}")
        return {}
    values: dict[str, str] = {}
    for raw in text[4:end].splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if ":" not in raw:
            error(errors, f"invalid front matter line in {path.relative_to(ROOT)}: {raw!r}")
            continue
        key, value = raw.split(":", 1)
        values[key.strip()] = value.strip()
    for key in REQUIRED_METADATA:
        if not values.get(key):
            error(errors, f"missing metadata {key!r}: {path.relative_to(ROOT)}")
    return values


def workspace_members(errors: list[str]) -> list[str]:
    if not WORKSPACE.is_file():
        error(errors, "missing trillionnium/Cargo.toml")
        return []
    try:
        data = tomllib.loads(WORKSPACE.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        error(errors, f"cannot parse trillionnium/Cargo.toml: {exc}")
        return []
    members = data.get("workspace", {}).get("members", [])
    if not isinstance(members, list) or not members:
        error(errors, "workspace.members is empty or invalid")
        return []
    normalized: list[str] = []
    for member in members:
        if not isinstance(member, str) or not member.startswith("crates/"):
            error(errors, f"unexpected workspace member: {member!r}")
            continue
        normalized.append(member)
    if len(normalized) != len(set(normalized)):
        error(errors, "workspace.members contains duplicates")
    return normalized


def check_root(errors: list[str]) -> None:
    text = read_text(ROOT_README, errors)
    if not text.strip():
        error(errors, "root README is empty or whitespace-only")
        return
    if len(text.splitlines()) < 80:
        error(errors, f"root README is unexpectedly short: {len(text.splitlines())} lines")
    for heading in REQUIRED_ROOT_HEADINGS:
        if heading not in text:
            error(errors, f"root README missing required heading: {heading}")


def check_modules(errors: list[str]) -> list[Path]:
    members = workspace_members(errors)
    catalog = read_text(CATALOG, errors)
    docs: list[Path] = []
    for member in members:
        crate_name = Path(member).name
        crate_dir = ROOT / "trillionnium" / member
        cargo = crate_dir / "Cargo.toml"
        readme = crate_dir / "README.md"
        if not cargo.is_file():
            error(errors, f"workspace member missing Cargo.toml: {member}")
        text = read_text(readme, errors)
        docs.append(readme)
        if text:
            parse_frontmatter(readme, text, errors)
            if f"# `{crate_name}`" not in text:
                error(errors, f"module title mismatch: {readme.relative_to(ROOT)}")
            for heading in REQUIRED_MODULE_HEADINGS:
                if heading not in text:
                    error(errors, f"{readme.relative_to(ROOT)} missing heading: {heading}")
            if "RELEASE_READINESS.md" not in text:
                error(errors, f"{readme.relative_to(ROOT)} lacks release truth-source link")
        if f"`{crate_name}`" not in catalog:
            error(errors, f"module catalog missing workspace member: {crate_name}")
    return docs


def clean_target(raw: str) -> str | None:
    target = raw.strip()
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1].strip()
    if not target or target.startswith(("#", "http://", "https://", "mailto:", "data:")):
        return None
    target = target.split("#", 1)[0].split("?", 1)[0]
    if not target:
        return None
    return unquote(target)


def check_links(path: Path, text: str, errors: list[str]) -> int:
    checked = 0
    for raw in LINK_RE.findall(text):
        target = clean_target(raw)
        if target is None:
            continue
        checked += 1
        if target.startswith("/"):
            error(errors, f"absolute repository link is not allowed in {path.relative_to(ROOT)}: {raw}")
            continue
        resolved = (path.parent / target).resolve()
        try:
            resolved.relative_to(ROOT.resolve())
        except ValueError:
            error(errors, f"link escapes repository in {path.relative_to(ROOT)}: {raw}")
            continue
        if not resolved.exists():
            error(errors, f"broken link in {path.relative_to(ROOT)}: {raw}")
    return checked


def check_canonical_links(module_docs: list[Path], errors: list[str]) -> int:
    paths = [ROOT / rel for rel in CANONICAL_ENTRYPOINTS]
    paths.extend(module_docs)
    total = 0
    seen: set[Path] = set()
    for path in paths:
        path = path.resolve()
        if path in seen:
            continue
        seen.add(path)
        text = read_text(path, errors)
        if text:
            if path.name == "README.md" and path.parent.name in {
                "docs", "architecture", "protocol", "runbooks", "release", "trillionnium", "crates"
            }:
                # Canonical index-like files carry metadata. The root and existing
                # subproject READMEs are intentionally excluded from this rule.
                rel = path.relative_to(ROOT)
                if str(rel) in {
                    "docs/README.md",
                    "docs/architecture/README.md",
                    "docs/protocol/README.md",
                    "docs/runbooks/README.md",
                    "docs/release/README.md",
                    "trillionnium/README.md",
                    "trillionnium/crates/README.md",
                }:
                    parse_frontmatter(path, text, errors)
            total += check_links(path, text, errors)
    if total == 0:
        error(errors, "canonical documentation contains zero checked relative links")
    return total


def main() -> int:
    errors: list[str] = []
    check_root(errors)
    module_docs = check_modules(errors)
    link_count = check_canonical_links(module_docs, errors)

    summary = {
        "status": "fail" if errors else "ok",
        "workspace_modules": len(module_docs),
        "relative_links_checked": link_count,
        "errors": errors,
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    if errors:
        for item in errors:
            print(f"[documentation-integrity][FAIL] {item}", file=sys.stderr)
        return 1
    print("[documentation-integrity] status=ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
