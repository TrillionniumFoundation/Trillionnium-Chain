#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCAN_ROOT="${TRNM_UNCHECKED_GOV_SCAN_ROOT:-$ROOT/trillionnium/crates}"
CARGO_ROOT="${TRNM_UNCHECKED_GOV_CARGO_ROOT:-$ROOT/trillionnium}"

python3 - "$SCAN_ROOT" "$CARGO_ROOT" <<'PY'
from __future__ import annotations

import re
import os
import sys
import tomllib
import bisect
from pathlib import Path

TOKEN = "set_gov_param_bootstrap_unchecked"
scan_root = Path(sys.argv[1]).resolve()
cargo_root = Path(sys.argv[2]).resolve()

if not scan_root.is_dir():
    raise SystemExit(f"[FAIL] governance scan root is not a directory: {scan_root}")
if not cargo_root.is_dir():
    raise SystemExit(f"[FAIL] governance cargo root is not a directory: {cargo_root}")


def sanitize_rust(text: str) -> str:
    """Blank comments and string/raw-string bodies while preserving line numbers."""

    out = list(text)
    i = 0
    state = "code"
    block_depth = 0
    raw_hashes = 0

    def blank(pos: int) -> None:
        if out[pos] != "\n":
            out[pos] = " "

    while i < len(text):
        if state == "code":
            if text.startswith("//", i):
                blank(i)
                if i + 1 < len(text):
                    blank(i + 1)
                i += 2
                state = "line_comment"
                continue
            if text.startswith("/*", i):
                blank(i)
                if i + 1 < len(text):
                    blank(i + 1)
                i += 2
                block_depth = 1
                state = "block_comment"
                continue
            raw = re.match(r'r(#{0,255})"', text[i:]) if text[i] == "r" else None
            if raw:
                raw_hashes = len(raw.group(1))
                for pos in range(i, i + len(raw.group(0))):
                    blank(pos)
                i += len(raw.group(0))
                state = "raw_string"
                continue
            if text[i] == '"':
                blank(i)
                i += 1
                state = "string"
                continue
            if text[i] == "'":
                # Rust lifetimes (`'a`, `'static`) are not character literals.
                # Only enter character-literal mode when a closing quote can be
                # established from the literal prefix.
                if i + 2 < len(text) and text[i + 2] == "'":
                    blank(i)
                    i += 1
                    state = "char"
                    continue
                if i + 1 < len(text) and text[i + 1] == "\\":
                    blank(i)
                    i += 1
                    state = "char"
                    continue
            i += 1
            continue

        if state == "line_comment":
            if text[i] == "\n":
                state = "code"
            else:
                blank(i)
            i += 1
            continue

        if state == "block_comment":
            if text.startswith("/*", i):
                blank(i)
                if i + 1 < len(text):
                    blank(i + 1)
                i += 2
                block_depth += 1
                continue
            if text.startswith("*/", i):
                blank(i)
                if i + 1 < len(text):
                    blank(i + 1)
                i += 2
                block_depth -= 1
                if block_depth == 0:
                    state = "code"
                continue
            blank(i)
            i += 1
            continue

        if state == "string":
            if text[i] == "\\":
                blank(i)
                if i + 1 < len(text):
                    blank(i + 1)
                i += 2
                continue
            blank(i)
            if text[i] == '"':
                state = "code"
            i += 1
            continue

        if state == "char":
            if text[i] == "\\":
                blank(i)
                if i + 1 < len(text):
                    blank(i + 1)
                i += 2
                continue
            blank(i)
            if text[i] == "'":
                state = "code"
            i += 1
            continue

        if state == "raw_string":
            terminator = '"' + ('#' * raw_hashes)
            if text.startswith(terminator, i):
                for pos in range(i, i + len(terminator)):
                    blank(pos)
                i += len(terminator)
                state = "code"
                continue
            blank(i)
            i += 1
            continue

    return "".join(out)


def iter_files(root: Path, filename_predicate):
    for current, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in {"target", ".git"}]
        base = Path(current)
        for filename in filenames:
            if filename_predicate(filename):
                yield base / filename


CFG_TEST_RE = re.compile(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]")
BUILTIN_TEST_RE = re.compile(r"#\s*\[\s*test\s*\]")
INNER_CFG_TEST_RE = re.compile(r"#\s*!\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]")
CFG_TEST_UTILS_RE = re.compile(
    r'#\s*\[\s*cfg\s*\(\s*feature\s*=\s*"test-utils"\s*\)\s*\]'
)
DOC_HIDDEN_RE = re.compile(r"#\s*\[\s*doc\s*\(\s*hidden\s*\)\s*\]")


def attached_attributes(code: str, raw: str, item_start: int) -> list[tuple[str, str]]:
    """Return attributes lexically attached to an item at `item_start`."""

    cursor = item_start
    prefix = code[:cursor]
    visibility = re.search(r"pub(?:\s*\([^)]*\))?\s+$", prefix)
    if visibility:
        cursor = visibility.start()

    attrs: list[tuple[str, str]] = []
    while True:
        while cursor > 0 and code[cursor - 1].isspace():
            cursor -= 1
        if cursor == 0 or code[cursor - 1] != "]":
            break

        end = cursor
        depth = 0
        idx = cursor - 1
        while idx >= 0:
            if code[idx] == "]":
                depth += 1
            elif code[idx] == "[":
                depth -= 1
                if depth == 0:
                    break
            idx -= 1
        if idx <= 0 or code[idx - 1] != "#":
            break

        start = idx - 1
        attrs.append((code[start:end], raw[start:end]))
        cursor = start

    attrs.reverse()
    return attrs


def exact_hidden_test_utils_definition_spans(
    code: str, raw: str
) -> list[tuple[int, int]]:
    """Return only the token of lexically gated hidden test-utils definitions."""

    spans: list[tuple[int, int]] = []
    definition = re.compile(rf"\bfn\s+({re.escape(TOKEN)})\s*\(")
    for match in definition.finditer(code):
        attrs = attached_attributes(code, raw, match.start())
        raw_attrs = [raw_attr.strip() for _, raw_attr in attrs]
        if not any(CFG_TEST_UTILS_RE.fullmatch(attr) for attr in raw_attrs):
            continue
        if not any(DOC_HIDDEN_RE.fullmatch(attr) for attr in raw_attrs):
            continue
        spans.append(match.span(1))
    return spans


def exact_builtin_test_function_spans(code: str, raw: str) -> list[tuple[int, int]]:
    """Return bodies of plain functions carrying the exact built-in #[test]."""

    spans: list[tuple[int, int]] = []
    function = re.compile(r"\bfn\s+[A-Za-z_][A-Za-z0-9_]*\s*\(")
    for match in function.finditer(code):
        attrs = attached_attributes(code, raw, match.start())
        if not any(
            BUILTIN_TEST_RE.fullmatch(code_attr.strip()) for code_attr, _ in attrs
        ):
            continue

        body_start = code.find("{", match.end())
        declaration_end = code.find(";", match.end())
        if body_start < 0 or (declaration_end >= 0 and declaration_end < body_start):
            continue

        depth = 0
        for offset in range(body_start, len(code)):
            if code[offset] == "{":
                depth += 1
            elif code[offset] == "}":
                depth -= 1
                if depth == 0:
                    spans.append((body_start, offset + 1))
                    break
    return spans


def exact_cfg_test_item_spans(code: str, raw: str) -> list[tuple[int, int]]:
    """Return braced items carrying the exact built-in #[cfg(test)]."""

    spans: list[tuple[int, int]] = []
    item = re.compile(r"\b(?:fn|mod|impl|trait|struct|enum|union|const|static|extern)\b")
    for match in item.finditer(code):
        attrs = attached_attributes(code, raw, match.start())
        if not any(CFG_TEST_RE.fullmatch(attr.strip()) for attr, _ in attrs):
            continue

        body_start = code.find("{", match.end())
        declaration_end = code.find(";", match.end())
        if body_start < 0 or (declaration_end >= 0 and declaration_end < body_start):
            continue

        depth = 0
        for offset in range(body_start, len(code)):
            if code[offset] == "{":
                depth += 1
            elif code[offset] == "}":
                depth -= 1
                if depth == 0:
                    spans.append((body_start, offset + 1))
                    break
    return spans


def has_exact_leading_inner_cfg_test(code: str) -> bool:
    """Accept only an exact leading Rust inner `#![cfg(test)]` attribute."""

    cursor = 0
    length = len(code)

    def skip_space(offset: int) -> int:
        while offset < length and code[offset].isspace():
            offset += 1
        return offset

    cursor = skip_space(cursor)
    if code.startswith("#!", cursor) and not code.startswith("#![", cursor):
        newline = code.find("\n", cursor)
        if newline < 0:
            return False
        cursor = skip_space(newline + 1)

    attrs: list[str] = []
    while code.startswith("#![", cursor):
        start = cursor
        depth = 0
        end = None
        for offset in range(cursor + 2, length):
            if code[offset] == "[":
                depth += 1
            elif code[offset] == "]":
                depth -= 1
                if depth == 0:
                    end = offset + 1
                    break
        if end is None:
            return False
        attrs.append(code[start:end])
        cursor = skip_space(end)

    return any(INNER_CFG_TEST_RE.fullmatch(attr.strip()) for attr in attrs)


violations: list[str] = []
for path in sorted(iter_files(scan_root, lambda name: name.endswith(".rs"))):
    raw = path.read_text(encoding="utf-8")
    if TOKEN not in raw:
        continue

    code = sanitize_rust(raw)
    raw_lines = raw.splitlines()
    intrinsic_file_test_only = has_exact_leading_inner_cfg_test(code)
    test_spans = exact_cfg_test_item_spans(code, raw)
    test_spans.extend(exact_builtin_test_function_spans(code, raw))
    definition_spans = exact_hidden_test_utils_definition_spans(code, raw)

    line_starts = [0]
    line_starts.extend(match.end() for match in re.finditer("\n", code))
    occurrence = re.compile(rf"\b{re.escape(TOKEN)}\b")
    for match in occurrence.finditer(code):
        token_offset = match.start()
        if intrinsic_file_test_only:
            continue
        if any(start <= token_offset < end for start, end in test_spans):
            continue
        if any(start <= token_offset < end for start, end in definition_spans):
            continue
        line_no = bisect.bisect_right(line_starts, token_offset)
        raw_line = raw_lines[line_no - 1].strip()
        violations.append(f"{path}:{line_no}:{raw_line}")


def dependency_tables(doc: dict) -> list[tuple[str, dict]]:
    tables: list[tuple[str, dict]] = []
    for key in ("dependencies", "build-dependencies"):
        value = doc.get(key)
        if isinstance(value, dict):
            tables.append((key, value))

    target = doc.get("target")
    if isinstance(target, dict):
        for target_name, target_doc in target.items():
            if not isinstance(target_doc, dict):
                continue
            for key in ("dependencies", "build-dependencies"):
                value = target_doc.get(key)
                if isinstance(value, dict):
                    tables.append((f"target.{target_name}.{key}", value))
    return tables


def dependency_spec(alias: str, spec) -> tuple[set[str], set[str]]:
    packages = {alias}
    features: set[str] = set()
    if isinstance(spec, dict):
        if isinstance(spec.get("package"), str):
            packages = {str(spec["package"])}
        raw_features = spec.get("features", [])
        if isinstance(raw_features, list):
            features.update(str(value) for value in raw_features)
    return packages, features


dependency_violations: list[str] = []
manifest_docs: dict[Path, dict] = {}
for manifest in sorted(iter_files(cargo_root, lambda name: name == "Cargo.toml")):
    manifest = manifest.resolve()
    try:
        manifest_docs[manifest] = tomllib.loads(manifest.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        dependency_violations.append(f"{manifest}: invalid TOML: {exc}")


def workspace_dependencies_from_manifest(
    member_manifest: Path, workspace_manifest: Path, provenance: str
) -> dict:
    workspace_doc = manifest_docs.get(workspace_manifest)
    if not isinstance(workspace_doc, dict):
        if not workspace_manifest.is_file():
            dependency_violations.append(
                f"{member_manifest}: {provenance} does not resolve to an existing "
                f"Cargo.toml: {workspace_manifest}"
            )
            return {}
        try:
            workspace_doc = tomllib.loads(
                workspace_manifest.read_text(encoding="utf-8")
            )
        except (OSError, tomllib.TOMLDecodeError) as exc:
            dependency_violations.append(
                f"{member_manifest}: {provenance} does not resolve to a valid "
                f"Cargo.toml: {workspace_manifest}: {exc}"
            )
            return {}

    workspace = workspace_doc.get("workspace")
    if not isinstance(workspace, dict):
        dependency_violations.append(
            f"{member_manifest}: {provenance} does not name a valid [workspace] "
            f"manifest: {workspace_manifest}"
        )
        return {}

    dependencies = workspace.get("dependencies")
    if dependencies is None:
        return {}
    if not isinstance(dependencies, dict):
        dependency_violations.append(
            f"{member_manifest}: {provenance} names a workspace with an invalid "
            f"dependencies table: {workspace_manifest}"
        )
        return {}
    return dependencies


def nearest_workspace_dependencies(manifest: Path, doc: dict) -> dict:
    package = doc.get("package")
    if isinstance(package, dict) and "workspace" in package:
        explicit_workspace = package.get("workspace")
        if not isinstance(explicit_workspace, str):
            dependency_violations.append(
                f"{manifest}: [package].workspace must be a relative path string"
            )
            return {}
        if Path(explicit_workspace).is_absolute():
            dependency_violations.append(
                f"{manifest}: [package].workspace must be relative to the package manifest"
            )
            return {}
        workspace_manifest = (
            (manifest.parent / explicit_workspace).resolve() / "Cargo.toml"
        )
        return workspace_dependencies_from_manifest(
            manifest, workspace_manifest, "[package].workspace"
        )

    directory = manifest.parent
    while True:
        candidate = (directory / "Cargo.toml").resolve()
        candidate_doc = manifest_docs.get(candidate)
        if isinstance(candidate_doc, dict):
            workspace = candidate_doc.get("workspace")
            if isinstance(workspace, dict):
                return workspace_dependencies_from_manifest(
                    manifest, candidate, "nearest ancestor workspace"
                )
        if directory == cargo_root or cargo_root not in directory.parents:
            return {}
        directory = directory.parent


for manifest, doc in sorted(manifest_docs.items(), key=lambda item: str(item[0])):
    workspace_dependencies = nearest_workspace_dependencies(manifest, doc)
    production_aliases: dict[str, set[str]] = {}

    for table_name, table in dependency_tables(doc):
        for raw_alias, local_spec in table.items():
            alias = str(raw_alias)
            packages: set[str]
            features: set[str]
            if isinstance(local_spec, dict) and local_spec.get("workspace") is True:
                if alias not in workspace_dependencies:
                    dependency_violations.append(
                        f"{manifest}: [{table_name}] {alias} uses workspace=true "
                        "without a nearest workspace dependency"
                    )
                    packages, features = dependency_spec(alias, local_spec)
                else:
                    workspace_packages, workspace_features = dependency_spec(
                        alias, workspace_dependencies[alias]
                    )
                    local_packages, local_features = dependency_spec(alias, local_spec)
                    packages = set(workspace_packages)
                    if isinstance(local_spec.get("package"), str):
                        packages.update(local_packages)
                    features = workspace_features | local_features
            else:
                packages, features = dependency_spec(alias, local_spec)

            production_aliases.setdefault(alias, set()).update(packages)
            if "trnm-state" in packages and "test-utils" in features:
                dependency_violations.append(
                    f"{manifest}: [{table_name}] enables trnm-state/test-utils"
                )

    feature_table = doc.get("features")
    if isinstance(feature_table, dict):
        for feature_name, forwarded in feature_table.items():
            if not isinstance(forwarded, list):
                continue
            for raw_forward in forwarded:
                forward = str(raw_forward)
                match = re.fullmatch(
                    r"([A-Za-z0-9_.-]+)(?:\?)?/test-utils", forward
                )
                if not match:
                    continue
                alias = match.group(1)
                if "trnm-state" in production_aliases.get(alias, set()):
                    dependency_violations.append(
                        f"{manifest}: [features].{feature_name} forwards "
                        f"production capability {forward}"
                    )

    package = doc.get("package")
    if (
        isinstance(package, dict)
        and package.get("name") == "trnm-state"
        and isinstance(feature_table, dict)
    ):
        local_graph: dict[str, set[str]] = {}
        for feature_name, forwarded in feature_table.items():
            edges: set[str] = set()
            if isinstance(forwarded, list):
                for raw_forward in forwarded:
                    forward = str(raw_forward)
                    if "/" not in forward and not forward.startswith("dep:"):
                        edges.add(forward)
            local_graph[str(feature_name)] = edges

        def reaches_test_utils(start: str) -> bool:
            pending = list(local_graph.get(start, set()))
            seen: set[str] = set()
            while pending:
                current = pending.pop()
                if current == "test-utils":
                    return True
                if current in seen:
                    continue
                seen.add(current)
                pending.extend(local_graph.get(current, set()))
            return False

        for feature_name in sorted(local_graph):
            if feature_name != "test-utils" and reaches_test_utils(feature_name):
                dependency_violations.append(
                    f"{manifest}: [features].{feature_name} transitively enables "
                    "the intrinsic test-utils feature"
                )


if violations or dependency_violations:
    if violations:
        print(
            f"[FAIL] disallowed {TOKEN} production usage detected:",
            file=sys.stderr,
        )
        for item in violations:
            print(item, file=sys.stderr)
    if dependency_violations:
        print(
            "[FAIL] trnm-state/test-utils must remain dev-dependency-only:",
            file=sys.stderr,
        )
        for item in dependency_violations:
            print(item, file=sys.stderr)
    raise SystemExit(2)

print(
    "[OK] governance bootstrap-unchecked access is limited to hidden test-utils "
    "definitions and exact intrinsic Rust test scopes"
)
PY
