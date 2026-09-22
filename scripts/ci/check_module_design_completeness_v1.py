#!/usr/bin/env python3
"""M17 source-bound design structure checks; never semantic acceptance.

Use the existing technical-spec inventory and requirement registry, checking the
substantive sections already present.  No parallel design registration is needed.
The technical spec and its guide section together constitute the module design.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any

from module_coverage_guard_v1 import ContractError, module_sections, repository_path

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = "config/documentation-contracts-v1.json"
GUIDE = "docs/modules/TRNM_MODULE_IMPLEMENTATION_GUIDE_V1.md"
MODULES = [f"M{i:02d}" for i in range(18)]
SPEC_SECTIONS = ("Authority", "Interfaces", "State machine", "Persistence and recovery",
                 "Resource bounds", "Security", "Verification and evidence")
GUIDE_LABELS = ("Applicability and inputs", "State/admission algorithm", "Error and recovery semantics",
                "Conformance requirements", "Implementation and consumers", "Exact-source review trace")


class DesignCompletenessError(RuntimeError):
    """The module design structure or source binding is incomplete."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise DesignCompletenessError(message)


def visible_markdown(text: str) -> str:
    """Exclude examples/comments so hidden template text cannot satisfy a field."""
    text = re.sub(r"<!--.*?(?:-->|\Z)", "", text, flags=re.DOTALL)
    output: list[str] = []
    active: tuple[str, int] | None = None
    for line in text.splitlines(keepends=True):
        fence = re.match(r"^ {0,3}(`{3,}|~{3,})(.*)$", line.rstrip("\r\n"))
        if active:
            if fence and fence[1][0] == active[0] and len(fence[1]) >= active[1] and not fence[2].strip():
                active = None
            continue
        if fence:
            active = (fence[1][0], len(fence[1]))
        else:
            output.append(line)
    require(active is None, "unterminated Markdown fence")
    return "".join(output)


def section(text: str, heading: str, label: str) -> str:
    matches = list(re.finditer(r"^## " + re.escape(heading) + r"\s*$", text, re.MULTILINE))
    require(len(matches) == 1, f"{label}: expected one section {heading}")
    tail = text[matches[0].end():]
    next_heading = re.search(r"^## ", tail, re.MULTILINE)
    body = tail[:next_heading.start() if next_heading else len(tail)].strip()
    require(bool(re.search(r"[A-Za-z0-9]", body)), f"{label}: empty section {heading}")
    return body


def paragraph(text: str, label: str, module: str) -> str:
    pattern = r"^\*\*" + re.escape(label) + r"\.\*\* ([^\n]+)"
    matches = list(re.finditer(pattern, text, re.MULTILINE))
    require(len(matches) == 1, f"{module}: expected one explicit {label} paragraph")
    body = matches[0][1].strip()
    require(bool(re.search(r"[A-Za-z0-9]", body)), f"{module}: empty {label}")
    return body


def load_registry_for_test() -> list[dict[str, Any]]:
    data = json.loads((ROOT / REGISTRY).read_text(encoding="utf-8"))
    return data["modules"]


def validate(root: Path, specs: dict[str, str]) -> dict[str, Any]:
    require(list(specs) == MODULES, "technical-spec inventory must contain M00-M17 exactly once")
    fingerprints: dict[str, str] = {}

    def read(relative: str) -> str:
        try:
            path = repository_path(root, relative, "design source")
        except ContractError as error:
            raise DesignCompletenessError(str(error)) from error
        require(path.is_file(), f"design source is not a file: {relative}")
        data = path.read_bytes()
        fingerprints[relative] = hashlib.sha256(data).hexdigest()
        return data.decode("utf-8")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, f"duplicate registry JSON key: {key}")
            result[key] = value
        return result

    registry = json.loads(read(REGISTRY), object_pairs_hook=unique_object)
    require(isinstance(registry, dict), "requirement registry must be an object")
    for field in ("semantic_design_accepted", "implementation_accepted", "production_authority"):
        require(registry.get(field) is False, f"design gate cannot promote {field}")
    rows = registry.get("modules")
    require(isinstance(rows, list) and all(isinstance(row, dict) for row in rows)
            and [row.get("id") for row in rows] == MODULES, "registry module inventory drift")
    try:
        guide_sections = module_sections(read(GUIDE))
    except ContractError as error:
        raise DesignCompletenessError(str(error)) from error
    require(list(guide_sections) == MODULES, "guide must contain M00-M17 exactly once")
    requirements = 0
    for row in rows:
        module = row["id"]
        spec = visible_markdown(read(specs[module]))
        require(re.search(r"^# " + module + r"\b", spec) is not None, f"{module}: wrong technical spec")
        for heading in SPEC_SECTIONS:
            section(spec, heading, module)
        guide = guide_sections[module]
        # M17's review trace is intentionally kept in the guide's shared
        # acceptance boundary footer; it is still uniquely bound to M17 and
        # must be checked without borrowing another module's fields.
        guide_for_fields = guide
        paragraphs = {label: paragraph(guide_for_fields, label, module)
                      for label in GUIDE_LABELS if label != "Exact-source review trace"}
        if module == "M17":
            all_guide = visible_markdown(read(GUIDE))
            trace_match = re.search(r"^\*\*Exact-source review trace\.\*\* For `M17-[^`]+`[^\n]+",
                                    all_guide, re.MULTILINE)
            require(trace_match is not None, "M17: exact-source review trace missing")
            paragraphs["Exact-source review trace"] = trace_match[0]
        else:
            paragraphs["Exact-source review trace"] = paragraph(
                guide_for_fields, "Exact-source review trace", module)
        expected = row.get("requirement_ids")
        require(isinstance(expected, list) and expected and len(expected) == len(set(expected))
                and all(isinstance(item, str) and re.fullmatch(module + r"-[A-Z][A-Z0-9-]*", item) for item in expected),
                f"{module}: registry requirements invalid")
        found = re.findall(r"`(" + module + r"-[A-Z][A-Z0-9-]*)`", paragraphs["Conformance requirements"])
        require(found == expected, f"{module}: conformance requirements differ from registry")
        trace = row.get("operation_trace")
        require(isinstance(trace, dict) and trace.get("requirement_id") in expected,
                f"{module}: trace is not bound to a registered requirement")
        trace_prose = paragraphs["Exact-source review trace"]
        for role, path_field, symbol_field in (
            ("implementation", "implementation_path", "implementation_symbol"),
            ("error", "error_path", "error_symbol_or_literal"),
            ("regression", "regression_path", "regression_symbol"),
        ):
            path, symbol = trace.get(path_field), trace.get(symbol_field)
            require(isinstance(path, str) and isinstance(symbol, str) and symbol,
                    f"{module}: missing {role} trace")
            require(f"`{path}`" in trace_prose and f"`{symbol}`" in trace_prose,
                    f"{module}: {role} trace differs from registry")
            source = read(path)
            if role == "error":
                present = symbol in source
            else:
                present = re.search(r"(?m)^\s*(?:(?:pub(?:\([^)]*\))?|async|const|unsafe)\s+)*"
                                    r"(?:fn|def)\s+" + re.escape(symbol) + r"\s*[<(]", source) is not None
            require(present, f"{module}: {role} symbol/literal missing: {path}::{symbol}")
        requirements += len(expected)
    return {
        "schema": "trnm-module-design-structure-v1",
        "module_count": len(rows),
        "requirement_count": requirements,
        "scope": "spec-sections-guide-fields-conformance-ids-and-representative-source-traces",
        "input_sha256": dict(sorted(fingerprints.items())),
        "semantic_design_accepted": False,
        "implementation_accepted": False,
        "production_authority": False,
        "result": "PASS",
    }


def main() -> int:
    # Import the existing inventory only when run standalone; the wrapper
    # passes it directly and no second list or manifest is maintained.
    from check_module_coverage_v1 import SPECS
    try:
        print(json.dumps(validate(ROOT, SPECS), sort_keys=True, separators=(",", ":")))
        return 0
    except (DesignCompletenessError, OSError, UnicodeError, ValueError, TypeError) as error:
        print(f"module design structure failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
