#!/usr/bin/env python3
"""Inventory operation obligations without mistaking headings for completeness.

One Markdown supplement supplies design rows. Existing executable catalogs are
read unchanged. Public Rust declarations are a lexical discovery aid only:
macros, trait members, reexports, foreign languages and feature reachability need
separate review. No generated count establishes a complete runtime surface.
"""
from __future__ import annotations

import argparse
from bisect import bisect_right
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tomllib
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DESIGN = "docs/modules/TRNM_OPERATION_DESIGN_V2.md"
ECONOMICS = "docs/security/POCO_ECONOMIC_SECURITY_CONTRACT_V1.md"
COVERAGE = "config/module-coverage-v1.toml"
CATALOGS = ("config/documentation-operations-v1.json",
            "config/documentation-operations-supplement-v1.json")
MODULES = [f"M{i:02d}" for i in range(18)]
MAX_SOURCE_BYTES = 256 * 1024 * 1024
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_FILES = 20_000


class DesignError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise DesignError(message)


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in out, f"duplicate JSON key: {key}")
        out[key] = value
    return out


def local(root: Path, relative: str) -> Path:
    require(isinstance(relative, str) and bool(relative), "empty path")
    path = PurePosixPath(relative)
    require(not path.is_absolute() and "\\" not in relative and ":" not in relative
            and all(part not in {"", ".", ".."} for part in relative.split("/")), "unsafe path")
    current = root
    for part in path.parts:
        current = current / part
        require(not current.is_symlink(), f"symlink input: {relative}")
    require(current.resolve().is_relative_to(root.resolve()), "path escape")
    require(current.is_file(), f"missing input: {relative}")
    require(current.stat().st_size <= MAX_FILE_BYTES, f"input too large: {relative}")
    return current


def parse_design(text: str) -> dict[str, list[dict[str, str]]]:
    rows: dict[str, list[dict[str, str]]] = {}
    seen: set[str] = set()
    current = None
    for line in text.splitlines():
        heading = re.fullmatch(r"## (M\d{2}) — .+", line)
        if heading:
            current = heading[1]
            require(current in MODULES and current not in rows, "duplicate/unknown module")
            rows[current] = []
        if not re.match(r"\| M\d{2}-OP-", line):
            continue
        columns = [value.strip() for value in line.strip().strip("|").split("|")]
        require(len(columns) == 6 and all(columns), "operation needs six explicit obligations")
        oid = columns[0]
        require(current is not None and re.fullmatch(current + r"-OP-[A-Z0-9-]+", oid)
                is not None and oid not in seen, "duplicate/foreign operation")
        seen.add(oid)
        rows[current].append(dict(zip(("id", "entry", "transition", "durability", "failure", "acceptance"), columns)))
    require(list(rows) == MODULES and all(rows.values()), "design must include nonempty ordered M00-M17")
    return rows


def rust_code_only(text: str) -> str:
    """Mask comments/string/char literals, preserving line offsets; NOT a Rust AST."""
    raw_pattern = re.compile(r'(?:br|cr|r)(#{0,255})"')
    char_pattern = re.compile(r"'(?:\\(?:u\{[0-9A-Fa-f_]+\}|x[0-9A-Fa-f]{2}|.)|[^'\\\n])'")
    out = list(text)
    i = 0
    while i < len(text):
        end = None
        if text.startswith("//", i):
            end = text.find("\n", i)
            end = len(text) if end < 0 else end
        elif text.startswith("/*", i):
            depth, end = 1, i + 2
            while end < len(text) and depth:
                if text.startswith("/*", end):
                    depth += 1
                    end += 2
                elif text.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
        else:
            raw = raw_pattern.match(text, i) if text[i] in "bcr" else None
            if raw and (i == 0 or not (text[i-1].isalnum() or text[i-1] == "_")):
                stop = text.find('"' + raw[1], raw.end())
                end = len(text) if stop < 0 else stop + 1 + len(raw[1])
            elif text[i] == '"':
                end = i + 1
                while end < len(text):
                    if text[end] == "\\":
                        end += 2
                    elif text[end] == '"':
                        end += 1
                        break
                    else:
                        end += 1
            elif text[i] == "'":
                char = char_pattern.match(text, i)
                if char:
                    end = char.end()
        if end is None:
            i += 1
        else:
            end = min(end, len(text))
            out[i:end] = ["\n" if char == "\n" else " " for char in text[i:end]]
            i = end
    return "".join(out)


def public_functions(text: str) -> list[tuple[str, int]]:
    code = rust_code_only(text)
    pattern = r'(?m)^\s*pub\s+(?:(?:async|const|unsafe)\s+|extern\s+)*fn\s+(r#)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:[<(])'
    newlines = [index for index, char in enumerate(code) if char == "\n"]
    return [(match[2], bisect_right(newlines, match.start(2)) + 1)
            for match in re.finditer(pattern, code)]


def inventory(root: Path, scan_public: bool = False) -> dict[str, Any]:
    root = root.resolve()
    digests: dict[str, str] = {}
    total_bytes = 0

    def read(relative: str) -> str:
        nonlocal total_bytes
        raw = local(root, relative).read_bytes()
        if relative not in digests:
            total_bytes += len(raw)
            require(total_bytes <= MAX_SOURCE_BYTES and len(digests) < MAX_FILES, "source inventory budget")
            digests[relative] = hashlib.sha256(raw).hexdigest()
        return raw.decode("utf-8")

    design = parse_design(read(DESIGN))
    read(ECONOMICS)
    coverage = tomllib.loads(read(COVERAGE))
    ownership = coverage.get("module_coverage", [])
    require([row.get("id") for row in ownership] == MODULES, "coverage module inventory")
    owners: dict[str, str] = {}
    for row in ownership:
        require(isinstance(row.get("primary_crates"), list), "crate inventory")
        for crate in row["primary_crates"]:
            require(isinstance(crate, str) and re.fullmatch(r"[a-z0-9_-]+", crate) is not None
                    and crate not in owners, "duplicate/invalid crate ownership")
            owners[crate] = row["id"]

    registered: dict[str, list[str]] = {mid: [] for mid in MODULES}
    bindings: set[tuple[str, str]] = set()
    operation_ids: set[str] = set()
    case_count = 0
    for catalog in CATALOGS:
        data = json.loads(read(catalog), object_pairs_hook=strict_object)
        require(data.get("production_authority") is False, "catalog cannot activate")
        require(data.get("semantic_acceptance") == data.get("implementation_acceptance") == "not-assessed",
                "catalog acceptance is not this checker's authority")
        for row in data["operations"]:
            mid, oid = row["module_id"], row["id"]
            require(mid in registered and oid not in operation_ids, "duplicate/unknown registered operation")
            require(isinstance(oid, str) and oid.startswith(mid + "-OP-"), "operation identity")
            operation_ids.add(oid)
            impl = row["implementation"]
            package, path, symbol = impl["package"], impl["path"], impl["symbol"]
            require(package in owners and path.startswith(f"trillionnium/crates/{package}/src/"),
                    "implementation ownership")
            require(isinstance(symbol, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", symbol) is not None,
                    "symbol spelling")
            source = rust_code_only(read(path))
            require(re.search(r"\bfn\s+" + re.escape(symbol) + r"\s*[<(]", source) is not None,
                    "catalog implementation symbol absent")
            registered[mid].append(oid)
            bindings.add((path, symbol))
            cases = row.get("cases")
            require(isinstance(cases, list) and bool(cases), "registered operation has no replay cases")
            for case in cases:
                read(case["source_path"])
            case_count += len(cases)

    declarations: list[dict[str, Any]] = []
    for crate, mid in (sorted(owners.items()) if scan_public else []):
        manifest = tomllib.loads(read(f"trillionnium/crates/{crate}/Cargo.toml"))
        require(manifest.get("package", {}).get("name") == crate, "crate manifest identity")
        source_root = root / "trillionnium/crates" / crate / "src"
        require(source_root.is_dir() and not source_root.is_symlink(), "missing/symlink crate source")
        for path in sorted(source_root.rglob("*.rs")):
            relative = path.relative_to(root).as_posix()
            text = read(relative)
            for symbol, line in public_functions(text):
                declarations.append({"module": mid, "path": relative, "symbol": symbol, "line": line,
                                     "catalog_name_match": (relative, symbol) in bindings})
    summaries = []
    for mid in MODULES:
        declared = [row for row in declarations if row["module"] == mid]
        summaries.append({"module": mid, "design_operations": len(design[mid]),
                          "registered_operations": len(registered[mid]),
                          "public_declarations": len(declared) if scan_public else None,
                          "unclassified_public_declarations": sum(not row["catalog_name_match"] for row in declared) if scan_public else None})
    digest = hashlib.sha256(json.dumps(digests, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"schema": "trnm-operation-design-inventory-v2", "result": "PASS",
            "design_operation_count": sum(map(len, design.values())),
            "registered_operation_count": len(operation_ids), "registered_case_count": case_count,
            "modules": summaries, "public_declarations": declarations, "public_scan_executed": scan_public,
            "input_files": len(digests), "input_bytes": total_bytes, "input_set_sha256": digest,
            "whole_project_operation_catalog_complete": False, "semantic_acceptance": "not-assessed",
            "implementation_acceptance": "not-assessed", "production_authority": False,
            "limitations": ["PASS means readable design and inventory, not complete operation coverage.",
                            "Name matches do not prove feature reachability or consumer composition.",
                            "Rust lexical inventory omits macros, trait members and reexports; includes conditional/test code.",
                            "Auxiliary/non-Rust public surfaces and target-only adapters need explicit classification.",
                            "Registered test references are not execution receipts or independent vectors."]}


def source_identity(root: Path) -> dict[str, Any]:
    try:
        head = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL).strip()
        tree = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD^{tree}"], text=True, stderr=subprocess.DEVNULL).strip()
        dirty = bool(subprocess.check_output(["git", "-C", str(root), "status", "--porcelain", "--untracked-files=all"], text=True))
        return {"commit": head, "tree": tree, "worktree_dirty": dirty}
    except (OSError, subprocess.CalledProcessError):
        return {"commit": None, "tree": None, "worktree_dirty": None}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--scan-public", action="store_true", help="bounded full Rust declaration audit; default is fast registered-surface feedback")
    args = parser.parse_args()
    try:
        report = inventory(args.root, scan_public=args.scan_public)
        report["source"] = source_identity(args.root)
        if args.output:
            require(not args.output.resolve().is_relative_to(args.root.resolve()), "write report outside source tree")
            args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps({key: value for key, value in report.items() if key != "public_declarations"}, sort_keys=True))
        return 0
    except (DesignError, OSError, ValueError, TypeError, KeyError) as error:
        print(json.dumps({"result": "FAIL", "error": str(error), "production_authority": False}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
