#!/usr/bin/env python3
"""Inventory public authority traits and public capability-minting APIs.

The scanner is deliberately standard-library only. It does not decide protocol
semantics; it produces a deterministic review inventory and highlights public
generic verifier paths that return opaque `Verified*` capabilities without a
visible sealed supertrait.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any


ROOT = Path("trillionnium/crates")
AUTHORITY_SUFFIXES = (
    "Verifier",
    "VerifierV0",
    "VerifierV1",
    "Resolver",
    "ResolverV0",
    "ResolverV1",
    "Authority",
    "AuthorityV0",
    "AuthorityV1",
    "Producer",
    "ProducerV0",
    "ProducerV1",
    "Signer",
    "SignerV0",
    "SignerV1",
)

TRAIT_RE = re.compile(
    r"(?m)^(?P<indent>\s*)pub(?:\([^\n)]*\))?\s+trait\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?P<tail>[^\{;]*)\{"
)
MINT_RE = re.compile(
    r"(?ms)^\s*pub(?:\([^\n)]*\))?\s+fn\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"(?:<(?P<generics>[^\{]{0,1200}?)>)?\s*"
    r"\((?P<args>[^\{]{0,2400}?)\)\s*"
    r"(?:where\s+(?P<where>[^\{]{0,1600}?))?"
    r"->\s*(?P<return>Result\s*<\s*(?P<cap>Verified[A-Za-z0-9_]*)[^\{]{0,400})\{"
)
DIRECT_MINT_RE = re.compile(
    r"(?ms)^\s*pub(?:\([^\n)]*\))?\s+fn\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)[^\{]{0,3000}?"
    r"->\s*(?P<cap>Verified[A-Za-z0-9_]*)\s*\{"
)
BOUND_RE = re.compile(
    r"(?:^|[,\s])(?P<param>[A-Z][A-Za-z0-9_]*)\s*:\s*"
    r"(?P<bounds>[A-Za-z_][A-Za-z0-9_:]*(?:\s*\+\s*[A-Za-z_][A-Za-z0-9_:]*)*)"
)


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def normalize_header(value: str) -> str:
    return " ".join(value.split())


def authority_like(name: str) -> bool:
    return any(name.endswith(suffix) for suffix in AUTHORITY_SUFFIXES)


def parse_bounds(fragment: str) -> list[str]:
    result: list[str] = []
    for match in BOUND_RE.finditer(fragment):
        for bound in match.group("bounds").split("+"):
            candidate = bound.strip().split("::")[-1]
            if candidate and candidate not in result:
                result.append(candidate)
    return result


def main() -> int:
    if not ROOT.is_dir():
        raise SystemExit(f"missing Rust workspace root: {ROOT}")

    traits: list[dict[str, Any]] = []
    trait_index: dict[str, list[dict[str, Any]]] = {}
    mints: list[dict[str, Any]] = []

    for path in sorted(ROOT.rglob("*.rs")):
        text = path.read_text(encoding="utf-8")
        relative = path.as_posix()
        for match in TRAIT_RE.finditer(text):
            name = match.group("name")
            tail = normalize_header(match.group("tail"))
            record = {
                "path": relative,
                "line": line_number(text, match.start()),
                "name": name,
                "header_tail": tail,
                "authority_like": authority_like(name),
                "sealed_supertrait_visible": "Sealed" in tail,
            }
            traits.append(record)
            trait_index.setdefault(name, []).append(record)

        for match in MINT_RE.finditer(text):
            generics = match.group("generics") or ""
            where_clause = match.group("where") or ""
            bounds = parse_bounds(generics + " " + where_clause)
            mints.append(
                {
                    "path": relative,
                    "line": line_number(text, match.start()),
                    "function": match.group("name"),
                    "capability": match.group("cap"),
                    "generic_bounds": bounds,
                    "direct_return": False,
                }
            )

        for match in DIRECT_MINT_RE.finditer(text):
            candidate = {
                "path": relative,
                "line": line_number(text, match.start()),
                "function": match.group("name"),
                "capability": match.group("cap"),
                "generic_bounds": [],
                "direct_return": True,
            }
            if not any(
                row["path"] == candidate["path"]
                and row["line"] == candidate["line"]
                and row["function"] == candidate["function"]
                for row in mints
            ):
                mints.append(candidate)

    public_authority_traits = [row for row in traits if row["authority_like"]]
    findings: list[dict[str, Any]] = []
    for mint in mints:
        for bound in mint["generic_bounds"]:
            definitions = trait_index.get(bound, [])
            if not definitions:
                continue
            if not authority_like(bound):
                continue
            sealed = any(row["sealed_supertrait_visible"] for row in definitions)
            findings.append(
                {
                    "severity": "review-required" if sealed else "candidate-p0",
                    "mint_path": {
                        "path": mint["path"],
                        "line": mint["line"],
                        "function": mint["function"],
                        "capability": mint["capability"],
                    },
                    "authority_trait": bound,
                    "trait_definitions": definitions,
                    "sealed_supertrait_visible": sealed,
                }
            )

    report: dict[str, Any] = {
        "schema": "trnm-capability-authority-audit-v1",
        "root": ROOT.as_posix(),
        "rust_files": len(list(ROOT.rglob("*.rs"))),
        "public_traits": len(traits),
        "public_authority_traits": public_authority_traits,
        "public_verified_capability_mints": sorted(
            mints, key=lambda row: (row["path"], row["line"], row["function"])
        ),
        "generic_authority_mint_findings": sorted(
            findings,
            key=lambda row: (
                row["severity"],
                row["mint_path"]["path"],
                row["mint_path"]["line"],
                row["authority_trait"],
            ),
        ),
    }
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":"))
    report["sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    rendered = json.dumps(report, sort_keys=True, indent=2)
    Path("/tmp/trnm-capability-authority-audit-v1.json").write_text(
        rendered + "\n", encoding="utf-8"
    )
    print(rendered)
    print(
        "authority_audit_summary "
        f"files={report['rust_files']} traits={report['public_traits']} "
        f"authority_traits={len(public_authority_traits)} "
        f"verified_mints={len(mints)} findings={len(findings)} "
        f"sha256={report['sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
