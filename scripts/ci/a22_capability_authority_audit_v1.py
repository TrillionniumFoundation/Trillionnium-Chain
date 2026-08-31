#!/usr/bin/env python3
"""Audit public capability minting and authority-upgrade boundaries.

The scanner is deliberately standard-library only.  It inventories public
`Verified*` constructors, joins them to an exact reviewed policy, verifies the
repository-owned production implementations, and rejects any new public path
that can upgrade an inert migration observation into consensus authority.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any


ROOT = Path("trillionnium/crates")
POLICY_PATH = Path("scripts/ci/a22_capability_authority_policy_v1.json")
COMPILE_FAIL_PATH = Path("scripts/ci/a22_inert_capability_compile_fail_v1.sh")
REHEARSAL_PATH = Path(
    "trillionnium/crates/trnm-consensus-app/src/migration_rehearsal.rs"
)

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
INERT_CAPABILITIES = frozenset(
    {
        "VerifiedCometStateExportV1",
        "VerifiedPocoTargetProjectionV1",
        "VerifiedPocoTargetGenesisCeremonyV1",
    }
)
MIGRATION_AUTHORITY_TRAITS = (
    "CometStateExportVerifierV1",
    "PocoTargetProjectionVerifierV1",
    "PocoTargetProjectionManifestVerifierV1",
)
APPROVED_PRODUCTION_IMPL_SNIPPETS = {
    "CometStateExportVerifierV1": (
        "impl CometStateExportVerifierV1 for MigrationSourceVerifierV1<'_>",
    ),
    "PocoTargetProjectionVerifierV1": (),
    "PocoTargetProjectionManifestVerifierV1": (
        "impl PocoTargetProjectionManifestVerifierV1 for MigrationTargetReplayVerifierV1<'_>",
    ),
}
REQUIRED_COMPILE_FAIL_PROOFS = (
    "A22-CF-COMET-TO-GENESIS-QC",
    "A22-CF-COMET-TO-CORE",
    "A22-CF-PROJECTION-TO-GENESIS-QC",
    "A22-CF-PROJECTION-TO-CORE",
    "A22-CF-CEREMONY-TO-GENESIS-QC",
    "A22-CF-CEREMONY-TO-CORE",
    "A21-SEALED-NATIVE-COMMIT-VERIFIER",
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
PUBLIC_FN_RE = re.compile(
    r"(?ms)^\s*pub(?:\([^\n)]*\))?\s+"
    r"(?:(?:const|async|unsafe)\s+)*fn\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?P<signature>[^\{;]{0,5000})\{"
)
AUTHORITY_RETURN_RE = re.compile(
    r"\b(?:"
    r"GenesisQcV0|Core|SafetyState|Effect|StorageAck|RequestSignature|SignIntent|"
    r"[A-Za-z_][A-Za-z0-9_]*(?:Activation|Permit|Authority)[A-Za-z0-9_]*|"
    r"[A-Za-z_][A-Za-z0-9_]*(?:CoreAccepted|CoreIssued)[A-Za-z0-9_]*"
    r")\b"
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


def finding_key(row: dict[str, Any]) -> tuple[str, str, str, str]:
    mint = row["mint_path"]
    return (
        mint["path"],
        mint["function"],
        mint["capability"],
        row["authority_trait"],
    )


def policy_key(row: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        row["path"],
        row["function"],
        row["capability"],
        row["authority_trait"],
    )


def key_record(key: tuple[str, str, str, str]) -> dict[str, str]:
    return {
        "path": key[0],
        "function": key[1],
        "capability": key[2],
        "authority_trait": key[3],
    }


def matching_brace(text: str, opening: int) -> int:
    depth = 0
    for offset in range(opening, len(text)):
        byte = text[offset]
        if byte == "{":
            depth += 1
        elif byte == "}":
            depth -= 1
            if depth == 0:
                return offset
    raise ValueError(f"unmatched opening brace at offset {opening}")


def named_function_body(text: str, name: str) -> str:
    match = re.search(rf"\bpub\s+fn\s+{re.escape(name)}\s*\(", text)
    if match is None:
        return ""
    opening = text.find("{", match.end())
    if opening < 0:
        return ""
    try:
        closing = matching_brace(text, opening)
    except ValueError:
        return ""
    return text[opening + 1 : closing]


def is_test_only_location(path: Path, text: str, offset: int) -> bool:
    if "tests" in path.parts or path.name == "tests.rs":
        return True
    test_modules = [
        match.start()
        for match in re.finditer(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*mod\s+tests", text)
    ]
    return any(start <= offset for start in test_modules)


def dangerous_return_type(return_fragment: str) -> bool:
    return AUTHORITY_RETURN_RE.search(return_fragment) is not None


def scan_public_authority_sinks(
    rust_sources: list[tuple[Path, str]],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    for path, text in rust_sources:
        relative = path.as_posix()
        for capability in sorted(INERT_CAPABILITIES):
            escaped = re.escape(capability)
            conversions = (
                re.compile(
                    rf"(?ms)^\s*impl(?:\s*<[^\{{\}};]{{0,800}}>)?\s+"
                    rf"(?P<kind>From|TryFrom)\s*<\s*&?\s*(?:[A-Za-z_][A-Za-z0-9_]*::)*{escaped}\s*>\s+"
                    rf"for\s+(?P<target>[^\{{\n]{{1,500}})\{{"
                ),
                re.compile(
                    rf"(?ms)^\s*impl(?:\s*<[^\{{\}};]{{0,800}}>)?\s+"
                    rf"(?P<kind>Into|TryInto)\s*<\s*(?P<target>[^>\n]{{1,500}})>\s+"
                    rf"for\s+&?\s*(?:[A-Za-z_][A-Za-z0-9_]*::)*{escaped}\s*\{{"
                ),
            )
            for pattern in conversions:
                for match in pattern.finditer(text):
                    target = normalize_header(match.group("target"))
                    if dangerous_return_type(target):
                        findings.append(
                            {
                                "kind": "authority-conversion-impl",
                                "path": relative,
                                "line": line_number(text, match.start()),
                                "capability": capability,
                                "conversion": match.group("kind"),
                                "target": target,
                            }
                        )

        for match in PUBLIC_FN_RE.finditer(text):
            signature = match.group("signature")
            if "->" not in signature:
                continue
            inputs, returned = signature.split("->", 1)
            if not dangerous_return_type(returned):
                continue
            for capability in sorted(INERT_CAPABILITIES):
                if re.search(rf"\b{re.escape(capability)}\b", inputs):
                    findings.append(
                        {
                            "kind": "public-authority-upgrade-function",
                            "path": relative,
                            "line": line_number(text, match.start()),
                            "function": match.group("name"),
                            "capability": capability,
                            "return": normalize_header(returned),
                        }
                    )

        for capability in sorted(INERT_CAPABILITIES):
            impl_re = re.compile(
                rf"(?m)^\s*impl\s+(?:[A-Za-z_][A-Za-z0-9_]*::)*"
                rf"{re.escape(capability)}\s*\{{"
            )
            for impl_match in impl_re.finditer(text):
                opening = text.find("{", impl_match.start())
                try:
                    closing = matching_brace(text, opening)
                except ValueError:
                    findings.append(
                        {
                            "kind": "unparseable-inert-capability-impl",
                            "path": relative,
                            "line": line_number(text, impl_match.start()),
                            "capability": capability,
                        }
                    )
                    continue
                block = text[opening + 1 : closing]
                for method in PUBLIC_FN_RE.finditer(block):
                    signature = method.group("signature")
                    if "->" not in signature:
                        continue
                    returned = signature.split("->", 1)[1]
                    if dangerous_return_type(returned):
                        findings.append(
                            {
                                "kind": "inert-capability-authority-method",
                                "path": relative,
                                "line": line_number(
                                    text, opening + 1 + method.start()
                                ),
                                "function": method.group("name"),
                                "capability": capability,
                                "return": normalize_header(returned),
                            }
                        )

    return sorted(
        findings,
        key=lambda row: (
            row["path"],
            row["line"],
            row["kind"],
            row.get("capability", ""),
        ),
    )


def scan_migration_trait_implementations(
    rust_sources: list[tuple[Path, str]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    inventory: list[dict[str, Any]] = []
    violations: list[dict[str, Any]] = []

    for path, text in rust_sources:
        relative = path.as_posix()
        for authority_trait in MIGRATION_AUTHORITY_TRAITS:
            pattern = re.compile(
                rf"(?ms)^\s*(?P<header>impl(?:\s*<[^\{{\}};]{{0,800}}>)?\s+"
                rf"{re.escape(authority_trait)}\s+for\s+[^\{{\n]{{1,800}})\{{"
            )
            for match in pattern.finditer(text):
                header = normalize_header(match.group("header"))
                test_only = is_test_only_location(path, text, match.start())
                approved = test_only or any(
                    snippet in header
                    for snippet in APPROVED_PRODUCTION_IMPL_SNIPPETS[authority_trait]
                )
                record = {
                    "path": relative,
                    "line": line_number(text, match.start()),
                    "authority_trait": authority_trait,
                    "header": header,
                    "test_only": test_only,
                    "approved": approved,
                }
                inventory.append(record)
                if not approved:
                    violations.append(record)

    for authority_trait, snippets in APPROVED_PRODUCTION_IMPL_SNIPPETS.items():
        for snippet in snippets:
            matches = [
                row
                for row in inventory
                if row["authority_trait"] == authority_trait
                and not row["test_only"]
                and snippet in row["header"]
            ]
            if len(matches) != 1:
                violations.append(
                    {
                        "kind": "approved-production-impl-cardinality",
                        "authority_trait": authority_trait,
                        "expected_header": snippet,
                        "actual": len(matches),
                    }
                )

    return (
        sorted(
            inventory,
            key=lambda row: (
                row["authority_trait"],
                row["path"],
                row["line"],
            ),
        ),
        sorted(
            violations,
            key=lambda row: (
                row.get("authority_trait", ""),
                row.get("path", ""),
                row.get("line", 0),
            ),
        ),
    )


def main() -> int:
    for required in (ROOT, POLICY_PATH, COMPILE_FAIL_PATH, REHEARSAL_PATH):
        if not required.exists():
            raise SystemExit(f"missing A22 audit input: {required}")

    rust_paths = sorted(ROOT.rglob("*.rs"))
    rust_sources = [(path, path.read_text(encoding="utf-8")) for path in rust_paths]
    traits: list[dict[str, Any]] = []
    trait_index: dict[str, list[dict[str, Any]]] = {}
    mints: list[dict[str, Any]] = []

    for path, text in rust_sources:
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
    raw_findings: list[dict[str, Any]] = []
    for mint in mints:
        for bound in mint["generic_bounds"]:
            definitions = trait_index.get(bound, [])
            if not definitions or not authority_like(bound):
                continue
            sealed = any(row["sealed_supertrait_visible"] for row in definitions)
            raw_findings.append(
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
    raw_findings.sort(
        key=lambda row: (
            row["mint_path"]["path"],
            row["mint_path"]["line"],
            row["authority_trait"],
        )
    )

    policy_text = POLICY_PATH.read_text(encoding="utf-8")
    policy = json.loads(policy_text)
    if policy.get("schema") != "trnm-capability-authority-policy-v1":
        raise SystemExit("invalid A22 authority policy schema")
    entries = policy.get("reviewed_findings")
    if not isinstance(entries, list):
        raise SystemExit("A22 authority policy reviewed_findings must be a list")

    policy_index: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise SystemExit("A22 authority policy entry must be an object")
        key = policy_key(entry)
        if key in policy_index:
            raise SystemExit(f"duplicate A22 authority policy key: {key}")
        if entry.get("disposition") not in {"reviewed-inert", "reviewed-sealed"}:
            raise SystemExit(f"invalid A22 authority disposition: {entry}")
        if not entry.get("proof_id") or not entry.get("rationale"):
            raise SystemExit(f"incomplete A22 authority policy entry: {entry}")
        policy_index[key] = entry

    compile_fail_text = COMPILE_FAIL_PATH.read_text(encoding="utf-8")
    missing_compile_fail_proofs = [
        proof for proof in REQUIRED_COMPILE_FAIL_PROOFS if proof not in compile_fail_text
    ]

    reviewed_findings: list[dict[str, Any]] = []
    unresolved_mints: list[dict[str, Any]] = []
    matched_policy: set[tuple[str, str, str, str]] = set()
    for raw in raw_findings:
        key = finding_key(raw)
        entry = policy_index.get(key)
        if entry is None:
            unresolved_mints.append(
                {
                    "kind": "unreviewed-authority-mint",
                    **key_record(key),
                    "line": raw["mint_path"]["line"],
                }
            )
            continue
        matched_policy.add(key)
        issues: list[str] = []
        disposition = entry["disposition"]
        if disposition == "reviewed-sealed" and not raw["sealed_supertrait_visible"]:
            issues.append("policy requires a visible sealed supertrait")
        if disposition == "reviewed-inert" and key[2] not in INERT_CAPABILITIES:
            issues.append("reviewed-inert capability is not in the frozen inert set")
        if entry["proof_id"] not in compile_fail_text:
            issues.append("compile-fail proof id is absent")
        if issues:
            unresolved_mints.append(
                {
                    "kind": "authority-policy-mismatch",
                    **key_record(key),
                    "issues": issues,
                }
            )
            continue
        reviewed_findings.append(
            {
                **raw,
                "disposition": disposition,
                "proof_id": entry["proof_id"],
                "rationale": entry["rationale"],
            }
        )

    stale_policy_entries = [
        {"kind": "stale-authority-policy-entry", **key_record(key)}
        for key in sorted(set(policy_index) - matched_policy)
    ]

    authority_sink_findings = scan_public_authority_sinks(rust_sources)
    production_impl_inventory, production_impl_findings = (
        scan_migration_trait_implementations(rust_sources)
    )

    rehearsal_text = REHEARSAL_PATH.read_text(encoding="utf-8")
    rehearsal_body = named_function_body(rehearsal_text, "run_migration_rehearsal_v1")
    strict_boundary_checks = {
        "run_migration_rehearsal_v1_present": bool(rehearsal_body),
        "strict_validator_set_admission": (
            "validate_validator_set_strict_ed25519_v0(trusted_target_set)"
            in rehearsal_body
        ),
        "strict_ed25519_verifier_fixed": (
            "&trnm_consensus_crypto::StrictEd25519Verifier" in rehearsal_body
        ),
        "production_activation_false": (
            "pub const MIGRATION_REHEARSAL_PRODUCTION_ACTIVATION_V1: bool = false;"
            in rehearsal_text
        ),
        "target_writer_activation_false": (
            "pub const MIGRATION_TARGET_JMT_WRITER_PRODUCTION_ACTIVATION_V1: bool = false;"
            in rehearsal_text
        ),
        "source_verifier_owned_by_rehearsal": (
            "impl CometStateExportVerifierV1 for MigrationSourceVerifierV1<'_>"
            in rehearsal_text
        ),
        "typed_projection_verifier_owned_by_rehearsal": (
            "impl PocoTargetProjectionManifestVerifierV1 for MigrationTargetReplayVerifierV1<'_>"
            in rehearsal_text
        ),
    }
    strict_boundary_failures = [
        {"kind": "strict-rehearsal-boundary-missing", "check": name}
        for name, passed in strict_boundary_checks.items()
        if not passed
    ]

    unresolved_total = (
        len(unresolved_mints)
        + len(stale_policy_entries)
        + len(missing_compile_fail_proofs)
        + len(authority_sink_findings)
        + len(production_impl_findings)
        + len(strict_boundary_failures)
    )

    report: dict[str, Any] = {
        "schema": "trnm-capability-authority-audit-v2",
        "root": ROOT.as_posix(),
        "rust_files": len(rust_paths),
        "public_traits": len(traits),
        "public_authority_traits": public_authority_traits,
        "public_verified_capability_mints": sorted(
            mints, key=lambda row: (row["path"], row["line"], row["function"])
        ),
        "generic_authority_mint_findings": raw_findings,
        "reviewed_authority_mint_findings": reviewed_findings,
        "unresolved_authority_mint_findings": unresolved_mints,
        "stale_policy_entries": stale_policy_entries,
        "missing_compile_fail_proofs": missing_compile_fail_proofs,
        "authority_sink_findings": authority_sink_findings,
        "production_migration_authority_impls": production_impl_inventory,
        "production_migration_authority_impl_findings": production_impl_findings,
        "strict_rehearsal_boundary": strict_boundary_checks,
        "strict_rehearsal_boundary_failures": strict_boundary_failures,
        "policy_sha256": hashlib.sha256(policy_text.encode("utf-8")).hexdigest(),
        "unresolved_total": unresolved_total,
    }
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":"))
    report["sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    rendered = json.dumps(report, sort_keys=True, indent=2)
    Path("/tmp/trnm-capability-authority-audit-v2.json").write_text(
        rendered + "\n", encoding="utf-8"
    )
    print(rendered)
    print(
        "authority_audit_summary "
        f"files={report['rust_files']} traits={report['public_traits']} "
        f"authority_traits={len(public_authority_traits)} "
        f"verified_mints={len(mints)} raw_findings={len(raw_findings)} "
        f"reviewed={len(reviewed_findings)} unresolved={unresolved_total} "
        f"sha256={report['sha256']}"
    )
    return 1 if unresolved_total else 0


if __name__ == "__main__":
    raise SystemExit(main())
