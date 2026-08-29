#!/usr/bin/env python3
"""Independent strict parser/checker for the candidate registry surface.

This module intentionally does not import repository protocol checkers or TRNM
implementation code. It uses only Python's standard library.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

REGISTRY_FILES = (
    "operation-registry-v1.json",
    "object-registry-v1.json",
    "domain-registry-v1.json",
    "error-registry-v1.json",
    "limit-registry-v1.json",
    "verification-profile-registry-v1.json",
)

class DuplicateKey(ValueError):
    pass


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise DuplicateKey(key)
        out[key] = value
    return out


def strict_loads(raw: str) -> Any:
    return json.loads(raw, object_pairs_hook=reject_duplicates, parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def unique(rows: list[dict[str, Any]], key: str) -> None:
    values = [row[key] for row in rows]
    if len(values) != len(set(values)):
        raise ValueError(f"duplicate:{key}")


def validate(documents: dict[str, dict[str, Any]]) -> None:
    for name, doc in documents.items():
        if doc.get("status") != "candidate-non-normative":
            raise ValueError(f"status:{name}")

    operations = documents["operation-registry-v1.json"]
    rows = operations["operations"]
    if operations.get("slot_count") != 30:
        raise ValueError("operation-slot-count")
    if sorted(row["kind"] for row in rows) != list(range(30)):
        raise ValueError("operation-slot-coverage")
    unique(rows, "kind")
    unique(rows, "name")
    if any(row.get("enabled") is not False for row in rows):
        raise ValueError("operation-enabled")
    if rows[-1].get("status") != "disabled" or rows[-1].get("canonical_error") != "ERR_OPERATION_DISABLED":
        raise ValueError("operation-disabled-sentinel")

    unique(documents["object-registry-v1.json"]["objects"], "id")
    domains = documents["domain-registry-v1.json"]["domains"]
    unique(domains, "id")
    unique(domains, "value")
    for domain in domains:
        value = domain["value"]
        if not isinstance(value, str) or not value.isascii() or not value.startswith("trnm.poco-ai.") or not value.endswith(".v1"):
            raise ValueError("domain-shape")

    errors = documents["error-registry-v1.json"]["errors"]
    unique(errors, "code")
    required = {"ERR_OPERATION_DISABLED", "ERR_PROFILE_DISABLED", "ERR_ASSET_CONSERVATION", "ERR_CHECKPOINT_ROLLBACK"}
    if not required.issubset({row["code"] for row in errors}):
        raise ValueError("required-error")

    limits = documents["limit-registry-v1.json"]["limits"]
    if not limits or any(int(value) <= 0 for value in limits.values()):
        raise ValueError("limit-positive")

    profiles = documents["verification-profile-registry-v1.json"]
    if profiles.get("fallback_allowed") is not False:
        raise ValueError("profile-fallback")
    unique(profiles["profiles"], "id")
    if any(row.get("globally_enabled") is not False for row in profiles["profiles"]):
        raise ValueError("profile-enabled")
    subjective = next(row for row in profiles["profiles"] if row["id"] == "subjective-v1")
    if subjective.get("objective_settlement_forbidden") is not True or subjective.get("poco_weight_forbidden") is not True:
        raise ValueError("subjective-authority")


def mutate(raw_docs: dict[str, str], case: str) -> dict[str, str]:
    docs = dict(raw_docs)
    if case == "duplicate-json-key":
        docs["operation-registry-v1.json"] = docs["operation-registry-v1.json"].replace('"schema":', '"schema":"duplicate", "schema":', 1)
        return docs
    values = {name: strict_loads(raw) for name, raw in docs.items()}
    if case == "missing-operation-slot":
        values["operation-registry-v1.json"]["operations"].pop()
    elif case == "enabled-operation":
        values["operation-registry-v1.json"]["operations"][0]["enabled"] = True
    elif case == "enabled-profile":
        values["verification-profile-registry-v1.json"]["profiles"][0]["globally_enabled"] = True
    elif case == "fallback-enabled":
        values["verification-profile-registry-v1.json"]["fallback_allowed"] = True
    elif case == "duplicate-domain":
        values["domain-registry-v1.json"]["domains"].append(dict(values["domain-registry-v1.json"]["domains"][0]))
    elif case == "bad-domain":
        values["domain-registry-v1.json"]["domains"][0]["value"] = "TRNM INVALID"
    elif case == "zero-limit":
        key = next(iter(values["limit-registry-v1.json"]["limits"]))
        values["limit-registry-v1.json"]["limits"][key] = 0
    else:
        raise ValueError(case)
    return {name: canonical_bytes(value).decode("utf-8") for name, value in values.items()}


def parse_all(raw_docs: dict[str, str]) -> dict[str, dict[str, Any]]:
    return {name: strict_loads(raw) for name, raw in raw_docs.items()}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry-dir", type=Path, required=True)
    parser.add_argument("--evidence-out", type=Path)
    args = parser.parse_args()
    raw_docs = {name: (args.registry_dir / name).read_text(encoding="utf-8") for name in REGISTRY_FILES}
    documents = parse_all(raw_docs)
    validate(documents)

    cases = [
        "duplicate-json-key", "missing-operation-slot", "enabled-operation",
        "enabled-profile", "fallback-enabled", "duplicate-domain",
        "bad-domain", "zero-limit",
    ]
    results: list[dict[str, str]] = []
    for case in cases:
        try:
            mutated = mutate(raw_docs, case)
            validate(parse_all(mutated))
        except (ValueError, KeyError, TypeError, DuplicateKey, json.JSONDecodeError) as exc:
            results.append({"case": case, "result": "rejected", "error": str(exc)})
        else:
            raise SystemExit(f"mutant unexpectedly accepted: {case}")

    digests = {name: hashlib.sha256(canonical_bytes(documents[name])).hexdigest() for name in REGISTRY_FILES}
    evidence = {
        "schema": "trnm-independent-cev1-registry-evidence-v1",
        "classification": "candidate-non-normative",
        "implementation": "python-standard-library-independent",
        "registry_digests": digests,
        "negative_cases": results,
        "global_cev1_conformance_complete": False,
        "normative_freeze": False,
    }
    if args.evidence_out:
        args.evidence_out.parent.mkdir(parents=True, exist_ok=True)
        args.evidence_out.write_bytes(canonical_bytes(evidence) + b"\n")
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
