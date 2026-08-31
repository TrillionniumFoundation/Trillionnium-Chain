#!/usr/bin/env python3
"""Cross-check the generated PoCO-BFT decoder registry against an independent manifest.

``check_poco_bft_v0_registry.py`` deliberately derives its artifact from the
Rust enum and schema partitions.  That is useful for source consistency, but
it cannot detect a mistake shared by those inputs.  This gate is a small,
standard-library-only second source: the manifest is curated separately and
contains no generated source hashes or Rust parsing logic.  A mismatch is
always an error and the gate never rewrites either input.

The gate is intentionally bounded.  It checks the stable decoder taxonomy,
scope partition, error class, entry-point inventory, and frozen resource
bounds.  It is evidence for registry drift only; it is not a second complete
CEV0 implementation, a cryptographic verifier, or an independent protocol
review.
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, NoReturn


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REGISTRY = (
    ROOT / "docs/protocol/poco-bft-v0/schema/decoder-error-registry-v0.json"
)
DEFAULT_REFERENCE = (
    ROOT
    / "docs/protocol/poco-bft-v0/schema/decoder-error-registry-reference-v0.json"
)

REFERENCE_SCHEMA = "trnm_poco_bft_decoder_error_reference_v0"
REGISTRY_SCHEMA = "trnm_poco_bft_decoder_error_registry_v0"
SCHEMA_VERSION = 0
SCOPES = ("B2-A", "B2-B", "B2-C", "B2-D", "B2-E", "node-local")
CLASSES = ("authorization", "canonical", "safety", "semantic", "structural")
CODE_RE = re.compile(r"[a-z0-9]+(?:_[a-z0-9]+)*\Z")
VARIANT_RE = re.compile(r"[A-Z][A-Za-z0-9]*\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


class RegistryReferenceError(ValueError):
    """A malformed manifest or generated-registry mismatch."""


def fail(message: str) -> NoReturn:
    raise RegistryReferenceError(message)


def display(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read {display(path)}: {error}")
    if not isinstance(value, dict):
        fail(f"{display(path)} must contain a JSON object")
    return value


def exact_int(value: Any, label: str) -> int:
    if type(value) is not int:  # bool is an int subclass; reject it here.
        fail(f"{label} must be an integer")
    return value


def exact_string(value: Any, label: str) -> str:
    if not isinstance(value, str):
        fail(f"{label} must be a string")
    return value


def code_projection(value: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        fail(f"{label}.codes must be a non-empty array")
    projection: list[dict[str, Any]] = []
    seen_codes: set[str] = set()
    seen_variants: set[str] = set()
    for index, item in enumerate(value):
        item_label = f"{label}.codes[{index}]"
        if not isinstance(item, dict):
            fail(f"{item_label} must be an object")
        required = ("ordinal", "rust_variant", "code", "scope", "class")
        if any(key not in item for key in required):
            fail(f"{item_label} is missing a required field")
        ordinal = exact_int(item["ordinal"], f"{item_label}.ordinal")
        if ordinal != index:
            fail(f"{item_label}.ordinal must be {index}, found {ordinal}")
        variant = exact_string(item["rust_variant"], f"{item_label}.rust_variant")
        if VARIANT_RE.fullmatch(variant) is None:
            fail(f"{item_label}.rust_variant is not a canonical Rust variant")
        code = exact_string(item["code"], f"{item_label}.code")
        if CODE_RE.fullmatch(code) is None:
            fail(f"{item_label}.code is not a canonical snake_case code")
        if code in seen_codes:
            fail(f"{item_label}.code is duplicated: {code}")
        if variant in seen_variants:
            fail(f"{item_label}.rust_variant is duplicated: {variant}")
        seen_codes.add(code)
        seen_variants.add(variant)
        scope = exact_string(item["scope"], f"{item_label}.scope")
        if scope not in SCOPES:
            fail(f"{item_label}.scope is unknown: {scope!r}")
        klass = exact_string(item["class"], f"{item_label}.class")
        if klass not in CLASSES:
            fail(f"{item_label}.class is unknown: {klass!r}")
        projection.append(
            {
                "ordinal": ordinal,
                "rust_variant": variant,
                "code": code,
                "scope": scope,
                "class": klass,
            }
        )
    return projection


def scope_projection(document: dict[str, Any], label: str, codes: list[dict[str, Any]]) -> dict[str, list[str]]:
    raw_order = document.get("scope_order")
    if raw_order != list(SCOPES):
        fail(f"{label}.scope_order must be {list(SCOPES)!r}")
    raw_scopes = document.get("scopes")
    if not isinstance(raw_scopes, list) or len(raw_scopes) != len(SCOPES):
        fail(f"{label}.scopes must contain one entry per scope")
    expected_codes = {
        scope: [item["code"] for item in codes if item["scope"] == scope]
        for scope in SCOPES
    }
    result: dict[str, list[str]] = {}
    for index, scope in enumerate(SCOPES):
        item_label = f"{label}.scopes[{index}]"
        item = raw_scopes[index]
        if not isinstance(item, dict):
            fail(f"{item_label} must be an object")
        if item.get("scope") != scope:
            fail(f"{item_label}.scope must be {scope!r}")
        description = item.get("description")
        if not isinstance(description, str) or not description.strip():
            fail(f"{item_label}.description must be non-empty")
        raw_codes = item.get("codes")
        if raw_codes != expected_codes[scope]:
            fail(
                f"{item_label}.codes differs from the ordered code projection: "
                f"expected {expected_codes[scope]!r}, found {raw_codes!r}"
            )
        result[scope] = list(raw_codes)
    return result


def entry_point_projection(document: dict[str, Any], label: str) -> dict[str, list[str]]:
    raw = document.get("entry_points")
    if not isinstance(raw, dict) or list(raw) != list(SCOPES):
        fail(f"{label}.entry_points must contain exactly the six ordered scopes")
    result: dict[str, list[str]] = {}
    for scope in SCOPES:
        values = raw.get(scope)
        if not isinstance(values, list) or not values:
            fail(f"{label}.entry_points[{scope!r}] must be a non-empty array")
        if any(not isinstance(value, str) or not value for value in values):
            fail(f"{label}.entry_points[{scope!r}] contains a non-string name")
        if len(set(values)) != len(values):
            fail(f"{label}.entry_points[{scope!r}] contains duplicates")
        result[scope] = list(values)
    return result


def bounds_projection(document: dict[str, Any], label: str) -> dict[str, int]:
    expected_names = (
        "max_certificate_items",
        "max_tc_aggregate_signature_shares",
        "max_root_bytes",
        "max_intrinsic_signature_work_units",
    )
    raw = document.get("bounds")
    if not isinstance(raw, dict) or list(raw) != list(expected_names):
        fail(f"{label}.bounds must contain the four ordered frozen bounds")
    result: dict[str, int] = {}
    for name in expected_names:
        value = exact_int(raw.get(name), f"{label}.bounds.{name}")
        if value < 0:
            fail(f"{label}.bounds.{name} cannot be negative")
        result[name] = value
    return result


def validate_reference(document: dict[str, Any]) -> dict[str, Any]:
    if document.get("schema") != REFERENCE_SCHEMA:
        fail(f"reference schema must be {REFERENCE_SCHEMA!r}")
    if document.get("schema_version") != SCHEMA_VERSION:
        fail("reference schema_version must be 0")
    if document.get("status") != "independently-curated":
        fail("reference status must remain independently-curated")
    if not isinstance(document.get("scope_basis"), str) or not document["scope_basis"].strip():
        fail("reference scope_basis must explain the independent curation basis")
    codes = code_projection(document.get("codes"), "reference")
    scopes = scope_projection(document, "reference", codes)
    entry_points = entry_point_projection(document, "reference")
    bounds = bounds_projection(document, "reference")
    return {
        "codes": codes,
        "scopes": scopes,
        "entry_points": entry_points,
        "bounds": bounds,
    }


def validate_registry(document: dict[str, Any]) -> dict[str, Any]:
    if document.get("schema") != REGISTRY_SCHEMA:
        fail(f"generated registry schema must be {REGISTRY_SCHEMA!r}")
    if document.get("schema_version") != SCHEMA_VERSION:
        fail("generated registry schema_version must be 0")
    if document.get("status") != "generated-and-gated":
        fail("generated registry status must remain generated-and-gated")
    codes = code_projection(document.get("codes"), "generated registry")
    scopes = scope_projection(document, "generated registry", codes)
    entry_points = entry_point_projection(document, "generated registry")
    bounds = bounds_projection(document, "generated registry")

    source_paths = document.get("source_paths")
    source_hashes = document.get("source_sha256")
    if not isinstance(source_paths, dict) or not source_paths:
        fail("generated registry source_paths must be a non-empty object")
    if not isinstance(source_hashes, dict) or set(source_hashes) != set(source_paths):
        fail("generated registry source_sha256 keys must match source_paths")
    for key, path in source_paths.items():
        if not isinstance(path, str) or not path or path.startswith("/") or ".." in Path(path).parts:
            fail(f"generated registry source_paths[{key!r}] is unsafe")
        digest = source_hashes[key]
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            fail(f"generated registry source_sha256[{key!r}] is not a SHA-256 digest")
    return {
        "codes": codes,
        "scopes": scopes,
        "entry_points": entry_points,
        "bounds": bounds,
    }


def compare_documents(registry: dict[str, Any], reference: dict[str, Any]) -> int:
    expected = validate_reference(reference)
    actual = validate_registry(registry)
    for key in ("codes", "scopes", "entry_points", "bounds"):
        if actual[key] != expected[key]:
            fail(f"generated registry {key} differs from the independent reference")
    return len(expected["codes"])


def compare_paths(registry_path: Path, reference_path: Path) -> int:
    return compare_documents(read_json(registry_path), read_json(reference_path))


def run_self_test(registry_path: Path, reference_path: Path) -> None:
    registry = read_json(registry_path)
    reference = read_json(reference_path)
    baseline = compare_documents(registry, reference)

    mutations: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    changed_registry = copy.deepcopy(registry)
    changed_registry["codes"][0]["code"] = "registry_drift"
    mutations.append(("generated-code", changed_registry, copy.deepcopy(reference)))

    changed_reference = copy.deepcopy(reference)
    changed_reference["codes"][-1]["class"] = "semantic"
    mutations.append(("reference-class", copy.deepcopy(registry), changed_reference))

    changed_scopes = copy.deepcopy(registry)
    changed_scopes["scope_order"] = list(reversed(changed_scopes["scope_order"]))
    mutations.append(("scope-order", changed_scopes, copy.deepcopy(reference)))

    with tempfile.TemporaryDirectory(prefix="trnm-poco-registry-reference-") as temp:
        temp_root = Path(temp)
        for name, mutated_registry, mutated_reference in mutations:
            mutated_registry_path = temp_root / f"{name}-registry.json"
            mutated_reference_path = temp_root / f"{name}-reference.json"
            mutated_registry_path.write_text(
                json.dumps(mutated_registry, indent=2) + "\n", encoding="utf-8"
            )
            mutated_reference_path.write_text(
                json.dumps(mutated_reference, indent=2) + "\n", encoding="utf-8"
            )
            try:
                compare_paths(mutated_registry_path, mutated_reference_path)
            except RegistryReferenceError:
                continue
            fail(f"self-test mutation {name!r} was not rejected")
    print(f"independent registry reference self-test: {len(mutations)} drift mutations rejected")
    if baseline <= 0:
        fail("self-test baseline unexpectedly contains no codes")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--reference", type=Path, default=DEFAULT_REFERENCE)
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run the positive comparison and deterministic drift mutations",
    )
    args = parser.parse_args()
    count = compare_paths(args.registry, args.reference)
    if args.self_test:
        run_self_test(args.registry, args.reference)
    print(
        "PoCO-BFT independent decoder registry reference verified: "
        f"{count} codes across {len(SCOPES)} scopes; "
        "taxonomy, classes, entry points, and bounds match"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RegistryReferenceError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
