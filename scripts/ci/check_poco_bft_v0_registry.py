#!/usr/bin/env python3
"""Check the generated PoCO-BFT v0 decoder/error registry.

The protocol has several deliberately scoped schema gates (B2-A through B2-E
and a node-local signing surface).  Historically each gate carried a copy of
the Rust ``DecodeErrorCode`` order.  That made a newly added decoder error easy
to register in one gate while silently omitting it from another.  This checker
builds one canonical registry from the Rust enum/as_str surface and the schema
partition metadata, then compares it byte-for-byte with the committed JSON
artifact.

No third-party packages are used.  A mismatch is always an error; the checker
never updates the registry in-place.  Run with ``--emit`` to print the exact
canonical JSON when intentionally regenerating the artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, NoReturn


ROOT = Path(__file__).resolve().parents[2]
RUST_SOURCE = ROOT / "trillionnium/crates/trnm-consensus-types/src/cev0_decode.rs"
SCHEMA_ROOT = ROOT / "docs/protocol/poco-bft-v0/schema"
BASE_SCHEMA = SCHEMA_ROOT / "cev0-logical-schema-v0.json"
ANCHOR_SCHEMA = SCHEMA_ROOT / "cev0-logical-schema-anchor-handoff-v0.json"
EPOCH_SCHEMA = SCHEMA_ROOT / "cev0-logical-schema-epoch-commitment-v0.json"
BODY_SCHEMA = SCHEMA_ROOT / "cev0-logical-schema-block-body-v0.json"
CHECKPOINT_SCHEMA = SCHEMA_ROOT / "cev0-logical-schema-checkpoint-finality-v0.json"
REGISTRY = SCHEMA_ROOT / "decoder-error-registry-v0.json"

REGISTRY_SCHEMA = "trnm_poco_bft_decoder_error_registry_v0"
RUST_RELATIVE = "trillionnium/crates/trnm-consensus-types/src/cev0_decode.rs"

SCOPE_NAMES = ("B2-A", "B2-B", "B2-C", "B2-D", "B2-E", "node-local")
SCOPE_TEXT = {
    "B2-A": "ordinary certificate-kernel exact decoder",
    "B2-B": "block, handoff, and epoch-anchor exact decoder",
    "B2-C": "NextEpochCommitmentV0 exact decoder",
    "B2-D": "ordinary block-body exact decoder",
    "B2-E": "checkpoint/finality exact decoder",
    "node-local": "node-local signer-intent exact decoder",
}
EXPECTED_SCOPE_BY_TEXT = {
    "B2-B block/handoff endpoint only": "B2-B",
    "B2-C NextEpochCommitmentV0 endpoint only": "B2-C",
    "B2-D ordinary block body endpoint only": "B2-D",
    "B2-E checkpoint finality endpoint only": "B2-E",
    "node-local signer-intent endpoint only": "node-local",
}


class RegistryError(ValueError):
    """A fail-closed registry or source mismatch."""


def fail(message: str) -> "NoReturn":
    raise RegistryError(message)


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read {path.relative_to(ROOT)}: {error}")
    if not isinstance(value, dict):
        fail(f"{path.relative_to(ROOT)} must contain a JSON object")
    return value


def sha256(path: Path) -> str:
    try:
        data = path.read_bytes()
    except OSError as error:
        fail(f"cannot read {path.relative_to(ROOT)} for hashing: {error}")
    return hashlib.sha256(data).hexdigest()


def code_from_variant(variant: str) -> str:
    # The Rust surface deliberately uses stable snake_case strings.  Keep this
    # conversion only as a cross-check; as_str() remains the source of truth.
    words = re.sub(r"(?<!^)(?=[A-Z])", "_", variant).lower()
    aliases = {
        "zero_consensus_public_key": "zero_public_key",
        "non_canonical_validator_order": "noncanonical_validator_order",
        "non_canonical_signer_order": "noncanonical_signer_order",
        "non_canonical_reference_order": "noncanonical_reference_order",
        "non_canonical_event_attribute_order": "noncanonical_event_attribute_order",
    }
    return aliases.get(words, words)


def rust_codes(source: str) -> list[dict[str, str]]:
    enum_match = re.search(
        r"pub enum DecodeErrorCode\s*\{(?P<body>.*?)^\}", source, re.MULTILINE | re.DOTALL
    )
    if enum_match is None:
        fail("Rust DecodeErrorCode enum is missing")
    variants: list[str] = []
    for line in enum_match.group("body").splitlines():
        # No data-carrying variants are allowed in this stable taxonomy.
        match = re.match(r"^\s*([A-Z][A-Za-z0-9_]*)\s*,\s*$", line)
        if match:
            variants.append(match.group(1))
    if not variants:
        fail("Rust DecodeErrorCode enum has no variants")
    if len(set(variants)) != len(variants):
        fail("Rust DecodeErrorCode enum contains duplicate variants")

    as_str_match = re.search(
        r"pub const fn as_str\(self\) -> &'static str\s*\{(?P<body>.*?)^\s*\}\n\s*\}",
        source,
        re.MULTILINE | re.DOTALL,
    )
    if as_str_match is None:
        fail("Rust DecodeErrorCode::as_str implementation is missing")
    pairs = re.findall(
        r"Self::([A-Z][A-Za-z0-9_]*)\s*=>\s*\"([a-z0-9_]+)\"\s*,?",
        as_str_match.group("body"),
    )
    if len(pairs) != len(variants):
        fail(
            "Rust DecodeErrorCode::as_str count differs from enum: "
            f"{len(pairs)} != {len(variants)}"
        )
    if set(variant for variant, _ in pairs) != set(variants):
        fail("Rust DecodeErrorCode::as_str variants differ from enum variants")
    codes = [code for _, code in pairs]
    if len(set(codes)) != len(codes):
        fail("Rust DecodeErrorCode::as_str contains duplicate strings")
    all_match = re.search(
        r"pub const ALL:\s*&'static \[Self\]\s*=\s*&\[(?P<body>.*?)^\s*\];",
        source,
        re.MULTILINE | re.DOTALL,
    )
    if all_match is None:
        fail("Rust DecodeErrorCode::ALL registry is missing")
    all_variants = re.findall(
        r"Self::([A-Z][A-Za-z0-9_]*)\s*,", all_match.group("body")
    )
    if all_variants != [variant for variant, _ in pairs]:
        fail("Rust DecodeErrorCode::ALL order differs from as_str order")
    for variant, code in pairs:
        if code_from_variant(variant) != code:
            # Keep aliases explicit above.  An accidental spelling change must
            # stop generation instead of creating a registry that looks valid.
            fail(f"Rust variant {variant} maps unexpectedly to {code}")
    return [
        {"ordinal": str(index), "rust_variant": variant, "code": code}
        for index, (variant, code) in enumerate(pairs)
    ]


def list_codes(value: Any, field: str, path: Path) -> list[str]:
    if not isinstance(value, list):
        fail(f"{path.relative_to(ROOT)}.{field} must be an array")
    result: list[str] = []
    for index, item in enumerate(value):
        if isinstance(item, str):
            code = item
        elif isinstance(item, dict) and isinstance(item.get("code"), str):
            code = item["code"]
        else:
            fail(f"{path.relative_to(ROOT)}.{field}[{index}] has no string code")
        result.append(code)
    if len(set(result)) != len(result):
        fail(f"{path.relative_to(ROOT)}.{field} contains duplicate codes")
    return result


def scoped_exclusions(base: dict[str, Any]) -> dict[str, list[str]]:
    raw = base.get("rust_decoder_error_exclusions")
    if not isinstance(raw, list):
        fail("base schema has no rust_decoder_error_exclusions array")
    result = {scope: [] for scope in SCOPE_NAMES if scope != "B2-A"}
    for index, item in enumerate(raw):
        if not isinstance(item, dict) or not isinstance(item.get("code"), str):
            fail(f"base schema rust_decoder_error_exclusions[{index}] is malformed")
        code = item["code"]
        text = item.get("scope")
        if text not in EXPECTED_SCOPE_BY_TEXT:
            fail(f"unknown decoder exclusion scope for {code}: {text!r}")
        scope = EXPECTED_SCOPE_BY_TEXT[text]
        if code in sum(result.values(), []):
            fail(f"decoder exclusion {code} is registered more than once")
        result[scope].append(code)
    return result


def schema_partitions(
    base: dict[str, Any],
    anchor: dict[str, Any],
    epoch: dict[str, Any],
    body: dict[str, Any],
    checkpoint: dict[str, Any],
    rust_order: list[str],
) -> dict[str, list[str]]:
    base_codes = list_codes(base.get("decoder_error_codes"), "decoder_error_codes", BASE_SCHEMA)
    exclusions = scoped_exclusions(base)
    expected = {
        "B2-A": base_codes,
        "B2-B": exclusions["B2-B"],
        "B2-C": exclusions["B2-C"],
        "B2-D": exclusions["B2-D"],
        "B2-E": exclusions["B2-E"],
        "node-local": exclusions["node-local"],
    }

    scope_by_code = {
        code: scope for scope, codes in expected.items() for code in codes
    }
    anchor_codes = list_codes(anchor.get("decoder_error_codes"), "decoder_error_codes", ANCHOR_SCHEMA)
    expected_anchor = [code for code in rust_order if scope_by_code[code] in ("B2-A", "B2-B")]
    if anchor_codes != expected_anchor:
        fail("B2-B anchor schema decoder list does not follow the Rust taxonomy order")
    epoch_codes = list_codes(epoch.get("decoder_error_codes"), "decoder_error_codes", EPOCH_SCHEMA)
    expected_epoch = [
        code for code in rust_order if scope_by_code[code] in ("B2-A", "B2-B", "B2-C")
    ]
    if epoch_codes != expected_epoch:
        fail("B2-C epoch schema decoder list does not follow the Rust taxonomy order")

    body_additions = list_codes(
        body.get("rust_decoder_error_additions"),
        "rust_decoder_error_additions",
        BODY_SCHEMA,
    )
    if body_additions != expected["B2-D"]:
        fail("B2-D block-body decoder additions differ from base scope metadata")

    taxonomy = checkpoint.get("decoder_error_taxonomy")
    if not isinstance(taxonomy, dict):
        fail("B2-E checkpoint schema has no decoder_error_taxonomy object")
    reused = list_codes(taxonomy.get("reused_codes"), "decoder_error_taxonomy.reused_codes", CHECKPOINT_SCHEMA)
    additions = list_codes(taxonomy.get("new_codes"), "decoder_error_taxonomy.new_codes", CHECKPOINT_SCHEMA)
    expected_reused = [
        code
        for code in rust_order
        if scope_by_code[code] in ("B2-A", "B2-B", "B2-C", "B2-D")
    ]
    if reused != expected_reused:
        fail("B2-E reused decoder taxonomy does not follow the Rust taxonomy order")
    if additions != [code for code in rust_order if scope_by_code[code] == "B2-E"]:
        fail("B2-E new decoder taxonomy differs from base scope metadata")

    all_scoped = sum(expected.values(), [])
    if len(all_scoped) != 52:
        fail(f"decoder scope partition must contain 52 codes, found {len(all_scoped)}")
    if len(set(all_scoped)) != len(all_scoped):
        fail("decoder scope partition contains duplicate codes")
    return expected


def parse_bound(source: str, name: str, expression: str) -> int:
    pattern = rf"pub const {re.escape(name)}:\s*usize\s*=\s*{re.escape(expression)}\s*;"
    if re.search(pattern, source) is None:
        fail(f"Rust bound {name} no longer matches the frozen expression {expression}")
    if name == "MAX_CEV0_CERTIFICATE_ITEMS":
        return 100
    if name == "MAX_CEV0_TC_AGGREGATE_SIGNATURE_SHARES":
        return 100 * 100
    if name == "MAX_CEV0_ROOT_BYTES_V0":
        return 8 * 1024 * 1024
    if name == "MAX_CEV0_INTRINSIC_SIGNATURE_WORK_UNITS_V0":
        return 3 * (100 * 100 + 100 * 3 + 1)
    raise AssertionError(name)


def build_registry() -> dict[str, Any]:
    try:
        rust_source = RUST_SOURCE.read_text(encoding="utf-8")
    except OSError as error:
        fail(f"cannot read {RUST_RELATIVE}: {error}")
    base = read_json(BASE_SCHEMA)
    anchor = read_json(ANCHOR_SCHEMA)
    epoch = read_json(EPOCH_SCHEMA)
    body = read_json(BODY_SCHEMA)
    checkpoint = read_json(CHECKPOINT_SCHEMA)
    raw_codes = rust_codes(rust_source)
    rust_code_names = [item["code"] for item in raw_codes]
    partitions = schema_partitions(
        base, anchor, epoch, body, checkpoint, rust_code_names
    )
    partition_codes = set(sum(partitions.values(), []))
    expected_codes = [code for code in rust_code_names if code in partition_codes]
    if rust_code_names != expected_codes:
        fail(
            "Rust DecodeErrorCode order differs from schema partition: "
            f"Rust={rust_code_names!r}, schema={expected_codes!r}"
        )

    class_by_code: dict[str, str] = {}
    for item in base["decoder_error_codes"]:
        class_by_code[item["code"]] = item.get("class", "unspecified")
    class_by_code.update(
        {
            "invalid_block_kind": "semantic",
            "invalid_optional_tag": "structural",
            "invalid_block_header": "semantic",
            "invalid_handoff_descriptor": "semantic",
            "invalid_handoff_certificate": "semantic",
            "invalid_epoch_anchor_relations": "safety",
            "invalid_boolean": "semantic",
            "invalid_rollout_phase": "semantic",
            "invalid_fallback_reason": "semantic",
            "invalid_next_epoch_commitment": "semantic",
            "invalid_utf8": "canonical",
            "noncanonical_event_attribute_order": "canonical",
            "invalid_double_vote_evidence": "safety",
            "invalid_leader_schedule": "semantic",
            "invalid_consensus_parameters": "semantic",
            "invalid_finality_proof": "safety",
            "invalid_checkpoint_two_seal": "safety",
            "invalid_sign_intent_tag": "semantic",
            "invalid_sign_intent": "safety",
            "invalid_handoff_sign_intent_role": "authorization",
            "invalid_handoff_sign_intent": "safety",
        }
    )
    if set(class_by_code) != set(rust_code_names):
        fail("decoder registry class map does not cover exactly the Rust taxonomy")

    scope_by_code = {
        code: scope for scope, codes in partitions.items() for code in codes
    }
    codes = []
    for item in raw_codes:
        code = item["code"]
        codes.append(
            {
                "ordinal": int(item["ordinal"]),
                "rust_variant": item["rust_variant"],
                "code": code,
                "scope": scope_by_code[code],
                "class": class_by_code[code],
            }
        )

    source_paths = {
        "rust_decoder": RUST_RELATIVE,
        "base_schema": str(BASE_SCHEMA.relative_to(ROOT)),
        "anchor_schema": str(ANCHOR_SCHEMA.relative_to(ROOT)),
        "epoch_schema": str(EPOCH_SCHEMA.relative_to(ROOT)),
        "block_body_schema": str(BODY_SCHEMA.relative_to(ROOT)),
        "checkpoint_schema": str(CHECKPOINT_SCHEMA.relative_to(ROOT)),
    }
    source_hashes = {
        key: sha256(ROOT / relative) for key, relative in source_paths.items()
    }
    return {
        "schema": REGISTRY_SCHEMA,
        "schema_version": 0,
        "status": "generated-and-gated",
        "rust_registry_const": "DecodeErrorCode::ALL",
        "source_paths": source_paths,
        "source_sha256": source_hashes,
        "scope_order": list(SCOPE_NAMES),
        "scopes": [
            {"scope": scope, "description": SCOPE_TEXT[scope], "codes": partitions[scope]}
            for scope in SCOPE_NAMES
        ],
        "codes": codes,
        "bounds": {
            "max_certificate_items": parse_bound(
                rust_source, "MAX_CEV0_CERTIFICATE_ITEMS", "100"
            ),
            "max_tc_aggregate_signature_shares": parse_bound(
                rust_source,
                "MAX_CEV0_TC_AGGREGATE_SIGNATURE_SHARES",
                "MAX_CEV0_CERTIFICATE_ITEMS * MAX_CEV0_CERTIFICATE_ITEMS",
            ),
            "max_root_bytes": parse_bound(
                rust_source, "MAX_CEV0_ROOT_BYTES_V0", "8 * 1024 * 1024"
            ),
            "max_intrinsic_signature_work_units": parse_bound(
                rust_source,
                "MAX_CEV0_INTRINSIC_SIGNATURE_WORK_UNITS_V0",
                "3 * (MAX_CEV0_TC_AGGREGATE_SIGNATURE_SHARES + (MAX_CEV0_CERTIFICATE_ITEMS * 3) + 1)",
            ),
        },
        "entry_points": {
            "B2-A": [
                "decode_ordinary_qc_v0_exact",
                "decode_ordinary_timeout_certificate_v0_exact",
                "decode_qc_reference_v0_exact_with_trusted_genesis",
            ],
            "B2-B": [
                "decode_block_header_v0_exact",
                "decode_handoff_descriptor_v0_exact",
                "decode_handoff_certificate_v0_exact",
                "decode_epoch_anchor_authorization_kernel_v0_exact",
            ],
            "B2-C": ["decode_next_epoch_commitment_v0_exact"],
            "B2-D": [
                "decode_application_payload_v0_exact",
                "decode_execution_receipt_commitment_v0_exact",
                "decode_double_vote_evidence_v0_exact",
            ],
            "B2-E": [
                "decode_consensus_parameters_v0_exact",
                "decode_ordinary_certified_header_v0_exact",
                "decode_checkpoint_finality_proof_v0_exact",
            ],
            "node-local": [
                "decode_canonical_sign_intent_v0_exact",
                "decode_canonical_handoff_sign_intent_v1_exact",
            ],
        },
    }


def canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--emit", action="store_true", help="print the canonical generated registry"
    )
    parser.add_argument(
        "--registry", type=Path, default=REGISTRY, help="registry path (for tests)"
    )
    args = parser.parse_args()
    expected = build_registry()
    rendered = canonical_json(expected)
    if args.emit:
        sys.stdout.write(rendered)
        return 0
    registry_path = args.registry.resolve()
    try:
        actual_bytes = registry_path.read_bytes()
    except OSError as error:
        fail(f"missing generated registry {registry_path}: {error}")
    if actual_bytes != rendered.encode("utf-8"):
        fail(
            f"generated registry drift at {registry_path.relative_to(ROOT)}; "
            "run this checker with --emit and update the committed artifact"
        )
    actual = read_json(registry_path)
    if actual != expected:
        fail("generated registry JSON differs despite matching bytes")
    print(
        "PoCO-BFT v0 decoder registry verified: "
        f"{len(expected['codes'])} codes across {len(expected['scopes'])} scopes; "
        "Rust order, schema partitions, bounds, and source hashes match"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RegistryError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
