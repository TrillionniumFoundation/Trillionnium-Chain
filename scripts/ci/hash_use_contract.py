#!/usr/bin/env python3
"""Inspect the reviewed per-purpose hash contract; never qualify cryptography.

Hash output width, copied parameter labels and source checksums establish no
security bound. This fixed inventory separates attack games and the bytes
actually committed. It cannot authorize a format migration or external effect.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

import pq_lifetime_budget as lifetime
from pq_source_reader import SourceReadError, read_regular

SCHEMA = "trnm-hash-use-contract-v1"
RESULT_SCHEMA = "trnm-hash-use-contract-result-v1"
DEFAULT_MANIFEST = "config/pon/hash-use-contract-v1.json"
REVIEW_BASE = "e4abb172147e941b62483652b0ceabaae4317624"
MAX_BYTES = 1024 * 1024
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_DEPTH = 64
# These are reviewed input identities, not cryptographic security assumptions.
# Changing source or semantics requires a new review; inspect never regenerates.
REVIEWED_SEMANTICS_SHA256 = "29189f8e96a255472577479d46204b2b403a1f8e27806da6aa616e417ced0b5b"
# Preserve the 31-path/19-use semantics. At 975ab093, five selected source
# identities and the proof descriptor's 140-input W1 map were separately reviewed.
# New exported APIs outside these declared uses are not a complete callgraph
# review or current-use approval. The selected upstream profile remains withdrawn.
REVIEWED_SOURCE_MAP_SHA256 = "75490c688e5bf5eab404cc57a716fc9fc51a3fd66d7e37285b10d3801471aadd"

USES = {
    "model-legacy-root": "model",
    "model-full-payload": "model",
    "model-direct-dependencies": "model",
    "model-declared-transitive-graph": "model",
    "transaction-root": "transaction",
    "state-root": "state",
    "history-block-anchor": "history",
    "signature-key-identity": "signature",
    "signature-tpq1-payload": "signature",
    "signature-cpq1-content": "signature",
    "storage-cell-chunks": "storage",
    "storage-bep52-root": "storage",
    "migration-full-state": "migration",
    "migration-bounded-state-history": "migration",
    "release-artifact": "release",
    "profile-byte-commitment": "profile",
    "work-threshold": "work",
    "proof-risc0-selected": "proof",
    "proof-p3-tagged-reference": "proof",
}
GAMES = {
    "fixed-target-preimage": {
        "selection_order": "target-digest-fixed-before-search",
        "attacker_output": "one-accepted-preimage-of-that-target",
        "qualification": "target-distribution-and-valid-input-domain-unqualified",
    },
    "fixed-message-second-preimage": {
        "selection_order": "complete-original-object-fixed-before-replacement-search",
        "attacker_output": "different-valid-object-with-the-fixed-original-digest",
        "qualification": "message-length-target-population-and-advice-unqualified",
    },
    "chosen-pair-collision": {
        "selection_order": "attacker-selects-both-objects-before-one-is-authorized",
        "attacker_output": "two-distinct-valid-objects-with-one-digest",
        "qualification": "valid-object-domain-and-authorization-reduction-unqualified",
    },
    "merkle-binding": {
        "selection_order": "depends-on-fixed-root-or-attacker-prepared-tree-game",
        "attacker_output": "conflicting-leaf-content-position-or-tree-opening",
        "qualification": "leaf-node-empty-shape-and-openings-reduction-unqualified",
    },
    "work-threshold-search": {
        "selection_order": "branch-context-and-threshold-fixed-before-each-search",
        "attacker_output": "legal-complete-W1-candidate-with-ticket-at-most-target",
        "qualification": "target-is-a-set-not-a-single-digest-and-work-cost-is-unqualified",
    },
    "proof-soundness-qrom": {
        "selection_order": "adaptive-statements-and-transcripts-in-a-complete-proof-game",
        "attacker_output": "accepting-proof-of-a-false-complete-statement",
        "qualification": "PCS-FS-recursion-extraction-and-concrete-oracle-losses-unqualified",
    },
}
PRIMITIVES = {
    "sha256": {"construction": "FIPS180-4/SHA-256", "output_bits": 256},
    "sha384": {"construction": "FIPS180-4/SHA-384", "output_bits": 384},
    "sha512": {"construction": "FIPS180-4/SHA-512", "output_bits": 512},
    "sha3-512": {"construction": "FIPS202/SHA3-512", "output_bits": 512},
    "risc0-poseidon2": {
        "construction": "risc0-3.0.6/Poseidon2/BabyBear",
        "output_bits": None,
    },
}
MIGRATION_REQUIREMENTS = [
    "new-versioned-domain-and-exact-canonical-encoding",
    "actual-original-content-before-any-full-content-claim",
    "independently-authenticated-expected-object-and-profile",
    "fresh-current-owner-authorization-for-the-new-format",
    "explicit-handling-of-every-retained-legacy-reference",
    "nonrewinding-recovery-frontier-and-surviving-liabilities",
    "explicit-retirement-and-downgrade-policy-before-adoption",
]
QUALIFICATION = {
    "actual_lifetime_failure_bound": None,
    "security_bits": None,
    "whole_chain_hash_query_scope_closed": False,
    "composition_coverage_proved": False,
    "whole_chain_pq_qualified": False,
    "production_activation": False,
}
MATERIAL_SCOPES = {
    "unchanged-existing-format": "existing-format-only",
    "legacy-digest-wrapper": "literal-digest-only",
    "actual-full-content": "direct-encoded-content-only",
    "actual-declared-direct-objects": "declared-direct-object-set-only",
    "actual-declared-transitive-objects": "declared-typed-graph-only",
    "actual-genesis-state-history": "bounded-genesis-to-checkpoint-state-bytes",
}


class ContractError(ValueError):
    """Reject changed, malformed, ambiguous or overclaiming declarations."""


def require(condition, message):
    if not condition:
        raise ContractError(message)


def fields(value, expected, where):
    require(type(value) is dict and set(value) == set(expected),
            "unexpected or missing fields: " + where)


def exact(value, expected, where):
    """Closed recursive comparison, including bool/int distinctions."""
    require(type(value) is type(expected), "wrong type: " + where)
    if type(expected) is dict:
        fields(value, expected, where)
        for key, item in expected.items():
            exact(value[key], item, where + "." + key)
    elif type(expected) is list:
        require(len(value) == len(expected), "wrong list length: " + where)
        for index, item in enumerate(expected):
            exact(value[index], item, where + "." + str(index))
    else:
        require(value == expected, "changed reviewed value: " + where)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def sha(value):
    return hashlib.sha256(value).hexdigest()


def strings(value, where, *, nonempty=True):
    require(type(value) is list and int(nonempty) <= len(value) <= 128,
            "invalid string list: " + where)
    for item in value:
        lifetime.string(item, where)
    require(len(set(value)) == len(value), "duplicate item: " + where)


def strict_json(raw):
    """Reuse the strict budget decoder with a lexical nesting ceiling first."""
    require(type(raw) is bytes and len(raw) <= MAX_BYTES, "invalid/oversize JSON input")
    depth, quoted, escaped = 0, False, False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            require(depth <= MAX_DEPTH, "JSON nesting limit")
        elif byte in (93, 125):
            depth -= 1
            require(depth >= 0, "invalid JSON nesting")
    try:
        return lifetime.strict_json(raw)
    except lifetime.BudgetError as error:
        raise ContractError(str(error)) from error


def review_migration(data):
    """Check declared prerequisites; never establish their runtime fulfillment.

The literal wrapper of an old digest can bind only that literal. A full-byte
recomputation gives a new direct-content obligation; it cannot strengthen the
old commitment, authenticate lost history, or establish transitive closure.
"""
    fields(data, ("input_material", "claimed_scope", "original_bytes_required",
                  "old_commitment_strengthened", "historical_provenance_restored",
                  "transitive_dependency_closure_proved", "adoption_status",
                  "requirements"), "migration")
    material = data["input_material"]
    require(type(material) is str and material in MATERIAL_SCOPES,
            "unsupported migration material")
    exact(data["claimed_scope"], MATERIAL_SCOPES[material], "migration.claimed_scope")
    actual = material in ("actual-full-content", "actual-declared-direct-objects",
                          "actual-declared-transitive-objects", "actual-genesis-state-history")
    exact(data["original_bytes_required"], actual, "migration.original_bytes_required")
    for key in ("old_commitment_strengthened", "historical_provenance_restored",
                "transitive_dependency_closure_proved"):
        exact(data[key], False, "migration." + key)
    exact(data["adoption_status"], "not-established", "migration.adoption_status")
    exact(data["requirements"], MIGRATION_REQUIREMENTS, "migration.requirements")
    return {
        "declared_scope": MATERIAL_SCOPES[material],
        "full_content_recomputation_required": actual,
        "old_commitment_collision_risk_removed": False,
        "wrapper_preserves_every_inner_collision": material == "legacy-digest-wrapper",
        "prerequisites_fulfilled": False,
        "migration_authorized": False,
    }


def _validate(data):
    fields(data, ("schema", "purpose", "review_base_revision", "source_binding",
                  "primitives", "games", "uses", "migration_requirements",
                  "query_model_notes", "proof_profiles", "qualification", "source_files"),
           "manifest")
    exact(data["schema"], SCHEMA, "schema")
    exact(data["purpose"], "reviewed-source-obligation-inventory", "purpose")
    exact(data["review_base_revision"], REVIEW_BASE, "review_base_revision")
    exact(data["source_binding"], "declared-path-bytes-only-not-authenticated-history", "source_binding")
    exact(data["primitives"], PRIMITIVES, "primitives")
    exact(data["games"], GAMES, "games")
    exact(data["migration_requirements"], MIGRATION_REQUIREMENTS, "migration_requirements")
    exact(data["qualification"], QUALIFICATION, "qualification")
    fields(data["uses"], USES, "uses")
    source_paths = set()
    reports = {}
    required_binding_games = {"fixed-message-second-preimage", "chosen-pair-collision"}
    for identity, category in USES.items():
        row = data["uses"][identity]
        fields(row, ("category", "source_paths", "symbols", "primitives", "consumed_outputs", "encoding",
                     "attack_games", "attacker_control", "input_scope",
                     "legacy_reference_roles", "migration", "open_obligations"), identity)
        exact(row["category"], category, identity + ".category")
        for key in ("source_paths", "symbols", "primitives", "attack_games", "open_obligations"):
            strings(row[key], identity + "." + key)
        strings(row["legacy_reference_roles"], identity + ".legacy_reference_roles", nonempty=False)
        require(set(row["primitives"]) <= set(PRIMITIVES), "unknown primitive: " + identity)
        outputs = row["consumed_outputs"]
        require(type(outputs) is dict and 0 < len(outputs) <= 32,
                "missing or invalid consumed output roles: " + identity)
        for role, output in outputs.items():
            lifetime.string(role, identity + ".output role")
            fields(output, ("primitive", "consumed_bits", "truncation", "notes"),
                   identity + ".output." + role)
            lifetime.string(output["notes"], identity + ".output notes")
            primitive, bits, truncation = output["primitive"], output["consumed_bits"], output["truncation"]
            if primitive is None:
                require(bits is None and truncation == "not-mapped",
                        "unmapped output cannot acquire a width: " + identity)
                continue
            require(type(primitive) is str and primitive in row["primitives"],
                    "output role uses an undeclared primitive: " + identity)
            width = PRIMITIVES[primitive]["output_bits"]
            if width is None:
                require(bits is None and truncation == "not-mapped",
                        "field/construction output requires its own mapping: " + identity)
            else:
                require(type(bits) is int and 0 < bits <= width,
                        "invalid consumed output width: " + identity)
                require((bits == width and truncation == "none")
                        or (bits < width and truncation == "explicit-bit-prefix"),
                        "truncation cannot retain the original output width: " + identity)
        games = set(row["attack_games"])
        require(games <= set(GAMES), "unknown attack game: " + identity)
        if category == "work":
            exact(row["attack_games"], ["work-threshold-search"], identity + ".attack_games")
        elif category == "proof":
            require({"proof-soundness-qrom", "merkle-binding"} <= games,
                    "proof hash game is not the complete proof game")
        else:
            require(required_binding_games <= games, "binding attack games omitted: " + identity)
        for path in row["source_paths"]:
            source_paths.add(lifetime.relative_path(path, identity + ".source_path"))
        fields(row["encoding"], ("record", "framing", "domains"), identity + ".encoding")
        lifetime.string(row["encoding"]["record"], identity + ".record")
        lifetime.string(row["encoding"]["framing"], identity + ".framing")
        strings(row["encoding"]["domains"], identity + ".domains")
        for key in ("attacker_control", "input_scope"):
            lifetime.string(row[key], identity + "." + key)
        reports[identity] = review_migration(row["migration"])
    files = data["source_files"]
    require(type(files) is dict and 0 < len(files) <= 128, "invalid source inventory")
    require(source_paths == set(files), "source roster differs from declared uses")
    for path, pin in files.items():
        lifetime.relative_path(path, "source path")
        fields(pin, ("bytes", "sha256"), "source pin")
        require(type(pin["bytes"]) is int and 0 < pin["bytes"] <= MAX_SOURCE_BYTES,
                "invalid source size: " + path)
        require(type(pin["sha256"]) is str
                and re.fullmatch(r"[0-9a-f]{64}", pin["sha256"]) is not None,
                "invalid source digest: " + path)
    require(sha(canonical(files)) == REVIEWED_SOURCE_MAP_SHA256,
            "source map differs from reviewed identity; automatic repinning refused")
    semantics = {key: value for key, value in data.items() if key != "source_files"}
    require(sha(canonical(semantics)) == REVIEWED_SEMANTICS_SHA256,
            "purpose/game/encoding/parameter semantics differ from reviewed identity")
    return {
        "schema": RESULT_SCHEMA, "status": "HOLD_NO_GO", "contract_satisfied": True,
        "review_base_revision": REVIEW_BASE,
        "declared_use_count": len(USES), "declared_source_count": len(files),
        "source_files_checked": False, "source_revision_authenticated": False,
        "complete_callgraph_coverage_proved": False,
        "source_semantics_refinement_proved": False,
        "per_use_migration_review": reports,
        "query_exponents_are_failure_probabilities": False,
        "source_hashes_supply_security_bits": False,
        "proof_parameter_labels_establish_qrom_soundness": False,
        **QUALIFICATION,
    }


def validate_manifest(data):
    """Validate only declarations; source_files_checked remains false."""
    try:
        return _validate(data)
    except (lifetime.BudgetError, KeyError, TypeError, ValueError, RecursionError) as error:
        raise ContractError(str(error)) from error


def inspect(root, manifest_path=DEFAULT_MANIFEST):
    """Read exactly the declared paths with descriptor-bound regular-file checks."""
    try:
        root = Path(root)
        path = lifetime.relative_path(manifest_path, "manifest")
        raw = read_regular(root, path, MAX_BYTES)
        data = strict_json(raw)
        result = validate_manifest(data)
        for source, pin in data["source_files"].items():
            content = read_regular(root, source, MAX_SOURCE_BYTES)
            require(len(content) == pin["bytes"] and sha(content) == pin["sha256"],
                    "reviewed source bytes differ: " + source)
        result.update({"manifest_sha256": sha(raw), "source_files_checked": True,
                       "reviewed_source_map_sha256": REVIEWED_SOURCE_MAP_SHA256,
                       "reviewed_semantics_sha256": REVIEWED_SEMANTICS_SHA256})
        return result
    except (SourceReadError, lifetime.BudgetError, OSError, TypeError, ValueError) as error:
        raise ContractError(str(error)) from error


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    args = parser.parse_args(argv)
    try:
        result = inspect(args.root, args.manifest)
    except ContractError as error:
        print(json.dumps({"schema": RESULT_SCHEMA, "status": "REFUSE", "error": str(error),
                          **QUALIFICATION}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
