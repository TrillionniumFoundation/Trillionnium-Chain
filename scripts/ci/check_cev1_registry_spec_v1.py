#!/usr/bin/env python3
"""Fail-closed checker for the candidate CEV1 registry set.

The registries are review/inventory artifacts only.  This gate deliberately
does not make a wire kind, profile, or protocol version active.  It does,
however, treat the committed object catalog as an exact source projection:
the object registry must contain the same 53 IDs, in the same order, with the
same planning plane.  A missing, extra, reordered, or reclassified object is
registry semantic drift and stops the gate.

Only Python's standard library is used.  ``--root`` is provided for the
retained-mutant harness; normal CI should invoke the script without it.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any, NoReturn


ROOT = Path(__file__).resolve().parents[2]
REGISTRY_REL = Path("docs/protocol/poco-ai-native-v1/registry")
CATALOG_REL = Path("docs/protocol/poco-ai-native-v1/schema/object-catalog-v1.toml")
REGISTRY_SCHEMA = "trnm-cev1-object-registry-v1"
REGISTRY_STATUS = "candidate-non-normative"
CATALOG_SCHEMA_VERSION = 1
CATALOG_ID = "trnm-poco-ai-native-v1-object-catalog-v1"
PROTOCOL_ID = "trnm-poco-ai-native-v1"
PLANES = (
    "agent",
    "market-task",
    "compute-verify",
    "data-availability",
    "order-coordination-settlement",
)

# This is the frozen planning inventory from the canonical design-truth gate.
# Keeping the projection here prevents a simultaneous catalog/registry edit
# from silently shrinking the candidate surface.
EXPECTED_OBJECTS: tuple[tuple[str, str], ...] = (
    ("AgentIdentityV1", "agent"),
    ("AgentKeyV1", "agent"),
    ("CapabilityGrantV1", "agent"),
    ("CapabilityRevocationOperationV1", "agent"),
    ("SessionKeyGrantV1", "agent"),
    ("NonceLaneStateV1", "agent"),
    ("AgentTransactionV1", "agent"),
    ("TaskOfferV1", "market-task"),
    ("BidV1", "market-task"),
    ("TaskLeaseV1", "market-task"),
    ("EscrowV1", "market-task"),
    ("ComputeCheckpointV1", "market-task"),
    ("ExecutionReceiptV1", "compute-verify"),
    ("ResultV1", "compute-verify"),
    ("VerificationProfileV1", "compute-verify"),
    ("VerificationClaimV1", "compute-verify"),
    ("ChallengeV1", "compute-verify"),
    ("EvaluationResultV1", "compute-verify"),
    ("ArtifactCommitmentV1", "data-availability"),
    ("DaCommitteeDescriptorV1", "data-availability"),
    ("DaBatchEnvelopeV1", "data-availability"),
    ("DaAttestationV1", "data-availability"),
    ("AvailabilityCertificateV1", "data-availability"),
    ("WithholdingEvidenceV1", "data-availability"),
    ("RetrievalReceiptV1", "data-availability"),
    ("BatchRefV1", "order-coordination-settlement"),
    ("ChainDescriptorV1", "order-coordination-settlement"),
    ("StackProfileV1", "order-coordination-settlement"),
    ("BlockHeaderV1", "order-coordination-settlement"),
    ("OrderProposalV1", "order-coordination-settlement"),
    ("VoteV1", "order-coordination-settlement"),
    ("QuorumCertificateV1", "order-coordination-settlement"),
    ("TimeoutV1", "order-coordination-settlement"),
    ("TimeoutCertificateV1", "order-coordination-settlement"),
    ("EpochDescriptorV1", "order-coordination-settlement"),
    ("EpochHandoffV1", "order-coordination-settlement"),
    ("EpochCheckpointV1", "order-coordination-settlement"),
    ("TransactionExecutionReceiptV1", "order-coordination-settlement"),
    ("ConsumptionReceiptV1", "order-coordination-settlement"),
    ("ConsumptionRollupV1", "order-coordination-settlement"),
    ("FeeScheduleV1", "order-coordination-settlement"),
    ("SettlementIntentV1", "order-coordination-settlement"),
    ("SettlementReceiptV1", "order-coordination-settlement"),
    ("StateSyncManifestV1", "order-coordination-settlement"),
    ("UpgradePlanV1", "order-coordination-settlement"),
    ("MigrationReceiptV1", "order-coordination-settlement"),
    ("V0ToV1ActivationStatementV1", "order-coordination-settlement"),
    ("V0ToV1ActivationCertificateV1", "order-coordination-settlement"),
    ("OrderFinalityProofV1", "order-coordination-settlement"),
    ("ApplicationStateProofV1", "order-coordination-settlement"),
    ("ArtifactAvailabilityProofV1", "order-coordination-settlement"),
    ("ResultSettlementFinalityProofV1", "order-coordination-settlement"),
    ("GlobalExecutionBindingV1", "order-coordination-settlement"),
)
EXPECTED_OBJECT_IDS = tuple(item[0] for item in EXPECTED_OBJECTS)
EXPECTED_OBJECT_PLANES = dict(EXPECTED_OBJECTS)

REGISTRY_FILES = (
    "operation-registry-v1.json",
    "object-registry-v1.json",
    "domain-registry-v1.json",
    "error-registry-v1.json",
    "limit-registry-v1.json",
    "verification-profile-registry-v1.json",
)

OPERATION_PLANES = {
    "agent",
    "market-task",
    "compute-verify",
    "data-availability",
    "execution",
    "settlement",
    "order",
    "upgrade",
    "sync",
    "light-client",
    "governance",
    "reserved",
}
ERROR_CLASSES = {
    "malformed",
    "resource",
    "invalid",
    "conflict",
    "disabled",
    "unavailable",
    "stop-condition",
    "replay",
    "backend-error",
    "internal",
}
WIRE_STATES = {"candidate", "unassigned"}
ID_RE = re.compile(r"[A-Z][A-Za-z0-9]*V1\Z")
SLUG_RE = re.compile(r"[a-z][a-z0-9-]*\Z")
CODE_RE = re.compile(r"[A-Z][A-Z0-9_]*\Z")
LIMIT_NAME_RE = re.compile(r"[a-z][a-z0-9_]*\Z")
DECIMAL_RE = re.compile(r"[1-9][0-9]*\Z")


class RegistryError(ValueError):
    """A malformed candidate registry or source-projection mismatch."""


def fail(message: str) -> NoReturn:
    raise RegistryError(message)


def display(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RegistryError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_constant(value: str) -> NoReturn:
    raise RegistryError(f"non-finite JSON constant is forbidden: {value}")


def read_json(path: Path, root: Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as error:
        fail(f"cannot read {display(path, root)}: {error}")
    try:
        value = json.loads(
            raw,
            object_pairs_hook=reject_duplicate_pairs,
            parse_constant=reject_constant,
        )
    except RegistryError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        fail(f"invalid JSON in {display(path, root)}: {error}")
    if not isinstance(value, dict):
        fail(f"{display(path, root)} must contain a JSON object")
    return value


def read_toml(path: Path, root: Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as error:
        fail(f"cannot read {display(path, root)}: {error}")
    try:
        value = tomllib.loads(raw)
    except (tomllib.TOMLDecodeError, TypeError, ValueError) as error:
        fail(f"invalid TOML in {display(path, root)}: {error}")
    if not isinstance(value, dict):
        fail(f"{display(path, root)} must contain a TOML table")
    return value


def exact_bool(value: Any, label: str) -> bool:
    if type(value) is not bool:
        fail(f"{label} must be a boolean")
    return value


def exact_int(value: Any, label: str) -> int:
    if type(value) is not int:
        fail(f"{label} must be an integer")
    return value


def exact_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        fail(f"{label} must be a non-empty string")
    return value


def expect_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        fail(f"{label} keys differ: expected {sorted(expected)!r}, found {sorted(actual)!r}")


def expect_status(value: dict[str, Any], label: str) -> None:
    if value.get("status") != REGISTRY_STATUS:
        fail(f"{label}.status must be {REGISTRY_STATUS!r}")


def check_catalog(catalog: dict[str, Any], root: Path) -> list[dict[str, Any]]:
    label = display(root / CATALOG_REL, root)
    expect_keys(
        catalog,
        {
            "schema_version",
            "catalog_id",
            "protocol_id",
            "protocol_major",
            "status",
            "normative",
            "implemented",
            "activation",
            "objects",
        },
        label,
    )
    if exact_int(catalog["schema_version"], f"{label}.schema_version") != CATALOG_SCHEMA_VERSION:
        fail(f"{label}.schema_version is not {CATALOG_SCHEMA_VERSION}")
    if exact_string(catalog["catalog_id"], f"{label}.catalog_id") != CATALOG_ID:
        fail(f"{label}.catalog_id is not {CATALOG_ID!r}")
    if exact_string(catalog["protocol_id"], f"{label}.protocol_id") != PROTOCOL_ID:
        fail(f"{label}.protocol_id is not {PROTOCOL_ID!r}")
    if exact_int(catalog["protocol_major"], f"{label}.protocol_major") != 1:
        fail(f"{label}.protocol_major must be 1")
    if exact_string(catalog["status"], f"{label}.status") != "draft-design-only":
        fail(f"{label}.status must remain draft-design-only")
    for key in ("normative", "implemented", "activation"):
        if exact_bool(catalog[key], f"{label}.{key}") is not False:
            fail(f"{label}.{key} must remain false")

    objects = catalog.get("objects")
    if not isinstance(objects, list):
        fail(f"{label}.objects must be an array of tables")
    if len(objects) != len(EXPECTED_OBJECTS):
        fail(
            f"catalog object count drift: expected {len(EXPECTED_OBJECTS)}, found {len(objects)}"
        )
    projection: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, item in enumerate(objects):
        item_label = f"{label}.objects[{index}]"
        if not isinstance(item, dict):
            fail(f"{item_label} must be a TOML table")
        expect_keys(
            item,
            {"id", "plane", "status", "implemented", "wire_schema_assigned", "activation"},
            item_label,
        )
        object_id = exact_string(item["id"], f"{item_label}.id")
        if ID_RE.fullmatch(object_id) is None:
            fail(f"{item_label}.id is not a canonical v1 object identifier")
        if object_id in seen:
            fail(f"duplicate catalog object id: {object_id}")
        seen.add(object_id)
        expected_id, expected_plane = EXPECTED_OBJECTS[index]
        if object_id != expected_id:
            fail(
                f"catalog object order/id drift at index {index}: "
                f"expected {expected_id}, found {object_id}"
            )
        plane = exact_string(item["plane"], f"{item_label}.plane")
        if plane not in PLANES:
            fail(f"{item_label}.plane is unknown: {plane!r}")
        if plane != expected_plane:
            fail(
                f"catalog plane drift for {object_id}: expected {expected_plane!r}, found {plane!r}"
            )
        if exact_string(item["status"], f"{item_label}.status") != "design-only":
            fail(f"{item_label}.status must remain design-only")
        if exact_bool(item["implemented"], f"{item_label}.implemented") is not False:
            fail(f"{item_label}.implemented must remain false")
        assigned = exact_bool(item["wire_schema_assigned"], f"{item_label}.wire_schema_assigned")
        if assigned is not (object_id == "GlobalExecutionBindingV1"):
            fail(f"{item_label}.wire_schema_assigned has unexpected value")
        if exact_bool(item["activation"], f"{item_label}.activation") is not False:
            fail(f"{item_label}.activation must remain false")
        projection.append(item)
    if tuple(seen) and len(seen) != len(EXPECTED_OBJECTS):
        fail("catalog object identifiers are not unique")
    return projection


def check_object_registry(
    document: dict[str, Any], catalog_objects: list[dict[str, Any]], root: Path
) -> None:
    label = display(root / REGISTRY_REL / "object-registry-v1.json", root)
    expect_keys(document, {"schema", "status", "catalog_source", "global_activation", "objects"}, label)
    if exact_string(document["schema"], f"{label}.schema") != REGISTRY_SCHEMA:
        fail(f"{label}.schema mismatch")
    expect_status(document, label)
    if exact_string(document["catalog_source"], f"{label}.catalog_source") != str(CATALOG_REL):
        fail(f"{label}.catalog_source must be {str(CATALOG_REL)!r}")
    if exact_bool(document["global_activation"], f"{label}.global_activation") is not False:
        fail(f"{label}.global_activation must remain false")
    objects = document.get("objects")
    if not isinstance(objects, list):
        fail(f"{label}.objects must be an array")
    if len(objects) != len(catalog_objects):
        fail(
            f"object registry/catalog count mismatch: registry={len(objects)}, "
            f"catalog={len(catalog_objects)}"
        )
    if len(objects) != len(EXPECTED_OBJECTS):
        fail(f"object registry count drift: expected {len(EXPECTED_OBJECTS)}, found {len(objects)}")
    seen: set[str] = set()
    for index, item in enumerate(objects):
        item_label = f"{label}.objects[{index}]"
        if not isinstance(item, dict):
            fail(f"{item_label} must be an object")
        expect_keys(item, {"id", "plane", "authority", "wire"}, item_label)
        object_id = exact_string(item["id"], f"{item_label}.id")
        if object_id in seen:
            fail(f"duplicate object registry id: {object_id}")
        seen.add(object_id)
        expected_id, expected_plane = EXPECTED_OBJECTS[index]
        if object_id != expected_id:
            fail(
                f"object registry/catalog id mismatch at index {index}: "
                f"expected {expected_id}, found {object_id}"
            )
        plane = exact_string(item["plane"], f"{item_label}.plane")
        catalog_plane = catalog_objects[index].get("plane")
        if plane != expected_plane or plane != catalog_plane:
            fail(
                f"object registry/catalog plane mismatch for {object_id}: "
                f"expected {expected_plane!r}, found {plane!r}"
            )
        authority = exact_string(item["authority"], f"{item_label}.authority")
        if SLUG_RE.fullmatch(authority) is None:
            fail(f"{item_label}.authority is not a canonical authority slug")
        wire = exact_string(item["wire"], f"{item_label}.wire")
        if wire not in WIRE_STATES:
            fail(f"{item_label}.wire is not an allowed candidate state: {wire!r}")
        # A candidate/unassigned row is inventory only.  The registry has no
        # activation authority and must never grow an enabled/active state.
    if tuple(item["id"] for item in objects) != EXPECTED_OBJECT_IDS:
        fail("object registry IDs are not the canonical catalog order")


def check_operation_registry(document: dict[str, Any]) -> None:
    label = "operation-registry-v1.json"
    expect_keys(
        document,
        {"schema", "status", "protocol_version", "slot_count", "global_activation", "operations"},
        label,
    )
    if exact_string(document["schema"], f"{label}.schema") != "trnm-cev1-operation-registry-v1":
        fail(f"{label}.schema mismatch")
    expect_status(document, label)
    if exact_int(document["protocol_version"], f"{label}.protocol_version") != 1:
        fail(f"{label}.protocol_version must be 1")
    if exact_int(document["slot_count"], f"{label}.slot_count") != 30:
        fail(f"{label}.slot_count must be 30")
    if exact_bool(document["global_activation"], f"{label}.global_activation") is not False:
        fail(f"{label}.global_activation must remain false")
    rows = document.get("operations")
    if not isinstance(rows, list) or len(rows) != 30:
        fail("operation registry must contain exactly 30 slots")
    seen_kinds: set[int] = set()
    seen_names: set[str] = set()
    for index, row in enumerate(rows):
        row_label = f"{label}.operations[{index}]"
        if not isinstance(row, dict):
            fail(f"{row_label} must be an object")
        required = {"kind", "name", "plane", "status", "enabled", "authority", "nonce_lane"}
        allowed = required | ({"canonical_error"} if index == 29 else set())
        if set(row) != allowed:
            fail(f"{row_label} has unexpected fields")
        kind = exact_int(row["kind"], f"{row_label}.kind")
        if kind != index or kind in seen_kinds:
            fail(f"operation slot drift at index {index}: {kind}")
        seen_kinds.add(kind)
        name = exact_string(row["name"], f"{row_label}.name")
        if name in seen_names:
            fail(f"duplicate operation name: {name}")
        seen_names.add(name)
        plane = exact_string(row["plane"], f"{row_label}.plane")
        if plane not in OPERATION_PLANES:
            fail(f"{row_label}.plane is unknown: {plane!r}")
        status = exact_string(row["status"], f"{row_label}.status")
        if index == 29:
            if status != "disabled" or row.get("canonical_error") != "ERR_OPERATION_DISABLED":
                fail("operation kind 29 must be the explicit disabled sentinel")
        elif status != "candidate-assigned":
            fail(f"{row_label}.status must be candidate-assigned")
        if exact_bool(row["enabled"], f"{row_label}.enabled") is not False:
            fail(f"{row_label}.enabled must remain false")
        exact_string(row["authority"], f"{row_label}.authority")
        exact_string(row["nonce_lane"], f"{row_label}.nonce_lane")


def check_domain_registry(document: dict[str, Any]) -> None:
    label = "domain-registry-v1.json"
    expect_keys(document, {"schema", "status", "domains"}, label)
    if exact_string(document["schema"], f"{label}.schema") != "trnm-cev1-domain-registry-v1":
        fail(f"{label}.schema mismatch")
    expect_status(document, label)
    rows = document.get("domains")
    if not isinstance(rows, list) or not rows:
        fail(f"{label}.domains must be a non-empty array")
    ids: set[str] = set()
    values: set[str] = set()
    for index, row in enumerate(rows):
        row_label = f"{label}.domains[{index}]"
        if not isinstance(row, dict):
            fail(f"{row_label} must be an object")
        expect_keys(row, {"id", "value", "meaning"}, row_label)
        domain_id = exact_string(row["id"], f"{row_label}.id")
        value = exact_string(row["value"], f"{row_label}.value")
        meaning = exact_string(row["meaning"], f"{row_label}.meaning")
        if domain_id in ids:
            fail(f"duplicate domain id: {domain_id}")
        if value in values:
            fail(f"duplicate domain value: {value}")
        ids.add(domain_id)
        values.add(value)
        if SLUG_RE.fullmatch(domain_id) is None:
            fail(f"{row_label}.id is not a canonical slug")
        if not value.isascii() or not value.startswith("trnm.poco-ai.") or not value.endswith(".v1"):
            fail(f"{row_label}.value is not a canonical ASCII v1 domain")
        if not meaning.strip():
            fail(f"{row_label}.meaning must not be blank")


def check_error_registry(document: dict[str, Any]) -> None:
    label = "error-registry-v1.json"
    expect_keys(document, {"schema", "status", "errors"}, label)
    if exact_string(document["schema"], f"{label}.schema") != "trnm-cev1-error-registry-v1":
        fail(f"{label}.schema mismatch")
    expect_status(document, label)
    rows = document.get("errors")
    if not isinstance(rows, list) or not rows:
        fail(f"{label}.errors must be a non-empty array")
    codes: set[str] = set()
    for index, row in enumerate(rows):
        row_label = f"{label}.errors[{index}]"
        if not isinstance(row, dict):
            fail(f"{row_label} must be an object")
        expect_keys(row, {"code", "class", "retryable"}, row_label)
        code = exact_string(row["code"], f"{row_label}.code")
        klass = exact_string(row["class"], f"{row_label}.class")
        if CODE_RE.fullmatch(code) is None:
            fail(f"{row_label}.code is not a canonical error code")
        if code in codes:
            fail(f"duplicate error code: {code}")
        codes.add(code)
        if klass not in ERROR_CLASSES:
            fail(f"{row_label}.class is unknown: {klass!r}")
        exact_bool(row["retryable"], f"{row_label}.retryable")
    required = {
        "ERR_OPERATION_DISABLED",
        "ERR_PROFILE_DISABLED",
        "ERR_PROFILE_EXPIRED",
        "ERR_PROFILE_EVIDENCE_MISSING",
        "ERR_ASSET_CONSERVATION",
        "ERR_CHECKPOINT_ROLLBACK",
        "ERR_STATE_ROOT_DIVERGENCE",
    }
    missing = sorted(required - codes)
    if missing:
        fail(f"missing required errors: {missing!r}")


def check_limit_registry(document: dict[str, Any]) -> None:
    label = "limit-registry-v1.json"
    expect_keys(document, {"schema", "status", "units", "limits", "note"}, label)
    if exact_string(document["schema"], f"{label}.schema") != "trnm-cev1-limit-registry-v1":
        fail(f"{label}.schema mismatch")
    expect_status(document, label)
    exact_string(document["units"], f"{label}.units")
    exact_string(document["note"], f"{label}.note")
    limits = document.get("limits")
    if not isinstance(limits, dict) or not limits:
        fail(f"{label}.limits must be a non-empty object")
    for name, value in limits.items():
        if not isinstance(name, str) or LIMIT_NAME_RE.fullmatch(name) is None:
            fail(f"{label}.limits has a non-canonical name: {name!r}")
        if type(value) is int:
            if value <= 0:
                fail(f"nonpositive limit: {name}")
        elif isinstance(value, str) and DECIMAL_RE.fullmatch(value):
            # Decimal strings are used for values beyond JavaScript's safe
            # integer range; they still represent strictly positive bounds.
            pass
        else:
            fail(f"limit {name} must be a positive integer or decimal string")


def check_profile_registry(document: dict[str, Any]) -> None:
    label = "verification-profile-registry-v1.json"
    expect_keys(document, {"schema", "status", "fallback_allowed", "profiles"}, label)
    if exact_string(document["schema"], f"{label}.schema") != "trnm-cev1-verification-profile-registry-v1":
        fail(f"{label}.schema mismatch")
    expect_status(document, label)
    if exact_bool(document["fallback_allowed"], f"{label}.fallback_allowed") is not False:
        fail("verification fallback must remain false")
    rows = document.get("profiles")
    if not isinstance(rows, list) or not rows:
        fail(f"{label}.profiles must be a non-empty array")
    ids: set[str] = set()
    for index, row in enumerate(rows):
        row_label = f"{label}.profiles[{index}]"
        if not isinstance(row, dict):
            fail(f"{row_label} must be an object")
        required = {
            "id",
            "class",
            "state",
            "globally_enabled",
            "required_evidence",
            "result_authority",
            "settlement_authority",
        }
        optional = {"objective_settlement_forbidden", "poco_weight_forbidden"}
        if set(row) - required - optional or not required.issubset(row):
            fail(f"{row_label} has an unexpected or missing field")
        profile_id = exact_string(row["id"], f"{row_label}.id")
        if profile_id in ids:
            fail(f"duplicate profile id: {profile_id}")
        ids.add(profile_id)
        if SLUG_RE.fullmatch(profile_id) is None:
            fail(f"{row_label}.id is not a canonical profile slug")
        exact_string(row["class"], f"{row_label}.class")
        state = exact_string(row["state"], f"{row_label}.state")
        if state not in {"design-only", "candidate-local"}:
            fail(f"{row_label}.state is unknown: {state!r}")
        if exact_bool(row["globally_enabled"], f"{row_label}.globally_enabled") is not False:
            fail(f"{row_label}.globally_enabled must remain false")
        evidence = row["required_evidence"]
        if not isinstance(evidence, list) or not evidence or any(
            not isinstance(item, str) or not item for item in evidence
        ):
            fail(f"{row_label}.required_evidence must be a non-empty string array")
        if len(set(evidence)) != len(evidence):
            fail(f"{row_label}.required_evidence contains duplicates")
        for key in ("result_authority", "settlement_authority"):
            if exact_bool(row[key], f"{row_label}.{key}") is not False:
                fail(f"{row_label}.{key} must remain false")
        if profile_id == "subjective-v1":
            for key in ("objective_settlement_forbidden", "poco_weight_forbidden"):
                if exact_bool(row.get(key), f"{row_label}.{key}") is not True:
                    fail(f"subjective profile authority boundary drift: {key}")
        elif optional & set(row):
            fail(f"{row_label} may not carry subjective-only authority fields")
    if "subjective-v1" not in ids:
        fail("subjective-v1 profile is missing")


def validate(root: Path) -> None:
    """Validate all six registries and their canonical object projection."""

    root = root.resolve()
    registry_dir = root / REGISTRY_REL
    catalog = read_toml(root / CATALOG_REL, root)
    catalog_objects = check_catalog(catalog, root)
    documents = {
        name: read_json(registry_dir / name, root) for name in REGISTRY_FILES
    }
    for document in documents.values():
        expect_status(document, "registry document")
    check_operation_registry(documents["operation-registry-v1.json"])
    check_object_registry(documents["object-registry-v1.json"], catalog_objects, root)
    check_domain_registry(documents["domain-registry-v1.json"])
    check_error_registry(documents["error-registry-v1.json"])
    check_limit_registry(documents["limit-registry-v1.json"])
    check_profile_registry(documents["verification-profile-registry-v1.json"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=ROOT,
        help="repository root (used by the retained-mutant harness)",
    )
    args = parser.parse_args(argv)
    try:
        validate(args.root)
    except RegistryError as error:
        print(f"cev1 registry candidate: FAIL: {error}", file=sys.stderr)
        return 1
    except (OSError, KeyError, TypeError, ValueError) as error:
        # Any unexpected malformed input is still a fail-closed result, not a
        # traceback that could be mistaken for a successful gate.
        print(f"cev1 registry candidate: FAIL: malformed input: {error}", file=sys.stderr)
        return 1
    print("cev1 registry candidate: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
