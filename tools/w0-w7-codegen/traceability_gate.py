#!/usr/bin/env python3
"""Fail-closed G2.0 source, parser, and W0-W7 evidence gate.

The operation registry is a candidate projection.  This gate never enables a
kind or changes protocol truth; it only records whether an exact, reproducible
source/parser snapshot was checked.  All inputs are pinned by Git commit,
tree, raw blob SHA-256, and a strict JSON decoder.  Results are deterministic
JSON under ``docs/evidence/g2.0`` rather than ephemeral ``/tmp`` output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NoReturn


ROOT = Path(__file__).resolve().parents[2]
REGISTRY_REL = Path("docs/protocol/poco-ai-native-v1/registry")
CATALOG_REL = Path("docs/protocol/poco-ai-native-v1/schema/object-catalog-v1.toml")
TRACE_SCHEMA_REL = Path("docs/protocol/poco-ai-native-v1/traceability/w0-w7-row-v1.schema.json")
REGISTRY_FILES = (
    "operation-registry-v1.json",
    "object-registry-v1.json",
    "domain-registry-v1.json",
    "error-registry-v1.json",
    "limit-registry-v1.json",
    "verification-profile-registry-v1.json",
)
A08_CHECKER_REL = Path("scripts/ci/check_cev1_registry_spec_v1.py")
A09_PARSER_REL = Path("tools/independent-cev1-parser/registry_conformance.py")
A09_GATE_REL = Path("scripts/ci/check_independent_cev1_registry_v1.sh")
A09_MAPPING_REL = Path("conformance/cev1/registry-v1/operation-mapping-v1.json")
A09_NEGATIVE_REL = Path("conformance/cev1/registry-v1/negative-cases.json")
A09_PLAN_REL = Path("docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md")

MANIFEST_SCHEMA = "trnm-g20-source-manifest-v1"
CLOSURE_SCHEMA = "trnm-g20-w0-w7-closure-v1"
EVIDENCE_SCHEMA = "trnm-g20-evidence-index-v1"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
SLUG = re.compile(r"[a-z][a-z0-9-]*\Z")
LIMIT_NAME = re.compile(r"[a-z][a-z0-9_]*\Z")
BODY_TYPE = re.compile(r"[A-Za-z][A-Za-z0-9]*V1\Z")
ERROR_CODE = re.compile(r"ERR_[A-Z0-9_]+\Z")
DECIMAL = re.compile(r"[1-9][0-9]*\Z")
EVIDENCE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,255}\Z")
MIN_A09_NEGATIVE_CASES = 54

PLANES = {
    "agent", "market-task", "compute-verify", "data-availability", "execution",
    "settlement", "order", "upgrade", "sync", "light-client", "governance",
    "reserved", "order-coordination-settlement",
}
LINKS_BY_PLANE = {
    "agent": ["W0", "W1", "W2", "W3", "W4", "W7"],
    "market-task": ["W0", "W1", "W2", "W3", "W4", "W7"],
    "compute-verify": ["W0", "W1", "W2", "W3", "W4", "W5", "W7"],
    "data-availability": ["W0", "W1", "W2", "W3", "W7"],
    "execution": ["W0", "W1", "W2", "W3", "W4", "W7"],
    "settlement": ["W0", "W1", "W2", "W3", "W4", "W5", "W6", "W7"],
    "order": ["W0", "W3", "W7"],
    "upgrade": ["W0", "W1", "W3", "W4", "W7"],
    "sync": ["W0", "W3", "W4", "W7"],
    "light-client": ["W0", "W7"],
    "governance": ["W0", "W1", "W2", "W3", "W4", "W7"],
    "reserved": ["W0"],
    "order-coordination-settlement": ["W0", "W3", "W4", "W7"],
}
DOMAIN_BY_PLANE = {
    "agent": "agent-transaction", "market-task": "task-offer",
    "compute-verify": "verification-claim", "data-availability": "artifact-evidence",
    "execution": "execution-receipt", "settlement": "settlement-intent",
    "order": "order-finality-proof", "upgrade": "upgrade-plan",
    "sync": "application-state-proof", "light-client": "order-finality-proof",
    "governance": "upgrade-plan", "reserved": "protocol-context",
    "order-coordination-settlement": "chain-descriptor",
}
LIMITS_BY_PLANE = {
    "agent": ("max_transaction_bytes", "max_cev1_nesting", "max_signature_work_per_transaction", "max_operation_scopes", "max_nonce_lanes_per_agent"),
    "market-task": ("max_transaction_bytes", "max_cev1_nesting", "max_signature_work_per_transaction", "max_protocol_objects_per_block"),
    "compute-verify": ("max_transaction_bytes", "max_cev1_nesting", "max_signature_work_per_transaction", "max_evidence_entries_per_challenge"),
    "data-availability": ("max_transaction_bytes", "max_cev1_nesting", "max_signature_work_per_transaction", "max_artifact_descriptor_bytes"),
    "execution": ("max_transaction_bytes", "max_cev1_nesting", "max_signature_work_per_transaction", "max_execution_units_per_transaction"),
    "settlement": ("max_transaction_bytes", "max_cev1_nesting", "max_signature_work_per_transaction", "max_execution_units_per_transaction"),
    "order": ("max_transaction_bytes", "max_cev1_nesting", "max_signature_work_per_transaction", "max_batch_refs_per_block"),
    "upgrade": ("max_transaction_bytes", "max_cev1_nesting", "max_signature_work_per_transaction", "max_protocol_objects_per_block"),
    "sync": ("max_transaction_bytes", "max_cev1_nesting", "max_signature_work_per_transaction", "max_state_sync_chunk_bytes"),
    "light-client": ("max_transaction_bytes", "max_cev1_nesting", "max_signature_work_per_transaction", "max_light_client_hops_per_bundle"),
    "governance": ("max_transaction_bytes", "max_cev1_nesting", "max_signature_work_per_transaction", "max_operation_scopes"),
    "reserved": ("max_transaction_bytes", "max_cev1_nesting"),
    "order-coordination-settlement": ("max_transaction_bytes", "max_cev1_nesting", "max_signature_work_per_transaction", "max_protocol_objects_per_block"),
}


class GateError(ValueError):
    pass


class DuplicateKey(GateError):
    pass


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise DuplicateKey(f"duplicate JSON key: {key}")
        out[key] = value
    return out


def reject_nonfinite(value: str) -> NoReturn:
    raise GateError(f"non-finite JSON constant: {value}")


def strict_loads(raw: bytes | str, label: str = "JSON") -> Any:
    try:
        text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
        return json.loads(text, object_pairs_hook=reject_duplicates, parse_constant=reject_nonfinite)
    except GateError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as error:
        raise GateError(f"{label}: malformed/trailing JSON: {error}") from error


def canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise GateError(f"cannot canonicalize JSON: {error}") from error


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def exact_bool(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise GateError(f"{label} must be boolean")
    return value


def exact_int(value: Any, label: str) -> int:
    if type(value) is not int:
        raise GateError(f"{label} must be integer (bool/string/float rejected)")
    return value


def exact_string(value: Any, label: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value:
        raise GateError(f"{label} must be a non-empty string")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise GateError(f"{label} has non-canonical value {value!r}")
    return value


def exact_string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list):
        raise GateError(f"{label} must be an array")
    result: list[str] = []
    for index, item in enumerate(value):
        result.append(exact_string(item, f"{label}[{index}]"))
    if len(set(result)) != len(result):
        raise GateError(f"{label} contains duplicate entries")
    return result


def expect_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise GateError(f"{label} keys differ: expected {sorted(expected)!r}, found {sorted(value)!r}")


def safe_path(value: Any, label: str) -> str:
    text = exact_string(value, label)
    path = Path(text)
    if path.is_absolute() or ".." in path.parts or "\\" in text:
        raise GateError(f"{label} must be a safe repository-relative path")
    return text


@dataclass
class Issue:
    code: str
    message: str
    severity: str = "hard"

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message, "severity": self.severity}


@dataclass
class Source:
    role: str
    ref: str
    commit: str
    tree: str
    files: dict[str, dict[str, str]] = field(default_factory=dict)
    projection_drift: list[str] = field(default_factory=list)


@dataclass
class Context:
    root: Path
    issues: list[Issue] = field(default_factory=list)
    a08: Source | None = None
    a09: Source | None = None
    trace_schema: dict[str, str] | None = None
    operations: list[dict[str, Any]] = field(default_factory=list)
    rows: list[dict[str, Any]] = field(default_factory=list)
    limits: dict[str, int | str] = field(default_factory=dict)
    domains: set[str] = field(default_factory=set)
    parser_pair: dict[str, Any] = field(default_factory=dict)

    def issue(self, code: str, message: str, severity: str = "hard") -> None:
        self.issues.append(Issue(code, message, severity))


def git(root: Path, *args: str, text: bool = False) -> bytes | str:
    result = subprocess.run(["git", *args], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise GateError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout.decode("utf-8", "strict").strip() if text else result.stdout


def resolve_ref(root: Path, ref: str) -> str:
    refs = [ref] if ref.startswith("refs/") else [ref, f"refs/remotes/origin/{ref}", f"refs/heads/{ref}"]
    for candidate in refs:
        result = subprocess.run(["git", "rev-parse", "--verify", candidate], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if result.returncode == 0:
            return result.stdout.decode("ascii").strip()
    raise GateError(f"pinned source ref unavailable: {ref}")


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        value = strict_loads(path.read_bytes(), str(path))
    except OSError as error:
        raise GateError(f"cannot read source manifest: {error}") from error
    if not isinstance(value, dict):
        raise GateError("source manifest must be an object")
    expect_keys(value, {"schema", "status", "a08", "a09", "traceability_schema", "artifacts", "policy"}, "source manifest")
    if value["schema"] != MANIFEST_SCHEMA or value["status"] not in {"candidate-non-normative", "upstream-pending"}:
        raise GateError("source manifest schema/status mismatch")
    for role in ("a08", "a09"):
        source = value[role]
        if not isinstance(source, dict):
            raise GateError(f"manifest.{role} must be an object")
        expect_keys(source, {"role", "ref", "commit", "tree", "files"}, f"manifest.{role}")
        if source["role"] != role:
            raise GateError(f"manifest.{role}.role mismatch")
        exact_string(source["ref"], f"manifest.{role}.ref")
        exact_string(source["commit"], f"manifest.{role}.commit", HEX40)
        exact_string(source["tree"], f"manifest.{role}.tree", HEX40)
        if not isinstance(source["files"], dict) or not source["files"]:
            raise GateError(f"manifest.{role}.files must be non-empty")
        for path_name, value_digest in source["files"].items():
            safe_path(path_name, f"manifest.{role}.files path")
            exact_string(value_digest, f"manifest.{role}.files[{path_name}]", HEX64)
    schema = value["traceability_schema"]
    if not isinstance(schema, dict):
        raise GateError("manifest.traceability_schema must be an object")
    expect_keys(schema, {"path", "sha256"}, "manifest.traceability_schema")
    safe_path(schema["path"], "manifest.traceability_schema.path")
    exact_string(schema["sha256"], "manifest.traceability_schema.sha256", HEX64)
    artifacts = value["artifacts"]
    if not isinstance(artifacts, dict):
        raise GateError("manifest.artifacts must be an object")
    expect_keys(artifacts, {"closure", "evidence_index"}, "manifest.artifacts")
    for key, path_name in artifacts.items():
        path_name = safe_path(path_name, f"manifest.artifacts.{key}")
        if not path_name.startswith("docs/evidence/g2.0/"):
            raise GateError(f"manifest.artifacts.{key} must stay under docs/evidence/g2.0")
    policy = value["policy"]
    if not isinstance(policy, dict):
        raise GateError("manifest.policy must be an object")
    expect_keys(policy, {"required_registry_files", "required_a08_files", "required_a09_files"}, "manifest.policy")
    required_registry_files = exact_string_list(policy["required_registry_files"], "policy.required_registry_files")
    required_a08_files = exact_string_list(policy["required_a08_files"], "policy.required_a08_files")
    required_a09_files = exact_string_list(policy["required_a09_files"], "policy.required_a09_files")
    if required_registry_files != list(REGISTRY_FILES):
        raise GateError("manifest registry order mismatch")
    expected_a08 = [str(REGISTRY_REL / name) for name in REGISTRY_FILES]
    expected_a08.extend([str(CATALOG_REL), str(A08_CHECKER_REL)])
    if sorted(required_a08_files) != sorted(expected_a08):
        raise GateError("manifest A08 file set mismatch")
    if set(value["a08"]["files"]) != set(expected_a08):
        raise GateError("manifest A08 pinned digests do not cover the required file set exactly")
    expected_a09 = [str(A09_PARSER_REL), str(A09_GATE_REL)]
    extended_a09 = [*expected_a09, str(A09_MAPPING_REL), str(A09_NEGATIVE_REL), str(CATALOG_REL), str(A09_PLAN_REL)]
    if sorted(required_a09_files) not in (sorted(expected_a09), sorted(extended_a09)):
        raise GateError("manifest A09 file set mismatch")
    if set(value["a09"]["files"]) != set(required_a09_files):
        raise GateError("manifest A09 pinned digests do not cover the required file set exactly")
    return value


def verify_source(root: Path, source_doc: dict[str, Any]) -> Source:
    role = source_doc["role"]
    commit, tree, ref = source_doc["commit"], source_doc["tree"], source_doc["ref"]
    if resolve_ref(root, ref) != commit:
        raise GateError(f"{role} ref does not resolve to pinned commit")
    if git(root, "rev-parse", f"{commit}^{{commit}}", text=True) != commit:
        raise GateError(f"{role} commit identity mismatch")
    if git(root, "rev-parse", f"{commit}^{{tree}}", text=True) != tree:
        raise GateError(f"{role} tree identity mismatch")
    result = Source(role, ref, commit, tree)
    for rel, expected in source_doc["files"].items():
        raw = git(root, "show", f"{commit}:{rel}")
        actual = digest(raw)
        if actual != expected:
            raise GateError(f"{role} raw blob digest mismatch for {rel}")
        blob = git(root, "rev-parse", f"{commit}:{rel}", text=True)
        canonical = ""
        if rel.endswith(".json"):
            canonical = digest(canonical_bytes(strict_loads(raw, f"{role}:{rel}")))
        result.files[rel] = {"blob": blob, "raw_sha256": actual, "canonical_sha256": canonical, "bytes": str(len(raw))}
        local = root / rel
        try:
            if digest(local.read_bytes()) != actual:
                result.projection_drift.append(rel)
        except OSError:
            result.projection_drift.append(f"missing:{rel}")
    return result


def check_clean(root: Path, context: Context) -> None:
    result = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    if result.returncode:
        context.issue("git-status-failed", result.stderr.strip() or "cannot inspect worktree")
    elif result.stdout:
        context.issue("dirty-worktree", result.stdout.strip())


def check_trace_schema(root: Path, manifest: dict[str, Any], context: Context) -> None:
    rel = manifest["traceability_schema"]["path"]
    try:
        raw = (root / rel).read_bytes()
        expected = manifest["traceability_schema"]["sha256"]
        if digest(raw) != expected:
            context.issue("trace-schema-drift", f"expected {expected}, found {digest(raw)}")
        value = strict_loads(raw, rel)
        if not isinstance(value, dict) or value.get("additionalProperties") is not False or not isinstance(value.get("properties"), dict) or not isinstance(value.get("required"), list):
            raise GateError("schema must close properties and required fields")
        required_order = [
            "kind", "name", "body_type", "plane", "status", "enabled", "required_links",
            "schema_hash", "domain_id", "limit_refs", "maximum_bytes", "maximum_nested_items",
            "maximum_signature_work", "static_authority", "nonce_lane", "access_set",
            "implementation_owner", "evidence", "evidence_id", "evidence_status",
        ]
        if value["required"] != required_order:
            raise GateError("schema required-field order/identity mismatch")
        expected_properties = set(required_order) | {"canonical_error"}
        if set(value["properties"]) != expected_properties:
            raise GateError("schema property set mismatch")
        properties = value["properties"]
        if not isinstance(properties["kind"], dict) or properties["kind"].get("type") != "integer":
            raise GateError("schema.kind must be an integer")
        if not isinstance(properties["body_type"], dict) or properties["body_type"].get("type") != ["string", "null"]:
            raise GateError("schema.body_type must preserve explicit string/null typing")
        if not isinstance(properties["enabled"], dict) or properties["enabled"].get("type") != "boolean" or properties["enabled"].get("const") is not False:
            raise GateError("schema.enabled must be a false boolean")
        if not isinstance(properties["required_links"], dict) or properties["required_links"].get("type") != "array":
            raise GateError("schema.required_links must be an array")
        if not isinstance(properties["evidence"], dict) or properties["evidence"].get("type") != "object":
            raise GateError("schema.evidence must be an object")
        if not isinstance(properties["evidence_id"], dict) or not isinstance(properties["evidence_status"], dict):
            raise GateError("schema evidence identity fields are malformed")
        context.trace_schema = {"path": rel, "raw_sha256": digest(raw), "bytes": str(len(raw))}
    except (OSError, GateError) as error:
        context.issue("trace-schema-invalid", str(error))


def validate_registries(documents: dict[str, Any], context: Context) -> None:
    """Validate all six A08 documents with exact types and 30 closed rows."""
    for name, value in documents.items():
        if not isinstance(value, dict) or value.get("status") != "candidate-non-normative":
            context.issue("registry-status", f"{name} is not candidate-non-normative")
    try:
        op = documents["operation-registry-v1.json"]
        expect_keys(op, {"schema", "status", "protocol_version", "slot_count", "global_activation", "operations"}, "operation registry")
        if op["schema"] != "trnm-cev1-operation-registry-v1" or exact_int(op["protocol_version"], "operation.protocol_version") != 1 or exact_int(op["slot_count"], "operation.slot_count") != 30 or exact_bool(op["global_activation"], "operation.global_activation") is not False:
            raise GateError("operation header mismatch")
        rows = op["operations"]
        if not isinstance(rows, list) or len(rows) != 30:
            raise GateError("operation registry must contain exactly 30 rows")
        seen_kinds: set[int] = set(); seen_names: set[str] = set(); seen_bodies: set[str] = set()
        for index, row in enumerate(rows):
            label = f"operation.operations[{index}]"
            if not isinstance(row, dict):
                raise GateError(f"{label} is not an object")
            required = {"kind", "name", "plane", "status", "enabled", "authority", "nonce_lane", "body_type"}
            if set(row) not in (required, required | {"canonical_error"}):
                raise GateError(f"{label} keys are not canonical (body_type is required)")
            if exact_int(row["kind"], f"{label}.kind") != index or row["kind"] in seen_kinds:
                raise GateError(f"{label}.kind is not unique ordered slot {index}")
            seen_kinds.add(row["kind"])
            name = exact_string(row["name"], f"{label}.name")
            body = exact_string(row["body_type"], f"{label}.body_type", BODY_TYPE)
            if name in seen_names or body in seen_bodies:
                raise GateError(f"duplicate operation name/body_type at {label}")
            seen_names.add(name); seen_bodies.add(body)
            plane = exact_string(row["plane"], f"{label}.plane")
            if plane not in PLANES:
                raise GateError(f"unknown operation plane {plane!r}")
            status = exact_string(row["status"], f"{label}.status")
            if status not in {"candidate-assigned", "disabled"}:
                raise GateError(f"unknown operation status {status!r}")
            if exact_bool(row["enabled"], f"{label}.enabled") is not False:
                raise GateError(f"{label}.enabled must remain false")
            exact_string(row["authority"], f"{label}.authority")
            exact_string(row["nonce_lane"], f"{label}.nonce_lane")
            if status == "disabled" and (set(row) != required | {"canonical_error"} or row.get("canonical_error") != "ERR_OPERATION_DISABLED"):
                raise GateError(f"{label} disabled row lacks canonical rejection")
            if status != "disabled" and "canonical_error" in row:
                raise GateError(f"{label} candidate row has canonical_error")
        context.operations = rows
    except (KeyError, TypeError, GateError) as error:
        context.issue("operation-registry-invalid", str(error))

    try:
        domain = documents["domain-registry-v1.json"]
        expect_keys(domain, {"schema", "status", "domains"}, "domain registry")
        if domain["schema"] != "trnm-cev1-domain-registry-v1" or not isinstance(domain["domains"], list) or not domain["domains"]:
            raise GateError("domain header/rows invalid")
        values: set[str] = set()
        for index, row in enumerate(domain["domains"]):
            if not isinstance(row, dict): raise GateError(f"domain[{index}] is not an object")
            expect_keys(row, {"id", "value", "meaning"}, f"domain[{index}]")
            ident = exact_string(row["id"], f"domain[{index}].id", SLUG)
            value = exact_string(row["value"], f"domain[{index}].value")
            exact_string(row["meaning"], f"domain[{index}].meaning")
            if ident in context.domains or value in values: raise GateError(f"duplicate domain at {index}")
            context.domains.add(ident); values.add(value)
            if not value.isascii() or not value.startswith("trnm.poco-ai.") or not value.endswith(".v1"): raise GateError(f"domain[{index}] value shape")
    except (KeyError, TypeError, GateError) as error:
        context.issue("domain-registry-invalid", str(error))

    try:
        limit = documents["limit-registry-v1.json"]
        expect_keys(limit, {"schema", "status", "units", "limits", "note"}, "limit registry")
        if limit["schema"] != "trnm-cev1-limit-registry-v1": raise GateError("limit schema mismatch")
        exact_string(limit["units"], "limits.units"); exact_string(limit["note"], "limits.note")
        if not isinstance(limit["limits"], dict) or not limit["limits"]: raise GateError("limits must be non-empty")
        for name, value in limit["limits"].items():
            exact_string(name, "limit name", LIMIT_NAME)
            if type(value) is int and value > 0: pass
            elif isinstance(value, str) and DECIMAL.fullmatch(value): pass
            else: raise GateError(f"limit {name} must be a positive exact integer/decimal string")
        context.limits = limit["limits"]
    except (KeyError, TypeError, GateError) as error:
        context.issue("limit-registry-invalid", str(error))

    # The remaining three registries are closed structural inputs.  Their
    # dedicated A08 checker supplies deeper catalog/profile semantics.
    structural = {
        "error-registry-v1.json": {"schema", "status", "errors"},
        "object-registry-v1.json": {"schema", "status", "catalog_source", "global_activation", "objects"},
        "verification-profile-registry-v1.json": {"schema", "status", "fallback_allowed", "profiles"},
    }
    for name, expected in structural.items():
        try:
            value = documents[name]
            if not isinstance(value, dict): raise GateError("not an object")
            expect_keys(value, expected, name)
            if name == "error-registry-v1.json":
                seen: set[str] = set()
                if not isinstance(value["errors"], list) or not value["errors"]: raise GateError("errors empty")
                for row in value["errors"]:
                    if not isinstance(row, dict): raise GateError("error row not object")
                    expect_keys(row, {"code", "class", "retryable"}, "error row")
                    code = exact_string(row["code"], "error.code", ERROR_CODE); exact_string(row["class"], "error.class"); exact_bool(row["retryable"], "error.retryable")
                    if code in seen: raise GateError(f"duplicate error {code}")
                    seen.add(code)
                if "ERR_OPERATION_DISABLED" not in seen: raise GateError("disabled error missing")
            elif name == "object-registry-v1.json":
                if exact_bool(value["global_activation"], "object.global_activation") is not False or not isinstance(value["objects"], list) or not value["objects"]: raise GateError("object activation/rows invalid")
                seen = set()
                for row in value["objects"]:
                    if not isinstance(row, dict): raise GateError("object row not object")
                    expect_keys(row, {"id", "plane", "authority", "wire"}, "object row")
                    ident = exact_string(row["id"], "object.id")
                    exact_string(row["plane"], "object.plane"); exact_string(row["authority"], "object.authority"); exact_string(row["wire"], "object.wire")
                    if ident in seen: raise GateError(f"duplicate object {ident}")
                    seen.add(ident)
            else:
                if exact_bool(value["fallback_allowed"], "profile.fallback_allowed") is not False or not isinstance(value["profiles"], list) or not value["profiles"]: raise GateError("profile fallback/rows invalid")
                seen = set()
                for row in value["profiles"]:
                    if not isinstance(row, dict): raise GateError("profile row not object")
                    required = {"id", "class", "state", "globally_enabled", "required_evidence", "result_authority", "settlement_authority"}
                    if set(row) - required - {"objective_settlement_forbidden", "poco_weight_forbidden"} or not required.issubset(row): raise GateError("profile row keys invalid")
                    ident = exact_string(row["id"], "profile.id", SLUG)
                    if ident in seen: raise GateError(f"duplicate profile {ident}")
                    seen.add(ident); exact_string(row["class"], "profile.class"); exact_string(row["state"], "profile.state")
                    if exact_bool(row["globally_enabled"], "profile.globally_enabled") is not False: raise GateError("profile enabled")
                    if not isinstance(row["required_evidence"], list) or not row["required_evidence"] or len(set(row["required_evidence"])) != len(row["required_evidence"]): raise GateError("profile evidence list invalid")
                    for item in row["required_evidence"]: exact_string(item, "profile evidence")
                    exact_bool(row["result_authority"], "profile.result_authority"); exact_bool(row["settlement_authority"], "profile.settlement_authority")
                if "subjective-v1" not in seen: raise GateError("subjective profile missing")
        except (KeyError, TypeError, GateError) as error:
            context.issue(name.replace(".json", "-invalid"), str(error))


def materialize(root: Path, source: Source, destination: Path) -> None:
    for rel in source.files:
        out = destination / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(git(root, "show", f"{source.commit}:{rel}"))


def git_snapshot(
    root: Path,
    source: Source,
    parent: Path,
    related_commits: tuple[str, ...] = (),
) -> Path:
    """Checkout an immutable source commit into a clean temporary Git repo.

    A source-file copy is not sufficient for A09: its evidence builder records
    ``HEAD``/tree and can otherwise accidentally describe the caller's mixed
    worktree.  Fetching the exact commit from the local object database gives
    the parser its own clean Git identity while avoiding any network or
    mutable branch lookup.  The returned path is intentionally ephemeral and
    never becomes part of a committed artifact.
    """
    snapshot = parent / "a09-repo"
    result = subprocess.run(
        ["git", "init", "--quiet", str(snapshot)],
        cwd=parent,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode:
        raise GateError(f"cannot initialise A09 snapshot: {result.stderr.strip()}")
    result = subprocess.run(
        [
            "git",
            "-C",
            str(snapshot),
            "fetch",
            "--quiet",
            "--no-tags",
            "--depth=1",
            str(root),
            source.commit,
        ],
        cwd=parent,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode:
        raise GateError(f"cannot fetch pinned A09 commit: {result.stderr.strip()}")
    for commit in related_commits:
        result = subprocess.run(
            [
                "git",
                "-C",
                str(snapshot),
                "fetch",
                "--quiet",
                "--no-tags",
                "--depth=1",
                str(root),
                commit,
            ],
            cwd=parent,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if result.returncode:
            raise GateError(f"cannot fetch related pinned commit {commit}: {result.stderr.strip()}")
    result = subprocess.run(
        ["git", "-C", str(snapshot), "checkout", "--quiet", "--detach", source.commit],
        cwd=parent,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode:
        raise GateError(f"cannot checkout pinned A09 commit: {result.stderr.strip()}")
    observed_commit = git(snapshot, "rev-parse", "HEAD", text=True)
    observed_tree = git(snapshot, "rev-parse", "HEAD^{tree}", text=True)
    if observed_commit != source.commit or observed_tree != source.tree:
        raise GateError(
            "A09 snapshot identity mismatch: "
            f"expected {source.commit}/{source.tree}, found {observed_commit}/{observed_tree}"
        )
    status = git(snapshot, "status", "--porcelain", text=True)
    if status:
        raise GateError(f"A09 snapshot is unexpectedly dirty: {status!r}")
    return snapshot


def parser_command(
    parser: Path,
    snapshot: Path,
    evidence_path: Path,
    a08: Source,
    a08_checker: Path,
) -> list[str]:
    """Select the CLI contract exposed by the pinned A09 parser.

    The original A09 candidate accepted ``--registry-dir``; the strict replay
    head accepts ``--root`` and source-pin options.  Discovering the advertised
    flags from that exact source keeps old candidates fail-closed without
    silently running a different parser implementation.
    """
    help_result = subprocess.run(
        [sys.executable, str(parser), "--help"],
        cwd=snapshot,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    advertised = help_result.stdout + help_result.stderr
    if help_result.returncode != 0:
        raise GateError(f"A09 parser --help failed: {advertised.strip()}")
    command = [sys.executable, str(parser)]
    if "--root" in advertised:
        command.extend(["--root", str(snapshot)])
        # These options are available on the source-bound A09 head.  Add them
        # only when advertised so the legacy candidate remains a diagnostic
        # (rather than a fabricated pass from ignored arguments).
        if "--a08-source-commit" in advertised:
            command.extend(["--a08-source-commit", a08.commit])
        if "--a08-source-tree" in advertised:
            command.extend(["--a08-source-tree", a08.tree])
        if "--a08-checker" in advertised:
            command.extend(["--a08-checker", str(a08_checker)])
        if "--require-a08-pin" in advertised:
            command.append("--require-a08-pin")
    elif "--registry-dir" in advertised:
        command.extend(["--registry-dir", str(snapshot / REGISTRY_REL)])
    else:
        raise GateError("pinned A09 parser exposes neither --root nor --registry-dir")
    command.extend(["--evidence-out", str(evidence_path)])
    return command


def expected_registry_hashes(root: Path, source: Source) -> dict[str, dict[str, str]]:
    expected: dict[str, dict[str, str]] = {}
    for name in REGISTRY_FILES:
        rel = REGISTRY_REL / name
        raw = git(root, "show", f"{source.commit}:{rel}")
        expected[name] = {
            "path": str(rel),
            "raw_sha256": digest(raw),
            "canonical_sha256": digest(canonical_bytes(strict_loads(raw, f"A08:{name}"))),
        }
    return expected


def a09_registry_hashes_match(evidence: dict[str, Any], expected: dict[str, dict[str, str]]) -> bool:
    """Accept the legacy digest map or the strict A09 v2 input records."""
    legacy = evidence.get("registry_digests")
    if isinstance(legacy, dict):
        return legacy == {name: item["canonical_sha256"] for name, item in expected.items()}

    inputs = evidence.get("inputs")
    records = inputs.get("registries") if isinstance(inputs, dict) else None
    if not isinstance(records, list) or len(records) != len(expected):
        return False
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            return False
        path = record.get("path")
        if not isinstance(path, str) or path in seen:
            return False
        seen.add(path)
        name = Path(path).name
        item = expected.get(name)
        if item is None or path != item["path"]:
            return False
        if record.get("raw_sha256") != item["raw_sha256"] or record.get("canonical_sha256") != item["canonical_sha256"]:
            return False
    return seen == {item["path"] for item in expected.values()}


def valid_negative_evidence(evidence: dict[str, Any]) -> bool:
    rows = evidence.get("negative_cases")
    if not isinstance(rows, list) or not rows:
        return False
    declared = evidence.get("negative_case_count")
    if declared is not None and (type(declared) is not int or declared != len(rows)):
        return False
    if len(rows) < MIN_A09_NEGATIVE_CASES:
        return False
    identifiers: set[str] = set()
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or row.get("result") != "rejected":
            return False
        identifier = row.get("id", row.get("case"))
        if not isinstance(identifier, str) or not identifier or identifier in identifiers:
            return False
        identifiers.add(identifier)
        error = row.get("error")
        if not isinstance(error, str) or not error:
            return False
        # Strict v2 corpus rows bind the target and mutation; reject partially
        # populated records rather than accepting ambiguous diagnostics.
        if "id" in row:
            if not isinstance(row.get("target"), str) or not isinstance(row.get("mutation"), str):
                return False
    if len(identifiers) != len(rows):
        return False
    controls = evidence.get("negative_controls")
    if controls is not None:
        if not isinstance(controls, list) or len(controls) != 1:
            return False
        control_count = evidence.get("negative_control_count")
        if type(control_count) is not int or control_count != len(controls):
            return False
        control = controls[0]
        if (
            not isinstance(control, dict)
            or control.get("id") != "evidence-id-payload-mutation"
            or control.get("result") != "rejected"
            or not isinstance(control.get("expected"), str)
            or not control["expected"]
        ):
            return False
    return True


def run_pair(context: Context) -> None:
    if not context.a08 or not context.a09 or not context.operations:
        context.issue("parser-pair-unavailable", "A08/A09 source snapshot is incomplete", "blocked")
        return
    with tempfile.TemporaryDirectory(prefix="trnm-g20-pair-") as temp:
        pair_root = Path(temp)
        try:
            # Run A08's checker against a materialized exact source projection.
            # A09 is stronger: its evidence builder records Git HEAD/tree, so
            # it must execute inside an independent clean checkout of the
            # pinned A09 commit rather than against the caller's worktree.
            a08_root = pair_root / "a08"
            a08_root.mkdir()
            materialize(context.root, context.a08, a08_root)
            checker = a08_root / A08_CHECKER_REL
            a08 = subprocess.run(
                [sys.executable, str(checker), "--root", str(a08_root)],
                cwd=a08_root,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )

            a09_root = git_snapshot(
                context.root,
                context.a09,
                pair_root,
                related_commits=(context.a08.commit,),
            )
            parser = a09_root / A09_PARSER_REL
            evidence_path = pair_root / "a09-evidence.json"
            pinned_checker_raw = git(context.root, "show", f"{context.a08.commit}:{A08_CHECKER_REL}")
            snapshot_checker = a09_root / A08_CHECKER_REL
            try:
                checker_matches = snapshot_checker.read_bytes() == pinned_checker_raw
            except OSError:
                checker_matches = False
            if not checker_matches:
                context.issue("a09-checker-source-mismatch", "A09 snapshot does not contain the pinned A08 checker", "blocked")
            command = parser_command(
                parser,
                a09_root,
                evidence_path,
                context.a08,
                snapshot_checker,
            )
            a09 = subprocess.run(
                command,
                cwd=a09_root,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            # Exercise the pinned A09 shell gate as a second independent
            # invocation.  It may intentionally use a temporary evidence file;
            # only normalized output is retained in the deterministic artifact.
            a09_gate_script = a09_root / A09_GATE_REL
            a09_gate = subprocess.run(
                ["bash", str(a09_gate_script)],
                cwd=a09_root,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )

            # Tracebacks and shell diagnostics can include the random
            # TemporaryDirectory name.  Normalize it before persisting or
            # hashing evidence so two replays produce byte-identical JSON.
            def stable_output(value: str) -> str:
                normalized = value.replace(str(pair_root), "<snapshot>")
                normalized = normalized.replace(str(a08_root), "<snapshot>/a08")
                normalized = normalized.replace(str(a09_root), "<snapshot>/a09")
                return normalized

            a08_stdout, a08_stderr = stable_output(a08.stdout), stable_output(a08.stderr)
            a09_stdout, a09_stderr = stable_output(a09.stdout), stable_output(a09.stderr)
            gate_stdout, gate_stderr = stable_output(a09_gate.stdout), stable_output(a09_gate.stderr)
            pair: dict[str, Any] = {
                "a08": {"returncode": a08.returncode, "stdout": a08_stdout.strip(), "stderr": a08_stderr.strip(), "derived_evidence_id": "g20-a08-" + digest((context.a08.commit + context.a08.tree + a08_stdout).encode())[:32]},
                "a09": {
                    "returncode": a09.returncode,
                    "stdout": a09_stdout.strip(),
                    "stderr": a09_stderr.strip(),
                    "gate_returncode": a09_gate.returncode,
                    "gate_stdout": gate_stdout.strip(),
                    "gate_stderr": gate_stderr.strip(),
                    "snapshot_commit": git(a09_root, "rev-parse", "HEAD", text=True),
                    "snapshot_tree": git(a09_root, "rev-parse", "HEAD^{tree}", text=True),
                    "snapshot_clean": not bool(git(a09_root, "status", "--porcelain", text=True)),
                    "derived_evidence_id": "g20-a09-" + digest((context.a09.commit + context.a09.tree + a09_stdout).encode())[:32],
                },
                "same_snapshot": True,
            }
            if a08.returncode: context.issue("a08-checker-rejected", a08_stderr.strip() or a08_stdout.strip(), "blocked")
            if a09.returncode: context.issue("a09-parser-rejected", a09_stderr.strip() or a09_stdout.strip(), "blocked")
            if a09_gate.returncode:
                context.issue("a09-gate-rejected", gate_stderr.strip() or gate_stdout.strip(), "blocked")
            if pair["a09"]["snapshot_commit"] != context.a09.commit or pair["a09"]["snapshot_tree"] != context.a09.tree or not pair["a09"]["snapshot_clean"]:
                context.issue("a09-source-evidence-drift", "A09 parser did not execute from the pinned clean commit/tree", "blocked")

            if not evidence_path.is_file():
                context.issue("a09-evidence-missing", "independent parser emitted no evidence object", "blocked")
            else:
                evidence_raw = evidence_path.read_bytes(); evidence = strict_loads(evidence_raw, "A09 evidence")
                pair["a09"]["evidence_sha256"] = digest(evidence_raw); pair["a09"]["evidence"] = evidence
                if not isinstance(evidence, dict):
                    context.issue("a09-evidence-shape", "A09 evidence must be an object", "blocked")
                else:
                    expected = expected_registry_hashes(context.root, context.a08)
                    if not a09_registry_hashes_match(evidence, expected):
                        context.issue("a09-digest-mismatch", "independent parser raw/canonical digests differ from pinned A08 snapshot", "blocked")
                    if not valid_negative_evidence(evidence):
                        context.issue("a09-negative-evidence-incomplete", "all parser mutants need unique IDs, targets, mutations, and rejection errors", "blocked")
                    source = evidence.get("source")
                    if (
                        not isinstance(source, dict)
                        or source.get("commit") != context.a09.commit
                        or source.get("tree") != context.a09.tree
                        or source.get("dirty") is not False
                        or source.get("dirty_paths") != []
                    ):
                        context.issue("a09-evidence-source-mismatch", "A09 evidence source tuple is not the pinned clean snapshot", "blocked")
                    evidence_id = evidence.get("evidence_id")
                    if not isinstance(evidence_id, str) or EVIDENCE_ID.fullmatch(evidence_id) is None:
                        context.issue("a09-evidence-id-missing", "A09 must emit a canonical explicit source-bound evidence_id", "blocked")
                    else:
                        pair["a09"]["evidence_id"] = evidence_id
            context.parser_pair = pair
        except (OSError, GateError, subprocess.SubprocessError) as error:
            context.issue("parser-pair-error", str(error), "blocked")


def build_rows(context: Context) -> None:
    schema_hash = context.trace_schema["raw_sha256"] if context.trace_schema else None
    for op in context.operations:
        kind, plane, status = op.get("kind"), op.get("plane"), op.get("status")
        links = ["W0"] if status == "disabled" else LINKS_BY_PLANE.get(plane, [])
        domain = DOMAIN_BY_PLANE.get(plane)
        if domain not in context.domains: context.issue("domain-reference-missing", f"kind {kind}: {domain!r}", "blocked")
        refs = list(LIMITS_BY_PLANE.get(plane, ()))
        missing = [name for name in refs if name not in context.limits]
        if missing: context.issue("limit-reference-missing", f"kind {kind}: {missing!r}", "blocked")
        row_digest = digest(canonical_bytes({"operation": op, "required_links": links}))
        row = {
            "kind": kind, "name": op.get("name"), "body_type": op.get("body_type"), "plane": plane,
            "status": "disabled" if status == "disabled" else "candidate-assigned", "enabled": False, "required_links": links,
            "schema_hash": schema_hash, "domain_id": domain,
            "limit_refs": {name: context.limits.get(name) for name in refs},
            "maximum_bytes": context.limits.get("max_transaction_bytes"),
            "maximum_nested_items": context.limits.get("max_cev1_nesting"),
            "maximum_signature_work": context.limits.get("max_signature_work_per_transaction"),
            "static_authority": op.get("authority"), "nonce_lane": op.get("nonce_lane"),
            "access_set": None, "implementation_owner": None,
            "evidence": {link: None for link in links},
            "evidence_id": f"g20-row-{int(kind):02d}-{row_digest[:32]}", "evidence_status": "missing",
        }
        if op.get("canonical_error") is not None:
            row["canonical_error"] = op["canonical_error"]
        context.rows.append(row)


def validate_rows(context: Context) -> None:
    """Check the generated closure rows against the strict row contract."""
    if len(context.rows) != 30:
        context.issue("trace-row-count", f"expected 30 rows, found {len(context.rows)}")
        return
    expected_keys = {
        "kind", "name", "body_type", "plane", "status", "enabled", "required_links",
        "schema_hash", "domain_id", "limit_refs", "maximum_bytes", "maximum_nested_items",
        "maximum_signature_work", "static_authority", "nonce_lane", "access_set",
        "implementation_owner", "evidence", "evidence_id", "evidence_status",
    }
    seen_ids: set[str] = set()
    for index, row in enumerate(context.rows):
        label = f"trace.rows[{index}]"
        allowed_keys = expected_keys | ({"canonical_error"} if row.get("status") == "disabled" else set())
        if set(row) != allowed_keys:
            context.issue("trace-row-schema", f"{label} keys are not canonical")
            continue
        if type(row["kind"]) is not int or row["kind"] != index:
            context.issue("trace-row-kind", f"{label}.kind is not ordered slot {index}")
        if not isinstance(row["name"], str) or not row["name"]:
            context.issue("trace-row-name", f"{label}.name is not a non-empty string")
        if not isinstance(row["body_type"], str) or BODY_TYPE.fullmatch(row["body_type"]) is None:
            context.issue("trace-row-body-type", f"{label}.body_type is not canonical")
        if row["enabled"] is not False:
            context.issue("trace-row-enabled", f"{label}.enabled must remain false")
        if row["status"] not in {"candidate-assigned", "disabled"}:
            context.issue("trace-row-status", f"{label}.status is invalid")
        if row["status"] == "disabled":
            source = context.operations[index] if index < len(context.operations) else {}
            if row.get("canonical_error") != "ERR_OPERATION_DISABLED" or source.get("canonical_error") != "ERR_OPERATION_DISABLED" or row["required_links"] != ["W0"]:
                context.issue("trace-row-disabled-boundary", f"{label} disabled row is not a W0 rejection")
        elif "canonical_error" in row:
            context.issue("trace-row-canonical-error", f"{label} candidate row may not carry canonical_error")
        expected_links = ["W0"] if row["status"] == "disabled" else LINKS_BY_PLANE.get(row["plane"], [])
        if row["required_links"] != expected_links or len(set(row["required_links"])) != len(row["required_links"]):
            context.issue("trace-row-links", f"{label}.required_links do not match closed plane policy")
        if not isinstance(row["evidence"], dict) or set(row["evidence"]) != set(row["required_links"]) or any(value is not None for value in row["evidence"].values()):
            context.issue("trace-row-evidence", f"{label}.evidence must be null for every required link")
        evidence_id = row["evidence_id"]
        if not isinstance(evidence_id, str) or EVIDENCE_ID.fullmatch(evidence_id) is None or evidence_id in seen_ids:
            context.issue("trace-row-evidence-id", f"{label}.evidence_id is missing, malformed, or duplicated")
        else:
            seen_ids.add(evidence_id)
        if row["evidence_status"] != "missing":
            context.issue("trace-row-evidence-status", f"{label}.evidence_status must remain missing")


def source_dict(source: Source | None) -> dict[str, Any]:
    if source is None: return {"available": False}
    return {"role": source.role, "ref": source.ref, "commit": source.commit, "tree": source.tree, "files": {k: source.files[k] for k in sorted(source.files)}, "projection_drift": sorted(source.projection_drift), "available": True}


def result_status(context: Context) -> str:
    if any(item.severity == "hard" for item in context.issues): return "FAIL"
    if context.issues or any(row["evidence_status"] != "accepted" for row in context.rows): return "BLOCKED_UPSTREAM"
    return "PASS"


def closure(context: Context, manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": CLOSURE_SCHEMA, "classification": "candidate-non-normative", "status": result_status(context), "g2_0_complete": False,
        "source": {"a08": source_dict(context.a08), "a09": source_dict(context.a09), "traceability_schema": context.trace_schema},
        "parser_pair": context.parser_pair, "rows": context.rows, "known_gaps": [x.as_dict() for x in context.issues],
        "non_claims": {"wire_conformance_complete": False, "rpc_sdk_complete": False, "light_client_complete": False, "node_support": False, "production_candidate": False, "normative_freeze": False},
        "manifest_schema": manifest.get("schema"),
    }


def evidence_index(context: Context, result: dict[str, Any]) -> dict[str, Any]:
    entries = [{"evidence_id": row["evidence_id"], "kind": row["kind"], "required_links": row["required_links"], "status": row["evidence_status"], "accepted": False, "source_commit": context.a08.commit if context.a08 else None, "source_tree": context.a08.tree if context.a08 else None} for row in context.rows]
    for role, source in (("a08", context.a08), ("a09", context.a09)):
        pair = context.parser_pair.get(role, {})
        entries.append({"evidence_id": pair.get("evidence_id") or pair.get("derived_evidence_id"), "kind": role, "required_links": ["W0"], "status": "accepted" if pair.get("evidence_id") else "missing", "accepted": bool(pair.get("evidence_id")), "source_commit": source.commit if source else None, "source_tree": source.tree if source else None})
    return {"schema": EVIDENCE_SCHEMA, "classification": "candidate-non-normative", "status": result["status"], "source": result["source"], "entries": entries, "known_gaps": result["known_gaps"], "g2_0_complete": False}


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(canonical_bytes(value) + b"\n")


def run(root: Path, manifest_path: Path, closure_path: Path, evidence_path: Path, *, clean: bool = True, write: bool = True) -> tuple[int, dict[str, Any], dict[str, Any]]:
    context = Context(root.resolve()); manifest: dict[str, Any] = {}
    if clean: check_clean(context.root, context)
    try: manifest = load_manifest(manifest_path)
    except (GateError, OSError) as error: context.issue("manifest-invalid", str(error))
    if manifest:
        try:
            context.a08 = verify_source(context.root, manifest["a08"]); context.a09 = verify_source(context.root, manifest["a09"])
            for source in (context.a08, context.a09):
                if source and source.projection_drift: context.issue("source-projection-drift", f"{source.role}: {sorted(source.projection_drift)!r}", "blocked")
            check_trace_schema(context.root, manifest, context)
            docs = {name: strict_loads(git(context.root, "show", f"{context.a08.commit}:{REGISTRY_REL / name}"), f"A08:{name}") for name in REGISTRY_FILES} if context.a08 else {}
            validate_registries(docs, context); run_pair(context); build_rows(context); validate_rows(context)
        except (GateError, OSError, subprocess.SubprocessError) as error:
            context.issue("source-validation-failed", str(error))
    result = closure(context, manifest); index = evidence_index(context, result)
    if write:
        try: write_json(closure_path, result); write_json(evidence_path, index)
        except OSError as error: context.issue("artifact-write-failed", str(error)); result = closure(context, manifest); index = evidence_index(context, result)
    return (0 if result["status"] == "PASS" else 1), result, index


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--manifest", type=Path, default=ROOT / "docs/evidence/g2.0/g20-source-manifest-v1.json")
    parser.add_argument("--closure", type=Path, default=ROOT / "docs/evidence/g2.0/g20-w0-w7-closure-v1.json")
    parser.add_argument("--evidence-index", type=Path, default=ROOT / "docs/evidence/g2.0/g20-evidence-index-v1.json")
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--allow-dirty", action="store_true", help="test-only; CI must use clean default")
    args = parser.parse_args(argv)
    code, result, _ = run(args.root, args.manifest, args.closure, args.evidence_index, clean=not args.allow_dirty, write=not args.no_write)
    print(json.dumps({"status": result["status"], "g2_0_complete": False, "known_gaps": len(result["known_gaps"])}, sort_keys=True))
    for item in result["known_gaps"]: print(f"{item['severity']}: {item['code']}: {item['message']}", file=sys.stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
