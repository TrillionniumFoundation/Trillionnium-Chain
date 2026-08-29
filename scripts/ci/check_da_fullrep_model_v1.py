#!/usr/bin/env python3
"""Fail-closed checker for the A11 DA-FULLREP candidate contract.

The checker is intentionally independent of the model's implementation.  It
parses the committed manifest/corpus with duplicate-key and non-finite-number
rejection, runs the model as a subprocess, and validates the returned evidence
envelope without importing the model.  A successful run is candidate evidence
only; it cannot promote G2A or any production/activation truth.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib
from typing import Any, NoReturn


ROOT = Path(__file__).resolve().parents[2]
# A11 replay is pinned to the exact published A10 candidate head.  Keep this
# tuple in lockstep with the manifest and evidence contract; a stale base must
# fail closed rather than silently reusing the old pre-A10 evidence.
BASE_COMMIT = "044224a3a6c9100cd64961ea34a28031bb78a636"
BASE_TREE = "02fb16fd12d2c6387495087e3eff578c2c44100a"
BASE_REF = "refs/heads/feature/chain-a10-g20-traceability-v2-20260829"
MODEL_REL = Path("tools/da-fullrep-model/fullrep_model.py")
CASES_REL = Path("conformance/da/fullrep-v1/cases.json")
MANIFEST_REL = Path("docs/development/packages/trnm-g2a-da-fullrep-v1.toml")
CONTRACT_REL = Path("docs/evidence/g2a-da-fullrep/fullrep-model-contract-v1.json")
PROTOCOL_REL = Path("docs/protocol/poco-ai-native-v1/da/DA_FULLREP_V1.md")
PACKAGE_REL = Path("docs/development/packages/TRNM_G2A_DA_FULLREP_V1.md")
EVIDENCE_README_REL = Path("docs/evidence/g2a-da-fullrep/README.md")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
FULLREP_MODE = "DA-FULLREP-V1"


class CheckError(ValueError):
    """A malformed candidate artifact or unexpectedly accepted mutant."""


def fail(message: str) -> NoReturn:
    raise CheckError(message)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_constant(value: str) -> NoReturn:
    fail(f"non-finite JSON constant is forbidden: {value}")


def read_json(path: Path) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_constant,
        )
    except CheckError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        fail(f"cannot parse {path}: {exc}")


def read_toml(path: Path) -> dict[str, Any]:
    try:
        value = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, TypeError, ValueError) as exc:
        fail(f"cannot parse {path}: {exc}")
    if type(value) is not dict:
        fail(f"{path} must contain a TOML table")
    return value


def exact_string(value: Any, label: str, *, pattern: re.Pattern[str] | None = None) -> str:
    if type(value) is not str or not value:
        fail(f"{label} must be a non-empty string")
    if pattern is not None and pattern.fullmatch(value) is None:
        fail(f"{label} has an invalid format")
    return value


def exact_bool(value: Any, label: str) -> bool:
    if type(value) is not bool:
        fail(f"{label} must be a boolean")
    return value


def exact_int(value: Any, label: str, *, minimum: int | None = None) -> int:
    if type(value) is not int:
        fail(f"{label} must be an integer")
    if minimum is not None and value < minimum:
        fail(f"{label} must be >= {minimum}")
    return value


def exact_list(value: Any, label: str) -> list[Any]:
    if type(value) is not list:
        fail(f"{label} must be an array")
    return value


def exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        fail(f"{label} keys differ: expected {sorted(expected)!r}, found {sorted(actual)!r}")


def check_clean_snapshot(root: Path) -> None:
    git_dir = root / ".git"
    if not git_dir.exists():
        return
    result = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        fail(f"cannot inspect worktree status: {result.stderr.strip()}")
    if result.stdout:
        fail("clean snapshot required; tracked or untracked worktree changes found")


def check_manifest(root: Path) -> dict[str, Any]:
    manifest = read_toml(root / MANIFEST_REL)
    exact_keys(
        manifest,
        {
            "schema_version",
            "package_id",
            "status",
            "repository",
            "gate",
            "owner_agent",
            "base_ref",
            "base_commit",
            "base_tree",
            "source_branch",
            "planned_branch",
            "plan_path",
            "assessed_plan_commit",
            "assessed_plan_tree",
            "latest_live_plan_commit",
            "latest_live_plan_tree",
            "parent_package",
            "evidence_contract",
            "production_candidate",
            "production_consensus_activation",
            "g2a_exit",
            "scope",
            "capabilities",
            "vectors",
            "files",
            "interface_requests",
            "truth",
            "upstream_blockers",
            "handoff",
        },
        "manifest",
    )
    if exact_int(manifest["schema_version"], "manifest.schema_version") != 1:
        fail("manifest schema version must be 1")
    for key, expected in {
        "package_id": "G2A_DA_FULLREP_V1",
        "status": "blocked-upstream",
        "repository": "TrillionniumFoundation/Trillionnium-Chain",
        "gate": "G2A",
        "owner_agent": "A11",
        "base_ref": BASE_REF,
        "base_commit": BASE_COMMIT,
        "base_tree": BASE_TREE,
        "evidence_contract": str(CONTRACT_REL),
    }.items():
        if exact_string(manifest[key], f"manifest.{key}") != expected:
            fail(f"manifest.{key} must be {expected!r}")
    for key in ("production_candidate", "production_consensus_activation", "g2a_exit"):
        if exact_bool(manifest[key], f"manifest.{key}"):
            fail(f"manifest.{key} must remain false")

    scope = manifest["scope"]
    if type(scope) is not dict:
        fail("manifest.scope must be a table")
    exact_keys(
        scope,
        {"scope", "authority", "classification", "data_scope", "owned_surface", "production_capability_constructors", "truth_flags_changed"},
        "manifest.scope",
    )
    if scope["scope"] != "independent-model-and-contract" or scope["authority"] != "candidate" or scope["classification"] != "candidate-non-normative":
        fail("manifest scope/authority/classification drift")
    for key in ("production_capability_constructors", "truth_flags_changed"):
        if exact_bool(scope[key], f"manifest.scope.{key}"):
            fail(f"manifest.scope.{key} must remain false")

    capabilities = manifest["capabilities"]
    if type(capabilities) is not dict:
        fail("manifest.capabilities must be a table")
    expected_capabilities = {
        "durable_before_attest": True,
        "immutable_manifest_binding": True,
        "strict_namespace_binding": True,
        "strict_complete_range": True,
        "authenticated_request_response_model": True,
        "repair_requires_complete_matching_source": True,
        "withholding_requires_certified_provider": True,
        "retention_and_challenge_holds": True,
        "node_permit_required_for_gc": True,
        "sampling_profile_rejected": True,
        "production_p2p": False,
        "production_signer_journal": False,
        "whole_node_cas": False,
        "order_vote_authority": False,
    }
    exact_keys(capabilities, set(expected_capabilities), "manifest.capabilities")
    for key, expected in expected_capabilities.items():
        if exact_bool(capabilities[key], f"manifest.capabilities.{key}") is not expected:
            fail(f"manifest.capabilities.{key} drift")

    vectors = manifest["vectors"]
    if type(vectors) is not dict:
        fail("manifest.vectors must be a table")
    exact_keys(
        vectors,
        {"positive_count", "negative_count", "strict_negative_count", "authenticated_negative_count", "fault_count", "retained_mutant_count", "profile"},
        "manifest.vectors",
    )
    expected_vectors = {
        "positive_count": 5,
        "negative_count": 6,
        "strict_negative_count": 10,
        "authenticated_negative_count": 2,
        "fault_count": 7,
        "retained_mutant_count": 10,
        "profile": "DA-FULLREP-V1",
    }
    for key, expected in expected_vectors.items():
        value = vectors[key]
        if type(expected) is int:
            if exact_int(value, f"manifest.vectors.{key}") != expected:
                fail(f"manifest.vectors.{key} drift")
        elif exact_string(value, f"manifest.vectors.{key}") != expected:
            fail(f"manifest.vectors.{key} drift")

    files = manifest["files"]
    if type(files) is not dict:
        fail("manifest.files must be a table")
    for key, expected in {
        "model": str(MODEL_REL),
        "focused_gate": "scripts/ci/check_da_fullrep_model_v1.sh",
        "focused_checker": str(Path("scripts/ci/check_da_fullrep_model_v1.py")),
        "conformance_cases": str(CASES_REL),
        "protocol_contract": str(PROTOCOL_REL),
        "evidence_contract": str(CONTRACT_REL),
        "evidence_readme": str(EVIDENCE_README_REL),
        "package_document": str(PACKAGE_REL),
    }.items():
        if exact_string(files.get(key), f"manifest.files.{key}") != expected:
            fail(f"manifest.files.{key} must be {expected!r}")

    truth = manifest["truth"]
    if type(truth) is not dict:
        fail("manifest.truth must be a table")
    for key in (
        "production_candidate",
        "production_consensus_activation",
        "g2a_exit",
        "authenticated_network",
        "artifact_evidence_authority",
        "order_vote_authority",
        "whole_node_gc_authority",
        "data_availability_sampling_active",
    ):
        if exact_bool(truth.get(key), f"manifest.truth.{key}"):
            fail(f"manifest.truth.{key} must remain false")
    blockers = exact_list(manifest["upstream_blockers"], "manifest.upstream_blockers")
    if len(blockers) < 4 or any(type(item) is not str or not item for item in blockers):
        fail("manifest.upstream_blockers must retain typed blockers")
    return manifest


def check_contract(root: Path) -> dict[str, Any]:
    contract = read_json(root / CONTRACT_REL)
    if type(contract) is not dict:
        fail("evidence contract must be an object")
    exact_keys(
        contract,
        {
            "schema",
            "schema_version",
            "package_id",
            "status",
            "scope",
            "authority",
            "classification",
            "data_scope",
            "candidate_only",
            "production",
            "production_candidate",
            "production_consensus_activation",
            "g2a_exit",
            "base",
            "plan",
            "entrypoint",
            "vectors",
            "required_fields",
            "required_invariants",
            "gate_requirements",
            "capabilities",
            "upstream_blockers",
            "non_claims",
        },
        "evidence contract",
    )
    if contract["schema"] != "trnm-g2a-da-fullrep-model-evidence-contract-v1" or contract["schema_version"] != 1:
        fail("evidence contract schema drift")
    for key, expected in {
        "package_id": "G2A_DA_FULLREP_V1",
        "status": "BLOCKED_UPSTREAM",
        "scope": "independent-model-and-contract",
        "authority": "candidate",
        "classification": "candidate-non-normative",
        "data_scope": "synthetic-local-full-replication",
    }.items():
        if contract[key] != expected:
            fail(f"evidence contract {key} drift")
    for key in ("candidate_only", "production", "production_candidate", "production_consensus_activation", "g2a_exit"):
        if contract[key] is not (key == "candidate_only"):
            fail(f"evidence contract {key} has unsafe truth")
    base = contract["base"]
    if type(base) is not dict or base != {"ref": BASE_REF, "commit": BASE_COMMIT, "tree": BASE_TREE}:
        fail("evidence contract base tuple drift")
    vectors = contract["vectors"]
    if type(vectors) is not dict:
        fail("evidence contract vectors must be an object")
    for key, expected in {
        "positive_count": 5,
        "negative_count": 6,
        "strict_negative_count": 10,
        "authenticated_negative_count": 2,
        "fault_count": 7,
        "retained_mutant_count": 10,
    }.items():
        if vectors.get(key) != expected:
            fail(f"evidence contract vectors.{key} drift")
    return contract


def check_cases(root: Path) -> dict[str, Any]:
    cases = read_json(root / CASES_REL)
    if type(cases) is not dict:
        fail("conformance cases must be an object")
    exact_keys(
        cases,
        {
            "schema",
            "schema_version",
            "package_id",
            "status",
            "profile",
            "global_activation",
            "positive",
            "negative",
            "strict_negative",
            "authenticated_negative",
            "fault_matrix",
            "required_invariants",
            "non_claims",
        },
        "conformance cases",
    )
    if cases["schema"] != "trnm-da-fullrep-conformance-cases-v1" or cases["schema_version"] != 1:
        fail("conformance case schema drift")
    if cases["package_id"] != "G2A_DA_FULLREP_V1" or cases["status"] != "candidate-non-normative" or cases["profile"] != FULLREP_MODE:
        fail("conformance case identity/profile drift")
    if cases["global_activation"] is not False:
        fail("conformance cases cannot activate globally")
    for key, count in (("positive", 5), ("negative", 6), ("strict_negative", 10), ("authenticated_negative", 2), ("fault_matrix", 7)):
        values = exact_list(cases[key], f"conformance.{key}")
        if len(values) != count:
            fail(f"conformance.{key} count drift")
        if key in {"positive", "negative"} and any(type(item) is not str or not item for item in values):
            fail(f"conformance.{key} entries must be non-empty strings")
    for index, item in enumerate(cases["strict_negative"]):
        if type(item) is not dict:
            fail(f"strict negative {index} must be an object")
        exact_keys(item, {"id", "mutation", "expected_error"}, f"strict negative {index}")
        for key in ("id", "mutation", "expected_error"):
            exact_string(item[key], f"strict negative {index}.{key}")
    for index, item in enumerate(cases["authenticated_negative"]):
        if type(item) is not dict:
            fail(f"authenticated negative {index} must be an object")
        exact_keys(item, {"id", "mutation", "expected_error"}, f"authenticated negative {index}")
        for key in ("id", "mutation", "expected_error"):
            exact_string(item[key], f"authenticated negative {index}.{key}")
    for index, item in enumerate(cases["fault_matrix"]):
        if type(item) is not dict:
            fail(f"fault case {index} must be an object")
        exact_keys(item, {"id", "expected"}, f"fault case {index}")
        exact_string(item["id"], f"fault case {index}.id")
        if item["expected"] != "reject":
            fail(f"fault case {index} must be reject-only")
    for key in ("required_invariants", "non_claims"):
        values = exact_list(cases[key], f"conformance.{key}")
        if not values or any(type(item) is not str or not item for item in values):
            fail(f"conformance.{key} must be non-empty strings")
    if "da-das-disabled" not in cases["required_invariants"]:
        fail("DA-DAS disabled invariant is missing")
    return cases


def model_auth_tag(envelope: dict[str, Any], key: bytes) -> str:
    encoded = json.dumps(envelope, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    return hmac.new(key, b"trnm.da-fullrep.auth-envelope.v1\x00" + encoded, hashlib.sha256).hexdigest()


def object_digest(namespace: str, payload: bytes) -> str:
    return hashlib.sha256(
        b"trnm.da-fullrep.object.v1\x00"
        + namespace.encode("ascii")
        + len(payload).to_bytes(8, "big")
        + payload
    ).hexdigest()


def check_model_source(root: Path) -> None:
    path = root / MODEL_REL
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeError, SyntaxError) as exc:
        fail(f"model source cannot be parsed: {exc}")
    allowed = {"argparse", "dataclasses", "hashlib", "hmac", "json", "re", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = {alias.name.split(".", 1)[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            names = {node.module.split(".", 1)[0]} if node.module else set()
        else:
            continue
        if not names.issubset(allowed | {"__future__"}):
            fail(f"model imports non-stdlib/undeclared module: {sorted(names - allowed)!r}")


def check_model_evidence(root: Path, cases: dict[str, Any]) -> dict[str, Any]:
    model = root / MODEL_REL
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(
        [sys.executable, "-B", str(model), "--self-test"],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        fail(f"model self-test failed: {(result.stdout + result.stderr).strip()}")
    if result.stderr:
        fail(f"model self-test wrote stderr: {result.stderr.strip()}")
    evidence = read_json_from_text(result.stdout, "model evidence")
    expected_keys = {
        "schema",
        "positive",
        "negative",
        "strict_negative",
        "authenticated_negative",
        "withholding",
        "certificate",
        "authenticated_response",
        "candidate_only",
        "network_authority",
    }
    exact_keys(evidence, expected_keys, "model evidence")
    if evidence["schema"] != "trnm-da-fullrep-model-evidence-v1" or evidence["positive"] != 5:
        fail("model evidence schema/positive count drift")
    negative = exact_list(evidence["negative"], "model evidence.negative")
    if len(negative) != 6:
        fail("model evidence negative count drift")
    strict_negative = exact_list(evidence["strict_negative"], "model evidence.strict_negative")
    if len(strict_negative) != 10:
        fail("model evidence strict negative count drift")
    authenticated_negative = exact_list(evidence["authenticated_negative"], "model evidence.authenticated_negative")
    if len(authenticated_negative) != 2:
        fail("model evidence authenticated negative count drift")
    expected_compat = {
        "attest-before-durable",
        "cross-namespace",
        "duplicate-provider",
        "sampling-disabled",
        "gc-with-hold",
        "gc-without-node-permit",
    }
    if {item.get("case") for item in negative if type(item) is dict} != expected_compat:
        fail("model compatibility negative IDs drift")
    expected_strict = {
        item["id"].removeprefix("N").split("-", 1)[1]
        for item in cases["strict_negative"]
    }
    actual_strict = {item.get("case") for item in strict_negative if type(item) is dict}
    if actual_strict != expected_strict:
        fail("model strict negative IDs drift")
    expected_authenticated = {
        item["id"].removeprefix("N").split("-", 1)[1]
        for item in cases["authenticated_negative"]
    }
    actual_authenticated = {item.get("case") for item in authenticated_negative if type(item) is dict}
    if actual_authenticated != expected_authenticated:
        fail("model authenticated negative IDs drift")
    for item in negative + strict_negative + authenticated_negative:
        if type(item) is not dict or type(item.get("case")) is not str or type(item.get("error")) is not str:
            fail("model negative entry is not typed")
    if evidence["candidate_only"] is not True or evidence["network_authority"] is not False:
        fail("model evidence carries unsafe authority flags")

    certificate = evidence["certificate"]
    if type(certificate) is not dict:
        fail("certificate evidence must be an object")
    exact_keys(certificate, {"certificate_id", "statement", "providers", "threshold", "mode"}, "certificate")
    cert_id = exact_string(certificate["certificate_id"], "certificate.certificate_id", pattern=HEX64)
    statement = exact_list(certificate["statement"], "certificate.statement")
    if len(statement) != 6:
        fail("certificate statement must bind manifest checksum")
    namespace = statement[0]
    object_id = statement[1]
    length = statement[2]
    retention_until = statement[3]
    mode = statement[4]
    manifest_checksum = statement[5]
    if namespace not in {"transaction-batch", "artifact-evidence"} or type(object_id) is not str or HEX64.fullmatch(object_id) is None:
        fail("certificate identity is malformed")
    if type(length) is not int or length <= 0 or type(retention_until) is not int or retention_until <= 0 or mode != FULLREP_MODE or HEX64.fullmatch(manifest_checksum) is None:
        fail("certificate statement bounds/mode are malformed")
    providers = exact_list(certificate["providers"], "certificate.providers")
    if not providers or any(type(provider) is not str or not provider for provider in providers) or len(providers) != len(set(providers)):
        fail("certificate providers are not unique typed IDs")
    if exact_int(certificate["threshold"], "certificate.threshold", minimum=1) > len(providers):
        fail("certificate threshold exceeds provider count")
    if certificate["mode"] != FULLREP_MODE:
        fail("certificate mode is not full replication")
    expected_cert_id = hashlib.sha256(
        b"trnm.da-fullrep.certificate.v1\x00"
        + json.dumps(
            {"statement": statement, "providers": providers, "threshold": certificate["threshold"]},
            separators=(",", ":"),
        ).encode("ascii")
    ).hexdigest()
    if cert_id != expected_cert_id:
        fail("certificate ID does not bind its statement/providers/threshold")

    withholding = evidence["withholding"]
    if type(withholding) is not dict:
        fail("withholding evidence must be an object")
    exact_keys(withholding, {"provider", "namespace", "object_id", "certificate_id", "request_nonce", "outcome"}, "withholding")
    if withholding["provider"] not in providers or withholding["certificate_id"] != cert_id or withholding["namespace"] != namespace or withholding["object_id"] != object_id or withholding["outcome"] != "withheld":
        fail("withholding is not bound to the certified provider/statement")

    response = evidence["authenticated_response"]
    if type(response) is not dict:
        fail("authenticated response must be an object")
    exact_keys(
        response,
        {
            "provider",
            "requester_id",
            "namespace",
            "object_id",
            "request_nonce",
            "first_byte",
            "byte_count",
            "response_height",
            "payload_digest",
            "payload",
            "request_signature",
            "response_signature",
            "mode",
        },
        "authenticated response",
    )
    if response["provider"] not in providers or response["namespace"] != namespace or response["object_id"] != object_id or response["mode"] != FULLREP_MODE or response["first_byte"] != 0:
        fail("authenticated response identity/range binding drift")
    payload = response["payload"].encode("utf-8", errors="surrogateescape") if type(response["payload"]) is str else b""
    if not payload or response["byte_count"] != len(payload) or response["byte_count"] != length or response["payload_digest"] != object_digest(namespace, payload):
        fail("authenticated response is not complete digest-matching bytes")
    request_unsigned = {
        "requester_id": response["requester_id"],
        "namespace": response["namespace"],
        "object_id": response["object_id"],
        "first_byte": response["first_byte"],
        "byte_count": response["byte_count"],
        "request_nonce": response["request_nonce"],
        "request_height": 10,
        "expiry_height": 20,
    }
    if response["request_signature"] != model_auth_tag(request_unsigned, b"requester-key-v1"):
        fail("request authentication tag does not verify")
    response_unsigned = {
        "provider": response["provider"],
        "requester_id": response["requester_id"],
        "namespace": response["namespace"],
        "object_id": response["object_id"],
        "request_nonce": response["request_nonce"],
        "first_byte": response["first_byte"],
        "byte_count": response["byte_count"],
        "response_height": response["response_height"],
        "payload_digest": response["payload_digest"],
    }
    if response["response_signature"] != model_auth_tag(response_unsigned, b"responder-key-p4-v1"):
        fail("response authentication tag does not verify")
    return evidence


def read_json_from_text(raw: str, label: str) -> Any:
    try:
        return json.loads(raw, object_pairs_hook=reject_duplicate_keys, parse_constant=reject_constant)
    except CheckError:
        raise
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        fail(f"cannot parse {label}: {exc}")


def check_text_contracts(root: Path) -> None:
    protocol = (root / PROTOCOL_REL).read_text(encoding="utf-8")
    package = (root / PACKAGE_REL).read_text(encoding="utf-8")
    readme = (root / EVIDENCE_README_REL).read_text(encoding="utf-8")
    required_protocol = (
        "DA-FULLREP-V1",
        "DA-DAS-V1",
        "ManifestDurable",
        "incomplete-range",
        "production Ed25519 signer",
        "whole-node CAS",
    )
    if any(token not in protocol for token in required_protocol):
        fail("DA protocol contract is missing a required fail-closed/boundary statement")
    required_package = (
        "BLOCKED_UPSTREAM",
        "base_commit = " + BASE_COMMIT,
        "positive cases, six compatibility negatives, ten strict binding/type negatives",
        "g2a_exit=false",
        "production_candidate=false",
    )
    if any(token not in package for token in required_package):
        fail("A11 package document is missing exact source/count/truth evidence")
    if "clean-snapshot gate" not in readme or "candidate-only" not in readme or "DA-DAS-V1" not in protocol:
        fail("A11 evidence README is missing clean-snapshot/candidate boundary")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        check_clean_snapshot(root)
        check_manifest(root)
        check_contract(root)
        cases = check_cases(root)
        check_model_source(root)
        check_text_contracts(root)
        check_model_evidence(root, cases)
    except CheckError as exc:
        print(f"DA-FULLREP-V1 candidate: FAIL: {exc}", file=sys.stderr)
        return 1
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"DA-FULLREP-V1 candidate: FAIL: {exc}", file=sys.stderr)
        return 1
    print("DA-FULLREP-V1 candidate: ok vectors=5/6/10+2auth faults=7 clean-snapshot=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
