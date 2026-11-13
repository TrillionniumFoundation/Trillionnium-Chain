#!/usr/bin/env python3
"""Read-only root V2-V5 source and shared-hash inventory; never qualification.

This fixed review schema records six authority roles and declared source bytes.
It has no theorem verifier, query-to-error calculator, telemetry-to-adversary
conversion, deployment authority, or promotion switch. Numeric adversary caps
and failure bounds are deliberately unsupported. Local refusal limits remain
operational limits, including after key rotation, restart or recovery.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import sys

from pq_lifetime_budget import BudgetError, strict_json
from pq_source_reader import SourceReadError, read_regular

SCHEMA = "trnm-pq-root-dependency-register-v3"
RESULT_SCHEMA = "trnm-pq-root-dependency-register-result-v3"
DEFAULT_MANIFEST = "config/pon/pq-root-dependency-register-v3.json"
REVIEW_BASE = '975af9eb4a7f15b405de602552fa05021a176c11'
MAX_BYTES = 1024 * 1024
# Frozen after review of all declared files. No runtime regeneration is allowed.
REVIEWED_SOURCE_SNAPSHOT_SHA256 = '8cfc6a3d9a0347cb8bd7e6c41f5286523d85bba48b3b392922ad8aae8c8d2435'

PY = "formal/pon-nakamoto-v1/"
POLICY = PY + "pq_root_recovery_policy_v1.py"
SIGNATURES = PY + "pq_root_recovery_signatures_v2.py"
JOURNAL = PY + "pq_root_recovery_journal_v2.py"
PROVIDER = PY + "pq_root_effect_readback_v2.py"
BACKEND = PY + "pq_openssl_backend.py"
BUDGET = PY + "pq_operation_budget.py"
CRATES = "trillionnium/crates/"
CRYPTO = CRATES + "trnm-crypto-primitives/"
RELEASE = CRATES + "trnm-release-bundle/"
NODE = CRATES + "trnm-pon-node/"
NATIVE_CRYPTO = CRYPTO + "src/pq_root_v3.rs"
NATIVE_ML_ADAPTER = CRYPTO + "src/pq_candidate.rs"
NATIVE_CRYPTO_PROFILE = CRATES + "trnm-protocol/src/crypto_profile.rs"
NATIVE_POLICY = RELEASE + "src/root_recovery_v3.rs"
NATIVE_OWNER = NODE + "src/root_recovery_v3.rs"
NATIVE_ANCHOR = NODE + "src/root_recovery_v3/anchor.rs"
NATIVE_STORAGE = NODE + "src/root_recovery_v3/storage.rs"
NATIVE_FLOOR = NODE + "src/root_recovery_v3/recovery_floor.rs"
NATIVE_PROVIDER = NODE + "src/root_recovery_v3/effect_readback_v4.rs"
NATIVE_WITNESS = NODE + "src/root_recovery_v3/witnessed_v5.rs"
NATIVE_WITNESS_DURABLE = NODE + "src/root_recovery_v3/witnessed_v5/durable.rs"
NATIVE_WITNESS_RECEIPTS = NODE + "src/root_recovery_v3/witnessed_v5/durable/receipts.rs"
NATIVE_WITNESS_PROVIDER = NODE + "src/root_recovery_v3/witnessed_v5/provider_readback.rs"
BASE_ROLES = ("root-approval", "successor-possession", "anchor-writer",
              "anchor-response", "effect-provider")
ROLES = BASE_ROLES + ("witness-response",)
SUITES = ("ML-DSA-87", "SLH-DSA-SHA2-256s")
ACTIONS = ("normal", "rotate", "revoke", "recover", "policy-change")
ROLE_ACTIONS = {
    "root-approval": list(ACTIONS),
    "successor-possession": ["rotate", "recover", "policy-change"],
    "anchor-writer": ["fresh-read", "compare-and-swap", "v5-witness-fresh-read",
                      "v5-witness-compare-and-swap"],
    "anchor-response": ["fresh-read", "compare-and-swap"],
    "effect-provider": ["fresh-outcome-readback-at-exact-orphan-epoch"],
    "witness-response": ["v5-fresh-read", "v5-exact-successor-acknowledgement"],
}
DOMAINS = ("signature", "commitment", "proof", "ledger", "transport",
           "recovery", "release", "application")
QUERY_COVERAGE = ("online", "offline", "preprocessing", "failed", "cancelled",
                  "unpublished", "recursive", "helpers", "shared-role",
                  "all-key-epochs", "surviving-authority-after-retirement")


class RegisterError(ValueError):
    """A changed, ambiguous or overclaiming register must fail closed."""


def require(ok, message):
    if not ok:
        raise RegisterError(message)


def fields(value, names, where):
    require(type(value) is dict and set(value) == set(names),
            "unexpected or missing fields: " + where)


def exact(value, expected, where):
    """Compare the frozen grammar without bool/int aliasing or open fields."""
    require(type(value) is type(expected), "wrong type: " + where)
    if type(expected) is dict:
        fields(value, expected, where)
        for key, item in expected.items():
            exact(value[key], item, where + "." + key)
    elif type(expected) is list:
        require(len(value) == len(expected), "wrong list size: " + where)
        for index, item in enumerate(expected):
            exact(value[index], item, where + "." + str(index))
    else:
        require(value == expected, "changed frozen contract: " + where)


def quorum(required):
    return {"combiner": "AND", "families": {
        suite: {"required": required, "roster_size": 3} for suite in SUITES}}


def implementation(paths, validity):
    return {"source_paths": sorted(paths), "status": "source-candidate-only",
            "validity_contract": validity, "production_qualified": False}


EPOCH_SCOPE = {
    "coverage": ["initial", "active", "successor", "retired", "recovered"],
    "total_keys": None, "total_rosters": None, "total_epochs": None,
    "maximum_signatures": None, "maximum_verification_attempts": None,
    "status": "unknown-lifetime-population",
    "reset_after_rotation": False, "reset_after_recovery": False,
    "reset_after_restart": False,
}

ROLE_CONTRACT = {}
for _role in BASE_ROLES:
    _python_sources = [POLICY, SIGNATURES, BACKEND, BUDGET]
    if _role in ("anchor-writer", "anchor-response"):
        _python_sources.append(JOURNAL)
    if _role == "effect-provider":
        _python_sources.extend((PROVIDER, JOURNAL))
    _is_root = _role in ("root-approval", "successor-possession")
    _python_validity = ("owner-height-inclusive-and-original-monotonic-budget"
                        if _is_root else "original-monotonic-budget-and-fresh-request")
    _native = implementation(
        [NATIVE_CRYPTO, NATIVE_ML_ADAPTER, NATIVE_CRYPTO_PROFILE, NATIVE_POLICY, NATIVE_OWNER,
         NATIVE_ANCHOR, NATIVE_STORAGE],
        "unix-seconds-expiry-exclusive-v3" if _is_root else "native-v3-fresh-request")
    if _role == "effect-provider":
        _native = {"source_paths": [], "status": "not-wired-in-native-v3",
                   "validity_contract": None, "production_qualified": False}
    ROLE_CONTRACT[_role] = {
        "approval_policy": quorum(3 if _role == "successor-possession" else 2),
        "action_coverage": ROLE_ACTIONS[_role],
        "epoch_scope": copy.deepcopy(EPOCH_SCOPE),
        "implementations": {
            "python-v2": implementation(_python_sources, _python_validity),
            "rust-v3": _native,
        },
        "actual_lifetime_failure_bound": None,
        "independent_custody_verified": False,
    }
    if _role == "effect-provider":
        ROLE_CONTRACT[_role]["implementations"]["rust-v4-readback"] = implementation(
            [NATIVE_CRYPTO, NATIVE_ML_ADAPTER, NATIVE_CRYPTO_PROFILE, NATIVE_POLICY,
             NATIVE_OWNER, NATIVE_ANCHOR, NATIVE_STORAGE, NATIVE_FLOOR, NATIVE_PROVIDER],
            "historical-operation-fresh-readback-only-no-effect-entry")

for _role in ROLES[:4]:
    ROLE_CONTRACT[_role]["implementations"]["rust-v5-witnessed-owner"] = implementation(
        [NATIVE_CRYPTO, NATIVE_ML_ADAPTER, NATIVE_CRYPTO_PROFILE, NATIVE_POLICY,
         NATIVE_OWNER, NATIVE_ANCHOR, NATIVE_STORAGE, NATIVE_FLOOR, NATIVE_WITNESS],
        "fresh-witness-and-exact-ack-required-under-original-budget-no-effect-entry")
ROLE_CONTRACT["witness-response"] = {
    "approval_policy": quorum(2),
    "action_coverage": ROLE_ACTIONS["witness-response"],
    "epoch_scope": copy.deepcopy(EPOCH_SCOPE),
    "implementations": {
        "rust-v5-witnessed-owner": implementation(
            [NATIVE_CRYPTO, NATIVE_ML_ADAPTER, NATIVE_CRYPTO_PROFILE, NATIVE_OWNER,
             NATIVE_WITNESS],
            "complete-fresh-request-and-exact-head-bound-dual-quorum-receipt"),
    },
    "actual_lifetime_failure_bound": None,
    "independent_custody_verified": False,
}


for _role in ("anchor-writer", "witness-response"):
    ROLE_CONTRACT[_role]["implementations"]["rust-v5-durable-register"] = implementation(
        [NATIVE_CRYPTO, NATIVE_ML_ADAPTER, NATIVE_CRYPTO_PROFILE, NATIVE_OWNER,
         NATIVE_WITNESS, NATIVE_WITNESS_DURABLE],
        "typed-v5-authenticated-sqlite-cas-durable-before-ack-live-session-retries-only-exact-external-reopen-pin-no-daemon")

for _role in ("anchor-writer", "witness-response"):
    ROLE_CONTRACT[_role]["implementations"]["rust-v6-receipted-register"] = implementation(
        [NATIVE_CRYPTO, NATIVE_ML_ADAPTER, NATIVE_CRYPTO_PROFILE, NATIVE_OWNER,
         NATIVE_WITNESS, NATIVE_WITNESS_DURABLE, NATIVE_WITNESS_RECEIPTS],
        "same-sqlite-original-signed-exchange-durable-before-return-external-head-count-digest-pin-no-new-authority-no-daemon")

ROLE_CONTRACT["effect-provider"]["implementations"]["rust-v5-witnessed-readback"] = implementation(
    [NATIVE_CRYPTO, NATIVE_ML_ADAPTER, NATIVE_CRYPTO_PROFILE, NATIVE_POLICY,
     NATIVE_OWNER, NATIVE_ANCHOR, NATIVE_STORAGE, NATIVE_FLOOR, NATIVE_PROVIDER,
     NATIVE_WITNESS, NATIVE_WITNESS_PROVIDER],
    "same-historical-operation-live-witness-before-and-after-readback-no-effect-entry")


def hash_use(primitives, constructions, paths, roles):
    return {"primitive_ids": sorted(primitives), "constructions": list(constructions),
            "source_paths": sorted(paths), "roles": list(roles),
            "query_to_primitive_mapping": "uninstantiated",
            "quantum_reduction": "uninstantiated", "failure_bound": None}


ROOT_ROLES = ROLES[:2]
HASH_USES = {
    "ml-dsa-internals": hash_use(
        ("shake128", "shake256"), ("ML-DSA-87",),
        (SIGNATURES, BACKEND, NATIVE_CRYPTO, NATIVE_ML_ADAPTER), ROLES),
    "slh-dsa-sha2-internals": hash_use(
        ("sha256", "sha512"), ("SLH-DSA-SHA2-256s", "HMAC-SHA-512", "MGF1-SHA-512"),
        (SIGNATURES, BACKEND, NATIVE_CRYPTO), ROLES),
    "python-policy-statement-operation-v1": hash_use(
        ("sha512",), ("domain-separated-complete-encodings",), (POLICY,), ROOT_ROLES),
    "python-public-key-identities-v2": hash_use(
        ("sha512",), ("suite-and-canonical-SPKI-DER",), (SIGNATURES,), BASE_ROLES),
    "python-statement-and-operation-v2": hash_use(
        ("sha512",), ("complete-statement", "witness-independent-operation-identity"),
        (SIGNATURES,), ROOT_ROLES),
    "python-verified-message-identity-v2": hash_use(
        ("sha512",), ("complete-verified-message",), (SIGNATURES,), BASE_ROLES),
    "python-journal-state-scope-effect-v2": hash_use(
        ("sha512",), ("enrollment-event-state-chain", "owner-scope", "complete-effect-intent"),
        (JOURNAL,), BASE_ROLES),
    "python-anchor-request-v2": hash_use(
        ("sha512",), ("complete-fresh-request",), (JOURNAL,), ROLES[2:4]),
    "python-provider-request-v2": hash_use(
        ("sha512",), ("complete-request-and-orphan-epoch",), (PROVIDER,), (ROLES[4],)),
    "python-provider-executable-integrity": hash_use(
        ("sha256",), ("trusted-local-executable-checksum",), (BACKEND,), BASE_ROLES),
    "native-key-identities-v3": hash_use(
        ("sha512",), ("native-v3-suite-and-key-encoding",),
        (NATIVE_CRYPTO,), ROLES),
    "native-roster-and-operation-v3": hash_use(
        ("sha512",), ("native-v3-complete-roster", "native-v3-witness-independent-operation"),
        (NATIVE_CRYPTO,), ROLES),
    "native-policy-checkpoint-artifact-v3": hash_use(
        ("sha512",), ("native-v3-policy", "native-v3-full-state-checkpoint",
                      "native-v3-actual-artifact-bytes"),
        (NATIVE_POLICY,), ROOT_ROLES),
    "native-owner-and-anchor-v3": hash_use(
        ("sha512",), ("native-v3-network-genesis-owner-scope",
                      "native-v3-enrollment-and-full-journal-head",
                      "native-v3-complete-anchor-request"),
        (NATIVE_OWNER, NATIVE_ANCHOR, NATIVE_STORAGE), ROLES[:4]),
    "native-recovery-floor-v4": hash_use(
        ("sha512",), ("native-v4-full-enrollment-external-floor-binding",),
        (NATIVE_FLOOR, NATIVE_OWNER), ROLES[:4]),
    "native-provider-readback-v4": hash_use(
        ("sha512",), ("native-v4-complete-provider-enrollment", "native-v4-complete-intent",
                      "native-v4-fresh-request-and-exact-orphan-epoch", "native-v4-retained-record-chain"),
        (NATIVE_PROVIDER,), (ROLES[4],)),
    "native-retained-witness-receipts-v6": hash_use(
        ("sha512",), ("native-v6-policy-bound-initial-receipt-checkpoint",
                      "native-v6-complete-original-request-and-all-quorum-signatures-receipt-chain"),
        (NATIVE_WITNESS_RECEIPTS, NATIVE_OWNER), ("anchor-writer", "witness-response")),
    "native-fresh-witness-v5": hash_use(
        ("sha512",), ("native-v5-complete-enrollment",
                      "native-v5-restore-domain-epoch-and-witness-roster-binding",
                      "native-v5-complete-fresh-read-or-exact-cas-request",
                      "native-v5-request-digest-bound-witness-receipt"),
        (NATIVE_WITNESS, NATIVE_WITNESS_DURABLE, NATIVE_OWNER), ("anchor-writer", "witness-response")),
}

PRIMITIVE_IDENTITIES = {
    "sha256": "FIPS180-4/SHA-256", "sha512": "FIPS180-4/SHA-512",
    "shake128": "FIPS202/SHAKE128", "shake256": "FIPS202/SHAKE256",
}
PRIMITIVES = {
    name: {
        "public_parameter_id": identity,
        "shared_scope": "all-listed-roles-in-one-lifetime",
        "use_ids": sorted(key for key, use in HASH_USES.items() if name in use["primitive_ids"]),
        "fixed_across_epochs": True,
        "query_budget": {
            "basis": "unknown", "maximum": None, "unit": "not-instantiated",
            "coverage": list(QUERY_COVERAGE), "initial_advice": "unqualified",
            "resource_to_query_reduction": "uninstantiated",
            "reset_at_key_epoch": False, "reset_at_recovery": False,
            "reset_at_role_boundary": False, "telemetry_is_upper_bound": False,
        },
        "actual_lifetime_failure_bound": None,
    } for name, identity in PRIMITIVE_IDENTITIES.items()
}


def refusal_cap(path, symbol, value, unit, scope="one-local-research-owner"):
    return {"source_path": path, "symbol": symbol, "maximum": str(value),
            "unit": unit, "scope": scope,
            "purpose": "operational-refusal-only", "bounds_adversary_queries": False,
            "permits_history_pruning": False, "permits_lifetime_reset": False}


OPERATIONAL_CAPS = {
    "python-retained-nonces": refusal_cap(POLICY, "MAX_HISTORY", 128, "nonce-records"),
    "python-retained-events": refusal_cap(JOURNAL, "MAX_EVENTS", 2048, "journal-events"),
    "python-state-row-bytes": refusal_cap(JOURNAL, "MAX_STATE_BYTES", 2097152, "bytes"),
    "native-retained-root-operations": refusal_cap(
        NATIVE_POLICY, "MAX_ROOT_OPERATIONS_V3", 128, "retained-root-operations"),
    "native-retained-root-revocations": refusal_cap(
        NATIVE_POLICY, "MAX_ROOT_REVOCATIONS_V3", 128, "revoked-key-identities"),
    "native-artifact-bytes": refusal_cap(
        NATIVE_POLICY, "MAX_ROOT_ARTIFACT_BYTES_V3", 67108864, "artifact-bytes",
        "one-release-intent"),
    "native-retained-journal-events": refusal_cap(
        NATIVE_OWNER, "MAX_JOURNAL_EVENTS_V3", 128, "journal-events"),
    "native-witness-database-bytes": refusal_cap(
        NATIVE_WITNESS_DURABLE, "MAX_DATABASE_BYTES", 1048576, "bytes",
        "one-typed-native-witness-register"),
    "native-witness-receipt-database-bytes-v6": refusal_cap(
        NATIVE_WITNESS_DURABLE, "MAX_RECEIPT_DATABASE_BYTES_V6", 33554432, "bytes",
        "one-typed-native-receipted-witness-register"),
    "native-witness-retained-receipts-v6": refusal_cap(
        NATIVE_WITNESS_RECEIPTS, "MAX_RECORDS", 128, "signed-exchange-records",
        "one-typed-native-receipted-witness-register"),
    "native-witness-receipt-record-bytes-v6": refusal_cap(
        NATIVE_WITNESS_RECEIPTS, "MAX_RECORD_BYTES", 196608, "bytes-per-retained-exchange",
        "one-typed-native-receipted-witness-register"),
    "native-verification-reservations": refusal_cap(
        NATIVE_CRYPTO, "MAX_VERIFICATIONS_V3", 4096, "verification-reservations",
        "one-shared-native-operation-budget"),
    "native-verification-input-bytes": refusal_cap(
        NATIVE_CRYPTO, "MAX_VERIFICATION_INPUT_BYTES_V3", 524288, "bytes-per-reservation",
        "one-shared-native-operation-budget"),
    "native-verification-cumulative-bytes": refusal_cap(
        NATIVE_CRYPTO, "MAX_CUMULATIVE_BYTES_V3", 67108864, "reserved-bytes",
        "one-shared-native-operation-budget"),
}
OPEN_OBLIGATIONS = {
    name: {"status": "open", "failure_bound": None} for name in (
        "whole-chain-event-coverage", "concrete-quantum-multi-user-forgery",
        "shared-oracle-instantiation", "resource-and-query-transformations",
        "preprocessing-and-initial-advice", "implementation-refinement",
        "independent-custody", "independently-retained-fresh-anchor",
        "independently-retained-witness-and-trusted-policy",
        "witness-durable-cas-before-acknowledgement",
        "native-provider-and-effect-owner-integration", "real-external-effect-reconciliation",
    )
}
SOURCE_PATHS = sorted(set(
    (POLICY, SIGNATURES, JOURNAL, PROVIDER, BACKEND, BUDGET,
     NATIVE_CRYPTO, NATIVE_ML_ADAPTER, NATIVE_CRYPTO_PROFILE, NATIVE_POLICY, NATIVE_OWNER,
     NATIVE_ANCHOR, NATIVE_STORAGE, NATIVE_FLOOR, NATIVE_PROVIDER, NATIVE_WITNESS, NATIVE_WITNESS_DURABLE,
     NATIVE_WITNESS_PROVIDER, NATIVE_WITNESS_RECEIPTS,
     NODE + "tests/root_witness_v6_receipts_native.rs",
     CRYPTO + "src/pq_root_v3/tests.rs", CRYPTO + "tests/pq_root_v3_native.rs",
     RELEASE + "src/root_recovery_v3_tests.rs",
     NODE + "tests/root_recovery_v3_native.rs",
     NODE + "tests/support/root_recovery_v3_fixture.rs",
     NODE + "tests/recovery_floor_v4_native.rs",
     NODE + "tests/root_effect_readback_v4_native.rs",
     NODE + "tests/root_budget_v4_native.rs",
     NODE + "tests/root_witness_v5_native.rs",
     NODE + "tests/root_witness_v5_durable_native.rs",
     NODE + "tests/root_witness_provider_v5_native.rs",
     CRYPTO + "src/lib.rs", CRYPTO + "Cargo.toml",
     CRATES + "trnm-protocol/src/lib.rs", CRATES + "trnm-protocol/Cargo.toml",
     RELEASE + "src/lib.rs", RELEASE + "Cargo.toml",
     NODE + "src/lib.rs", NODE + "Cargo.toml",
     "trillionnium/Cargo.toml", "trillionnium/Cargo.lock",
     RELEASE + "src/pq_release.rs", NODE + "src/release_owner.rs",
     "scripts/ci/pq_lifetime_budget.py", "scripts/ci/pq_source_reader.py")
))
FROZEN = {
    "schema": SCHEMA,
    "purpose": "declared-root-dependency-and-query-obligation-inventory",
    "review_base_revision": REVIEW_BASE,
    "source_binding_scope": "declared-root-component-files-only",
    "profiles": {
        "python": "root-research-v2-height-contract",
        "rust": "root-research-v3-unix-seconds-contract",
        "wire_equivalence_proved": False,
        "native_real_crypto_feature": "pq-native-openssl",
        "native_root_kernel_feature": "pq-root-v3",
        "native_clock_source": "trusted-caller-unix-seconds",
        "native_storage_assumption": "trusted-private-directory-administration-during-sqlite-open",
        "native_clock_authority_qualified": False,
        "native_sqlite_descriptor_race_proved_absent": False,
        "native_m15_production_integration_complete": False,
        "native_recovery_floor": "caller-authenticated-pin-not-independent-custody-proof",
        "native_provider_readback": "v4-declarations-only-no-effect-dispatch",
        "native_witness": "v5-client-and-typed-durable-register-component-no-daemon",
        "native_witness_trust": "separately-provisioned-policy-and-surviving-durable-register-required",
        "native_witness_receipt_archive": "v6-bounded-original-exchange-evidence-with-external-checkpoint-no-distributed-service",
        "native_witness_receipt_archive_independence_verified": False,
        "independent_common_restore_exclusion_proved": False,
        "native_witness_durable_service_verified": False,
    },
    "roles": ROLE_CONTRACT,
    "hash_uses": HASH_USES,
    "primitives": PRIMITIVES,
    "operational_refusal_caps": OPERATIONAL_CAPS,
    "operational_cap_inventory_scope": "selected-refusal-limits-not-complete-resource-policy",
    "operation_deadline_policy": {
        "source_path": NATIVE_CRYPTO, "default_symbol": "VERIFICATION_LIFETIME_V3",
        "default_verification_budget_seconds": "60",
        "deadline_source": "original-caller-supplied-monotonic-deadline",
        "universal_duration_maximum": None,
        "preempts_in_progress_native_call": False,
        "bounds_adversary_queries": False,
    },
    "lifetime": {"status": "unknown", "maximum_duration": None, "stopping_rule": None,
                 "total_adversary_queries": None, "total_initial_advice": None},
    "domain_failure_bounds": {domain: None for domain in DOMAINS},
    "open_obligations": OPEN_OBLIGATIONS,
    "prior_lifetime_manifest": "config/pon/pq128-lifetime-budget-v1.json",
    "prior_register_covers_this_component": False,
    "prior_register_query_budgets_are_independent": False,
    "whole_chain_hash_query_scope_closed": False,
    "transitive_dependency_closure_proved": False,
    "composition_coverage_proved": False,
    "actual_lifetime_failure_bound": None,
    "whole_chain_pq_qualified": False,
    "production_activation": False,
}


def source_snapshot_digest(files):
    raw = json.dumps({"review_base_revision": REVIEW_BASE, "source_files_sha256": files},
                     sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def validate_manifest(data):
    """Validate frozen review inputs without inspecting source or proving claims."""
    fields(data, (*FROZEN, "source_files_sha256"), "register")
    for key, expected in FROZEN.items():
        exact(data[key], expected, key)
    files = data["source_files_sha256"]
    fields(files, SOURCE_PATHS, "source_files_sha256")
    for path, digest in files.items():
        require(type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
                "invalid source digest: " + path)
    require(source_snapshot_digest(files) == REVIEWED_SOURCE_SNAPSHOT_SHA256,
            "source map differs from the frozen reviewed snapshot")
    return {
        "schema": RESULT_SCHEMA, "status": "HOLD",
        "inventory_contract_satisfied": True,
        "source_files_checked": False,
        "source_binding_scope": "unbound-until-file-inspection",
        "source_revision_bound": False,
        "review_base_revision": REVIEW_BASE,
        "declared_source_snapshot_sha256": REVIEWED_SOURCE_SNAPSHOT_SHA256,
        "source_file_count": len(SOURCE_PATHS), "declared_roles": list(ROLES),
        "native_unwired_roles": ["effect-provider"],
        "native_unwired_role_scope": "effect-entry-and-production-owner-not-readback-code",
        "native_readback_candidate_roles": ["effect-provider"],
        "native_witness_candidate_roles": ["witness-response"],
        "independent_common_restore_exclusion_proved": False,
        "native_witness_durable_service_verified": False,
        "hash_use_count": len(HASH_USES),
        "unknown_lifetime_query_budgets": sorted(PRIMITIVES),
        "unknown_role_lifetime_populations": list(ROLES),
        "operational_refusal_caps_are_adversary_bounds": False,
        "domain_failure_bounds": {domain: None for domain in DOMAINS},
        "actual_lifetime_failure_bound": None,
        "whole_chain_pq_qualified": False, "pq_128_qualified": False,
        "composition_coverage_proved": False, "theorem_applicability_verified": False,
        "transitive_dependency_closure_proved": False,
        "whole_chain_hash_query_scope_closed": False,
        "independent_custody_verified": False, "anchor_independence_verified": False,
        "actual_external_effects_verified": False,
        "native_m15_production_integration_complete": False,
        "production_activation": False,
        "open_obligations": sorted(OPEN_OBLIGATIONS),
        "note": "Frozen declared-role/source inventory only; no call-graph, deployed-owner, complete dependency, cryptographic reduction or adversary query-cap qualification.",
    }


def inspect(root, manifest_path=DEFAULT_MANIFEST):
    """Match regular source bytes to the reviewed map; never rewrite that map."""
    root = Path(root)
    try:
        raw = read_regular(root, manifest_path, MAX_BYTES)
        data = strict_json(raw)
        result = validate_manifest(data)
        observed = {}
        for path in SOURCE_PATHS:
            digest = hashlib.sha256(read_regular(root, path, MAX_BYTES)).hexdigest()
            require(digest == data["source_files_sha256"][path],
                    "source hash mismatch: " + path)
            observed[path] = digest
    except (SourceReadError, BudgetError) as error:
        raise RegisterError(str(error)) from error
    result.update({"source_files_checked": True,
                   "source_binding_scope": "declared-root-component-files-only",
                   "manifest_sha256": hashlib.sha256(raw).hexdigest(),
                   "source_files_sha256": observed})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    args = parser.parse_args()
    try:
        report = inspect(args.root, args.manifest)
    except (RegisterError, OSError, ValueError) as error:
        print(json.dumps({"schema": RESULT_SCHEMA, "status": "REFUSE", "reason": str(error)},
                         sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
