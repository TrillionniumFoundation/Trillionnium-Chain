#!/usr/bin/env python3
"""Check a reviewed current source correspondence while preserving frozen PQ V1.

This entry does not qualify native cryptography, a deployment, a whole dependency
graph, a scientific campaign, or the original frozen source. Its own current
reader and workflow are bound by the independent committed-source CI recorder,
not by a self-referential map.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

import check_pq_research_integration as frozen
from pq_source_reader import SourceReadError, read_regular

SCHEMA = "trnm-pq-corpus-current-source-result-v2"
MAP_SCHEMA = "trnm-pq-corpus-current-source-v2"
DEFAULT_MAP = "config/pon/pq-corpus-current-source-v2.json"
SCOPE = "frozen-declared-paths-plus-reviewed-native-additions-only"
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_MAP_BYTES = 64 * 1024
MAX_REPORT_BYTES = 64 * 1024
EXPECTED_FROZEN_PIN_COUNT = 2613
EXPECTED_MAP_SHA256 = "a9c24994d101245c9244da474a49afebb1ab4541ca640e78b75921fd6f6c7a2b"
EXPECTED_CURRENT_BLOBS_SHA256 = "526183c5f25fc633573c4f45422456cea788d2e2d7a3f862fdc36e775efecc64"
FROZEN_INPUTS_SHA256 = {
    "config/pon/pq-cross-branch-corpus-v1.json": "ceb3f8d7adb519e4d2cfa5644f7686d61bd3c4976245e069e0a9d7a04068f176",
    "scripts/ci/check_pq_research_integration.py": "912314a9c13ce8d882ec88ee52926de9aa02613b5f8225b3aa09f5b59885221f",
    "scripts/ci/test_pq_research_integration.py": "3e28aa336967d1916612d9a62d2ea0726e1b7211cbdfdac58d0a3219b17ea3d0",
    "scripts/ci/pq_source_reader.py": "b3eb3f23b42c012dc1a5a07daa479db5e2982b2a20006f047552c9f13e1a65cb",
}
EXPECTED_REPLACEMENT_PATHS = frozenset((
    ".github/workflows/chain-hepta-closure-candidate.yml",
    ".github/workflows/cpq1-full-content.yml",
    ".github/workflows/pon-pq-system-continuation.yml",
    "config/pon/hash-use-contract-v1.json",
    "config/pon/joint-consensus-qualification-v1.json",
    "config/pon/pq-authority-effects-v1.json",
    "config/pon/pq-proof-profile-binding-v1.json",
    "config/pon/pq-root-dependency-register-v3.json",
    "config/pon/pq128-lifetime-composition-current-v3.json",
    "config/pon/pq128-source-correspondence-current-v2.json",
    "config/pon/w1-lifetime-current-source-v2.json",
    "config/pon/w1-qrom-implementation-current-v2.json",
    "config/pon/w1-stark-route-registry-v1.json",
    "config/pon/w1-upstream-security-v1.json",
    "docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md",
    "docs/security/PQ_AUTHORITY_EFFECT_REGISTER_V1.md",
    "formal/pon-nakamoto-v1/joint_consensus_qualification.py",
    "scripts/ci/hash_use_contract.py",
    "scripts/ci/pq_authority_effect_register.py",
    "scripts/ci/pq_lifetime_composition.py",
    "scripts/ci/pq_lifetime_current_v2.py",
    "scripts/ci/pq_root_dependency_register.py",
    "scripts/ci/run_from_zero_native.py",
    "scripts/ci/test_pq_authority_effect_register.py",
    "scripts/ci/test_pq_proof_profile_binding.py",
    "scripts/ci/test_pq_root_dependency_register.py",
    "scripts/ci/test_run_from_zero_native.py",
    "scripts/ci/test_w1_qrom_current_ci.py",
    "scripts/ci/test_w1_qrom_current_implementation_audit.py",
    "scripts/pon_public_v3_phase_read.py",
    "scripts/w1_lifetime_current_observation.py",
    "scripts/w1_qrom_current_implementation_audit.py",
    "scripts/w1_stark_route_audit.py",
    "trillionnium/Cargo.toml",
    "trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs",
    "trillionnium/crates/trnm-pon-node/examples/support/distributed_source_inventory.rs",
    "trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs",
    "trillionnium/crates/trnm-pon-node/src/host_kernel_parent_resource_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/history_import.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/history_import/observation.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/public_v3/request_observation.rs",
    "trillionnium/crates/trnm-pon-node/src/lib.rs",
    "trillionnium/crates/trnm-pon-node/src/pq_rollback_witness.rs",
    "trillionnium/crates/trnm-pon-node/src/pq_tls_cli.rs",
    "trillionnium/crates/trnm-pon-node/src/pq_tls_cli_witness.rs",
    "trillionnium/crates/trnm-pon-node/src/store/pq_rollback_witness/combined_tests.rs",
    "trillionnium/crates/trnm-pon-node/tests/native_task_operation_v2.rs",
    "trillionnium/crates/trnm-pon-node/tests/pq_tls_refusal_diagnostics.rs",
    "trillionnium/crates/trnm-pon-node/tests/pq_tls_witness_cli/refusal_diagnostics.rs",
    "trillionnium/crates/trnm-pon-node/tests/pq_tls_witness_cli/support.rs",
    "trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero.rs",
))
EXPECTED_ADDED_PATHS = frozenset((
    ".github/workflows/pon-throughput-evidence.yml",
    "evidence/pft-candidate-readback-20261128/SYNTHETIC_CANDIDATE.json",
    "evidence/pft-native-loader-20261128/SYNTHETIC_EXPECTED.json",
    "evidence/pft-native-loader-20261128/SYNTHETIC_FEATURES.json",
    "evidence/pft-selected-inspection-20261128/SYNTHETIC_BINDING_EXPECTED.json",
    "evidence/pft-selected-owner-controls-20261128/SYNTHETIC_OWNER_FIXTURE.json",
    "evidence/pft-selected-readout-20261128/SYNTHETIC_OWNER_FIXTURE.json",
    "evidence/pft-selected-readout-20261128/build_fixture.py",
    "scripts/ci/cpq1_current_gate.py",
    "scripts/ci/test_cpq1_current_gate.py",
    "scripts/test_pon_history_kernel_cpu_observation.py",
    "trillionnium/crates/trnm-crypto-primitives/src/pon_work/noise_frame.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/adoption/tests/selected_manifest.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/history_import/kernel_cpu_observation.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/public_v3/response_signing_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/pft_native_loader_v1.rs",
    "trillionnium/crates/trnm-pon-node/src/pft_native_loader_v1/adversarial_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/pft_native_loader_v1/json.rs",
    "trillionnium/crates/trnm-pon-node/src/pft_native_loader_v1/tests.rs",
    "trillionnium/crates/trnm-pon-node/src/pft_readout_f64_v1.rs",
    "trillionnium/crates/trnm-pon-node/src/pft_readout_f64_v1/tests.rs",
    "trillionnium/crates/trnm-pon-node/src/pft_selected_inspection_v1.rs",
    "trillionnium/crates/trnm-pon-node/src/pft_selected_inspection_v1/binding.rs",
    "trillionnium/crates/trnm-pon-node/src/pft_selected_inspection_v1/binding_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/pft_selected_inspection_v1/owner_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/pft_selected_readout_v1.rs",
    "trillionnium/crates/trnm-pon-node/src/pft_selected_readout_v1/tests.rs",
    "trillionnium/crates/trnm-pon-node/src/pq_rollback_witness/development_observation.rs",
    "trillionnium/crates/trnm-pon-node/src/store/pq_rollback_witness/combined_tests/failure_observation.rs",
))
QUALIFICATION = {
    "frozen_source_accepted": False,
    "native_cryptography_qualified": False,
    "whole_chain_pq_qualified": False,
    "production_activation": False,
    "complete_dependency_coverage_proved": False,
    "theorem_applicability_verified": False,
    "old_campaign_qualification_transferred": False,
    "actual_lifetime_failure_bound": None,
}


class CurrentCorpusError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise CurrentCorpusError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def strict_json(raw):
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    def reject_constant(_value):
        raise CurrentCorpusError("nonfinite JSON number")

    value = json.loads(raw, object_pairs_hook=unique_pairs,
                       parse_constant=reject_constant)
    require(type(value) is dict, "expected JSON object")
    return value


def fields(value, expected, description):
    require(type(value) is dict and set(value) == set(expected.split()),
            "unexpected fields: " + description)


def digest(value, length, description):
    require(type(value) is str
            and re.fullmatch(r"[0-9a-f]{" + str(length) + "}", value) is not None,
            "invalid digest: " + description)


def inspect(root):
    """Inspect declared current bytes; separate reads are not a Git snapshot."""
    root = Path(root).absolute()
    try:
        map_raw = read_regular(root, DEFAULT_MAP, MAX_MAP_BYTES)
        require(hashlib.sha256(map_raw).hexdigest() == EXPECTED_MAP_SHA256,
                "current map differs from reviewed bytes")
        mapping = strict_json(map_raw)
        fields(mapping, "schema status scope frozen_inputs_sha256 replacements "
               "additions current_git_blob_map_sha256 qualification", "current map")
        require(mapping["schema"] == MAP_SCHEMA and mapping["status"] == "HOLD"
                and mapping["scope"] == SCOPE, "unsupported current map namespace")
        require(canonical(mapping["qualification"]) == canonical(QUALIFICATION),
                "current correspondence cannot grant qualification")
        require(mapping["frozen_inputs_sha256"] == FROZEN_INPUTS_SHA256,
                "frozen corpus and guard identities cannot be replaced")

        frozen_raw = {}
        for path, expected in sorted(FROZEN_INPUTS_SHA256.items()):
            raw = read_regular(root, path, MAX_SOURCE_BYTES)
            require(hashlib.sha256(raw).hexdigest() == expected,
                    "frozen input changed: " + path)
            frozen_raw[path] = raw
        original = strict_json(frozen_raw[frozen.REL_MANIFEST])
        require(original.get("schema") == "trnm-pq-cross-branch-corpus-v1"
                and original.get("status") == "research-only-hold-no-go",
                "frozen corpus namespace changed")
        assertions = original.get("assertions")
        require(type(assertions) is dict and set(assertions) == frozen.REQUIRED_FALSE
                and all(value is False for value in assertions.values()),
                "frozen assertions cannot grant acceptance")
        old_pins = original.get("pinned_blobs")
        required = original.get("required_paths")
        require(type(old_pins) is dict and len(old_pins) == EXPECTED_FROZEN_PIN_COUNT
                and type(required) is list and required
                and all(type(path) is str for path in required)
                and len(required) == len(set(required))
                and set(required).issubset(old_pins), "frozen declared pin set changed")
        for path, value in old_pins.items():
            require(type(path) is str, "invalid frozen source path")
            digest(value, 40, path)

        replacements, additions = mapping["replacements"], mapping["additions"]
        require(type(replacements) is dict
                and set(replacements) == EXPECTED_REPLACEMENT_PATHS,
                "current replacement roster changed")
        require(type(additions) is dict and set(additions) == EXPECTED_ADDED_PATHS,
                "current addition roster changed")
        require(EXPECTED_REPLACEMENT_PATHS.issubset(old_pins)
                and EXPECTED_ADDED_PATHS.isdisjoint(old_pins),
                "replacement and addition ownership overlap")
        current = dict(old_pins)
        extra_sha256 = {}
        for path, row in sorted(replacements.items()):
            fields(row, "frozen_git_blob current_git_blob current_sha256", path)
            require(row["frozen_git_blob"] == old_pins[path],
                    "replacement does not preserve original blob: " + path)
            digest(row["current_git_blob"], 40, path)
            digest(row["current_sha256"], 64, path)
            require(row["current_git_blob"] != old_pins[path],
                    "unchanged path cannot be a replacement: " + path)
            current[path] = row["current_git_blob"]
            extra_sha256[path] = row["current_sha256"]
        for path, row in sorted(additions.items()):
            fields(row, "current_git_blob current_sha256", path)
            digest(row["current_git_blob"], 40, path)
            digest(row["current_sha256"], 64, path)
            current[path] = row["current_git_blob"]
            extra_sha256[path] = row["current_sha256"]
        require(mapping["current_git_blob_map_sha256"] == EXPECTED_CURRENT_BLOBS_SHA256
                and hashlib.sha256(canonical(current)).hexdigest()
                == EXPECTED_CURRENT_BLOBS_SHA256,
                "current blob map differs from independent snapshot pin")

        for path, expected in sorted(current.items()):
            raw = read_regular(root, path, MAX_SOURCE_BYTES)
            require(frozen._git_blob(raw) == expected, "current source changed: " + path)
            if path in extra_sha256:
                require(hashlib.sha256(raw).hexdigest() == extra_sha256[path],
                        "current source SHA-256 changed: " + path)
        frozen._check_pq_source_coverage(root, current)
        frozen._check_canonical_provider_contract(root)
        for path, raw in frozen_raw.items():
            require(read_regular(root, path, MAX_SOURCE_BYTES) == raw,
                    "frozen input changed during inspection: " + path)
        require(read_regular(root, DEFAULT_MAP, MAX_MAP_BYTES) == map_raw,
                "current map changed during inspection")
        return {
            "schema": SCHEMA, "status": "HOLD", **QUALIFICATION,
            "current_source_correspondence_checked": True,
            "source_revision_bound": False,
            "source_binding_scope": SCOPE,
            "map_sha256": EXPECTED_MAP_SHA256,
            "current_git_blob_map_sha256": EXPECTED_CURRENT_BLOBS_SHA256,
            "frozen_inputs_sha256": dict(FROZEN_INPUTS_SHA256),
            "frozen_declared_path_count": len(old_pins),
            "current_declared_path_count": len(current),
            "changed_from_frozen_paths": sorted(replacements),
            "added_current_paths": sorted(additions),
            "note": "This entry checks a reviewed declared-path correspondence and the original bounded coverage/provider guards. It does not make the frozen V1 entry accept current source, prove a Git revision or complete dependency graph, or transfer native, security, deployment or campaign qualification. The new current reader and workflow require independent exact-source CI binding.",
        }
    except (frozen.IntegrityError, SourceReadError, KeyError, TypeError,
            ValueError, UnicodeError, OSError, RecursionError) as error:
        if isinstance(error, CurrentCorpusError):
            raise
        raise CurrentCorpusError(str(error)) from error


def verify_report(root, raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_REPORT_BYTES,
            "invalid current report bytes")
    try:
        supplied = strict_json(raw)
        expected = inspect(root)
        require(canonical(supplied) == canonical(expected),
                "current report differs from fresh inspection")
        return expected
    except (ValueError, TypeError, UnicodeError, RecursionError) as error:
        if isinstance(error, CurrentCorpusError):
            raise
        raise CurrentCorpusError("invalid current report") from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    try:
        result = inspect(args.root)
    except CurrentCorpusError as error:
        print(json.dumps({"schema": SCHEMA, "status": "REFUSE",
                          "reason": str(error), **QUALIFICATION}, sort_keys=True),
              file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
