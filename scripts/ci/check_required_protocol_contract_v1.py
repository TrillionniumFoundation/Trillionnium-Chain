#!/usr/bin/env python3
"""Structured, GitHub-hosted merge contract for the active PoCO-BFT boundary.

This check deliberately avoids treating historical prose layout or privileged
self-hosted workflow implementation details as protocol semantics. Expensive
formal/fault/evidence campaigns remain separate fail-closed gates.
"""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys
import tomllib
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]


class ContractError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def read(path: str) -> str:
    try:
        return (ROOT / path).read_text(encoding="utf-8")
    except OSError as exc:
        raise ContractError(f"{path}: unreadable: {exc}") from exc


def load_json(path: str) -> dict[str, Any]:
    try:
        value = json.loads(read(path))
    except json.JSONDecodeError as exc:
        raise ContractError(f"{path}: invalid JSON: {exc}") from exc
    require(isinstance(value, dict), f"{path}: top level must be an object")
    return value


def load_toml(path: str) -> dict[str, Any]:
    try:
        with (ROOT / path).open("rb") as handle:
            value = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ContractError(f"{path}: invalid TOML: {exc}") from exc
    require(isinstance(value, dict), f"{path}: top level must be a table")
    return value


def require_tokens(path: str, tokens: tuple[str, ...]) -> None:
    text = read(path)
    missing = [token for token in tokens if token not in text]
    require(not missing, f"{path}: missing contract tokens: {missing}")


def require_tracked_clean(path: str) -> None:
    subprocess.run(
        ["git", "cat-file", "-e", f":{path}"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    result = subprocess.run(
        ["git", "diff", "--quiet", "--", path],
        cwd=ROOT,
        check=False,
    )
    require(result.returncode == 0, f"{path}: working tree differs from candidate index")


def main() -> int:
    truth = load_json("config/consensus-mainline.json")
    policy = load_json("config/repository-policy-v1.json")
    boundary = load_json("PROJECT_BOUNDARY.json")
    cargo = load_toml("trillionnium/Cargo.toml")
    node_cargo = load_toml("trillionnium/crates/trnm-poco-node/Cargo.toml")
    protocol_manifest = load_toml("docs/protocol/poco-ai-native-v1/spec-manifest.toml")

    require(truth.get("consensus_mainline") == "native-poco-bft",
            "machine truth must select Native PoCO-BFT")
    require(truth.get("protocol_target") == "poco-bft-v0",
            "machine truth protocol target drift")
    require(truth.get("production_candidate") is False,
            "protocol contract cannot run against a promoted production candidate")
    require(truth.get("production_consensus_activation") is False,
            "protocol contract cannot activate consensus")
    require(truth.get("cometbft", {}).get("role") == "migration-residue-only",
            "CometBFT role must remain migration-only")
    require(boundary.get("consensus", {}).get("legacy_comet_may_authorize_release") is False,
            "legacy Comet path must not authorize release")

    workspace = cargo.get("workspace", {})
    members = set(workspace.get("members", []))
    excluded = set(workspace.get("exclude", []))
    required_members = {
        "crates/trnm-consensus-types",
        "crates/trnm-consensus-crypto",
        "crates/trnm-consensus-core",
        "crates/trnm-consensus-safety-rules",
        "crates/trnm-consensus-safety-store",
        "crates/trnm-consensus-signer-journal",
        "crates/trnm-native-application",
        "crates/trnm-poco-node",
    }
    require(required_members <= members,
            f"active protocol workspace members missing: {sorted(required_members - members)}")
    require({"crates/trnm-consensus-app", "crates/trnm-node"} <= excluded,
            "legacy Comet packages must remain excluded")
    require(not ({"crates/trnm-consensus-app", "crates/trnm-node"} & members),
            "legacy Comet packages re-entered the active workspace")

    required_checks = policy.get("required_check_names", [])
    require("protocol-contract" in required_checks,
            "protocol-contract is not a stable required check")
    require("fuzz-smoke" in required_checks,
            "canonical input fuzz smoke is not a stable required check")

    require(protocol_manifest.get("manifest_version") in {1, "1"},
            "unsupported protocol spec manifest version")
    require(protocol_manifest.get("protocol_id") is not None,
            "protocol spec manifest must identify the protocol")

    node_metadata = node_cargo.get("package", {}).get("metadata", {}).get("trnm", {})
    require(node_metadata.get("production_candidate") is False,
            "node package metadata may not claim production candidacy")
    require(node_metadata.get("production_consensus_activation") is False,
            "node package metadata may not activate production consensus")
    require(node_metadata.get("incomplete") is True,
            "node package must retain its incomplete boundary")
    require(node_metadata.get("effect_driver") is False,
            "default production effect driver must remain unavailable")
    require(node_metadata.get("production_signature_producer") is False,
            "production signature producer must remain unavailable")

    require_tokens(
        "trillionnium/crates/trnm-poco-node/src/lib.rs",
        (
            "pub const PRODUCTION_CANDIDATE_V0: bool = false;",
            "pub const HOST_IMPLEMENTATION_COMPLETE_V0: bool = false;",
            "production_activation_gate_v0",
        ),
    )
    require_tokens(
        "trillionnium/crates/trnm-poco-node/src/main.rs",
        (
            "production_activation_gate_v0()",
            "production_candidate=false",
            "host_complete=false",
        ),
    )
    require_tokens(
        "trillionnium/crates/trnm-poco-node/src/recovery_process_watermark.rs",
        (
            "It is not an independently administered",
            "whole-namespace rollback",
            "cloning",
            "hostile same-EUID replacement",
            "device write-cache loss",
            "power failure",
            "ExternalMonotonicWatermarkV0",
            "compare_and_advance",
        ),
    )
    require_tokens(
        "trillionnium/crates/trnm-poco-node/src/ordinary_timeout.rs",
        (
            "on_local_timeout_v0",
            "SafetyPersistedBeforeStorageAck",
            "SignatureRequestedBeforeJournal",
            "SignaturePersistedBeforeSignatureReady",
            "BroadcastProducedBeforeReturn",
        ),
    )
    require_tokens(
        "trillionnium/crates/trnm-consensus-core/src/core.rs",
        (
            "PREAUTHENTICATION_CACHE_MAX_ENTRIES_V0",
            "step_with_preauthenticated_token_v0",
            "begin_payload_validation_obligation_recovery_v0",
        ),
    )
    require_tokens(
        "trillionnium/crates/trnm-consensus-safety-store/src/sqlite.rs",
        (
            "ConfirmedNativeDeterministicInvalidHeadV0",
            "journal_id_v0",
            "verifier_profile_ref_v0",
        ),
    )

    contract_files = (
        "docs/protocol/poco-bft-v0/schema/decoder-error-registry-v0.json",
        "docs/protocol/poco-bft-v0/schema/decoder-error-registry-reference-v0.json",
        "scripts/ci/check_poco_bft_v0_parameters.py",
        "scripts/ci/check_poco_bft_v0_wire_vectors.py",
        "scripts/ci/check_poco_bft_v0_wire_reference.py",
        "scripts/ci/check_poco_bft_v0_wire_semantic_reference.py",
        "scripts/ci/check_poco_bft_v0_registry.sh",
        "scripts/ci/check_poco_bft_v0_registry_reference.sh",
        "scripts/ci/check_canonical_fuzz_smoke.sh",
        "scripts/ci/install_cargo_fuzz.sh",
    )
    for path in contract_files:
        require((ROOT / path).is_file(), f"required protocol contract file missing: {path}")
        require_tracked_clean(path)

    legacy_truth = read("scripts/ci/check_poco_bft_v0_ci_truth.sh")
    require("runs-on: [self-hosted" not in read(".github/workflows/trnm-required-baseline.yml"),
            "required baseline must not depend on a self-hosted runner")
    require("require_literal" in legacy_truth,
            "legacy deep CI truth checker unexpectedly disappeared")
    require("check_poco_bft_v0_ci_truth.sh" not in
            read(".github/workflows/trnm-required-baseline.yml"),
            "historical line-layout checker must not be a required merge dependency")

    # Refuse an accidental production promotion hidden in active source or docs.
    forbidden_patterns = (
        r"PRODUCTION_CANDIDATE_V0:\s*bool\s*=\s*true",
        r"HOST_IMPLEMENTATION_COMPLETE_V0:\s*bool\s*=\s*true",
        r'"production_consensus_activation"\s*:\s*true',
    )
    active_text = "\n".join(
        read(path)
        for path in (
            "config/consensus-mainline.json",
            "trillionnium/crates/trnm-poco-node/src/lib.rs",
            "PROJECT_BOUNDARY.json",
        )
    )
    for pattern in forbidden_patterns:
        require(re.search(pattern, active_text) is None,
                f"forbidden production promotion matched: {pattern}")

    report = {
        "schema": "trnm-required-protocol-contract-v1",
        "consensus_mainline": "native-poco-bft",
        "protocol_target": "poco-bft-v0",
        "active_workspace_members": len(members),
        "legacy_active_members": [],
        "default_node_fail_closed": True,
        "local_watermark_nonproduction_scope_declared": True,
        "long_run_fuzz_closed": False,
        "independent_review_closed": False,
        "production_candidate": False,
        "production_consensus_activation": False,
        "result": "PASS",
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ContractError, subprocess.CalledProcessError) as exc:
        print(f"required protocol contract failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
