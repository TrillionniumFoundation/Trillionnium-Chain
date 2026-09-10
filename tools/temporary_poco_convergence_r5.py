#!/usr/bin/env python3
"""One-shot native PoCO convergence helper. Removed from the qualified tree."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs/development/plan-manifest-v1.toml"
PLAN = ROOT / "docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md"
SNAPSHOT = ROOT / "docs/development/CURRENT_SNAPSHOT_V1.json"

V0_IMPORT_PATHS = (
    "docs/protocol/poco-bft-v0/01-system-model-and-threat-model.md",
    "docs/protocol/poco-bft-v0/02-chained-qc-consensus.md",
    "docs/protocol/poco-bft-v0/03-wire-crypto-and-domain-separation.md",
    "docs/protocol/poco-bft-v0/04-epochs-validator-sets-and-upgrades.md",
    "docs/protocol/poco-bft-v0/05-poco-weights-bond-and-slashing.md",
    "docs/protocol/poco-bft-v0/06-light-client.md",
    "docs/protocol/poco-bft-v0/07-invariants-and-conformance.md",
)

EXPLICIT_PLAN_BLOB_PINS = {
    "build_closure_git_blob": "build_closure_registry_path",
    "build_closure_validator_git_blob": "build_closure_validator_path",
    "workspace_manifest_git_blob": "workspace_manifest_path",
    "workspace_lock_git_blob": "workspace_lock_path",
    "codeowners_git_blob": "codeowners_path",
    "module_registry_git_blob": "module_registry_path",
    "module_coverage_git_blob": "module_coverage_path",
    "module_technical_reference_git_blob": "module_technical_reference_path",
    "technical_convergence_git_blob": "technical_convergence_path",
    "technical_convergence_gate_git_blob": "technical_convergence_gate_path",
    "technical_convergence_test_git_blob": "technical_convergence_test_path",
    "detailed_module_spec_index_git_blob": "detailed_module_spec_index_path",
    "current_snapshot_git_blob": "current_snapshot_path",
    "documentation_truth_git_blob": "documentation_truth_path",
    "repository_policy_git_blob": "repository_policy_path",
    "blocker_execution_git_blob": "blocker_execution_path",
    "blocker_execution_validator_git_blob": "blocker_execution_validator_path",
    "candidate_runtime_closure_git_blob": "candidate_runtime_closure_path",
    "candidate_runtime_closure_validator_git_blob": "candidate_runtime_closure_validator_path",
    "candidate_runtime_closure_architecture_git_blob": "candidate_runtime_closure_architecture_path",
    "task_archive_closure_git_blob": "task_archive_closure_path",
    "task_archive_closure_validator_git_blob": "task_archive_closure_validator_path",
    "task_archive_closure_architecture_git_blob": "task_archive_closure_architecture_path",
    "documentation_reference_gate_git_blob": "documentation_reference_gate_path",
    "module_coverage_gate_git_blob": "module_coverage_gate_path",
    "canonical_plan_gate_git_blob": "canonical_plan_gate_path",
    "node_decomposition_git_blob": "node_decomposition_path",
    "node_decomposition_gate_git_blob": "node_decomposition_gate_path",
    "required_baseline_workflow_git_blob": "required_baseline_workflow_path",
    "required_baseline_gate_git_blob": "required_baseline_gate_path",
    "plan_manifest_pin_gate_git_blob": "plan_manifest_pin_gate_path",
}


def run(*args: str) -> str:
    return subprocess.run(
        args, cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout.strip()


def replace_scalar(text: str, key: str, value: str) -> str:
    pattern = re.compile(rf'(?m)^({re.escape(key)}\s*=\s*")[^"]*("\s*)$')
    updated, count = pattern.subn(
        lambda match: match.group(1) + value + match.group(2), text
    )
    if count != 1:
        raise RuntimeError(f"{key}: expected one TOML scalar, found {count}")
    return updated


def prepare() -> None:
    purge = ROOT / "tools/temporary_native_purge.py"
    if not purge.is_file():
        raise RuntimeError("temporary native purge helper missing")
    subprocess.run(["python3", str(purge)], cwd=ROOT, check=True)

    restart = ROOT / "trillionnium/crates/trnm-poco-lab-validator/src/restart_catchup.rs"
    text = restart.read_text(encoding="utf-8")
    for stale in (
        '            include_str!("../../trnm-node/src/lib.rs"),\n',
        '            include_str!("../../trnm-node/src/main.rs"),\n',
    ):
        text = text.replace(stale, "")
    restart.write_text(text, encoding="utf-8")

    for path in (ROOT / "trillionnium").rglob("*.rs"):
        source = path.read_text(encoding="utf-8")
        # Retired application-path blocks must stay disabled. Converting them
        # to cfg(test) reactivates archived host/recovery modules during
        # --all-targets builds and violates the native-only cutover.
        updated = source.replace(
            'feature = "recovery-test-support"',
            'feature = "recovery-process-test-support"',
        )
        if updated != source:
            path.write_text(updated, encoding="utf-8")

    anchor = ROOT / "trillionnium/crates/trnm-consensus-types/src/anchor.rs"
    source = anchor.read_text(encoding="utf-8")
    if "pub struct GenesisQcV0" in source and not re.search(
        r"\bfn\s+validator_set_id\s*\(", source
    ):
        existing = """    pub const fn validator_set_hash(&self) -> ValidatorSetId {
        self.validator_set_hash
    }
"""
        if existing not in source:
            raise RuntimeError("GenesisQcV0 validator-set accessor shape drift")
        alias = existing + """
    /// Validator-set identity committed by this immutable genesis certificate.
    pub const fn validator_set_id(&self) -> ValidatorSetId {
        self.validator_set_hash
    }
"""
        anchor.write_text(source.replace(existing, alias, 1), encoding="utf-8")

    contract = ROOT / "scripts/ci/check_required_protocol_contract_v1.py"
    text = contract.read_text(encoding="utf-8")
    stale_package_check = """    require(
        not ({"crates/trnm-native-application", "crates/trnm-node"} & members),
        "legacy foreign packages re-entered the active workspace",
    )
"""
    text = text.replace(stale_package_check, "")
    stale_truth_check = """    baseline = read(".github/workflows/trnm-required-baseline.yml")
    legacy_truth = read("scripts/ci/check_poco_bft_v0_ci_truth.sh")
    require(
        "runs-on: [self-hosted" not in baseline,
        "required baseline must not depend on a self-hosted runner",
    )
    require(
        "require_literal" in legacy_truth,
        "legacy deep CI truth checker unexpectedly disappeared",
    )
    require(
        "check_poco_bft_v0_ci_truth.sh" not in baseline,
        "historical line-layout checker must not be a required merge dependency",
    )
"""
    native_truth_check = """    baseline = read(".github/workflows/trnm-required-baseline.yml")
    native_truth = read("scripts/ci/check_poco_bft_v0_ci_truth.sh")
    require(
        "runs-on: [self-hosted" not in baseline,
        "required baseline must not depend on a self-hosted runner",
    )
    require(
        "check_native_consensus_only.py" in native_truth
        and "trnm-native-ci-truth-v1" in native_truth,
        "native CI truth checker contract drift",
    )
    require(
        "check_poco_bft_v0_ci_truth.sh" not in baseline,
        "non-required deep CI checker must not become a required merge dependency",
    )
"""
    if stale_truth_check in text:
        text = text.replace(stale_truth_check, native_truth_check)
    elif "native CI truth checker contract drift" not in text:
        raise RuntimeError("required protocol checker has an unknown CI-truth shape")
    contract.write_text(text, encoding="utf-8")

    coverage = ROOT / "config/module-coverage-v1.toml"
    text = coverage.read_text(encoding="utf-8")
    old = '"docs/runbooks/TRNM_V3_TO_V4_EXPORT_NEW_GENESIS.md"'
    new = '"docs/architecture/TRNM_STATE_SYNC_STAGING_ADMISSION_V0.md"'
    if old in text:
        text = text.replace(old, new)
    elif new not in text:
        raise RuntimeError("M13 migration/state-sync contract path drift")
    coverage.write_text(text, encoding="utf-8")


def update_plan_hashes(value: object, plan_sha: str) -> None:
    if isinstance(value, dict):
        for key, child in list(value.items()):
            if (
                "plan" in str(key).lower()
                and "sha256" in str(key).lower()
                and isinstance(child, str)
                and re.fullmatch(r"[0-9a-f]{64}", child)
            ):
                value[key] = plan_sha
            else:
                update_plan_hashes(child, plan_sha)
    elif isinstance(value, list):
        for child in value:
            update_plan_hashes(child, plan_sha)


def refresh_path_digests(path: pathlib.Path) -> None:
    text = path.read_text(encoding="utf-8")
    parsed = tomllib.loads(text)
    for key, value in parsed.items():
        if not key.endswith("_path") or not isinstance(value, str):
            continue
        digest_key = key[:-5] + "_sha256"
        if digest_key not in parsed:
            continue
        target = ROOT / value
        if not target.is_file():
            raise RuntimeError(f"{path.relative_to(ROOT)}: missing digest target {value}")
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        text = replace_scalar(text, digest_key, digest)
    path.write_text(text, encoding="utf-8")
    tomllib.loads(text)


def refresh_frozen_v0_imports() -> dict[str, str]:
    """Rebind the retained PoCO-v0 kernel after explicit native-only wording edits."""
    imports = {relative: run("git", "hash-object", relative) for relative in V0_IMPORT_PATHS}

    registry_path = ROOT / "config/documentation-contracts-v1.json"
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    if set(registry.get("pcc1_v0_imports", {})) != set(imports):
        raise RuntimeError("documentation v0 import inventory drift")
    registry["pcc1_v0_imports"] = imports
    registry_path.write_text(
        json.dumps(registry, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    checker_path = ROOT / "scripts/ci/check_documentation_contracts_v1.py"
    checker = checker_path.read_text(encoding="utf-8")
    for relative, oid in imports.items():
        name = relative.rsplit("/", 1)[1]
        pattern = re.compile(
            rf"(_V0\+'{re.escape(name)}': ')[0-9a-f]{{40}}(')"
        )
        checker, count = pattern.subn(
            lambda match: match.group(1) + oid + match.group(2), checker
        )
        if count != 1:
            raise RuntimeError(f"documentation checker v0 pin drift: {name} ({count})")
    checker_path.write_text(checker, encoding="utf-8")

    convergence_path = ROOT / "docs/protocol/poco-convergence-v1/README.md"
    convergence = convergence_path.read_text(encoding="utf-8")
    for relative, oid in imports.items():
        name = relative.rsplit("/", 1)[1]
        pattern = re.compile(
            rf"(\| `{re.escape(name)}` \| `)[0-9a-f]{{40}}(` \|)"
        )
        convergence, count = pattern.subn(
            lambda match: match.group(1) + oid + match.group(2), convergence
        )
        if count != 1:
            raise RuntimeError(f"PCC1 v0 import table drift: {name} ({count})")
    convergence_path.write_text(convergence, encoding="utf-8")
    return imports


def refresh_manifest_blob_pins() -> int:
    """Refresh every explicit and regular path/blob binding in the manifest."""
    text = MANIFEST.read_text(encoding="utf-8")
    parsed = tomllib.loads(text)
    updated_fields: set[str] = set()

    # The canonical pin checker owns several deliberately non-isomorphic names
    # (for example build_closure_registry_path -> build_closure_git_blob).
    # These must be refreshed explicitly rather than inferred by suffix.
    for blob_field, path_field in EXPLICIT_PLAN_BLOB_PINS.items():
        relative = parsed.get(path_field)
        if not isinstance(relative, str) or not relative:
            raise RuntimeError(f"plan manifest missing {path_field}")
        if blob_field not in parsed:
            raise RuntimeError(f"plan manifest missing {blob_field}")
        target = ROOT / relative
        if not target.is_file():
            raise RuntimeError(f"plan manifest pinned path missing: {relative}")
        text = replace_scalar(text, blob_field, run("git", "hash-object", relative))
        updated_fields.add(blob_field)

    # Refresh additive regular pairs not yet part of the canonical checker.
    parsed = tomllib.loads(text)
    for path_field, relative in parsed.items():
        if not path_field.endswith("_path") or not isinstance(relative, str):
            continue
        blob_field = path_field[:-5] + "_git_blob"
        if blob_field not in parsed or blob_field in updated_fields:
            continue
        target = ROOT / relative
        if not target.is_file():
            raise RuntimeError(f"plan manifest pinned path missing: {relative}")
        text = replace_scalar(text, blob_field, run("git", "hash-object", relative))
        updated_fields.add(blob_field)

    MANIFEST.write_text(text, encoding="utf-8")
    tomllib.loads(text)
    return len(updated_fields)


def refresh_pins() -> None:
    plan_sha = hashlib.sha256(PLAN.read_bytes()).hexdigest()
    snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    update_plan_hashes(snapshot, plan_sha)
    SNAPSHOT.write_text(
        json.dumps(snapshot, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    imports = refresh_frozen_v0_imports()

    for relative in (
        "docs/development/release-train-v1.toml",
        "docs/development/plan-manifest-v1.toml",
    ):
        refresh_path_digests(ROOT / relative)

    pinned_blobs = refresh_manifest_blob_pins()
    text = MANIFEST.read_text(encoding="utf-8")
    manifest = tomllib.loads(text)
    evidence = ROOT / manifest["evidence_contract_path"]
    if manifest["plan_sha256"] != plan_sha:
        raise RuntimeError("plan digest did not converge")
    if manifest["evidence_contract_sha256"] != hashlib.sha256(
        evidence.read_bytes()
    ).hexdigest():
        raise RuntimeError("evidence-contract digest did not converge")
    print(
        json.dumps(
            {
                "plan_sha256": plan_sha,
                "pinned_blobs": pinned_blobs,
                "frozen_v0_imports": imports,
            },
            sort_keys=True,
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("prepare", "refresh-pins"))
    args = parser.parse_args()
    if args.action == "prepare":
        prepare()
    else:
        refresh_pins()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
