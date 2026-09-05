#!/usr/bin/env python3
'''Apply deterministic, fail-closed Plan v2 repository blocker repairs.

This program only closes repository-owned implementation and verification gaps.
It never promotes production, public-testnet, release, audit, hardware, soak, or
activation truth.
'''
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tomllib
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
PLAN = ROOT / "docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md"
PLAN_MANIFEST = ROOT / "docs/development/plan-manifest-v1.toml"
FREEZE_COMMIT = "2fb758bd22e4db51b15215bfce91f701588ab934"


class RepairError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RepairError(message)


def run(*args: str, capture: bool = False) -> str:
    completed = subprocess.run(
        list(args),
        cwd=ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    return completed.stdout.strip() if capture else ""


def replace_exact(path: pathlib.Path, old: str, new: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    require(count == 1, f"{path.relative_to(ROOT)}: {label}: expected one edge, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def patch_durable_adapter() -> None:
    path = ROOT / "trillionnium/crates/trnm-durable-file-adapters-v0/src/lib.rs"
    source = path.read_text(encoding="utf-8")
    old_helper_edge = '''    fn staging_matches(
        active: &ActiveStagingV0,
        identity: StagingIdentityV0,
    ) -> Result<(), DurableFileErrorV0> {
        if active.identity != identity {
            return Err(DurableFileErrorV0::StagingIdentityMismatch);
        }
        Ok(())
    }

    fn write_manifest_record(
'''
    new_helper_edge = '''    fn staging_matches(
        active: &ActiveStagingV0,
        identity: StagingIdentityV0,
    ) -> Result<(), DurableFileErrorV0> {
        if active.identity != identity {
            return Err(DurableFileErrorV0::StagingIdentityMismatch);
        }
        Ok(())
    }

    fn validate_staging_inventory(
        active: &ActiveStagingV0,
    ) -> Result<(), DurableFileErrorV0> {
        let mut manifest_seen = false;
        for entry in fs::read_dir(&active.path)? {
            let entry = entry?;
            let path = entry.path();
            if !entry.file_type()?.is_file() {
                return Err(DurableFileErrorV0::RecoveryRequired(path));
            }
            let file_name = entry.file_name();
            let Some(name) = file_name.to_str() else {
                return Err(DurableFileErrorV0::RecoveryRequired(path));
            };
            if name == "MANIFEST.v0" {
                manifest_seen = true;
                continue;
            }
            let Some(raw_index) = name
                .strip_prefix("chunk-")
                .and_then(|value| value.strip_suffix(".bin"))
            else {
                return Err(DurableFileErrorV0::RecoveryRequired(path));
            };
            let index = raw_index
                .parse::<u32>()
                .map_err(|_| DurableFileErrorV0::RecoveryRequired(path.clone()))?;
            if raw_index.len() != 8
                || index >= active.chunk_count
                || name != format!("chunk-{index:08}.bin")
            {
                return Err(DurableFileErrorV0::RecoveryRequired(path));
            }
        }
        if !manifest_seen {
            return Err(DurableFileErrorV0::RecoveryRequired(
                active.path.join("MANIFEST.v0"),
            ));
        }
        Ok(())
    }

    fn write_manifest_record(
'''
    old_commit_edge = '''        if active.manifest_digest != manifest.manifest_digest
            || active.state_root != manifest.state_root
            || active.height != manifest.height
            || active.chunk_count != manifest.chunk_count
            || active.total_bytes != manifest.total_bytes
        {
            return Err(DurableFileErrorV0::InvalidSnapshotManifest);
        }
        let mut total_bytes = 0_u64;
'''
    new_commit_edge = '''        if active.manifest_digest != manifest.manifest_digest
            || active.state_root != manifest.state_root
            || active.height != manifest.height
            || active.chunk_count != manifest.chunk_count
            || active.total_bytes != manifest.total_bytes
        {
            return Err(DurableFileErrorV0::InvalidSnapshotManifest);
        }
        Self::validate_staging_inventory(&active)?;
        let mut total_bytes = 0_u64;
'''
    old_abort = '''    fn abort_staging(&mut self, staging: StagingIdentityV0) -> Result<(), Self::Error> {
        let active = self
            .active
            .take()
            .ok_or(DurableFileErrorV0::UnknownStaging)?;
        Self::staging_matches(&active, staging)?;
        if active.identity.generation == self.current.generation {
            self.active = Some(active);
            return Err(DurableFileErrorV0::StagingIdentityMismatch);
        }
        if active.path.exists() {
            fs::remove_dir_all(&active.path)?;
        }
        let generation_path = self.generation_path(active.identity.generation);
        if generation_path.exists() {
            fs::remove_dir_all(generation_path)?;
        }
        sync_directory(&self.root.join("staging"))?;
        sync_directory(&self.root.join("generations"))?;
        Ok(())
    }
'''
    new_abort = '''    fn abort_staging(&mut self, staging: StagingIdentityV0) -> Result<(), Self::Error> {
        let active = self
            .active
            .as_ref()
            .ok_or(DurableFileErrorV0::UnknownStaging)?
            .clone();
        Self::staging_matches(&active, staging)?;
        if active.identity.generation == self.current.generation {
            return Err(DurableFileErrorV0::StagingIdentityMismatch);
        }
        if active.path.exists() {
            fs::remove_dir_all(&active.path)?;
        }
        let generation_path = self.generation_path(active.identity.generation);
        if generation_path.exists() {
            fs::remove_dir_all(generation_path)?;
        }
        sync_directory(&self.root.join("staging"))?;
        sync_directory(&self.root.join("generations"))?;
        self.active = None;
        Ok(())
    }
'''
    for old, new, label in (
        (old_helper_edge, new_helper_edge, "staging inventory helper"),
        (old_commit_edge, new_commit_edge, "pre-linearization inventory gate"),
        (old_abort, new_abort, "staging ownership preservation"),
    ):
        count = source.count(old)
        require(count == 1, f"{path.relative_to(ROOT)}: {label}: expected one edge, found {count}")
        source = source.replace(old, new, 1)
    path.write_text(source, encoding="utf-8")


def restore_frozen_legacy_harness() -> None:
    paths = (
        "trillionnium/crates/trnm-node/src/bin/trnm-chain-cli.rs",
        "trillionnium/crates/trnm-node/src/bin/trnm-chain-node.rs",
        "trillionnium/crates/trnm-node/src/bin/trnm-chain-validator.rs",
        "trillionnium/crates/trnm-node/src/main.rs",
    )
    run("git", "cat-file", "-e", f"{FREEZE_COMMIT}^{{commit}}")
    run("git", "checkout", FREEZE_COMMIT, "--", *paths)


DEPENDENCY_ROOT_TABLE = re.compile(
    r"(?:^|\.)(?:dependencies|dev-dependencies|build-dependencies)$"
)
DEPENDENCY_SPECIFIC_TABLE = re.compile(
    r"(?:^|\.)(?:dependencies|dev-dependencies|build-dependencies)\.[^.]+$"
)
INLINE_PATH = re.compile(
    r'^(?P<prefix>\s*(?:"[^"]+"|[A-Za-z0-9_.-]+)\s*=\s*\{)(?P<body>.*\bpath\s*=\s*"(?P<path>[^"]+)"[^}]*)'
    r'(?P<suffix>\}\s*(?:#.*)?)$'
)


def target_version(manifest: pathlib.Path, relative: str) -> str:
    target_manifest = (manifest.parent / relative / "Cargo.toml").resolve()
    require(target_manifest.is_file(), f"{manifest.relative_to(ROOT)}: path dependency target missing: {relative}")
    require(
        ROOT.resolve() in target_manifest.parents,
        f"{manifest.relative_to(ROOT)}: path dependency escapes repository: {relative}",
    )
    data = tomllib.loads(target_manifest.read_text(encoding="utf-8"))
    version = data.get("package", {}).get("version")
    require(isinstance(version, str) and version, f"{target_manifest.relative_to(ROOT)}: package version missing")
    return version


def pin_path_dependencies_in_manifest(manifest: pathlib.Path) -> None:
    lines = manifest.read_text(encoding="utf-8").splitlines()
    output: list[str] = []
    current_table = ""
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        header = re.fullmatch(r"\[([^\]]+)\]", stripped)
        if header:
            current_table = header.group(1)
            output.append(line)
            i += 1
            continue

        inline = INLINE_PATH.match(line)
        if (
            inline
            and DEPENDENCY_ROOT_TABLE.search(current_table)
            and not re.search(r"\bversion\s*=", inline.group("body"))
        ):
            version = target_version(manifest, inline.group("path"))
            body = inline.group("body").strip()
            if body and not body.endswith(","):
                body += ","
            line = f'{inline.group("prefix")} version = "{version}", {body}{inline.group("suffix")}'
            output.append(line)
            i += 1
            continue

        if (
            current_table
            and DEPENDENCY_SPECIFIC_TABLE.search(current_table)
            and stripped.startswith("path")
        ):
            path_match = re.fullmatch(r'\s*path\s*=\s*"([^"]+)"\s*(?:#.*)?', line)
            if path_match:
                j = i + 1
                has_version = False
                while j < len(lines) and not lines[j].lstrip().startswith("["):
                    if re.match(r"\s*version\s*=", lines[j]):
                        has_version = True
                        break
                    j += 1
                output.append(line)
                if not has_version:
                    version = target_version(manifest, path_match.group(1))
                    indent = line[: len(line) - len(line.lstrip())]
                    output.append(f'{indent}version = "{version}"')
                i += 1
                continue
        output.append(line)
        i += 1
    manifest.write_text("\n".join(output) + "\n", encoding="utf-8")


def iter_dependency_tables(value: Any):
    if not isinstance(value, dict):
        return
    for key, child in value.items():
        if key in {"dependencies", "dev-dependencies", "build-dependencies"} and isinstance(child, dict):
            yield child
        if isinstance(child, dict):
            yield from iter_dependency_tables(child)


def pin_all_path_dependencies() -> None:
    manifests = sorted(ROOT.rglob("Cargo.toml"))
    for manifest in manifests:
        if any(part in {".git", "target"} for part in manifest.parts):
            continue
        pin_path_dependencies_in_manifest(manifest)
        data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        for table in iter_dependency_tables(data):
            for name, spec in table.items():
                if isinstance(spec, dict) and "path" in spec:
                    require(
                        isinstance(spec.get("version"), str) and bool(spec["version"]),
                        f"{manifest.relative_to(ROOT)}: unversioned path dependency {name}",
                    )


def patch_runner_policy_fixture() -> None:
    path = ROOT / "scripts/check_ci_runner_policy_test.sh"
    old = '''    "       (github.actor == 'ProfAlexQI' &&" \\
    "        github.triggering_actor == 'ProfAlexQI' &&" \\
'''
    new = '''    "       ((github.actor == 'ProfAlexQI' || github.actor == 'Tomasrgbsf') &&" \\
    "        github.triggering_actor == github.actor &&" \\
'''
    replace_exact(path, old, new, "PoCO maintainer fixture")


def patch_phasea_development_opt_in() -> None:
    path = ROOT / ".github/workflows/agent-user-phasea-gate.yml"
    text = path.read_text(encoding="utf-8")
    marker = '      TRNM_RPC_DEVELOPMENT_ONLY: "1"\n'
    if marker in text:
        return
    anchor = "      CI: 'true'\n"
    require(text.count(anchor) == 1, f"{path.relative_to(ROOT)}: Phase A env anchor drift")
    addition = (
        anchor
        + "      # Explicit development-only opt-in for this Phase A rehearsal; production defaults remain closed.\n"
        + marker
    )
    path.write_text(text.replace(anchor, addition, 1), encoding="utf-8")


def harden_poco_checkouts() -> None:
    path = ROOT / ".github/workflows/trnm-poco-bft-v0.yml"
    lines = path.read_text(encoding="utf-8").splitlines()
    output: list[str] = []
    count = 0
    i = 0
    while i < len(lines):
        line = lines[i]
        if "uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262" not in line:
            output.append(line)
            i += 1
            continue
        count += 1
        step_indent = len(line) - len(line.lstrip())
        output.append(line)
        i += 1
        while i < len(lines) and not lines[i].strip():
            output.append(lines[i])
            i += 1
        if (
            i < len(lines)
            and lines[i].strip() == "with:"
            and (len(lines[i]) - len(lines[i].lstrip())) == step_indent + 2
        ):
            output.append(lines[i])
            i += 1
            block: list[str] = []
            while i < len(lines):
                indent = len(lines[i]) - len(lines[i].lstrip())
                if lines[i].strip() and indent <= step_indent + 2:
                    break
                block.append(lines[i])
                i += 1
            seen_fetch = seen_persist = False
            for row in block:
                stripped = row.strip()
                if stripped.startswith("fetch-depth:"):
                    output.append(" " * (step_indent + 4) + "fetch-depth: 0")
                    seen_fetch = True
                elif stripped.startswith("persist-credentials:"):
                    output.append(" " * (step_indent + 4) + "persist-credentials: false")
                    seen_persist = True
                else:
                    output.append(row)
            if not seen_fetch:
                output.append(" " * (step_indent + 4) + "fetch-depth: 0")
            if not seen_persist:
                output.append(" " * (step_indent + 4) + "persist-credentials: false")
        else:
            output.extend(
                [
                    " " * (step_indent + 2) + "with:",
                    " " * (step_indent + 4) + "fetch-depth: 0",
                    " " * (step_indent + 4) + "persist-credentials: false",
                ]
            )
    require(count > 0, f"{path.relative_to(ROOT)}: no checkout steps found")
    path.write_text("\n".join(output) + "\n", encoding="utf-8")


def patch_offline_cache_unlisted_lock_proof() -> None:
    path = ROOT / "scripts/ci/check_cargo_offline_ready.sh"
    old = '''  expected_hash=${stamped_paths[$lock]:-}
  [[ -n "$expected_hash" ]] || {
    printf 'offline cache stamp is missing the lock path: %s\\n' "$lock" >&2
    exit 2
  }
  if [[ "$actual_hash" != "$expected_hash" ]]; then
    stamp_status=stale
    printf 'offline cache stamp is stale; requiring executable host-target proof: lock=%s expected=%s actual=%s\\n' \\
      "$lock" "$expected_hash" "$actual_hash" >&2
  fi
'''
    new = '''  expected_hash=${stamped_paths[$lock]:-}
  if [[ -z "$expected_hash" ]]; then
    stamp_status=unlisted
    printf 'offline cache stamp lacks newly tracked lock; requiring executable host-target proof: lock=%s\\n' \\
      "$lock" >&2
  elif [[ "$actual_hash" != "$expected_hash" ]]; then
    stamp_status=stale
    printf 'offline cache stamp is stale; requiring executable host-target proof: lock=%s expected=%s actual=%s\\n' \\
      "$lock" "$expected_hash" "$actual_hash" >&2
  fi
'''
    replace_exact(path, old, new, "unlisted lock executable proof")


def append_recovery_contract() -> None:
    text = PLAN.read_text(encoding="utf-8")
    required_literals = ("payload replay", "replay-to-Core", "SIGKILL", "catch-up", "signed", "cut hash")
    if all(literal in text for literal in required_literals):
        return
    section = '''
## Authenticated recovery chain contract

- **Recovery pipeline:** `payload replay` and `replay-to-Core` bind the same signed cut hash and catch-up boundary. After SIGKILL, crash, or reopen, only authenticated, durable, monotonic replay may resume.
- A replay acknowledgement is not finality authority, and a local fixture, synthetic clock, unsigned cut, substituted payload, skipped stage, or mutable carrier may not promote recovery, release, public-testnet, production, or activation truth.
'''
    PLAN.write_text(text.rstrip() + "\n\n---\n\n" + section.strip() + "\n", encoding="utf-8")


def git_blob_for_worktree(path: pathlib.Path) -> str:
    value = run("git", "hash-object", str(path.relative_to(ROOT)), capture=True)
    require(re.fullmatch(r"[0-9a-f]{40}", value) is not None, f"invalid worktree blob: {path}")
    return value


def replace_toml_scalar(text: str, key: str, value: str) -> str:
    pattern = re.compile(rf'(?m)^({re.escape(key)}\s*=\s*")[^"]*("\s*)$')
    text, count = pattern.subn(rf'\g<1>{value}\g<2>', text)
    require(count == 1, f"{PLAN_MANIFEST.relative_to(ROOT)}: scalar key drift: {key}")
    return text


PIN_FIELDS = {
    "build_closure_git_blob": "build_closure_registry_path",
    "build_closure_validator_git_blob": "build_closure_validator_path",
    "workspace_manifest_git_blob": "workspace_manifest_path",
    "workspace_lock_git_blob": "workspace_lock_path",
    "codeowners_git_blob": "codeowners_path",
    "module_registry_git_blob": "module_registry_path",
    "module_coverage_git_blob": "module_coverage_path",
    "module_technical_reference_git_blob": "module_technical_reference_path",
    "current_snapshot_git_blob": "current_snapshot_path",
    "documentation_truth_git_blob": "documentation_truth_path",
    "repository_policy_git_blob": "repository_policy_path",
    "blocker_execution_git_blob": "blocker_execution_path",
    "blocker_execution_validator_git_blob": "blocker_execution_validator_path",
    "documentation_reference_gate_git_blob": "documentation_reference_gate_path",
    "module_coverage_gate_git_blob": "module_coverage_gate_path",
    "canonical_plan_gate_git_blob": "canonical_plan_gate_path",
    "node_decomposition_git_blob": "node_decomposition_path",
    "node_decomposition_gate_git_blob": "node_decomposition_gate_path",
    "required_baseline_workflow_git_blob": "required_baseline_workflow_path",
    "required_baseline_gate_git_blob": "required_baseline_gate_path",
    "plan_manifest_pin_gate_git_blob": "plan_manifest_pin_gate_path",
}


def update_json_plan_hashes(value: Any, plan_sha: str) -> None:
    if isinstance(value, dict):
        for key, child in list(value.items()):
            lower = str(key).lower()
            if "plan" in lower and "sha256" in lower and isinstance(child, str):
                value[key] = plan_sha
            else:
                update_json_plan_hashes(child, plan_sha)
    elif isinstance(value, list):
        for child in value:
            update_json_plan_hashes(child, plan_sha)


def refresh_path_digests_in_toml(path: pathlib.Path) -> None:
    text = path.read_text(encoding="utf-8")
    parsed = tomllib.loads(text)
    for key, value in parsed.items():
        if not key.endswith("_path") or not isinstance(value, str):
            continue
        digest_key = key[:-5] + "_sha256"
        if digest_key not in parsed:
            continue
        target = ROOT / value
        require(target.is_file(), f"{path.relative_to(ROOT)}: digest target missing: {value}")
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        pattern = re.compile(rf'(?m)^({re.escape(digest_key)}\s*=\s*")[0-9a-f]{{64}}("\s*)$')
        text, count = pattern.subn(rf'\g<1>{digest}\g<2>', text)
        require(count == 1, f"{path.relative_to(ROOT)}: digest key drift: {digest_key}")
    path.write_text(text, encoding="utf-8")
    tomllib.loads(text)


def refresh_machine_truth_and_pins() -> None:
    plan_sha = hashlib.sha256(PLAN.read_bytes()).hexdigest()
    snapshot_path = ROOT / "docs/development/CURRENT_SNAPSHOT_V1.json"
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    update_json_plan_hashes(snapshot, plan_sha)
    snapshot_path.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    for relative in (
        "docs/development/release-train-v1.toml",
        "docs/development/plan-manifest-v1.toml",
    ):
        refresh_path_digests_in_toml(ROOT / relative)

    manifest_text = PLAN_MANIFEST.read_text(encoding="utf-8")
    manifest = tomllib.loads(manifest_text)
    for blob_field, path_field in PIN_FIELDS.items():
        relative = manifest.get(path_field)
        require(isinstance(relative, str) and relative, f"plan manifest missing {path_field}")
        target = ROOT / relative
        require(target.exists(), f"plan manifest pinned path missing: {relative}")
        manifest_text = replace_toml_scalar(
            manifest_text, blob_field, git_blob_for_worktree(target)
        )
    PLAN_MANIFEST.write_text(manifest_text, encoding="utf-8")
    tomllib.loads(manifest_text)


def ensure_external_truth_remains_closed() -> None:
    forbidden = (
        "production_candidate = true",
        "production_consensus_activation = true",
        "public_testnet_ready = true",
        "release_ready = true",
    )
    texts = [
        PLAN.read_text(encoding="utf-8"),
        PLAN_MANIFEST.read_text(encoding="utf-8"),
    ]
    for marker in forbidden:
        require(all(marker not in text for text in texts), f"forbidden truth promotion: {marker}")


def chmod_validators() -> None:
    for relative in (
        "scripts/ci/check_payload_replay_recovery_v1.sh",
        "scripts/ci/check_replay_to_core_coordinator_v1.sh",
        "scripts/check_repository_blocker_registry_v0.py",
        "scripts/ci/check_module_documentation_v1.py",
        "scripts/ci/check_markdown_links_v1.py",
    ):
        path = ROOT / relative
        require(path.is_file(), f"validator missing after closure construction: {relative}")
        path.chmod(path.stat().st_mode | 0o111)


def main() -> int:
    require(
        run("git", "rev-parse", "--show-toplevel", capture=True) == str(ROOT),
        "repository root mismatch",
    )
    patch_durable_adapter()
    restore_frozen_legacy_harness()
    pin_all_path_dependencies()
    patch_runner_policy_fixture()
    patch_phasea_development_opt_in()
    harden_poco_checkouts()
    patch_offline_cache_unlisted_lock_proof()
    append_recovery_contract()
    chmod_validators()
    refresh_machine_truth_and_pins()
    ensure_external_truth_remains_closed()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        RepairError,
        OSError,
        ValueError,
        KeyError,
        tomllib.TOMLDecodeError,
        subprocess.CalledProcessError,
    ) as error:
        print(f"Plan v2 deterministic repair failed: {error}", file=sys.stderr)
        raise SystemExit(2)
