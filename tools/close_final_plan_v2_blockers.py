#!/usr/bin/env python3
'''Close the final repository-owned Plan v2 durable-adapter regressions.'''
from __future__ import annotations

import hashlib
import pathlib
import re
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
LIB = ROOT / "trillionnium/crates/trnm-durable-file-adapters-v0/src/lib.rs"
MANIFEST = ROOT / "docs/development/plan-manifest-v1.toml"


def replace_exact(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one source edge, found {count}")
    return source.replace(old, new, 1)


source = LIB.read_text(encoding="utf-8")
source = replace_exact(
    source,
    '''    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(path)?;
''',
    '''    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)?;
''',
    "lock file explicit non-truncation",
)
source = replace_exact(
    source,
    '''    if bytes.len() % AUTHORITY_RECORD_BYTES_V0 != 0 {
''',
    '''    if !bytes.len().is_multiple_of(AUTHORITY_RECORD_BYTES_V0) {
''',
    "authority journal exact-record divisibility",
)
source = replace_exact(
    source,
    '''        if active.manifest_digest != manifest.manifest_digest
            || active.state_root != manifest.state_root
            || active.height != manifest.height
            || active.chunk_count != manifest.chunk_count
            || active.total_bytes != manifest.total_bytes
        {
            return Err(DurableFileErrorV0::InvalidSnapshotManifest);
        }
        let mut total_bytes = 0_u64;
''',
    '''        if active.manifest_digest != manifest.manifest_digest
            || active.state_root != manifest.state_root
            || active.height != manifest.height
            || active.chunk_count != manifest.chunk_count
            || active.total_bytes != manifest.total_bytes
        {
            return Err(DurableFileErrorV0::InvalidSnapshotManifest);
        }

        // Fail closed on every staging namespace entry before the pointer
        // linearization point. Only the exact manifest plus the canonical,
        // contiguous chunk names declared by this staging owner are admissible.
        let mut manifest_seen = false;
        let mut chunk_entries = 0_u32;
        for entry in fs::read_dir(&active.path)? {
            let entry = entry?;
            let path = entry.path();
            if !entry.file_type()?.is_file() {
                return Err(DurableFileErrorV0::RecoveryRequired(path));
            }
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                return Err(DurableFileErrorV0::RecoveryRequired(path));
            };
            if name == "MANIFEST.v0" {
                manifest_seen = true;
                continue;
            }
            let Some(raw_index) = name
                .strip_prefix("chunk-")
                .and_then(|name| name.strip_suffix(".bin"))
            else {
                return Err(DurableFileErrorV0::RecoveryRequired(path));
            };
            if raw_index.len() != 8 {
                return Err(DurableFileErrorV0::RecoveryRequired(path));
            }
            let index = raw_index
                .parse::<u32>()
                .map_err(|_| DurableFileErrorV0::RecoveryRequired(path.clone()))?;
            if index >= active.chunk_count || format!("{index:08}") != raw_index {
                return Err(DurableFileErrorV0::RecoveryRequired(path));
            }
            chunk_entries = chunk_entries
                .checked_add(1)
                .ok_or(DurableFileErrorV0::SequenceOverflow)?;
        }
        if !manifest_seen || chunk_entries != active.chunk_count {
            return Err(DurableFileErrorV0::RecoveryRequired(active.path.clone()));
        }

        let mut total_bytes = 0_u64;
''',
    "staging namespace inventory",
)
source = replace_exact(
    source,
    '''    fn abort_staging(&mut self, staging: StagingIdentityV0) -> Result<(), Self::Error> {
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
''',
    '''    fn abort_staging(&mut self, staging: StagingIdentityV0) -> Result<(), Self::Error> {
        // Authenticate the caller against a retained owner snapshot before
        // mutating or consuming the live staging handle.
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
''',
    "staging owner retention",
)
LIB.write_text(source, encoding="utf-8")


PINNED = {
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


def git_blob_sha1(path: pathlib.Path) -> str:
    data = path.read_bytes()
    digest = hashlib.sha1(usedforsecurity=False)
    digest.update(f"blob {len(data)}\0".encode("ascii"))
    digest.update(data)
    return digest.hexdigest()


manifest_text = MANIFEST.read_text(encoding="utf-8")
manifest = tomllib.loads(manifest_text)
for blob_field, path_field in PINNED.items():
    relative = manifest.get(path_field)
    if (
        not isinstance(relative, str)
        or not relative
        or relative.startswith("/")
        or ".." in pathlib.Path(relative).parts
    ):
        raise SystemExit(f"{path_field}: invalid repository-relative path {relative!r}")
    target = ROOT / relative
    if not target.is_file():
        raise SystemExit(f"{path_field}: pinned file missing: {relative}")
    actual = git_blob_sha1(target)
    pattern = rf'(?m)^{re.escape(blob_field)} = "[0-9a-f]{{40}}"$'
    manifest_text, count = re.subn(
        pattern,
        f'{blob_field} = "{actual}"',
        manifest_text,
        count=1,
    )
    if count != 1:
        raise SystemExit(f"{blob_field}: expected exactly one manifest pin, found {count}")

MANIFEST.write_text(manifest_text, encoding="utf-8")
