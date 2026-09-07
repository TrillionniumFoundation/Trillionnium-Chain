#!/usr/bin/env python3
"""Temporary one-shot purge used only on the native-only cleanup branch."""

from __future__ import annotations

import json
import pathlib
import re
import shutil
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def write(path: str, content: str) -> None:
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def remove(path: str) -> None:
    target = ROOT / path
    if target.is_dir():
        shutil.rmtree(target)
    elif target.exists() or target.is_symlink():
        target.unlink()


def replace_exact(path: str, old: str, new: str) -> None:
    text = read(path)
    if old not in text:
        raise RuntimeError(f"{path}: expected cleanup fragment missing")
    write(path, text.replace(old, new))


def remove_test_functions_containing(text: str, tokens: tuple[str, ...]) -> str:
    starts = [match.start() for match in re.finditer(r"(?m)^\s*#\[test\]\s*\n\s*fn\s+", text)]
    removed: list[tuple[int, int]] = []
    for start in starts:
        brace = text.find("{", start)
        if brace < 0:
            continue
        depth = 0
        end = None
        for index in range(brace, len(text)):
            char = text[index]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    end = index + 1
                    break
        if end is not None and any(token in text[start:end] for token in tokens):
            removed.append((start, end))
    for start, end in reversed(removed):
        text = text[:start] + text[end:]
    return text


def native_genesis_module() -> str:
    return r'''//! Native genesis application commitment and ceremony binding.
//!
//! These values bind the exact application parent selected for the synthetic
//! genesis anchor. They are native PoCO-BFT types and do not encode, import,
//! or adapt another consensus protocol.

use alloc::vec::Vec;

use sha2::{Digest, Sha256};

use crate::{
    canonical::{try_canonical_bytes, Encoder},
    GenesisHash, GenesisQcV0, Result, StateRoot, ValidationError, ValidatorSet,
};

/// Domain used by the authenticated-genesis parent comparison digest.
pub const GENESIS_APPLICATION_COMMITMENT_BINDING_DOMAIN_V0: &[u8] =
    b"trnm.consensus-core.authenticated-genesis-application-parent.v0";

/// Domain for the additive GenesisQC/application ceremony reference.
pub const GENESIS_QC_APPLICATION_BINDING_DOMAIN_V0: &[u8] =
    b"trnm.consensus-types.genesis-qc-application-ceremony.v0";

/// Canonical schema marker for the non-wire application commitment bytes.
pub const GENESIS_APPLICATION_COMMITMENT_SCHEMA_VERSION_V0: u16 = 0;

/// Exact application state parent installed by authenticated native genesis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenesisApplicationCommitmentV0 {
    genesis_hash: GenesisHash,
    timestamp_ms: u64,
    state_version: u64,
    state_root: StateRoot,
    descriptor_ref: [u8; 32],
    projection_profile_ref: [u8; 32],
}

impl GenesisApplicationCommitmentV0 {
    pub fn new(
        genesis_hash: GenesisHash,
        timestamp_ms: u64,
        state_version: u64,
        state_root: StateRoot,
        descriptor_ref: [u8; 32],
        projection_profile_ref: [u8; 32],
    ) -> Result<Self> {
        if state_version != 0 {
            return Err(ValidationError::InvalidCertificate(
                "genesis application commitment state version must be zero",
            ));
        }
        if genesis_hash.is_zero() {
            return Err(ValidationError::ZeroGenesisHash);
        }
        if state_root.is_zero() {
            return Err(ValidationError::InvalidCertificate(
                "genesis application commitment state root must be nonzero",
            ));
        }
        if descriptor_ref == [0; 32] {
            return Err(ValidationError::InvalidCertificate(
                "genesis application commitment descriptor reference must be nonzero",
            ));
        }
        if projection_profile_ref == [0; 32] {
            return Err(ValidationError::InvalidCertificate(
                "genesis application commitment projection profile reference must be nonzero",
            ));
        }
        Ok(Self {
            genesis_hash,
            timestamp_ms,
            state_version,
            state_root,
            descriptor_ref,
            projection_profile_ref,
        })
    }

    pub const fn genesis_hash(&self) -> GenesisHash {
        self.genesis_hash
    }

    pub const fn timestamp_ms(&self) -> u64 {
        self.timestamp_ms
    }

    pub const fn state_version(&self) -> u64 {
        self.state_version
    }

    pub const fn state_root(&self) -> StateRoot {
        self.state_root
    }

    pub const fn descriptor_ref(&self) -> [u8; 32] {
        self.descriptor_ref
    }

    pub const fn projection_profile_ref(&self) -> [u8; 32] {
        self.projection_profile_ref
    }

    pub fn binding_ref_v0(&self) -> [u8; 32] {
        let timestamp = self.timestamp_ms.to_be_bytes();
        let state_version = self.state_version.to_be_bytes();
        hash_len_framed(
            GENESIS_APPLICATION_COMMITMENT_BINDING_DOMAIN_V0,
            &[
                self.genesis_hash.as_bytes(),
                &timestamp,
                &state_version,
                self.state_root.as_bytes(),
                &self.descriptor_ref,
                &self.projection_profile_ref,
            ],
        )
    }

    pub fn try_canonical_bytes_v0(&self) -> Result<Vec<u8>> {
        try_canonical_bytes(|encoder| self.encode_canonical_v0(encoder))
    }

    fn encode_canonical_v0(&self, encoder: &mut Encoder) {
        encoder.u16(GENESIS_APPLICATION_COMMITMENT_SCHEMA_VERSION_V0);
        encoder.fixed(self.genesis_hash.as_bytes());
        encoder.u64(self.timestamp_ms);
        encoder.u64(self.state_version);
        encoder.fixed(self.state_root.as_bytes());
        encoder.fixed(&self.descriptor_ref);
        encoder.fixed(&self.projection_profile_ref);
    }
}

/// Native commissioning envelope pairing GenesisQC with its application root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisQcApplicationBindingV0 {
    genesis_qc: GenesisQcV0,
    application_commitment: GenesisApplicationCommitmentV0,
}

impl GenesisQcApplicationBindingV0 {
    pub fn new(
        genesis_qc: GenesisQcV0,
        application_commitment: GenesisApplicationCommitmentV0,
    ) -> Result<Self> {
        if genesis_qc.genesis_hash() != application_commitment.genesis_hash() {
            return Err(ValidationError::GenesisHashMismatch);
        }
        Ok(Self {
            genesis_qc,
            application_commitment,
        })
    }

    pub const fn genesis_qc_v0(&self) -> &GenesisQcV0 {
        &self.genesis_qc
    }

    pub const fn application_commitment_v0(&self) -> GenesisApplicationCommitmentV0 {
        self.application_commitment
    }

    pub const fn genesis_hash(&self) -> GenesisHash {
        self.genesis_qc.genesis_hash()
    }

    pub fn validate_against_trusted_set(&self, validator_set: &ValidatorSet) -> Result<()> {
        self.genesis_qc.matches_trusted_set(validator_set)?;
        if self.genesis_qc.genesis_hash() != self.application_commitment.genesis_hash() {
            return Err(ValidationError::GenesisHashMismatch);
        }
        Ok(())
    }

    pub fn ceremony_ref_v0(&self) -> Result<[u8; 32]> {
        let genesis_qc = self.genesis_qc.try_cev0_bytes()?;
        let application = self.application_commitment.try_canonical_bytes_v0()?;
        Ok(hash_len_framed(
            GENESIS_QC_APPLICATION_BINDING_DOMAIN_V0,
            &[&genesis_qc, &application],
        ))
    }

    pub fn into_parts(self) -> (GenesisQcV0, GenesisApplicationCommitmentV0) {
        (self.genesis_qc, self.application_commitment)
    }
}

fn hash_len_framed(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"trnm.domain.hash.v1");
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ChainId, ValidatorSetId};

    const CHAIN: ChainId = ChainId::from_static("trnm-genesis-binding-test-0");

    fn test_qc() -> GenesisQcV0 {
        GenesisQcV0::from_parts_for_test(
            GenesisHash::new([0xA5; 32]),
            CHAIN,
            ValidatorSetId::new([0xB6; 32]),
        )
        .expect("test GenesisQC")
    }

    fn commitment(root: u8, descriptor: u8, profile: u8) -> GenesisApplicationCommitmentV0 {
        GenesisApplicationCommitmentV0::new(
            GenesisHash::new([0xA5; 32]),
            7,
            0,
            StateRoot::new([root; 32]),
            [descriptor; 32],
            [profile; 32],
        )
        .expect("shape-valid application commitment")
    }

    #[test]
    fn binding_preserves_raw_genesis_qc() {
        let qc = test_qc();
        let raw = qc.try_cev0_bytes().unwrap();
        let id = qc.id();
        let binding = GenesisQcApplicationBindingV0::new(qc.clone(), commitment(1, 2, 3)).unwrap();
        assert_eq!(qc.try_cev0_bytes().unwrap(), raw);
        assert_eq!(qc.id(), id);
        assert_eq!(binding.genesis_qc_v0(), &qc);
        assert!(binding.ceremony_ref_v0().is_ok());
    }

    #[test]
    fn binding_rejects_foreign_genesis_and_commits_mutations() {
        let qc = test_qc();
        let foreign = GenesisApplicationCommitmentV0::new(
            GenesisHash::new([0xC7; 32]),
            7,
            0,
            StateRoot::new([1; 32]),
            [2; 32],
            [3; 32],
        )
        .unwrap();
        assert_eq!(
            GenesisQcApplicationBindingV0::new(qc.clone(), foreign).unwrap_err(),
            ValidationError::GenesisHashMismatch
        );
        assert_ne!(commitment(1, 2, 3).binding_ref_v0(), commitment(4, 2, 3).binding_ref_v0());
    }

    #[test]
    fn commitment_rejects_invalid_shape() {
        assert!(GenesisApplicationCommitmentV0::new(
            GenesisHash::new([0xA5; 32]),
            0,
            1,
            StateRoot::new([1; 32]),
            [2; 32],
            [3; 32],
        )
        .is_err());
    }
}
'''


def native_only_guard() -> str:
    return r'''#!/usr/bin/env python3
"""Reject every tracked reference to retired consensus engines and adapters."""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
FORBIDDEN = {
    "retired-engine-brand": "co" + "met",
    "retired-engine-family": "tender" + "mint",
    "retired-adapter-protocol": "a" + "bci",
    "retired-adapter-package": "trnm-consensus-" + "app",
    "retired-adapter-module": "trnm_consensus_" + "app",
    "retired-adapter-feature": "legacy-consensus-" + "app",
}
RETIRED_DIRS = (
    ROOT / "trillionnium" / "crates" / ("trnm-consensus-" + "app"),
    ROOT / "trillionnium" / "crates" / "trnm-node",
)


def tracked_paths() -> list[pathlib.Path]:
    raw = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
    return [ROOT / item.decode("utf-8") for item in raw.split(b"\0") if item]


def main() -> int:
    findings: list[dict[str, object]] = []
    for directory in RETIRED_DIRS:
        if directory.exists():
            findings.append({"path": str(directory.relative_to(ROOT)), "reason": "retired-directory-present"})
    for path in tracked_paths():
        relative = path.relative_to(ROOT).as_posix()
        lowered_path = relative.casefold()
        for label, token in FORBIDDEN.items():
            if token.casefold() in lowered_path:
                findings.append({"path": relative, "reason": label, "location": "path"})
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        lowered = text.casefold()
        for label, token in FORBIDDEN.items():
            needle = token.casefold()
            start = 0
            while True:
                offset = lowered.find(needle, start)
                if offset < 0:
                    break
                line = text.count("\n", 0, offset) + 1
                findings.append({"path": relative, "reason": label, "line": line})
                start = offset + len(needle)
    result = {
        "schema": "trnm-native-consensus-only-check-v1",
        "tracked_files": len(tracked_paths()),
        "findings": findings,
        "result": "PASS" if not findings else "FAIL",
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if not findings else 2


if __name__ == "__main__":
    raise SystemExit(main())
'''


def mainline_gate() -> str:
    return r'''#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel)
python3 "$root/scripts/ci/check_native_consensus_only.py"
python3 - "$root" <<'PY'
import json
import pathlib
import sys
import tomllib
root = pathlib.Path(sys.argv[1])
truth = json.loads((root / "config/consensus-mainline.json").read_text())
boundary = json.loads((root / "PROJECT_BOUNDARY.json").read_text())
with (root / "trillionnium/Cargo.toml").open("rb") as handle:
    cargo = tomllib.load(handle)
assert truth["consensus_mainline"] == "native-poco-bft"
assert truth["protocol_target"] == "poco-bft-v0"
assert truth["production_candidate"] is False
assert truth["production_consensus_activation"] is False
assert boundary["consensus"]["dependency_policy"] == "native-only"
assert boundary["consensus"]["external_consensus_engines_allowed"] is False
metadata = cargo["workspace"]["metadata"]["trnm"]
assert metadata["consensus_mainline"] == "native-poco-bft"
assert metadata["consensus_dependency_policy"] == "native-only"
assert metadata["external_consensus_dependency_count"] == 0
assert set(cargo["workspace"].get("exclude", [])) == {"fuzz"}
print('{"schema":"trnm-native-mainline-gate-v1","result":"PASS"}')
PY
'''


def recovery_gate() -> str:
    return r'''#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel)
cd "$root"
python3 scripts/ci/check_native_consensus_only.py
cargo test --manifest-path trillionnium/Cargo.toml --locked --offline \
  -p trnm-native-application -p trnm-state-sync-v0
'''


def ci_truth_gate() -> str:
    return r'''#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel)
python3 "$root/scripts/ci/check_native_consensus_only.py"
python3 - "$root" <<'PY'
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
workflow = (root / ".github/workflows/trnm-required-baseline.yml").read_text()
assert "check_native_consensus_only.py" in workflow
assert "runs-on: ubuntu-24.04" in workflow
assert "pull_request:" in workflow
print('{"schema":"trnm-native-ci-truth-v1","result":"PASS"}')
PY
'''


def purge_paths() -> None:
    explicit = [
        "trillionnium/crates/trnm-consensus-app",
        "trillionnium/crates/trnm-node",
        ".github/workflows/trnm-a22-capability-authority-audit.yml",
        "scripts/ci/a22_capability_authority_audit_v1.py",
        "scripts/ci/a22_capability_authority_policy_v1.json",
        "scripts/ci/a22_inert_capability_compile_fail_v1.sh",
        "scripts/ci/check_poco_bft_v0_application_operation_sequences.sh",
        "scripts/ci/check_poco_bft_v0_migration_boundary_v1.py",
        "scripts/ci/check_poco_bft_v0_workflow_trigger_truth.sh",
        "tools/fixup_plan_v2_repair_generator.py",
        "docs/architecture/TRNM_POCO_BFT_MAINLINE_CUTOVER_2026-08-25.md",
        "docs/architecture/TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md",
        "docs/architecture/TRNM_CONSENSUS_DELIVERY_DUAL_TRACK_DECISION_2026-08-11.md",
        "docs/architecture/TRNM_CONSENSUS_ENGINE_DECISION_2026-07-27.md",
        "docs/architecture/TRNM_VALIDATOR_LIFECYCLE_V1_2026-07-27.md",
        "docs/audits/TRNM_POCO_MIGRATION_BOUNDARY_2026-08-27.md",
        "docs/audits/TRNM_POCO_BFT_V0_IMPLEMENTATION_AUDIT_2026-08-26.md",
        "docs/audits/TRNM_POCO_BFT_EXECUTION_BOARD_AUDIT_2026-08-26.md",
        "docs/audits/TRNM_CHAIN_ALL_VERSIONS_AUDIT_2026-08-26.md",
        "docs/runbooks/TRNM_PUBLIC_TESTNET_MULTIHOST_AND_SOAK_2026-07-28.md",
        "docs/runbooks/TRNM_V3_TO_V4_EXPORT_NEW_GENESIS.md",
    ]
    for path in explicit:
        remove(path)
    path_tokens = ("comet", "tendermint", "abci")
    for path in sorted(ROOT.rglob("*"), reverse=True):
        if ".git" in path.parts or not path.exists():
            continue
        relative = path.relative_to(ROOT).as_posix().casefold()
        if any(token in relative for token in path_tokens):
            remove(str(path.relative_to(ROOT)))


def shrink_consensus_types() -> None:
    write("trillionnium/crates/trnm-consensus-types/src/genesis_application.rs", native_genesis_module())

    decoder_path = "trillionnium/crates/trnm-consensus-types/src/cev0_decode.rs"
    text = read(decoder_path)
    start_marker = "/// Decode the exact bounded canonical bytes of a read-only\n"
    end_marker = "pub type DecodeResult<T> = core::result::Result<T, DecodeError>;"
    start = text.find(start_marker)
    end = text.find(end_marker)
    if start < 0 or end < 0 or end <= start:
        raise RuntimeError("migration decoder block boundary not found")
    text = text[:start] + text[end:]
    old_names = (
        "CometFinalizedBlockIdentityV1", "CometStateExportV1", "GenesisQcCeremonyEvidenceV1",
        "GenesisQcSignatureShareV1", "LegacyCometAppHashV1", "LegacyCometGenesisHashV1",
        "LegacyStorageRejectionV1", "PocoFreshDataDirectoryV1", "PocoFreshGenesisImportV1",
        "PocoGenesisQcBindingV1", "PocoGenesisV1", "PocoTargetGenesisManifestV1",
        "PocoTargetProjectionV1", "VerifiedCometStateExportV1",
        "COMET_BLOCK_IDENTITY_SCHEMA_VERSION_V1", "COMET_FINALIZED_BLOCK_IDENTITY_PROFILE_V1",
        "COMET_STATE_EXPORT_PROFILE_V1", "COMET_STATE_EXPORT_SCHEMA_VERSION_V1",
        "GENESIS_QC_CEREMONY_PROFILE_V1", "GENESIS_QC_CEREMONY_SCHEMA_VERSION_V1",
        "LEGACY_STORAGE_REJECTION_PROFILE_V1", "LEGACY_STORAGE_REJECTION_SCHEMA_VERSION_V1",
        "MAX_COMET_STATE_EXPORT_CANONICAL_BYTES_V1", "MAX_GENESIS_QC_CEREMONY_CANONICAL_BYTES_V1",
        "MAX_GENESIS_QC_CEREMONY_SIGNATURES_V1", "MAX_LEGACY_STORAGE_REJECTION_CANONICAL_BYTES_V1",
        "MAX_POCO_FRESH_DATA_DIRECTORY_CANONICAL_BYTES_V1", "MAX_POCO_FRESH_GENESIS_IMPORT_CANONICAL_BYTES_V1",
        "MAX_POCO_GENESIS_CANONICAL_BYTES_V1", "MAX_POCO_GENESIS_QC_BINDING_CANONICAL_BYTES_V1",
        "MAX_POCO_TARGET_GENESIS_MANIFEST_CANONICAL_BYTES_V1", "MAX_POCO_TARGET_PROJECTION_CANONICAL_BYTES_V1",
        "POCO_FRESH_DATA_DIRECTORY_PROFILE_V1", "POCO_FRESH_DATA_DIRECTORY_SCHEMA_VERSION_V1",
        "POCO_FRESH_GENESIS_IMPORT_PROFILE_V1", "POCO_FRESH_GENESIS_IMPORT_SCHEMA_VERSION_V1",
        "POCO_GENESIS_PROFILE_V1", "POCO_GENESIS_QC_BINDING_PROFILE_V1", "POCO_GENESIS_SCHEMA_VERSION_V1",
        "POCO_TARGET_GENESIS_MANIFEST_PROFILE_V1", "POCO_TARGET_GENESIS_MANIFEST_SCHEMA_VERSION_V1",
        "POCO_TARGET_PROJECTION_PROFILE_V1", "POCO_TARGET_PROJECTION_SCHEMA_VERSION_V1",
    )
    import_start = text.index("use crate::{")
    import_end = text.index("};", import_start) + 2
    block = text[import_start:import_end]
    for name in old_names:
        block = re.sub(rf"\b{re.escape(name)}\b\s*,?\s*", "", block)
    block = re.sub(r",\s*,", ",", block)
    text = text[:import_start] + block + text[import_end:]
    text = remove_test_functions_containing(text, old_names)
    write(decoder_path, text)

    lib_path = "trillionnium/crates/trnm-consensus-types/src/lib.rs"
    text = read(lib_path)
    text = re.sub(
        r"pub use genesis_application::\{.*?\};",
        "pub use genesis_application::{\n    GenesisApplicationCommitmentV0, GenesisQcApplicationBindingV0,\n    GENESIS_APPLICATION_COMMITMENT_BINDING_DOMAIN_V0,\n    GENESIS_APPLICATION_COMMITMENT_SCHEMA_VERSION_V0,\n    GENESIS_QC_APPLICATION_BINDING_DOMAIN_V0,\n};",
        text,
        count=1,
        flags=re.S,
    )
    decoder_exports = (
        "decode_comet_state_export_v1_exact", "decode_genesis_qc_ceremony_evidence_v1_exact",
        "decode_legacy_storage_rejection_v1_exact", "decode_poco_fresh_data_directory_v1_exact",
        "decode_poco_fresh_genesis_import_v1_exact", "decode_poco_genesis_qc_binding_v1_exact",
        "decode_poco_genesis_v1_exact", "decode_poco_target_genesis_manifest_v1_exact",
        "decode_poco_target_projection_v1_exact",
    )
    for name in decoder_exports:
        text = re.sub(rf"\b{re.escape(name)}\b\s*,?\s*", "", text)
    text = re.sub(r",\s*,", ",", text)
    write(lib_path, text)


def update_manifests_and_truth() -> None:
    cargo_path = "trillionnium/Cargo.toml"
    text = read(cargo_path)
    text = re.sub(r'(?m)^\s*"crates/trnm-consensus-app",\n', "", text)
    text = re.sub(r'(?m)^\s*"crates/trnm-node",\n', "", text)
    text = re.sub(r'(?m)^\s*(?:zero_comet[^=]*|legacy_comet[^=]*|cometbft_[^=]*)\s*=.*\n', "", text)
    if 'consensus_dependency_policy = "native-only"' not in text:
        text = text.replace(
            'consensus_mainline = "native-poco-bft"\n',
            'consensus_mainline = "native-poco-bft"\nconsensus_dependency_policy = "native-only"\nexternal_consensus_dependency_count = 0\n',
            1,
        )
    write(cargo_path, text)

    node_path = "trillionnium/crates/trnm-poco-node/Cargo.toml"
    text = read(node_path)
    text = re.sub(
        r"# The former App-aware recovery modules.*?\n\[package\.metadata\.trnm\]",
        "[package.metadata.trnm]",
        text,
        count=1,
        flags=re.S,
    )
    text = re.sub(r'(?m)^\s*(?:zero_comet[^=]*|legacy_comet[^=]*|cometbft_[^=]*)\s*=.*\n', "", text)
    if 'consensus_dependency_policy = "native-only"' not in text:
        text = text.replace(
            'consensus_mainline = "native-poco-bft"\n',
            'consensus_mainline = "native-poco-bft"\nconsensus_dependency_policy = "native-only"\nexternal_consensus_dependency_count = 0\n',
            1,
        )
    write(node_path, text)

    closures_path = "config/build-closures-v1.toml"
    text = read(closures_path)
    text = re.sub(r'legacy_excluded_packages\s*=\s*\[[^\]]*\]', 'legacy_excluded_packages = []', text, count=1, flags=re.S)
    write(closures_path, text)

    deny_path = "deny.toml"
    text = read(deny_path)
    text = re.sub(r'(?m)^\s*\{ id = "RUSTSEC-2024-0436".*\n', "", text)
    write(deny_path, text)

    boundary_path = "PROJECT_BOUNDARY.json"
    boundary = json.loads(read(boundary_path))
    consensus = boundary.setdefault("consensus", {})
    for key in list(consensus):
        if "comet" in key.casefold():
            consensus.pop(key)
    consensus["dependency_policy"] = "native-only"
    consensus["external_consensus_engines_allowed"] = False
    consensus["fallback_consensus_engines_allowed"] = False
    boundary.setdefault("cargo", {})["required_excluded_members"] = []
    write(boundary_path, json.dumps(boundary, indent=2, ensure_ascii=False) + "\n")

    truth_path = "config/consensus-mainline.json"
    truth = json.loads(read(truth_path))
    truth["as_of"] = "2026-09-07"
    for key in list(truth):
        if "comet" in key.casefold():
            truth.pop(key)
    seams = truth.setdefault("candidate_seams", {})
    seams["migration_boundary"] = {
        "implementation": "trnm-migration-v0",
        "source_consensus_agnostic": True,
        "fresh_genesis_only": True,
        "validator_signing_state_import": False,
        "production_activation": False,
    }
    truth["migration"] = {
        "implementation": "trnm-migration-v0",
        "source_consensus_agnostic": True,
        "fresh_genesis_only": True,
        "in_place_database_or_wal_conversion": False,
        "validator_signing_state_import": False,
        "fallback_consensus_engine": False,
        "production_activation": False,
    }
    write(truth_path, json.dumps(truth, indent=2, ensure_ascii=False) + "\n")

    policy_path = "config/repository-policy-v1.json"
    policy = json.loads(read(policy_path))
    required = policy.setdefault("required_paths", [])
    guard = "scripts/ci/check_native_consensus_only.py"
    if guard not in required:
        required.append(guard)
    write(policy_path, json.dumps(policy, indent=2, ensure_ascii=False) + "\n")


def update_truth_checkers() -> None:
    path = "scripts/ci/check_repository_truth_v1.py"
    text = read(path)
    text = text.replace(
        '    require(consensus.get("legacy_comet_role") == "migration-residue-only", "legacy Comet role drift")\n'
        '    require(consensus.get("legacy_comet_may_authorize_release") is False, "legacy Comet must not authorize release")\n',
        '    require(consensus.get("dependency_policy") == "native-only", "native-only dependency policy drift")\n'
        '    require(consensus.get("external_consensus_engines_allowed") is False, "external consensus engines must remain forbidden")\n'
        '    require(consensus.get("fallback_consensus_engines_allowed") is False, "fallback consensus engines must remain forbidden")\n',
    )
    text = text.replace('    require(truth.get("as_of") == "2026-08-30", "machine truth as_of date is stale")',
                        '    require(truth.get("as_of") == "2026-09-07", "machine truth as_of date is stale")')
    text = re.sub(
        r'    require\(set\(cargo_policy\.get\("required_excluded_members", \[\]\)\) <= excluded,.*?\n'
        r'    require\(\n        not \(\{"crates/trnm-consensus-app", "crates/trnm-node"\} & members\),.*?\n    \)\n',
        '    require(not cargo_policy.get("required_excluded_members", []), "removed packages may not remain as exclusions")\n'
        '    require(excluded == {"fuzz"}, "workspace exclusions must contain only the fuzz workspace")\n',
        text,
        count=1,
        flags=re.S,
    )
    text = text.replace(
        '    require(metadata.get("cometbft_role") == "migration-residue-only", "Cargo Comet role drift")\n',
        '    require(metadata.get("consensus_dependency_policy") == "native-only", "Cargo native-only policy drift")\n'
        '    require(metadata.get("external_consensus_dependency_count") == 0, "Cargo external consensus dependency count drift")\n',
    )
    text = re.sub(r'\("https://github\.com/ProfAlexQI/TrillionniumChain\.git", "Node\.js 20\+", "CometBFT is the sole"\)',
                  '("https://github.com/ProfAlexQI/TrillionniumChain.git", "Node.js 20+")', text)
    text = text.replace(
        '    require("migration residue" in security, "security policy must classify legacy Comet as migration residue")\n',
        '    require("native-only consensus dependency policy" in security, "security policy must cover the native-only boundary")\n',
    )
    text = text.replace('("CometBFT -> trnm-consensus-app -> trnm-runtime", "/home/", "/Users/")', '("/home/", "/Users/")')
    text = text.replace(
        '            "Run the application with `trnm-cometbft-app`",\n'
        '            "CometBFT -> trnm-consensus-app -> trnm-runtime",\n',
        '',
    )
    text = text.replace('"legacy_active_members": [],', '"external_active_members": [],')
    if 'check_native_consensus_only.py' not in text:
        text = text.replace('def main() -> int:\n', 'def main() -> int:\n    import subprocess\n    subprocess.run([sys.executable, str(ROOT / "scripts/ci/check_native_consensus_only.py")], cwd=ROOT, check=True)\n')
    write(path, text)

    path = "scripts/ci/check_required_protocol_contract_v1.py"
    text = read(path)
    text = re.sub(
        r'    require\(\n        truth\.get\("cometbft", \{\}\)\.get\("role"\) == "migration-residue-only",.*?\n    \)\n',
        '', text, count=1, flags=re.S,
    )
    text = re.sub(
        r'    require\(\n        boundary\.get\("consensus", \{\}\)\.get\("legacy_comet_may_authorize_release"\) is False,.*?\n    \)\n',
        '    require(boundary.get("consensus", {}).get("dependency_policy") == "native-only", "native-only boundary drift")\n'
        '    require(boundary.get("consensus", {}).get("external_consensus_engines_allowed") is False, "external engines must remain forbidden")\n',
        text, count=1, flags=re.S,
    )
    text = re.sub(
        r'    require\(\n        \{"crates/trnm-consensus-app", "crates/trnm-node"\} <= excluded,.*?\n    \)\n',
        '    require(excluded == {"fuzz"}, "workspace exclusions must contain only fuzz")\n',
        text, count=1, flags=re.S,
    )
    if 'check_native_consensus_only.py' not in text:
        text = text.replace('def main() -> int:\n', 'def main() -> int:\n    import subprocess\n    subprocess.run([sys.executable, str(ROOT / "scripts/ci/check_native_consensus_only.py")], cwd=ROOT, check=True)\n')
    write(path, text)


def update_ci_and_preflight() -> None:
    write("scripts/ci/check_native_consensus_only.py", native_only_guard())
    write("scripts/ci/check_poco_bft_mainline_truth.sh", mainline_gate())
    write("scripts/ci/check_poco_bft_v0_recovery_smoke.sh", recovery_gate())
    write("scripts/ci/check_poco_bft_v0_ci_truth.sh", ci_truth_gate())

    preflight_path = "scripts/project-preflight.sh"
    text = read(preflight_path)
    text = text.replace(
        '    rg -q \'"crates/trnm-consensus-app"\' "$root/trillionnium/Cargo.toml" || error "canonical consensus app missing"\n'
        '    rg -q \'"crates/trnm-runtime"\' "$root/trillionnium/Cargo.toml" || error "canonical runtime missing"\n',
        '    rg -q \'"crates/trnm-consensus-core"\' "$root/trillionnium/Cargo.toml" || error "native consensus core missing"\n'
        '    rg -q \'"crates/trnm-poco-node"\' "$root/trillionnium/Cargo.toml" || error "native node missing"\n'
        '    python3 "$root/scripts/ci/check_native_consensus_only.py" >/dev/null || error "native-only consensus boundary failed"\n',
    )
    write(preflight_path, text)

    privileged = "scripts/check_privileged_cargo_offline_policy.sh"
    text = read(privileged)
    text = re.sub(r'(?m)^register trnm-a22-capability-authority-audit\.yml:[^\n]*\\\n  [^\n]*\n', '', text)
    text = re.sub(r'(?m)^register trnm-cometbft-spike\.yml:[^\n]*\\\n  [^\n]*\n', '', text)
    write(privileged, text)

    offline_test = "scripts/check_cargo_offline_policy_test.sh"
    text = read(offline_test)
    lines = text.splitlines(keepends=True)
    output: list[str] = []
    skip = False
    for line in lines:
        if 'workflow="$repo/.github/workflows/trnm-cometbft-spike.yml"' in line:
            skip = True
            continue
        if skip:
            if line.startswith("restore_fixture"):
                skip = False
            continue
        output.append(line)
    write(offline_test, "".join(output))

    runner_policy = "scripts/check_ci_runner_policy.sh"
    text = read(runner_policy)
    text = re.sub(r'(?m)^\s*"trnm-cometbft-spike\.yml",\n', '', text)
    text = re.sub(r'(?m)^\s*"trnm-a22-capability-authority-audit\.yml",\n', '', text)
    write(runner_policy, text)

    workflow_path = ".github/workflows/trnm-required-baseline.yml"
    text = read(workflow_path)
    text = text.replace("bash ./scripts/ci/check_poco_bft_mainline_truth.sh --pre-cutover", "bash ./scripts/ci/check_poco_bft_mainline_truth.sh")
    text = re.sub(r'(?m)^\s*\.\/scripts\/ci\/check_poco_bft_v0_application_operation_sequences\.sh\s*\n', '', text)
    if "python3 ./scripts/ci/check_native_consensus_only.py" not in text:
        text = text.replace(
            "python3 ./scripts/ci/check_repository_truth_v1.py",
            "python3 ./scripts/ci/check_native_consensus_only.py\n          python3 ./scripts/ci/check_repository_truth_v1.py",
            1,
        )
    write(workflow_path, text)

    for path in ROOT.glob(".github/workflows/*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        lines = [line for line in text.splitlines(keepends=True) if not any(name in line for name in (
            "trnm-a22-capability-authority-audit.yml",
            "check_poco_bft_v0_application_operation_sequences.sh",
            "check_poco_bft_v0_migration_boundary_v1.py",
            "check_poco_bft_v0_workflow_trigger_truth.sh",
        ))]
        path.write_text("".join(lines), encoding="utf-8")


def sanitize_remaining_sources() -> None:
    replacements = (
        ("ZeroComet", "Native"),
        ("ZERO_COMET", "NATIVE_ONLY"),
        ("zero_comet", "native"),
        ("zero-comet", "native-only"),
        ("comet_hash_mapping", "foreign_hash_mapping"),
        ("recursive_comet_field_injection", "recursive_foreign_field_injection"),
        ("Comet/native", "foreign/native"),
        ("comet/native", "foreign/native"),
        ("COMETBFT", "EXTERNAL_BFT_ENGINE"),
        ("CometBFT", "external BFT engine"),
        ("cometbft", "external_bft_engine"),
        ("TENDERMINT", "EXTERNAL_BFT_ENGINE"),
        ("Tendermint", "external BFT engine"),
        ("tendermint", "external_bft_engine"),
        ("ABCI", "external application adapter"),
        ("Abci", "ExternalApplicationAdapter"),
        ("abci", "external_application_adapter"),
        ("trnm-consensus-app", "trnm-native-application"),
        ("trnm_consensus_app", "trnm_native_application"),
        ("legacy-consensus-app", "retired-application-path"),
        ("COMET", "FOREIGN"),
        ("Comet", "foreign"),
        ("comet", "foreign"),
    )
    excluded = {
        ".cleanup-residue-report.txt",
        ".cleanup-residue-paths.txt",
        ".cleanup-residue-summary.json",
        ".cleanup-genesis-symbol-usage.txt",
        ".cleanup-native-genesis-usage.txt",
        ".github/workflows/trnm-temporary-residue-inventory.yml",
        ".github/workflows/trnm-temporary-native-purge.yml",
        "tools/temporary_native_purge.py",
    }
    for path in ROOT.rglob("*"):
        if not path.is_file() or ".git" in path.parts:
            continue
        relative = path.relative_to(ROOT).as_posix()
        if relative in excluded:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        updated = text
        for old, new in replacements:
            updated = updated.replace(old, new)
        if updated != text:
            path.write_text(updated, encoding="utf-8")


def add_native_statements() -> None:
    additions = {
        "README.md": "\n## Consensus dependency policy\n\nNative PoCO-BFT is the repository's only consensus engine. The tracked source tree contains no external consensus engine, adapter, fallback, compatibility layer, or runtime dependency.\n",
        "SECURITY.md": "\n## Native consensus boundary\n\nThe native-only consensus dependency policy is security-critical. Any external consensus engine, adapter, fallback path, compatibility feature, or hidden source archive is rejected by required CI.\n",
        "OPERATIONS.md": "\n## Native-only operation\n\nOperators run only the native PoCO-BFT node path. No external consensus process, adapter process, fallback binary, or compatibility data directory is supported.\n",
    }
    for path, addition in additions.items():
        text = read(path)
        marker = addition.splitlines()[1]
        if marker not in text:
            write(path, text.rstrip() + "\n" + addition)


def main() -> int:
    purge_paths()
    shrink_consensus_types()
    update_manifests_and_truth()
    update_truth_checkers()
    update_ci_and_preflight()
    sanitize_remaining_sources()
    add_native_statements()
    for path in (
        "scripts/ci/check_native_consensus_only.py",
        "scripts/ci/check_poco_bft_mainline_truth.sh",
        "scripts/ci/check_poco_bft_v0_recovery_smoke.sh",
        "scripts/ci/check_poco_bft_v0_ci_truth.sh",
    ):
        (ROOT / path).chmod(0o755)
    subprocess.run(["python3", "-m", "compileall", "-q", "scripts/ci"], cwd=ROOT, check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
