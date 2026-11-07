//! Serialized source/SBOM/provenance declarations are still checked by M15 V0.
use super::frontier::Digest32;
use serde::{Deserialize, Serialize};
use trnm_release_bundle::{
    ArtifactEntryV0, BuildInputV0, BuilderProvenanceV0, Digest32V0, ExactSourceV0, ReleaseBundleV0,
    SbomPackageV0,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Artifact {
    pub logical_name: String,
    pub media_type: String,
    pub size_bytes: u64,
    pub content_digest: Digest32,
    pub executable: bool,
    pub platform_digest: Digest32,
    pub source_path_digest: Digest32,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Package {
    pub package_name: String,
    pub package_version: String,
    pub source_digest: Digest32,
    pub package_checksum: Digest32,
    pub license_expression: String,
    pub direct_production_dependency: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Source {
    pub repository_digest: Digest32,
    pub commit_digest: Digest32,
    pub tree_digest: Digest32,
    pub cargo_lock_digest: Digest32,
    pub toolchain_digest: Digest32,
    pub production_closure_digest: Digest32,
    pub dirty: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Input {
    pub logical_name: String,
    pub source_digest: Digest32,
    pub content_digest: Digest32,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Provenance {
    pub builder_identity_digest: Digest32,
    pub workflow_digest: Digest32,
    pub run_identity_digest: Digest32,
    pub isolated_environment_digest: Digest32,
    pub exact_source_digest: Digest32,
    pub build_inputs: Vec<Input>,
    pub artifact_set_digest: Digest32,
    pub sbom_digest: Digest32,
    pub provenance_digest: Digest32,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Bundle {
    pub bundle_name: String,
    pub release_version: String,
    pub protocol_digest: Digest32,
    pub exact_source: Source,
    pub artifacts: Vec<Artifact>,
    pub sbom_packages: Vec<Package>,
    pub provenance: Provenance,
    pub previous_bundle_digest: Option<Digest32>,
    pub signer_identity_digest: Digest32,
    pub signature_digest: Digest32,
    pub bundle_digest: Digest32,
}

impl Bundle {
    pub fn kernel(&self) -> ReleaseBundleV0 {
        let source = &self.exact_source;
        let p = &self.provenance;
        ReleaseBundleV0 {
            bundle_name: self.bundle_name.as_bytes().to_vec(),
            release_version: self.release_version.as_bytes().to_vec(),
            protocol_digest: Digest32V0(self.protocol_digest),
            exact_source: ExactSourceV0 {
                repository_digest: Digest32V0(source.repository_digest),
                commit_digest: Digest32V0(source.commit_digest),
                tree_digest: Digest32V0(source.tree_digest),
                cargo_lock_digest: Digest32V0(source.cargo_lock_digest),
                toolchain_digest: Digest32V0(source.toolchain_digest),
                production_closure_digest: Digest32V0(source.production_closure_digest),
                dirty: source.dirty,
            },
            artifacts: self
                .artifacts
                .iter()
                .map(|v| ArtifactEntryV0 {
                    logical_name: v.logical_name.as_bytes().to_vec(),
                    media_type: v.media_type.as_bytes().to_vec(),
                    size_bytes: v.size_bytes,
                    content_digest: Digest32V0(v.content_digest),
                    executable: v.executable,
                    platform_digest: Digest32V0(v.platform_digest),
                    source_path_digest: Digest32V0(v.source_path_digest),
                })
                .collect(),
            sbom_packages: self
                .sbom_packages
                .iter()
                .map(|v| SbomPackageV0 {
                    package_name: v.package_name.as_bytes().to_vec(),
                    package_version: v.package_version.as_bytes().to_vec(),
                    source_digest: Digest32V0(v.source_digest),
                    package_checksum: Digest32V0(v.package_checksum),
                    license_expression: v.license_expression.as_bytes().to_vec(),
                    direct_production_dependency: v.direct_production_dependency,
                })
                .collect(),
            provenance: BuilderProvenanceV0 {
                builder_identity_digest: Digest32V0(p.builder_identity_digest),
                workflow_digest: Digest32V0(p.workflow_digest),
                run_identity_digest: Digest32V0(p.run_identity_digest),
                isolated_environment_digest: Digest32V0(p.isolated_environment_digest),
                exact_source_digest: Digest32V0(p.exact_source_digest),
                build_inputs: p
                    .build_inputs
                    .iter()
                    .map(|v| BuildInputV0 {
                        logical_name: v.logical_name.as_bytes().to_vec(),
                        source_digest: Digest32V0(v.source_digest),
                        content_digest: Digest32V0(v.content_digest),
                    })
                    .collect(),
                artifact_set_digest: Digest32V0(p.artifact_set_digest),
                sbom_digest: Digest32V0(p.sbom_digest),
                provenance_digest: Digest32V0(p.provenance_digest),
            },
            previous_bundle_digest: self.previous_bundle_digest.map(Digest32V0),
            signer_identity_digest: Digest32V0(self.signer_identity_digest),
            signature_digest: Digest32V0(self.signature_digest),
            bundle_digest: Digest32V0(self.bundle_digest),
        }
    }
}
