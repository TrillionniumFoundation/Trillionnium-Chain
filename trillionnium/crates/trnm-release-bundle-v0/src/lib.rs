#![forbid(unsafe_code)]
//! Exact-source release bundle, SBOM and provenance contract.
//!
//! This crate validates declarations and cryptographic binding.  It does not
//! claim reproducibility, independent review, artifact publication, HSM-backed
//! signing, or release readiness until corresponding evidence is supplied by
//! external builders and reviewers.

use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, error::Error, fmt};

pub const RELEASE_BUNDLE_VERSION_V0: u16 = 0;
pub const MAX_ARTIFACTS_V0: usize = 4096;
pub const MAX_PACKAGES_V0: usize = 100_000;
pub const MAX_BUILD_INPUTS_V0: usize = 100_000;
pub const MAX_NAME_BYTES_V0: usize = 512;
pub const MAX_VERSION_BYTES_V0: usize = 256;
pub const MAX_MEDIA_TYPE_BYTES_V0: usize = 256;
pub const MAX_LICENSE_BYTES_V0: usize = 512;
pub const MAX_ARTIFACT_BYTES_V0: u64 = 128 * 1024 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Digest32V0(pub [u8; 32]);

impl Digest32V0 {
    #[must_use]
    pub fn hash(domain: &[u8], parts: &[&[u8]]) -> Self {
        let mut h = Sha256::new();
        h.update((domain.len() as u64).to_be_bytes());
        h.update(domain);
        for part in parts {
            h.update((part.len() as u64).to_be_bytes());
            h.update(part);
        }
        Self(h.finalize().into())
    }
}

fn valid_text(value: &[u8], maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.iter().all(|byte| matches!(byte, 0x20..=0x7e))
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ArtifactEntryV0 {
    pub logical_name: Vec<u8>,
    pub media_type: Vec<u8>,
    pub size_bytes: u64,
    pub content_digest: Digest32V0,
    pub executable: bool,
    pub platform_digest: Digest32V0,
    pub source_path_digest: Digest32V0,
}

impl ArtifactEntryV0 {
    pub fn validate(&self) -> Result<(), ReleaseBundleErrorV0> {
        if !valid_text(&self.logical_name, MAX_NAME_BYTES_V0)
            || !valid_text(&self.media_type, MAX_MEDIA_TYPE_BYTES_V0)
            || self.size_bytes == 0
            || self.size_bytes > MAX_ARTIFACT_BYTES_V0
            || self.content_digest == Digest32V0([0; 32])
            || self.platform_digest == Digest32V0([0; 32])
            || self.source_path_digest == Digest32V0([0; 32])
        {
            return Err(ReleaseBundleErrorV0::InvalidArtifact);
        }
        Ok(())
    }

    #[must_use]
    pub fn canonical_digest(&self) -> Digest32V0 {
        Digest32V0::hash(
            b"trnm.release.artifact.v0",
            &[
                &self.logical_name,
                &self.media_type,
                &self.size_bytes.to_be_bytes(),
                &self.content_digest.0,
                &[u8::from(self.executable)],
                &self.platform_digest.0,
                &self.source_path_digest.0,
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SbomPackageV0 {
    pub package_name: Vec<u8>,
    pub package_version: Vec<u8>,
    pub source_digest: Digest32V0,
    pub package_checksum: Digest32V0,
    pub license_expression: Vec<u8>,
    pub direct_production_dependency: bool,
}

impl SbomPackageV0 {
    pub fn validate(&self) -> Result<(), ReleaseBundleErrorV0> {
        if !valid_text(&self.package_name, MAX_NAME_BYTES_V0)
            || !valid_text(&self.package_version, MAX_VERSION_BYTES_V0)
            || !valid_text(&self.license_expression, MAX_LICENSE_BYTES_V0)
            || self.source_digest == Digest32V0([0; 32])
            || self.package_checksum == Digest32V0([0; 32])
        {
            return Err(ReleaseBundleErrorV0::InvalidSbomPackage);
        }
        Ok(())
    }

    #[must_use]
    pub fn canonical_digest(&self) -> Digest32V0 {
        Digest32V0::hash(
            b"trnm.release.sbom-package.v0",
            &[
                &self.package_name,
                &self.package_version,
                &self.source_digest.0,
                &self.package_checksum.0,
                &self.license_expression,
                &[u8::from(self.direct_production_dependency)],
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExactSourceV0 {
    pub repository_digest: Digest32V0,
    pub commit_digest: Digest32V0,
    pub tree_digest: Digest32V0,
    pub cargo_lock_digest: Digest32V0,
    pub toolchain_digest: Digest32V0,
    pub production_closure_digest: Digest32V0,
    pub dirty: bool,
}

impl ExactSourceV0 {
    pub fn validate(self) -> Result<Self, ReleaseBundleErrorV0> {
        if self.dirty
            || self.repository_digest == Digest32V0([0; 32])
            || self.commit_digest == Digest32V0([0; 32])
            || self.tree_digest == Digest32V0([0; 32])
            || self.cargo_lock_digest == Digest32V0([0; 32])
            || self.toolchain_digest == Digest32V0([0; 32])
            || self.production_closure_digest == Digest32V0([0; 32])
        {
            return Err(ReleaseBundleErrorV0::InvalidExactSource);
        }
        Ok(self)
    }

    #[must_use]
    pub fn canonical_digest(self) -> Digest32V0 {
        Digest32V0::hash(
            b"trnm.release.exact-source.v0",
            &[
                &self.repository_digest.0,
                &self.commit_digest.0,
                &self.tree_digest.0,
                &self.cargo_lock_digest.0,
                &self.toolchain_digest.0,
                &self.production_closure_digest.0,
                &[u8::from(self.dirty)],
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BuildInputV0 {
    pub logical_name: Vec<u8>,
    pub source_digest: Digest32V0,
    pub content_digest: Digest32V0,
}

impl BuildInputV0 {
    pub fn validate(&self) -> Result<(), ReleaseBundleErrorV0> {
        if !valid_text(&self.logical_name, MAX_NAME_BYTES_V0)
            || self.source_digest == Digest32V0([0; 32])
            || self.content_digest == Digest32V0([0; 32])
        {
            return Err(ReleaseBundleErrorV0::InvalidBuildInput);
        }
        Ok(())
    }

    #[must_use]
    pub fn canonical_digest(&self) -> Digest32V0 {
        Digest32V0::hash(
            b"trnm.release.build-input.v0",
            &[
                &self.logical_name,
                &self.source_digest.0,
                &self.content_digest.0,
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuilderProvenanceV0 {
    pub builder_identity_digest: Digest32V0,
    pub workflow_digest: Digest32V0,
    pub run_identity_digest: Digest32V0,
    pub isolated_environment_digest: Digest32V0,
    pub exact_source_digest: Digest32V0,
    pub build_inputs: Vec<BuildInputV0>,
    pub artifact_set_digest: Digest32V0,
    pub sbom_digest: Digest32V0,
    pub provenance_digest: Digest32V0,
}

impl BuilderProvenanceV0 {
    #[must_use]
    pub fn canonical_digest(&self) -> Digest32V0 {
        let mut inputs = self.build_inputs.clone();
        inputs.sort_unstable();
        let mut h = Sha256::new();
        h.update(b"trnm.release.builder-provenance.v0");
        h.update(self.builder_identity_digest.0);
        h.update(self.workflow_digest.0);
        h.update(self.run_identity_digest.0);
        h.update(self.isolated_environment_digest.0);
        h.update(self.exact_source_digest.0);
        h.update((inputs.len() as u64).to_be_bytes());
        for input in inputs {
            h.update(input.canonical_digest().0);
        }
        h.update(self.artifact_set_digest.0);
        h.update(self.sbom_digest.0);
        Digest32V0(h.finalize().into())
    }

    pub fn validate(&self) -> Result<(), ReleaseBundleErrorV0> {
        if self.builder_identity_digest == Digest32V0([0; 32])
            || self.workflow_digest == Digest32V0([0; 32])
            || self.run_identity_digest == Digest32V0([0; 32])
            || self.isolated_environment_digest == Digest32V0([0; 32])
            || self.exact_source_digest == Digest32V0([0; 32])
            || self.artifact_set_digest == Digest32V0([0; 32])
            || self.sbom_digest == Digest32V0([0; 32])
            || self.build_inputs.is_empty()
            || self.build_inputs.len() > MAX_BUILD_INPUTS_V0
            || self.provenance_digest != self.canonical_digest()
        {
            return Err(ReleaseBundleErrorV0::InvalidProvenance);
        }
        let mut unique = BTreeSet::new();
        for input in &self.build_inputs {
            input.validate()?;
            if !unique.insert((&input.logical_name, input.source_digest)) {
                return Err(ReleaseBundleErrorV0::DuplicateBuildInput);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseBundleV0 {
    pub bundle_name: Vec<u8>,
    pub release_version: Vec<u8>,
    pub protocol_digest: Digest32V0,
    pub exact_source: ExactSourceV0,
    pub artifacts: Vec<ArtifactEntryV0>,
    pub sbom_packages: Vec<SbomPackageV0>,
    pub provenance: BuilderProvenanceV0,
    pub previous_bundle_digest: Option<Digest32V0>,
    pub signer_identity_digest: Digest32V0,
    pub signature_digest: Digest32V0,
    pub bundle_digest: Digest32V0,
}

impl ReleaseBundleV0 {
    #[must_use]
    pub fn artifact_set_digest(&self) -> Digest32V0 {
        let mut artifacts = self.artifacts.clone();
        artifacts.sort_unstable();
        let mut h = Sha256::new();
        h.update(b"trnm.release.artifact-set.v0");
        for artifact in artifacts {
            h.update(artifact.canonical_digest().0);
        }
        Digest32V0(h.finalize().into())
    }

    #[must_use]
    pub fn sbom_digest(&self) -> Digest32V0 {
        let mut packages = self.sbom_packages.clone();
        packages.sort_unstable();
        let mut h = Sha256::new();
        h.update(b"trnm.release.sbom.v0");
        for package in packages {
            h.update(package.canonical_digest().0);
        }
        Digest32V0(h.finalize().into())
    }

    #[must_use]
    pub fn canonical_digest(&self) -> Digest32V0 {
        let previous = self.previous_bundle_digest.unwrap_or(Digest32V0([0; 32]));
        Digest32V0::hash(
            b"trnm.release.bundle.v0",
            &[
                &self.bundle_name,
                &self.release_version,
                &self.protocol_digest.0,
                &self.exact_source.canonical_digest().0,
                &self.artifact_set_digest().0,
                &self.sbom_digest().0,
                &self.provenance.provenance_digest.0,
                &previous.0,
                &self.signer_identity_digest.0,
            ],
        )
    }
}

pub trait ReleaseSignatureVerifierV0 {
    type Error: Error + Send + Sync + 'static;

    fn verify_release_signature(&self, bundle: &ReleaseBundleV0) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedReleaseBundleV0 {
    pub bundle_digest: Digest32V0,
    pub exact_source_digest: Digest32V0,
    pub artifact_set_digest: Digest32V0,
    pub sbom_digest: Digest32V0,
    pub provenance_digest: Digest32V0,
    pub artifact_count: u32,
    pub package_count: u32,
}

pub fn verify_release_bundle_v0<V>(
    verifier: &V,
    bundle: &ReleaseBundleV0,
    required_production_packages: &[(Vec<u8>, Vec<u8>)],
) -> Result<VerifiedReleaseBundleV0, ReleaseBundleHostErrorV0<V::Error>>
where
    V: ReleaseSignatureVerifierV0,
{
    if !valid_text(&bundle.bundle_name, MAX_NAME_BYTES_V0)
        || !valid_text(&bundle.release_version, MAX_VERSION_BYTES_V0)
        || bundle.protocol_digest == Digest32V0([0; 32])
        || bundle.artifacts.is_empty()
        || bundle.artifacts.len() > MAX_ARTIFACTS_V0
        || bundle.sbom_packages.is_empty()
        || bundle.sbom_packages.len() > MAX_PACKAGES_V0
        || bundle.signer_identity_digest == Digest32V0([0; 32])
        || bundle.signature_digest == Digest32V0([0; 32])
    {
        return Err(ReleaseBundleHostErrorV0::Protocol(
            ReleaseBundleErrorV0::InvalidBundle,
        ));
    }
    let exact_source = bundle
        .exact_source
        .validate()
        .map_err(ReleaseBundleHostErrorV0::Protocol)?;

    let mut artifact_names = BTreeSet::new();
    for artifact in &bundle.artifacts {
        artifact
            .validate()
            .map_err(ReleaseBundleHostErrorV0::Protocol)?;
        if !artifact_names.insert(artifact.logical_name.clone()) {
            return Err(ReleaseBundleHostErrorV0::Protocol(
                ReleaseBundleErrorV0::DuplicateArtifact,
            ));
        }
    }

    let mut package_keys = BTreeSet::new();
    for package in &bundle.sbom_packages {
        package
            .validate()
            .map_err(ReleaseBundleHostErrorV0::Protocol)?;
        if !package_keys.insert((package.package_name.clone(), package.package_version.clone())) {
            return Err(ReleaseBundleHostErrorV0::Protocol(
                ReleaseBundleErrorV0::DuplicateSbomPackage,
            ));
        }
    }
    for required in required_production_packages {
        if !package_keys.contains(required) {
            return Err(ReleaseBundleHostErrorV0::Protocol(
                ReleaseBundleErrorV0::IncompleteSbom,
            ));
        }
    }

    bundle
        .provenance
        .validate()
        .map_err(ReleaseBundleHostErrorV0::Protocol)?;
    let exact_source_digest = exact_source.canonical_digest();
    let artifact_set_digest = bundle.artifact_set_digest();
    let sbom_digest = bundle.sbom_digest();
    if bundle.provenance.exact_source_digest != exact_source_digest
        || bundle.provenance.artifact_set_digest != artifact_set_digest
        || bundle.provenance.sbom_digest != sbom_digest
        || bundle.bundle_digest != bundle.canonical_digest()
    {
        return Err(ReleaseBundleHostErrorV0::Protocol(
            ReleaseBundleErrorV0::ProvenanceBindingMismatch,
        ));
    }
    verifier
        .verify_release_signature(bundle)
        .map_err(ReleaseBundleHostErrorV0::Signature)?;
    Ok(VerifiedReleaseBundleV0 {
        bundle_digest: bundle.bundle_digest,
        exact_source_digest,
        artifact_set_digest,
        sbom_digest,
        provenance_digest: bundle.provenance.provenance_digest,
        artifact_count: bundle.artifacts.len() as u32,
        package_count: bundle.sbom_packages.len() as u32,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReproducibilityDecisionV0 {
    Match,
    Mismatch,
}

#[must_use]
pub fn compare_independent_builds_v0(
    first: VerifiedReleaseBundleV0,
    second: VerifiedReleaseBundleV0,
) -> ReproducibilityDecisionV0 {
    if first.exact_source_digest == second.exact_source_digest
        && first.artifact_set_digest == second.artifact_set_digest
        && first.sbom_digest == second.sbom_digest
        && first.artifact_count == second.artifact_count
        && first.package_count == second.package_count
    {
        ReproducibilityDecisionV0::Match
    } else {
        ReproducibilityDecisionV0::Mismatch
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseBundleErrorV0 {
    InvalidArtifact,
    InvalidSbomPackage,
    InvalidExactSource,
    InvalidBuildInput,
    InvalidProvenance,
    DuplicateBuildInput,
    InvalidBundle,
    DuplicateArtifact,
    DuplicateSbomPackage,
    IncompleteSbom,
    ProvenanceBindingMismatch,
}

impl fmt::Display for ReleaseBundleErrorV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidArtifact => "invalid release artifact entry",
            Self::InvalidSbomPackage => "invalid SBOM package entry",
            Self::InvalidExactSource => "release source is dirty, incomplete, or unbound",
            Self::InvalidBuildInput => "invalid build input",
            Self::InvalidProvenance => "invalid builder provenance",
            Self::DuplicateBuildInput => "duplicate build input",
            Self::InvalidBundle => "invalid release bundle",
            Self::DuplicateArtifact => "duplicate release artifact logical name",
            Self::DuplicateSbomPackage => "duplicate SBOM package name and version",
            Self::IncompleteSbom => "SBOM does not cover the required production closure",
            Self::ProvenanceBindingMismatch => "source, artifact, SBOM, provenance, or bundle digest mismatch",
        })
    }
}

impl Error for ReleaseBundleErrorV0 {}

#[derive(Debug)]
pub enum ReleaseBundleHostErrorV0<SignatureError> {
    Protocol(ReleaseBundleErrorV0),
    Signature(SignatureError),
}

impl<S: fmt::Display> fmt::Display for ReleaseBundleHostErrorV0<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "release bundle rejected: {error}"),
            Self::Signature(error) => write!(f, "release signature verification failed: {error}"),
        }
    }
}

impl<S> Error for ReleaseBundleHostErrorV0<S>
where
    S: Error + 'static,
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;

    fn d(byte: u8) -> Digest32V0 {
        Digest32V0([byte; 32])
    }

    struct AcceptSignature;
    impl ReleaseSignatureVerifierV0 for AcceptSignature {
        type Error = Infallible;
        fn verify_release_signature(&self, _bundle: &ReleaseBundleV0) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    fn bundle(builder: u8, artifact_digest: u8) -> ReleaseBundleV0 {
        let exact_source = ExactSourceV0 {
            repository_digest: d(1),
            commit_digest: d(2),
            tree_digest: d(3),
            cargo_lock_digest: d(4),
            toolchain_digest: d(5),
            production_closure_digest: d(6),
            dirty: false,
        };
        let artifacts = vec![ArtifactEntryV0 {
            logical_name: b"trnm-poco-node".to_vec(),
            media_type: b"application/vnd.trnm.elf".to_vec(),
            size_bytes: 1024,
            content_digest: d(artifact_digest),
            executable: true,
            platform_digest: d(8),
            source_path_digest: d(9),
        }];
        let packages = vec![SbomPackageV0 {
            package_name: b"trnm-poco-node".to_vec(),
            package_version: b"0.1.0".to_vec(),
            source_digest: d(10),
            package_checksum: d(11),
            license_expression: b"Apache-2.0".to_vec(),
            direct_production_dependency: true,
        }];
        let mut draft = ReleaseBundleV0 {
            bundle_name: b"trnm-native-poco".to_vec(),
            release_version: b"0.1.0-dev".to_vec(),
            protocol_digest: d(12),
            exact_source,
            artifacts,
            sbom_packages: packages,
            provenance: BuilderProvenanceV0 {
                builder_identity_digest: d(builder),
                workflow_digest: d(14),
                run_identity_digest: d(builder.saturating_add(1)),
                isolated_environment_digest: d(16),
                exact_source_digest: d(0),
                build_inputs: vec![BuildInputV0 {
                    logical_name: b"Cargo.lock".to_vec(),
                    source_digest: d(17),
                    content_digest: d(4),
                }],
                artifact_set_digest: d(0),
                sbom_digest: d(0),
                provenance_digest: d(0),
            },
            previous_bundle_digest: None,
            signer_identity_digest: d(18),
            signature_digest: d(19),
            bundle_digest: d(0),
        };
        draft.provenance.exact_source_digest = draft.exact_source.canonical_digest();
        draft.provenance.artifact_set_digest = draft.artifact_set_digest();
        draft.provenance.sbom_digest = draft.sbom_digest();
        draft.provenance.provenance_digest = draft.provenance.canonical_digest();
        draft.bundle_digest = draft.canonical_digest();
        draft
    }

    #[test]
    fn exact_bundle_and_sbom_are_verified() {
        let bundle = bundle(20, 7);
        let verified = verify_release_bundle_v0(
            &AcceptSignature,
            &bundle,
            &[(b"trnm-poco-node".to_vec(), b"0.1.0".to_vec())],
        )
        .unwrap();
        assert_eq!(verified.bundle_digest, bundle.bundle_digest);
    }

    #[test]
    fn independent_build_comparison_uses_outputs_not_builder_identity() {
        let first = verify_release_bundle_v0(&AcceptSignature, &bundle(20, 7), &[]).unwrap();
        let second = verify_release_bundle_v0(&AcceptSignature, &bundle(30, 7), &[]).unwrap();
        assert_eq!(
            compare_independent_builds_v0(first, second),
            ReproducibilityDecisionV0::Match
        );
        let mismatch = verify_release_bundle_v0(&AcceptSignature, &bundle(30, 99), &[]).unwrap();
        assert_eq!(
            compare_independent_builds_v0(first, mismatch),
            ReproducibilityDecisionV0::Mismatch
        );
    }
}
