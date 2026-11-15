//! Real content-addressed executable installation under the held M15 owner.
use super::execution_wire::Installation;
use super::frontier::{invalid, Digest32, Result};
use super::owner::Owner;
use super::records::Record;
use super::sealed::Sealed;
use std::path::Path;
use trnm_release_bundle::pq_release::PqReleaseRoleV1;

fn name(digest: Digest32) -> String {
    format!("artifact-{}.elf", hex::encode(digest))
}

pub(super) fn install(source: &Path, logical_name: &str) -> Result<Digest32> {
    let mut owner = Owner::open()?;
    let state = owner.reload()?;
    let now = owner.now()?;
    let bundle = state
        .bundle
        .as_ref()
        .ok_or_else(|| invalid("M15 current Node bundle missing"))?;
    state.check_role(PqReleaseRoleV1::NodeSoftware, bundle.bundle_digest, now)?;
    let artifact = bundle
        .artifacts
        .iter()
        .find(|value| value.logical_name == logical_name)
        .ok_or_else(|| invalid("M15 signed artifact name missing"))?;
    if !artifact.executable || artifact.platform_digest != super::elf::platform()? {
        return Err(invalid("M15 native static ELF artifact required"));
    }
    let (image, source_identity) =
        Sealed::from_path(source, artifact.content_digest, artifact.size_bytes, true)?;
    image.verify_elf(artifact.platform_digest)?;
    owner
        .store
        .objects()?
        .put_sealed(&name(image.digest), &image)?;
    let observed_at = owner.now()?;
    let installation = Installation {
        schema_version: 1,
        bundle: bundle.bundle_digest,
        artifact_name: logical_name.into(),
        program_sha256: image.digest,
        source_identity,
        kernel_checkpoint: state.authority.checkpoint(),
        observed_at,
    };
    owner.append(Record::Installation(installation), |_, _| {
        image.recheck()?;
        image.verify_elf(artifact.platform_digest)
    })
}

pub(super) fn load(
    owner: &Owner,
    installation: &Installation,
    size: u64,
    platform: Digest32,
) -> Result<Sealed> {
    let files = owner.store.objects()?;
    let name = name(installation.program_sha256);
    let original = files.open_object(&name, size)?;
    let image = Sealed::from_file(&original, installation.program_sha256, size, true)?;
    files.recheck_object(&name, &original)?;
    image.verify_elf(platform)?;
    Ok(image)
}
