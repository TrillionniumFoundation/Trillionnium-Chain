//! Deployment service identities are disjoint from every retained root epoch.
//! This profile check supplements, never replaces, the kernel's full validation.
use super::frontier::{invalid, Digest32, Result};
use trnm_release_bundle::pq_release::PqReleaseRootV1;

pub(super) fn require(root: &PqReleaseRootV1, services: &[Digest32; 3]) -> Result<()> {
    if services.contains(&[0; 32])
        || services[0] == services[1]
        || services[0] == services[2]
        || services[1] == services[2]
        || root
            .offline_root
            .keys
            .keys()
            .chain(root.roles.values().flat_map(|role| role.keys.keys()))
            .any(|key| services.contains(key))
    {
        return Err(invalid("M15 service key cannot impersonate a release role"));
    }
    Ok(())
}
