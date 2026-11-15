//! Immutable, externally supplied lower bound for recovered root history.
//!
//! A local constructor cannot authenticate a human, backup or independent
//! recovery authority. The caller must provision this pin through its separately
//! authenticated recovery procedure. The owner checks its exact complete
//! enrollment and signed ancestry in addition to the existing fresh anchor.
//! The pin is not stored or refreshed from the journal or anchor response.
use super::{digest, require, JournalEnrollmentV3, JournalHeadV3, RootOwnerResultV3};
use trnm_release_bundle::root_recovery_v3::DigestV3;

const ENROLLMENT_FLOOR_DOMAIN: &[u8] = b"TRNM/RootOwner/RecoveryFloorEnrollment/v4\0";

/// An explicit recovery lower bound, never an effect capability. The caller
/// is responsible for authenticating its source before construction.
///
/// It binds the full network/genesis/owner domain, initial root policy, initial
/// time, writer roster and anchor roster through canonical enrollment bytes.
/// Matching only a version counter does not satisfy it. This type deliberately
/// has no serialization, local-store loader, setter or promotion flag.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryFloorV4 {
    enrollment_commitment: DigestV3,
    head: JournalHeadV3,
}

impl RecoveryFloorV4 {
    /// Accept an explicit external pin as trusted input. This validates shape
    /// and binds enrollment; it does not authenticate the source of `head`.
    /// Passing a head read from the same restored state supplies no independent
    /// rollback guarantee. Freshness/age must be checked by the recovery owner.
    pub fn from_external_pin(
        enrollment: &JournalEnrollmentV3,
        head: JournalHeadV3,
    ) -> RootOwnerResultV3<Self> {
        head.validate()?;
        let enrollment_commitment = digest(ENROLLMENT_FLOOR_DOMAIN, &[&enrollment.encode()?]);
        Ok(Self {
            enrollment_commitment,
            head,
        })
    }

    pub fn enrollment_commitment(&self) -> DigestV3 {
        self.enrollment_commitment
    }

    pub fn head(&self) -> JournalHeadV3 {
        self.head
    }

    pub(super) fn check_enrollment(
        &self,
        enrollment: &JournalEnrollmentV3,
    ) -> RootOwnerResultV3<()> {
        self.head.validate()?;
        require(
            self.enrollment_commitment == digest(ENROLLMENT_FLOOR_DOMAIN, &[&enrollment.encode()?]),
            "ROOT_OWNER_RECOVERY_FLOOR_ENROLLMENT",
        )
    }

    pub(super) fn matches_head(&self, authenticated_head: JournalHeadV3) -> bool {
        authenticated_head == self.head
    }
}
