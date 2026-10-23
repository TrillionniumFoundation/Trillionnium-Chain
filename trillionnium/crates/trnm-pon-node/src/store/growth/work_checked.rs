//! An immutable, fully verified PGH2 work relation. This capability has no
//! parent-state, local-clock, admission, activation or task authority.
use super::{GrowthPacket, GrowthProgress};
use crate::{Error, Result};
use trnm_crypto_primitives::pon_work;

/// Private fields prevent replacing any packet byte after complete W1 replay.
/// Verification needs no Node reference and can run outside its owner mutex.
pub(crate) struct GrowthWorkCheckedPacket {
    packet: GrowthPacket,
    work: pon_work::VerifiedWork,
}

impl GrowthWorkCheckedPacket {
    pub(crate) fn verify_with_progress(
        packet: GrowthPacket,
        progress: &(impl Fn(GrowthProgress) -> Result<()> + Sync),
    ) -> Result<Self> {
        // Bound and canonicalize the exact PNP2 body before expensive work.
        // These bytes retain PGH2's witness-bound challenge, never PNH1's.
        packet.encode()?;
        progress(GrowthProgress::BeforeWork)?;
        let work = pon_work::verify_with_progress(
            packet.header.challenge(),
            packet.header.ledger.work_task,
            packet.header.ledger.target,
            &packet.proof,
            &mut |point| progress(GrowthProgress::Work(point)),
        )
        .map_err(|error| match error {
            pon_work::VerificationError::Relation(error) => Error::from(format!("WORK:{error:?}")),
            pon_work::VerificationError::Cancelled(error) => error,
        })?;
        Ok(Self { packet, work })
    }

    /// Domain-separated exact complete packet identity for the original shared
    /// scheduling set. Neither block ID alone nor caller text can claim it.
    pub(crate) fn completion_identity(&self) -> Result<trnm_protocol::pon_wire::Hash> {
        Ok(trnm_protocol::pon_wire::hash(
            b"public-growth-complete-work-identity-v1",
            &[&self.packet.encode()?],
        ))
    }

    pub(super) fn into_parts(self) -> (GrowthPacket, pon_work::VerifiedWork) {
        (self.packet, self.work)
    }
}
