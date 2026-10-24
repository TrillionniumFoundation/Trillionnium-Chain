//! Atomic renewal is selected only by a fresh revision8 context. The embedded V2
//! codecs retain their signing domains: both bind the new network and parameters.
//! Decoding proves structure and exact lease binding, not either signature.
use super::lifecycle_v2::{
    DemandLeaseV2, LifecycleError, SignedLifecycleTaskV2, DEMAND_LEASE_BYTES, LIFECYCLE_TASK_BYTES,
};

pub const PROFILE: &str = "signed-task-lifecycle-dev-v3";
pub const ATOMIC_RENEW_TAG: u8 = 22;
pub const ATOMIC_RENEW_BYTES: usize = DEMAND_LEASE_BYTES + LIFECYCLE_TASK_BYTES;

/// One requester-signed main envelope contains both the successor lease and the
/// source's signature over that exact successor. There is no nested main envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtomicRenewTaskV3 {
    pub lease: DemandLeaseV2,
    pub signed: SignedLifecycleTaskV2,
}
impl AtomicRenewTaskV3 {
    pub fn encode(&self) -> Result<Vec<u8>, LifecycleError> {
        if self.signed.lease_id != self.lease.id()?
            || self.signed.manifest.network != self.lease.network
            || self.signed.manifest.parameters != self.lease.parameters
        {
            return Err(LifecycleError::Identity);
        }
        let mut bytes = self.lease.encode()?;
        bytes.extend(self.signed.encode()?);
        debug_assert_eq!(bytes.len(), ATOMIC_RENEW_BYTES);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, LifecycleError> {
        if bytes.len() != ATOMIC_RENEW_BYTES {
            return Err(LifecycleError::Length);
        }
        let value = Self {
            lease: DemandLeaseV2::decode(&bytes[..DEMAND_LEASE_BYTES])?,
            signed: SignedLifecycleTaskV2::decode(&bytes[DEMAND_LEASE_BYTES..])?,
        };
        value.encode()?;
        Ok(value)
    }
}
