//! An explicit signed, immediate original tag22 lease edge. No source/class or
//! matrix substitution, implicit discovery, historical rewrite or budget reset.
use crate::operator_continuous_recipient::{declared_binding_digest, DeclaredBinding};
use crate::operator_pq_auth::Profile;
use crate::operator_task_policy::PolicyError;
use serde::{Deserialize, Serialize};
use trnm_protocol::qualified_work_task::lifecycle_v2::DemandLeaseV2;
use trnm_protocol::qualified_work_task::pq_lifecycle_v5::DemandLeaseV5;
type Result<T> = std::result::Result<T, PolicyError>;
const DOMAIN: &[u8] = b"TRNM-RESTRICTED-CONTINUOUS-LEASE-EDGE1";
const PQ_DOMAIN: &[u8] = b"TRNM/PoN/ContinuousLeaseEdge/PQ/v2\0";
fn check(v: bool) -> Result<()> {
    if v {
        Ok(())
    } else {
        Err(PolicyError::NativeBinding)
    }
}
fn id(v: &str) -> Result<()> {
    check(
        v.len() == 64
            && v.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
    )
}
/// The complete body is signed inside the new TaskView, and its digest is the
/// old declared task's independently double-signed lease-reconcile allocation.
/// A new original Registry2 budget-level declaration is separately mandatory.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct LeaseEdge {
    pub schema: String,
    pub actual_parent: String,
    pub actual_generation: u64,
    pub native_task: String,
    pub old_task_binding: String,
    pub new_task_binding: String,
    pub old_complete_lease: String,
    pub new_complete_lease: String,
    pub renewal_packet_sha256: String,
    pub new_registry2_declaration_digest: String,
}
/// This compares every original declared field. Only one exact lease hash may
/// differ; model/layer/input/A-B, cost/source/class, funding and reuse remain.
pub(crate) fn same_except_lease(old: &DeclaredBinding, new: &DeclaredBinding) -> bool {
    let mut normalized = new.clone();
    normalized.task.lease_sha256 = old.task.lease_sha256.clone();
    normalized == *old
}
impl LeaseEdge {
    fn profile(&self) -> Result<Profile> {
        match self.schema.as_str() {
            "restricted-continuous-lease-edge-v1" => Ok(Profile::ClassicalV2),
            "restricted-continuous-lease-edge-pq-v2" => Ok(Profile::PqV3),
            _ => Err(PolicyError::NativeBinding),
        }
    }
    fn lease(value: &str, profile: Profile) -> Result<(Vec<u8>, Lease)> {
        let size = match profile {
            Profile::ClassicalV2 => {
                trnm_protocol::qualified_work_task::lifecycle_v2::DEMAND_LEASE_BYTES
            }
            Profile::PqV3 => {
                trnm_protocol::qualified_work_task::pq_lifecycle_v5::DEMAND_LEASE_BYTES
            }
        };
        check(value.len() == 2 * size)?;
        let raw = hex::decode(value).map_err(|_| PolicyError::Input)?;
        check(hex::encode(&raw) == value)?;
        let lease = match profile {
            Profile::ClassicalV2 => {
                let lease = DemandLeaseV2::decode(&raw).map_err(|_| PolicyError::NativeBinding)?;
                check(lease.encode().map_err(|_| PolicyError::NativeBinding)? == raw)?;
                Lease::Classical(lease)
            }
            Profile::PqV3 => {
                let lease = DemandLeaseV5::decode(&raw).map_err(|_| PolicyError::NativeBinding)?;
                check(lease.encode().map_err(|_| PolicyError::NativeBinding)? == raw)?;
                Lease::Pq(lease)
            }
        };
        Ok((raw, lease))
    }
    /// Profile comes from the externally pinned Identity, never from lease bytes.
    pub(crate) fn payload_for(&self, profile: Profile) -> Result<String> {
        check(self.profile()? == profile)?;
        self.payload()
    }
    pub(crate) fn payload(&self) -> Result<String> {
        let profile = self.profile()?;
        for h in [
            &self.actual_parent,
            &self.native_task,
            &self.old_task_binding,
            &self.new_task_binding,
            &self.renewal_packet_sha256,
            &self.new_registry2_declaration_digest,
        ] {
            id(h)?;
        }
        Self::lease(&self.old_complete_lease, profile)?;
        Self::lease(&self.new_complete_lease, profile)?;
        let raw = serde_json::to_vec(self).map_err(|_| PolicyError::Input)?;
        check(raw.len() <= 4096)?;
        let mut message = match profile {
            Profile::ClassicalV2 => DOMAIN,
            Profile::PqV3 => PQ_DOMAIN,
        }
        .to_vec();
        message.extend_from_slice(&(raw.len() as u32).to_le_bytes());
        message.extend_from_slice(&raw);
        Ok(crate::operator_task_policy::digest_bytes(&message))
    }
    pub(crate) fn check_declarations(
        &self,
        old: &DeclaredBinding,
        new: &DeclaredBinding,
    ) -> Result<()> {
        self.payload()?;
        let (old_raw, old_lease) = Self::lease(&self.old_complete_lease, self.profile()?)?;
        let (new_raw, new_lease) = Self::lease(&self.new_complete_lease, self.profile()?)?;
        check(
            same_except_lease(old, new)
                && old.task.native_task == self.native_task
                && new.task.native_task == self.native_task
                && declared_binding_digest(old)? == self.old_task_binding
                && declared_binding_digest(new)? == self.new_task_binding
                && crate::operator_task_policy::digest_bytes(&old_raw) == old.task.lease_sha256
                && crate::operator_task_policy::digest_bytes(&new_raw) == new.task.lease_sha256
                && old.task.lease_sha256 != new.task.lease_sha256
                && old_lease.successor(&new_lease),
        )
    }
    /// Byte equality against actual original Node state and the actual retained
    /// renewal packet, not a prior report boolean or a projected lease ID.
    pub(crate) fn check_actual(
        &self,
        parent: crate::Hash,
        generation: u64,
        old_lease: &[u8],
        new_lease: &[u8],
        actual_packet: &[u8],
    ) -> Result<()> {
        check(
            hex::encode(parent) == self.actual_parent
                && generation == self.actual_generation
                && hex::encode(old_lease) == self.old_complete_lease
                && hex::encode(new_lease) == self.new_complete_lease
                && crate::operator_task_policy::digest_bytes(actual_packet)
                    == self.renewal_packet_sha256,
        )
    }
}

enum Lease {
    Classical(DemandLeaseV2),
    Pq(DemandLeaseV5),
}
impl Lease {
    fn successor(&self, next: &Self) -> bool {
        match (self, next) {
            (Self::Classical(old), Self::Classical(new)) => {
                old.slot == new.slot
                    && old.purpose == new.purpose
                    && old.network == new.network
                    && old.parameters == new.parameters
                    && old.demand_id == new.demand_id
                    && old.requester == new.requester
                    && old.source == new.source
                    && old.generation == new.generation
                    && old.revision.checked_add(1) == Some(new.revision)
            }
            (Self::Pq(old), Self::Pq(new)) => {
                new.same_scope(old) && old.revision.checked_add(1) == Some(new.revision)
            }
            _ => false,
        }
    }
}

#[cfg(test)]
#[path = "operator_continuous_lease_tests.rs"]
pub(crate) mod tests;
