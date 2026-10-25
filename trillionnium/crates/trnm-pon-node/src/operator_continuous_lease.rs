//! An explicit signed, immediate original tag22 lease edge. No source/class or
//! matrix substitution, implicit discovery, historical rewrite or budget reset.
use crate::operator_continuous_recipient::{declared_binding_digest, DeclaredBinding};
use crate::operator_task_policy::PolicyError;
use serde::{Deserialize, Serialize};
use trnm_protocol::qualified_work_task::lifecycle_v2::DemandLeaseV2;
type Result<T> = std::result::Result<T, PolicyError>;
const DOMAIN: &[u8] = b"TRNM-RESTRICTED-CONTINUOUS-LEASE-EDGE1";
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
    fn lease(value: &str) -> Result<(Vec<u8>, DemandLeaseV2)> {
        check(
            value.len() == 2 * trnm_protocol::qualified_work_task::lifecycle_v2::DEMAND_LEASE_BYTES,
        )?;
        let raw = hex::decode(value).map_err(|_| PolicyError::Input)?;
        check(hex::encode(&raw) == value)?;
        let lease = DemandLeaseV2::decode(&raw).map_err(|_| PolicyError::NativeBinding)?;
        check(lease.encode().map_err(|_| PolicyError::NativeBinding)? == raw)?;
        Ok((raw, lease))
    }
    pub(crate) fn payload(&self) -> Result<String> {
        check(self.schema == "restricted-continuous-lease-edge-v1")?;
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
        Self::lease(&self.old_complete_lease)?;
        Self::lease(&self.new_complete_lease)?;
        let raw = serde_json::to_vec(self).map_err(|_| PolicyError::Input)?;
        check(raw.len() <= 4096)?;
        let mut message = DOMAIN.to_vec();
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
        let (old_raw, old_lease) = Self::lease(&self.old_complete_lease)?;
        let (new_raw, new_lease) = Self::lease(&self.new_complete_lease)?;
        check(
            same_except_lease(old, new)
                && old.task.native_task == self.native_task
                && new.task.native_task == self.native_task
                && declared_binding_digest(old)? == self.old_task_binding
                && declared_binding_digest(new)? == self.new_task_binding
                && crate::operator_task_policy::digest_bytes(&old_raw) == old.task.lease_sha256
                && crate::operator_task_policy::digest_bytes(&new_raw) == new.task.lease_sha256
                && old.task.lease_sha256 != new.task.lease_sha256
                && old_lease.slot == new_lease.slot
                && old_lease.purpose == new_lease.purpose
                && old_lease.network == new_lease.network
                && old_lease.parameters == new_lease.parameters
                && old_lease.demand_id == new_lease.demand_id
                && old_lease.requester == new_lease.requester
                && old_lease.source == new_lease.source
                && old_lease.generation == new_lease.generation
                && old_lease.revision.checked_add(1) == Some(new_lease.revision),
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

#[cfg(test)]
#[path = "operator_continuous_lease_tests.rs"]
pub(crate) mod tests;


/// Read-only Q4 overlap forecast for an independently signed *future* source
/// statement. This never checks a signature or returns admission authority:
/// the caller must re-read the actual parent, perform original dual-signature
/// verification and submit tag22 before the old lease expires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Q4RenewalPhase {
    AwaitSignedWindow,
    WindowOpenByTime,
    AtRisk,
    Expired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Q4RenewalForecast {
    pub phase: Q4RenewalPhase,
    pub earliest_possible_height: u64,
    pub last_legal_height: u64,
    pub inclusion_slack_blocks: u64,
    pub assumed_queue_lag_blocks: u64,
    pub assumed_safety_margin_blocks: u64,
}

/// Conservative timing *advice*, not a scheduler, lease issuer or consensus
/// validity check. Assumed lag/margin have no network guarantee. Every call
/// must use the active parent branch's canonical original lease and an already
/// independently prepared successor; reorg or signature withdrawal invalidates
/// the forecast.
pub fn forecast_q4_renewal_window(
    old: &DemandLeaseV2,
    next: &DemandLeaseV2,
    next_block_height: u64,
    assumed_queue_lag_blocks: u64,
    assumed_safety_margin_blocks: u64,
) -> Result<Q4RenewalForecast> {
    check(old.encode().is_ok() && next.encode().is_ok())?;
    check(
        old.network == next.network
            && old.parameters == next.parameters
            && old.slot == next.slot
            && old.generation == next.generation
            && old.demand_id == next.demand_id
            && old.requester == next.requester
            && old.source == next.source
            && old.purpose == next.purpose
            && old.cost_class == next.cost_class
            && old.source_record == next.source_record
            && old.authorization_scope == next.authorization_scope
            && old.availability_manifest == next.availability_manifest
            && old.availability_root == next.availability_root
            && old.revision.checked_add(1) == Some(next.revision)
            && old.not_before <= next.not_before
            && next.not_before <= old.expires
            && next.expires > old.expires,
    )?;
    check(
        assumed_queue_lag_blocks <= 1000 && assumed_safety_margin_blocks <= 1000,
    )?;
    let need = assumed_queue_lag_blocks
        .checked_add(assumed_safety_margin_blocks)
        .ok_or(PolicyError::Budget)?;
    let earliest = next_block_height.max(next.not_before);
    let remaining = old.expires.saturating_sub(earliest);
    let phase = if next_block_height > old.expires {
        Q4RenewalPhase::Expired
    } else if next_block_height < next.not_before {
        Q4RenewalPhase::AwaitSignedWindow
    } else if remaining < need {
        Q4RenewalPhase::AtRisk
    } else {
        Q4RenewalPhase::WindowOpenByTime
    };
    Ok(Q4RenewalForecast {
        phase,
        earliest_possible_height: earliest,
        last_legal_height: old.expires,
        inclusion_slack_blocks: remaining,
        assumed_queue_lag_blocks,
        assumed_safety_margin_blocks,
    })
}
