//! Distinct outside allocated recipient permission, never a local Search claim.
//! Full original packet Work/State remains mandatory after cheap exact checks.
use crate::operator_continuous_history::{Claim, Identity};
use crate::operator_task_policy::{PolicyError, Task};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use trnm_crypto_primitives::verify_hex_strict;
type Result<T> = std::result::Result<T, PolicyError>;
const DOMAIN: &[u8] = b"TRNM-RESTRICTED-CONTINUOUS-RECIPIENT2";
const OP_DOMAIN: &[u8] = b"TRNM-RESTRICTED-CONTINUOUS-OP2";
const TASK_DOMAIN: &[u8] = b"TRNM-RESTRICTED-CONTINUOUS-DECLARED-TASK2";
const MAX_BYTES: usize = 65536;
fn check(ok: bool, e: PolicyError) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(e)
    }
}
fn digest(raw: &[u8]) -> String {
    hex::encode(Sha256::digest(raw))
}
fn id(v: &str, n: usize) -> Result<()> {
    check(
        v.len() == 2 * n
            && v.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        PolicyError::Input,
    )
}
fn put_text(raw: &mut Vec<u8>, v: &str) {
    raw.extend_from_slice(&(v.len() as u32).to_le_bytes());
    raw.extend_from_slice(v.as_bytes());
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeclaredBinding {
    pub task: Task,
    pub instance_class: String,
    pub source_class: String,
    pub cost_class: String,
    pub cost_evidence: Option<String>,
    pub preprocessing: String,
    pub prepared_artifact: Option<String>,
    pub setup_record: Option<String>,
    pub funding_commitment: String,
    pub funding_evidence: String,
}
impl DeclaredBinding {
    fn validate(&self) -> Result<()> {
        let t = &self.task;
        check(
            t.purpose == "maintenance-tag1"
                && t.dimension == 64
                && t.field_modulus == 4294967291
                && t.encoding == "canonical-u32-le",
            PolicyError::Unsupported,
        )?;
        for s in [&t.model_id, &t.layer_tensor] {
            check(
                !s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_control),
                PolicyError::Input,
            )?;
        }
        id(&t.model_revision, 20)?;
        for h in [
            &t.native_task,
            &t.lease_sha256,
            &t.model_material,
            &t.native_model,
            &t.layer_selector,
            &t.input_material,
            &t.native_input,
            &t.a_sha256,
            &t.b_sha256,
            &t.full_material_catalog,
            &t.recipe_sha256,
            &self.funding_commitment,
            &self.funding_evidence,
        ] {
            id(h, 32)?;
        }
        check(
            matches!(
                self.instance_class.as_str(),
                "dense" | "structured" | "zero"
            ) && matches!(
                self.source_class.as_str(),
                "declared-same-operator"
                    | "declared-licensed-external"
                    | "declared-public-artifact"
            ) && matches!(
                self.cost_class.as_str(),
                "unmeasured" | "reported-full-invocation" | "reported-preprocessed-reuse"
            ),
            PolicyError::Input,
        )?;
        if self.cost_class == "unmeasured" {
            check(self.cost_evidence.is_none(), PolicyError::Input)?;
        } else {
            id(self.cost_evidence.as_deref().ok_or(PolicyError::Input)?, 32)?;
        }
        match self.preprocessing.as_str() {
            "forbidden" => check(
                self.prepared_artifact.is_none() && self.setup_record.is_none(),
                PolicyError::Input,
            )?,
            "exact-task-input-only" => {
                id(
                    self.prepared_artifact
                        .as_deref()
                        .ok_or(PolicyError::Input)?,
                    32,
                )?;
                id(self.setup_record.as_deref().ok_or(PolicyError::Input)?, 32)?;
            }
            _ => return Err(PolicyError::Input),
        }
        Ok(())
    }
}
pub(crate) fn declared_binding_digest(v: &DeclaredBinding) -> Result<String> {
    v.validate()?;
    let raw = serde_json::to_vec(v).map_err(|_| PolicyError::Input)?;
    check(raw.len() <= MAX_BYTES, PolicyError::Capacity)?;
    let mut message = TASK_DOMAIN.to_vec();
    message.extend_from_slice(&(raw.len() as u32).to_le_bytes());
    message.extend_from_slice(&raw);
    Ok(digest(&message))
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum Origin {
    MinerSearch {
        miner_node: String,
        search_operation: String,
        search_claim_sha256: String,
        search_result_sha256: String,
        packet_sha256: String,
        parent: String,
        generation: u64,
        task_binding_sha256: String,
        actual_trials: u64,
        source_commit: String,
        node_policy_source: String,
        closed_receipt_sha256: String,
    },
    ClosedFixture {
        producer_node: String,
        packet_sha256: String,
        parent: String,
        generation: u64,
        task_binding_sha256: String,
        source_commit: String,
        node_policy_source: String,
        native_receipt_sha256: String,
        full_reference_receipt_sha256: String,
    },
}
impl Origin {
    fn check(&self, c: &Claim) -> Result<()> {
        let (packet, parent, generation, binding) = match self {
            Self::MinerSearch {
                miner_node,
                search_operation,
                search_claim_sha256,
                search_result_sha256,
                packet_sha256,
                parent,
                generation,
                task_binding_sha256,
                actual_trials,
                source_commit,
                node_policy_source,
                closed_receipt_sha256,
            } => {
                for h in [
                    miner_node,
                    search_operation,
                    search_claim_sha256,
                    search_result_sha256,
                    node_policy_source,
                    closed_receipt_sha256,
                ] {
                    id(h, 32)?;
                }
                id(source_commit, 20)?;
                check(
                    *actual_trials > 0 && *actual_trials <= 4096,
                    PolicyError::Input,
                )?;
                (packet_sha256, parent, generation, task_binding_sha256)
            }
            Self::ClosedFixture {
                producer_node,
                packet_sha256,
                parent,
                generation,
                task_binding_sha256,
                source_commit,
                node_policy_source,
                native_receipt_sha256,
                full_reference_receipt_sha256,
            } => {
                for h in [
                    producer_node,
                    node_policy_source,
                    native_receipt_sha256,
                    full_reference_receipt_sha256,
                ] {
                    id(h, 32)?;
                }
                id(source_commit, 20)?;
                (packet_sha256, parent, generation, task_binding_sha256)
            }
        };
        for h in [packet, parent, binding] {
            id(h, 32)?;
        }
        check(
            *packet == c.payload
                && *parent == c.parent
                && *generation == c.generation
                && *binding == c.task_binding,
            PolicyError::NativeBinding,
        )
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AllocationBody {
    pub schema: String,
    pub identity: Identity,
    pub allocator_sequence: u64,
    pub allocator_previous_digest: Option<String>,
    pub allocator_record_sha256: String,
    pub local_budget_sequence: u64,
    pub local_budget_digest: String,
    pub claim: Claim,
    pub declared_binding: DeclaredBinding,
    pub origin: Option<Origin>,
    pub issued_ns: u64,
    pub expires_ns: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    body: AllocationBody,
    registry_signature: String,
    task_signature: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Authority {
    pub identity: Identity,
    pub expected: AllocationBody,
    pub expected_envelope_sha256: String,
    pub latest_allocator_sequence: u64,
    pub latest_allocator_digest: String,
}
pub(crate) struct VerifiedAllocation {
    body: AllocationBody,
}
pub(crate) fn operation_id(identity: &Identity, c: &Claim) -> Result<String> {
    identity.validate()?;
    let identity_raw = serde_json::to_vec(identity).map_err(|_| PolicyError::Input)?;
    for h in [
        &c.operation_nonce,
        &c.payload,
        &c.parent,
        &c.native_task,
        &c.task_binding,
        &c.global_allocation_id,
    ] {
        id(h, 32)?;
    }
    check(
        c.purpose.len() <= 32
            && matches!(c.instance_class.as_str(), "dense" | "structured" | "zero"),
        PolicyError::Input,
    )?;
    let mut out = OP_DOMAIN.to_vec();
    out.extend_from_slice(&(identity_raw.len() as u32).to_le_bytes());
    out.extend_from_slice(&identity_raw);
    put_text(&mut out, &c.purpose);
    for h in [&c.operation_nonce, &c.payload, &c.parent] {
        out.extend_from_slice(&hex::decode(h).map_err(|_| PolicyError::Input)?);
    }
    out.extend_from_slice(&c.generation.to_le_bytes());
    out.extend_from_slice(&hex::decode(&c.native_task).map_err(|_| PolicyError::Input)?);
    put_text(&mut out, &c.instance_class);
    for h in [&c.task_binding, &c.global_allocation_id] {
        out.extend_from_slice(&hex::decode(h).map_err(|_| PolicyError::Input)?);
    }
    out.extend_from_slice(&c.global_allocation_sequence.to_le_bytes());
    Ok(digest(&out))
}
fn message(body: &AllocationBody, role: u8) -> Result<Vec<u8>> {
    let raw = serde_json::to_vec(body).map_err(|_| PolicyError::Input)?;
    check(raw.len() <= MAX_BYTES, PolicyError::Capacity)?;
    let mut out = DOMAIN.to_vec();
    out.push(role);
    out.extend_from_slice(&(raw.len() as u32).to_le_bytes());
    out.extend_from_slice(&raw);
    Ok(out)
}
pub(crate) fn authenticate(raw: &[u8], e: &Authority, now: u64) -> Result<VerifiedAllocation> {
    check(
        !raw.is_empty() && raw.len() <= MAX_BYTES,
        PolicyError::Capacity,
    )?;
    e.identity.validate()?;
    for h in [&e.expected_envelope_sha256, &e.latest_allocator_digest] {
        id(h, 32)?;
    }
    let v: Envelope = serde_json::from_slice(raw).map_err(|_| PolicyError::Input)?;
    check(
        v.body.schema == "restricted-continuous-recipient-allocation-v2"
            && v.body.identity == e.identity
            && v.body == e.expected
            && digest(raw) == e.expected_envelope_sha256
            && v.body.allocator_sequence == e.latest_allocator_sequence
            && v.body.allocator_record_sha256 == e.latest_allocator_digest,
        PolicyError::ExternalContext,
    )?;
    let b = &v.body;
    check(
        b.allocator_sequence > 0
            && b.allocator_sequence <= 131072
            && (b.allocator_sequence == 1) == b.allocator_previous_digest.is_none()
            && b.issued_ns <= now
            && now < b.expires_ns
            && b.expires_ns - b.issued_ns <= 86_400_000_000_000
            && b.local_budget_sequence > 0,
        PolicyError::Window,
    )?;
    if let Some(h) = &b.allocator_previous_digest {
        id(h, 32)?;
    }
    for h in [&b.allocator_record_sha256, &b.local_budget_digest] {
        id(h, 32)?;
    }
    b.claim.validate()?;
    check(
        b.claim.operation == operation_id(&e.identity, &b.claim)?
            && b.claim.global_allocation_sequence == b.allocator_sequence
            && b.claim.task_binding == declared_binding_digest(&b.declared_binding)?
            && b.claim.native_task == b.declared_binding.task.native_task
            && b.claim.instance_class == b.declared_binding.instance_class,
        PolicyError::NativeBinding,
    )?;
    check(
        b.declared_binding.preprocessing != "forbidden" || b.claim.allocation.reuse_uses == 0,
        PolicyError::NativeBinding,
    )?;
    if matches!(
        b.claim.purpose.as_str(),
        "receiver-validation" | "receiver-activate"
    ) {
        b.origin
            .as_ref()
            .ok_or(PolicyError::NativeBinding)?
            .check(&b.claim)?;
    } else {
        check(b.origin.is_none(), PolicyError::Input)?;
    }
    verify_hex_strict(
        &e.identity.registry_key,
        &message(b, 1)?,
        &v.registry_signature,
    )
    .map_err(|_| PolicyError::Signature)?;
    verify_hex_strict(&e.identity.task_key, &message(b, 2)?, &v.task_signature)
        .map_err(|_| PolicyError::Signature)?;
    Ok(VerifiedAllocation { body: v.body })
}
impl VerifiedAllocation {
    pub(crate) fn body(&self) -> &AllocationBody {
        &self.body
    }
    pub(crate) fn check_delegation(
        &self,
        d: &crate::operator_continuous_history::RegistryDelegation,
        now: u64,
    ) -> Result<()> {
        let b = &self.body;
        let c = &b.claim;
        check(
            b.declared_binding == d.declared_binding
                && d.allowed_purposes.iter().any(|p| p == &c.purpose)
                && d.recipient_nodes
                    .iter()
                    .any(|p| p == &b.identity.recipient_node)
                && d.global_allocator == b.identity.global_allocator
                && d.not_before_ns <= b.issued_ns
                && b.expires_ns <= d.expires_ns
                && now >= d.not_before_ns
                && now < d.expires_ns
                && now >= b.issued_ns
                && now < b.expires_ns
                && b.allocator_sequence >= d.allocator_latest.sequence,
            PolicyError::ExternalContext,
        )?;
        if b.allocator_sequence == d.allocator_latest.sequence {
            check(
                b.allocator_record_sha256 == d.allocator_latest.digest,
                PolicyError::ExternalContext,
            )?;
        }
        Ok(())
    }
    pub(crate) fn identity(&self) -> &Identity {
        &self.body.identity
    }
    pub(crate) fn claim(&self) -> &Claim {
        &self.body.claim
    }
    pub(crate) fn local_budget(&self) -> (u64, &str) {
        (
            self.body.local_budget_sequence,
            &self.body.local_budget_digest,
        )
    }
    /// Cheap digest/typed header-task check precedes State/lease/context/M05.
    /// This is metadata permission, never WorkCheckedPacket or admitted State.
    pub(crate) fn check_exact_receiver_packet(
        &self,
        packet: &crate::Packet,
        parent: crate::Hash,
        generation: u64,
    ) -> Result<()> {
        let c = &self.body.claim;
        check(
            c.purpose == "receiver-validation"
                && c.parent == hex::encode(parent)
                && c.generation == generation
                && packet.header.parent == parent
                && hex::encode(packet.header.work_task) == c.native_task,
            PolicyError::NativeBinding,
        )?;
        let raw = packet.encode().map_err(|_| PolicyError::NativeBinding)?;
        check(digest(&raw) == c.payload, PolicyError::NativeBinding)
    }
}
#[cfg(all(test, target_os = "linux"))]
#[path = "operator_continuous_recipient_tests.rs"]
mod tests;
