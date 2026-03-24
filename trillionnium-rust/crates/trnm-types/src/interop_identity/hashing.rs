use super::identity::{AuditAction, CapabilityScope, IdentityRegistry};

impl IdentityRegistry {
    pub fn content_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"dids");
        for (k, v) in &self.dids {
            hasher.update(k.as_bytes());
            hasher.update(v.did.as_bytes());
            hasher.update(v.controller.as_bytes());
            hasher.update(v.created_at.to_le_bytes());
            if let Some(r) = v.revoked_at {
                hasher.update([1]);
                hasher.update(r.to_le_bytes());
            } else {
                hasher.update([0]);
            }
        }
        hasher.update(b"caps");
        for (k, v) in &self.capabilities {
            hasher.update(k.to_le_bytes());
            hasher.update(v.token_id.to_le_bytes());
            hasher.update(v.subject_did.as_bytes());
            let scope_byte = match v.scope {
                CapabilityScope::BridgeSettle => 1,
                CapabilityScope::BridgeRevert => 2,
                CapabilityScope::AuditRead => 3,
                CapabilityScope::MarketPublish => 4,
                CapabilityScope::MarketExecute => 5,
            };
            hasher.update([scope_byte]);
            hasher.update(v.issued_at.to_le_bytes());
            if let Some(exp) = v.expires_at {
                hasher.update([1]);
                hasher.update(exp.to_le_bytes());
            } else {
                hasher.update([0]);
            }
            if let Some(rev) = v.revoked_at {
                hasher.update([1]);
                hasher.update(rev.to_le_bytes());
            } else {
                hasher.update([0]);
            }
        }
        hasher.update(b"audit");
        hasher.update(self.audit_trail.len().to_le_bytes());
        for ev in &self.audit_trail {
            hasher.update(ev.seq.to_le_bytes());
            let action_tag = match ev.action {
                AuditAction::DidRegistered => 1u8,
                AuditAction::DidRevoked => 2u8,
                AuditAction::CapabilityIssued => 3u8,
                AuditAction::CapabilityRenewed => 4u8,
                AuditAction::CapabilityRevoked => 5u8,
            };
            hasher.update([action_tag]);
            hasher.update(ev.actor.as_bytes());
            hasher.update(ev.subject.as_bytes());
            hasher.update(ev.at_height.to_le_bytes());
            if let Some(note) = ev.note.as_deref() {
                hasher.update([1]);
                hasher.update(note.as_bytes());
            } else {
                hasher.update([0]);
            }
        }
        hasher.update(self.next_capability_id.to_le_bytes());
        hasher.finalize().into()
    }
}
