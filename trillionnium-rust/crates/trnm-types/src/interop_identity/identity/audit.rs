use super::{
    is_disallowed_invisible_char, AuditAction, AuditEvent, CapabilityToken, DidRecord,
    IdentityRegistry,
};

impl IdentityRegistry {
    pub fn did(&self, did: &str) -> Option<&DidRecord> {
        self.dids.get(did)
    }

    pub fn capability(&self, token_id: u64) -> Option<&CapabilityToken> {
        self.capabilities.get(&token_id)
    }

    pub fn capability_ids_by_subject(&self, subject_did: &str) -> Vec<u64> {
        self.capabilities
            .values()
            .filter(|token| token.subject_did == subject_did)
            .map(|token| token.token_id)
            .collect()
    }

    pub fn audit_trail(&self) -> &[AuditEvent] {
        &self.audit_trail
    }

    fn normalize_note(note: Option<String>) -> Option<String> {
        note.and_then(|v| {
            let sanitized: String = v
                .trim()
                .chars()
                .map(|ch| {
                    if ch.is_control() || is_disallowed_invisible_char(ch) {
                        ' '
                    } else {
                        ch
                    }
                })
                .collect();

            let collapsed = sanitized.split_whitespace().collect::<Vec<_>>().join(" ");
            (!collapsed.is_empty()).then_some(collapsed)
        })
    }

    pub(super) fn push_audit(
        &mut self,
        action: AuditAction,
        actor: String,
        subject: String,
        at_height: u64,
        note: Option<String>,
    ) {
        let seq = self.audit_trail.len() as u64 + 1;
        self.audit_trail.push(AuditEvent {
            seq,
            action,
            actor,
            subject,
            at_height,
            note: Self::normalize_note(note),
        });
    }
}
