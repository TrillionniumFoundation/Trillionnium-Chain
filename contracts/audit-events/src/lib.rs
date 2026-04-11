#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub source: &'static str,
    pub event_type: &'static str,
    pub actor: Option<String>,
    pub object_id: Option<String>,
    pub related_id: Option<String>,
    pub amount: Option<u128>,
    pub reason: Option<String>,
    pub note: Option<String>,
}

impl AuditEvent {
    #[must_use]
    pub fn new(source: &'static str, event_type: &'static str) -> Self {
        Self {
            source,
            event_type,
            actor: None,
            object_id: None,
            related_id: None,
            amount: None,
            reason: None,
            note: None,
        }
    }

    #[must_use]
    pub fn with_actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = Some(actor.into());
        self
    }

    #[must_use]
    pub fn with_object_id(mut self, object_id: impl Into<String>) -> Self {
        self.object_id = Some(object_id.into());
        self
    }

    #[must_use]
    pub fn with_related_id(mut self, related_id: impl Into<String>) -> Self {
        self.related_id = Some(related_id.into());
        self
    }

    #[must_use]
    pub fn with_amount(mut self, amount: u128) -> Self {
        self.amount = Some(amount);
        self
    }

    #[must_use]
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::AuditEvent;

    #[test]
    fn new_preserves_source_and_event_type() {
        let event = AuditEvent::new("bridge-relay", "bridge_relay.config_version_updated");

        assert_eq!(event.source, "bridge-relay");
        assert_eq!(event.event_type, "bridge_relay.config_version_updated");
    }

    #[test]
    fn new_starts_with_all_optional_fields_absent() {
        let event = AuditEvent::new("governance-guard", "governance.proposal_executed");

        assert_eq!(event.actor, None);
        assert_eq!(event.object_id, None);
        assert_eq!(event.related_id, None);
        assert_eq!(event.amount, None);
        assert_eq!(event.reason, None);
        assert_eq!(event.note, None);
    }

    #[test]
    fn builder_setters_fill_normalized_fields() {
        let event = AuditEvent::new("settlement-vault", "vault.locked")
            .with_actor("operator")
            .with_object_id("req-7")
            .with_related_id("alice")
            .with_amount(42)
            .with_reason("manual_review")
            .with_note("eta=123");

        assert_eq!(event.actor.as_deref(), Some("operator"));
        assert_eq!(event.object_id.as_deref(), Some("req-7"));
        assert_eq!(event.related_id.as_deref(), Some("alice"));
        assert_eq!(event.amount, Some(42));
        assert_eq!(event.reason.as_deref(), Some("manual_review"));
        assert_eq!(event.note.as_deref(), Some("eta=123"));
    }
}
