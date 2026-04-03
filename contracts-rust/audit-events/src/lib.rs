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
}
