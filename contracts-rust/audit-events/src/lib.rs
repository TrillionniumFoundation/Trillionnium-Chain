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
