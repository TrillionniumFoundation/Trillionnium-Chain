use std::cmp::Ordering;

use super::*;

const NORMALIZED_AUDIT_REASON_MAX_CHARS: usize = 160;
const NORMALIZED_AUDIT_NOTE_MAX_CHARS: usize = 160;

pub(crate) fn query_normalized_audit_events(
    node_events: &[NodeEventRecord],
    recs: &[AdapterRecord],
    query: &QueryNormalizedAuditEventsQuery,
) -> QueryNormalizedAuditEventsResponse {
    let limit = clamp_limit(
        "QueryNormalizedAuditEvents",
        query.limit,
        QUERY_NORMALIZED_AUDIT_EVENTS_LIMIT_DEFAULT,
        QUERY_NORMALIZED_AUDIT_EVENTS_LIMIT_MAX,
    );
    let mut events = collect_normalized_audit_events(node_events, recs, query);

    events.sort_by(compare_normalized_audit_events);

    paginate_normalized_audit_events(events, query.cursor.unwrap_or(0), limit)
}

fn collect_normalized_audit_events(
    node_events: &[NodeEventRecord],
    recs: &[AdapterRecord],
    query: &QueryNormalizedAuditEventsQuery,
) -> Vec<NormalizedAuditEvent> {
    let mut events = Vec::new();
    events.extend(
        node_events
            .iter()
            .filter_map(|event| map_node_event(event, query)),
    );
    events.extend(
        recs.iter()
            .filter(|record| record.status == "accepted")
            .filter_map(|record| map_adapter_record(record, query)),
    );
    events
}

fn map_node_event(
    event: &NodeEventRecord,
    query: &QueryNormalizedAuditEventsQuery,
) -> Option<NormalizedAuditEvent> {
    if !is_legal_node_event_transition(&event.event_type, &event.from_status, &event.to_status)
        || !is_trusted_event_source(event)
    {
        return None;
    }

    let actor = normalize_actor_or_signer(&event.actor)?;
    let event_type = format!("trnm.task.{}", event.event_type);
    if !matches_source_filter(query.source.as_deref(), "trnm.task")
        || !matches_event_type_filter(query.event_type.as_deref(), &event_type)
    {
        return None;
    }

    Some(NormalizedAuditEvent {
        source: "trnm.task".into(),
        event_type,
        actor: Some(actor),
        object_id: Some(format!("task:{}", event.task_id)),
        related_id: None,
        amount: None,
        reason: Some(bound_audit_text(
            &format!("{} -> {}", event.from_status, event.to_status),
            NORMALIZED_AUDIT_REASON_MAX_CHARS,
        )),
        note: event
            .resolution_code
            .as_deref()
            .map(|value| bound_audit_text(value, NORMALIZED_AUDIT_NOTE_MAX_CHARS)),
        checked_at: Some(format!("height:{}", event.block_height)),
        timestamp: None,
        subject: None,
    })
}

fn map_adapter_record(
    record: &AdapterRecord,
    query: &QueryNormalizedAuditEventsQuery,
) -> Option<NormalizedAuditEvent> {
    let actor = record
        .worker
        .as_deref()
        .and_then(normalize_actor_or_signer)?;
    let event_type = format!("trnm.adapter.{}", record.kind);
    if !matches_source_filter(query.source.as_deref(), "trnm.adapter")
        || !matches_event_type_filter(query.event_type.as_deref(), &event_type)
    {
        return None;
    }

    Some(NormalizedAuditEvent {
        source: "trnm.adapter".into(),
        event_type,
        actor: Some(actor),
        object_id: Some(format!("task:{}", record.task_id)),
        related_id: None,
        amount: None,
        reason: Some(bound_audit_text(
            "adapter-event",
            NORMALIZED_AUDIT_REASON_MAX_CHARS,
        )),
        note: record
            .tx_hash
            .as_deref()
            .or(record.result_hash.as_deref())
            .map(|value| bound_audit_text(value, NORMALIZED_AUDIT_NOTE_MAX_CHARS)),
        checked_at: Some(format!("height:{}", record.ts)),
        timestamp: None,
        subject: None,
    })
}

fn bound_audit_text(value: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }

    let mut out = String::new();
    for ch in value.chars() {
        if out.chars().count() + 1 > max_chars {
            if max_chars == 1 {
                return "…".to_string();
            }
            out.pop();
            out.push('…');
            break;
        }
        out.push(ch);
    }
    out
}

fn matches_source_filter(filter: Option<&str>, expected: &str) -> bool {
    !filter.is_some_and(|candidate| candidate != expected)
}

fn matches_event_type_filter(filter: Option<&str>, event_type: &str) -> bool {
    !filter.is_some_and(|candidate| candidate != event_type)
}

fn audit_event_height(event: &NormalizedAuditEvent) -> u64 {
    event
        .checked_at
        .as_deref()
        .and_then(|value| value.strip_prefix("height:"))
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0)
}

fn compare_normalized_audit_events(
    left: &NormalizedAuditEvent,
    right: &NormalizedAuditEvent,
) -> Ordering {
    audit_event_height(right)
        .cmp(&audit_event_height(left))
        .then_with(|| left.event_type.cmp(&right.event_type))
        .then_with(|| left.source.cmp(&right.source))
        .then_with(|| cmp_optional_str(left.object_id.as_deref(), right.object_id.as_deref()))
        .then_with(|| cmp_optional_str(left.actor.as_deref(), right.actor.as_deref()))
        .then_with(|| cmp_optional_str(left.checked_at.as_deref(), right.checked_at.as_deref()))
        .then_with(|| cmp_optional_str(left.note.as_deref(), right.note.as_deref()))
        .then_with(|| cmp_optional_str(left.reason.as_deref(), right.reason.as_deref()))
}

fn cmp_optional_str(left: Option<&str>, right: Option<&str>) -> Ordering {
    left.unwrap_or("").cmp(right.unwrap_or(""))
}

fn paginate_normalized_audit_events(
    events: Vec<NormalizedAuditEvent>,
    start: usize,
    limit: usize,
) -> QueryNormalizedAuditEventsResponse {
    let total = events.len();
    if start >= total {
        return QueryNormalizedAuditEventsResponse {
            events: Vec::new(),
            next_cursor: None,
            has_more: Some(false),
            total: Some(total),
        };
    }

    let end = (start + limit).min(total);
    let has_more = end < total;
    let page = events.into_iter().skip(start).take(limit).collect();

    QueryNormalizedAuditEventsResponse {
        events: page,
        next_cursor: if has_more {
            Some(end.to_string())
        } else {
            None
        },
        has_more: Some(has_more),
        total: Some(total),
    }
}
