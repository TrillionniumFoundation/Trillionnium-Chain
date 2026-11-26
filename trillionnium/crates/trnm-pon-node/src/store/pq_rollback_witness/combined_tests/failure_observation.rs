//! Failure-only test evidence independent of successful libtest output capture.
//! No business operation, retry, live deadline or production path is changed.
use super::{Process, Worker};
use crate::pq_rollback_witness::test_observation;
use serde_json::{json, Value};
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    sync::atomic::{AtomicUsize, Ordering},
};

const PREFIX: &str = "TRNM_PQ_FIXTURE_FAILURE_V1 ";
const MAX_CHILD_BYTES: usize = 32 * 1024;
const MAX_LINE_BYTES: usize = 16 * 1024;
const MAX_FAILURE_LOG_BYTES: usize = 64 * 1024;
// Separate, finite failure evidence; the existing 256 KiB observer budget and
// its normal output remain unchanged. This does not grant execution authority.
static FAILURE_LOG_REMAINING: AtomicUsize = AtomicUsize::new(MAX_FAILURE_LOG_BYTES);

fn projection(snapshot: &Value) -> Value {
    let fields = [
        "schema",
        "process_id",
        "measurement_unavailable",
        "encoding_truncated",
        "cpu_is_calling_thread_only",
        "operation_ids_are_process_local",
        "mark_order",
        "records_started",
        "records_completed",
        "records_closed",
        "records_overwritten",
        "measurement_failures",
        "has_open_operations",
        "scope_snapshot_is_final",
        "failure_checkpoint_saved",
        "last_failure",
        "last_service_failure",
        "last_tcp_failure",
    ];
    let mut value = serde_json::Map::new();
    for field in fields {
        value.insert(
            field.to_owned(),
            snapshot.get(field).cloned().unwrap_or(Value::Null),
        );
    }
    let records = snapshot
        .get("records")
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .take(8)
                .map(|row| {
                    let mut record = serde_json::Map::new();
                    for field in [
                        "id",
                        "kind",
                        "closed",
                        "accepted",
                        "error",
                        "wall_ns",
                        "thread_cpu_ns",
                        "original_remaining_ns",
                        "effective_remaining_ns",
                        "last_phase",
                        "transport_entered",
                        "cas_commit_attempted",
                        "cas_committed",
                        "local_commit_attempted",
                        "local_committed",
                        "matching_cas_receipt",
                    ] {
                        record.insert(
                            field.to_owned(),
                            row.get(field).cloned().unwrap_or(Value::Null),
                        );
                    }
                    Value::Object(record)
                })
                .collect::<Vec<_>>()
        });
    value.insert(
        "records".to_owned(),
        records.map_or(Value::Null, Value::Array),
    );
    value.insert(
        "nested_intervals_are_not_additive".to_owned(),
        Value::Bool(true),
    );
    value.insert("observation_has_authority".to_owned(), Value::Bool(false));
    Value::Object(value)
}

fn child_snapshot(external: &Process) -> Value {
    // Cleanup must already have observed this exact child's exit. Missing,
    // oversized, changed or malformed evidence is unknown, never a zero result.
    if external.status.is_none() {
        return json!({"status":"UNKNOWN","reason":"child_exit_not_observed"});
    }
    let read = || -> Option<Value> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(external.directory.path().join(test_observation::CHILD_FILE))
            .ok()?;
        let before = file.metadata().ok()?;
        if !before.is_file() || before.nlink() != 1 || before.len() > MAX_CHILD_BYTES as u64 {
            return None;
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(MAX_CHILD_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        let after = file.metadata().ok()?;
        let identity = |m: &std::fs::Metadata| {
            (
                m.dev(),
                m.ino(),
                m.mode(),
                m.nlink(),
                m.len(),
                m.mtime(),
                m.mtime_nsec(),
                m.ctime(),
                m.ctime_nsec(),
            )
        };
        if identity(&before) != identity(&after)
            || bytes.len() != before.len() as usize
            || bytes.len() > MAX_CHILD_BYTES
            || bytes.last() != Some(&b'\n')
        {
            return None;
        }
        let prefix = test_observation::PREFIX.as_bytes();
        let body = bytes.strip_prefix(prefix)?;
        if body[..body.len() - 1].contains(&b'\n') {
            return None;
        }
        let value: Value = serde_json::from_slice(body).ok()?;
        if value["schema"] != "pon-pq-test-phase-observation-v1"
            || value["process_id"].as_u64() != Some(u64::from(external.pid))
        {
            return None;
        }
        Some(projection(&value))
    };
    read().map_or_else(
        || json!({"status":"UNKNOWN","reason":"bounded_original_child_snapshot_unavailable"}),
        |snapshot| json!({"status":"OBSERVED","snapshot":snapshot}),
    )
}

fn encode_line(value: &Value, remaining: &AtomicUsize) -> Option<String> {
    let encoded = serde_json::to_string(value).ok()?;
    let bytes = PREFIX.len().checked_add(encoded.len())?.checked_add(1)?;
    if bytes > MAX_LINE_BYTES {
        return None;
    }
    remaining
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            n.checked_sub(bytes)
        })
        .ok()?;
    Some(format!("{PREFIX}{encoded}\n"))
}

pub(super) fn emit(scope: &test_observation::Scope, worker: &Worker, external: &Process) {
    let value = json!({
        "schema":"pon-pq-test-unexpected-failure-v1",
        "stage":"after_owned_cleanup",
        "parent":projection(&scope.snapshot()),
        "child":child_snapshot(external),
        "worker_join_observed":worker.joined,
        "child_exit_observed":external.status.is_some(),
        "child_exit_success":external.status.map(|status|status.success()),
        "metrics":worker.metrics.as_ref(),
        "business_result_preserved":true,
        "request_retry":false,
        "qualification":false,
    });
    let line = encode_line(&value, &FAILURE_LOG_REMAINING).or_else(|| {
        encode_line(
            &json!({
                "schema":"pon-pq-test-unexpected-failure-v1",
                "status":"UNKNOWN",
                "reason":"failure_record_oversized_or_budget_exhausted",
                "business_result_preserved":true,
                "qualification":false,
            }),
            &FAILURE_LOG_REMAINING,
        )
    });
    if let Some(line) = line {
        eprint!("{line}");
    }
}

#[test]
fn failure_projection_retains_typed_cause_and_unknown_fields_without_request_data() {
    let source = json!({
        "schema":"pon-pq-test-phase-observation-v1",
        "cpu_is_calling_thread_only":true,
        "operation_ids_are_process_local":true,
        "mark_order":["decode", "verify"],
        "last_tcp_failure":{"error":{"code":"PQ_WITNESS_DEADLINE"}},
        "records":[{"kind":"client_current","accepted":false,"effective_remaining_ns":250000000,
                    "request":"never-export","signature":"never-export"}],
        "request":"never-export",
    });
    let projected = projection(&source);
    assert_eq!(projected["last_tcp_failure"], source["last_tcp_failure"]);
    for field in [
        "cpu_is_calling_thread_only",
        "operation_ids_are_process_local",
        "mark_order",
    ] {
        assert_eq!(projected[field], source[field]);
    }
    assert!(projected["measurement_failures"].is_null());
    assert_eq!(projected["records"][0]["effective_remaining_ns"], 250000000);
    assert!(projected.get("request").is_none());
    assert!(projected["records"][0].get("signature").is_none());
    assert_eq!(projected["observation_has_authority"], false);
}

#[test]
fn failure_receipt_byte_limit_and_exhaustion_never_reset_the_local_budget() {
    let budget = AtomicUsize::new(MAX_FAILURE_LOG_BYTES);
    let huge = json!({"ignored": "x".repeat(MAX_LINE_BYTES)});
    assert!(encode_line(&huge, &budget).is_none());
    assert_eq!(budget.load(Ordering::Acquire), MAX_FAILURE_LOG_BYTES);
    let record = json!({"schema":"pon-pq-test-unexpected-failure-v1","qualification":false});
    let encoded = encode_line(&record, &budget).unwrap();
    assert!(encoded.len() <= MAX_LINE_BYTES);
    assert_eq!(
        budget.load(Ordering::Acquire),
        MAX_FAILURE_LOG_BYTES - encoded.len()
    );
    let exact = AtomicUsize::new(encoded.len());
    assert_eq!(encode_line(&record, &exact).unwrap(), encoded);
    assert_eq!(exact.load(Ordering::Acquire), 0);
    assert!(encode_line(&record, &exact).is_none());
    assert_eq!(exact.load(Ordering::Acquire), 0);
}
