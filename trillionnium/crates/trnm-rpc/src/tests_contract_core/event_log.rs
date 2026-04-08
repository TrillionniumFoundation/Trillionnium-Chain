pub(crate) use super::*;

#[test]
fn parse_event_log_kv_preserves_quoted_values_with_spaces() {
    let line = "[event] event_type=resolve task_id=7 from_status=Challenged to_status=Completed actor=authority tx_id=9 block_height=12 state_root=abc ts_unix_ms=1000 resolution_code=\"timeout reached\" bond_disposition='forfeit all'";
    let kv = parse_event_log_kv(line);

    assert_eq!(kv.get("event_type").map(String::as_str), Some("resolve"));
    assert_eq!(
        kv.get("resolution_code").map(String::as_str),
        Some("timeout reached")
    );
    assert_eq!(
        kv.get("bond_disposition").map(String::as_str),
        Some("forfeit all")
    );
}

#[test]
fn load_node_events_parses_llm_metering_audit_block() {
    let root = tempfile::tempdir().expect("tempdir");
    let run = root.path().join("run");
    fs::create_dir_all(&run).expect("create run dir");
    let line = "2026-03-03T20:10:12Z INFO node [event] event_schema=v1 event_type=resolve task_id=7 from_status=Challenged to_status=Completed actor=authority signer=authority challenger=challenger-a tx_hash=0x123 tx_id=2 block_height=2 state_root=s2 ts_unix_ms=2000 resolution_code=completed treasury_delta=0 challenger_delta=0 bond_disposition=forfeited metering_workload_class=llm_inference metering_schema=llm_token_meter_v1 metering_receipt_hash=deadbeef metering_policy_snapshot_version=1 metering_prompt_tokens=128 metering_generated_tokens=32 metering_decode_steps=32 metering_kv_bytes_moved=4096 metering_normalized_work_units=192 metering_prompt_token_weight=1 metering_generated_token_weight=1 metering_decode_step_weight=1 metering_kv_byte_weight=0 metering_min_accept_work_units=100 metering_challenge_success_bounty_base=1 metering_challenge_success_bounty_per_work_unit_num=1 metering_challenge_success_bounty_per_work_unit_den=192 metering_worker_completion_bonus_per_work_unit_num=1 metering_worker_completion_bonus_per_work_unit_den=256 metering_worker_slash_rebate_per_work_unit_num=1 metering_worker_slash_rebate_per_work_unit_den=384
";
    fs::write(run.join("node1.log"), line).expect("write log");

    let loaded = load_node_events_from_root(root.path(), NodeEventScanMode::Authoritative);
    assert_eq!(loaded.events.len(), 1);
    let metering = loaded.events[0]
        .metering
        .as_ref()
        .expect("metering expected");
    assert_eq!(metering.normalized_work_units, 192);
    assert_eq!(metering.policy.snapshot_version, 1);
    assert_eq!(metering.policy.min_accept_work_units, 100);
    assert_eq!(
        metering.policy.challenge_success_bounty_per_work_unit_den,
        192
    );
    assert_eq!(metering.derived.path, "Completed");
    assert_eq!(metering.derived.challenge_bonus_total, 2);
}

#[test]
fn load_node_events_normalizes_wrapped_metering_numeric_fields() {
    let root = tempfile::tempdir().expect("tempdir");
    let run = root.path().join("run");
    fs::create_dir_all(&run).expect("create run dir");
    let line = "2026-03-03T20:10:12Z INFO node [event] event_schema=v1 event_type=resolve task_id=7 from_status=Challenged to_status=Completed actor=authority signer=authority challenger=challenger-a tx_hash=0x123 tx_id=2 block_height=2 state_root=s2 ts_unix_ms=2000 resolution_code=completed treasury_delta=0 challenger_delta=0 bond_disposition=forfeited metering_workload_class=llm_inference metering_schema=llm_token_meter_v1 metering_receipt_hash=deadbeef metering_policy_snapshot_version='1' metering_prompt_tokens='128,' metering_generated_tokens='32;' metering_decode_steps='(32)' metering_kv_bytes_moved='[4096]' metering_normalized_work_units='{192}' metering_prompt_token_weight='1' metering_generated_token_weight='1' metering_decode_step_weight='1' metering_kv_byte_weight='0' metering_min_accept_work_units='100' metering_challenge_success_bounty_base='1' metering_challenge_success_bounty_per_work_unit_num='1' metering_challenge_success_bounty_per_work_unit_den='192' metering_worker_completion_bonus_per_work_unit_num='1' metering_worker_completion_bonus_per_work_unit_den='256' metering_worker_slash_rebate_per_work_unit_num='1' metering_worker_slash_rebate_per_work_unit_den='384'
";
    fs::write(run.join("node1.log"), line).expect("write log");

    let loaded = load_node_events_from_root(root.path(), NodeEventScanMode::Authoritative);
    assert_eq!(loaded.events.len(), 1);
    let metering = loaded.events[0]
        .metering
        .as_ref()
        .expect("wrapped metering expected");
    assert_eq!(metering.prompt_tokens, 128);
    assert_eq!(metering.generated_tokens, 32);
    assert_eq!(metering.decode_steps, 32);
    assert_eq!(metering.kv_bytes_moved, 4096);
    assert_eq!(metering.normalized_work_units, 192);
    assert_eq!(metering.policy.snapshot_version, 1);
    assert_eq!(metering.derived.challenge_bonus_total, 2);
}

#[test]
fn load_node_events_normalizes_wrapped_metering_text_fields() {
    let root = tempfile::tempdir().expect("tempdir");
    let run = root.path().join("run");
    fs::create_dir_all(&run).expect("create run dir");
    let line = "2026-03-03T20:10:12Z INFO node [event] event_schema=v1 event_type=resolve task_id=7 from_status=' Challenged ' to_status=' [Completed] ' actor=authority signer=' authority ' challenger=' {challenger-a} ' tx_hash=' (0x123) ' tx_id=2 block_height=2 state_root=s2 ts_unix_ms=2000 resolution_code=' completed ' treasury_delta=0 challenger_delta=0 bond_disposition=' forfeited ' metering_workload_class=' [llm_inference] ' metering_schema=' {llm_token_meter_v1} ' metering_receipt_hash=' (deadbeef) ' metering_policy_snapshot_version=1 metering_prompt_tokens=128 metering_generated_tokens=32 metering_decode_steps=32 metering_kv_bytes_moved=4096 metering_normalized_work_units=192 metering_prompt_token_weight=1 metering_generated_token_weight=1 metering_decode_step_weight=1 metering_kv_byte_weight=0 metering_min_accept_work_units=100 metering_challenge_success_bounty_base=1 metering_challenge_success_bounty_per_work_unit_num=1 metering_challenge_success_bounty_per_work_unit_den=192 metering_worker_completion_bonus_per_work_unit_num=1 metering_worker_completion_bonus_per_work_unit_den=256 metering_worker_slash_rebate_per_work_unit_num=1 metering_worker_slash_rebate_per_work_unit_den=384
";
    fs::write(run.join("node1.log"), line).expect("write log");

    let loaded = load_node_events_from_root(root.path(), NodeEventScanMode::Authoritative);
    assert_eq!(loaded.events.len(), 1);
    let event = &loaded.events[0];
    assert_eq!(event.from_status.as_deref(), Some("Challenged"));
    assert_eq!(event.to_status.as_deref(), Some("Completed"));
    assert_eq!(event.signer.as_deref(), Some("authority"));
    assert_eq!(event.challenger.as_deref(), Some("challenger-a"));
    assert_eq!(event.tx_hash.as_deref(), Some("0x123"));
    assert_eq!(event.resolution_code.as_deref(), Some("completed"));
    assert_eq!(event.bond_disposition.as_deref(), Some("forfeited"));
    let metering = event.metering.as_ref().expect("wrapped metering expected");
    assert_eq!(metering.workload_class, "llm_inference");
    assert_eq!(metering.metering_schema, "llm_token_meter_v1");
    assert_eq!(metering.receipt_hash, "deadbeef");
    assert_eq!(metering.derived.path, "Completed");
}

#[test]
fn load_node_events_drops_invalid_metering_policy_with_zero_denominator() {
    let root = tempfile::tempdir().expect("tempdir");
    let run = root.path().join("run");
    fs::create_dir_all(&run).expect("create run dir");
    let line = "2026-03-03T20:10:12Z INFO node [event] event_schema=v1 event_type=resolve task_id=7 from_status=Challenged to_status=Completed actor=authority signer=authority challenger=challenger-a tx_hash=0x123 tx_id=2 block_height=2 state_root=s2 ts_unix_ms=2000 resolution_code=completed treasury_delta=0 challenger_delta=0 bond_disposition=forfeited metering_workload_class=llm_inference metering_schema=llm_token_meter_v1 metering_receipt_hash=deadbeef metering_policy_snapshot_version=1 metering_prompt_tokens=128 metering_generated_tokens=32 metering_decode_steps=32 metering_kv_bytes_moved=4096 metering_normalized_work_units=192 metering_prompt_token_weight=1 metering_generated_token_weight=1 metering_decode_step_weight=1 metering_kv_byte_weight=0 metering_min_accept_work_units=100 metering_challenge_success_bounty_base=1 metering_challenge_success_bounty_per_work_unit_num=1 metering_challenge_success_bounty_per_work_unit_den=0 metering_worker_completion_bonus_per_work_unit_num=1 metering_worker_completion_bonus_per_work_unit_den=256 metering_worker_slash_rebate_per_work_unit_num=1 metering_worker_slash_rebate_per_work_unit_den=384
";
    fs::write(run.join("node1.log"), line).expect("write log");

    let loaded = load_node_events_from_root(root.path(), NodeEventScanMode::Authoritative);
    assert_eq!(loaded.events.len(), 1);
    assert!(loaded.events[0].metering.is_none());
}

#[test]
fn load_node_events_drops_invalid_metering_policy_with_zero_snapshot_version() {
    let root = tempfile::tempdir().expect("tempdir");
    let run = root.path().join("run");
    fs::create_dir_all(&run).expect("create run dir");
    let line = "2026-03-03T20:10:12Z INFO node [event] event_schema=v1 event_type=resolve task_id=7 from_status=Challenged to_status=Completed actor=authority signer=authority challenger=challenger-a tx_hash=0x123 tx_id=2 block_height=2 state_root=s2 ts_unix_ms=2000 resolution_code=completed treasury_delta=0 challenger_delta=0 bond_disposition=forfeited metering_workload_class=llm_inference metering_schema=llm_token_meter_v1 metering_receipt_hash=deadbeef metering_policy_snapshot_version=0 metering_prompt_tokens=128 metering_generated_tokens=32 metering_decode_steps=32 metering_kv_bytes_moved=4096 metering_normalized_work_units=192 metering_prompt_token_weight=1 metering_generated_token_weight=1 metering_decode_step_weight=1 metering_kv_byte_weight=0 metering_min_accept_work_units=100 metering_challenge_success_bounty_base=1 metering_challenge_success_bounty_per_work_unit_num=1 metering_challenge_success_bounty_per_work_unit_den=192 metering_worker_completion_bonus_per_work_unit_num=1 metering_worker_completion_bonus_per_work_unit_den=256 metering_worker_slash_rebate_per_work_unit_num=1 metering_worker_slash_rebate_per_work_unit_den=384
";
    fs::write(run.join("node1.log"), line).expect("write log");

    let loaded = load_node_events_from_root(root.path(), NodeEventScanMode::Authoritative);
    assert_eq!(loaded.events.len(), 1);
    assert!(loaded.events[0].metering.is_none());
}

#[test]
fn load_node_events_drops_invalid_metering_policy_when_snapshot_version_exceeds_u8() {
    let root = tempfile::tempdir().expect("tempdir");
    let run = root.path().join("run");
    fs::create_dir_all(&run).expect("create run dir");
    let line = "2026-03-03T20:10:12Z INFO node [event] event_schema=v1 event_type=resolve task_id=7 from_status=Challenged to_status=Completed actor=authority signer=authority challenger=challenger-a tx_hash=0x123 tx_id=2 block_height=2 state_root=s2 ts_unix_ms=2000 resolution_code=completed treasury_delta=0 challenger_delta=0 bond_disposition=forfeited metering_workload_class=llm_inference metering_schema=llm_token_meter_v1 metering_receipt_hash=deadbeef metering_policy_snapshot_version=256 metering_prompt_tokens=128 metering_generated_tokens=32 metering_decode_steps=32 metering_kv_bytes_moved=4096 metering_normalized_work_units=192 metering_prompt_token_weight=1 metering_generated_token_weight=1 metering_decode_step_weight=1 metering_kv_byte_weight=0 metering_min_accept_work_units=100 metering_challenge_success_bounty_base=1 metering_challenge_success_bounty_per_work_unit_num=1 metering_challenge_success_bounty_per_work_unit_den=192 metering_worker_completion_bonus_per_work_unit_num=1 metering_worker_completion_bonus_per_work_unit_den=256 metering_worker_slash_rebate_per_work_unit_num=1 metering_worker_slash_rebate_per_work_unit_den=384
";
    fs::write(run.join("node1.log"), line).expect("write log");

    let loaded = load_node_events_from_root(root.path(), NodeEventScanMode::Authoritative);
    assert_eq!(loaded.events.len(), 1);
    assert!(loaded.events[0].metering.is_none());
}

#[test]
fn load_node_events_treats_trimmed_dash_metering_fields_as_missing() {
    let root = tempfile::tempdir().expect("tempdir");
    let run = root.path().join("run");
    fs::create_dir_all(&run).expect("create run dir");
    let line = "2026-03-03T20:10:12Z INFO node [event] event_schema=v1 event_type=resolve task_id=7 from_status=Challenged to_status='  -  ' actor=authority signer=authority challenger='  -  ' tx_hash='  -  ' tx_id=2 block_height=2 state_root=s2 ts_unix_ms=2000 resolution_code=completed treasury_delta=0 challenger_delta=0 bond_disposition=forfeited metering_workload_class='  -  ' metering_schema='  -  ' metering_receipt_hash='  -  ' metering_policy_snapshot_version=1 metering_prompt_tokens=128 metering_generated_tokens=32 metering_decode_steps=32 metering_kv_bytes_moved=4096 metering_normalized_work_units=192 metering_prompt_token_weight=1 metering_generated_token_weight=1 metering_decode_step_weight=1 metering_kv_byte_weight=0 metering_min_accept_work_units=100 metering_challenge_success_bounty_base=1 metering_challenge_success_bounty_per_work_unit_num=1 metering_challenge_success_bounty_per_work_unit_den=192 metering_worker_completion_bonus_per_work_unit_num=1 metering_worker_completion_bonus_per_work_unit_den=256 metering_worker_slash_rebate_per_work_unit_num=1 metering_worker_slash_rebate_per_work_unit_den=384
";
    fs::write(run.join("node1.log"), line).expect("write log");

    let loaded = load_node_events_from_root(root.path(), NodeEventScanMode::Authoritative);
    assert_eq!(loaded.events.len(), 1);
    let event = &loaded.events[0];
    assert_eq!(event.to_status.as_deref(), None);
    assert_eq!(event.challenger.as_deref(), None);
    assert_eq!(event.tx_hash.as_deref(), None);
    assert!(event.metering.is_none());
}

#[test]
fn load_node_events_treats_common_placeholder_text_as_missing() {
    let root = tempfile::tempdir().expect("tempdir");
    let run = root.path().join("run");
    fs::create_dir_all(&run).expect("create run dir");
    let line = "2026-03-03T20:10:12Z INFO node [event] event_schema=v1 event_type=resolve task_id=7 from_status=Challenged to_status=' N/A ' actor=authority signer=authority challenger=' none ' tx_hash=' NULL ' tx_id=2 block_height=2 state_root=s2 ts_unix_ms=2000 resolution_code=completed treasury_delta=0 challenger_delta=0 bond_disposition=forfeited metering_workload_class=' none ' metering_schema=' N/A ' metering_receipt_hash=' null ' metering_policy_snapshot_version=1 metering_prompt_tokens=128 metering_generated_tokens=32 metering_decode_steps=32 metering_kv_bytes_moved=4096 metering_normalized_work_units=192 metering_prompt_token_weight=1 metering_generated_token_weight=1 metering_decode_step_weight=1 metering_kv_byte_weight=0 metering_min_accept_work_units=100 metering_challenge_success_bounty_base=1 metering_challenge_success_bounty_per_work_unit_num=1 metering_challenge_success_bounty_per_work_unit_den=192 metering_worker_completion_bonus_per_work_unit_num=1 metering_worker_completion_bonus_per_work_unit_den=256 metering_worker_slash_rebate_per_work_unit_num=1 metering_worker_slash_rebate_per_work_unit_den=384
";
    fs::write(run.join("node1.log"), line).expect("write log");

    let loaded = load_node_events_from_root(root.path(), NodeEventScanMode::Authoritative);
    assert_eq!(loaded.events.len(), 1);
    let event = &loaded.events[0];
    assert_eq!(event.to_status.as_deref(), None);
    assert_eq!(event.challenger.as_deref(), None);
    assert_eq!(event.tx_hash.as_deref(), None);
    assert!(event.metering.is_none());
}

#[test]
fn load_node_events_drops_metering_when_to_status_is_missing_but_audit_fields_exist() {
    let root = tempfile::tempdir().expect("tempdir");
    let run = root.path().join("run");
    fs::create_dir_all(&run).expect("create run dir");
    let line = "2026-03-03T20:10:12Z INFO node [event] event_schema=v1 event_type=resolve task_id=7 from_status=Challenged to_status='  -  ' actor=authority signer=authority challenger=challenger-a tx_hash=0x123 tx_id=2 block_height=2 state_root=s2 ts_unix_ms=2000 resolution_code=completed treasury_delta=0 challenger_delta=0 bond_disposition=forfeited metering_workload_class=llm_inference metering_schema=llm_token_meter_v1 metering_receipt_hash=deadbeef metering_policy_snapshot_version=1 metering_prompt_tokens=128 metering_generated_tokens=32 metering_decode_steps=32 metering_kv_bytes_moved=4096 metering_normalized_work_units=192 metering_prompt_token_weight=1 metering_generated_token_weight=1 metering_decode_step_weight=1 metering_kv_byte_weight=0 metering_min_accept_work_units=100 metering_challenge_success_bounty_base=1 metering_challenge_success_bounty_per_work_unit_num=1 metering_challenge_success_bounty_per_work_unit_den=192 metering_worker_completion_bonus_per_work_unit_num=1 metering_worker_completion_bonus_per_work_unit_den=256 metering_worker_slash_rebate_per_work_unit_num=1 metering_worker_slash_rebate_per_work_unit_den=384
";
    fs::write(run.join("node1.log"), line).expect("write log");

    let loaded = load_node_events_from_root(root.path(), NodeEventScanMode::Authoritative);
    assert_eq!(loaded.events.len(), 1);
    let event = &loaded.events[0];
    assert_eq!(event.to_status.as_deref(), None);
    assert!(
        event.metering.is_none(),
        "missing to_status must fail closed instead of synthesizing a placeholder metering path"
    );
}

#[test]
fn load_node_events_recent_tail_marks_truncation_but_authoritative_keeps_history() {
    let root = tempfile::tempdir().expect("tempdir");
    let run = root.path().join("run");
    fs::create_dir_all(&run).expect("create run dir");

    let old_event = "2026-03-03T20:10:11Z INFO node [event] event_type=challenge task_id=7 from_status=Revealed to_status=Challenged actor=challenger-a tx_id=1 block_height=1 state_root=s1 ts_unix_ms=1000 challenger=challenger-a challenger_delta=-5 bond_disposition=posted\n";
    let filler = "x".repeat(600);
    let new_event = "2026-03-03T20:10:12Z INFO node [event] event_type=resolve task_id=7 from_status=Challenged to_status=Completed actor=authority tx_id=2 block_height=2 state_root=s2 ts_unix_ms=2000 signer=authority resolution_code=completed challenger=challenger-a challenger_delta=0 bond_disposition=forfeited\n";
    fs::write(
        run.join("node1.log"),
        format!("{old_event}{filler}\n{new_event}"),
    )
    .expect("write log");

    std::env::set_var("TRNM_RPC_NODE_EVENT_LOG_TAIL_BYTES", "400");
    let recent = load_node_events_from_root(root.path(), NodeEventScanMode::RecentTail);
    std::env::remove_var("TRNM_RPC_NODE_EVENT_LOG_TAIL_BYTES");

    assert!(recent.truncated);
    assert_eq!(recent.mode, NodeEventScanMode::RecentTail);
    assert_eq!(recent.events.len(), 1);
    assert_eq!(recent.events[0].event_type, "resolve");

    let authoritative = load_node_events_from_root(root.path(), NodeEventScanMode::Authoritative);
    assert!(!authoritative.truncated);
    assert_eq!(authoritative.mode, NodeEventScanMode::Authoritative);
    assert_eq!(authoritative.events.len(), 2);
    assert_eq!(authoritative.events[0].event_type, "challenge");
    assert_eq!(authoritative.events[1].event_type, "resolve");
}

#[test]
fn parse_event_log_kv_supports_prefixed_runtime_noise() {
    let line = "2026-03-03T20:10:11Z INFO node [event] event_type=commit task_id=7 from_status=Accepted to_status=Committed actor=did:trnm:worker tx_id=9 block_height=12 state_root=abc ts_unix_ms=1000";
    let event_line = &line[line.find("[event]").expect("event marker")..];
    let kv = parse_event_log_kv(event_line);
    assert_eq!(kv.get("event_type").map(String::as_str), Some("commit"));
    assert_eq!(kv.get("task_id").map(String::as_str), Some("7"));
}
