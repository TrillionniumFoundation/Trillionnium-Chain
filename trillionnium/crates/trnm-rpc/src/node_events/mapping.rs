use crate::metering::{
    normalize_opt_kv, parse_event_log_kv, parse_event_metering_query_response, parse_i128_kv_value,
    parse_u128_kv_value, parse_u64_kv_value,
};
use crate::NodeEventRecord;

pub(super) fn parse_node_event_line(line: &str) -> Option<NodeEventRecord> {
    let event_pos = line.find("[event]")?;
    let event_line = &line[event_pos..];
    if !event_line.contains("event_type=") {
        return None;
    }
    let kv = parse_event_log_kv(event_line);

    let task_id = kv.get("task_id").and_then(|s| parse_u64_kv_value(s))?;
    let tx_id = kv.get("tx_id").and_then(|s| parse_u64_kv_value(s))?;
    let block_height = kv.get("block_height").and_then(|s| parse_u64_kv_value(s))?;
    let ts_unix_ms = kv
        .get("ts_unix_ms")
        .and_then(|s| parse_u128_kv_value(s))
        .unwrap_or(0);

    let normalize_opt = |k: &str| normalize_opt_kv(&kv, k);

    Some(NodeEventRecord {
        event_type: kv
            .get("event_type")
            .cloned()
            .unwrap_or_else(|| "unknown".into()),
        task_id,
        from_status: kv
            .get("from_status")
            .cloned()
            .unwrap_or_else(|| "NONE".into()),
        to_status: kv.get("to_status").cloned().unwrap_or_else(|| "NONE".into()),
        actor: kv.get("actor").cloned().unwrap_or_else(|| "unknown".into()),
        tx_id,
        block_height,
        state_root: kv
            .get("state_root")
            .cloned()
            .unwrap_or_else(|| "unknown".into()),
        ts_unix_ms,
        signer: normalize_opt("signer"),
        challenger: normalize_opt("challenger"),
        tx_hash: normalize_opt("tx_hash"),
        resolution_code: normalize_opt("resolution_code"),
        treasury_delta: kv
            .get("treasury_delta")
            .and_then(|v| parse_i128_kv_value(v)),
        challenger_delta: kv
            .get("challenger_delta")
            .and_then(|v| parse_i128_kv_value(v)),
        bond_disposition: normalize_opt("bond_disposition"),
        metering: parse_event_metering_query_response(&kv),
    })
}

pub(super) fn parse_node_event_lines<I>(lines: I) -> Vec<NodeEventRecord>
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    lines
        .into_iter()
        .filter_map(|line| parse_node_event_line(line.as_ref()))
        .collect()
}
