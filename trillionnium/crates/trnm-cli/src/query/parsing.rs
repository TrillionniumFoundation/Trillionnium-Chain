use super::*;

pub(crate) fn parse_task_query_response(
    raw: &str,
    requested_task_id: u64,
) -> Result<serde_json::Value> {
    let parsed: serde_json::Value = serde_json::from_str(raw)
        .map_err(|err| anyhow!("failed to parse task query response as json: {err}"))?;
    let Some(task_id) = parsed.get("task_id").and_then(|v| v.as_u64()) else {
        bail!("task query response missing numeric task_id");
    };
    if task_id != requested_task_id {
        bail!(
            "task query response task_id mismatch: requested={}, got={}",
            requested_task_id,
            task_id
        );
    }
    Ok(parsed)
}

pub(crate) fn parse_events_query_response(
    raw: &str,
    requested_task_id: u64,
) -> Result<serde_json::Value> {
    let parsed: serde_json::Value = serde_json::from_str(raw)
        .map_err(|err| anyhow!("failed to parse events query response as json: {err}"))?;
    let Some(events) = parsed.as_array() else {
        bail!("events query response must be a json array");
    };
    for (idx, event) in events.iter().enumerate() {
        let Some(task_id) = event.get("task_id").and_then(|v| v.as_u64()) else {
            bail!("events query response item {} missing numeric task_id", idx);
        };
        if task_id != requested_task_id {
            bail!(
                "events query response task_id mismatch at item {}: requested={}, got={}",
                idx,
                requested_task_id,
                task_id
            );
        }
    }
    Ok(parsed)
}

pub(crate) fn parse_request_full_query_response(
    raw: &str,
    requested_request_id: &str,
) -> Result<serde_json::Value> {
    let parsed: serde_json::Value = serde_json::from_str(raw)
        .map_err(|err| anyhow!("failed to parse request-full response as json: {err}"))?;
    let Some(request) = parsed.get("request") else {
        bail!("request-full response missing request object");
    };
    let Some(request_id) = request.get("request_id").and_then(|v| v.as_str()) else {
        bail!("request-full response missing string request.request_id");
    };
    if request_id != requested_request_id {
        bail!(
            "request-full response request_id mismatch: requested={}, got={}",
            requested_request_id,
            request_id
        );
    }
    let Some(task_id) = request.get("task_id").and_then(|v| v.as_u64()) else {
        bail!("request-full response missing numeric request.task_id");
    };
    let Some(events) = parsed.get("events").and_then(|v| v.as_array()) else {
        bail!("request-full response missing events array");
    };
    for (idx, event) in events.iter().enumerate() {
        let Some(event_task_id) = event.get("task_id").and_then(|v| v.as_u64()) else {
            bail!(
                "request-full response event {} missing numeric task_id",
                idx
            );
        };
        if event_task_id != task_id {
            bail!(
                "request-full response event task_id mismatch at item {}: request.task_id={}, got={}",
                idx,
                task_id,
                event_task_id
            );
        }
    }
    Ok(parsed)
}
