use crate::capability::{load_identity_registry, query_capability_audit};
use crate::envpaths::identity_registry_file;
use crate::node_events::load_node_events;
use crate::rpc_util::rpc_fail;
use crate::snapshot::{governance_state, load_latest_adapter_records};
use crate::taskview::{query_events_response, query_task_response};
use crate::NodeEventScanMode;
use anyhow::{bail, Result};
use trnm_rpc::{GovParamQueryResponse, GovProposalQueryResponse};

pub(crate) fn handle_query_task(task_id: u64) -> Result<()> {
    let recs = load_latest_adapter_records();
    let node_events = load_node_events(NodeEventScanMode::Authoritative);
    let out = query_task_response(task_id, &node_events.events, &recs)?;
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

pub(crate) fn handle_query_proposal(proposal_id: u64) -> Result<()> {
    let st = governance_state();
    let Some(p) = st.get_proposal(proposal_id) else {
        bail!("proposal not found: {}", proposal_id);
    };
    let out = GovProposalQueryResponse {
        proposal_id: p.proposal_id,
        title: p.title,
        proposer: p.proposer,
        status: p.status,
        version: p.version,
    };
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

pub(crate) fn handle_query_param(key: &str) -> Result<()> {
    let st = governance_state();
    let Some(p) = st.gov_param_snapshot(key) else {
        bail!("param not found: {}", key);
    };
    let pending_update = st.pending_gov_update(key).map(|pending| trnm_rpc::PendingGovParamUpdateQueryResponse {
        key_id: pending.key_id,
        key: pending.key,
        value: pending.value,
        activate_at_height: pending.activate_at_height,
    });
    let out = GovParamQueryResponse {
        key_id: p.key_id,
        key: p.key,
        value: p.value,
        version: p.version,
        pending_update,
    };
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

pub(crate) fn handle_query_events(task_id: u64, limit: usize) -> Result<()> {
    let recs = load_latest_adapter_records();
    let node_events = load_node_events(NodeEventScanMode::Authoritative);
    let events = query_events_response(task_id, limit, &node_events.events, &recs)?;
    println!("{}", serde_json::to_string_pretty(&events)?);
    Ok(())
}

pub(crate) fn handle_query_capability_audit(token_id: u64) -> Result<()> {
    let registry = load_identity_registry(&identity_registry_file());
    let out = query_capability_audit(&registry, token_id)
        .map_err(|e| rpc_fail(e.to_rpc_error()))?;
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}
