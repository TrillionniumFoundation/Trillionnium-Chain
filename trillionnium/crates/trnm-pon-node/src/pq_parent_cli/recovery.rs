use super::*;
use std::path::Path;
use trnm_pon_node::{
    ingress::pq_network::tls::PqTlsClient,
    public_submit::pq::{
        submit_with_pq_parent_recovery, PinnedPqRecoveryClient, PqRecoveryCampaign,
        PqRecoveryTransport,
    },
    Packet,
};

fn alive(plan: Option<&SubmitRecoveryPlan>) -> Result<()> {
    if let Some(plan) = plan {
        ensure(Instant::now() < plan.deadline, "SUBMIT_RECOVERY_DEADLINE")?;
    }
    Ok(())
}
fn configure(
    args: &BTreeMap<String, String>,
    mut plan: SubmitRecoveryPlan,
) -> Result<SubmitRecoveryPlan> {
    let budget = number(args, "--submit-deadline-ms", 60_000)?;
    ensure((1..=60_000).contains(&budget), "SUBMIT_RECOVERY_LIMITS")?;
    plan.deadline = plan.deadline.min(
        plan.started
            .checked_add(Duration::from_millis(budget))
            .ok_or("SUBMIT_RECOVERY_LIMITS")?,
    );
    plan.max_submit_attempts = number(args, "--submit-attempts", 3)?
        .try_into()
        .map_err(|_| "SUBMIT_RECOVERY_LIMITS")?;
    plan.max_calls = number(args, "--submit-call-cap", 16)?
        .try_into()
        .map_err(|_| "SUBMIT_RECOVERY_LIMITS")?;
    plan.max_parent_packets = number(args, "--submit-parent-depth", 1)?
        .try_into()
        .map_err(|_| "SUBMIT_RECOVERY_LIMITS")?;
    plan.validate()?;
    Ok(plan)
}

pub(super) fn run(
    args: &BTreeMap<String, String>,
    native_address: SocketAddr,
    history_address: SocketAddr,
    workers: usize,
    plan: Option<SubmitRecoveryPlan>,
) -> Result<Value> {
    let plan = plan.map(|plan| configure(args, plan)).transpose()?;
    let initial_sequence: u64 = need(args, "--initial-sequence")?
        .parse()
        .map_err(|_| "PQ_NETWORK_SEQUENCE")?;
    ensure(
        (1..=i64::MAX as u64).contains(&initial_sequence),
        "PQ_NETWORK_SEQUENCE",
    )?;
    let directory = Path::new(need(args, "--campaign")?);
    let store = Path::new(need(args, "--store")?);
    alive(plan.as_ref())?;
    let material = config::load(args)?;
    let native = PqTlsClient::new(
        material.policy.clone(),
        material.signer()?,
        material.tls_identity()?,
    )?;
    let history = material.history_identity()?;
    let history_policy = material.history;
    alive(plan.as_ref())?;
    // Recovery reads the actual producer's retained ancestry. An empty store
    // is never silently created to stand in for that independently supplied owner.
    ensure(
        store.join("native.sqlite").is_file(),
        "SUBMIT_RECOVERY_EXISTING_PRODUCER_REQUIRED",
    )?;
    let node = material.open_node(args, workers)?;
    alive(plan.as_ref())?;
    // Regular same-FD bounded input only. Resume deliberately creates no new
    // deadline: cold Journal::open validates the original BOOTTIME/boot/time-namespace
    // epoch before any RPC; time spent here cannot renew that retained epoch.
    let raw = input(need(args, "--packet")?, 1_048_576, false)?;
    let packet = Packet::decode_for_settings(&raw, node.settings())?;
    alive(plan.as_ref())?;
    let client = PinnedPqRecoveryClient::new(
        &node,
        PqRecoveryTransport::HybridTlsLoopback(&native),
        native_address,
        history_address,
        &history,
        history_policy,
    )?;
    let campaign = match plan {
        Some(plan) => PqRecoveryCampaign::Create {
            directory,
            initial_sequence,
            plan,
        },
        None => PqRecoveryCampaign::Resume {
            directory,
            initial_sequence,
        },
    };
    Ok(serde_json::to_value(submit_with_pq_parent_recovery(
        &node, &client, &packet, campaign,
    )?)?)
}
