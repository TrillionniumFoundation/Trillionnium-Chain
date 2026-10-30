//! Explicit PGH2/PNP2 development slice on the original protected-v3 transport.
//! No pool, history walker, automatic parent recovery or new supervisor.
use super::*;
use crate::store::growth::GrowthWorkCheckedPacket;
use crate::{GrowthPacket, GrowthProgress};

pub const GROWTH_PROFILE: &str = "public-protected-growth-development-v1";

#[derive(Clone, Copy)]
pub(super) enum ClientProfile {
    Legacy,
    ArithmeticFacts,
    PurePoNV2,
    NativeGrowthV1,
}
impl ClientProfile {
    pub(super) fn id(self, policy: PublicPolicy) -> Hash {
        match self {
            Self::Legacy => policy.id(),
            Self::ArithmeticFacts => policy.arithmetic_facts_id(),
            Self::PurePoNV2 => policy.pure_admission_v2_id(),
            Self::NativeGrowthV1 => policy.growth_id(),
        }
    }
    pub(super) fn operation_allowed(self, op: u8) -> bool {
        match self {
            Self::Legacy | Self::ArithmeticFacts => (1..=5).contains(&op),
            Self::PurePoNV2 => (1..=5).contains(&op) || op == 9,
            Self::NativeGrowthV1 => (6..=8).contains(&op),
        }
    }
}

impl PublicPolicy {
    /// Fresh explicit resource identity. The original v3 transport, ticket,
    /// CPU, queue, response and kernel limits remain bound through policy.id().
    pub fn growth_id(self) -> Hash {
        hash(b"public-protected-growth-profile-v1", &[
            GROWTH_PROFILE.as_bytes(), &self.id(),
            b"PGH2-PNP2-permanent-account-growth-native-v2/original-node-network-parameters-genesis-namespace/ops6-growth_submit_v1-7-growth_packet_status_v1-8-growth_head_v1/other-ops-refused-before-cookie/no-pool-history-auto-parent-recovery-miner-or-poller/packet1048576-hex-body2097216/submit-and-exact-observation-original-paid-proof-queue-and-CPU-domain/head-original-read-queue-fixed-metadata-snapshot-no-State/response16384/exact-single-read-snapshot-full-retained-W1-M06-account-proof-deltas-active-membership-sql8193-no-authority/submit-current-context-owner-release-full-W1-original-owner-reacquire-current-clock-context-parent-and-epoch/no-State-cache/complete-work-key-domain-public-growth-complete-work-identity-v1-shares-original-fixed4096-set/admission-precommit-cancel/original-postcommit-activation-noncancellable-paid-outer-tail-reorg-depth-not-latency-qualified/no-new-credit-or-process-owner/ordinary-original-durable-service-epoch-fence/development-only-production-activation-false",
        ])
    }
}
impl PublicServer {
    /// Trusted setup changes only the explicit profile. It preserves the same
    /// actual CPU/intake domain and starts no listener or owner.
    pub fn with_native_growth(mut self) -> Result<Self> {
        ensure(
            !self.policy.is_pure_history_raw(),
            "PUBLIC_PURE_HISTORY_RAW_PROFILE",
        )?;
        ensure(
            !self.native_growth
                && self.arithmetic_facts.is_none()
                && self.pure_admission_v2.is_none(),
            "PUBLIC_GROWTH_PROFILE",
        )?;
        self.native_growth = true;
        Ok(self)
    }
    pub(super) fn operation_allowed(&self, op: u8) -> bool {
        if op == 9 {
            return self.policy.is_pure_pon()
                && !self.native_growth
                && self.arithmetic_facts.is_none();
        }
        if self.native_growth {
            ClientProfile::NativeGrowthV1.operation_allowed(op)
        } else {
            ClientProfile::Legacy.operation_allowed(op)
        }
    }
}

/// No fallback to PNP1 or another resource profile. The caller pins the server
/// key and complete original growth Settings context, plus its own deadline.
pub fn call_public_protected_growth_v1(
    address: SocketAddr,
    request: &Request,
    settings: &Settings,
    pinned_server: &str,
    caller: &DevelopmentIdentity,
    policy: PublicPolicy,
    outer_deadline: Option<Instant>,
) -> (Result<PublicReply>, PublicClientMetrics) {
    call_public_protected_v3_with_profile(
        address,
        request,
        settings,
        pinned_server,
        caller,
        (policy, ClientProfile::NativeGrowthV1),
        outer_deadline,
    )
}

fn packet(text: &str) -> Result<GrowthPacket> {
    ensure(
        text.len() <= 2 * MAX_PACKET && text.len().is_multiple_of(2) && lower_hex(text.as_bytes()),
        "PUBLIC_PACKET_TEXT",
    )?;
    GrowthPacket::decode(&hex::decode(text).map_err(|_| "PUBLIC_PACKET_TEXT")?)
}

fn submit_result(owner: &mut Node, id: Hash) -> Result<Value> {
    // Admission has already committed. Match the existing public Native submit
    // boundary: finish activation and charge the entire outer interval; do not
    // rewrite this durable result as an earlier request cancellation.
    let active = owner.activate(id)?;
    let generation = owner.active()?.1;
    Ok(json!({
        "schema":"pon-native-growth-submit-v1",
        "packet_profile":"PNP2", "state_profile":"permanent-account-growth-native-v2",
        "network":hex::encode(owner.settings().network()),
        "parameters":hex::encode(owner.settings().parameters()),
        "genesis":hex::encode(owner.settings().genesis()),
        "block":hex::encode(id), "admitted":true,
        "active":hex::encode(active), "generation":generation,
        "physical_execution":false, "production_activation":false
    }))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn dispatch(
    node: &Mutex<Node>,
    request: Request,
    deadline: Instant,
    stop: &AtomicBool,
    cancelled: &AtomicBool,
    metrics: &Mutex<PublicMetrics>,
    observation: Option<&TaskObservation>,
    measurement: Option<&MutationCpuMeasurement>,
) -> Result<Value> {
    let live_cpu = measurement.map(|cpu| &cpu.workers);
    let checkpoint = |_: GrowthProgress| {
        task_alive(deadline, stop, cancelled)?;
        live_cpu.map_or(Ok(()), ScopedWorkerCpu::checkpoint)
    };
    let mut wait = |_: u64| checkpoint(GrowthProgress::BeforeContext);
    match request {
        Request::GrowthSubmitV1 { packet: text } => {
            let charge = measurement.ok_or("PUBLIC_GROWTH_ORIGINAL_CPU_REQUIRED")?;
            let packet = packet(&text)?;
            {
                let mut owner = lock_owner(node, &mut wait)?;
                if let Some(id) = owner.precheck_growth_admission_with_progress(
                    &packet,
                    super::super::now()?,
                    &checkpoint,
                )? {
                    // This existing exact packet gets no new W1 priority.
                    return submit_result(&mut owner, id);
                }
            }
            checkpoint(GrowthProgress::BeforeWork)?;
            let stamp = ThreadCpuStamp::start();
            if stamp.is_none() {
                charge.unavailable.set(true);
                charge.workers.unknown();
                return Err("PUBLIC_MUTATION_CPU_UNAVAILABLE".into());
            }
            let start = Instant::now();
            metrics.lock().map_err(|_| "PUBLIC_METRICS")?.work_started += 1;
            if let Some(record) = observation {
                record.work_started();
            }
            let result = GrowthWorkCheckedPacket::verify_with_progress(packet, &checkpoint);
            let cpu = stamp.and_then(ThreadCpuStamp::finish);
            charge.full_work_ns.set(cpu);
            charge
                .unavailable
                .set(charge.unavailable.get() || cpu.is_none());
            if cpu.is_none() {
                charge.workers.unknown();
            }
            if let Some(record) = observation {
                record.work_finished(cpu, result.is_ok());
            }
            {
                let mut m = metrics.lock().map_err(|_| "PUBLIC_METRICS")?;
                m.work_ns = m.work_ns.saturating_add(elapsed_ns(start));
                m.work_finished += 1;
                m.work_failed += u64::from(result.is_err());
            }
            let checked = result?;
            checkpoint(GrowthProgress::BeforeContext)?;
            charge
                .workers
                .live
                .as_ref()
                .ok_or("PUBLIC_GROWTH_ORIGINAL_CPU_REQUIRED")?
                .growth_work_verified(&checked)?;
            let mut owner = lock_owner(node, &mut wait)?;
            // Reacquired ORIGINAL owner. No cached State, clock or parent is
            // supplied; the typed entry rebinds all current inputs before commit.
            let id = owner.admit_growth_work_checked_with_progress(
                checked,
                super::super::now()?,
                &checkpoint,
            )?;
            submit_result(&mut owner, id)
        }
        Request::GrowthPacketStatusV1 { packet: text } => {
            // Semantically read-only, but full retained W1/M06 is charged to the
            // SAME original proof lane and CPU domain as a submit.
            ensure(measurement.is_some(), "PUBLIC_GROWTH_ORIGINAL_CPU_REQUIRED")?;
            let packet = packet(&text)?;
            let owner = lock_owner(node, &mut wait)?;
            owner.growth_exact_packet_observation_with_progress(&packet, &checkpoint)
        }
        Request::GrowthHeadV1 => {
            let owner = lock_owner(node, &mut wait)?;
            owner.growth_head_observation_with_progress(&checkpoint)
        }
        _ => Err("PUBLIC_OPERATION_PROFILE".into()),
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
