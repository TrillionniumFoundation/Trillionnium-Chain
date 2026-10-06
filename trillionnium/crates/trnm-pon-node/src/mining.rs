//! Bounded wall-clock mining driven by the existing Node and local pool owner.
//! No independent scheduler, execution certificate or automatically signed task.
use crate::store::ParentTaskEligibility;
use crate::{ensure, ingress, Node, Packet, Result};
use serde::Serialize;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, TryLockError,
    },
    thread,
    time::{Duration, Instant},
};
use trnm_crypto_primitives::qualified_work_task::{
    derive_matrices, lifecycle_v2::verify_lifecycle_admission, verify_development_admission,
    TaskMaterial,
};
use trnm_mvcc_fee::continuity_v1;
use trnm_mvcc_fee::qualified_task_lifecycle;
use trnm_protocol::{
    pon_wire::{hash, Hash, Header},
    qualified_work_task::SignedQualifiedWorkTask,
};

/// Prepared under the owner lock; proof search holds neither SQLite nor Node.
/// Fields stay crate private so ordinary callers cannot manufacture an admission.
pub(crate) struct PreparedCandidate {
    pub(crate) header: Header,
    pub(crate) transactions: Vec<Vec<u8>>,
    pub(crate) prepared: trnm_crypto_primitives::pon_work::PreparedTask,
}
#[derive(Serialize)]
pub struct OwnedNonceTrial {
    pub ordinal: u64,
    pub nonce: u64,
    pub challenge: String,
    pub full_proof_sha256: Option<String>,
    pub complete_proof: bool,
    pub ticket_accepted: Option<bool>,
    pub fence_passed: bool,
    pub status: &'static str,
}
pub(crate) struct OwnedWindowTrace {
    pub(crate) packet: Option<Packet>,
    pub(crate) trials: Vec<OwnedNonceTrial>,
    pub(crate) stopped: bool,
    pub(crate) error: Option<String>,
}
enum SearchOutcome {
    Found(Box<Packet>),
    Exhausted(u64),
    Stopped(u64),
}
impl PreparedCandidate {
    pub(crate) fn search(self, attempts: u64) -> Result<Packet> {
        match self.search_cooperative(attempts, &AtomicBool::new(false), None)? {
            SearchOutcome::Found(packet) => Ok(*packet),
            SearchOutcome::Exhausted(_) => Err("WORK_BUDGET".into()),
            SearchOutcome::Stopped(_) => Err("MINING_STOPPED".into()),
        }
    }
    /// A finite, positive outside-signed nonce window. Each started proof is
    /// retained, including errors and the completed proof at a cancelling fence.
    /// The original PreparedTask::prove and ticket predicate are unchanged.
    pub(crate) fn search_owned_window(
        mut self,
        first: u64,
        count: u64,
        progress: &impl Fn() -> Result<()>,
    ) -> Result<OwnedWindowTrace> {
        ensure(
            first > 0 && (1..=4096).contains(&count) && first.checked_add(count - 1).is_some(),
            "OWNER_MINING_NONCE_WINDOW",
        )?;
        let mut trace = OwnedWindowTrace {
            packet: None,
            trials: Vec::new(),
            stopped: false,
            error: None,
        };
        for ordinal in 0..count {
            if progress().is_err() {
                trace.stopped = true;
                break;
            }
            self.header.nonce = first
                .checked_add(ordinal)
                .ok_or("OWNER_MINING_NONCE_WINDOW")?;
            let challenge = self.header.challenge();
            let mut row = OwnedNonceTrial {
                ordinal,
                nonce: self.header.nonce,
                challenge: hex::encode(challenge),
                full_proof_sha256: None,
                complete_proof: false,
                ticket_accepted: None,
                fence_passed: false,
                status: "proof-error",
            };
            let proof = match self.prepared.prove(challenge) {
                Ok(proof) => proof,
                Err(error) => {
                    trace.error = Some(format!("WORK:{error:?}"));
                    trace.trials.push(row);
                    break;
                }
            };
            row.complete_proof = true;
            row.full_proof_sha256 = Some(crate::operator_task_policy::digest_bytes(&proof));
            // This complete original predicate is evaluated for every complete
            // proof, even if the following epoch/CPU fence rejects its reuse.
            let ticket =
                hash(b"ticket", &[&challenge, &proof[proof.len() - 32..]]) <= self.header.target;
            row.ticket_accepted = Some(ticket);
            if progress().is_err() {
                row.status = "stop-after-complete-proof";
                trace.trials.push(row);
                trace.stopped = true;
                break;
            }
            row.fence_passed = true;
            row.status = if ticket { "winner" } else { "ticket-miss" };
            trace.trials.push(row);
            if ticket {
                trace.packet = Some(Packet {
                    header: self.header,
                    transactions: self.transactions,
                    proof,
                });
                break;
            }
        }
        Ok(trace)
    }
    fn search_cooperative(
        self,
        attempts: u64,
        stop: &AtomicBool,
        end: Option<Instant>,
    ) -> Result<SearchOutcome> {
        self.search_with_progress(attempts, |_| {
            if stop.load(Ordering::Acquire)
                || end.is_some_and(|deadline| Instant::now() >= deadline)
            {
                Err(())
            } else {
                Ok(())
            }
        })
    }

    // Use the producer's existing checkpoints, not a second work relation or
    // proof cache. The callback runs outside the Node/SQLite owner. Cancellation
    // yields no Packet; ordinary native admission and re-entry fences remain.
    fn search_with_progress(
        mut self,
        attempts: u64,
        mut progress: impl FnMut(
            trnm_crypto_primitives::pon_work::PreparedGenerationProgress,
        ) -> std::result::Result<(), ()>,
    ) -> Result<SearchOutcome> {
        use trnm_crypto_primitives::pon_work::PreparedGenerationError;
        ensure((1..=4096).contains(&attempts), "WORK_BUDGET")?;
        for nonce in 0..attempts {
            self.header.nonce = nonce;
            let challenge = self.header.challenge();
            let proof = match self.prepared.prove_with_progress(challenge, &mut progress) {
                Ok(proof) => proof,
                Err(PreparedGenerationError::Relation(error)) => {
                    return Err(format!("WORK:{error:?}").into());
                }
                Err(PreparedGenerationError::Cancelled(())) => {
                    // This field has always counted COMPLETE proof trials.
                    // Search elapsed time still includes the abandoned partial
                    // attempt. Do not invent a completed trial or refund work.
                    return Ok(SearchOutcome::Stopped(nonce));
                }
            };
            if hash(b"ticket", &[&challenge, &proof[proof.len() - 32..]]) <= self.header.target {
                return Ok(SearchOutcome::Found(Box::new(Packet {
                    header: self.header,
                    transactions: self.transactions,
                    proof,
                })));
            }
        }
        Ok(SearchOutcome::Exhausted(attempts))
    }
}

#[derive(Clone, Debug)]
pub enum MiningMaterial {
    /// Explicit historical development context only.
    LegacyDevelopment,
    /// The exact source statement must already exist in the parent branch.
    Registered { model: Vec<u8>, input: Vec<u8> },
}

#[derive(Clone, Debug)]
pub struct MiningConfig {
    pub miner: Hash,
    pub material: MiningMaterial,
    pub max_transactions: usize,
    pub max_transaction_bytes: usize,
    pub search_attempts: u64,
    pub pace: Duration,
    pub runtime: Duration,
    pub max_blocks: u64,
}
impl MiningConfig {
    pub fn validate(&self) -> Result<()> {
        ensure(
            self.miner != [0; 32]
                && (1..=256).contains(&self.max_transactions)
                && (159..=524288).contains(&self.max_transaction_bytes)
                && (1..=4096).contains(&self.search_attempts)
                && (Duration::from_secs(1)..=Duration::from_secs(60)).contains(&self.pace)
                && self.runtime > Duration::ZERO
                && self.runtime <= Duration::from_secs(259200)
                && (1..=100000).contains(&self.max_blocks),
            "MINING_LIMITS",
        )?;
        if let MiningMaterial::Registered { model, input } = &self.material {
            ensure(
                model.len() == 16384 && input.len() == 16384,
                "TASK_MATERIAL",
            )?;
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct MiningEvent {
    pub schema: &'static str,
    pub kind: &'static str,
    pub observed_wall_seconds: u64,
    pub parent: String,
    pub parent_generation: u64,
    pub block: Option<String>,
    pub admitted: bool,
    pub activated: bool,
    pub height: u64,
    pub transactions: usize,
    pub transaction_bytes: usize,
    pub work_trials: u64,
    /// Elapsed polling/lock acquisition, not CPU time or a service deadline.
    pub initial_owner_wait_ns: u128,
    pub pool_batch_ns: u128,
    pub pre_search_batch_validation_ns: u128,
    pub prepare_ns: u128,
    pub search_ns: u128,
    pub post_search_owner_wait_ns: u128,
    pub post_search_batch_validation_ns: u128,
    pub make_ns: u128,
    pub admit_ns: u128,
    pub activate_ns: u128,
    pub reconcile_ns: u128,
    pub failure: Option<String>,
    pub failure_stage: Option<&'static str>,
    pub public_network_ready: bool,
    pub production_activation: bool,
}

#[derive(Debug, Serialize)]
pub struct MiningReport {
    pub schema: &'static str,
    pub stop_reason: &'static str,
    pub attempted_searches: u64,
    pub exhausted_searches: u64,
    pub stale_searches: u64,
    pub activated_blocks: u64,
    pub included_transactions: u64,
    pub observed_work_trials: u64,
    /// Elapsed polling/lock acquisition, not CPU time or a service deadline.
    pub initial_owner_wait_ns: u128,
    pub pool_batch_ns: u128,
    pub pre_search_batch_validation_ns: u128,
    pub prepare_ns: u128,
    pub search_ns: u128,
    pub post_search_owner_wait_ns: u128,
    pub post_search_batch_validation_ns: u128,
    /// Existing event stage aggregates; make includes prepare plus search.
    pub make_ns: u128,
    pub admit_ns: u128,
    pub activate_ns: u128,
    pub reconcile_ns: u128,
    pub actual_elapsed_ns: u128,
    pub stage_preemption: bool,
    pub public_network_ready: bool,
    pub production_activation: bool,
}

impl Node {
    /// Load and verify the currently registered exact source bytes. A queued
    /// renewal cannot authorize its own containing block. New statement bytes
    /// become available through the actual parent state on the following block.
    #[allow(clippy::too_many_arguments)]
    pub fn make_with_registered_material(
        &self,
        parent: Hash,
        transactions: Vec<Vec<u8>>,
        miner: Hash,
        timestamp: u64,
        attempts: u64,
        model: &[u8],
        input: &[u8],
    ) -> Result<Packet> {
        self.prepare_registered_material(
            parent,
            transactions,
            miner,
            timestamp,
            attempts,
            model,
            input,
        )?
        .search(attempts)
    }
    #[allow(clippy::too_many_arguments)]
    fn prepare_registered_material(
        &self,
        parent: Hash,
        transactions: Vec<Vec<u8>>,
        miner: Hash,
        timestamp: u64,
        attempts: u64,
        model: &[u8],
        input: &[u8],
    ) -> Result<PreparedCandidate> {
        let (a, b) = derive_matrices(model, input).map_err(|e| format!("TASK_MATERIAL:{e:?}"))?;
        let task = trnm_crypto_primitives::pon_work::task_id(&a, &b)
            .map_err(|e| format!("TASK_MATRIX:{e:?}"))?;
        let height = self.parent_height(parent)?.checked_add(1).ok_or("HEIGHT")?;
        let state = self.state_at(parent)?;
        if continuity_v1::enabled(&self.settings().app)
            && task == continuity_v1::maintenance_task()?
        {
            continuity_v1::check_maintenance(&state, task, &self.settings().app)?;
            let expected = continuity_v1::maintenance_material();
            ensure(
                model == expected.0 && input == expected.1,
                "CONTINUITY_MATERIAL",
            )?;
            ensure((1..=4096).contains(&attempts), "WORK_BUDGET")?;
            return self.prepare_from_checked_parent(
                parent,
                transactions,
                miner,
                timestamp,
                &a,
                &b,
                &state,
                &ParentTaskEligibility::ConsensusMaintenance,
            );
        }
        let material = || TaskMaterial {
            model,
            input,
            a: &a,
            b: &b,
        };
        let mut eligibility = None;
        let admission = match self.settings().task_profile() {
            "signed-task-lifecycle-dev-v2"
            | "signed-task-lifecycle-dev-v3"
            | "signed-task-lifecycle-dev-v4"
            | continuity_v1::PROFILE
            | "signed-checkpoint-tile-maintenance-dev-v1" => {
                let eligible = qualified_task_lifecycle::eligible_task(
                    &state,
                    task,
                    height,
                    &self.settings().app,
                )?;
                let record = state
                    .get(&qualified_task_lifecycle::slot_key(eligible.lease().slot)?)
                    .ok_or("TASK_DEMAND")?;
                let encoded = record["statement"].as_str().ok_or("TASK_STATEMENT")?;
                ensure(encoded.len() == 1368, "TASK_STATEMENT")?;
                let wire = hex::decode(encoded).map_err(|_| "TASK_STATEMENT")?;
                ensure(hex::encode(&wire) == encoded, "TASK_STATEMENT")?;
                let admission =
                    verify_lifecycle_admission(&wire, material(), eligible.lease(), height)
                        .map_err(|e| format!("TASK_ADMISSION:{e:?}"))?;
                eligibility = Some(ParentTaskEligibility::Lifecycle(Box::new(eligible)));
                admission
            }
            "signed-task-dev-v1" => {
                let record = state
                    .get(&format!("work:{}", hex::encode(task)))
                    .ok_or("TASK")?;
                let encoded = record["manifest"].as_str().ok_or("TASK_MANIFEST")?;
                ensure(encoded.len() == 1304, "TASK_MANIFEST")?;
                let wire = hex::decode(encoded).map_err(|_| "TASK_MANIFEST")?;
                ensure(hex::encode(&wire) == encoded, "TASK_MANIFEST")?;
                let signed = SignedQualifiedWorkTask::decode(&wire).map_err(|_| "TASK_MANIFEST")?;
                let context = self
                    .settings()
                    .qualified_task_context(signed.manifest.demand_id, height)?;
                verify_development_admission(&wire, material(), &context)
                    .map_err(|e| format!("TASK_ADMISSION:{e:?}"))?
            }
            _ => return Err("SIGNED_TASK_PROFILE_REQUIRED".into()),
        };
        self.prepare_with_task_from_parent(
            parent,
            transactions,
            miner,
            timestamp,
            attempts,
            &admission,
            material(),
            &state,
            eligibility,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_registered_material_controlled(
        &self,
        parent: Hash,
        transactions: Vec<Vec<u8>>,
        miner: Hash,
        timestamp: u64,
        attempts: u64,
        model: &[u8],
        input: &[u8],
        control: &trnm_mvcc_fee::pon_executor::ExecutionControl<'_, crate::Error>,
    ) -> Result<PreparedCandidate> {
        let (a, b) = derive_matrices(model, input).map_err(|e| format!("TASK_MATERIAL:{e:?}"))?;
        let task = trnm_crypto_primitives::pon_work::task_id(&a, &b)
            .map_err(|e| format!("TASK_MATRIX:{e:?}"))?;
        let height = self.parent_height(parent)?.checked_add(1).ok_or("HEIGHT")?;
        let state = self.state_at(parent)?;
        if continuity_v1::enabled(&self.settings().app)
            && task == continuity_v1::maintenance_task()?
        {
            continuity_v1::check_maintenance(&state, task, &self.settings().app)?;
            let expected = continuity_v1::maintenance_material();
            ensure(
                model == expected.0 && input == expected.1,
                "CONTINUITY_MATERIAL",
            )?;
            ensure((1..=4096).contains(&attempts), "WORK_BUDGET")?;
            return self.prepare_from_checked_parent_controlled(
                parent,
                transactions,
                miner,
                timestamp,
                &a,
                &b,
                &state,
                &ParentTaskEligibility::ConsensusMaintenance,
                control,
            );
        }
        let material = || TaskMaterial {
            model,
            input,
            a: &a,
            b: &b,
        };
        let mut eligibility = None;
        let admission = match self.settings().task_profile() {
            "signed-task-lifecycle-dev-v2"
            | "signed-task-lifecycle-dev-v3"
            | "signed-task-lifecycle-dev-v4"
            | continuity_v1::PROFILE
            | "signed-checkpoint-tile-maintenance-dev-v1" => {
                let eligible = qualified_task_lifecycle::eligible_task(
                    &state,
                    task,
                    height,
                    &self.settings().app,
                )?;
                let record = state
                    .get(&qualified_task_lifecycle::slot_key(eligible.lease().slot)?)
                    .ok_or("TASK_DEMAND")?;
                let encoded = record["statement"].as_str().ok_or("TASK_STATEMENT")?;
                ensure(encoded.len() == 1368, "TASK_STATEMENT")?;
                let wire = hex::decode(encoded).map_err(|_| "TASK_STATEMENT")?;
                ensure(hex::encode(&wire) == encoded, "TASK_STATEMENT")?;
                let admission =
                    verify_lifecycle_admission(&wire, material(), eligible.lease(), height)
                        .map_err(|e| format!("TASK_ADMISSION:{e:?}"))?;
                eligibility = Some(ParentTaskEligibility::Lifecycle(Box::new(eligible)));
                admission
            }
            "signed-task-dev-v1" => {
                let record = state
                    .get(&format!("work:{}", hex::encode(task)))
                    .ok_or("TASK")?;
                let encoded = record["manifest"].as_str().ok_or("TASK_MANIFEST")?;
                ensure(encoded.len() == 1304, "TASK_MANIFEST")?;
                let wire = hex::decode(encoded).map_err(|_| "TASK_MANIFEST")?;
                ensure(hex::encode(&wire) == encoded, "TASK_MANIFEST")?;
                let signed = SignedQualifiedWorkTask::decode(&wire).map_err(|_| "TASK_MANIFEST")?;
                let context = self
                    .settings()
                    .qualified_task_context(signed.manifest.demand_id, height)?;
                verify_development_admission(&wire, material(), &context)
                    .map_err(|e| format!("TASK_ADMISSION:{e:?}"))?
            }
            _ => return Err("SIGNED_TASK_PROFILE_REQUIRED".into()),
        };
        self.prepare_with_task_from_parent_controlled(
            parent,
            transactions,
            miner,
            timestamp,
            attempts,
            &admission,
            material(),
            &state,
            eligibility,
            control,
        )
    }
}

fn pause_until(deadline: Instant, end: Instant, stop: &AtomicBool) {
    while !stop.load(Ordering::Acquire) && Instant::now() < deadline && Instant::now() < end {
        let remaining = deadline.min(end).saturating_duration_since(Instant::now());
        thread::sleep(remaining.min(Duration::from_millis(25)));
    }
}

/// Shares the existing exclusive Node owner with ingress. Stop/runtime are checked
/// before search and admission, and at bounded producer checkpoints. SQLite and
/// deep native stages still cannot be preempted. Each real activated packet remains in the native durable store.
pub fn run_pool_mining<F>(
    node: Arc<Mutex<Node>>,
    config: MiningConfig,
    stop: Arc<AtomicBool>,
    mut observe: F,
) -> Result<MiningReport>
where
    F: FnMut(&MiningEvent) -> Result<()>,
{
    config.validate()?;
    let started = Instant::now();
    let end = started + config.runtime;
    let mut next = started;
    let mut report = MiningReport {
        schema: "native-wall-pool-mining-report-v1",
        stop_reason: "runtime",
        attempted_searches: 0,
        exhausted_searches: 0,
        stale_searches: 0,
        activated_blocks: 0,
        included_transactions: 0,
        observed_work_trials: 0,
        initial_owner_wait_ns: 0,
        pool_batch_ns: 0,
        pre_search_batch_validation_ns: 0,
        prepare_ns: 0,
        search_ns: 0,
        post_search_owner_wait_ns: 0,
        post_search_batch_validation_ns: 0,
        make_ns: 0,
        admit_ns: 0,
        activate_ns: 0,
        reconcile_ns: 0,
        actual_elapsed_ns: 0,
        stage_preemption: false,
        public_network_ready: false,
        production_activation: false,
    };
    let mut initial_owner_wait_ns = 0;
    while Instant::now() < end
        && !stop.load(Ordering::Acquire)
        && report.activated_blocks < config.max_blocks
    {
        pause_until(next, end, &stop);
        if Instant::now() >= end || stop.load(Ordering::Acquire) {
            break;
        }
        let acquisition = Instant::now();
        let mut owner = match node.try_lock() {
            Ok(owner) => owner,
            Err(TryLockError::WouldBlock) => {
                thread::sleep(Duration::from_millis(25));
                let elapsed = acquisition.elapsed().as_nanos();
                initial_owner_wait_ns += elapsed;
                report.initial_owner_wait_ns += elapsed;
                continue;
            }
            Err(TryLockError::Poisoned(_)) => return Err("MINING_OWNER".into()),
        };
        let elapsed = acquisition.elapsed().as_nanos();
        initial_owner_wait_ns += elapsed;
        report.initial_owner_wait_ns += elapsed;
        let acquired_wait = std::mem::take(&mut initial_owner_wait_ns);
        let (parent, generation) = owner.active()?;
        // A retained future timestamp is never converted into a logical mining clock.
        let now = ingress::now()?;
        let parent_time = if owner.parent_height(parent)? == 0 {
            owner.settings().genesis_time()
        } else {
            owner.packet(parent)?.header.timestamp
        };
        if now <= parent_time {
            drop(owner);
            next = Instant::now() + Duration::from_millis(25);
            continue;
        }
        let mut event = MiningEvent {
            schema: "native-wall-pool-mining-event-v1",
            kind: "activated",
            observed_wall_seconds: now,
            parent: hex::encode(parent),
            parent_generation: generation,
            block: None,
            admitted: false,
            activated: false,
            height: owner
                .parent_height(parent)?
                .checked_add(1)
                .ok_or("HEIGHT")?,
            transactions: 0,
            transaction_bytes: 0,
            work_trials: 0,
            initial_owner_wait_ns: acquired_wait,
            pool_batch_ns: 0,
            pre_search_batch_validation_ns: 0,
            prepare_ns: 0,
            search_ns: 0,
            post_search_owner_wait_ns: 0,
            post_search_batch_validation_ns: 0,
            make_ns: 0,
            admit_ns: 0,
            activate_ns: 0,
            reconcile_ns: 0,
            failure: None,
            failure_stage: None,
            public_network_ready: false,
            production_activation: false,
        };
        if stop.load(Ordering::Acquire) || Instant::now() >= end {
            event.kind = "stopped-before-search";
            event.failure_stage = Some("parent-observation");
            drop(owner);
            observe(&event)?;
            break;
        }
        let stage = Instant::now();
        let batch_result = owner.pool_mining_batch(
            parent,
            generation,
            config.max_transactions,
            config.max_transaction_bytes,
        );
        event.pool_batch_ns = stage.elapsed().as_nanos();
        report.pool_batch_ns += event.pool_batch_ns;
        let batch = match batch_result {
            Ok(batch) => batch,
            Err(error) => {
                event.kind = "failed";
                event.failure_stage = Some("pool-batch");
                event.failure = Some(error.to_string());
                drop(owner);
                observe(&event)?;
                return Err(error);
            }
        };
        event.transactions = batch.transactions.len();
        event.transaction_bytes = batch.transactions.iter().map(Vec::len).sum();
        if stop.load(Ordering::Acquire) || Instant::now() >= end {
            event.kind = "stopped-before-search";
            event.failure_stage = Some("pool-batch");
            drop(owner);
            observe(&event)?;
            break;
        }
        let stage = Instant::now();
        // Selection already performed complete M05/M06 against the actual
        // parent and retained raws under this same uninterrupted owner guard.
        // This local batch has no mutable external alias. Only the producer's
        // separately supplied miner still needs its configuration binding.
        let validation = ensure(batch.preview_miner == config.miner, "POOL_MINER");
        event.pre_search_batch_validation_ns = stage.elapsed().as_nanos();
        report.pre_search_batch_validation_ns += event.pre_search_batch_validation_ns;
        if let Err(error) = validation {
            event.kind = "failed";
            event.failure_stage = Some("pre-search-batch-validation");
            event.failure = Some(error.to_string());
            drop(owner);
            observe(&event)?;
            return Err(error);
        }
        if stop.load(Ordering::Acquire) || Instant::now() >= end {
            event.kind = "stopped-before-search";
            event.failure_stage = Some("pre-search-batch-validation");
            drop(owner);
            observe(&event)?;
            break;
        }
        let make_stage = Instant::now();
        let stage = Instant::now();
        let prepared = (|| match &config.material {
            MiningMaterial::LegacyDevelopment => {
                ensure(
                    owner.settings().task_profile() == "legacy-task-v1",
                    "EXPLICIT_TASK_REQUIRED",
                )?;
                let (a, b) = crate::maintenance();
                owner.prepare_from_matrices(
                    parent,
                    batch.transactions.clone(),
                    config.miner,
                    now,
                    &a,
                    &b,
                )
            }
            MiningMaterial::Registered { model, input } => owner.prepare_registered_material(
                parent,
                batch.transactions.clone(),
                config.miner,
                now,
                config.search_attempts,
                model,
                input,
            ),
        })();
        event.prepare_ns = stage.elapsed().as_nanos();
        report.prepare_ns += event.prepare_ns;
        drop(owner);
        let candidate = match prepared {
            Ok(candidate) => candidate,
            Err(error) => {
                event.make_ns = make_stage.elapsed().as_nanos();
                event.kind = "failed";
                event.failure = Some(error.to_string());
                event.failure_stage = Some("prepare");
                observe(&event)?;
                return Err(error);
            }
        };
        if stop.load(Ordering::Acquire) || Instant::now() >= end {
            event.make_ns = make_stage.elapsed().as_nanos();
            report.make_ns += event.make_ns;
            event.kind = "stopped-before-search";
            event.failure_stage = Some("prepare");
            observe(&event)?;
            break;
        }
        report.attempted_searches += 1;
        let stage = Instant::now();
        let made = candidate.search_cooperative(config.search_attempts, &stop, Some(end));
        event.search_ns = stage.elapsed().as_nanos();
        report.search_ns += event.search_ns;
        event.make_ns = make_stage.elapsed().as_nanos();
        report.make_ns += event.make_ns;
        let packet = match made {
            Ok(SearchOutcome::Found(packet)) => *packet,
            Ok(SearchOutcome::Exhausted(trials)) => {
                event.kind = "search-exhausted";
                event.work_trials = trials;
                event.failure = Some("WORK_BUDGET".into());
                report.exhausted_searches += 1;
                report.observed_work_trials += trials;
                observe(&event)?;
                next = Instant::now() + config.pace;
                continue;
            }
            Ok(SearchOutcome::Stopped(trials)) => {
                event.kind = "search-stopped";
                event.work_trials = trials;
                report.observed_work_trials += trials;
                observe(&event)?;
                break;
            }
            Err(error) => {
                event.kind = "failed";
                event.failure = Some(error.to_string());
                event.failure_stage = Some("search");
                observe(&event)?;
                return Err(error);
            }
        };
        event.work_trials = packet.header.nonce.checked_add(1).ok_or("NONCE")?;
        report.observed_work_trials += event.work_trials;
        if stop.load(Ordering::Acquire) || Instant::now() >= end {
            event.kind = "stopped-before-admission";
            event.failure =
                Some("work completed outside the remaining cooperative run budget".into());
            observe(&event)?;
            break;
        }
        let acquisition = Instant::now();
        let owner = loop {
            if stop.load(Ordering::Acquire) || Instant::now() >= end {
                event.kind = "stopped-before-admission";
                break None;
            }
            match node.try_lock() {
                Ok(owner) => break Some(owner),
                Err(TryLockError::WouldBlock) => thread::sleep(Duration::from_millis(25)),
                Err(TryLockError::Poisoned(_)) => return Err("MINING_OWNER".into()),
            }
        };
        event.post_search_owner_wait_ns = acquisition.elapsed().as_nanos();
        report.post_search_owner_wait_ns += event.post_search_owner_wait_ns;
        let Some(mut owner) = owner else {
            observe(&event)?;
            break;
        };
        if !owner.pool_batch_is_current(&batch)? {
            event.kind = "stale-search";
            report.stale_searches += 1;
            drop(owner);
            observe(&event)?;
            next = Instant::now() + config.pace;
            continue;
        }
        if stop.load(Ordering::Acquire) || Instant::now() >= end {
            event.kind = "stopped-before-admission";
            event.failure_stage = Some("parent-fence");
            drop(owner);
            observe(&event)?;
            break;
        }
        // Rechecking the whole native prefix is nonpreemptive. Inspect the
        // cooperative fence again afterwards, before starting durable admission.
        let mut failure_stage = "batch-revalidation";
        let completion: Result<bool> = (|| {
            let stage = Instant::now();
            let validation = owner.pool_validate_batch(&batch);
            event.post_search_batch_validation_ns = stage.elapsed().as_nanos();
            report.post_search_batch_validation_ns += event.post_search_batch_validation_ns;
            validation?;
            if stop.load(Ordering::Acquire) || Instant::now() >= end {
                return Ok(false);
            }
            failure_stage = "admission";
            let stage = Instant::now();
            let admitted = owner.admit(&packet, ingress::now()?);
            event.admit_ns = stage.elapsed().as_nanos();
            report.admit_ns += event.admit_ns;
            let id = admitted?;
            event.block = Some(hex::encode(id));
            event.admitted = true;
            failure_stage = "activation";
            let stage = Instant::now();
            let activated = owner.activate_observed(id, ingress::now()?);
            event.activate_ns = stage.elapsed().as_nanos();
            report.activate_ns += event.activate_ns;
            activated?;
            // Preserve the durable fact even if the subsequent cache update or
            // observation sink fails. A cache failure never rolls back a block.
            event.activated = true;
            report.activated_blocks += 1;
            report.included_transactions += event.transactions as u64;
            failure_stage = "pool-reconciliation";
            let stage = Instant::now();
            let reconciled = owner.pool_reconcile();
            event.reconcile_ns = stage.elapsed().as_nanos();
            report.reconcile_ns += event.reconcile_ns;
            reconciled?;
            Ok(true)
        })();
        drop(owner);
        match completion {
            Ok(true) => {}
            Ok(false) => {
                event.kind = "stopped-before-admission";
                event.failure_stage = Some("batch-revalidation");
                observe(&event)?;
                break;
            }
            Err(error) => {
                event.kind = "failed";
                event.failure_stage = Some(failure_stage);
                event.failure = Some(error.to_string());
                observe(&event)?;
                return Err(error);
            }
        }
        observe(&event)?;
        // Start spacing includes each complete local stage, without catch-up bursts.
        next = Instant::now() + config.pace;
    }
    report.stop_reason = if stop.load(Ordering::Acquire) {
        "stop-request"
    } else if report.activated_blocks == config.max_blocks {
        "block-limit"
    } else {
        "runtime"
    };
    report.actual_elapsed_ns = started.elapsed().as_nanos();
    Ok(report)
}


#[cfg(test)]
mod cooperative_search_tests {
    use super::*;
    use trnm_crypto_primitives::pon_work::{self, PreparedGenerationProgress as Point};

    // Search mechanics only. This template does not claim ledger admission.
    fn candidate(target: Hash) -> PreparedCandidate {
        let a: Vec<u32> = (0..4096).map(|i| (i % 19) as u32).collect();
        let b: Vec<u32> = (0..4096).map(|i| (i % 23) as u32).collect();
        PreparedCandidate {
            header: Header {
                network: [1; 32],
                parameters: [2; 32],
                parent: [3; 32],
                height: 1,
                timestamp: 10,
                target,
                miner: [4; 32],
                transactions: [5; 32],
                state: [6; 32],
                receipts: [7; 32],
                work_task: pon_work::task_id(&a, &b).unwrap(),
                nonce: 0,
            },
            transactions: vec![vec![9, 8, 7]],
            prepared: pon_work::PreparedTask::new(&a, &b).unwrap(),
        }
    }

    #[test]
    fn cooperative_search_matches_complete_first_winner_and_full_verifier() {
        let mut target = [255; 32];
        target[0] = 127;
        let mut reference = candidate(target);
        let mut expected = None;
        for nonce in 0..4096 {
            reference.header.nonce = nonce;
            let c = reference.header.challenge();
            let proof = reference.prepared.prove(c).unwrap();
            if hash(b"ticket", &[&c, &proof[proof.len() - 32..]]) <= target {
                expected = Some((reference.header.clone(), proof));
                break;
            }
        }
        let (header, proof) = expected.expect("finite reference search found no winner");
        let mut completed = 0u64;
        let result = candidate(target)
            .search_with_progress(4096, |point| {
                if point == Point::BeforeProof {
                    completed += 1;
                }
                Ok(())
            })
            .unwrap();
        let SearchOutcome::Found(packet) = result else {
            panic!("cooperative search disagreed with the complete reference");
        };
        assert_eq!(packet.header, header);
        assert_eq!(packet.proof, proof);
        assert_eq!(packet.transactions, reference.transactions);
        assert_eq!(completed, header.nonce + 1);
        let work = pon_work::verify(
            header.challenge(), header.work_task, header.target, &packet.proof,
        ).unwrap();
        assert_eq!(work.task(), header.work_task);
    }

    #[test]
    fn cooperative_search_discards_partial_proof_at_each_stage() {
        for cut in [
            Point::BeforeReplay,
            Point::Noise { label: 0, counter: 0 },
            Point::Noise { label: 3, counter: 63 },
            Point::NoiseRow { operand: 0, row: 0 },
            Point::NoiseRow { operand: 1, row: 63 },
            Point::TranscriptTile { row: 0, column: 0, inner: 0 },
            Point::TranscriptTile { row: 7, column: 7, inner: 7 },
            Point::BeforeProof,
        ] {
            let mut reached = false;
            let result = candidate([255; 32]).search_with_progress(1, |point| {
                assert!(!reached, "callback continued after cancellation");
                if point == cut {
                    reached = true;
                    Err(())
                } else {
                    Ok(())
                }
            }).unwrap();
            assert!(reached, "checkpoint was not exercised: {cut:?}");
            assert!(matches!(result, SearchOutcome::Stopped(0)));
        }
    }

    #[test]
    fn cooperative_search_checks_atomic_stop_and_actual_expired_deadline() {
        let stopped = AtomicBool::new(true);
        assert!(matches!(
            candidate([255; 32]).search_cooperative(1, &stopped, None).unwrap(),
            SearchOutcome::Stopped(0)
        ));
        let running = AtomicBool::new(false);
        assert!(matches!(
            candidate([255; 32])
                .search_cooperative(1, &running, Some(Instant::now())).unwrap(),
            SearchOutcome::Stopped(0)
        ));
        // A cancelled search leaves no process-global cancellation state.
        assert!(matches!(
            candidate([255; 32]).search_cooperative(1, &running, None).unwrap(),
            SearchOutcome::Found(_)
        ));
    }

    #[test]
    fn cooperative_search_invalid_budget_never_enters_producer() {
        for attempts in [0, 4097, u64::MAX] {
            let mut called = false;
            let result = candidate([255; 32]).search_with_progress(attempts, |_| {
                called = true;
                Ok(())
            });
            assert!(!called);
            assert_eq!(result.err().unwrap().to_string(), "WORK_BUDGET");
        }
    }

    #[test]
    fn cooperative_search_keeps_complete_misses_when_next_attempt_is_cancelled() {
        // Select a deterministic template whose first legal complete proof is a
        // miss. Header changes are followed by full work; no stale proof is used.
        let mut target = [255; 32];
        target[0] = 7;
        let mut selected = None;
        for timestamp in 10..74 {
            let mut trial = candidate(target);
            trial.header.timestamp = timestamp;
            let challenge = trial.header.challenge();
            let proof = trial.prepared.prove(challenge).unwrap();
            if hash(b"ticket", &[&challenge, &proof[proof.len() - 32..]]) > target {
                selected = Some(trial);
                break;
            }
        }
        let trial = selected.expect("finite template control found no first miss");
        let mut starts = 0;
        let result = trial.search_with_progress(2, |point| {
            if point == Point::BeforeReplay {
                starts += 1;
                if starts == 2 {
                    return Err(());
                }
            }
            Ok(())
        }).unwrap();
        assert_eq!(starts, 2);
        assert!(matches!(result, SearchOutcome::Stopped(1)));
    }
}
