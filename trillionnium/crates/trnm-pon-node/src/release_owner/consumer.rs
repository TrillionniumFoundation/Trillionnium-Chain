//! Authenticated one-shot Claim before the real Node owner opens.
use super::deployment::Deployment;
use super::execution_wire::{Claim, Contract, LaunchAttempt};
use super::frontier::{hash, invalid, Digest32, Result};
use super::launch::{Handoff, MAX_CONFIGURATION};
use super::owner::Owner;
use super::process_identity::{self, WorkingDirectory};
use super::proof_state::State;
use super::records::Record;
use super::sealed::Sealed;
use std::collections::BTreeMap;
use std::sync::Arc;

struct Actual {
    deployment: Deployment,
    attempt_id: Digest32,
    attempt: LaunchAttempt,
    configuration: Sealed,
    handoff: Sealed,
    image: Sealed,
    working: WorkingDirectory,
    raw: Vec<u8>,
}
pub(crate) struct Session {
    actual: Arc<Actual>,
    active_inputs: Digest32,
}
pub(crate) struct Admission {
    owner: Owner,
    state: State,
    contract: Contract,
    actual: Arc<Actual>,
}

fn environment(contract: &Contract) -> Result<()> {
    let raw: Vec<_> = std::env::vars_os().collect();
    let values = raw
        .iter()
        .map(|(k, v)| {
            Ok((
                k.to_str()
                    .ok_or_else(|| invalid("M15 environment key encoding"))?
                    .to_string(),
                v.to_str()
                    .ok_or_else(|| invalid("M15 environment value encoding"))?
                    .to_string(),
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    if values.len() != raw.len() || values != contract.environment {
        return Err(invalid("M15 exact restricted environment required"));
    }
    Ok(())
}
fn arguments(attempt: &LaunchAttempt) -> Result<()> {
    let actual = std::env::args_os()
        .map(|v| {
            v.into_string()
                .map_err(|_| invalid("M15 actual argv encoding"))
        })
        .collect::<Result<Vec<_>>>()?;
    if actual != attempt.actual_arguments {
        return Err(invalid("M15 complete actual argv mismatch"));
    }
    Ok(())
}
pub(crate) fn inputs_digest(inputs: &serde_json::Value) -> Result<Digest32> {
    fn ordered(value: &serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Object(map) => {
                let sorted: BTreeMap<_, _> = map.iter().collect();
                serde_json::Value::Object(
                    sorted
                        .into_iter()
                        .map(|(key, value)| (key.clone(), ordered(value)))
                        .collect(),
                )
            }
            serde_json::Value::Array(values) => {
                serde_json::Value::Array(values.iter().map(ordered).collect())
            }
            value => value.clone(),
        }
    }
    if !inputs.is_object() {
        return Err(invalid("M15 actual inputs object required"));
    }
    Ok(hash(
        b"TRNM/M15/OperatorInputs/v1\0",
        &super::codec::encode(&ordered(inputs), MAX_CONFIGURATION)?,
    ))
}

impl Session {
    pub(super) fn consume(
        outside: crate::operator_continuous_controller::OutsideLaunch<'_>,
        launch_fd: u32,
        handoff_fd: u32,
    ) -> Result<Self> {
        // The handoff is only an untrusted locator. The independent fixed
        // deployment chooses namespace, roots, endpoints and actual retained state.
        let mut owner = Owner::open()?;
        let transport = Sealed::untrusted_handoff(handoff_fd, 4096)?;
        let handoff: Handoff = super::codec::decode(&transport.read(4096)?, 4096)?;
        if handoff.schema_version != 1 || handoff.namespace != owner.context.namespace {
            return Err(invalid("M15 handoff namespace/schema"));
        }
        let state = owner.reload()?;
        let attempt = state
            .pending_attempt(handoff.attempt, owner.now()?)?
            .clone();
        let contract = &attempt.contract;
        if attempt.launch_fd != launch_fd
            || attempt.handoff_fd != handoff_fd
            || state.claims.contains(&handoff.attempt)
            || contract.outside.path != outside.path
            || contract.outside.sha256 != outside.sha256
            || contract.outside.registry_key != outside.registry_key
            || contract.outside.task_key != outside.task_key
            || contract.outside.source_commit != outside.source_commit
            || contract.outside.node_policy_source != outside.node_policy_source
            || contract.outside.registry2_package != outside.registry2_package
        {
            return Err(invalid(
                "M15 handoff original outside/descriptor/replay mismatch",
            ));
        }
        let data = Sealed::untrusted_handoff(launch_fd, MAX_CONFIGURATION)?;
        if data.digest != super::launch::configuration_digest(&contract.outside.sha256)? {
            return Err(invalid("M15 actual inherited launch configuration hash"));
        }
        let raw = data.read(MAX_CONFIGURATION)?;
        let policy = state
            .configuration
            .as_ref()
            .ok_or_else(|| invalid("M15 current configuration"))?;
        super::launch::check_inputs(contract, &raw, policy.inputs_digest)?;
        let image = Sealed::actual_process_image(
            contract.program_sha256,
            contract.program_size,
            contract.platform_digest,
        )?;
        let working =
            WorkingDirectory::open(&contract.working_directory, &contract.working_identity)?;
        let actual = Arc::new(Actual {
            deployment: owner.deployment.clone(),
            attempt_id: handoff.attempt,
            attempt,
            configuration: data,
            handoff: transport,
            image,
            working,
            raw,
        });
        let session = Self {
            actual,
            active_inputs: policy.inputs_digest,
        };
        session.actual.check_actual()?;
        let claim = Claim {
            schema_version: 1,
            attempt: handoff.attempt,
            process: process_identity::actual()?,
            observed_at: owner.now()?,
            kernel_checkpoint: state.authority.checkpoint(),
        };
        owner.append(Record::Claim(claim), |_, _| session.actual.check_actual())?;
        // Claim is durable reservation consumption, never an assertion that
        // exec/Node open completed. Reopen/replay cannot consume it again.
        let current = owner.reload()?;
        let window = owner.revalidate_current(&current, &session.actual.attempt.contract)?;
        session.actual.check_actual()?;
        owner.finish_observation(window)?;
        Ok(session)
    }

    pub(crate) fn configuration(&self) -> &[u8] {
        &self.actual.raw
    }

    pub(crate) fn refreshed(&mut self, digest: Digest32) {
        self.active_inputs = digest;
    }

    pub(crate) fn admit(&self, inputs: Option<Digest32>) -> Result<Admission> {
        self.actual.check_actual()?;
        let mut owner = Owner::open()?;
        if owner.deployment != self.actual.deployment {
            return Err(invalid("M15 deployment epoch changed"));
        }
        let state = owner.reload()?;
        if !state.claims.contains(&self.actual.attempt_id)
            || state.attempts.get(&self.actual.attempt_id) != Some(&self.actual.attempt)
        {
            return Err(invalid("M15 actual process claim no longer present"));
        }
        if state
            .configuration
            .as_ref()
            .ok_or_else(|| invalid("M15 current policy"))?
            .inputs_digest
            != inputs.unwrap_or(self.active_inputs)
        {
            return Err(invalid(
                "M15 actual active/Refresh inputs are not the current signed configuration",
            ));
        }
        owner.revalidate_current(&state, &self.actual.attempt.contract)?;
        Ok(Admission {
            owner,
            state,
            contract: self.actual.attempt.contract.clone(),
            actual: self.actual.clone(),
        })
    }
}
impl Admission {
    /// Call after taking the actual Node mutex and immediately before its owner
    /// mutation. No serialized receipt can be reused as this admission.
    pub(crate) fn revalidate(&mut self) -> Result<()> {
        self.actual.check_actual()?;
        let window = self.owner.revalidate_current(&self.state, &self.contract)?;
        self.actual.check_actual()?;
        self.owner.finish_observation(window)
    }
}

impl Actual {
    fn check_actual(&self) -> Result<()> {
        self.deployment.revalidate()?;
        if process_identity::actual()? != self.attempt.process {
            return Err(invalid("M15 actual process mismatch"));
        }
        arguments(&self.attempt)?;
        environment(&self.attempt.contract)?;
        self.configuration
            .require_descriptor(self.attempt.launch_fd)?;
        self.handoff.require_descriptor(self.attempt.handoff_fd)?;
        self.image.recheck()?;
        self.working.require_current()
    }
}
