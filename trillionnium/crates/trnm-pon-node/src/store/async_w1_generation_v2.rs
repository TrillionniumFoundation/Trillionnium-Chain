//! Real Node funding/payment owner adapter plus a strict
//! full-W1 verifier boundary. There is deliberately no signer or payment sender.
use super::Node;
use trnm_mvcc_fee::pon_executor;
use trnm_service_settlement::native_budget::{
    NativeBudgetErrorV1, NativeBudgetResultV1, NativeFundingObservationV1, NativeFundingOwnerV1,
    NativeFundingSourceV1, NativePaymentObservationV1, NativePaymentQueryV1,
};
use trnm_service_settlement::native_generation_budget_v2::{
    sha256, ClockCheckpointV2, GenerationEvidenceV2, GenerationResourcesV2, GenerationStatementV2,
    Hash, IndependentFullVerdictV2, NativeGenerationOwnerV2, ProviderJobV2, Result, PROFILE,
};

fn error(code: &'static str) -> NativeBudgetErrorV1 {
    NativeBudgetErrorV1::Invalid(code)
}
fn check(ok: bool, code: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(error(code))
    }
}
fn owner_error(e: impl std::fmt::Display) -> NativeBudgetErrorV1 {
    NativeBudgetErrorV1::Owner(e.to_string())
}

/// These are owner-runtime observations, not deserializable provider responses.
/// The actual runtime implementation belongs inside this crate and must verify
/// its source/run closure, original process/cgroup/job identity, artifact bytes,
/// every stage exit and complete relation. A reused-segment compression result
/// cannot construct this FreshFull evidence. No permissive constructor is public.
pub struct OwnedFullGenerationV2 {
    pub(crate) job: ProviderJobV2,
    pub(crate) execution_source_commitment: Hash,
    pub(crate) input_sha256: Hash,
    pub(crate) guest_sha256: Hash,
    pub(crate) evidence_digest: Hash,
    pub(crate) receipt_sha256: Hash,
    pub(crate) resources: GenerationResourcesV2,
    /// Clock in the CONTROLLER'S original domain, never a remote monotonic stamp.
    pub(crate) controller_received: ClockCheckpointV2,
}
pub struct OwnedVerifierRunV2 {
    pub(crate) executable_sha256: Hash,
    pub(crate) successful_exit: bool,
    pub(crate) stdout: Vec<u8>,
    /// Owned verifier-process resources, separately measured after join. CPU
    /// and GPU time are added; the sum of scope memory peaks is a conservative
    /// upper bound, explicitly NOT a measured simultaneous aggregate RSS peak.
    pub(crate) resources: GenerationResourcesV2,
    /// Includes process cleanup/receipt collection on the controller clock.
    pub(crate) finished: ClockCheckpointV2,
}
/// Production runtimes implement these methods without permissive defaults.
/// The ignored heavy research entry supplies an actual owned-process runtime;
/// unknown resource observations never become a complete owner verdict.
pub trait OwnedGenerationRuntimeV2 {
    fn clock_checkpoint(&mut self) -> Result<ClockCheckpointV2>;
    fn reconcile_fresh_execution(
        &mut self,
        statement: &GenerationStatementV2,
        job: &ProviderJobV2,
        evidence: &GenerationEvidenceV2<'_>,
    ) -> Result<OwnedFullGenerationV2>;
    /// Execute the pinned independent binary with exactly RECEIPT HEADER
    /// EXPECTED_ARTIFACTS; enforce the original absolute deadline and join owned
    /// descendants. Verify executable identity using the actual owned runtime,
    /// not only a pathname hash vulnerable to substitution during exec.
    fn run_independent_verifier(
        &mut self,
        statement: &GenerationStatementV2,
        evidence: &GenerationEvidenceV2<'_>,
    ) -> Result<OwnedVerifierRunV2>;
}
mod task_owner;
pub struct NodeGenerationOwnerV2<'a, R> {
    node: &'a mut Node,
    runtime: &'a mut R,
    task_owner: task_owner::TaskOwnerV2,
}
impl<'a, R> NodeGenerationOwnerV2<'a, R> {
    pub fn new(node: &'a mut Node, runtime: &'a mut R) -> Result<Self> {
        let task_owner = task_owner::TaskOwnerV2::open(node)?;
        Ok(Self {
            node,
            runtime,
            task_owner,
        })
    }
}
impl<R> NativeFundingOwnerV1 for NodeGenerationOwnerV2<'_, R> {
    fn observe_funding(
        &mut self,
        source: NativeFundingSourceV1,
    ) -> NativeBudgetResultV1<NativeFundingObservationV1> {
        self.node
            .native_funding_observation(source)
            .map_err(owner_error)
    }
    fn observe_payment(
        &mut self,
        query: &NativePaymentQueryV1,
    ) -> NativeBudgetResultV1<NativePaymentObservationV1> {
        self.node
            .native_payment_observation(query)
            .map_err(owner_error)
    }
}
fn json_hash(v: &serde_json::Value, key: &str) -> Result<Hash> {
    let text = v
        .get(key)
        .and_then(serde_json::Value::as_str)
        .ok_or(error("GENERATION_VERIFIER_JSON"))?;
    check(
        text.len() == 64
            && text
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "GENERATION_VERIFIER_JSON",
    )?;
    hex::decode(text)
        .map_err(owner_error)?
        .try_into()
        .map_err(|_| error("GENERATION_VERIFIER_JSON"))
}
impl<R: OwnedGenerationRuntimeV2> NativeGenerationOwnerV2 for NodeGenerationOwnerV2<'_, R> {
    fn claim_generation_task(&mut self, s: &GenerationStatementV2, journal: Hash) -> Result<()> {
        self.task_owner.claim(s, journal)
    }
    fn clock_checkpoint(&mut self) -> Result<ClockCheckpointV2> {
        self.runtime.clock_checkpoint()
    }
    fn verify_full_generation(
        &mut self,
        s: &GenerationStatementV2,
        job: &ProviderJobV2,
        e: &GenerationEvidenceV2<'_>,
    ) -> Result<IndependentFullVerdictV2> {
        s.original_deadline
            .check(&self.runtime.clock_checkpoint()?)?;
        let generation = self.runtime.reconcile_fresh_execution(s, job, e)?;
        check(
            generation.job == *job
                && generation.execution_source_commitment == s.execution_source_commitment
                && generation.input_sha256 == s.input_sha256
                && generation.guest_sha256 == s.guest_sha256
                && generation.evidence_digest == e.owned_execution_evidence
                && generation.evidence_digest != [0; 32]
                && generation.receipt_sha256 == sha256(e.receipt)
                && generation.resources.receipt_bytes == e.receipt.len() as u64,
            "GENERATION_FRESH_OWNED_EXECUTION",
        )?;
        s.original_deadline.check(&generation.controller_received)?;
        check(
            sha256(e.header) == s.header_sha256
                && e.expected_artifacts.len() == 64
                && sha256(e.expected_artifacts) == s.expected_artifacts_sha256,
            "GENERATION_INDEPENDENT_EXPECTATION",
        )?;
        let verifier = self.runtime.run_independent_verifier(s, e)?;
        s.original_deadline.check(&verifier.finished)?;
        check(
            verifier.successful_exit
                && verifier.executable_sha256 == s.verifier_binary_sha256
                && !verifier.stdout.is_empty()
                && verifier.stdout.len() <= 16_384,
            "GENERATION_INDEPENDENT_VERIFIER_PROCESS",
        )?;
        let v: serde_json::Value = serde_json::from_slice(&verifier.stdout).map_err(owner_error)?;
        check(
            v["schema"] == "TRNM-W1-V2-FULL-VERIFY1"
                && v["profile_id"] == PROFILE
                && v["sdk"] == "3.0.6"
                && v["iterations"] == 1
                && v["independent_proof_trials"] == 1
                && v["receipt_bytes"] == e.receipt.len() as u64
                && v["image_id"] == serde_json::to_value(s.image_id).map_err(owner_error)?
                && v["parent_eligibility_checked"] == false
                && v["admission_authorized"] == false,
            "GENERATION_INDEPENDENT_VERIFIER_PROFILE",
        )?;
        // independent_proof_trials in this verifier output is a decode/verify
        // report field; ONLY the owned pipeline evidence above establishes a
        // new generation trial. It is never used as freshness evidence here.
        let plus = |a: u64, b: u64| {
            a.checked_add(b)
                .ok_or(error("GENERATION_RESOURCE_ARITHMETIC"))
        };
        let consumed = GenerationResourcesV2 {
            cpu_ns: plus(generation.resources.cpu_ns, verifier.resources.cpu_ns)?,
            gpu_ns: plus(generation.resources.gpu_ns, verifier.resources.gpu_ns)?,
            memory_peak_upper_bound_bytes: plus(
                generation.resources.memory_peak_upper_bound_bytes,
                verifier.resources.memory_peak_upper_bound_bytes,
            )?,
            receipt_bytes: generation.resources.receipt_bytes,
        };
        let verdict = IndependentFullVerdictV2 {
            receipt_sha256: json_hash(&v, "receipt_sha256")?,
            header_sha256: json_hash(&v, "header_sha256")?,
            expected_artifacts_sha256: json_hash(&v, "expected_artifacts_sha256")?,
            journal_sha256: json_hash(&v, "journal_sha256")?,
            work_id: json_hash(&v, "work_id")?,
            image_id: s.image_id,
            profile_id: PROFILE.into(),
            sdk: "3.0.6".into(),
            verifier_binary_sha256: verifier.executable_sha256,
            owned_execution_evidence: generation.evidence_digest,
            consumed,
        };
        check(
            verdict.receipt_sha256 == sha256(e.receipt)
                && verdict.header_sha256 == s.header_sha256
                && verdict.expected_artifacts_sha256 == s.expected_artifacts_sha256
                && verdict.journal_sha256 == s.expected_journal_sha256
                && verdict.work_id == s.expected_work_id,
            "GENERATION_INDEPENDENT_VERIFIER_BINDING",
        )?;
        Ok(verdict)
    }
    fn check_settlement_wire(
        &mut self,
        s: &GenerationStatementV2,
        wire: &[u8],
    ) -> Result<NativePaymentQueryV1> {
        // This first candidate uses the actual b6 classical native owner API.
        // It explicitly refuses PQ profiles through validate_main_envelope;
        // it must not silently downgrade or translate a PQ transaction.
        let funding = self
            .node
            .native_funding_observation(NativeFundingSourceV1::Task(s.task))
            .map_err(owner_error)?;
        let next_height = funding
            .anchor
            .height
            .checked_add(1)
            .ok_or(error("GENERATION_HEIGHT"))?;
        check(
            next_height < s.chain_deadline && wire.len() <= 4096,
            "GENERATION_SETTLEMENT_DEADLINE",
        )?;
        let tx = pon_executor::validate_main_envelope(wire, next_height, &self.node.settings.app)
            .map_err(owner_error)?;
        let mut payload = s.task.to_vec();
        payload.extend(s.id()?);
        check(
            tx.sender == s.owner && tx.tag == 5 && tx.payload == payload,
            "GENERATION_SETTLEMENT_WIRE",
        )?;
        let row = funding
            .row
            .ok_or(error("GENERATION_NATIVE_SOURCE_MISSING"))?;
        let amount = row
            .get("remaining")
            .and_then(serde_json::Value::as_u64)
            .ok_or(error("GENERATION_NATIVE_ROW"))?;
        // The public M06 precheck verifies canonical context/signature/expiry.
        // Nonce, fees, funds, branch admission and the payment still belong to
        // the ordinary native execution path. Nothing is submitted here.
        Ok(NativePaymentQueryV1 {
            source: NativeFundingSourceV1::Task(s.task),
            subject: s.id()?,
            beneficiary: s.provider,
            operation: tx.id().map_err(|e| owner_error(format!("{e:?}")))?,
            maximum_gross_units: amount,
        })
    }
}

#[cfg(test)]
mod tests;
