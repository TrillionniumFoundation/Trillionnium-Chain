//! Crate-private PoCO-BFT v0 execution-outcome policy kernel.
//!
//! This module deliberately does not adapt the policy to ABCI. In particular,
//! an unavailable dependency is never converted into a terminal proposal
//! rejection here. It also defines no receipt constructor: only the `Valid`
//! variant can carry a caller's already-sealed successful execution value.

use std::fmt::Display;

use crate::native_payload_validation::{
    ClosedFailedCoreAuthorizedRegularRuntimeAttemptV0, CoreAuthorizedRegularComputedRootMismatchV0,
    CoreAuthorizedRegularFailureOutcomeFactsV0,
    CoreAuthorizedRegularNonRuntimeDeterministicInvalidV0,
    CoreAuthorizedRegularNonRuntimeFailureOutcomeFactsV0,
    CoreAuthorizedRegularNonRuntimeFailureOutcomeViewV0,
    CoreAuthorizedRegularNonRuntimeInvariantV0, CoreAuthorizedRegularNonRuntimeUnavailableKindV0,
    CoreAuthorizedRegularPreExecutionFailureOutcomeFactsV0,
    CoreAuthorizedRegularPreExecutionInvalidKindV0,
    CoreAuthorizedRegularPreExecutionInvariantStageV0,
    CoreAuthorizedRegularPreExecutionUnavailableKindV0,
    CoreAuthorizedRegularRuntimeFailureOutcomeFactsV0,
    CoreAuthorizedRegularRuntimeUnavailableKindV0,
    FailedCoreAuthorizedRegularRuntimeCommitmentComparisonV0,
    MatchedCoreAuthorizedRegularRuntimeCommitmentsV0,
};
use trnm_protocol::CanonicalTxV1;
use trnm_runtime::{
    try_execute_v0, DeterministicRuntimeFailureDispositionV0, ExecutionContext,
    RuntimeExecutionAttemptFailureV0, RuntimeReceipt, TryStateViewV0,
};

const VALID_CODE: &str = "valid";
const VALID_REASON: &str = "deterministic execution and committed roots match";

/// One host-issued attempt to validate an exact signed header.
///
/// A later generation may retry an `Unavailable` result. The generation is a
/// local correlation value, not a terminal fact about the header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct ValidationGenerationV0(u64);

impl ValidationGenerationV0 {
    pub(super) const fn new(value: u64) -> Self {
        Self(value)
    }

    pub(super) const fn get(self) -> u64 {
        self.0
    }
}

/// Successful result of one real runtime attempt.
///
/// This value is deliberately not a valid execution-outcome authority.
/// The future native host comparator must consume it together with authenticated
/// inputs and prove every committed post-execution root before `Valid` can be
/// formed.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct AppliedRuntimeAttemptV0 {
    inputs: AuthenticatedExecutionInputsV0,
    receipt: RuntimeReceipt,
}

impl AppliedRuntimeAttemptV0 {
    pub(super) const fn generation(&self) -> ValidationGenerationV0 {
        self.inputs.generation()
    }

    pub(super) const fn receipt(&self) -> &RuntimeReceipt {
        &self.receipt
    }
}

/// Opaque failure of one real runtime attempt.
///
/// The wrapped runtime token has no public constructor, so this type cannot be
/// manufactured from a standalone public `RuntimeError`. A state dependency
/// error remains available under its original type and is never classified by
/// diagnostic text.
#[derive(Debug)]
pub(super) struct RuntimePlanningFailureV0<StateError> {
    inputs: AuthenticatedExecutionInputsV0,
    attempt: RuntimeExecutionAttemptFailureV0<StateError>,
}

impl<StateError> RuntimePlanningFailureV0<StateError> {
    pub(super) const fn generation(&self) -> ValidationGenerationV0 {
        self.inputs.generation()
    }

    pub(super) fn state_unavailable(&self) -> Option<&StateError> {
        self.attempt.state_unavailable()
    }
}

/// Unwired module-private adapter from an actual runtime call into a typed
/// planning result. The authenticated-input token is consumed into either the
/// success or failure result, so a later caller cannot splice in a different
/// same-generation body/parent/runtime join. There is intentionally no
/// production constructor for that input token or an exact tx/index/view
/// carrier in this slice.
fn attempt_runtime_transaction_v0<View>(
    inputs: AuthenticatedExecutionInputsV0,
    tx: &CanonicalTxV1,
    context: ExecutionContext<'_>,
    view: &View,
) -> Result<AppliedRuntimeAttemptV0, RuntimePlanningFailureV0<View::Error>>
where
    View: TryStateViewV0 + ?Sized,
{
    match try_execute_v0(tx, context, view) {
        Ok(receipt) => Ok(AppliedRuntimeAttemptV0 { inputs, receipt }),
        Err(attempt) => Err(RuntimePlanningFailureV0 { inputs, attempt }),
    }
}

/// Proof-stage fact that the complete canonical body reproduces the signed
/// header's payload root.
///
/// There is intentionally no production constructor in this unwired slice.
/// The eventual host adapter must construct it only from its body verifier.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct CanonicalBodyMatchesHeaderV0 {
    generation: ValidationGenerationV0,
}

/// Proof-stage fact that the direct parent state is authenticated and its root
/// reproduces the parent header's state root.
///
/// There is intentionally no production constructor in this unwired slice.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct AuthenticatedParentStateV0 {
    generation: ValidationGenerationV0,
}

/// Proof-stage fact that the epoch-authorized runtime, parameters, and any
/// block-kind-specific dependencies (including a required cutoff) are fixed.
///
/// There is intentionally no production constructor in this unwired slice.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct AuthorizedRuntimeContextV0 {
    generation: ValidationGenerationV0,
}

/// Opaque prerequisite for producing a terminal execution-validation result.
///
/// Runtime failures and post-execution root mismatches cannot be classified as
/// terminal without consuming this token. Its fields are private so the
/// application cannot mint it from a generation number alone.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct AuthenticatedExecutionInputsV0 {
    generation: ValidationGenerationV0,
}

impl AuthenticatedExecutionInputsV0 {
    const fn generation(&self) -> ValidationGenerationV0 {
        self.generation
    }
}

/// Successful execution bound to an exact comparison of every committed
/// post-execution root against the authenticated signed header.
///
/// This slice intentionally provides no production constructor yet. The
/// future host adapter must mint this token only inside one exact comparator
/// that owns both the successful execution and the authenticated inputs, and
/// that compares state, receipts, and evidence roots. A boolean "roots match"
/// flag is not an authority boundary.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct ComputedRootsMatchHeaderV0<SuccessfulExecution> {
    inputs: AuthenticatedExecutionInputsV0,
    successful_execution: SuccessfulExecution,
}

/// Joins independently established input facts into the sole terminal-result
/// prerequisite. Cross-generation joins are local integration faults and must
/// fail stop rather than becoming a property of any signed header.
fn join_authenticated_execution_inputs_v0(
    body: CanonicalBodyMatchesHeaderV0,
    parent: AuthenticatedParentStateV0,
    runtime: AuthorizedRuntimeContextV0,
) -> Result<AuthenticatedExecutionInputsV0, InvariantFaultV0> {
    if body.generation != parent.generation || body.generation != runtime.generation {
        return Err(InvariantFaultV0 {
            generation: body.generation,
            cause: InvariantFaultCauseV0::AuthenticatedInputGenerationMismatch,
        });
    }
    Ok(AuthenticatedExecutionInputsV0 {
        generation: body.generation,
    })
}

/// Retryable dependency/source failures admitted by protocol v0.
///
/// Every variant remains `Unavailable`; diagnostic text is never inspected to
/// promote one of these causes into a terminal result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UnavailableCauseV0 {
    BodyMissing,
    BodyIncomplete,
    BodyNonCanonical,
    SourcePayloadRootMismatch,
    ParentStateMissing,
    ParentStateUnauthenticated,
    CutoffStateMissing,
    CutoffStateUnauthenticated,
    RuntimeDependency,
    Database,
    StorageIo,
    HostResource,
    ReservationCapacity,
}

impl UnavailableCauseV0 {
    const fn code(self) -> &'static str {
        match self {
            Self::BodyMissing => "body_missing",
            Self::BodyIncomplete => "body_incomplete",
            Self::BodyNonCanonical => "body_non_canonical",
            Self::SourcePayloadRootMismatch => "source_payload_root_mismatch",
            Self::ParentStateMissing => "parent_state_missing",
            Self::ParentStateUnauthenticated => "parent_state_unauthenticated",
            Self::CutoffStateMissing => "cutoff_state_missing",
            Self::CutoffStateUnauthenticated => "cutoff_state_unauthenticated",
            Self::RuntimeDependency => "runtime_unavailable",
            Self::Database => "database_unavailable",
            Self::StorageIo => "storage_io_unavailable",
            Self::HostResource => "host_resource_unavailable",
            Self::ReservationCapacity => "validation_reservation_capacity_unavailable",
        }
    }

    const fn reason(self) -> &'static str {
        match self {
            Self::BodyMissing => "complete canonical block body is missing",
            Self::BodyIncomplete => "complete canonical block body is unavailable",
            Self::BodyNonCanonical => "body source did not provide canonical bytes",
            Self::SourcePayloadRootMismatch => {
                "source body does not reproduce the signed payload root"
            }
            Self::ParentStateMissing => "authenticated parent state is missing",
            Self::ParentStateUnauthenticated => "parent state could not be authenticated",
            Self::CutoffStateMissing => "authenticated cutoff state is missing",
            Self::CutoffStateUnauthenticated => "cutoff state could not be authenticated",
            Self::RuntimeDependency => "transient runtime dependency is unavailable",
            Self::Database => "transient database dependency is unavailable",
            Self::StorageIo => "transient storage I/O is unavailable",
            Self::HostResource => "transient host resource is unavailable",
            Self::ReservationCapacity => "native validation reservation capacity is unavailable",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct UnavailableV0 {
    generation: ValidationGenerationV0,
    cause: UnavailableCauseV0,
}

impl UnavailableV0 {
    pub(super) const fn cause(&self) -> UnavailableCauseV0 {
        self.cause
    }
}

/// Roots computed only after deterministic execution of authenticated inputs.
/// Payload-root mismatch is intentionally absent: a mismatched source body is
/// `Unavailable`, not a terminal fact about the header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ComputedRootMismatchV0 {
    State,
    Receipts,
    Evidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeterministicallyInvalidCauseV0 {
    RuntimeTransactionReject {
        runtime_code: &'static str,
        runtime_reason: &'static str,
    },
    ComputedRootMismatch(ComputedRootMismatchV0),
    NativeRegularBodyEvidence,
    NativeRegularTransactionEncodingOrAuthorization,
    NativeRegularTransactionReplay,
    NativeRegularNonRuntime(CoreAuthorizedRegularNonRuntimeDeterministicInvalidV0),
}

impl DeterministicallyInvalidCauseV0 {
    const fn code(self) -> &'static str {
        match self {
            Self::RuntimeTransactionReject { .. } => "runtime_transaction_reject",
            Self::ComputedRootMismatch(ComputedRootMismatchV0::State) => {
                "computed_state_root_mismatch"
            }
            Self::ComputedRootMismatch(ComputedRootMismatchV0::Receipts) => {
                "computed_receipts_root_mismatch"
            }
            Self::ComputedRootMismatch(ComputedRootMismatchV0::Evidence) => {
                "computed_evidence_root_mismatch"
            }
            Self::NativeRegularBodyEvidence => "native_regular_body_evidence_invalid",
            Self::NativeRegularTransactionEncodingOrAuthorization => {
                "native_regular_transaction_encoding_or_authorization_invalid"
            }
            Self::NativeRegularTransactionReplay => "native_regular_transaction_replay_invalid",
            Self::NativeRegularNonRuntime(reason) => reason.code(),
        }
    }

    const fn reason(self) -> &'static str {
        match self {
            Self::RuntimeTransactionReject { .. } => {
                "deterministic transaction rejection invalidates the complete block"
            }
            Self::ComputedRootMismatch(ComputedRootMismatchV0::State) => {
                "computed state root differs from the signed header"
            }
            Self::ComputedRootMismatch(ComputedRootMismatchV0::Receipts) => {
                "computed receipts root differs from the signed header"
            }
            Self::ComputedRootMismatch(ComputedRootMismatchV0::Evidence) => {
                "computed evidence root differs from the signed header"
            }
            Self::NativeRegularBodyEvidence => {
                "canonical body evidence fails deterministic strict verification"
            }
            Self::NativeRegularTransactionEncodingOrAuthorization => {
                "canonical body transaction encoding or authorization is invalid"
            }
            Self::NativeRegularTransactionReplay => {
                "canonical body transaction command or signer nonce is already consumed"
            }
            Self::NativeRegularNonRuntime(reason) => reason.reason(),
        }
    }

    const fn runtime_detail(self) -> Option<RuntimeFailureDetailV0> {
        match self {
            Self::RuntimeTransactionReject {
                runtime_code,
                runtime_reason,
            } => Some(RuntimeFailureDetailV0 {
                code: runtime_code,
                reason: runtime_reason,
            }),
            Self::ComputedRootMismatch(_)
            | Self::NativeRegularBodyEvidence
            | Self::NativeRegularTransactionEncodingOrAuthorization
            | Self::NativeRegularTransactionReplay
            | Self::NativeRegularNonRuntime(_) => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RuntimeFailureDetailV0 {
    code: &'static str,
    reason: &'static str,
}

impl RuntimeFailureDetailV0 {
    pub(super) const fn code(self) -> &'static str {
        self.code
    }

    pub(super) const fn reason(self) -> &'static str {
        self.reason
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum InvalidExecutionScopeV0 {
    WholeBlockNoReceipt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DeterministicallyInvalidV0 {
    generation: ValidationGenerationV0,
    cause: DeterministicallyInvalidCauseV0,
}

impl DeterministicallyInvalidV0 {
    pub(super) const fn scope(&self) -> InvalidExecutionScopeV0 {
        InvalidExecutionScopeV0::WholeBlockNoReceipt
    }

    pub(super) const fn runtime_detail(&self) -> Option<RuntimeFailureDetailV0> {
        self.cause.runtime_detail()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InvariantFaultCauseV0 {
    Runtime {
        runtime_code: &'static str,
        runtime_reason: &'static str,
    },
    AuthenticatedInputGenerationMismatch,
    NativeRegularCommitmentComparison,
    NativeRegularRuntimeAttempt,
    NativeRegularPreExecution(CoreAuthorizedRegularPreExecutionInvariantStageV0),
    NativeRegularNonRuntime(CoreAuthorizedRegularNonRuntimeInvariantV0),
}

impl InvariantFaultCauseV0 {
    const fn code(self) -> &'static str {
        match self {
            Self::Runtime { .. } => "runtime_invariant_fault",
            Self::AuthenticatedInputGenerationMismatch => "authenticated_input_generation_mismatch",
            Self::NativeRegularCommitmentComparison => {
                "native_regular_commitment_comparison_invariant"
            }
            Self::NativeRegularRuntimeAttempt => "native_regular_runtime_attempt_invariant",
            Self::NativeRegularPreExecution(
                CoreAuthorizedRegularPreExecutionInvariantStageV0::Open,
            ) => "native_regular_open_invariant",
            Self::NativeRegularPreExecution(
                CoreAuthorizedRegularPreExecutionInvariantStageV0::Reservation,
            ) => "native_regular_reservation_invariant",
            Self::NativeRegularPreExecution(
                CoreAuthorizedRegularPreExecutionInvariantStageV0::TransactionDecode,
            ) => "native_regular_transaction_decode_invariant",
            Self::NativeRegularPreExecution(
                CoreAuthorizedRegularPreExecutionInvariantStageV0::PostStatePlan,
            ) => "native_regular_post_state_plan_invariant",
            Self::NativeRegularNonRuntime(reason) => reason.code(),
        }
    }

    const fn reason(self) -> &'static str {
        match self {
            Self::Runtime { .. } => "deterministic runtime invariant fault requires host fail-stop",
            Self::AuthenticatedInputGenerationMismatch => {
                "authenticated execution inputs belong to different request generations"
            }
            Self::NativeRegularCommitmentComparison => {
                "native regular commitment comparison invariant requires host fail-stop"
            }
            Self::NativeRegularRuntimeAttempt => {
                "native regular runtime attempt invariant requires host fail-stop"
            }
            Self::NativeRegularPreExecution(_) => {
                "native regular pre-execution invariant requires host fail-stop"
            }
            Self::NativeRegularNonRuntime(reason) => reason.reason(),
        }
    }

    const fn runtime_detail(self) -> Option<RuntimeFailureDetailV0> {
        match self {
            Self::Runtime {
                runtime_code,
                runtime_reason,
            } => Some(RuntimeFailureDetailV0 {
                code: runtime_code,
                reason: runtime_reason,
            }),
            Self::AuthenticatedInputGenerationMismatch
            | Self::NativeRegularCommitmentComparison
            | Self::NativeRegularRuntimeAttempt
            | Self::NativeRegularPreExecution(_)
            | Self::NativeRegularNonRuntime(_) => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct InvariantFaultV0 {
    generation: ValidationGenerationV0,
    cause: InvariantFaultCauseV0,
}

impl InvariantFaultV0 {
    pub(super) const fn requires_fail_stop(&self) -> bool {
        true
    }

    pub(super) const fn code(&self) -> &'static str {
        self.cause.code()
    }

    pub(super) const fn reason(&self) -> &'static str {
        self.cause.reason()
    }

    pub(super) const fn runtime_detail(&self) -> Option<RuntimeFailureDetailV0> {
        self.cause.runtime_detail()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TerminalExecutionDispositionV0 {
    Valid,
    DeterministicallyInvalid,
}

/// App-private opaque execution result. `SuccessfulExecution` is carried only
/// by the private `Valid` representation; sibling modules cannot construct a
/// variant or bypass the roots-match constructor.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct ExecutionOutcomeV0<SuccessfulExecution> {
    inner: ExecutionOutcomeKindV0<SuccessfulExecution>,
}

#[derive(Debug, PartialEq, Eq)]
enum ExecutionOutcomeKindV0<SuccessfulExecution> {
    Valid {
        generation: ValidationGenerationV0,
        successful_execution: SuccessfulExecution,
    },
    Unavailable(UnavailableV0),
    DeterministicallyInvalid(DeterministicallyInvalidV0),
    InvariantFault(InvariantFaultV0),
}

impl<SuccessfulExecution> ExecutionOutcomeV0<SuccessfulExecution> {
    pub(super) const fn generation(&self) -> ValidationGenerationV0 {
        match &self.inner {
            ExecutionOutcomeKindV0::Valid { generation, .. } => *generation,
            ExecutionOutcomeKindV0::Unavailable(fact) => fact.generation,
            ExecutionOutcomeKindV0::DeterministicallyInvalid(fact) => fact.generation,
            ExecutionOutcomeKindV0::InvariantFault(fact) => fact.generation,
        }
    }

    pub(super) const fn successful_execution(&self) -> Option<&SuccessfulExecution> {
        match &self.inner {
            ExecutionOutcomeKindV0::Valid {
                successful_execution,
                ..
            } => Some(successful_execution),
            ExecutionOutcomeKindV0::Unavailable(_)
            | ExecutionOutcomeKindV0::DeterministicallyInvalid(_)
            | ExecutionOutcomeKindV0::InvariantFault(_) => None,
        }
    }

    pub(super) const fn terminal_disposition(&self) -> Option<TerminalExecutionDispositionV0> {
        match &self.inner {
            ExecutionOutcomeKindV0::Valid { .. } => Some(TerminalExecutionDispositionV0::Valid),
            ExecutionOutcomeKindV0::DeterministicallyInvalid(_) => {
                Some(TerminalExecutionDispositionV0::DeterministicallyInvalid)
            }
            ExecutionOutcomeKindV0::Unavailable(_) | ExecutionOutcomeKindV0::InvariantFault(_) => {
                None
            }
        }
    }

    pub(super) const fn code(&self) -> &'static str {
        match &self.inner {
            ExecutionOutcomeKindV0::Valid { .. } => VALID_CODE,
            ExecutionOutcomeKindV0::Unavailable(fact) => fact.cause.code(),
            ExecutionOutcomeKindV0::DeterministicallyInvalid(fact) => fact.cause.code(),
            ExecutionOutcomeKindV0::InvariantFault(fact) => fact.cause.code(),
        }
    }

    pub(super) const fn reason(&self) -> &'static str {
        match &self.inner {
            ExecutionOutcomeKindV0::Valid { .. } => VALID_REASON,
            ExecutionOutcomeKindV0::Unavailable(fact) => fact.cause.reason(),
            ExecutionOutcomeKindV0::DeterministicallyInvalid(fact) => fact.cause.reason(),
            ExecutionOutcomeKindV0::InvariantFault(fact) => fact.cause.reason(),
        }
    }

    #[cfg(test)]
    fn unavailable_fact(&self) -> Option<&UnavailableV0> {
        match &self.inner {
            ExecutionOutcomeKindV0::Unavailable(fact) => Some(fact),
            _ => None,
        }
    }

    #[cfg(test)]
    fn invalid_fact(&self) -> Option<&DeterministicallyInvalidV0> {
        match &self.inner {
            ExecutionOutcomeKindV0::DeterministicallyInvalid(fact) => Some(fact),
            _ => None,
        }
    }

    #[cfg(test)]
    fn invariant_fault(&self) -> Option<&InvariantFaultV0> {
        match &self.inner {
            ExecutionOutcomeKindV0::InvariantFault(fact) => Some(fact),
            _ => None,
        }
    }
}

/// Seals an already-successful execution only after every computed committed
/// root matches the signed header. The match token owns the successful value,
/// so a caller cannot compare one execution and substitute another here.
fn valid_after_matching_roots_v0<SuccessfulExecution>(
    matched: ComputedRootsMatchHeaderV0<SuccessfulExecution>,
) -> ExecutionOutcomeV0<SuccessfulExecution> {
    ExecutionOutcomeV0 {
        inner: ExecutionOutcomeKindV0::Valid {
            generation: matched.inputs.generation(),
            successful_execution: matched.successful_execution,
        },
    }
}

/// Promotes the sole owning production comparator success into `Valid`.
///
/// The exact matched carrier owns the Core request, authenticated parent
/// configuration, complete body traversal, runtime receipts, and same-snapshot
/// post-state plan. No caller-supplied generation or second successful value is
/// accepted at this boundary.
pub(super) fn valid_from_core_authorized_regular_match_v0(
    matched: Box<MatchedCoreAuthorizedRegularRuntimeCommitmentsV0>,
) -> ExecutionOutcomeV0<Box<MatchedCoreAuthorizedRegularRuntimeCommitmentsV0>> {
    let generation = ValidationGenerationV0::new(matched.validation_generation_v0());
    ExecutionOutcomeV0 {
        inner: ExecutionOutcomeKindV0::Valid {
            generation,
            successful_execution: matched,
        },
    }
}

/// Produces the non-valid execution-outcome branch from an opaque failed
/// production comparator owner. The failure carrier remains borrowed here and
/// must stay retained by the caller alongside the returned policy outcome.
pub(super) fn failure_from_core_authorized_regular_comparison_v0(
    failed: &FailedCoreAuthorizedRegularRuntimeCommitmentComparisonV0,
) -> ExecutionOutcomeV0<()> {
    match failed.outcome_facts_v0() {
        CoreAuthorizedRegularFailureOutcomeFactsV0::DeterministicMismatch {
            generation,
            mismatch,
        } => {
            let mismatch = match mismatch {
                CoreAuthorizedRegularComputedRootMismatchV0::State => ComputedRootMismatchV0::State,
                CoreAuthorizedRegularComputedRootMismatchV0::Receipts => {
                    ComputedRootMismatchV0::Receipts
                }
            };
            ExecutionOutcomeV0 {
                inner: ExecutionOutcomeKindV0::DeterministicallyInvalid(
                    DeterministicallyInvalidV0 {
                        generation: ValidationGenerationV0::new(generation),
                        cause: DeterministicallyInvalidCauseV0::ComputedRootMismatch(mismatch),
                    },
                ),
            }
        }
        CoreAuthorizedRegularFailureOutcomeFactsV0::Invariant { generation } => {
            ExecutionOutcomeV0 {
                inner: ExecutionOutcomeKindV0::InvariantFault(InvariantFaultV0 {
                    generation: ValidationGenerationV0::new(generation),
                    cause: InvariantFaultCauseV0::NativeRegularCommitmentComparison,
                }),
            }
        }
    }
}

/// Promotes one snapshot-closed real runtime-attempt failure. Classification
/// comes only from the opaque runtime attempt token or typed authenticated
/// read failure retained by that owner; diagnostic text is never inspected.
pub(super) fn failure_from_core_authorized_regular_runtime_attempt_v0(
    failed: &ClosedFailedCoreAuthorizedRegularRuntimeAttemptV0,
) -> ExecutionOutcomeV0<()> {
    match failed.outcome_facts_v0() {
        CoreAuthorizedRegularRuntimeFailureOutcomeFactsV0::Unavailable { generation, kind } => {
            let cause = match kind {
                CoreAuthorizedRegularRuntimeUnavailableKindV0::RuntimeDependency => {
                    UnavailableCauseV0::RuntimeDependency
                }
                CoreAuthorizedRegularRuntimeUnavailableKindV0::Database => {
                    UnavailableCauseV0::Database
                }
                CoreAuthorizedRegularRuntimeUnavailableKindV0::StorageIo => {
                    UnavailableCauseV0::StorageIo
                }
                CoreAuthorizedRegularRuntimeUnavailableKindV0::ParentStateMissing => {
                    UnavailableCauseV0::ParentStateMissing
                }
                CoreAuthorizedRegularRuntimeUnavailableKindV0::ParentStateUnauthenticated => {
                    UnavailableCauseV0::ParentStateUnauthenticated
                }
            };
            ExecutionOutcomeV0 {
                inner: ExecutionOutcomeKindV0::Unavailable(UnavailableV0 {
                    generation: ValidationGenerationV0::new(generation),
                    cause,
                }),
            }
        }
        CoreAuthorizedRegularRuntimeFailureOutcomeFactsV0::DeterministicallyInvalid {
            generation,
            runtime_code,
            runtime_reason,
        } => ExecutionOutcomeV0 {
            inner: ExecutionOutcomeKindV0::DeterministicallyInvalid(DeterministicallyInvalidV0 {
                generation: ValidationGenerationV0::new(generation),
                cause: DeterministicallyInvalidCauseV0::RuntimeTransactionReject {
                    runtime_code,
                    runtime_reason,
                },
            }),
        },
        CoreAuthorizedRegularRuntimeFailureOutcomeFactsV0::Invariant {
            generation,
            runtime_detail,
        } => ExecutionOutcomeV0 {
            inner: ExecutionOutcomeKindV0::InvariantFault(InvariantFaultV0 {
                generation: ValidationGenerationV0::new(generation),
                cause: match runtime_detail {
                    Some((runtime_code, runtime_reason)) => InvariantFaultCauseV0::Runtime {
                        runtime_code,
                        runtime_reason,
                    },
                    None => InvariantFaultCauseV0::NativeRegularRuntimeAttempt,
                },
            }),
        },
    }
}

/// Shared data-free mapping for retryable source/dependency categories already
/// extracted from an owning native validation failure.
const fn native_regular_unavailable_cause_v0(
    kind: CoreAuthorizedRegularPreExecutionUnavailableKindV0,
) -> UnavailableCauseV0 {
    match kind {
        CoreAuthorizedRegularPreExecutionUnavailableKindV0::BodySource => {
            UnavailableCauseV0::BodyNonCanonical
        }
        CoreAuthorizedRegularPreExecutionUnavailableKindV0::ParentStateMissing => {
            UnavailableCauseV0::ParentStateMissing
        }
        CoreAuthorizedRegularPreExecutionUnavailableKindV0::ParentStateUnauthenticated => {
            UnavailableCauseV0::ParentStateUnauthenticated
        }
        CoreAuthorizedRegularPreExecutionUnavailableKindV0::Database => {
            UnavailableCauseV0::Database
        }
        CoreAuthorizedRegularPreExecutionUnavailableKindV0::StorageIo => {
            UnavailableCauseV0::StorageIo
        }
        CoreAuthorizedRegularPreExecutionUnavailableKindV0::HostResource => {
            UnavailableCauseV0::HostResource
        }
        CoreAuthorizedRegularPreExecutionUnavailableKindV0::ReservationCapacity => {
            UnavailableCauseV0::ReservationCapacity
        }
    }
}

const fn native_regular_non_runtime_unavailable_cause_v0(
    kind: CoreAuthorizedRegularNonRuntimeUnavailableKindV0,
) -> UnavailableCauseV0 {
    match kind {
        CoreAuthorizedRegularNonRuntimeUnavailableKindV0::ParentStateMissing => {
            UnavailableCauseV0::ParentStateMissing
        }
        CoreAuthorizedRegularNonRuntimeUnavailableKindV0::ParentStateUnauthenticated => {
            UnavailableCauseV0::ParentStateUnauthenticated
        }
        CoreAuthorizedRegularNonRuntimeUnavailableKindV0::Database => UnavailableCauseV0::Database,
        CoreAuthorizedRegularNonRuntimeUnavailableKindV0::StorageIo => {
            UnavailableCauseV0::StorageIo
        }
        CoreAuthorizedRegularNonRuntimeUnavailableKindV0::HostResource => {
            UnavailableCauseV0::HostResource
        }
    }
}

/// Maps one owner-derived pre-execution failure classification into the common
/// outcome kernel. Callers cannot supply a diagnostic string or detached
/// generation; the native adapter obtains these facts only from a complete
/// open/reservation/decode/post-state owner and retains that owner separately.
pub(super) fn failure_from_core_authorized_regular_pre_execution_v0(
    facts: CoreAuthorizedRegularPreExecutionFailureOutcomeFactsV0,
) -> ExecutionOutcomeV0<()> {
    match facts {
        CoreAuthorizedRegularPreExecutionFailureOutcomeFactsV0::Unavailable {
            generation,
            kind,
        } => ExecutionOutcomeV0 {
            inner: ExecutionOutcomeKindV0::Unavailable(UnavailableV0 {
                generation: ValidationGenerationV0::new(generation),
                cause: native_regular_unavailable_cause_v0(kind),
            }),
        },
        CoreAuthorizedRegularPreExecutionFailureOutcomeFactsV0::DeterministicallyInvalid {
            generation,
            kind,
        } => {
            let cause = match kind {
                CoreAuthorizedRegularPreExecutionInvalidKindV0::BodyEvidence => {
                    DeterministicallyInvalidCauseV0::NativeRegularBodyEvidence
                }
                CoreAuthorizedRegularPreExecutionInvalidKindV0::TransactionEncodingOrAuthorization => {
                    DeterministicallyInvalidCauseV0::NativeRegularTransactionEncodingOrAuthorization
                }
                CoreAuthorizedRegularPreExecutionInvalidKindV0::TransactionReplay => {
                    DeterministicallyInvalidCauseV0::NativeRegularTransactionReplay
                }
            };
            ExecutionOutcomeV0 {
                inner: ExecutionOutcomeKindV0::DeterministicallyInvalid(
                    DeterministicallyInvalidV0 {
                        generation: ValidationGenerationV0::new(generation),
                        cause,
                    },
                ),
            }
        }
        CoreAuthorizedRegularPreExecutionFailureOutcomeFactsV0::Invariant { generation, stage } => {
            ExecutionOutcomeV0 {
                inner: ExecutionOutcomeKindV0::InvariantFault(InvariantFaultV0 {
                    generation: ValidationGenerationV0::new(generation),
                    cause: InvariantFaultCauseV0::NativeRegularPreExecution(stage),
                }),
            }
        }
    }
}

/// Maps only facts extracted from a complete snapshot-closed non-runtime
/// semantic or family owner. The exact typed reason becomes a stable app-
/// private code without inspecting diagnostics, while retryable source loss
/// remains non-terminal and every invariant remains fail-stop.
pub(super) fn failure_from_core_authorized_regular_non_runtime_v0(
    facts: CoreAuthorizedRegularNonRuntimeFailureOutcomeFactsV0,
) -> ExecutionOutcomeV0<()> {
    match facts.into_view_v0() {
        CoreAuthorizedRegularNonRuntimeFailureOutcomeViewV0::Unavailable { generation, kind } => {
            ExecutionOutcomeV0 {
                inner: ExecutionOutcomeKindV0::Unavailable(UnavailableV0 {
                    generation: ValidationGenerationV0::new(generation),
                    cause: native_regular_non_runtime_unavailable_cause_v0(kind),
                }),
            }
        }
        CoreAuthorizedRegularNonRuntimeFailureOutcomeViewV0::DeterministicallyInvalid {
            generation,
            reason,
        } => ExecutionOutcomeV0 {
            inner: ExecutionOutcomeKindV0::DeterministicallyInvalid(DeterministicallyInvalidV0 {
                generation: ValidationGenerationV0::new(generation),
                cause: DeterministicallyInvalidCauseV0::NativeRegularNonRuntime(reason),
            }),
        },
        CoreAuthorizedRegularNonRuntimeFailureOutcomeViewV0::Invariant { generation, reason } => {
            ExecutionOutcomeV0 {
                inner: ExecutionOutcomeKindV0::InvariantFault(InvariantFaultV0 {
                    generation: ValidationGenerationV0::new(generation),
                    cause: InvariantFaultCauseV0::NativeRegularNonRuntime(reason),
                }),
            }
        }
    }
}

/// Converts an untyped host/dependency failure into a retryable result.
///
/// `_diagnostic` is deliberately non-authoritative and never inspected. This
/// prevents error-message text such as "root mismatch" or "invalid" from
/// manufacturing a terminal fact.
pub(super) fn unavailable_from_host_failure_v0<SuccessfulExecution>(
    generation: ValidationGenerationV0,
    cause: UnavailableCauseV0,
    _diagnostic: &dyn Display,
) -> ExecutionOutcomeV0<SuccessfulExecution> {
    ExecutionOutcomeV0 {
        inner: ExecutionOutcomeKindV0::Unavailable(UnavailableV0 { generation, cause }),
    }
}

/// Promotes a failure from one real runtime attempt only after the complete
/// authenticated execution context has been established.
///
/// A typed state dependency failure is returned unchanged and remains
/// retryable. Only the opaque attempt's deterministic branch can become a
/// whole-block rejection or fail-stop invariant; a standalone `RuntimeError`
/// is not accepted by this API.
fn promote_authenticated_runtime_failure_v0<SuccessfulExecution, StateError>(
    planning_failure: RuntimePlanningFailureV0<StateError>,
) -> Result<ExecutionOutcomeV0<SuccessfulExecution>, RuntimePlanningFailureV0<StateError>> {
    let Some(failure) = planning_failure.attempt.deterministic_failure_v0() else {
        return Err(planning_failure);
    };

    let generation = planning_failure.inputs.generation();

    Ok(match failure.disposition() {
        DeterministicRuntimeFailureDispositionV0::TransactionReject => ExecutionOutcomeV0 {
            inner: ExecutionOutcomeKindV0::DeterministicallyInvalid(DeterministicallyInvalidV0 {
                generation,
                cause: DeterministicallyInvalidCauseV0::RuntimeTransactionReject {
                    runtime_code: failure.code(),
                    runtime_reason: failure.reason(),
                },
            }),
        },
        DeterministicRuntimeFailureDispositionV0::InvariantFault => ExecutionOutcomeV0 {
            inner: ExecutionOutcomeKindV0::InvariantFault(InvariantFaultV0 {
                generation,
                cause: InvariantFaultCauseV0::Runtime {
                    runtime_code: failure.code(),
                    runtime_reason: failure.reason(),
                },
            }),
        },
    })
}

/// Classifies an execution-computed root mismatch. Requiring the opaque input
/// token prevents a source body/root mismatch or missing parent from reaching
/// this terminal path.
fn classify_computed_root_mismatch_v0<SuccessfulExecution>(
    inputs: AuthenticatedExecutionInputsV0,
    mismatch: ComputedRootMismatchV0,
) -> ExecutionOutcomeV0<SuccessfulExecution> {
    ExecutionOutcomeV0 {
        inner: ExecutionOutcomeKindV0::DeterministicallyInvalid(DeterministicallyInvalidV0 {
            generation: inputs.generation(),
            cause: DeterministicallyInvalidCauseV0::ComputedRootMismatch(mismatch),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use trnm_protocol::{account_key, CanonicalCommandV1, CANONICAL_TX_SCHEMA_V1};
    use trnm_runtime::StateObject;

    #[derive(Debug, PartialEq, Eq)]
    struct SealedSuccessfulExecutionForTest {
        receipt_indices: Vec<u32>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum InjectedStateReadFailure {
        DependencyUnavailable,
    }

    #[derive(Default)]
    struct TestStateView {
        objects: BTreeMap<String, StateObject>,
        fail_key: Option<String>,
    }

    impl TryStateViewV0 for TestStateView {
        type Error = InjectedStateReadFailure;

        fn try_get(&self, object_key_hex: &str) -> Result<Option<StateObject>, Self::Error> {
            if self.fail_key.as_deref() == Some(object_key_hex) {
                return Err(InjectedStateReadFailure::DependencyUnavailable);
            }
            Ok(self.objects.get(object_key_hex).cloned())
        }
    }

    fn operator_credit_tx(max_gas: u64) -> CanonicalTxV1 {
        CanonicalTxV1 {
            schema: CANONICAL_TX_SCHEMA_V1.to_string(),
            sender: "operator".to_string(),
            nonce: 1,
            max_gas,
            fee_limit: u128::MAX,
            command: CanonicalCommandV1::CreditAccount {
                account: "alice".to_string(),
                amount: 100,
            },
        }
    }

    fn execution_context(tx: &CanonicalTxV1) -> ExecutionContext<'_> {
        ExecutionContext {
            height: 1,
            signer_id: &tx.sender,
            signer_role: "operator",
            payload_len: serde_json::to_vec(tx)
                .expect("canonical test transaction serializes")
                .len(),
        }
    }

    fn authenticated_inputs(generation: u64) -> AuthenticatedExecutionInputsV0 {
        let generation = ValidationGenerationV0::new(generation);
        join_authenticated_execution_inputs_v0(
            CanonicalBodyMatchesHeaderV0 { generation },
            AuthenticatedParentStateV0 { generation },
            AuthorizedRuntimeContextV0 { generation },
        )
        .expect("same-generation authenticated facts join")
    }

    fn matched_execution<SuccessfulExecution>(
        inputs: AuthenticatedExecutionInputsV0,
        successful_execution: SuccessfulExecution,
    ) -> ComputedRootsMatchHeaderV0<SuccessfulExecution> {
        ComputedRootsMatchHeaderV0 {
            inputs,
            successful_execution,
        }
    }

    #[test]
    fn real_transaction_reject_needs_authenticated_inputs_before_terminal_promotion() {
        let tx = operator_credit_tx(1);
        let planning_failure = attempt_runtime_transaction_v0(
            authenticated_inputs(1),
            &tx,
            execution_context(&tx),
            &TestStateView::default(),
        )
        .expect_err("real low-gas execution attempt must reject");
        assert!(planning_failure.state_unavailable().is_none());

        let outcome: ExecutionOutcomeV0<AppliedRuntimeAttemptV0> =
            promote_authenticated_runtime_failure_v0(planning_failure)
                .expect("deterministic attempt promotes only after authenticated inputs");
        assert_eq!(outcome.code(), "runtime_transaction_reject");
        assert_eq!(
            outcome.terminal_disposition(),
            Some(TerminalExecutionDispositionV0::DeterministicallyInvalid)
        );
        assert!(outcome.successful_execution().is_none());
        let fact = outcome
            .invalid_fact()
            .expect("runtime transaction reject must be terminally invalid");
        assert_eq!(fact.scope(), InvalidExecutionScopeV0::WholeBlockNoReceipt);
        let detail = fact.runtime_detail().expect("runtime detail preserved");
        assert_eq!(detail.code(), "gas_limit_exceeded");
        assert_eq!(detail.reason(), "transaction gas limit exceeded");
    }

    #[test]
    fn real_authenticated_state_invariant_requires_fail_stop() {
        let tx = operator_credit_tx(100_000);
        let mut view = TestStateView::default();
        view.objects.insert(
            account_key("operator"),
            StateObject {
                object_type: "trnm.foreign-object.v1".to_string(),
                version: 1,
                value_bytes: Vec::new(),
            },
        );

        let planning_failure = attempt_runtime_transaction_v0(
            authenticated_inputs(2),
            &tx,
            execution_context(&tx),
            &view,
        )
        .expect_err("wrong authenticated object type must fail deterministically");
        let outcome: ExecutionOutcomeV0<AppliedRuntimeAttemptV0> =
            promote_authenticated_runtime_failure_v0(planning_failure)
                .expect("deterministic invariant is not a retryable state read failure");
        assert_eq!(outcome.code(), "runtime_invariant_fault");
        assert_eq!(outcome.terminal_disposition(), None);
        let fact = outcome
            .invariant_fault()
            .expect("authenticated state corruption must fail stop");
        assert!(fact.requires_fail_stop());
        let detail = fact.runtime_detail().expect("runtime detail preserved");
        assert_eq!(detail.code(), "object_type_mismatch");
        assert_eq!(detail.reason(), "authenticated state object type mismatch");
    }

    #[test]
    fn typed_state_read_failure_stays_retryable_and_never_promotes() {
        let tx = operator_credit_tx(100_000);
        let view = TestStateView {
            objects: BTreeMap::new(),
            fail_key: Some(account_key("operator")),
        };
        let planning_failure = attempt_runtime_transaction_v0(
            authenticated_inputs(3),
            &tx,
            execution_context(&tx),
            &view,
        )
        .expect_err("failed authenticated read must stay typed and retryable");
        assert_eq!(planning_failure.generation().get(), 3);
        assert_eq!(
            planning_failure.state_unavailable(),
            Some(&InjectedStateReadFailure::DependencyUnavailable)
        );

        let still_retryable =
            promote_authenticated_runtime_failure_v0::<AppliedRuntimeAttemptV0, _>(
                planning_failure,
            )
            .expect_err("state dependency loss must not become a terminal outcome");
        assert_eq!(
            still_retryable.state_unavailable(),
            Some(&InjectedStateReadFailure::DependencyUnavailable)
        );
    }

    #[test]
    fn successful_runtime_attempt_is_applied_but_not_valid_before_root_match() {
        let tx = operator_credit_tx(100_000);
        let applied = attempt_runtime_transaction_v0(
            authenticated_inputs(4),
            &tx,
            execution_context(&tx),
            &TestStateView::default(),
        )
        .expect("valid operator credit produces a success-only runtime receipt");
        assert_eq!(applied.generation().get(), 4);
        assert!(!applied.receipt().mutations.is_empty());

        let AppliedRuntimeAttemptV0 { inputs, receipt } = applied;
        let valid = valid_after_matching_roots_v0(matched_execution(inputs, receipt));
        assert_eq!(
            valid.terminal_disposition(),
            Some(TerminalExecutionDispositionV0::Valid)
        );
        assert!(valid.successful_execution().is_some());
    }

    #[test]
    fn only_valid_can_carry_successful_receipt_artifacts() {
        let valid = valid_after_matching_roots_v0(matched_execution(
            authenticated_inputs(7),
            SealedSuccessfulExecutionForTest {
                receipt_indices: vec![0, 1],
            },
        ));
        assert_eq!(valid.code(), VALID_CODE);
        assert_eq!(valid.reason(), VALID_REASON);
        assert_eq!(
            valid.terminal_disposition(),
            Some(TerminalExecutionDispositionV0::Valid)
        );
        assert_eq!(
            valid
                .successful_execution()
                .expect("valid execution carries success-only artifacts")
                .receipt_indices,
            vec![0, 1]
        );

        let tx = operator_credit_tx(1);
        let planning_failure = attempt_runtime_transaction_v0(
            authenticated_inputs(8),
            &tx,
            execution_context(&tx),
            &TestStateView::default(),
        )
        .expect_err("low gas must fail before a receipt exists");
        let invalid: ExecutionOutcomeV0<SealedSuccessfulExecutionForTest> =
            promote_authenticated_runtime_failure_v0(planning_failure)
                .expect("real deterministic attempt promotes");
        assert!(invalid.successful_execution().is_none());
    }

    #[test]
    fn root_mismatch_is_terminal_only_after_authenticated_inputs_join() {
        let source_mismatch: ExecutionOutcomeV0<SealedSuccessfulExecutionForTest> =
            unavailable_from_host_failure_v0(
                ValidationGenerationV0::new(11),
                UnavailableCauseV0::SourcePayloadRootMismatch,
                &"computed state root mismatch: deterministically invalid",
            );
        assert_eq!(source_mismatch.code(), "source_payload_root_mismatch");
        assert_eq!(source_mismatch.terminal_disposition(), None);

        let expected = [
            (
                ComputedRootMismatchV0::State,
                "computed_state_root_mismatch",
            ),
            (
                ComputedRootMismatchV0::Receipts,
                "computed_receipts_root_mismatch",
            ),
            (
                ComputedRootMismatchV0::Evidence,
                "computed_evidence_root_mismatch",
            ),
        ];
        for (mismatch, code) in expected {
            let outcome: ExecutionOutcomeV0<SealedSuccessfulExecutionForTest> =
                classify_computed_root_mismatch_v0(authenticated_inputs(12), mismatch);
            assert_eq!(outcome.code(), code);
            assert_eq!(
                outcome.terminal_disposition(),
                Some(TerminalExecutionDispositionV0::DeterministicallyInvalid)
            );
            assert!(outcome.successful_execution().is_none());
        }

        let generation = ValidationGenerationV0::new(13);
        let fault = join_authenticated_execution_inputs_v0(
            CanonicalBodyMatchesHeaderV0 { generation },
            AuthenticatedParentStateV0 {
                generation: ValidationGenerationV0::new(14),
            },
            AuthorizedRuntimeContextV0 { generation },
        )
        .expect_err("cross-generation facts cannot mint authenticated inputs");
        assert_eq!(fault.code(), "authenticated_input_generation_mismatch");
        assert_eq!(
            fault.reason(),
            "authenticated execution inputs belong to different request generations"
        );
        assert!(fault.requires_fail_stop());
    }

    #[test]
    fn every_unavailable_cause_is_nonterminal_and_ignores_diagnostic_words() {
        let causes = [
            UnavailableCauseV0::BodyMissing,
            UnavailableCauseV0::BodyIncomplete,
            UnavailableCauseV0::BodyNonCanonical,
            UnavailableCauseV0::SourcePayloadRootMismatch,
            UnavailableCauseV0::ParentStateMissing,
            UnavailableCauseV0::ParentStateUnauthenticated,
            UnavailableCauseV0::CutoffStateMissing,
            UnavailableCauseV0::CutoffStateUnauthenticated,
            UnavailableCauseV0::RuntimeDependency,
            UnavailableCauseV0::Database,
            UnavailableCauseV0::StorageIo,
        ];

        for cause in causes {
            let outcome: ExecutionOutcomeV0<SealedSuccessfulExecutionForTest> =
                unavailable_from_host_failure_v0(
                    ValidationGenerationV0::new(21),
                    cause,
                    &"DETERMINISTIC INVALID: receipts root mismatch; reject",
                );
            assert_eq!(outcome.terminal_disposition(), None);
            assert!(outcome.successful_execution().is_none());
            let fact = outcome
                .unavailable_fact()
                .expect("host dependency failure must stay unavailable");
            assert_eq!(fact.cause(), cause);
        }
    }

    #[test]
    fn unavailable_generation_can_retry_to_a_later_terminal_result() {
        let unavailable: ExecutionOutcomeV0<SealedSuccessfulExecutionForTest> =
            unavailable_from_host_failure_v0(
                ValidationGenerationV0::new(31),
                UnavailableCauseV0::CutoffStateMissing,
                &"cutoff pruned locally",
            );
        assert_eq!(unavailable.generation().get(), 31);
        assert_eq!(unavailable.terminal_disposition(), None);

        let retried = valid_after_matching_roots_v0(matched_execution(
            authenticated_inputs(32),
            SealedSuccessfulExecutionForTest {
                receipt_indices: vec![0],
            },
        ));
        assert_eq!(retried.generation().get(), 32);
        assert_eq!(
            retried.terminal_disposition(),
            Some(TerminalExecutionDispositionV0::Valid)
        );
    }
}
