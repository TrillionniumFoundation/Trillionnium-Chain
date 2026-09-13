//! Default-built, private fail-closed owner scaffold for one native application
//! boundary.
//!
//! This slice deliberately exposes neither the owned application nor a generic
//! call-through. Its test seam serializes execution and mints a non-cloneable
//! capability for one exact valid result, but commit additionally consumes a
//! separate private finality permit. Production can construct neither the raw
//! owner nor that permit. Any application error or result-substitution attempt
//! permanently fail-stops the owner because the application may already have
//! changed hidden state.
//!
//! This is not a Proposal validation journal or authority to commit before
//! finality. Core, SafetyStore, whole-node checkpointing, finality, recovery,
//! and the process host are not wired to this owner. The owner and its linear
//! values are not re-exported, its raw constructor exists only in tests, and a
//! commit additionally requires a private finality permit for which production
//! has no constructor. Commit uncertainty therefore has no restart recovery in
//! this slice: an in-process application error fail-stops, while durable
//! recovery remains an explicit future integration. This development boundary
//! does not change any production/activation truth.

use std::{error::Error, fmt};

#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};

use trnm_native_application::{
    ApplicationHeadV0, BlockIdV0, ChainIdV0, GenesisHashV0, Hash32V0, HeightV0,
    NativeApplicationCommitRequestV0, NativeApplicationCommitResultV0, NativeApplicationV0,
    NativeBlockExecutionRequestV0, NativeBlockExecutionResultV0, NativeDeterministicInvalidV0,
    NativeExecutedBlockV0, NativeUnavailableReasonV0,
};

#[cfg(test)]
static NEXT_NATIVE_APPLICATION_OWNER_ID_V0: AtomicU64 = AtomicU64::new(1);

/// Lifecycle visible without exposing the application or a pending commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PocoNodeNativeApplicationOwnerStatusV0 {
    Ready,
    CommitPending,
    FailStopped,
}

/// A valid execution capability minted only after exact result validation.
///
/// The value is intentionally non-cloneable and its fields are private. It can
/// only be consumed by its originating owner.
#[derive(Debug)]
pub(crate) struct PocoNodeNativePreparedCommitV0 {
    owner_id: u64,
    owner_nonce: u64,
    block_id: BlockIdV0,
    height: HeightV0,
    executed: NativeExecutedBlockV0,
}

/// Process-local proof that a future finality owner authorized exactly one
/// prepared block for committed-head advancement.
///
/// This type is private, non-cloneable, and has no production constructor. The
/// revision and checksum fields reserve the exact binding that a later
/// Core/QC/finality integration must authenticate; they are not synthesized by
/// this scaffold.
#[derive(Debug)]
struct PocoNodeNativeFinalityPermitV0 {
    owner_id: u64,
    owner_nonce: u64,
    exact_request: NativeBlockExecutionRequestV0,
    source_head: ApplicationHeadV0,
    expected_committed_head: ApplicationHeadV0,
    finality_revision: u64,
    finality_record_checksum: Hash32V0,
}

impl PocoNodeNativePreparedCommitV0 {
    pub(crate) const fn block_id(&self) -> BlockIdV0 {
        self.block_id
    }

    pub(crate) const fn height(&self) -> HeightV0 {
        self.height
    }
}

#[derive(Debug)]
pub(crate) enum PocoNodeNativeExecutionOutcomeV0 {
    Prepared(Box<PocoNodeNativePreparedCommitV0>),
    DeterministicallyInvalid(Box<NativeDeterministicInvalidV0>),
    Unavailable(NativeUnavailableReasonV0),
}

/// Non-cloneable owner of one native application implementation.
pub(crate) struct PocoNodeNativeApplicationOwnerV0<A> {
    application: A,
    owner_id: u64,
    chain_id: ChainIdV0,
    genesis_hash: GenesisHashV0,
    head: ApplicationHeadV0,
    next_durable_sequence: u64,
    next_owner_nonce: u64,
    pending: Option<(u64, BlockIdV0, HeightV0)>,
    fail_stopped: bool,
}

impl<A: NativeApplicationV0> PocoNodeNativeApplicationOwnerV0<A> {
    /// Test-only raw construction. Production must eventually construct this
    /// owner from a fresh authenticated recovery attestation, which is not yet
    /// implemented.
    #[cfg(test)]
    fn new_for_test_v0(
        application: A,
        chain_id: ChainIdV0,
        genesis_hash: GenesisHashV0,
        authenticated_head: ApplicationHeadV0,
        next_durable_sequence: u64,
    ) -> Result<Self, PocoNodeNativeApplicationOwnerErrorV0<A::Error>> {
        if next_durable_sequence == 0 {
            return Err(PocoNodeNativeApplicationOwnerErrorV0::ZeroDurableSequence);
        }
        let owner_id = NEXT_NATIVE_APPLICATION_OWNER_ID_V0
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| PocoNodeNativeApplicationOwnerErrorV0::OwnerIdentityExhausted)?;
        Ok(Self {
            application,
            owner_id,
            chain_id,
            genesis_hash,
            head: authenticated_head,
            next_durable_sequence,
            next_owner_nonce: 1,
            pending: None,
            fail_stopped: false,
        })
    }

    pub(crate) const fn status(&self) -> PocoNodeNativeApplicationOwnerStatusV0 {
        if self.fail_stopped {
            PocoNodeNativeApplicationOwnerStatusV0::FailStopped
        } else if self.pending.is_some() {
            PocoNodeNativeApplicationOwnerStatusV0::CommitPending
        } else {
            PocoNodeNativeApplicationOwnerStatusV0::Ready
        }
    }

    pub(crate) const fn authenticated_head(&self) -> &ApplicationHeadV0 {
        &self.head
    }

    pub(crate) const fn next_durable_sequence(&self) -> u64 {
        self.next_durable_sequence
    }

    pub(crate) fn execute_block_v0(
        &mut self,
        request: NativeBlockExecutionRequestV0,
    ) -> Result<PocoNodeNativeExecutionOutcomeV0, PocoNodeNativeApplicationOwnerErrorV0<A::Error>>
    {
        self.require_ready_v0()?;
        if request.chain_id() != &self.chain_id
            || request.genesis_hash() != self.genesis_hash
            || request.parent() != &self.head
        {
            return Err(PocoNodeNativeApplicationOwnerErrorV0::RequestBindingMismatch);
        }
        let expected_block_id = request.block_id();
        let expected_height = request.height();
        let exact_request = request.clone();
        let result = match self.application.execute_block(request) {
            Ok(result) => result,
            Err(error) => {
                self.fail_stopped = true;
                return Err(PocoNodeNativeApplicationOwnerErrorV0::Application(error));
            }
        };
        match result {
            NativeBlockExecutionResultV0::Valid(executed) => {
                if executed.request() != &exact_request {
                    self.fail_stopped = true;
                    return Err(PocoNodeNativeApplicationOwnerErrorV0::ResultBindingMismatch);
                }
                let owner_nonce = self.next_owner_nonce;
                self.next_owner_nonce = match self.next_owner_nonce.checked_add(1) {
                    Some(next) => next,
                    None => {
                        self.fail_stopped = true;
                        return Err(PocoNodeNativeApplicationOwnerErrorV0::OwnerNonceExhausted);
                    }
                };
                self.pending = Some((owner_nonce, expected_block_id, expected_height));
                Ok(PocoNodeNativeExecutionOutcomeV0::Prepared(Box::new(
                    PocoNodeNativePreparedCommitV0 {
                        owner_id: self.owner_id,
                        owner_nonce,
                        block_id: expected_block_id,
                        height: expected_height,
                        executed: *executed,
                    },
                )))
            }
            NativeBlockExecutionResultV0::DeterministicallyInvalid(invalid) => {
                if invalid.request() != &exact_request {
                    self.fail_stopped = true;
                    return Err(PocoNodeNativeApplicationOwnerErrorV0::ResultBindingMismatch);
                }
                // Until an implementation returns a durable attestation that
                // execution left every hidden overlay/journal byte unchanged,
                // even an exact negative result cannot make this owner reusable.
                self.fail_stopped = true;
                Ok(PocoNodeNativeExecutionOutcomeV0::DeterministicallyInvalid(
                    Box::new(invalid),
                ))
            }
            NativeBlockExecutionResultV0::Unavailable(unavailable) => {
                if unavailable.request() != &exact_request {
                    self.fail_stopped = true;
                    return Err(PocoNodeNativeApplicationOwnerErrorV0::ResultBindingMismatch);
                }
                // Host unavailability may likewise follow partial hidden-state
                // mutation. Reuse requires a future durable unchanged proof.
                self.fail_stopped = true;
                Ok(PocoNodeNativeExecutionOutcomeV0::Unavailable(
                    unavailable.reason(),
                ))
            }
        }
    }

    /// Test-only seam that models the exact fields a future authenticated
    /// finality owner must bind. It is intentionally unavailable in production.
    #[cfg(test)]
    fn finality_permit_for_test_v0(
        &self,
        prepared: &PocoNodeNativePreparedCommitV0,
        expected_committed_head: ApplicationHeadV0,
        finality_revision: u64,
        finality_record_checksum: Hash32V0,
    ) -> Result<PocoNodeNativeFinalityPermitV0, PocoNodeNativeApplicationOwnerErrorV0<A::Error>>
    {
        if self.fail_stopped {
            return Err(PocoNodeNativeApplicationOwnerErrorV0::FailStopped);
        }
        if prepared.owner_id != self.owner_id
            || self.pending != Some((prepared.owner_nonce, prepared.block_id, prepared.height))
            || prepared.executed.request().parent() != &self.head
            || expected_committed_head.height() != prepared.height
            || expected_committed_head.block_id() != prepared.block_id
            || expected_committed_head.state_root()
                != prepared.executed.request().expected().post_state_root()
        {
            return Err(PocoNodeNativeApplicationOwnerErrorV0::FinalityPermitMismatch);
        }
        if finality_revision == 0 {
            return Err(PocoNodeNativeApplicationOwnerErrorV0::ZeroFinalityRevision);
        }
        if finality_record_checksum.is_zero() {
            return Err(PocoNodeNativeApplicationOwnerErrorV0::ZeroFinalityRecordChecksum);
        }
        Ok(PocoNodeNativeFinalityPermitV0 {
            owner_id: self.owner_id,
            owner_nonce: prepared.owner_nonce,
            exact_request: prepared.executed.request().clone(),
            source_head: self.head.clone(),
            expected_committed_head,
            finality_revision,
            finality_record_checksum,
        })
    }

    fn commit_block_v0(
        &mut self,
        prepared: Box<PocoNodeNativePreparedCommitV0>,
        finality_permit: PocoNodeNativeFinalityPermitV0,
    ) -> Result<NativeApplicationCommitResultV0, PocoNodeNativeApplicationOwnerErrorV0<A::Error>>
    {
        let prepared = *prepared;
        if self.fail_stopped {
            return Err(PocoNodeNativeApplicationOwnerErrorV0::FailStopped);
        }
        if prepared.owner_id != self.owner_id
            || self.pending != Some((prepared.owner_nonce, prepared.block_id, prepared.height))
        {
            return Err(PocoNodeNativeApplicationOwnerErrorV0::PreparedCommitMismatch);
        }
        if finality_permit.owner_id != self.owner_id
            || finality_permit.owner_nonce != prepared.owner_nonce
            || &finality_permit.exact_request != prepared.executed.request()
            || finality_permit.source_head != self.head
            || &finality_permit.source_head != prepared.executed.request().parent()
            || finality_permit.expected_committed_head.height() != prepared.height
            || finality_permit.expected_committed_head.block_id() != prepared.block_id
            || finality_permit.expected_committed_head.state_root()
                != prepared.executed.request().expected().post_state_root()
            || finality_permit.finality_revision == 0
            || finality_permit.finality_record_checksum.is_zero()
        {
            return Err(PocoNodeNativeApplicationOwnerErrorV0::FinalityPermitMismatch);
        }
        let request = NativeApplicationCommitRequestV0::new(prepared.executed);
        let exact_request = request.clone();
        let result = match self.application.commit_block(request) {
            Ok(result) => result,
            Err(error) => {
                self.fail_stopped = true;
                return Err(PocoNodeNativeApplicationOwnerErrorV0::Application(error));
            }
        };
        if result.request() != &exact_request
            || result.head() != &finality_permit.expected_committed_head
            || result.durable_sequence() != self.next_durable_sequence
        {
            self.fail_stopped = true;
            return Err(PocoNodeNativeApplicationOwnerErrorV0::CommitBindingMismatch);
        }
        self.next_durable_sequence = match self.next_durable_sequence.checked_add(1) {
            Some(next) => next,
            None => {
                self.fail_stopped = true;
                return Err(PocoNodeNativeApplicationOwnerErrorV0::DurableSequenceExhausted);
            }
        };
        self.head = result.head().clone();
        self.pending = None;
        Ok(result)
    }

    fn require_ready_v0(&self) -> Result<(), PocoNodeNativeApplicationOwnerErrorV0<A::Error>> {
        if self.fail_stopped {
            Err(PocoNodeNativeApplicationOwnerErrorV0::FailStopped)
        } else if self.pending.is_some() {
            Err(PocoNodeNativeApplicationOwnerErrorV0::CommitPending)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
pub(crate) enum PocoNodeNativeApplicationOwnerErrorV0<E> {
    ZeroDurableSequence,
    RequestBindingMismatch,
    ResultBindingMismatch,
    CommitPending,
    PreparedCommitMismatch,
    FinalityPermitMismatch,
    ZeroFinalityRevision,
    ZeroFinalityRecordChecksum,
    CommitBindingMismatch,
    OwnerIdentityExhausted,
    OwnerNonceExhausted,
    DurableSequenceExhausted,
    FailStopped,
    Application(E),
}

impl<E: fmt::Display> fmt::Display for PocoNodeNativeApplicationOwnerErrorV0<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroDurableSequence => {
                formatter.write_str("native application durable sequence must be nonzero")
            }
            Self::RequestBindingMismatch => formatter.write_str(
                "native execution request differs from the owner's authenticated chain or head",
            ),
            Self::ResultBindingMismatch => formatter
                .write_str("native execution result differs from the exact submitted request"),
            Self::CommitPending => {
                formatter.write_str("one native application commit is already pending")
            }
            Self::PreparedCommitMismatch => formatter.write_str(
                "native prepared commit was not minted for the owner's pending execution",
            ),
            Self::FinalityPermitMismatch => formatter.write_str(
                "native finality permit does not bind the exact owner, request, or committed head",
            ),
            Self::ZeroFinalityRevision => {
                formatter.write_str("native finality revision must be nonzero")
            }
            Self::ZeroFinalityRecordChecksum => {
                formatter.write_str("native finality record checksum must be nonzero")
            }
            Self::CommitBindingMismatch => formatter.write_str(
                "native commit result differs from the pending block or durable sequence",
            ),
            Self::OwnerIdentityExhausted => {
                formatter.write_str("native application owner identity space exhausted")
            }
            Self::OwnerNonceExhausted => {
                formatter.write_str("native application owner nonce exhausted")
            }
            Self::DurableSequenceExhausted => {
                formatter.write_str("native application durable sequence exhausted")
            }
            Self::FailStopped => formatter.write_str("native application owner is fail-stopped"),
            Self::Application(error) => {
                write!(formatter, "native application call failed: {error}")
            }
        }
    }
}

impl<E: Error + 'static> Error for PocoNodeNativeApplicationOwnerErrorV0<E> {}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::VecDeque};

    use trnm_native_application::{
        ApplicationCommitIdV0, Hash32V0, NativeApplicationGenesisRequestV0,
        NativeApplicationGenesisResultV0, NativeApplicationRecoveryRequestV0,
        NativeApplicationRecoveryResultV0, NativeExecutionReceiptV0,
        NativeExpectedBlockCommitmentsV0, NativeSnapshotManifestV0, NativeSnapshotRequestV0,
        NativeStateProofRequestV0, NativeStateProofV0, ReceiptsRootV0, StateRootV0,
        ValidatorSetIdV0,
    };

    use super::*;

    fn hash(byte: u8) -> Hash32V0 {
        Hash32V0::new([byte; 32])
    }

    fn block_id(byte: u8) -> BlockIdV0 {
        BlockIdV0::new([byte; 32]).expect("nonzero block")
    }

    fn state_root(byte: u8) -> StateRootV0 {
        StateRootV0::new([byte; 32]).expect("nonzero state root")
    }

    fn commit_id(byte: u8) -> ApplicationCommitIdV0 {
        ApplicationCommitIdV0::new([byte; 32]).expect("nonzero commit")
    }

    fn chain_id() -> ChainIdV0 {
        ChainIdV0::new("trnm-native-owner-test").expect("canonical chain")
    }

    fn genesis_hash() -> GenesisHashV0 {
        GenesisHashV0::new([4; 32]).expect("nonzero genesis")
    }

    fn head() -> ApplicationHeadV0 {
        ApplicationHeadV0::new(HeightV0::GENESIS, block_id(1), state_root(2), commit_id(3))
    }

    fn request(block: u8) -> NativeBlockExecutionRequestV0 {
        request_at(block, 7)
    }

    fn request_at(block: u8, timestamp_ms: u64) -> NativeBlockExecutionRequestV0 {
        request_with_payload_root(block, timestamp_ms, 6)
    }

    fn request_with_payload_root(
        block: u8,
        timestamp_ms: u64,
        payload_root: u8,
    ) -> NativeBlockExecutionRequestV0 {
        NativeBlockExecutionRequestV0::new(
            chain_id(),
            genesis_hash(),
            head(),
            block_id(block),
            HeightV0::new(1),
            timestamp_ms,
            ValidatorSetIdV0::new([5; 32]).expect("nonzero set"),
            Vec::new(),
            NativeExpectedBlockCommitmentsV0::new(
                hash(payload_root),
                state_root(7),
                ReceiptsRootV0::new([8; 32]).expect("nonzero receipts"),
                hash(9),
            )
            .expect("commitments"),
        )
        .expect("execution request")
    }

    fn executed(request: NativeBlockExecutionRequestV0) -> NativeExecutedBlockV0 {
        let expected = request.expected();
        NativeExecutedBlockV0::new(
            request,
            expected.payload_root(),
            expected.post_state_root(),
            expected.receipts_root(),
            expected.evidence_root(),
            Vec::<NativeExecutionReceiptV0>::new(),
        )
        .expect("exact executed block")
    }

    struct MockApplication {
        execution_results: RefCell<VecDeque<NativeBlockExecutionResultV0>>,
        commit_results: RefCell<VecDeque<NativeApplicationCommitResultV0>>,
        execute_error: bool,
        commit_error: bool,
    }

    impl MockApplication {
        fn new(
            execution_results: Vec<NativeBlockExecutionResultV0>,
            commit_results: Vec<NativeApplicationCommitResultV0>,
        ) -> Self {
            Self {
                execution_results: RefCell::new(execution_results.into()),
                commit_results: RefCell::new(commit_results.into()),
                execute_error: false,
                commit_error: false,
            }
        }

        fn failing_execute() -> Self {
            Self {
                execution_results: RefCell::new(VecDeque::new()),
                commit_results: RefCell::new(VecDeque::new()),
                execute_error: true,
                commit_error: false,
            }
        }

        fn failing_commit(execution_result: NativeBlockExecutionResultV0) -> Self {
            Self {
                execution_results: RefCell::new(vec![execution_result].into()),
                commit_results: RefCell::new(VecDeque::new()),
                execute_error: false,
                commit_error: true,
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct MockError;

    impl fmt::Display for MockError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("injected native application failure")
        }
    }

    impl Error for MockError {}

    impl NativeApplicationV0 for MockApplication {
        type Error = MockError;

        fn initialize(
            &self,
            _: NativeApplicationGenesisRequestV0,
        ) -> Result<NativeApplicationGenesisResultV0, Self::Error> {
            unreachable!()
        }

        fn execute_block(
            &self,
            _: NativeBlockExecutionRequestV0,
        ) -> Result<NativeBlockExecutionResultV0, Self::Error> {
            if self.execute_error {
                return Err(MockError);
            }
            Ok(self
                .execution_results
                .borrow_mut()
                .pop_front()
                .expect("mock execution result"))
        }

        fn commit_block(
            &self,
            _: NativeApplicationCommitRequestV0,
        ) -> Result<NativeApplicationCommitResultV0, Self::Error> {
            if self.commit_error {
                return Err(MockError);
            }
            Ok(self
                .commit_results
                .borrow_mut()
                .pop_front()
                .expect("mock commit result"))
        }

        fn state_proof(
            &self,
            _: NativeStateProofRequestV0,
        ) -> Result<NativeStateProofV0, Self::Error> {
            unreachable!()
        }

        fn snapshot(
            &self,
            _: NativeSnapshotRequestV0,
        ) -> Result<NativeSnapshotManifestV0, Self::Error> {
            unreachable!()
        }

        fn recover(
            &self,
            _: NativeApplicationRecoveryRequestV0,
        ) -> Result<NativeApplicationRecoveryResultV0, Self::Error> {
            unreachable!()
        }
    }

    #[test]
    fn exact_valid_execution_is_linear_until_bound_commit() {
        let execution_request = request(10);
        let commit_request =
            NativeApplicationCommitRequestV0::new(executed(execution_request.clone()));
        let committed_head =
            ApplicationHeadV0::new(HeightV0::new(1), block_id(10), state_root(7), commit_id(11));
        let committed =
            NativeApplicationCommitResultV0::new(&commit_request, committed_head.clone(), 1, None)
                .expect("bound commit");
        let application = MockApplication::new(
            vec![NativeBlockExecutionResultV0::valid(executed(
                execution_request.clone(),
            ))],
            vec![committed],
        );
        let mut owner = PocoNodeNativeApplicationOwnerV0::new_for_test_v0(
            application,
            chain_id(),
            genesis_hash(),
            head(),
            1,
        )
        .expect("owner");

        let prepared = match owner.execute_block_v0(execution_request).expect("execute") {
            PocoNodeNativeExecutionOutcomeV0::Prepared(prepared) => prepared,
            other => panic!("expected prepared result, got {other:?}"),
        };
        assert_eq!(
            owner.status(),
            PocoNodeNativeApplicationOwnerStatusV0::CommitPending
        );
        assert!(matches!(
            owner.execute_block_v0(request(12)),
            Err(PocoNodeNativeApplicationOwnerErrorV0::CommitPending)
        ));
        let finality_permit = owner
            .finality_permit_for_test_v0(&prepared, committed_head.clone(), 1, hash(90))
            .expect("exact test finality permit");
        let result = owner
            .commit_block_v0(prepared, finality_permit)
            .expect("commit");
        assert_eq!(result.head(), &committed_head);
        assert_eq!(owner.authenticated_head(), &committed_head);
        assert_eq!(owner.next_durable_sequence(), 2);
        assert_eq!(
            owner.status(),
            PocoNodeNativeApplicationOwnerStatusV0::Ready
        );
    }

    #[test]
    fn substituted_valid_result_fail_stops_owner() {
        let submitted = request(20);
        let substituted = request_at(20, 8);
        let application = MockApplication::new(
            vec![NativeBlockExecutionResultV0::valid(executed(substituted))],
            Vec::new(),
        );
        let mut owner = PocoNodeNativeApplicationOwnerV0::new_for_test_v0(
            application,
            chain_id(),
            genesis_hash(),
            head(),
            1,
        )
        .expect("owner");
        assert!(matches!(
            owner.execute_block_v0(submitted),
            Err(PocoNodeNativeApplicationOwnerErrorV0::ResultBindingMismatch)
        ));
        assert_eq!(
            owner.status(),
            PocoNodeNativeApplicationOwnerStatusV0::FailStopped
        );
        assert!(matches!(
            owner.execute_block_v0(request(22)),
            Err(PocoNodeNativeApplicationOwnerErrorV0::FailStopped)
        ));
    }

    #[test]
    fn invalid_and_unavailable_results_require_exact_request_identity() {
        let submitted = request(30);
        let different = request_at(30, 8);
        let invalid =
            NativeDeterministicInvalidV0::new(&different, "invalid_body").expect("invalid result");
        let application = MockApplication::new(
            vec![NativeBlockExecutionResultV0::DeterministicallyInvalid(
                invalid,
            )],
            Vec::new(),
        );
        let mut owner = PocoNodeNativeApplicationOwnerV0::new_for_test_v0(
            application,
            chain_id(),
            genesis_hash(),
            head(),
            1,
        )
        .expect("owner");
        assert!(matches!(
            owner.execute_block_v0(submitted),
            Err(PocoNodeNativeApplicationOwnerErrorV0::ResultBindingMismatch)
        ));

        let submitted = request(40);
        let application = MockApplication::new(
            vec![NativeBlockExecutionResultV0::unavailable(
                &request_at(40, 8),
                NativeUnavailableReasonV0::HostResourceUnavailable,
            )],
            Vec::new(),
        );
        let mut owner = PocoNodeNativeApplicationOwnerV0::new_for_test_v0(
            application,
            chain_id(),
            genesis_hash(),
            head(),
            1,
        )
        .expect("owner");
        assert!(matches!(
            owner.execute_block_v0(submitted),
            Err(PocoNodeNativeApplicationOwnerErrorV0::ResultBindingMismatch)
        ));
    }

    #[test]
    fn mismatched_commit_result_fail_stops_without_releasing_head() {
        let execution_request = request(50);
        let commit_request =
            NativeApplicationCommitRequestV0::new(executed(execution_request.clone()));
        let wrong_head =
            ApplicationHeadV0::new(HeightV0::new(1), block_id(50), state_root(7), commit_id(51));
        let wrong_sequence =
            NativeApplicationCommitResultV0::new(&commit_request, wrong_head.clone(), 2, None)
                .expect("shape-valid commit");
        let application = MockApplication::new(
            vec![NativeBlockExecutionResultV0::valid(executed(
                execution_request.clone(),
            ))],
            vec![wrong_sequence],
        );
        let mut owner = PocoNodeNativeApplicationOwnerV0::new_for_test_v0(
            application,
            chain_id(),
            genesis_hash(),
            head(),
            1,
        )
        .expect("owner");
        let prepared = match owner.execute_block_v0(execution_request).expect("execute") {
            PocoNodeNativeExecutionOutcomeV0::Prepared(prepared) => prepared,
            other => panic!("expected prepared result, got {other:?}"),
        };
        let finality_permit = owner
            .finality_permit_for_test_v0(&prepared, wrong_head, 2, hash(91))
            .expect("exact test finality permit");
        assert!(matches!(
            owner.commit_block_v0(prepared, finality_permit),
            Err(PocoNodeNativeApplicationOwnerErrorV0::CommitBindingMismatch)
        ));
        assert_eq!(owner.authenticated_head(), &head());
        assert_eq!(
            owner.status(),
            PocoNodeNativeApplicationOwnerStatusV0::FailStopped
        );
    }

    #[test]
    fn substituted_commit_request_fail_stops_despite_same_head_and_sequence() {
        let execution_request = request(55);
        let substituted_request = request_with_payload_root(55, 7, 99);
        let substituted_commit_request =
            NativeApplicationCommitRequestV0::new(executed(substituted_request));
        let same_head =
            ApplicationHeadV0::new(HeightV0::new(1), block_id(55), state_root(7), commit_id(56));
        let substituted_result = NativeApplicationCommitResultV0::new(
            &substituted_commit_request,
            same_head.clone(),
            1,
            None,
        )
        .expect("shape-valid substituted commit");
        let application = MockApplication::new(
            vec![NativeBlockExecutionResultV0::valid(executed(
                execution_request.clone(),
            ))],
            vec![substituted_result],
        );
        let mut owner = PocoNodeNativeApplicationOwnerV0::new_for_test_v0(
            application,
            chain_id(),
            genesis_hash(),
            head(),
            1,
        )
        .expect("owner");
        let prepared = match owner.execute_block_v0(execution_request).expect("execute") {
            PocoNodeNativeExecutionOutcomeV0::Prepared(prepared) => prepared,
            other => panic!("expected prepared result, got {other:?}"),
        };
        let finality_permit = owner
            .finality_permit_for_test_v0(&prepared, same_head, 3, hash(92))
            .expect("exact test finality permit");

        assert!(matches!(
            owner.commit_block_v0(prepared, finality_permit),
            Err(PocoNodeNativeApplicationOwnerErrorV0::CommitBindingMismatch)
        ));
        assert_eq!(owner.authenticated_head(), &head());
        assert_eq!(
            owner.status(),
            PocoNodeNativeApplicationOwnerStatusV0::FailStopped
        );
    }

    #[test]
    fn exact_invalid_and_unavailable_fail_stop_without_unchanged_attestation() {
        let invalid_request = request(60);
        let application = MockApplication::new(
            vec![NativeBlockExecutionResultV0::DeterministicallyInvalid(
                NativeDeterministicInvalidV0::new(&invalid_request, "invalid_body")
                    .expect("invalid result"),
            )],
            Vec::new(),
        );
        let mut invalid_owner = PocoNodeNativeApplicationOwnerV0::new_for_test_v0(
            application,
            chain_id(),
            genesis_hash(),
            head(),
            1,
        )
        .expect("owner");

        assert!(matches!(
            invalid_owner
                .execute_block_v0(invalid_request)
                .expect("invalid"),
            PocoNodeNativeExecutionOutcomeV0::DeterministicallyInvalid(_)
        ));
        assert_eq!(
            invalid_owner.status(),
            PocoNodeNativeApplicationOwnerStatusV0::FailStopped
        );

        let unavailable_request = request(61);
        let application = MockApplication::new(
            vec![NativeBlockExecutionResultV0::unavailable(
                &unavailable_request,
                NativeUnavailableReasonV0::HostResourceUnavailable,
            )],
            Vec::new(),
        );
        let mut unavailable_owner = PocoNodeNativeApplicationOwnerV0::new_for_test_v0(
            application,
            chain_id(),
            genesis_hash(),
            head(),
            1,
        )
        .expect("owner");
        assert!(matches!(
            unavailable_owner
                .execute_block_v0(unavailable_request)
                .expect("unavailable"),
            PocoNodeNativeExecutionOutcomeV0::Unavailable(
                NativeUnavailableReasonV0::HostResourceUnavailable
            )
        ));
        assert_eq!(
            unavailable_owner.status(),
            PocoNodeNativeApplicationOwnerStatusV0::FailStopped
        );
    }

    #[test]
    fn application_errors_fail_stop_execute_and_commit_uncertainty() {
        let mut execute_owner = PocoNodeNativeApplicationOwnerV0::new_for_test_v0(
            MockApplication::failing_execute(),
            chain_id(),
            genesis_hash(),
            head(),
            1,
        )
        .expect("execute owner");
        assert!(matches!(
            execute_owner.execute_block_v0(request(70)),
            Err(PocoNodeNativeApplicationOwnerErrorV0::Application(
                MockError
            ))
        ));
        assert_eq!(
            execute_owner.status(),
            PocoNodeNativeApplicationOwnerStatusV0::FailStopped
        );

        let execution_request = request(71);
        let mut commit_owner = PocoNodeNativeApplicationOwnerV0::new_for_test_v0(
            MockApplication::failing_commit(NativeBlockExecutionResultV0::valid(executed(
                execution_request.clone(),
            ))),
            chain_id(),
            genesis_hash(),
            head(),
            1,
        )
        .expect("commit owner");
        let prepared = match commit_owner
            .execute_block_v0(execution_request)
            .expect("execute")
        {
            PocoNodeNativeExecutionOutcomeV0::Prepared(prepared) => prepared,
            other => panic!("expected prepared result, got {other:?}"),
        };
        let expected_committed_head =
            ApplicationHeadV0::new(HeightV0::new(1), block_id(71), state_root(7), commit_id(72));
        let finality_permit = commit_owner
            .finality_permit_for_test_v0(&prepared, expected_committed_head, 4, hash(93))
            .expect("exact test finality permit");
        assert!(matches!(
            commit_owner.commit_block_v0(prepared, finality_permit),
            Err(PocoNodeNativeApplicationOwnerErrorV0::Application(
                MockError
            ))
        ));
        assert_eq!(commit_owner.authenticated_head(), &head());
        assert_eq!(
            commit_owner.status(),
            PocoNodeNativeApplicationOwnerStatusV0::FailStopped
        );
    }

    #[test]
    fn test_finality_permit_requires_exact_head_revision_and_checksum() {
        let execution_request = request(75);
        let application = MockApplication::new(
            vec![NativeBlockExecutionResultV0::valid(executed(
                execution_request.clone(),
            ))],
            Vec::new(),
        );
        let mut owner = PocoNodeNativeApplicationOwnerV0::new_for_test_v0(
            application,
            chain_id(),
            genesis_hash(),
            head(),
            1,
        )
        .expect("owner");
        let prepared = match owner.execute_block_v0(execution_request).expect("execute") {
            PocoNodeNativeExecutionOutcomeV0::Prepared(prepared) => prepared,
            other => panic!("expected prepared result, got {other:?}"),
        };
        let exact_head =
            ApplicationHeadV0::new(HeightV0::new(1), block_id(75), state_root(7), commit_id(76));

        assert!(matches!(
            owner.finality_permit_for_test_v0(&prepared, exact_head.clone(), 0, hash(96)),
            Err(PocoNodeNativeApplicationOwnerErrorV0::ZeroFinalityRevision)
        ));
        assert!(matches!(
            owner.finality_permit_for_test_v0(
                &prepared,
                exact_head.clone(),
                6,
                Hash32V0::new([0; 32]),
            ),
            Err(PocoNodeNativeApplicationOwnerErrorV0::ZeroFinalityRecordChecksum)
        ));
        let wrong_head = ApplicationHeadV0::new(
            HeightV0::new(1),
            block_id(75),
            state_root(99),
            commit_id(76),
        );
        assert!(matches!(
            owner.finality_permit_for_test_v0(&prepared, wrong_head, 6, hash(96)),
            Err(PocoNodeNativeApplicationOwnerErrorV0::FinalityPermitMismatch)
        ));
        owner
            .finality_permit_for_test_v0(&prepared, exact_head, 6, hash(96))
            .expect("fully bound test permit");
    }

    #[test]
    fn prepared_commit_cannot_cross_between_live_owners() {
        let execution_request = request(80);
        let commit_request =
            NativeApplicationCommitRequestV0::new(executed(execution_request.clone()));
        let committed_head =
            ApplicationHeadV0::new(HeightV0::new(1), block_id(80), state_root(7), commit_id(81));
        let committed =
            NativeApplicationCommitResultV0::new(&commit_request, committed_head.clone(), 1, None)
                .expect("bound commit");
        let mut left = PocoNodeNativeApplicationOwnerV0::new_for_test_v0(
            MockApplication::new(
                vec![NativeBlockExecutionResultV0::valid(executed(
                    execution_request.clone(),
                ))],
                Vec::new(),
            ),
            chain_id(),
            genesis_hash(),
            head(),
            1,
        )
        .expect("left owner");
        let mut right = PocoNodeNativeApplicationOwnerV0::new_for_test_v0(
            MockApplication::new(
                vec![NativeBlockExecutionResultV0::valid(executed(
                    execution_request.clone(),
                ))],
                vec![committed],
            ),
            chain_id(),
            genesis_hash(),
            head(),
            1,
        )
        .expect("right owner");
        let left_prepared = match left
            .execute_block_v0(execution_request.clone())
            .expect("left execute")
        {
            PocoNodeNativeExecutionOutcomeV0::Prepared(prepared) => prepared,
            other => panic!("expected prepared result, got {other:?}"),
        };
        let right_prepared = match right
            .execute_block_v0(execution_request)
            .expect("right execute")
        {
            PocoNodeNativeExecutionOutcomeV0::Prepared(prepared) => prepared,
            other => panic!("expected prepared result, got {other:?}"),
        };

        let left_finality_permit = left
            .finality_permit_for_test_v0(&left_prepared, committed_head.clone(), 5, hash(94))
            .expect("left finality permit");
        assert!(matches!(
            right.commit_block_v0(left_prepared, left_finality_permit),
            Err(PocoNodeNativeApplicationOwnerErrorV0::PreparedCommitMismatch)
        ));
        assert_eq!(
            right.status(),
            PocoNodeNativeApplicationOwnerStatusV0::CommitPending
        );
        let right_finality_permit = right
            .finality_permit_for_test_v0(&right_prepared, committed_head, 5, hash(95))
            .expect("right finality permit");
        right
            .commit_block_v0(right_prepared, right_finality_permit)
            .expect("originating capability commits");
    }
}
