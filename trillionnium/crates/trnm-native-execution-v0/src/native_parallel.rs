//! Private frozen-v0 runtime speculation. No receipt, mutation or error from
//! this module is authoritative until the ordered owner validates dependencies.

use std::{cell::RefCell, thread};

use trnm_protocol::{
    account_key, AccountV1, CanonicalCommandV1, ACCOUNT_OBJECT_TYPE_V1, FEE_COLLECTOR_ACCOUNT_V1,
};

use super::{
    try_execute_v0, validate_signer_v0, AuthorizedSignerV0, BTreeMap, CanonicalTxV1,
    CompleteNativeExecutionFailureV0, CompleteOverlayView, ExecutionContext,
    InMemoryNativeExecutionStoreV0, Result, RuntimeReceipt, SignedCommandEnvelopeV1, StateObject,
    TryStateViewV0, CANONICAL_TX_PAYLOAD_TYPE_V1,
};

pub(super) const MAX_WORKERS_V0: usize = 8;
pub(super) const MAX_BATCH_V0: usize = 32;
const MAX_READS_V0: usize = 64;
const MAX_RETAINED_READ_BYTES_V0: usize = 256 * 1024;
const MAX_RETAINED_RESULT_BYTES_V0: usize = 256 * 1024;

#[cfg(test)]
#[derive(Debug, Default)]
pub(super) struct NativeSchedulingCountsV0 {
    pub(super) exact_reused: usize,
    pub(super) fee_rebased: usize,
    pub(super) reexecuted: usize,
}

pub(super) struct RuntimeReuseV0 {
    pub(super) outcome: Result<RuntimeReceipt>,
    #[cfg(test)]
    pub(super) fee_rebased: bool,
}

/// An internal proof about one successful real runtime attempt, never supplied
/// by a caller or serialized. The deliberately narrow Transfer whitelist has
/// no collector-dependent command behavior: the collector is touched only by
/// the mandatory fee credit, while all other accesses remain exact.
#[derive(Debug)]
struct TransferFeeDeltaV0 {
    mutation_index: usize,
    previous_version: Option<u64>,
    previous_balance: u128,
    nonce: u64,
}

pub(super) fn default_worker_count_v0() -> usize {
    thread::available_parallelism()
        .map_or(1, usize::from)
        .min(MAX_WORKERS_V0)
}

#[derive(Clone, Copy)]
pub(super) struct NativeSpeculationContextV0<'a> {
    pub(super) store: &'a InMemoryNativeExecutionStoreV0,
    pub(super) parent_version: u64,
    pub(super) parent_root: jmt::RootHash,
    pub(super) height: u64,
    pub(super) chain_id: &'a str,
    pub(super) timestamp_ms: u64,
    pub(super) signers: &'a [AuthorizedSignerV0],
    pub(super) changes: &'a BTreeMap<String, StateObject>,
}

#[derive(Debug)]
pub(super) struct SpeculativeRuntimeAttemptV0 {
    // Absence is a dependency too: a prior transaction may create the object.
    reads: BTreeMap<String, Option<StateObject>>,
    reads_available: bool,
    pub(super) outcome: Result<RuntimeReceipt>,
    fee_delta: Option<TransferFeeDeltaV0>,
    #[cfg(test)]
    pub(super) worker_id: thread::ThreadId,
}

impl SpeculativeRuntimeAttemptV0 {
    pub(super) fn into_reusable_outcome_v0(
        mut self,
        view: &impl TryStateViewV0,
    ) -> Option<RuntimeReuseV0> {
        if !self.reads_available {
            return None;
        }
        let collector_key = account_key(FEE_COLLECTOR_ACCOUNT_V1);
        let mut changed_collector = None;
        for (key, observed) in &self.reads {
            let current = view.try_get(key).ok()?;
            if current != *observed {
                if key != &collector_key || self.fee_delta.is_none() {
                    return None;
                }
                changed_collector = Some(current);
            }
        }
        let fee_rebased = changed_collector.is_some();
        if let Some(current) = changed_collector {
            let delta = self.fee_delta.as_ref()?;
            let (version, mut collector) = decode_collector_v0(current.as_ref())?;
            // Only monotonic fee additions since the batch base can take this
            // path. Explicit collector operations are canonical barriers.
            if collector.nonce != delta.nonce
                || collector.balance < delta.previous_balance
                || version? <= delta.previous_version.unwrap_or(0)
            {
                return None;
            }
            let receipt = self.outcome.as_mut().ok()?;
            collector.balance = collector.balance.checked_add(receipt.fee_charged)?;
            let mutation = receipt.mutations.get_mut(delta.mutation_index)?;
            mutation.expected_version = version;
            mutation.next_version = version?.checked_add(1)?;
            mutation.value_bytes = serde_json::to_vec(&collector).ok()?;
        }
        // Any failed check above discards the entire attempt. Canonical runtime
        // execution, rather than this optimization, chooses a typed error.
        #[cfg(not(test))]
        let _ = fee_rebased;
        Some(RuntimeReuseV0 {
            outcome: self.outcome,
            #[cfg(test)]
            fee_rebased,
        })
    }
}

pub(super) fn transfer_has_fee_only_collector_access_v0(transaction: &CanonicalTxV1) -> bool {
    transaction.sender != FEE_COLLECTOR_ACCOUNT_V1
        && matches!(&transaction.command, CanonicalCommandV1::Transfer { to, .. } if to != FEE_COLLECTOR_ACCOUNT_V1)
}

pub(super) fn requires_collector_barrier_v0(
    transaction: &CanonicalTxV1,
    receipt: &RuntimeReceipt,
) -> bool {
    !transfer_has_fee_only_collector_access_v0(transaction)
        && receipt
            .mutations
            .iter()
            .any(|mutation| mutation.object_key_hex == account_key(FEE_COLLECTOR_ACCOUNT_V1))
}

fn decode_collector_v0(object: Option<&StateObject>) -> Option<(Option<u64>, AccountV1)> {
    match object {
        None => Some((
            None,
            AccountV1 {
                account: FEE_COLLECTOR_ACCOUNT_V1.to_string(),
                balance: 0,
                nonce: 0,
            },
        )),
        Some(object) => {
            if object.object_type != ACCOUNT_OBJECT_TYPE_V1 || object.version == 0 {
                return None;
            }
            let account: AccountV1 = serde_json::from_slice(&object.value_bytes).ok()?;
            if account.account != FEE_COLLECTOR_ACCOUNT_V1 {
                return None;
            }
            Some((Some(object.version), account))
        }
    }
}

fn prove_transfer_fee_delta_v0(
    transaction: &CanonicalTxV1,
    attempt: &SpeculativeRuntimeAttemptV0,
) -> Option<TransferFeeDeltaV0> {
    if !attempt.reads_available || !transfer_has_fee_only_collector_access_v0(transaction) {
        return None;
    }
    let receipt = attempt.outcome.as_ref().ok()?;
    let key = account_key(FEE_COLLECTOR_ACCOUNT_V1);
    let (previous_version, previous) = decode_collector_v0(attempt.reads.get(&key)?.as_ref())?;
    let mut collector_mutations = receipt
        .mutations
        .iter()
        .enumerate()
        .filter(|(_, mutation)| mutation.object_key_hex == key);
    let (mutation_index, mutation) = collector_mutations.next()?;
    if collector_mutations.next().is_some()
        || mutation.object_type != ACCOUNT_OBJECT_TYPE_V1
        || mutation.expected_version != previous_version
        || mutation.next_version != previous_version.unwrap_or(0).checked_add(1)?
    {
        return None;
    }
    let successor: AccountV1 = serde_json::from_slice(&mutation.value_bytes).ok()?;
    if successor.account != FEE_COLLECTOR_ACCOUNT_V1
        || successor.nonce != previous.nonce
        || successor.balance != previous.balance.checked_add(receipt.fee_charged)?
        || serde_json::to_vec(&successor).ok()? != mutation.value_bytes
    {
        return None;
    }
    Some(TransferFeeDeltaV0 {
        mutation_index,
        previous_version,
        previous_balance: previous.balance,
        nonce: previous.nonce,
    })
}

struct RecordingViewV0<'a, View> {
    view: &'a View,
    reads: RefCell<BTreeMap<String, Option<StateObject>>>,
    reads_available: std::cell::Cell<bool>,
    retained_bytes: std::cell::Cell<usize>,
}

impl<View: TryStateViewV0> TryStateViewV0 for RecordingViewV0<'_, View> {
    type Error = View::Error;

    fn try_get(&self, key: &str) -> std::result::Result<Option<StateObject>, Self::Error> {
        let result = self.view.try_get(key);
        match &result {
            Ok(value) => {
                let mut reads = self.reads.borrow_mut();
                if self.reads_available.get() && !reads.contains_key(key) {
                    let bytes = key.len().saturating_add(value.as_ref().map_or(0, |object| {
                        object
                            .object_type
                            .len()
                            .saturating_add(object.value_bytes.len())
                    }));
                    let retained = self.retained_bytes.get().saturating_add(bytes);
                    if reads.len() >= MAX_READS_V0 || retained > MAX_RETAINED_READ_BYTES_V0 {
                        // Scheduling bounds cannot reject a valid transaction.
                        self.reads_available.set(false);
                        reads.clear();
                    } else {
                        reads.insert(key.to_string(), value.clone());
                        self.retained_bytes.set(retained);
                    }
                }
            }
            Err(_) => self.reads_available.set(false),
        }
        result
    }
}

pub(super) fn execute_runtime_v0(
    transaction: &CanonicalTxV1,
    context: ExecutionContext<'_>,
    view: &impl TryStateViewV0,
) -> Result<RuntimeReceipt> {
    try_execute_v0(transaction, context, view).map_err(|failure| {
        let classified = match failure.deterministic_failure_v0() {
            Some(classification) => CompleteNativeExecutionFailureV0::Deterministic(classification),
            None if failure.state_unavailable().is_some() => {
                CompleteNativeExecutionFailureV0::StateUnavailable
            }
            None => CompleteNativeExecutionFailureV0::Unclassified,
        };
        anyhow::Error::new(classified)
    })
}

fn record_runtime_attempt_v0(
    transaction: &CanonicalTxV1,
    context: ExecutionContext<'_>,
    view: &impl TryStateViewV0,
) -> SpeculativeRuntimeAttemptV0 {
    let recording = RecordingViewV0 {
        view,
        reads: RefCell::new(BTreeMap::new()),
        reads_available: std::cell::Cell::new(true),
        retained_bytes: std::cell::Cell::new(0),
    };
    let outcome = execute_runtime_v0(transaction, context, &recording);
    let mut attempt = SpeculativeRuntimeAttemptV0 {
        reads: recording.reads.into_inner(),
        reads_available: recording.reads_available.get(),
        outcome,
        fee_delta: None,
        #[cfg(test)]
        worker_id: thread::current().id(),
    };
    attempt.fee_delta = prove_transfer_fee_delta_v0(transaction, &attempt);
    attempt
}

fn speculate_outer_v0(
    context: NativeSpeculationContextV0<'_>,
    exact_outer: &[u8],
) -> Option<SpeculativeRuntimeAttemptV0> {
    // This preliminary admission is deliberately inert. The ordered owner
    // repeats exact envelope verification and checks block/committed replay
    // before it can consume the retained runtime result. Invalid or internal
    // inputs are handled only by that existing canonical path.
    let envelope: SignedCommandEnvelopeV1 = serde_json::from_slice(exact_outer).ok()?;
    if envelope.payload_type != CANONICAL_TX_PAYLOAD_TYPE_V1 {
        return None;
    }
    envelope
        .validate_at_strict(context.chain_id, context.timestamp_ms)
        .ok()?;
    let signer = validate_signer_v0(context.signers, &envelope).ok()?;
    let inner = envelope.payload_bytes().ok()?;
    let transaction: CanonicalTxV1 = serde_json::from_slice(&inner).ok()?;
    transaction.validate().ok()?;
    if transaction.sender != envelope.signer_id || transaction.nonce != envelope.nonce {
        return None;
    }
    let view = CompleteOverlayView {
        store: context.store,
        parent_version: context.parent_version,
        parent_root: context.parent_root,
        changes: context.changes,
    };
    let attempt = record_runtime_attempt_v0(
        &transaction,
        ExecutionContext {
            height: context.height,
            signer_id: signer.signer_id(),
            signer_role: signer.signer_role(),
            payload_len: inner.len(),
        },
        &view,
    );
    if !attempt.reads_available {
        return None;
    }
    if let Ok(receipt) = &attempt.outcome {
        // Explicit collector writes (and other command families without a
        // fee-only proof) always execute at the canonical owner, then form a
        // barrier. They cannot be accidentally covered by the transfer proof.
        if requires_collector_barrier_v0(&transaction, receipt) {
            return None;
        }
        let bytes = receipt.mutations.iter().fold(0usize, |total, mutation| {
            total
                .saturating_add(mutation.object_key_hex.len())
                .saturating_add(mutation.object_type.len())
                .saturating_add(mutation.value_bytes.len())
        });
        let bytes = receipt.events.iter().fold(bytes, |total, event| {
            event.attributes.iter().fold(
                total.saturating_add(event.kind.len()),
                |sum, (key, value)| sum.saturating_add(key.len()).saturating_add(value.len()),
            )
        });
        if bytes > MAX_RETAINED_RESULT_BYTES_V0 {
            return None;
        }
    }
    Some(attempt)
}

pub(super) fn speculate_transactions_v0(
    context: NativeSpeculationContextV0<'_>,
    transactions: &[Vec<u8>],
    worker_count: usize,
) -> Vec<Option<SpeculativeRuntimeAttemptV0>> {
    // Zero bypasses the speculation scheduler entirely for differential tests.
    let mut outcomes: Vec<_> = (0..transactions.len()).map(|_| None).collect();
    if worker_count == 0 || transactions.is_empty() || transactions.len() > MAX_BATCH_V0 {
        return outcomes;
    }
    let active_workers = worker_count.min(MAX_WORKERS_V0).min(transactions.len());
    let chunk_size = transactions.len().div_ceil(active_workers);
    thread::scope(|scope| {
        let handles: Vec<_> = transactions
            .chunks(chunk_size)
            .enumerate()
            .map(|(chunk_index, chunk)| {
                let handle = thread::Builder::new().spawn_scoped(scope, move || {
                    chunk
                        .iter()
                        .map(|outer| speculate_outer_v0(context, outer))
                        .collect::<Vec<_>>()
                });
                (chunk_index * chunk_size, handle)
            })
            .collect();
        for (start, handle) in handles {
            // Worker resource failure or panic cannot authorize rejection at
            // an unrelated transaction index. Join every started worker and
            // leave its chunk for the unchanged canonical execution path.
            if let Ok(handle) = handle {
                if let Ok(computed) = handle.join() {
                    for (index, attempt) in computed.into_iter().enumerate() {
                        outcomes[start + index] = attempt;
                    }
                }
            }
        }
    });
    outcomes
}

#[cfg(test)]
#[path = "native_parallel_dependency_tests.rs"]
mod dependency_tests;
