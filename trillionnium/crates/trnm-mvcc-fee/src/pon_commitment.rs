//! Pure derived commitment computation for the existing PoN executor.
//!
//! Each new binding canonically checks the complete actual State. A matching
//! opaque snapshot can share its bytes after that comparison. Within one
//! operation, CheckedExecutionParent reuses those bytes while borrowing State.
//! A snapshot is neither a state
//! setter nor a transaction/admission verdict. The caller must still read actual
//! KV, check its committed root and publish any staged snapshot only after its
//! own durable commit. Cache limits select the unchanged full-root algorithm;
//! they never reduce protocol state limits. Charges are software accounting,
//! not a bound on process RSS or allocations in the executor/SQLite/proof code.
use crate::pon_executor::{
    self, BlockExecution, Config, ControlledResult, ExecutionError, ExecutionProgress, Output,
    Result, State,
};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::sync::Arc;
use trnm_protocol::pon_state::{Change, StateTree};
use trnm_protocol::pon_wire::{state_root, Hash};

type CanonicalValues = BTreeMap<Vec<u8>, Vec<u8>>;
pub const MAX_CACHE_KEYS: usize = 65536;
pub const MAX_CACHE_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_WORKSPACE_CHARGE_BYTES: usize = 512 * 1024 * 1024;
// Deliberate conservative software charges, not claims about an allocator ABI.
const MAP_ENTRY_CHARGE: usize = 1024;
const COMPRESSED_NODE_CHARGE: usize = 256;
const CHANGE_ENTRY_CHARGE: usize = 256;
const EMPTY_TABLE_CHARGE: usize = 257 * 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheLimits {
    pub max_keys: usize,
    pub max_payload_bytes: usize,
    pub max_workspace_charge_bytes: usize,
}
impl Default for CacheLimits {
    fn default() -> Self {
        Self {
            max_keys: MAX_CACHE_KEYS,
            max_payload_bytes: MAX_CACHE_PAYLOAD_BYTES,
            max_workspace_charge_bytes: MAX_WORKSPACE_CHARGE_BYTES,
        }
    }
}
impl CacheLimits {
    fn validate(self) -> Result<()> {
        if self.max_keys > MAX_CACHE_KEYS
            || self.max_payload_bytes > MAX_CACHE_PAYLOAD_BYTES
            || self.max_workspace_charge_bytes > MAX_WORKSPACE_CHARGE_BYTES
        {
            return Err("COMMITMENT_CACHE_LIMIT");
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FullRootReason {
    KeyBudget,
    PayloadBudget,
    WorkspaceBudget,
    DeltaBudget,
    InternalSnapshotMismatch,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitmentMethod {
    RebuiltTree,
    CheckedApply,
    FullRoot(FullRootReason),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentObservation {
    pub method: CommitmentMethod,
    pub actual_keys: usize,
    pub actual_payload_bytes: usize,
    pub changed_keys: usize,
    /// Logical key/before/after bytes in the complete returned changes. This is
    /// neither Vec capacity nor a process memory observation.
    pub changed_payload_bytes: usize,
    pub compressed_nodes: Option<usize>,
    pub workspace_charge_bytes: usize,
}
/// Opaque immutable canonical bytes and structurally shared compressed tree.
/// Clone shares Arcs; it does not copy the entire state/tree. Retaining unbounded
/// clones would retain unbounded versions: callers must bound retained snapshots.
#[derive(Clone)]
pub struct CheckedCommitment {
    values: Arc<CanonicalValues>,
    tree: StateTree,
    root: Hash,
    charges: Charges,
}
impl std::fmt::Debug for CheckedCommitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheckedCommitment")
            .field("root", &self.root)
            .field("keys", &self.values.len())
            .finish_non_exhaustive()
    }
}
impl CheckedCommitment {
    pub fn root(&self) -> Hash {
        self.root
    }
    pub fn keys(&self) -> usize {
        self.values.len()
    }
    pub fn payload_bytes(&self) -> usize {
        self.charges.payload
    }
    /// Software charge for this canonical map/tree, excluding any actual State.
    pub fn retained_charge_bytes(&self) -> usize {
        self.charges.map + self.charges.tree
    }
}
#[derive(Clone, Debug)]
pub struct PreparedCommitment {
    pub root: Hash,
    pub snapshot: Option<CheckedCommitment>,
    pub changes: Vec<Change>,
    pub observation: CommitmentObservation,
}
#[derive(Debug)]
pub struct StagedOutput {
    pub output: Output,
    pub commitment: PreparedCommitment,
}
/// All ordinary execution inputs; keeps the adapter independent of any Node owner.
pub struct ExecutionRequest<'a> {
    pub transactions: &'a [Vec<u8>],
    pub height: u64,
    pub miner: Hash,
    pub parent_id: Hash,
    pub workers: usize,
}
#[derive(Clone, Copy)]
struct Charges {
    payload: usize,
    map: usize,
    tree: usize,
    nodes: usize,
}
fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or("COMMITMENT_CHARGE")
}
fn mul(a: usize, b: usize) -> Result<usize> {
    a.checked_mul(b).ok_or("COMMITMENT_CHARGE")
}
fn encode(state: &State) -> Result<CanonicalValues> {
    // Preserve the original root() canonical error order, before protocol bounds.
    let mut values = BTreeMap::new();
    for (key, value) in state {
        values.insert(key.as_bytes().to_vec(), pon_executor::canonical(value)?);
    }
    if values.len() > 65_536
        || values
            .iter()
            .any(|(key, value)| key.len() > 160 || value.len() > 4096)
    {
        return Err("LIMIT");
    }
    Ok(values)
}
/// Check the complete actual State before sharing an immutable canonical map.
/// A mismatch cannot short-circuit later canonical errors or protocol bounds.
/// At most one newly serialized value is live here; keys remain borrowed.
fn matches_encoded(state: &State, expected: &CanonicalValues) -> Result<bool> {
    let mut matches = state.len() == expected.len();
    let mut within_limits = state.len() <= 65_536;
    let mut previous = expected.iter();
    for (key, value) in state {
        let actual = pon_executor::canonical(value)?;
        within_limits &= key.len() <= 160 && actual.len() <= 4096;
        matches &= previous
            .next()
            .is_some_and(|(old_key, old_value)| key.as_bytes() == old_key && actual == *old_value);
    }
    if !within_limits {
        return Err("LIMIT");
    }
    Ok(matches)
}
fn charges(values: &CanonicalValues) -> Result<Charges> {
    let mut payload = 0;
    let mut capacities = 0;
    for (key, value) in values {
        payload = add(payload, add(key.len(), value.len())?)?;
        capacities = add(capacities, add(key.capacity(), value.capacity())?)?;
    }
    let nodes = values
        .len()
        .checked_mul(2)
        .ok_or("COMMITMENT_CHARGE")?
        .saturating_sub(1);
    Ok(Charges {
        payload,
        map: add(capacities, mul(values.len(), MAP_ENTRY_CHARGE)?)?,
        tree: add(
            add(capacities, mul(nodes, COMPRESSED_NODE_CHARGE)?)?,
            EMPTY_TABLE_CHARGE,
        )?,
        nodes,
    })
}
/// Visit every actual difference in key order without allocating a union of keys
/// or cloning canonical values. Both passes use these same borrowed comparisons.
fn visit_differences(
    before: &CanonicalValues,
    after: &CanonicalValues,
    mut visit: impl FnMut(&Vec<u8>, Option<&Vec<u8>>, Option<&Vec<u8>>) -> Result<()>,
) -> Result<()> {
    let mut old = before.iter().peekable();
    let mut new = after.iter().peekable();
    loop {
        match (old.peek(), new.peek()) {
            (Some((old_key, old_value)), Some((new_key, new_value))) => {
                match old_key.cmp(new_key) {
                    Ordering::Less => {
                        visit(old_key, Some(old_value), None)?;
                        old.next();
                    }
                    Ordering::Greater => {
                        visit(new_key, None, Some(new_value))?;
                        new.next();
                    }
                    Ordering::Equal => {
                        if old_value != new_value {
                            visit(old_key, Some(old_value), Some(new_value))?;
                        }
                        old.next();
                        new.next();
                    }
                }
            }
            (Some((key, value)), None) => {
                visit(key, Some(value), None)?;
                old.next();
            }
            (None, Some((key, value))) => {
                visit(key, None, Some(value))?;
                new.next();
            }
            (None, None) => return Ok(()),
        }
    }
}
#[derive(Clone, Copy, Default)]
struct DifferencePlan {
    count: usize,
    payload: usize,
}
fn plan_differences(before: &CanonicalValues, after: &CanonicalValues) -> Result<DifferencePlan> {
    let mut plan = DifferencePlan::default();
    visit_differences(before, after, |key, old, new| {
        plan.count = add(plan.count, 1)?;
        plan.payload = add(
            plan.payload,
            add(
                key.len(),
                add(old.map_or(0, Vec::len), new.map_or(0, Vec::len))?,
            )?,
        )?;
        Ok(())
    })?;
    Ok(plan)
}
fn materialize_differences(
    before: Option<&CanonicalValues>,
    after: &CanonicalValues,
    plan: DifferencePlan,
) -> Result<Vec<Change>> {
    mark_stage("changes-allocation");
    let mut changes = Vec::with_capacity(plan.count);
    if let Some(before) = before {
        visit_differences(before, after, |key, old, new| {
            changes.push(Change {
                key: key.clone(),
                before: old.cloned(),
                after: new.cloned(),
            });
            Ok(())
        })?;
    }
    debug_assert_eq!(changes.len(), plan.count);
    Ok(changes)
}
// Test-only markers bracket real full-root computation and the actual allocation
// sites. They do not measure allocator bytes/RSS and disappear from production.
#[cfg(test)]
std::thread_local! {
    static ALLOCATION_STAGES: std::cell::RefCell<Vec<&'static str>> = const {
        std::cell::RefCell::new(Vec::new())
    };
}
fn mark_stage(_stage: &'static str) {
    #[cfg(test)]
    ALLOCATION_STAGES.with(|stages| stages.borrow_mut().push(_stage));
}
fn prepare_values(
    values: CanonicalValues,
    prior: Option<&CheckedCommitment>,
    actual_before: Option<&CanonicalValues>,
    limits: CacheLimits,
) -> Result<PreparedCommitment> {
    limits.validate()?;
    let current = charges(&values)?;
    let before = actual_before.or_else(|| prior.map(|p| p.values.as_ref()));
    let difference_plan = before
        .map(|previous| plan_differences(previous, &values))
        .transpose()?
        .unwrap_or_default();
    let preceding = before.map(charges).transpose()?.unwrap_or(current);
    let maximum = Charges {
        payload: current.payload.max(preceding.payload),
        map: current.map.max(preceding.map),
        tree: current.tree.max(preceding.tree),
        nodes: current.nodes.max(preceding.nodes),
    };
    // At most old base, previous staged and newly built path roots while apply
    // replaces an Arc. Full successor maps/diffs are encoded/checked on every call.
    let workspace = add(
        mul(add(maximum.map, maximum.tree)?, 3)?,
        add(
            mul(maximum.payload, 2)?,
            mul(difference_plan.count, CHANGE_ENTRY_CHARGE)?,
        )?,
    )?;
    let reason = if values.len() > limits.max_keys {
        Some(FullRootReason::KeyBudget)
    } else if current.payload > limits.max_payload_bytes {
        Some(FullRootReason::PayloadBudget)
    } else if workspace > limits.max_workspace_charge_bytes {
        Some(FullRootReason::WorkspaceBudget)
    } else if prior.is_some() && difference_plan.count > MAX_CACHE_KEYS {
        // StateTree::apply bounds its complete batch to the protocol key limit.
        // A valid successor can differ by more keys (removals plus insertions).
        // This known limit is checked before cloning its mandatory public delta.
        Some(FullRootReason::DeltaBudget)
    } else {
        None
    };
    mark_stage("budget-selected");
    let mut observation = CommitmentObservation {
        method: CommitmentMethod::RebuiltTree,
        actual_keys: values.len(),
        actual_payload_bytes: current.payload,
        changed_keys: difference_plan.count,
        changed_payload_bytes: difference_plan.payload,
        compressed_nodes: None,
        workspace_charge_bytes: workspace,
    };
    if let Some(reason) = reason {
        observation.method = CommitmentMethod::FullRoot(reason);
        // Complete-root temporaries must finish before the mandatory public
        // delta clones are allocated. Full canonical maps remain actual input.
        let root = state_root(&values).map_err(|_| "LIMIT")?;
        mark_stage("full-root-completed");
        let changes = materialize_differences(before, &values, difference_plan)?;
        return Ok(PreparedCommitment {
            root,
            snapshot: None,
            changes,
            observation,
        });
    }
    let changes = materialize_differences(before, &values, difference_plan)?;
    mark_stage("tree-allocation");
    let tree = if let Some(previous) = prior {
        match previous.tree.apply(previous.root, &changes) {
            Ok(tree) => {
                observation.method = CommitmentMethod::CheckedApply;
                tree
            }
            Err(_) => {
                // Internal cache damage cannot become a new ledger rejection or
                // repair the actual state. The caller still compares the full root.
                observation.method =
                    CommitmentMethod::FullRoot(FullRootReason::InternalSnapshotMismatch);
                return Ok(PreparedCommitment {
                    root: state_root(&values).map_err(|_| "LIMIT")?,
                    snapshot: None,
                    changes,
                    observation,
                });
            }
        }
    } else {
        StateTree::from_values(&values).map_err(|_| "LIMIT")?
    };
    let root = tree.root();
    observation.compressed_nodes = Some(current.nodes);
    Ok(PreparedCommitment {
        root,
        snapshot: Some(CheckedCommitment {
            values: Arc::new(values),
            tree,
            root,
            charges: current,
        }),
        changes,
        observation,
    })
}
/// Validate a complete actual State against its owner-selected committed root.
/// A prior snapshot only accelerates computation; changed actual KV is always
/// encoded and checked. Unknown/fork contexts may simply pass None.
pub fn checked_snapshot(
    actual_state: &State,
    expected_root: Hash,
    prior: Option<&CheckedCommitment>,
    limits: CacheLimits,
) -> Result<PreparedCommitment> {
    let prepared = derive_snapshot(actual_state, prior, limits)?;
    if prepared.root != expected_root {
        return Err("COMMITMENT_ROOT");
    }
    Ok(prepared)
}
/// Compute a successor commitment from complete actual state values. This is
/// only a calculation: an admitted context must use checked_snapshot or compare
/// its expected root separately. No state setter or eligibility fact is created.
pub fn derive_snapshot(
    actual_state: &State,
    prior: Option<&CheckedCommitment>,
    limits: CacheLimits,
) -> Result<PreparedCommitment> {
    prepare_values(encode(actual_state)?, prior, None, limits)
}
/// Pure full-rule execution. Never advances or mutates the supplied snapshot.
/// A canonical byte/root mismatch is rejected before transaction execution;
/// internal tree inconsistency takes the complete-root fallback during staging.
/// An owner can explicitly discard/reseed via checked_snapshot/None. None uses
/// actual full-root validation and still returns a budgeted staged successor.
pub fn execute_checked(
    actual_parent: &State,
    expected_parent_root: Hash,
    predecessor: Option<&CheckedCommitment>,
    request: ExecutionRequest<'_>,
    config: &Config,
    limits: CacheLimits,
) -> Result<StagedOutput> {
    CheckedExecutionParent::bind(actual_parent, expected_parent_root, predecessor, limits)?
        .execute(request, config)
}

/// Controlled full-rule preview. Cancellation never triggers snapshot fallback.
pub fn execute_checked_with_progress<E: Send>(
    actual_parent: &State,
    expected_parent_root: Hash,
    predecessor: Option<&CheckedCommitment>,
    request: ExecutionRequest<'_>,
    config: &Config,
    limits: CacheLimits,
    progress: &(impl Fn(ExecutionProgress) -> std::result::Result<(), E> + Sync),
) -> ControlledResult<StagedOutput, E> {
    execute_checked_with_control(
        actual_parent,
        expected_parent_root,
        predecessor,
        request,
        config,
        limits,
        &pon_executor::ExecutionControl::new(progress, &()),
    )
}
pub fn execute_checked_with_control<E: Send>(
    actual_parent: &State,
    expected_parent_root: Hash,
    predecessor: Option<&CheckedCommitment>,
    request: ExecutionRequest<'_>,
    config: &Config,
    limits: CacheLimits,
    control: &pon_executor::ExecutionControl<'_, E>,
) -> ControlledResult<StagedOutput, E> {
    (control.progress)(ExecutionProgress::BeforeParentBinding)
        .map_err(ExecutionError::Cancelled)?;
    CheckedExecutionParent::bind(actual_parent, expected_parent_root, predecessor, limits)?
        .execute_with_control(request, config, control)
}

/// Operation-local immutable binding of actual parent bytes to its admitted root.
/// The borrow prevents changing the State while this value exists; it is not a
/// branch/generation fence and must not be retained across owner operations.
/// Every preview still runs complete block rules from the original parent,
/// including maintenance, nonce/fee rules, subsidy, receipts and successor root.
pub struct CheckedExecutionParent<'a> {
    state: &'a State,
    actual: Arc<CanonicalValues>,
    predecessor: Option<CheckedCommitment>,
    limits: CacheLimits,
}
impl<'a> CheckedExecutionParent<'a> {
    pub fn bind(
        actual_parent: &'a State,
        expected_parent_root: Hash,
        predecessor: Option<&CheckedCommitment>,
        limits: CacheLimits,
    ) -> Result<Self> {
        limits.validate()?;
        let actual = if let Some(snapshot) = predecessor {
            if !matches_encoded(actual_parent, &snapshot.values)? {
                return Err("COMMITMENT_PARENT");
            }
            if snapshot.root != expected_parent_root {
                return Err("COMMITMENT_ROOT");
            }
            Arc::clone(&snapshot.values)
        } else {
            let actual = encode(actual_parent)?;
            if state_root(&actual).map_err(|_| "LIMIT")? != expected_parent_root {
                return Err("COMMITMENT_ROOT");
            }
            Arc::new(actual)
        };
        Ok(Self {
            state: actual_parent,
            actual,
            predecessor: predecessor.cloned(),
            limits,
        })
    }

    pub fn execute(&self, request: ExecutionRequest<'_>, config: &Config) -> Result<StagedOutput> {
        self.execute_with_accounting(request, config, &())
    }
    pub fn execute_with_accounting(
        &self,
        request: ExecutionRequest<'_>,
        config: &Config,
        worker_accounting: &dyn pon_executor::ExecutionWorkerAccounting,
    ) -> Result<StagedOutput> {
        pon_executor::relation_only(self.execute_with_control(
            request,
            config,
            &pon_executor::ExecutionControl::new(&pon_executor::no_cancellation, worker_accounting),
        ))
    }
    pub fn execute_with_progress<E: Send>(
        &self,
        request: ExecutionRequest<'_>,
        config: &Config,
        progress: &(impl Fn(ExecutionProgress) -> std::result::Result<(), E> + Sync),
    ) -> ControlledResult<StagedOutput, E> {
        self.execute_with_control(
            request,
            config,
            &pon_executor::ExecutionControl::new(progress, &()),
        )
    }
    pub fn execute_with_control<E: Send>(
        &self,
        request: ExecutionRequest<'_>,
        config: &Config,
        control: &pon_executor::ExecutionControl<'_, E>,
    ) -> ControlledResult<StagedOutput, E> {
        let mut staged = None;
        let output = pon_executor::execute_with_commitment_and_control(
            self.state,
            BlockExecution {
                transactions: request.transactions,
                height: request.height,
                miner: request.miner,
                parent_id: request.parent_id,
                workers: request.workers,
            },
            config,
            |_, after| {
                let prepared = prepare_values(
                    encode(after)?,
                    self.predecessor.as_ref(),
                    Some(&self.actual),
                    self.limits,
                )?;
                let root = prepared.root;
                staged = Some(prepared);
                Ok(root)
            },
            control,
        )?;
        Ok(StagedOutput {
            output,
            commitment: staged.ok_or("COMMITMENT_STAGED")?,
        })
    }

    /// Consume this exact immutable parent binding into a one-block prefix
    /// builder. The caller must discard it when its owner operation ends.
    pub fn into_prefix_with_control<E: Send>(
        self,
        context: pon_executor::PrefixContext,
        config: &Config,
        control: &pon_executor::ExecutionControl<'_, E>,
    ) -> ControlledResult<CheckedTransactionPrefix<'a>, E> {
        let execution = pon_executor::TransactionPrefix::new(self.state, context, config, control)?;
        Ok(CheckedTransactionPrefix {
            parent: self,
            execution,
        })
    }
}

/// Operation-local suffix execution of one fixed block. The unfinalized state
/// cannot be extracted, replaced, persisted or used as an admitted parent. Each
/// returned output commits the COMPLETE original-parent-to-prefix transition.
/// M05/owner checks and current actual KV/root checks remain caller obligations.
pub struct CheckedTransactionPrefix<'a> {
    parent: CheckedExecutionParent<'a>,
    execution: pon_executor::TransactionPrefix,
}
impl CheckedTransactionPrefix<'_> {
    pub fn len(&self) -> usize {
        self.execution.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn execute(&mut self, transactions: &[Vec<u8>]) -> Result<StagedOutput> {
        pon_executor::relation_only(self.execute_with_control(
            transactions,
            &pon_executor::ExecutionControl::new(&pon_executor::no_cancellation, &()),
        ))
    }
    pub fn execute_with_control<E: Send>(
        &mut self,
        transactions: &[Vec<u8>],
        control: &pon_executor::ExecutionControl<'_, E>,
    ) -> ControlledResult<StagedOutput, E> {
        let mut staged = None;
        let output = self.execution.execute_with_commitment_and_control(
            transactions,
            |after| {
                let prepared = prepare_values(
                    encode(after)?,
                    self.parent.predecessor.as_ref(),
                    Some(&self.parent.actual),
                    self.parent.limits,
                )?;
                let root = prepared.root;
                staged = Some(prepared);
                Ok(root)
            },
            control,
        )?;
        Ok(StagedOutput {
            output,
            commitment: staged.ok_or("COMMITMENT_STAGED")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn preview_fixture() -> (State, Config, Vec<Vec<u8>>) {
        use trnm_crypto_primitives::{public_key_hex, sign_hex, signing_key_from_hex};
        use trnm_protocol::pon_wire::Envelope;
        let cfg = Config::installed().unwrap();
        let key = signing_key_from_hex(&hex::encode([7; 32])).unwrap();
        let public = public_key_hex(&key);
        let sender = hex::decode(&public).unwrap().try_into().unwrap();
        let state = State::from([
            ("meta:issued".into(), json!(1_000_000_000u64)),
            ("model:current".into(), json!(hex::encode([0; 32]))),
            (
                format!("account:{public}"),
                json!({"balance":1_000_000_000u64,"nonce":0}),
            ),
        ]);
        let raws = (1..=16)
            .map(|nonce| {
                let mut payload = [2; 32].to_vec();
                payload.extend(1u64.to_le_bytes());
                let mut tx = Envelope {
                    network: cfg.network,
                    sender,
                    nonce,
                    expiry: 2000,
                    fee_limit: 1_000_000,
                    tag: 1,
                    payload,
                    signature: [0; 64],
                };
                tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
                    .unwrap()
                    .try_into()
                    .unwrap();
                tx.encode().unwrap()
            })
            .collect();
        (state, cfg, raws)
    }

    // The previous warm-binding algorithm is an allocation/timing control only.
    // It separately encodes and retains every actual key/value before comparing.
    fn copying_parent_reference<'a>(
        state: &'a State,
        expected_root: Hash,
        snapshot: &CheckedCommitment,
        limits: CacheLimits,
    ) -> Result<CheckedExecutionParent<'a>> {
        limits.validate()?;
        let actual = encode(state)?;
        if actual != *snapshot.values {
            return Err("COMMITMENT_PARENT");
        }
        if snapshot.root != expected_root {
            return Err("COMMITMENT_ROOT");
        }
        Ok(CheckedExecutionParent {
            state,
            actual: Arc::new(actual),
            predecessor: Some(snapshot.clone()),
            limits,
        })
    }

    #[test]
    fn warm_parent_binding_shares_only_after_complete_actual_comparison() {
        let (state, cfg, raws) = preview_fixture();
        let root = pon_executor::root(&state).unwrap();
        let snapshot = checked_snapshot(&state, root, None, CacheLimits::default())
            .unwrap()
            .snapshot
            .unwrap();
        for limits in [
            CacheLimits::default(),
            CacheLimits {
                max_keys: 0,
                max_payload_bytes: 0,
                max_workspace_charge_bytes: 0,
            },
        ] {
            let parent =
                CheckedExecutionParent::bind(&state, root, Some(&snapshot), limits).unwrap();
            let copied = copying_parent_reference(&state, root, &snapshot, limits).unwrap();
            assert!(Arc::ptr_eq(&parent.actual, &snapshot.values));
            assert!(!Arc::ptr_eq(&copied.actual, &snapshot.values));
            assert_eq!(parent.actual.as_ref(), copied.actual.as_ref());
            for workers in [1, 4] {
                let expected =
                    pon_executor::execute(&state, &raws, 1, [3; 32], [4; 32], workers, &cfg)
                        .unwrap();
                let request = || ExecutionRequest {
                    transactions: &raws,
                    height: 1,
                    miner: [3; 32],
                    parent_id: [4; 32],
                    workers,
                };
                let result = parent.execute(request(), &cfg).unwrap();
                let reference = copied.execute(request(), &cfg).unwrap();
                assert_eq!(result.output.state, expected.state);
                assert_eq!(result.output.receipts, expected.receipts);
                assert_eq!(result.output.root, expected.root);
                assert_eq!(result.commitment.root, expected.root);
                assert_eq!(
                    result.commitment.changes.len(),
                    reference.commitment.changes.len()
                );
                for (actual, expected) in result
                    .commitment
                    .changes
                    .iter()
                    .zip(&reference.commitment.changes)
                {
                    assert_eq!(actual.key, expected.key);
                    assert_eq!(actual.before, expected.before);
                    assert_eq!(actual.after, expected.after);
                }
                assert_eq!(
                    result.commitment.observation,
                    reference.commitment.observation
                );
                assert_eq!(parent.actual.as_ref(), &encode(&state).unwrap());
                assert!(Arc::ptr_eq(&parent.actual, &snapshot.values));
            }
        }
        for change in 0..3 {
            let mut actual = state.clone();
            match change {
                0 => {
                    actual.remove("model:current");
                }
                1 => {
                    actual.insert("extra-key".into(), json!(0));
                }
                _ => {
                    actual.insert("meta:issued".into(), json!(1));
                }
            }
            assert!(matches!(
                CheckedExecutionParent::bind(
                    &actual,
                    root,
                    Some(&snapshot),
                    CacheLimits::default()
                ),
                Err("COMMITMENT_PARENT")
            ));
        }
        assert_eq!(snapshot.root(), root);
        assert_eq!(snapshot.values.as_ref(), &encode(&state).unwrap());
    }

    #[test]
    fn warm_parent_binding_preserves_late_canonical_limits_and_context_error_order() {
        let (state, _, _) = preview_fixture();
        let root = pon_executor::root(&state).unwrap();
        let snapshot = checked_snapshot(&state, root, None, CacheLimits::default())
            .unwrap()
            .snapshot
            .unwrap();
        let check = |actual: &State, expected_root: Hash, limits, expected| {
            let observed =
                CheckedExecutionParent::bind(actual, expected_root, Some(&snapshot), limits).err();
            let reference =
                copying_parent_reference(actual, expected_root, &snapshot, limits).err();
            assert_eq!(observed, Some(expected));
            assert_eq!(observed, reference);
        };
        let limits = CacheLimits::default();
        check(&state, [9; 32], limits, "COMMITMENT_ROOT");
        let mut actual = state.clone();
        actual.insert("a-first-mismatch".into(), json!(0));
        check(&actual, [9; 32], limits, "COMMITMENT_PARENT");
        actual.insert("a".repeat(161), json!(0));
        check(&actual, [9; 32], limits, "LIMIT");
        actual.insert("zz-late".into(), json!("非ASCII"));
        check(&actual, [9; 32], limits, "NONCANONICAL");
        actual.insert("zz-late".into(), json!(1.5));
        check(&actual, [9; 32], limits, "RANGE");
        check(
            &actual,
            [9; 32],
            CacheLimits {
                max_keys: MAX_CACHE_KEYS + 1,
                ..limits
            },
            "COMMITMENT_CACHE_LIMIT",
        );

        let boundary = State::from([("k".repeat(160), json!("x".repeat(4094)))]);
        let boundary_root = pon_executor::root(&boundary).unwrap();
        let boundary_snapshot = checked_snapshot(&boundary, boundary_root, None, limits)
            .unwrap()
            .snapshot
            .unwrap();
        let bound = CheckedExecutionParent::bind(
            &boundary,
            boundary_root,
            Some(&boundary_snapshot),
            limits,
        )
        .unwrap();
        assert!(Arc::ptr_eq(&bound.actual, &boundary_snapshot.values));
        // A 4,097-byte canonical value fails after the complete canonical pass.
        let mut oversized = boundary.clone();
        oversized.insert("k".repeat(160), json!("x".repeat(4095)));
        check(&oversized, [9; 32], limits, "LIMIT");
        oversized.insert("zz-late".into(), json!("非ASCII"));
        check(&oversized, [9; 32], limits, "NONCANONICAL");

        // Distinguish the inclusive protocol key ceiling from unrelated-cache
        // rejection without treating this generic shape as a reachable ledger.
        let mut crowded: State = (0..65_536)
            .map(|index| (format!("k{index:05}"), json!(0)))
            .collect();
        check(&crowded, [9; 32], limits, "COMMITMENT_PARENT");
        crowded.insert("k65536".into(), json!(0));
        check(&crowded, [9; 32], limits, "LIMIT");
        crowded.insert("zz-late".into(), json!("非ASCII"));
        check(&crowded, [9; 32], limits, "NONCANONICAL");
        assert_eq!(snapshot.values.as_ref(), &encode(&state).unwrap());
    }

    #[test]
    fn warm_parent_binding_cancellation_preserves_shared_bytes_and_successful_retry() {
        let (state, cfg, raws) = preview_fixture();
        let root = pon_executor::root(&state).unwrap();
        let snapshot = checked_snapshot(&state, root, None, CacheLimits::default())
            .unwrap()
            .snapshot
            .unwrap();
        let parent =
            CheckedExecutionParent::bind(&state, root, Some(&snapshot), CacheLimits::default())
                .unwrap();
        let expected = pon_executor::execute(&state, &raws, 1, [3; 32], [4; 32], 1, &cfg).unwrap();
        for point in [
            ExecutionProgress::AfterCommitment,
            ExecutionProgress::BeforeOutput,
        ] {
            let request = || ExecutionRequest {
                transactions: &raws,
                height: 1,
                miner: [3; 32],
                parent_id: [4; 32],
                workers: 1,
            };
            let cancelled = parent.execute_with_progress(request(), &cfg, &|observed| {
                if observed == point {
                    Err("COMMITMENT_ROOT")
                } else {
                    Ok(())
                }
            });
            assert!(matches!(
                cancelled,
                Err(ExecutionError::Cancelled("COMMITMENT_ROOT"))
            ));
            assert!(Arc::ptr_eq(&parent.actual, &snapshot.values));
            assert_eq!(parent.actual.as_ref(), &encode(&state).unwrap());
            assert_eq!(snapshot.root(), root);
            let retry = parent.execute(request(), &cfg).unwrap();
            assert_eq!(retry.output.state, expected.state);
            assert_eq!(retry.output.receipts, expected.receipts);
            assert_eq!(retry.output.root, expected.root);
        }
    }

    #[test]
    #[ignore = "explicit binding A/B timing; excludes execution, SQLite and Node locks"]
    fn warm_parent_binding_component_timing() {
        use std::time::Instant;
        const BINDINGS_PER_SAMPLE: usize = 16;
        for inert_keys in [64, 512, 4096] {
            let (mut state, cfg, raws) = preview_fixture();
            for index in 0..inert_keys {
                state.insert(format!("inert:{index:05}"), json!("x".repeat(128)));
            }
            let root = pon_executor::root(&state).unwrap();
            let snapshot = checked_snapshot(&state, root, None, CacheLimits::default())
                .unwrap()
                .snapshot
                .unwrap();
            let copied =
                copying_parent_reference(&state, root, &snapshot, CacheLimits::default()).unwrap();
            let shared =
                CheckedExecutionParent::bind(&state, root, Some(&snapshot), CacheLimits::default())
                    .unwrap();
            assert!(!Arc::ptr_eq(&copied.actual, &snapshot.values));
            assert!(Arc::ptr_eq(&shared.actual, &snapshot.values));
            assert_eq!(copied.actual.as_ref(), shared.actual.as_ref());
            let expected =
                pon_executor::execute(&state, &raws, 1, [3; 32], [4; 32], 1, &cfg).unwrap();
            for parent in [&copied, &shared] {
                let result = parent
                    .execute(
                        ExecutionRequest {
                            transactions: &raws,
                            height: 1,
                            miner: [3; 32],
                            parent_id: [4; 32],
                            workers: 1,
                        },
                        &cfg,
                    )
                    .unwrap();
                assert_eq!(result.output.state, expected.state);
                assert_eq!(result.output.receipts, expected.receipts);
                assert_eq!(result.output.root, expected.root);
            }
            drop(copied);
            drop(shared);
            let mut samples: [Vec<u128>; 2] = Default::default();
            for sample in 0usize..8 {
                for offset in 0..2 {
                    let arm = (sample + offset) % 2;
                    let start = Instant::now();
                    for _ in 0..BINDINGS_PER_SAMPLE {
                        let bound = if arm == 0 {
                            copying_parent_reference(
                                &state,
                                root,
                                &snapshot,
                                CacheLimits::default(),
                            )
                        } else {
                            CheckedExecutionParent::bind(
                                &state,
                                root,
                                Some(&snapshot),
                                CacheLimits::default(),
                            )
                        }
                        .unwrap();
                        std::hint::black_box(&bound);
                        // Destruction of this operation's binding is part of both clocks.
                        drop(bound);
                    }
                    samples[arm].push(start.elapsed().as_nanos());
                }
            }
            println!(
                "{}",
                json!({"schema":"warm-parent-binding-component-v1",
                    "state_keys":state.len(),"canonical_payload_bytes":snapshot.payload_bytes(),
                    "bindings_per_sample":BINDINGS_PER_SAMPLE,"samples_per_arm":8,
                    "copying_reference_ns":samples[0],"checked_sharing_ns":samples[1],
                    "order":"alternating paired arms; copying first on even sample",
                    "shared_map_identity_checked":true,"complete_bytes_and_execution_parity":true,
                    "new_retained_canonical_keys_per_binding":[state.len(),0],
                    "new_retained_canonical_payload_bytes_per_binding":[snapshot.payload_bytes(),0],
                    "retained_counts_scope":"logical additional complete map only; serialization temporaries remain",
                    "scope":"warm parent binding plus its drop; excludes snapshot seeding, execution, SQLite, Node locks and concurrency",
                    "physical_memory_bound":false,"public_network_ready":false})
            );
        }
    }

    #[test]
    fn controlled_previews_preserve_full_state_receipts_and_canonical_errors_for_all_workers() {
        let (state, cfg, raws) = preview_fixture();
        let initial = state.clone();
        let root = pon_executor::root(&state).unwrap();
        let parent =
            CheckedExecutionParent::bind(&state, root, None, CacheLimits::default()).unwrap();
        let mut bad = raws.last().unwrap().clone();
        *bad.last_mut().unwrap() ^= 1;
        let mut late_bad = raws.clone();
        *late_bad.last_mut().unwrap() = bad.clone();
        let earlier_nonce_error = [raws[1].clone(), bad];
        for workers in [1, 2, 4, 8] {
            for (transactions, expected_error) in [
                (&raws[..], None),
                (&late_bad[..], Some("SIGNATURE")),
                (&earlier_nonce_error[..], Some("NONCE")),
            ] {
                let expected =
                    pon_executor::execute(&state, transactions, 1, [3; 32], [4; 32], workers, &cfg);
                let observed = parent.execute_with_progress(
                    ExecutionRequest {
                        transactions,
                        height: 1,
                        miner: [3; 32],
                        parent_id: [4; 32],
                        workers,
                    },
                    &cfg,
                    &|_| Ok::<_, ()>(()),
                );
                match (expected, observed) {
                    (Ok(expected), Ok(observed)) => {
                        assert_eq!(expected_error, None);
                        assert_eq!(observed.output.state, expected.state);
                        assert_eq!(observed.output.receipts, expected.receipts);
                        assert_eq!(observed.output.root, expected.root);
                        assert_eq!(
                            observed.output.metrics.signature_verifications,
                            expected.metrics.signature_verifications
                        );
                    }
                    (Err(expected), Err(ExecutionError::Relation(observed))) => {
                        assert_eq!(Some(expected), expected_error);
                        assert_eq!(observed, expected)
                    }
                    results => panic!("controlled parity mismatch: {results:?}"),
                }
                assert_eq!(state, initial);
            }
        }
    }

    #[test]
    fn cancelled_prepare_apply_and_staged_root_never_publish_output_or_change_parent() {
        let (state, cfg, raws) = preview_fixture();
        let initial = state.clone();
        let root = pon_executor::root(&state).unwrap();
        let parent =
            CheckedExecutionParent::bind(&state, root, None, CacheLimits::default()).unwrap();
        for workers in [1, 2, 4, 8] {
            for cancel_at in [
                ExecutionProgress::AfterPrepare {
                    index: raws.len() - 1,
                },
                ExecutionProgress::AfterApply {
                    index: raws.len() - 1,
                },
                ExecutionProgress::AfterCommitment,
                ExecutionProgress::BeforeOutput,
            ] {
                let seen = std::sync::atomic::AtomicUsize::new(0);
                let observed = parent.execute_with_progress(
                    ExecutionRequest {
                        transactions: &raws,
                        height: 1,
                        miner: [3; 32],
                        parent_id: [4; 32],
                        workers,
                    },
                    &cfg,
                    &|point| {
                        if point == cancel_at {
                            seen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            Err("local-stop")
                        } else {
                            Ok(())
                        }
                    },
                );
                assert!(matches!(
                    observed,
                    Err(ExecutionError::Cancelled("local-stop"))
                ));
                assert_eq!(seen.load(std::sync::atomic::Ordering::Relaxed), 1);
                assert_eq!(state, initial);
                assert_eq!(pon_executor::root(&state).unwrap(), root);
                // The same immutable binding still performs the complete successful preview.
                let retry = parent
                    .execute(
                        ExecutionRequest {
                            transactions: &raws,
                            height: 1,
                            miner: [3; 32],
                            parent_id: [4; 32],
                            workers,
                        },
                        &cfg,
                    )
                    .unwrap();
                let expected =
                    pon_executor::execute(&state, &raws, 1, [3; 32], [4; 32], workers, &cfg)
                        .unwrap();
                assert_eq!(retry.output.state, expected.state);
                assert_eq!(retry.output.root, expected.root);
                assert_eq!(retry.output.receipts, expected.receipts);
            }
        }
    }

    #[test]
    fn controlled_cancellation_joins_every_started_scoped_worker_before_return() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (state, cfg, raws) = preview_fixture();
        for workers in [2, 4, 8] {
            let started = AtomicUsize::new(0);
            let completed = AtomicUsize::new(0);
            let result = pon_executor::execute_with_progress(
                &state,
                BlockExecution {
                    transactions: &raws,
                    height: 1,
                    miner: [3; 32],
                    parent_id: [4; 32],
                    workers,
                },
                &cfg,
                &|point| {
                    if let ExecutionProgress::BeforePrepare { index } = point {
                        if index < workers {
                            started.fetch_add(1, Ordering::AcqRel);
                            if index == 0 {
                                return Err("first-worker-cancel");
                            }
                            // Other real workers finish after the first worker has failed.
                            std::thread::sleep(std::time::Duration::from_millis(2));
                            completed.fetch_add(1, Ordering::Release);
                        }
                    }
                    Ok(())
                },
            );
            assert!(matches!(
                result,
                Err(ExecutionError::Cancelled("first-worker-cancel"))
            ));
            assert_eq!(started.load(Ordering::Acquire), workers);
            assert_eq!(completed.load(Ordering::Acquire), workers - 1);
        }
    }

    #[derive(Default)]
    struct AccountedWorkers {
        spawned: std::sync::atomic::AtomicUsize,
        started: std::sync::atomic::AtomicUsize,
        finished: std::sync::atomic::AtomicUsize,
        refuse_spawn_at: Option<usize>,
    }
    struct AccountedInterval<'a>(&'a AccountedWorkers, std::thread::ThreadId);
    impl pon_executor::ExecutionWorkerInterval for AccountedInterval<'_> {}
    impl Drop for AccountedInterval<'_> {
        fn drop(&mut self) {
            assert_eq!(self.1, std::thread::current().id());
            self.0
                .finished
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        }
    }
    impl pon_executor::ExecutionWorkerAccounting for AccountedWorkers {
        fn worker_started(&self) -> Option<Box<dyn pon_executor::ExecutionWorkerInterval + '_>> {
            self.started
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            Some(Box::new(AccountedInterval(
                self,
                std::thread::current().id(),
            )))
        }
        fn worker_spawn_succeeded(&self) {
            self.spawned
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        }
        fn test_spawn_allowed(&self, index: usize) -> bool {
            self.refuse_spawn_at != Some(index)
        }
    }
    impl AccountedWorkers {
        fn assert_closed(&self, count: usize) {
            use std::sync::atomic::Ordering;
            assert_eq!(self.spawned.load(Ordering::Acquire), count);
            assert_eq!(self.started.load(Ordering::Acquire), count);
            assert_eq!(self.finished.load(Ordering::Acquire), count);
        }
    }
    #[test]
    fn scoped_accounting_preserves_all_workers_state_receipts_and_late_error_parity() {
        let (state, cfg, raws) = preview_fixture();
        let parent = CheckedExecutionParent::bind(
            &state,
            pon_executor::root(&state).unwrap(),
            None,
            CacheLimits::default(),
        )
        .unwrap();
        let mut invalid = raws.clone();
        *invalid.last_mut().unwrap().last_mut().unwrap() ^= 1;
        for workers in [1, 2, 4, 8] {
            for transactions in [&raws, &invalid] {
                let accounting = AccountedWorkers::default();
                let request = || ExecutionRequest {
                    transactions,
                    height: 1,
                    miner: [3; 32],
                    parent_id: [4; 32],
                    workers,
                };
                let expected = parent.execute(request(), &cfg);
                let measured = parent.execute_with_accounting(request(), &cfg, &accounting);
                match (expected, measured) {
                    (Ok(a), Ok(b)) => {
                        assert_eq!(a.output.state, b.output.state);
                        assert_eq!(a.output.receipts, b.output.receipts);
                        assert_eq!(a.output.root, b.output.root);
                        assert_eq!(
                            a.output.metrics.signature_verifications,
                            b.output.metrics.signature_verifications
                        );
                    }
                    (Err(a), Err(b)) => assert_eq!(a, b),
                    values => panic!("accounting changed canonical result: {values:?}"),
                }
                accounting.assert_closed(if workers == 1 { 0 } else { workers });
            }
        }
    }
    #[test]
    fn cancelled_panicked_and_partially_started_workers_all_finish_and_join() {
        let (state, cfg, raws) = preview_fixture();
        let initial = state.clone();
        for mode in 0..3 {
            let accounting = AccountedWorkers {
                refuse_spawn_at: (mode == 2).then_some(2),
                ..AccountedWorkers::default()
            };
            let result = pon_executor::execute_with_control(
                &state,
                BlockExecution {
                    transactions: &raws,
                    height: 1,
                    miner: [3; 32],
                    parent_id: [4; 32],
                    workers: 4,
                },
                &cfg,
                &pon_executor::ExecutionControl::new(
                    &|point| {
                        if point == (ExecutionProgress::BeforePrepare { index: 0 }) {
                            if mode == 0 {
                                return Err("local-cancel");
                            }
                            if mode == 1 {
                                panic!("test worker unwind");
                            }
                        }
                        Ok(())
                    },
                    &accounting,
                ),
            );
            match mode {
                0 => assert!(matches!(
                    result,
                    Err(ExecutionError::Cancelled("local-cancel"))
                )),
                1 => assert!(matches!(
                    result,
                    Err(ExecutionError::Relation("WORKER_PANIC"))
                )),
                _ => assert!(matches!(
                    result,
                    Err(ExecutionError::Relation("WORKER_START"))
                )),
            }
            // The injected third-spawn refusal joins two genuine earlier workers.
            accounting.assert_closed(if mode == 2 { 2 } else { 4 });
            assert_eq!(state, initial);
        }
    }

    #[test]
    fn immutable_parent_previews_match_full_execution_including_failures_and_rebind() {
        let (state, cfg, raws) = preview_fixture();
        let root = pon_executor::root(&state).unwrap();
        for limits in [
            CacheLimits::default(),
            CacheLimits {
                max_keys: 0,
                max_payload_bytes: 0,
                max_workspace_charge_bytes: 0,
            },
        ] {
            let checked = checked_snapshot(&state, root, None, limits).unwrap();
            let parent =
                CheckedExecutionParent::bind(&state, root, checked.snapshot.as_ref(), limits)
                    .unwrap();
            let mut cases = (0..=raws.len())
                .map(|n| raws[..n].to_vec())
                .collect::<Vec<_>>();
            cases.push(vec![raws[1].clone()]); // nonce failure
            let mut invalid = raws[0].clone();
            *invalid.last_mut().unwrap() ^= 1;
            cases.push(vec![invalid.clone()]); // signature failure
            cases.push(vec![raws[1].clone(), invalid]); // first error precedence
            cases.push(vec![vec![0; 2049]]);
            for transactions in cases {
                let expected =
                    pon_executor::execute(&state, &transactions, 1, [3; 32], [4; 32], 1, &cfg);
                let actual = parent.execute(
                    ExecutionRequest {
                        transactions: &transactions,
                        height: 1,
                        miner: [3; 32],
                        parent_id: [4; 32],
                        workers: 1,
                    },
                    &cfg,
                );
                match (expected, actual) {
                    (Ok(expected), Ok(actual)) => {
                        assert_eq!(actual.output.state, expected.state);
                        assert_eq!(actual.output.root, expected.root);
                        assert_eq!(actual.output.receipts, expected.receipts);
                        assert_eq!(
                            actual.output.metrics.signature_verifications,
                            expected.metrics.signature_verifications
                        );
                    }
                    (Err(expected), Err(actual)) => assert_eq!(actual, expected),
                    results => panic!("differential mismatch: {results:?}"),
                }
            }
            assert_eq!(pon_executor::root(&state).unwrap(), root);
            let mut changed = state.clone();
            changed.insert("meta:issued".into(), json!(0));
            assert!(CheckedExecutionParent::bind(
                &changed,
                root,
                checked.snapshot.as_ref(),
                limits
            )
            .is_err());
            assert!(CheckedExecutionParent::bind(
                &state,
                [9; 32],
                checked.snapshot.as_ref(),
                limits
            )
            .is_err());
            // Cold binding needs no retained snapshot or previous successful preview.
            CheckedExecutionParent::bind(&state, root, None, limits).unwrap();
        }
    }

    #[test]
    fn immutable_parent_corrupt_tree_fallback_matches_full_execution() {
        let (state, cfg, raws) = preview_fixture();
        let root = pon_executor::root(&state).unwrap();
        let mut snapshot = checked_snapshot(&state, root, None, CacheLimits::default())
            .unwrap()
            .snapshot
            .unwrap();
        snapshot.tree = StateTree::default();
        let parent =
            CheckedExecutionParent::bind(&state, root, Some(&snapshot), CacheLimits::default())
                .unwrap();
        let expected = pon_executor::execute(&state, &raws, 1, [3; 32], [4; 32], 1, &cfg).unwrap();
        let actual = parent
            .execute(
                ExecutionRequest {
                    transactions: &raws,
                    height: 1,
                    miner: [3; 32],
                    parent_id: [4; 32],
                    workers: 1,
                },
                &cfg,
            )
            .unwrap();
        assert_eq!(actual.output.root, expected.root);
        assert_eq!(actual.output.state, expected.state);
        assert_eq!(actual.output.receipts, expected.receipts);
        assert_eq!(
            actual.commitment.observation.method,
            CommitmentMethod::FullRoot(FullRootReason::InternalSnapshotMismatch)
        );
        assert!(snapshot.tree.is_empty());
    }

    #[test]
    #[ignore = "explicit component timing; excludes SQLite, M05 and Node lock wait"]
    fn immutable_parent_preview_component_timing() {
        use std::time::Instant;
        let (mut state, cfg, raws) = preview_fixture();
        for n in 0..4096 {
            state.insert(format!("inert:{n:05}"), json!("x".repeat(128)));
        }
        let root = pon_executor::root(&state).unwrap();
        let seed = checked_snapshot(&state, root, None, CacheLimits::default()).unwrap();
        let mut samples: [Vec<u128>; 4] = Default::default();
        let expected: Vec<_> = (1..=raws.len())
            .map(|n| {
                pon_executor::execute(&state, &raws[..n], 1, [3; 32], [4; 32], 1, &cfg)
                    .unwrap()
                    .root
            })
            .collect();
        for sample in 0usize..8 {
            // Rotate all four arms so cold/warm and fresh/bound do not always
            // receive the same cache/thermal/order advantage.
            for offset in 0..4 {
                let arm = (sample + offset) % 4;
                let prior = if arm >= 2 {
                    seed.snapshot.as_ref()
                } else {
                    None
                };
                let start = Instant::now();
                if arm.is_multiple_of(2) {
                    for n in 1..=raws.len() {
                        let checked =
                            checked_snapshot(&state, root, prior, CacheLimits::default()).unwrap();
                        let actual = execute_checked(
                            &state,
                            root,
                            checked.snapshot.as_ref(),
                            ExecutionRequest {
                                transactions: &raws[..n],
                                height: 1,
                                miner: [3; 32],
                                parent_id: [4; 32],
                                workers: 1,
                            },
                            &cfg,
                            CacheLimits::default(),
                        )
                        .unwrap();
                        assert_eq!(actual.output.root, expected[n - 1]);
                    }
                } else {
                    let checked =
                        checked_snapshot(&state, root, prior, CacheLimits::default()).unwrap();
                    let parent = CheckedExecutionParent::bind(
                        &state,
                        root,
                        checked.snapshot.as_ref(),
                        CacheLimits::default(),
                    )
                    .unwrap();
                    for n in 1..=raws.len() {
                        let actual = parent
                            .execute(
                                ExecutionRequest {
                                    transactions: &raws[..n],
                                    height: 1,
                                    miner: [3; 32],
                                    parent_id: [4; 32],
                                    workers: 1,
                                },
                                &cfg,
                            )
                            .unwrap();
                        assert_eq!(actual.output.root, expected[n - 1]);
                    }
                }
                samples[arm].push(start.elapsed().as_nanos());
            }
        }
        println!(
            "{}",
            serde_json::json!({"schema":"immutable-parent-preview-component-v1",
            "state_keys":state.len(),"prefixes":raws.len(),"samples_per_arm":8,
            "cold_fresh_check_each_prefix_ns":samples[0],"cold_operation_bound_ns":samples[1],
            "warm_fresh_check_each_prefix_ns":samples[2],"warm_operation_bound_ns":samples[3],
            "order":"four rotating arms",
            "scope":"complete signed M06 prefixes and commitments; excludes M05, SQLite, Node lock wait and concurrency",
            "physical_memory_bound":false,"public_network_ready":false})
        );
    }

    #[test]
    fn disjoint_delta_exact_and_overflow_preserve_full_state_and_allocation_order() {
        let old: State = (0..32768).map(|i| (format!("a{i:05}"), json!(0))).collect();
        let root = pon_executor::root(&old).unwrap();
        let base = checked_snapshot(&old, root, None, CacheLimits::default()).unwrap();
        for (count, method) in [
            (32768, CommitmentMethod::CheckedApply),
            (
                32769,
                CommitmentMethod::FullRoot(FullRootReason::DeltaBudget),
            ),
        ] {
            let new: State = (0..count).map(|i| (format!("b{i:05}"), json!(0))).collect();
            let expected = pon_executor::root(&new).unwrap();
            ALLOCATION_STAGES.with(|stages| stages.borrow_mut().clear());
            let result = checked_snapshot(
                &new,
                expected,
                base.snapshot.as_ref(),
                CacheLimits::default(),
            )
            .unwrap();
            let stages = ALLOCATION_STAGES.with(|stages| stages.borrow().clone());
            assert_eq!(result.observation.method, method);
            assert_eq!(result.changes.len(), 32768 + count);
            assert_eq!(result.root, expected);
            let expected_stages = if count == 32768 {
                ["budget-selected", "changes-allocation", "tree-allocation"]
            } else {
                [
                    "budget-selected",
                    "full-root-completed",
                    "changes-allocation",
                ]
            };
            assert_eq!(stages, expected_stages);
            let before = encode(&old).unwrap();
            let after = encode(&new).unwrap();
            let keys: std::collections::BTreeSet<_> = before.keys().chain(after.keys()).collect();
            let reference: Vec<_> = keys
                .into_iter()
                .map(|key| {
                    (
                        key.clone(),
                        before.get(key).cloned(),
                        after.get(key).cloned(),
                    )
                })
                .collect();
            let actual: Vec<_> = result
                .changes
                .iter()
                .map(|change| {
                    (
                        change.key.clone(),
                        change.before.clone(),
                        change.after.clone(),
                    )
                })
                .collect();
            assert_eq!(actual, reference);
            if count == 32769 {
                let resource_first = checked_snapshot(
                    &new,
                    expected,
                    base.snapshot.as_ref(),
                    CacheLimits {
                        max_workspace_charge_bytes: 1,
                        ..CacheLimits::default()
                    },
                )
                .unwrap();
                assert_eq!(
                    resource_first.observation.method,
                    CommitmentMethod::FullRoot(FullRootReason::WorkspaceBudget)
                );
                // No retained tree means rebuild, without StateTree::apply's batch limit.
                let rebuilt =
                    checked_snapshot(&new, expected, None, CacheLimits::default()).unwrap();
                assert_eq!(rebuilt.observation.method, CommitmentMethod::RebuiltTree);
            }
            println!(
                "{}",
                json!({"case":"disjoint-delta-allocation-order", "changed_keys":result.changes.len(),"method":format!("{:?}",method),"stages":stages,"complete_root_and_delta_parity":true})
            );
        }
        assert_eq!(base.snapshot.as_ref().unwrap().root(), root);
    }

    #[test]
    fn resource_fallback_finishes_full_root_before_required_change_clones() {
        let old: State = (0..32)
            .map(|i| (format!("k{i:04}"), json!("x".repeat(4000))))
            .collect();
        let new: State = (0..32)
            .map(|i| (format!("k{i:04}"), json!("y".repeat(4000))))
            .collect();
        let old_root = pon_executor::root(&old).unwrap();
        let expected = pon_executor::root(&new).unwrap();
        let base = checked_snapshot(&old, old_root, None, CacheLimits::default()).unwrap();
        ALLOCATION_STAGES.with(|stages| stages.borrow_mut().clear());
        let fallback = checked_snapshot(
            &new,
            expected,
            base.snapshot.as_ref(),
            CacheLimits {
                max_workspace_charge_bytes: 1,
                ..CacheLimits::default()
            },
        )
        .unwrap();
        let fallback_stages = ALLOCATION_STAGES.with(|stages| stages.borrow().clone());
        assert_eq!(
            fallback_stages,
            [
                "budget-selected",
                "full-root-completed",
                "changes-allocation"
            ]
        );
        assert_eq!(fallback.root, expected);
        assert!(fallback.snapshot.is_none());
        assert_eq!(fallback.changes.len(), 32);
        assert_eq!(fallback.observation.changed_keys, 32);
        assert_eq!(
            fallback.observation.changed_payload_bytes,
            32 * (5 + 4002 * 2)
        );
        // Independent old union algorithm checks the entire returned public delta.
        let before = encode(&old).unwrap();
        let after = encode(&new).unwrap();
        let keys: std::collections::BTreeSet<_> = before.keys().chain(after.keys()).collect();
        let reference: Vec<_> = keys
            .into_iter()
            .filter(|key| before.get(*key) != after.get(*key))
            .map(|key| {
                (
                    key.clone(),
                    before.get(key).cloned(),
                    after.get(key).cloned(),
                )
            })
            .collect();
        let actual: Vec<_> = fallback
            .changes
            .iter()
            .map(|change| {
                (
                    change.key.clone(),
                    change.before.clone(),
                    change.after.clone(),
                )
            })
            .collect();
        assert_eq!(actual, reference);
        ALLOCATION_STAGES.with(|stages| stages.borrow_mut().clear());
        let cached = checked_snapshot(
            &new,
            expected,
            base.snapshot.as_ref(),
            CacheLimits::default(),
        )
        .unwrap();
        let cached_stages = ALLOCATION_STAGES.with(|stages| stages.borrow().clone());
        assert_eq!(
            cached_stages,
            ["budget-selected", "changes-allocation", "tree-allocation"]
        );
        assert_eq!(cached.root, expected);
        assert_eq!(
            cached.observation.changed_payload_bytes,
            fallback.observation.changed_payload_bytes
        );
        assert_eq!(base.snapshot.as_ref().unwrap().root(), old_root);
        println!(
            "resource-allocation-order-control: {}",
            serde_json::json!({"fallback":fallback_stages,"cached":cached_stages,
                "changed_keys":32,"logical_change_bytes":fallback.observation.changed_payload_bytes,
                "allocator_or_RSS_measurement":false})
        );
    }

    #[test]
    fn late_canonical_error_precedes_cache_choice_and_all_change_clones() {
        let mut state = State::from([("a".into(), json!("x".repeat(4000)))]);
        let root = pon_executor::root(&state).unwrap();
        let prior = checked_snapshot(&state, root, None, CacheLimits::default()).unwrap();
        state.insert("zz-late".into(), json!("非ASCII"));
        ALLOCATION_STAGES.with(|stages| stages.borrow_mut().clear());
        assert_eq!(
            checked_snapshot(
                &state,
                root,
                prior.snapshot.as_ref(),
                CacheLimits {
                    max_keys: 0,
                    max_payload_bytes: 0,
                    max_workspace_charge_bytes: 0,
                }
            )
            .unwrap_err(),
            pon_executor::root(&state).unwrap_err()
        );
        assert!(ALLOCATION_STAGES.with(|stages| stages.borrow().is_empty()));
        assert_eq!(prior.snapshot.as_ref().unwrap().root(), root);
    }

    #[test]
    fn internal_tree_mismatch_uses_complete_root_without_mutating_snapshot() {
        let state = State::from([("real".into(), json!(7))]);
        let expected = pon_executor::root(&state).unwrap();
        let mut snapshot = checked_snapshot(&state, expected, None, CacheLimits::default())
            .unwrap()
            .snapshot
            .unwrap();
        snapshot.tree = StateTree::default();
        let fallback =
            checked_snapshot(&state, expected, Some(&snapshot), CacheLimits::default()).unwrap();
        assert_eq!(fallback.root, expected);
        assert_eq!(
            fallback.observation.method,
            CommitmentMethod::FullRoot(FullRootReason::InternalSnapshotMismatch)
        );
        assert!(fallback.snapshot.is_none());
        assert!(snapshot.tree.is_empty());
        let mut corrupted_actual = state;
        corrupted_actual.insert("real".into(), json!(8));
        assert_eq!(
            checked_snapshot(
                &corrupted_actual,
                expected,
                Some(&snapshot),
                CacheLimits::default()
            )
            .unwrap_err(),
            "COMMITMENT_ROOT"
        );
    }
}
