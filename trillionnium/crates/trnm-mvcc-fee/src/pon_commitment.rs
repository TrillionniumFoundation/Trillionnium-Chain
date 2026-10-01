//! Pure derived commitment computation for the existing PoN executor.
//!
//! Every call encodes the complete actual State. A snapshot is neither a state
//! setter nor a transaction/admission verdict. The caller must still read actual
//! KV, check its committed root and publish any staged snapshot only after its
//! own durable commit. Cache limits select the unchanged full-root algorithm;
//! they never reduce protocol state limits. Charges are software accounting,
//! not a bound on process RSS or allocations in the executor/SQLite/proof code.
use crate::pon_executor::{self, BlockExecution, Config, Output, Result, State};
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
    // replaces an Arc. Full maps/diffs are still encoded/checked on every call.
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
    limits.validate()?;
    let actual = encode(actual_parent)?;
    if let Some(snapshot) = predecessor {
        if actual != *snapshot.values {
            return Err("COMMITMENT_PARENT");
        }
        if snapshot.root != expected_parent_root {
            return Err("COMMITMENT_ROOT");
        }
    } else if state_root(&actual).map_err(|_| "LIMIT")? != expected_parent_root {
        return Err("COMMITMENT_ROOT");
    }
    let mut staged = None;
    let output = pon_executor::execute_with_commitment(
        actual_parent,
        BlockExecution {
            transactions: request.transactions,
            height: request.height,
            miner: request.miner,
            parent_id: request.parent_id,
            workers: request.workers,
        },
        config,
        |_, after| {
            let prepared = prepare_values(encode(after)?, predecessor, Some(&actual), limits)?;
            let root = prepared.root;
            staged = Some(prepared);
            Ok(root)
        },
    )?;
    Ok(StagedOutput {
        output,
        commitment: staged.ok_or("COMMITMENT_STAGED")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
