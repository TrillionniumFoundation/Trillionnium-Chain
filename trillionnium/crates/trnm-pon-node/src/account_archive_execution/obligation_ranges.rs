//! Complete monetary namespace ranges in a separate, ordered research index.
//!
//! The existing sparse state roots are unchanged. A private operation-local
//! index is rebuilt from the already checked complete parent partition. Its
//! ordering and leaf count are therefore source facts, not proof-supplied
//! assertions. Revealed ranks plus adjacent boundary leaves prove every row in
//! all four monetary namespaces, including future and zero-valued obligations.
//! The other non-account rules still require the complete parent reference.
use super::state_witness::{BoundState, StateWitnessProgress};
use super::{prepare_state_witness, CheckedExecutionError, Result};
use crate::account_archive_prototype::{AccountArchive, Checkpoint};
use crate::Settings;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::io::Write;
use trnm_mvcc_fee::pon_executor::{self, State};
use trnm_protocol::pon_wire::{hash, Hash};

pub const SCHEMA: &str = "pon-monetary-obligation-range-v1";
pub const MAX_ROWS: usize = 65_536;
const MAX_KEY_BYTES: usize = 160;
const MAX_VALUE_BYTES: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RangeError {
    Context,
    Bounds,
    RowOrder,
    Frontier,
    Root,
    Boundary,
    ExtraRow,
    Encoding,
}
impl From<RangeError> for CheckedExecutionError {
    fn from(value: RangeError) -> Self {
        Self::ObligationRange(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RankedRow {
    pub rank: u32,
    pub key: String,
    pub value: Value,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Frontier {
    pub first: u32,
    pub count: u32,
    pub digest: Hash,
}
/// Untrusted data. Neither deserialization nor a self-consistent index root
/// constructs the private checked monetary input consumed by M06.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RangeProof {
    pub schema: String,
    pub parent_checkpoint: Hash,
    pub parent_id: Hash,
    pub parent_height: u64,
    pub state_commitment: Hash,
    pub non_account_count: u32,
    pub index_root: Hash,
    pub rows: Vec<RankedRow>,
    pub frontier: Vec<Frontier>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RangeObservation {
    pub schema: &'static str,
    pub parent_checkpoint: Hash,
    pub state_commitment: Hash,
    pub index_root: Hash,
    pub complete_non_account_rows: usize,
    pub monetary_rows: usize,
    pub revealed_rows: usize,
    pub boundary_rows: usize,
    pub frontier_nodes: usize,
    pub proof_json_bytes: usize,
    pub index_leaf_hashes: usize,
    pub index_branch_hashes: usize,
    pub verification_leaf_hashes: usize,
    pub verification_branch_hashes: usize,
    pub complete_future_monetary_ranges: bool,
    pub full_parent_anchor_required: bool,
    pub other_non_account_rules_use_full_state: bool,
    pub consensus_admission: bool,
}

struct BoundedBytes(Vec<u8>);
impl Write for BoundedBytes {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.0.len().saturating_add(bytes.len()) > MAX_VALUE_BYTES {
            return Err(std::io::Error::other("monetary range value bound"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn value_bytes(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = BoundedBytes(Vec::new());
    serde_json::to_writer(&mut bytes, value).map_err(|_| RangeError::Bounds)?;
    Ok(bytes.0)
}
/// Borrowed dimensions and row encodings are bounded before full-parent source
/// binding. Decoding allocations remain the responsibility of the caller.
pub(super) fn check_bounds(proof: &RangeProof) -> Result<()> {
    let count = proof.non_account_count as usize;
    if count > MAX_ROWS || proof.rows.len() > count || proof.frontier.len() > count {
        return Err(RangeError::Bounds.into());
    }
    for row in &proof.rows {
        if row.key.len() > MAX_KEY_BYTES || row.rank as usize >= count {
            return Err(RangeError::Bounds.into());
        }
        value_bytes(&row.value)?;
    }
    Ok(())
}
fn leaf(rank: u32, key: &str, value: &Value) -> Result<Hash> {
    Ok(hash(
        b"monetary-obligation-range-leaf-v1",
        &[&rank.to_le_bytes(), key.as_bytes(), &value_bytes(value)?],
    ))
}
fn branch(first: u32, count: u32, left: Hash, right: Hash) -> Hash {
    hash(
        b"monetary-obligation-range-node-v1",
        &[&first.to_le_bytes(), &count.to_le_bytes(), &left, &right],
    )
}
fn empty() -> Hash {
    hash(b"monetary-obligation-range-empty-v1", &[])
}
struct Node {
    first: u32,
    count: u32,
    digest: Hash,
    children: Option<(usize, usize)>,
}
struct Index<'a> {
    rows: Vec<(&'a String, &'a Value)>,
    nodes: Vec<Node>,
    root: Option<usize>,
}
impl<'a> Index<'a> {
    fn build(
        state: &'a State,
        progress: &(impl Fn(StateWitnessProgress) -> Result<()> + Sync + ?Sized),
    ) -> Result<Self> {
        if state.len() > MAX_ROWS || state.keys().any(|key| key.starts_with("account:")) {
            return Err(RangeError::Bounds.into());
        }
        let mut index = Self {
            rows: state.iter().collect(),
            nodes: Vec::with_capacity(state.len().saturating_mul(2).saturating_sub(1)),
            root: None,
        };
        if !state.is_empty() {
            index.root = Some(index.subtree(0, state.len(), progress)?);
        }
        Ok(index)
    }
    fn subtree(
        &mut self,
        first: usize,
        count: usize,
        progress: &(impl Fn(StateWitnessProgress) -> Result<()> + Sync + ?Sized),
    ) -> Result<usize> {
        progress(StateWitnessProgress::ObligationRange {
            index: self.nodes.len(),
        })?;
        let (digest, children) = if count == 1 {
            let (key, value) = self.rows[first];
            (leaf(first as u32, key, value)?, None)
        } else {
            let left_count = count / 2;
            let left = self.subtree(first, left_count, progress)?;
            let right = self.subtree(first + left_count, count - left_count, progress)?;
            (
                branch(
                    first as u32,
                    count as u32,
                    self.nodes[left].digest,
                    self.nodes[right].digest,
                ),
                Some((left, right)),
            )
        };
        let id = self.nodes.len();
        self.nodes.push(Node {
            first: first as u32,
            count: count as u32,
            digest,
            children,
        });
        Ok(id)
    }
    fn digest(&self) -> Hash {
        self.root.map_or_else(empty, |root| self.nodes[root].digest)
    }
    fn reveal(&self) -> BTreeSet<usize> {
        let mut revealed = BTreeSet::new();
        for prefix in pon_executor::MONETARY_OBLIGATION_PREFIXES {
            let end = upper(prefix);
            let first = self.rows.partition_point(|(key, _)| key.as_str() < prefix);
            let after = self
                .rows
                .partition_point(|(key, _)| key.as_str() < end.as_str());
            revealed.extend(first..after);
            if first > 0 {
                revealed.insert(first - 1);
            }
            if after < self.rows.len() {
                revealed.insert(after);
            }
        }
        revealed
    }
    fn frontier(&self, id: usize, revealed: &BTreeSet<usize>, out: &mut Vec<Frontier>) {
        let node = &self.nodes[id];
        let first = node.first as usize;
        let after = first + node.count as usize;
        if revealed.range(first..after).next().is_none() {
            out.push(Frontier {
                first: node.first,
                count: node.count,
                digest: node.digest,
            });
        } else if let Some((left, right)) = node.children {
            self.frontier(left, revealed, out);
            self.frontier(right, revealed, out);
        }
    }
}
// The fixed ASCII prefixes end in ':'. Its byte successor gives the exact
// half-open lexical interval, including arbitrary suffix bytes.
fn upper(prefix: &str) -> String {
    let mut upper = prefix.to_owned();
    upper.pop();
    upper.push(';');
    upper
}

pub fn prepare(
    settings: &Settings,
    archive: &AccountArchive,
    parent_checkpoint: Hash,
    parent_state: &State,
) -> Result<RangeProof> {
    prepare_with_progress(settings, archive, parent_checkpoint, parent_state, &|_| {
        Ok(())
    })
}
pub fn prepare_with_progress(
    settings: &Settings,
    archive: &AccountArchive,
    parent_checkpoint: Hash,
    parent_state: &State,
    progress: &(impl Fn(StateWitnessProgress) -> Result<()> + Sync),
) -> Result<RangeProof> {
    progress(StateWitnessProgress::BeforeBinding)?;
    let state = prepare_state_witness(settings, archive, parent_checkpoint, parent_state)?;
    let partition: State = state
        .non_accounts
        .into_iter()
        .map(|row| (row.key, row.value))
        .collect();
    let index = Index::build(&partition, progress)?;
    let revealed = index.reveal();
    let mut frontier = Vec::new();
    if let Some(root) = index.root {
        index.frontier(root, &revealed, &mut frontier);
    }
    let proof = RangeProof {
        schema: SCHEMA.into(),
        parent_checkpoint,
        parent_id: state.parent_id,
        parent_height: state.parent_height,
        state_commitment: state.commitment.id,
        non_account_count: index.rows.len() as u32,
        index_root: index.digest(),
        rows: revealed
            .into_iter()
            .map(|rank| RankedRow {
                rank: rank as u32,
                key: index.rows[rank].0.clone(),
                value: index.rows[rank].1.clone(),
            })
            .collect(),
        frontier,
    };
    progress(StateWitnessProgress::BeforeOutput)?;
    Ok(proof)
}

struct Verification<'a> {
    proof: &'a RangeProof,
    row: usize,
    frontier: usize,
    branches: usize,
}
impl Verification<'_> {
    fn subtree(
        &mut self,
        first: u32,
        count: u32,
        progress: &(impl Fn(StateWitnessProgress) -> Result<()> + Sync + ?Sized),
    ) -> Result<Hash> {
        progress(StateWitnessProgress::ObligationRange {
            index: self.row + self.frontier + self.branches,
        })?;
        let after = first.checked_add(count).ok_or(RangeError::Bounds)?;
        let next = self.proof.rows.get(self.row);
        if next.is_none_or(|row| row.rank >= after) {
            let frontier = self
                .proof
                .frontier
                .get(self.frontier)
                .ok_or(RangeError::Frontier)?;
            if frontier.first != first || frontier.count != count {
                return Err(RangeError::Frontier.into());
            }
            self.frontier += 1;
            return Ok(frontier.digest);
        }
        if next.is_some_and(|row| row.rank < first) {
            return Err(RangeError::RowOrder.into());
        }
        if count == 1 {
            let row = next.ok_or(RangeError::RowOrder)?;
            self.row += 1;
            leaf(row.rank, &row.key, &row.value)
        } else {
            let left_count = count / 2;
            let left = self.subtree(first, left_count, progress)?;
            let right = self.subtree(first + left_count, count - left_count, progress)?;
            self.branches += 1;
            Ok(branch(first, count, left, right))
        }
    }
}

/// Every matching row must be consecutive in the source ordering. The nearest
/// predecessor/successor must be adjacent too; membership of a supplied subset
/// alone would not prove range completeness. Empty ranges use the same two
/// boundaries (or the actual first/last edge), never an unauthenticated absence.
fn complete_ranges(proof: &RangeProof) -> Result<State> {
    let rows = &proof.rows;
    let mut used = BTreeSet::new();
    let mut monetary = State::new();
    for prefix in pon_executor::MONETARY_OBLIGATION_PREFIXES {
        let end = upper(prefix);
        let first = rows.partition_point(|row| row.key.as_str() < prefix);
        let after = rows.partition_point(|row| row.key.as_str() < end.as_str());
        let mut expected = if first == 0 {
            0
        } else {
            used.insert(first - 1);
            rows[first - 1]
                .rank
                .checked_add(1)
                .ok_or(RangeError::Boundary)?
        };
        for (index, row) in rows.iter().enumerate().take(after).skip(first) {
            if row.rank != expected {
                return Err(RangeError::Boundary.into());
            }
            expected = expected.checked_add(1).ok_or(RangeError::Boundary)?;
            used.insert(index);
            monetary.insert(row.key.clone(), row.value.clone());
        }
        if after == rows.len() {
            if expected != proof.non_account_count {
                return Err(RangeError::Boundary.into());
            }
        } else {
            used.insert(after);
            if rows[after].rank != expected {
                return Err(RangeError::Boundary.into());
            }
        }
    }
    if used.len() != rows.len() {
        return Err(RangeError::ExtraRow.into());
    }
    Ok(monetary)
}

pub(super) struct CheckedRanges {
    pub monetary: State,
    pub observation: RangeObservation,
}
/// This constructor is private to the checked execution owner. The anchor is
/// obtained from BoundState, never from the raw proof's root/count claims.
pub(super) fn verify_bound(
    checkpoint: &Checkpoint,
    state: &BoundState<'_>,
    proof: &RangeProof,
    progress: &(impl Fn(StateWitnessProgress) -> Result<()> + Sync + ?Sized),
) -> Result<CheckedRanges> {
    check_bounds(proof)?;
    if proof.schema != SCHEMA
        || proof.parent_checkpoint != checkpoint.id()
        || proof.parent_id != checkpoint.branch()
        || proof.parent_height != checkpoint.height()
        || proof.state_commitment != state.parent.id
        || proof.non_account_count as usize != state.non_accounts.len()
    {
        return Err(RangeError::Context.into());
    }
    for pair in proof.rows.windows(2) {
        if pair[0].rank >= pair[1].rank || pair[0].key >= pair[1].key {
            return Err(RangeError::RowOrder.into());
        }
    }
    let index = Index::build(&state.non_accounts, progress)?;
    if proof.index_root != index.digest() {
        return Err(RangeError::Root.into());
    }
    let mut verification = Verification {
        proof,
        row: 0,
        frontier: 0,
        branches: 0,
    };
    let root = if proof.non_account_count == 0 {
        empty()
    } else {
        verification.subtree(0, proof.non_account_count, progress)?
    };
    if verification.row != proof.rows.len() || verification.frontier != proof.frontier.len() {
        return Err(RangeError::Frontier.into());
    }
    if root != index.digest() {
        return Err(RangeError::Root.into());
    }
    let monetary = complete_ranges(proof)?;
    Ok(CheckedRanges {
        observation: RangeObservation {
            schema: SCHEMA,
            parent_checkpoint: checkpoint.id(),
            state_commitment: state.parent.id,
            index_root: index.digest(),
            complete_non_account_rows: index.rows.len(),
            monetary_rows: monetary.len(),
            revealed_rows: proof.rows.len(),
            boundary_rows: proof.rows.len() - monetary.len(),
            frontier_nodes: proof.frontier.len(),
            proof_json_bytes: serde_json::to_vec(proof)
                .map_err(|_| RangeError::Encoding)?
                .len(),
            index_leaf_hashes: index.rows.len(),
            index_branch_hashes: index.rows.len().saturating_sub(1),
            verification_leaf_hashes: verification.row,
            verification_branch_hashes: verification.branches,
            complete_future_monetary_ranges: true,
            full_parent_anchor_required: true,
            other_non_account_rules_use_full_state: true,
            consensus_admission: false,
        },
        monetary,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn raw_proof(index: &Index<'_>, revealed: &BTreeSet<usize>) -> RangeProof {
        let mut frontier = Vec::new();
        if let Some(root) = index.root {
            index.frontier(root, revealed, &mut frontier);
        }
        RangeProof {
            schema: SCHEMA.into(),
            parent_checkpoint: [0; 32],
            parent_id: [1; 32],
            parent_height: 0,
            state_commitment: [2; 32],
            non_account_count: index.rows.len() as u32,
            index_root: index.digest(),
            rows: revealed
                .iter()
                .map(|&rank| RankedRow {
                    rank: rank as u32,
                    key: index.rows[rank].0.clone(),
                    value: index.rows[rank].1.clone(),
                })
                .collect(),
            frontier,
        }
    }
    fn membership(proof: &RangeProof) -> Result<Hash> {
        check_bounds(proof)?;
        let mut verifier = Verification {
            proof,
            row: 0,
            frontier: 0,
            branches: 0,
        };
        let result = if proof.non_account_count == 0 {
            empty()
        } else {
            verifier.subtree(0, proof.non_account_count, &|_| Ok(()))?
        };
        if verifier.row != proof.rows.len() || verifier.frontier != proof.frontier.len() {
            return Err(RangeError::Frontier.into());
        }
        Ok(result)
    }

    #[test]
    fn complete_ranges_cover_empty_edges_shared_neighbors_and_retained_unknown_namespaces() {
        for keys in [
            vec![],
            vec!["a"],
            vec!["z"],
            vec!["quota:a"],
            vec![
                "a", "quota", "quota;", "release;", "reward;", "task", "task;", "z",
            ],
            vec![
                "a",
                "quota:a",
                "quota:b",
                "release:a",
                "reward:a",
                "task:a",
                "task:z",
                "z",
            ],
        ] {
            let state: State = keys
                .into_iter()
                .map(|key| (key.into(), Value::Null))
                .collect();
            let index = Index::build(&state, &|_| Ok(())).unwrap();
            let proof = raw_proof(&index, &index.reveal());
            assert_eq!(membership(&proof).unwrap(), index.digest());
            assert_eq!(
                complete_ranges(&proof).unwrap(),
                state
                    .iter()
                    .filter(|(key, _)| pon_executor::is_monetary_obligation(key))
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect()
            );
        }
        let state: State = (0..100)
            .map(|i| (format!("retained:{i:03}"), json!(i)))
            .chain([
                ("task:future".into(), json!({"deadline":100,"remaining":1})),
                ("zzz:unknown".into(), Value::Null),
            ])
            .collect();
        let index = Index::build(&state, &|_| Ok(())).unwrap();
        let proof = raw_proof(&index, &index.reveal());
        assert_eq!(membership(&proof).unwrap(), index.digest());
        assert_eq!(complete_ranges(&proof).unwrap().len(), 1);
        assert!(proof.rows.len() < state.len());
        assert!(!proof.frontier.is_empty());
    }

    #[test]
    fn valid_subset_membership_cannot_omit_due_future_zero_or_neighbor_rows() {
        let state = State::from([
            ("a:retained".into(), Value::Null),
            ("quota:zero".into(), json!({"remaining":0,"deadline":0})),
            (
                "release:current".into(),
                json!({"remaining":2,"deadline":200}),
            ),
            ("reward:future".into(), json!({"amount":3,"maturity":20})),
            ("task:due".into(), json!({"remaining":4,"deadline":1})),
            ("task:future".into(), json!({"remaining":5,"deadline":100})),
            ("z:retained".into(), Value::Null),
        ]);
        let index = Index::build(&state, &|_| Ok(())).unwrap();
        let revealed = index.reveal();
        for &omitted in &revealed {
            let mut fewer = revealed.clone();
            fewer.remove(&omitted);
            let proof = raw_proof(&index, &fewer);
            // This is a valid membership multiproof for exactly the same full
            // root, with the omitted leaf replaced by its true frontier hash.
            assert_eq!(membership(&proof).unwrap(), index.digest());
            assert_eq!(
                complete_ranges(&proof).unwrap_err(),
                RangeError::Boundary.into()
            );
        }
    }

    #[test]
    fn range_frontier_is_maximal_and_extra_authenticated_rows_are_refused() {
        let state: State = (0..32)
            .map(|i| (format!("a:{i:03}"), json!(i)))
            .chain([
                ("task:due".into(), json!({"deadline":1,"remaining":1})),
                ("z".into(), Value::Null),
            ])
            .collect();
        let index = Index::build(&state, &|_| Ok(())).unwrap();
        let revealed = index.reveal();
        let original = raw_proof(&index, &revealed);
        let chosen = original
            .frontier
            .iter()
            .position(|frontier| frontier.count > 1)
            .unwrap();
        let frontier = &original.frontier[chosen];
        let node = index
            .nodes
            .iter()
            .find(|node| node.first == frontier.first && node.count == frontier.count)
            .unwrap();
        let (left, right) = node.children.unwrap();
        let mut split = original.clone();
        split.frontier.splice(
            chosen..=chosen,
            [left, right].into_iter().map(|id| {
                let node = &index.nodes[id];
                Frontier {
                    first: node.first,
                    count: node.count,
                    digest: node.digest,
                }
            }),
        );
        assert_eq!(membership(&split).unwrap_err(), RangeError::Frontier.into());
        let extra = (0..state.len())
            .find(|rank| !revealed.contains(rank))
            .unwrap();
        let mut too_many = revealed;
        too_many.insert(extra);
        let extra = raw_proof(&index, &too_many);
        assert_eq!(membership(&extra).unwrap(), index.digest());
        assert_eq!(
            complete_ranges(&extra).unwrap_err(),
            RangeError::ExtraRow.into()
        );
        let mut oversized = original;
        oversized.rows[0].value = json!("x".repeat(MAX_VALUE_BYTES + 1));
        assert_eq!(
            check_bounds(&oversized).unwrap_err(),
            RangeError::Bounds.into()
        );
    }
}
