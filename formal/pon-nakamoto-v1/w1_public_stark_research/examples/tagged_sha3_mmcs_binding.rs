//! Actual P3 0.8.0 pruned-MMCS two-opening collision reduction checks.
//!
//! The real arm calls the unchanged R1 LeafHasher and BranchCompressor. The
//! deliberately colliding arms are explicitly artificial test oracles. Nothing
//! in this executable is a W1 verifier, profile activation, quantum extractor,
//! or concrete collision-security estimate.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use p3_commit::{BatchOpeningRef, ExtensionMmcs, Mmcs};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use p3_matrix::Dimensions;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::{MerkleTreeMmcs, PrunedBatchOpening};
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};
use serde_json::{Value, json};
use sha3::{Digest, Sha3_512};
use w1_full_public_stark_research::tagged_sha3::{
    BranchCompressor, Challenge, Component, Context, LeafHasher, MerkleDigest, Role, Val, ValMmcs,
    digest_bytes, digest_words, frame_header,
};

const MAX_LOG_HEIGHT: u32 = 20;
const MAX_MATRICES: usize = 64;
const MAX_QUERIES: usize = 64;
const MAX_ROW_WIDTH: usize = 8192;
const MAX_OPENED_FIELDS: usize = 1_048_576;
const SHA3_512_RATE_BYTES: u64 = 72;
const LENGTH_SUFFIX_BYTES: u64 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HashEvaluation {
    CachedPrefixSha3,
    FullMessageSha3,
    ArtificialOverride,
}

impl HashEvaluation {
    fn name(self) -> &'static str {
        match self {
            Self::CachedPrefixSha3 => "native-sha3-cached-prefix",
            Self::FullMessageSha3 => "native-sha3-full-message",
            Self::ArtificialOverride => "artificial-override-NOT-SHA3",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FrameSize {
    header_bytes: u64,
    payload_bytes: u64,
    message_bytes: u64,
    padded_blocks: u64,
}

impl FrameSize {
    fn new(header_bytes: u64, payload_bytes: u64) -> Result<Self, &'static str> {
        let message_bytes = header_bytes
            .checked_add(payload_bytes)
            .and_then(|n| n.checked_add(LENGTH_SUFFIX_BYTES))
            .ok_or("complete frame byte count overflow")?;
        // SHA3 domain suffix and pad10*1 fit in the final rate block, including
        // at rate-1 bytes. Exact multiples need one additional block. Its
        // 64-byte digest fits in the first 72-byte output block.
        let padded_blocks = message_bytes / SHA3_512_RATE_BYTES + 1;
        Ok(Self {
            header_bytes,
            payload_bytes,
            message_bytes,
            padded_blocks,
        })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SpongeTotals {
    whole_message_calls: u64,
    complete_message_bytes: u64,
    complete_message_equivalent_absorption_blocks: u64,
    native_cached_prefix_calls: u64,
    native_cached_prefix_reused_block_equivalents: u64,
    native_cached_prefix_continuation_block_equivalents: u64,
    native_full_message_calls: u64,
    native_full_message_block_equivalents: u64,
    artificial_override_calls: u64,
    artificial_message_block_equivalents: u64,
}

impl SpongeTotals {
    fn with_call(self, call: &SpongeCall) -> Result<Self, &'static str> {
        fn add(target: &mut u64, value: u64) -> Result<(), &'static str> {
            *target = target
                .checked_add(value)
                .ok_or("sponge accounting overflow")?;
            Ok(())
        }
        let mut next = self;
        add(&mut next.whole_message_calls, 1)?;
        add(&mut next.complete_message_bytes, call.frame.message_bytes)?;
        add(
            &mut next.complete_message_equivalent_absorption_blocks,
            call.frame.padded_blocks,
        )?;
        match call.evaluation {
            HashEvaluation::CachedPrefixSha3 => {
                let reused = call.frame.header_bytes / SHA3_512_RATE_BYTES;
                add(&mut next.native_cached_prefix_calls, 1)?;
                add(
                    &mut next.native_cached_prefix_reused_block_equivalents,
                    reused,
                )?;
                add(
                    &mut next.native_cached_prefix_continuation_block_equivalents,
                    call.frame.padded_blocks - reused,
                )?;
            }
            HashEvaluation::FullMessageSha3 => {
                add(&mut next.native_full_message_calls, 1)?;
                add(
                    &mut next.native_full_message_block_equivalents,
                    call.frame.padded_blocks,
                )?;
            }
            HashEvaluation::ArtificialOverride => {
                add(&mut next.artificial_override_calls, 1)?;
                add(
                    &mut next.artificial_message_block_equivalents,
                    call.frame.padded_blocks,
                )?;
            }
        }
        Ok(next)
    }

    fn json(self) -> Value {
        json!({
            "whole_message_calls":self.whole_message_calls,
            "complete_message_bytes":self.complete_message_bytes,
            "complete_message_equivalent_absorption_blocks":self.complete_message_equivalent_absorption_blocks,
            "native_cached_prefix_calls":self.native_cached_prefix_calls,
            "native_cached_prefix_reused_block_equivalents":self.native_cached_prefix_reused_block_equivalents,
            "native_cached_prefix_continuation_block_equivalents":self.native_cached_prefix_continuation_block_equivalents,
            "native_full_message_calls":self.native_full_message_calls,
            "native_full_message_block_equivalents":self.native_full_message_block_equivalents,
            "artificial_override_calls":self.artificial_override_calls,
            "artificial_message_block_equivalents":self.artificial_message_block_equivalents,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SpongeCall {
    role: Role,
    evaluation: HashEvaluation,
    frame: FrameSize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct SpongeAccounting {
    totals: SpongeTotals,
    calls: Vec<SpongeCall>,
}

impl SpongeAccounting {
    fn observe(&mut self, query: &Query, evaluation: HashEvaluation) -> Result<(), &'static str> {
        if !matches!(query.role, Role::Leaf | Role::Branch) {
            return Err("sponge accounting covers only MMCS leaf and branch calls");
        }
        let payload_bytes = query
            .message
            .len()
            .checked_sub(query.header_bytes)
            .and_then(|n| n.checked_sub(LENGTH_SUFFIX_BYTES as usize))
            .ok_or("truncated complete hash frame")?;
        let header_bytes =
            u64::try_from(query.header_bytes).map_err(|_| "header length overflow")?;
        let payload_bytes = u64::try_from(payload_bytes).map_err(|_| "payload length overflow")?;
        let suffix = &query.message[query.message.len() - LENGTH_SUFFIX_BYTES as usize..];
        if u64::from_le_bytes(suffix.try_into().unwrap()) != payload_bytes {
            return Err("hash frame length suffix mismatch");
        }
        let frame = FrameSize::new(header_bytes, payload_bytes)?;
        let call = SpongeCall {
            role: query.role,
            evaluation,
            frame,
        };
        // Compute all checked sums before changing either totals or records.
        // Repeated messages remain repeated calls, even if by_digest deduplicates.
        let next = self.totals.with_call(&call)?;
        self.calls.push(call);
        self.totals = next;
        Ok(())
    }

    fn json(&self) -> Value {
        let calls: Vec<Value> = self
            .calls
            .iter()
            .enumerate()
            .map(|(i, call)| {
                json!({
                    "call":i + 1,
                    "role":format!("{:?}", call.role),
                    "evaluation":call.evaluation.name(),
                    "header_bytes":call.frame.header_bytes,
                    "payload_bytes":call.frame.payload_bytes,
                    "length_suffix_bytes":LENGTH_SUFFIX_BYTES,
                    "complete_message_bytes":call.frame.message_bytes,
                    "complete_message_equivalent_absorption_blocks":call.frame.padded_blocks,
                })
            })
            .collect();
        json!({
            "schema":"p3.tagged-mmcs.sponge-accounting.v1",
            "rate_bytes":SHA3_512_RATE_BYTES,"digest_bytes":64,
            "counting_unit":"complete-message-equivalent-absorption-blocks",
            "prefix_initializations_counted":false,
            "native_permutation_telemetry":false,"native_permutation_calls":null,
            "adversary_lifetime_query_budget":null,"qualified":false,"security_bits":null,
            "totals":self.totals.json(),"calls":calls,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Oracle {
    NativeSha3,
    ArtificialLeafCollision,
    ArtificialBranchCollision,
}

impl Oracle {
    fn name(self) -> &'static str {
        match self {
            Self::NativeSha3 => "unchanged-tagged-sha3-512-r1",
            Self::ArtificialLeafCollision => "artificial-zero-leaf-oracle-NOT-SHA3",
            Self::ArtificialBranchCollision => "artificial-zero-branch-oracle-NOT-SHA3",
        }
    }

    fn overrides(self, role: Role) -> bool {
        matches!(
            (self, role),
            (Self::ArtificialLeafCollision, Role::Leaf)
                | (Self::ArtificialBranchCollision, Role::Branch)
        )
    }

    fn evaluation(self, role: Role, cached_prefix: bool) -> HashEvaluation {
        if self.overrides(role) {
            HashEvaluation::ArtificialOverride
        } else if cached_prefix {
            HashEvaluation::CachedPrefixSha3
        } else {
            HashEvaluation::FullMessageSha3
        }
    }

    fn evaluate_frame(self, role: Role, bytes: &[u8]) -> Context {
        if self.overrides(role) {
            [0; 64]
        } else {
            Sha3_512::digest(bytes).into()
        }
    }
}

#[derive(Clone, Debug)]
struct Query {
    role: Role,
    header_bytes: usize,
    message: Vec<u8>,
    digest: Context,
}

#[derive(Clone, Debug)]
struct Collision {
    first: Query,
    second: Query,
}

impl Collision {
    fn check(&self, oracle: Oracle) -> Result<SpongeAccounting, &'static str> {
        if self.first.message == self.second.message || self.first.digest != self.second.digest {
            return Err("collision witness has equal messages or unequal digests");
        }
        let mut accounting = SpongeAccounting::default();
        for query in [&self.first, &self.second] {
            let digest = oracle.evaluate_frame(query.role, &query.message);
            // Rechecks start with the complete message; they do not clone a prefix.
            accounting.observe(query, oracle.evaluation(query.role, false))?;
            if digest != query.digest {
                return Err("collision witness failed independent two-call recheck");
            }
        }
        Ok(accounting)
    }

    fn json(&self) -> Value {
        json!({
            "role0":format!("{:?}", self.first.role),
            "role1":format!("{:?}", self.second.role),
            "message0_hex":hex::encode(&self.first.message),
            "message1_hex":hex::encode(&self.second.message),
            "full_digest_hex":hex::encode(self.first.digest),
        })
    }
}

#[derive(Default)]
struct QueryLog {
    calls: usize,
    sponge: SpongeAccounting,
    // All roles use this one table. A role never receives a fresh oracle.
    by_digest: BTreeMap<Context, Query>,
    collision: Option<Collision>,
}

impl QueryLog {
    fn observe(&mut self, query: Query, evaluation: HashEvaluation) -> Result<(), &'static str> {
        let next_calls = self
            .calls
            .checked_add(1)
            .ok_or("whole-hash call count overflow")?;
        self.sponge.observe(&query, evaluation)?;
        self.calls = next_calls;
        if let Some(prior) = self.by_digest.get(&query.digest) {
            if prior.message != query.message && self.collision.is_none() {
                self.collision = Some(Collision {
                    first: prior.clone(),
                    second: query,
                });
            }
        } else {
            self.by_digest.insert(query.digest, query);
        }
        Ok(())
    }
}

type SharedLog = Arc<Mutex<QueryLog>>;

#[derive(Clone)]
struct RecordedLeaf {
    native: LeafHasher,
    component: Component,
    context: Context,
    oracle: Oracle,
    log: SharedLog,
}

impl CryptographicHasher<Val, MerkleDigest> for RecordedLeaf {
    fn hash_iter<I: IntoIterator<Item = Val>>(&self, input: I) -> MerkleDigest {
        let values: Vec<Val> = input.into_iter().collect();
        let mut message = frame_header(self.component as u32, Role::Leaf, &self.context);
        let header_bytes = message.len();
        let payload_bytes = u64::try_from(values.len())
            .ok()
            .and_then(|n| n.checked_mul(8))
            .expect("leaf payload byte count overflow");
        for value in &values {
            message.extend_from_slice(&value.to_unique_u64().to_le_bytes());
        }
        message.extend_from_slice(&payload_bytes.to_le_bytes());
        let digest = if self.oracle.overrides(Role::Leaf) {
            [0; 64]
        } else {
            digest_bytes(self.native.hash_slice(&values))
        };
        self.log
            .lock()
            .unwrap()
            .observe(
                Query {
                    role: Role::Leaf,
                    header_bytes,
                    message,
                    digest,
                },
                self.oracle.evaluation(Role::Leaf, true),
            )
            .expect("leaf sponge accounting failed");
        digest_words(digest)
    }
}

#[derive(Clone)]
struct RecordedBranch {
    native: BranchCompressor,
    component: Component,
    context: Context,
    oracle: Oracle,
    log: SharedLog,
}

impl PseudoCompressionFunction<MerkleDigest, 2> for RecordedBranch {
    fn compress(&self, input: [MerkleDigest; 2]) -> MerkleDigest {
        let mut message = frame_header(self.component as u32, Role::Branch, &self.context);
        let header_bytes = message.len();
        for child in input {
            message.extend_from_slice(&digest_bytes(child));
        }
        message.extend_from_slice(&128u64.to_le_bytes());
        let digest = if self.oracle.overrides(Role::Branch) {
            [0; 64]
        } else {
            digest_bytes(self.native.compress(input))
        };
        self.log
            .lock()
            .unwrap()
            .observe(
                Query {
                    role: Role::Branch,
                    header_bytes,
                    message,
                    digest,
                },
                self.oracle.evaluation(Role::Branch, true),
            )
            .expect("branch sponge accounting failed");
        digest_words(digest)
    }
}

type AuditMmcs = MerkleTreeMmcs<Val, u64, RecordedLeaf, RecordedBranch, 2, 8>;
type Commitment = <AuditMmcs as Mmcs<Val>>::Commitment;
type Opening = PrunedBatchOpening<Val, u64, 8>;

fn mmcs(component: Component, context: Context, oracle: Oracle) -> (AuditMmcs, SharedLog) {
    let log = Arc::new(Mutex::new(QueryLog::default()));
    let value = AuditMmcs::new(
        RecordedLeaf {
            native: LeafHasher::new(component, context),
            component,
            context,
            oracle,
            log: log.clone(),
        },
        RecordedBranch {
            native: BranchCompressor::new(component, context),
            component,
            context,
            oracle,
            log: log.clone(),
        },
        0,
    );
    (value, log)
}

fn native_mmcs(component: Component, context: Context) -> ValMmcs {
    ValMmcs::new(
        LeafHasher::new(component, context),
        BranchCompressor::new(component, context),
        0,
    )
}

fn shape(dimensions: &[Dimensions], indices: &[usize], opening: &Opening) -> Result<(), String> {
    if dimensions.is_empty() || dimensions.len() > MAX_MATRICES {
        return Err("dimension count outside the proved/checker scope".into());
    }
    let max_height = dimensions.iter().map(|d| d.height).max().unwrap();
    if dimensions.iter().any(|d| {
        !d.height.is_power_of_two()
            || d.height.ilog2() > MAX_LOG_HEIGHT
            || d.width == 0
            || d.width > MAX_ROW_WIDTH
    }) {
        return Err(
            "only bounded positive power-of-two heights and positive widths are covered".into(),
        );
    }
    if indices.is_empty() || indices.len() > MAX_QUERIES || indices.iter().any(|&i| i >= max_height)
    {
        return Err("query set outside the proved/checker scope".into());
    }
    if opening.opened_values.len() != indices.len()
        || opening.pruned_proof.sibling_hashes.len() > indices.len() * max_height.ilog2() as usize
    {
        return Err("opening envelope shape".into());
    }
    let mut fields = 0usize;
    for rows in &opening.opened_values {
        if rows.len() != dimensions.len() {
            return Err("matrix count".into());
        }
        for (row, dims) in rows.iter().zip(dimensions) {
            if row.len() != dims.width {
                return Err("pinned matrix width".into());
            }
            fields = fields
                .checked_add(row.len())
                .ok_or("field count overflow")?;
            if fields > MAX_OPENED_FIELDS {
                return Err("opened-field budget".into());
            }
        }
    }
    Ok(())
}

fn coordinate(dimensions: &[Dimensions], global_index: usize, matrix: usize) -> (usize, usize) {
    let log_max = dimensions.iter().map(|d| d.height.ilog2()).max().unwrap();
    (
        matrix,
        global_index >> (log_max - dimensions[matrix].height.ilog2()),
    )
}

fn shared_conflict(
    dimensions: &[Dimensions],
    indices0: &[usize],
    opening0: &Opening,
    indices1: &[usize],
    opening1: &Opening,
) -> Option<(usize, usize)> {
    // Preserve every value, even if a future verifier regression admits an
    // inconsistent duplicate. Last-wins insertion could erase a real conflict.
    let mut left: BTreeMap<(usize, usize), Vec<&[Val]>> = BTreeMap::new();
    for (&index, rows) in indices0.iter().zip(&opening0.opened_values) {
        for (matrix, row) in rows.iter().enumerate() {
            left.entry(coordinate(dimensions, index, matrix))
                .or_default()
                .push(row);
        }
    }
    for (&index, rows) in indices1.iter().zip(&opening1.opened_values) {
        for (matrix, row) in rows.iter().enumerate() {
            let key = coordinate(dimensions, index, matrix);
            if left
                .get(&key)
                .is_some_and(|values| values.iter().any(|other| *other != row.as_slice()))
            {
                return Some(key);
            }
        }
    }
    None
}

fn call_bound(dimensions: &[Dimensions], num_queries: usize) -> usize {
    let h = dimensions.iter().map(|d| d.height.ilog2()).max().unwrap() as usize;
    let mut heights: Vec<usize> = dimensions.iter().map(|d| d.height).collect();
    heights.sort_unstable();
    heights.dedup();
    // One initial leaf, h structural branches, and one leaf plus one branch
    // at each of the k-1 lower-height injections. Amortization only saves calls.
    num_queries * (h + 2 * heights.len() - 1)
}

struct PairAudit {
    collision: Collision,
    conflict: (usize, usize),
    verification_hash_calls: usize,
    verification_hash_call_bound: usize,
    verification_sponge: SpongeAccounting,
    collision_recheck_sponge: SpongeAccounting,
}

#[allow(clippy::too_many_arguments)]
fn audit_pair(
    component: Component,
    context: Context,
    oracle: Oracle,
    cap: &Commitment,
    dimensions: &[Dimensions],
    indices0: &[usize],
    opening0: &Opening,
    indices1: &[usize],
    opening1: &Opening,
) -> Result<PairAudit, String> {
    // These are externally pinned parameters, shared by both checks. No
    // dimensions, context, component, cap policy or indices come from a proof.
    shape(dimensions, indices0, opening0)?;
    shape(dimensions, indices1, opening1)?;
    if cap.num_roots() != 1 {
        return Err("the reduction is for the fixed cap-zero profile".into());
    }
    let (verifier, log) = mmcs(component, context, oracle);
    for (which, indices, opening) in [(0, indices0, opening0), (1, indices1, opening1)] {
        verifier
            .verify_batch_pruned(
                cap,
                dimensions,
                indices,
                &opening.opened_values,
                &opening.pruned_proof,
            )
            .map_err(|error| format!("opening {which} rejected: {error:?}"))?;
    }
    let conflict = shared_conflict(dimensions, indices0, opening0, indices1, opening1)
        .ok_or("no conflicting shared matrix-row coordinate")?;
    let log = log.lock().unwrap();
    let bound = call_bound(dimensions, indices0.len() + indices1.len());
    if log.calls > bound {
        return Err("native verifier exceeded the proved whole-hash call bound".into());
    }
    let collision = log.collision.clone().ok_or(
        "INVARIANT_FAILURE: accepted conflicting rows without an observed framed-hash collision",
    )?;
    let collision_recheck_sponge = collision.check(oracle)?;
    Ok(PairAudit {
        collision,
        conflict,
        verification_hash_calls: log.calls,
        verification_hash_call_bound: bound,
        verification_sponge: log.sponge.clone(),
        collision_recheck_sponge,
    })
}

fn matrices(dimensions: &[Dimensions]) -> Vec<RowMajorMatrix<Val>> {
    dimensions
        .iter()
        .enumerate()
        .map(|(matrix, d)| {
            let values = (0..d.height * d.width)
                .map(|i| Val::from_u64(1 + matrix as u64 * 1_000_000 + i as u64))
                .collect();
            RowMajorMatrix::new(values, d.width)
        })
        .collect()
}

fn dims() -> Vec<Dimensions> {
    // Deliberately unsorted, repeated tallest height and two injection levels.
    vec![
        Dimensions {
            height: 2,
            width: 2,
        },
        Dimensions {
            height: 8,
            width: 3,
        },
        Dimensions {
            height: 1,
            width: 4,
        },
        Dimensions {
            height: 8,
            width: 1,
        },
    ]
}

fn honest_case(component: Component) -> Value {
    let context = [41; 64];
    let dimensions = dims();
    let indices = [7, 0, 2, 2, 6];
    let (recorded, log) = mmcs(component, context, Oracle::NativeSha3);
    let native = native_mmcs(component, context);
    let (cap, data) = recorded.commit(matrices(&dimensions));
    let (native_cap, native_data) = native.commit(matrices(&dimensions));
    assert_eq!(cap, native_cap);
    let opening = recorded.open_batch_pruned(&indices, &data);
    let native_opening = native.open_batch_pruned(&indices, &native_data);
    assert_eq!(opening.opened_values, native_opening.opened_values);
    assert_eq!(
        opening.pruned_proof.sibling_hashes,
        native_opening.pruned_proof.sibling_hashes
    );
    *log.lock().unwrap() = QueryLog::default();
    recorded
        .verify_batch_pruned(
            &cap,
            &dimensions,
            &indices,
            &opening.opened_values,
            &opening.pruned_proof,
        )
        .unwrap();
    // Freeze precisely the verifier's observation. Later parity checks and
    // restored-path recomputation are controls, outside this reported ledger.
    let (calls, verification_sponge) = {
        let log = log.lock().unwrap();
        (log.calls, log.sponge.clone())
    };
    assert!(calls <= call_bound(&dimensions, indices.len()));
    assert!(log.lock().unwrap().collision.is_none());
    // Check the complete recorded preimages against a fresh full SHA3 call.
    for query in log.lock().unwrap().by_digest.values() {
        assert_eq!(
            Oracle::NativeSha3.evaluate_frame(query.role, &query.message),
            query.digest
        );
    }
    let paths = recorded
        .restore_and_recompute_paths(
            &dimensions,
            &indices,
            &opening.opened_values,
            &opening.pruned_proof,
        )
        .unwrap();
    for (q, path) in paths.iter().enumerate() {
        native
            .verify_batch(
                &cap,
                &dimensions,
                indices[q],
                BatchOpeningRef::new(&opening.opened_values[q], &path.siblings),
            )
            .unwrap();
    }
    assert_eq!(paths[2], paths[3]);
    assert!(
        audit_pair(
            component,
            context,
            Oracle::NativeSha3,
            &cap,
            &dimensions,
            &indices,
            &opening,
            &indices,
            &opening
        )
        .is_err()
    );
    json!({"component":component as u32,"queries":indices,"native_pruned_hash_calls":calls,
        "unpruned_upper_bound":call_bound(&dimensions, indices.len()),
        "verification_sponge_accounting":verification_sponge.json(),
        "restored_paths_individually_verified":paths.len(),"native_role_and_cap_parity":true})
}

fn artificial_case(oracle: Oracle) -> Value {
    assert_ne!(oracle, Oracle::NativeSha3);
    let component = Component::Sha;
    let context = [42; 64];
    let dimensions = dims();
    // Distinct global indices share matrix 0's reduced row 0.
    let indices0 = [0, 2];
    let indices1 = [1, 3, 1];
    let (verifier, _) = mmcs(component, context, oracle);
    let (cap, data) = verifier.commit(matrices(&dimensions));
    let left = verifier.open_batch_pruned(&indices0, &data);
    let mut right = verifier.open_batch_pruned(&indices1, &data);
    for rows in &mut right.opened_values {
        rows[0][0] += Val::ONE;
    }
    if oracle == Oracle::ArtificialBranchCollision {
        // No child-preimage witnesses are required: the real verifier accepts
        // arbitrary full digest bytes as boundary siblings in this test oracle.
        for (i, sibling) in right.pruned_proof.sibling_hashes.iter_mut().enumerate() {
            *sibling = [u64::MAX - i as u64; 8];
        }
    }
    let audit = audit_pair(
        component,
        context,
        oracle,
        &cap,
        &dimensions,
        &indices0,
        &left,
        &indices1,
        &right,
    )
    .unwrap();
    assert_eq!(audit.conflict, (0, 0));
    assert_eq!(
        audit.collision.first.role,
        if oracle == Oracle::ArtificialLeafCollision {
            Role::Leaf
        } else {
            Role::Branch
        }
    );
    json!({"oracle":oracle.name(),"actual_p3_pruned_verifier":true,
        "real_sha3_collision":false,"w1_forgery":false,
        "shared_matrix_row":[audit.conflict.0,audit.conflict.1],
        "verification_whole_hash_calls":audit.verification_hash_calls,
        "verification_whole_hash_call_bound":audit.verification_hash_call_bound,
        "verification_sponge_accounting":audit.verification_sponge.json(),
        "independent_collision_recheck_calls":2,
        "collision_recheck_sponge_accounting":audit.collision_recheck_sponge.json(),
        "candidate_collision_padded_block_total":audit.collision_recheck_sponge.totals.complete_message_equivalent_absorption_blocks,
        "collision":audit.collision.json()})
}

fn rejection_cases() -> usize {
    let component = Component::Sha;
    let context = [43; 64];
    let dimensions = dims();
    let indices = [0, 1, 2, 2];
    let verifier = native_mmcs(component, context);
    let (cap, data) = verifier.commit(matrices(&dimensions));
    let opening = verifier.open_batch_pruned(&indices, &data);
    let accepted = |value: &Opening| {
        verifier
            .verify_batch_pruned(
                &cap,
                &dimensions,
                &indices,
                &value.opened_values,
                &value.pruned_proof,
            )
            .is_ok()
    };
    assert!(accepted(&opening));
    let mut controls = 0;
    let mut changed = opening.clone();
    changed.opened_values[3][1][0] += Val::ONE;
    assert!(!accepted(&changed)); // duplicate full index
    controls += 1;
    let mut changed = opening.clone();
    changed.opened_values[1][0][0] += Val::ONE;
    assert!(!accepted(&changed)); // different indices, same injected row
    controls += 1;
    let mut changed = opening.clone();
    changed.opened_values[0][1][0] += Val::ONE;
    assert!(!accepted(&changed)); // ordinary committed row
    controls += 1;
    let mut changed = opening.clone();
    changed.pruned_proof.sibling_hashes.push([0; 8]);
    assert!(!accepted(&changed));
    controls += 1;
    let mut changed = opening.clone();
    assert!(changed.pruned_proof.sibling_hashes.pop().is_some());
    assert!(!accepted(&changed));
    controls += 1;
    let mut changed = opening.clone();
    changed.pruned_proof.sibling_hashes[0][0] ^= 1;
    assert!(!accepted(&changed));
    controls += 1;
    let mut changed = opening.clone();
    // Preserve the complete tallest-height concatenation while moving its
    // matrix boundary. Fixed per-matrix widths must reject it before hashing.
    for rows in &mut changed.opened_values {
        let value = rows[1].pop().unwrap();
        rows[3].insert(0, value);
    }
    assert!(!accepted(&changed));
    assert!(shape(&dimensions, &indices, &changed).is_err());
    controls += 1;
    for (other_component, other_context) in
        [(Component::PackedCarry, context), (component, [44; 64])]
    {
        assert!(
            native_mmcs(other_component, other_context)
                .verify_batch_pruned(
                    &cap,
                    &dimensions,
                    &indices,
                    &opening.opened_values,
                    &opening.pruned_proof
                )
                .is_err()
        );
        controls += 1;
    }
    let mut wrong_indices = indices;
    wrong_indices[0] = 7;
    assert!(
        verifier
            .verify_batch_pruned(
                &cap,
                &dimensions,
                &wrong_indices,
                &opening.opened_values,
                &opening.pruned_proof
            )
            .is_err()
    );
    controls += 1;
    let mut wrong_dimensions = dimensions.clone();
    wrong_dimensions[0].height = 3;
    assert!(shape(&wrong_dimensions, &indices, &opening).is_err());
    controls += 1;
    controls
}

fn extension_case() -> Value {
    let component = Component::PackedCarry;
    let context = [45; 64];
    let dimensions = vec![
        Dimensions {
            height: 8,
            width: 2,
        },
        Dimensions {
            height: 2,
            width: 1,
        },
    ];
    let matrices: Vec<RowMajorMatrix<Challenge>> = dimensions
        .iter()
        .enumerate()
        .map(|(m, d)| {
            let values = (0..d.height * d.width)
                .map(|i| {
                    Challenge::from_basis_coefficients_fn(|basis| {
                        Val::from_u64(1000 * m as u64 + 10 * i as u64 + basis as u64 + 1)
                    })
                })
                .collect();
            RowMajorMatrix::new(values, d.width)
        })
        .collect();
    let base = native_mmcs(component, context);
    let ext = ExtensionMmcs::<Val, Challenge, _>::new(base.clone());
    let (cap, data) = ext.commit(matrices);
    let indices = [0, 1, 4, 0, 7];
    let (rows, proof) = ext.open_multi_batch(&indices, &data);
    ext.verify_multi_batch(&cap, &dimensions, &indices, &rows, &proof)
        .unwrap();
    let flat: Vec<Vec<Vec<Val>>> = rows
        .iter()
        .map(|query| {
            query
                .iter()
                .map(|row| {
                    row.iter()
                        .flat_map(|element| element.as_basis_coefficients_slice().iter().copied())
                        .collect()
                })
                .collect()
        })
        .collect();
    let flat_dimensions: Vec<Dimensions> = dimensions
        .iter()
        .map(|d| Dimensions {
            height: d.height,
            width: d.width * 2,
        })
        .collect();
    base.verify_multi_batch(&cap, &flat_dimensions, &indices, &flat, &proof)
        .unwrap();
    let paths = base
        .restore_and_recompute_paths(&flat_dimensions, &indices, &flat, &proof)
        .unwrap();
    for (q, path) in paths.iter().enumerate() {
        base.verify_batch(
            &cap,
            &flat_dimensions,
            indices[q],
            BatchOpeningRef::new(&flat[q], &path.siblings),
        )
        .unwrap();
    }
    json!({"extension":"Goldilocks[X]/(X^2-7)","basis_width":2,
        "actual_extension_mmcs_and_base_flatten_agree":true,"restored_paths":paths.len()})
}

fn main() {
    let report = json!({
        "schema":"p3.tagged-mmcs.two-opening-reduction-check.v1",
        "qualification":"HOLD_NO_GO",
        "qualified":false,"security_bits":null,"native_permutation_telemetry":false,
        "scope":"P3 0.8.0 binary cap-zero, pinned positive power-of-two matrix heights and widths",
        "sponge_accounting_scope":"only verifier calls in cases carrying verification_sponge_accounting and successful collision-witness rechecks; excludes extension/base-parity verification, prefix creation, commit/open, other parity checks, restored-path verification and other controls",
        "native":[honest_case(Component::Sha),honest_case(Component::PackedCarry)],
        "extension":extension_case(),
        "native_rejection_controls":rejection_cases(),
        "artificial_collision_extractions":[artificial_case(Oracle::ArtificialLeafCollision),artificial_case(Oracle::ArtificialBranchCollision)],
        "actual_w1_forgery":false,"concrete_hash_binding_bits":null,
        "quantum_pcs_extraction":false,"fiat_shamir_knowledge_soundness":false,
        "complete_noninteractive_security_bits":null,"production_activation":false,
    });
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn framed_query(role: Role, payload: &[u8], oracle: Oracle) -> Query {
        let mut message = frame_header(Component::Sha as u32, role, &[50; 64]);
        let header_bytes = message.len();
        message.extend_from_slice(payload);
        message.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        let digest = oracle.evaluate_frame(role, &message);
        Query {
            role,
            header_bytes,
            message,
            digest,
        }
    }

    #[test]
    fn sponge_padding_counts_rate_boundaries_and_the_length_suffix() {
        // Payload lengths are chosen independently of the fixed 322-byte R1
        // header: totals 71, 72, 73, 143, 144 and 145 exercise SHA3 padding.
        for (payload, expected_bytes, expected_blocks) in [
            (63, 71, 1),
            (64, 72, 2),
            (65, 73, 2),
            (135, 143, 2),
            (136, 144, 3),
            (137, 145, 3),
        ] {
            let frame = FrameSize::new(0, payload).unwrap();
            assert_eq!(frame.message_bytes, expected_bytes);
            assert_eq!(frame.padded_blocks, expected_blocks);
        }
        assert_eq!(FrameSize::new(0, 0).unwrap().message_bytes, 8);
        assert_eq!(
            FrameSize::new(0, u64::MAX - 8).unwrap().padded_blocks,
            u64::MAX / 72 + 1
        );
    }

    #[test]
    fn sponge_cached_prefix_continuation_is_not_full_message_telemetry() {
        let query = framed_query(Role::Branch, &[0; 128], Oracle::NativeSha3);
        assert_eq!(query.header_bytes, 322);
        let mut cached = SpongeAccounting::default();
        cached
            .observe(&query, HashEvaluation::CachedPrefixSha3)
            .unwrap();
        assert_eq!(cached.totals.complete_message_bytes, 458);
        assert_eq!(
            cached.totals.complete_message_equivalent_absorption_blocks,
            7
        );
        assert_eq!(
            cached.totals.native_cached_prefix_reused_block_equivalents,
            4
        );
        assert_eq!(
            cached
                .totals
                .native_cached_prefix_continuation_block_equivalents,
            3
        );
        let mut fresh = SpongeAccounting::default();
        fresh
            .observe(&query, HashEvaluation::FullMessageSha3)
            .unwrap();
        assert_eq!(fresh.totals.native_full_message_block_equivalents, 7);
        assert_eq!(
            fresh.totals.native_cached_prefix_reused_block_equivalents,
            0
        );
        assert_eq!(cached.json()["native_permutation_telemetry"], false);
        assert!(cached.json()["native_permutation_calls"].is_null());
    }

    #[test]
    fn sponge_query_log_counts_repeated_hash_calls_before_deduplication() {
        let log = Arc::new(Mutex::new(QueryLog::default()));
        let leaf = RecordedLeaf {
            native: LeafHasher::new(Component::Sha, [50; 64]),
            component: Component::Sha,
            context: [50; 64],
            oracle: Oracle::NativeSha3,
            log: log.clone(),
        };
        let values = [Val::from_u64(1), Val::from_u64(2)];
        assert_eq!(leaf.hash_slice(&values), leaf.hash_slice(&values));
        let log = log.lock().unwrap();
        assert_eq!(log.calls, 2);
        assert_eq!(log.by_digest.len(), 1);
        assert_eq!(log.sponge.calls.len(), 2);
        assert_eq!(log.sponge.totals.complete_message_bytes, 2 * 346);
        assert_eq!(
            log.sponge
                .totals
                .complete_message_equivalent_absorption_blocks,
            10
        );
        assert_eq!(
            log.sponge
                .totals
                .native_cached_prefix_continuation_block_equivalents,
            2
        );
    }

    #[test]
    fn sponge_artificial_roles_are_separated_from_actual_sha3_calls() {
        for oracle in [
            Oracle::ArtificialLeafCollision,
            Oracle::ArtificialBranchCollision,
        ] {
            let (verifier, log) = mmcs(Component::Sha, [51; 64], oracle);
            verifier.commit(vec![RowMajorMatrix::new(
                vec![Val::ONE, Val::from_u64(2)],
                1,
            )]);
            let log = log.lock().unwrap();
            assert!(log.sponge.totals.artificial_override_calls > 0);
            assert!(log.sponge.totals.native_cached_prefix_calls > 0);
            assert_eq!(log.sponge.totals.native_full_message_calls, 0);
            assert_eq!(
                log.sponge.totals.whole_message_calls,
                log.sponge.totals.artificial_override_calls
                    + log.sponge.totals.native_cached_prefix_calls
            );
            for call in &log.sponge.calls {
                assert_eq!(
                    call.evaluation == HashEvaluation::ArtificialOverride,
                    oracle.overrides(call.role)
                );
            }
        }
    }

    #[test]
    fn sponge_collision_recheck_retains_both_output_message_lengths() {
        let oracle = Oracle::ArtificialLeafCollision;
        let collision = Collision {
            first: framed_query(Role::Leaf, &[1; 8], oracle),
            second: framed_query(Role::Leaf, &[2; 80], oracle),
        };
        let accounting = collision.check(oracle).unwrap();
        assert_eq!(accounting.totals.whole_message_calls, 2);
        assert_eq!(accounting.totals.artificial_override_calls, 2);
        assert_eq!(accounting.totals.native_full_message_calls, 0);
        assert_eq!(accounting.calls[0].frame.message_bytes, 338);
        assert_eq!(accounting.calls[1].frame.message_bytes, 410);
        assert_eq!(
            accounting
                .totals
                .complete_message_equivalent_absorption_blocks,
            5 + 6
        );
    }

    #[test]
    fn sponge_accounting_overflow_fails_without_partial_updates() {
        assert!(FrameSize::new(u64::MAX - 7, 0).is_err());
        assert!(FrameSize::new(322, u64::MAX).is_err());
        let query = framed_query(Role::Leaf, &[0; 8], Oracle::NativeSha3);
        for totals in [
            SpongeTotals {
                whole_message_calls: u64::MAX,
                ..SpongeTotals::default()
            },
            SpongeTotals {
                complete_message_bytes: u64::MAX,
                ..SpongeTotals::default()
            },
            SpongeTotals {
                complete_message_equivalent_absorption_blocks: u64::MAX,
                ..SpongeTotals::default()
            },
            SpongeTotals {
                native_cached_prefix_continuation_block_equivalents: u64::MAX,
                ..SpongeTotals::default()
            },
        ] {
            let mut accounting = SpongeAccounting {
                totals,
                calls: Vec::new(),
            };
            let before = accounting.clone();
            assert!(
                accounting
                    .observe(&query, HashEvaluation::CachedPrefixSha3)
                    .is_err()
            );
            assert_eq!(accounting, before);
        }
        let mut log = QueryLog {
            calls: usize::MAX,
            ..QueryLog::default()
        };
        assert!(
            log.observe(query, HashEvaluation::CachedPrefixSha3)
                .is_err()
        );
        assert!(log.sponge.calls.is_empty());
        assert!(log.by_digest.is_empty());
    }

    #[test]
    fn sponge_accounting_rejects_truncated_wrong_suffix_and_uncovered_roles() {
        let mut wrong_suffix = framed_query(Role::Leaf, &[0; 8], Oracle::NativeSha3);
        *wrong_suffix.message.last_mut().unwrap() = 1;
        let mut truncated = framed_query(Role::Branch, &[0; 128], Oracle::NativeSha3);
        truncated.message.truncate(truncated.header_bytes + 7);
        let transcript = framed_query(Role::Transcript, &[0; 8], Oracle::NativeSha3);
        for query in [wrong_suffix, truncated, transcript] {
            let mut accounting = SpongeAccounting::default();
            assert!(
                accounting
                    .observe(&query, HashEvaluation::CachedPrefixSha3)
                    .is_err()
            );
            assert_eq!(accounting, SpongeAccounting::default());
        }
    }

    #[test]
    fn sha_profile_pruned_mixed_heights_restore_to_native_paths() {
        honest_case(Component::Sha);
    }

    #[test]
    fn carry_profile_pruned_mixed_heights_restore_to_native_paths() {
        honest_case(Component::PackedCarry);
    }

    #[test]
    fn extension_flattening_preserves_exact_rows_and_shared_paths() {
        extension_case();
    }

    #[test]
    fn real_hash_rejects_duplicate_injection_shape_index_and_sibling_controls() {
        assert_eq!(rejection_cases(), 11);
    }

    #[test]
    fn deliberately_colliding_leaves_yield_full_framed_collision() {
        artificial_case(Oracle::ArtificialLeafCollision);
    }

    #[test]
    fn arbitrary_siblings_and_injected_row_conflict_yield_branch_collision() {
        artificial_case(Oracle::ArtificialBranchCollision);
    }

    #[test]
    fn shared_coordinate_is_the_reduced_matrix_row_not_the_global_index() {
        let dimensions = dims();
        assert_eq!(coordinate(&dimensions, 0, 0), coordinate(&dimensions, 3, 0));
        assert_ne!(coordinate(&dimensions, 0, 1), coordinate(&dimensions, 3, 1));
        assert_eq!(coordinate(&dimensions, 7, 2), (2, 0));
    }

    #[test]
    fn conflict_search_never_erases_an_earlier_duplicate_value() {
        let dimensions = vec![Dimensions {
            height: 1,
            width: 1,
        }];
        let verifier = native_mmcs(Component::Sha, [46; 64]);
        let (_, data) = verifier.commit(matrices(&dimensions));
        let mut left = verifier.open_batch_pruned(&[0, 0], &data);
        let right = verifier.open_batch_pruned(&[0], &data);
        left.opened_values[0][0][0] += Val::ONE;
        // The P3 verifier rejects this inconsistent duplicate. The conflict
        // detector itself must also not hide it by overwriting the first row.
        assert_eq!(
            shared_conflict(&dimensions, &[0, 0], &left, &[0], &right),
            Some((0, 0))
        );
    }

    #[test]
    fn a_single_row_conflict_needs_no_authentication_sibling() {
        let dimensions = vec![Dimensions {
            height: 1,
            width: 2,
        }];
        let component = Component::Sha;
        let context = [47; 64];
        let oracle = Oracle::ArtificialLeafCollision;
        let (verifier, _) = mmcs(component, context, oracle);
        let (cap, data) = verifier.commit(matrices(&dimensions));
        let left = verifier.open_batch_pruned(&[0], &data);
        let mut right = left.clone();
        right.opened_values[0][0][0] += Val::ONE;
        let audit = audit_pair(
            component,
            context,
            oracle,
            &cap,
            &dimensions,
            &[0],
            &left,
            &[0],
            &right,
        )
        .unwrap();
        assert_eq!(audit.verification_hash_calls, 2);
        assert_eq!(audit.verification_hash_call_bound, 2);
    }

    #[test]
    fn disjoint_valid_queries_are_not_reported_as_a_binding_violation() {
        let dimensions = vec![Dimensions {
            height: 8,
            width: 2,
        }];
        let component = Component::Sha;
        let context = [48; 64];
        let verifier = native_mmcs(component, context);
        let (cap, data) = verifier.commit(matrices(&dimensions));
        let left = verifier.open_batch_pruned(&[0], &data);
        let right = verifier.open_batch_pruned(&[7], &data);
        let error = audit_pair(
            component,
            context,
            Oracle::NativeSha3,
            &cap,
            &dimensions,
            &[0],
            &left,
            &[7],
            &right,
        )
        .err()
        .unwrap();
        assert_eq!(error, "no conflicting shared matrix-row coordinate");
    }

    #[test]
    fn an_extra_cap_entry_is_outside_the_fixed_profile() {
        let dimensions = vec![Dimensions {
            height: 1,
            width: 2,
        }];
        let component = Component::Sha;
        let context = [49; 64];
        let verifier = native_mmcs(component, context);
        let (cap, data) = verifier.commit(matrices(&dimensions));
        let opening = verifier.open_batch_pruned(&[0], &data);
        let extra = Commitment::new(vec![cap[0], cap[0]]);
        let error = audit_pair(
            component,
            context,
            Oracle::NativeSha3,
            &extra,
            &dimensions,
            &[0],
            &opening,
            &[0],
            &opening,
        )
        .err()
        .unwrap();
        assert_eq!(error, "the reduction is for the fixed cap-zero profile");
    }
}
