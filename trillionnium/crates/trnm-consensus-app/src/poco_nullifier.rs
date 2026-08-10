//! Sparse-Merkle anti-replay nullifiers for authenticated PoCO application state.
//!
//! The tree is fixed at 256 levels. A `Hash32` key is interpreted as one
//! big-endian 256-bit integer, but the path is consumed least-significant bit
//! first: leaf level 0 uses bit 0 of `key[31]`, level 1 uses bit 1 of
//! `key[31]`, and level 255 uses bit 7 of `key[0]`. Proof siblings are stored
//! in that same leaf-to-root order. The proof codec is deliberately full and
//! fixed-width; v0 has no bitmap, omitted-default, or variable-depth form.

use std::sync::OnceLock;

use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};
use trnm_consensus_types::SCHEMA_VERSION_V0;

pub(crate) type Hash32 = [u8; 32];

const HASH_PREFIX: &[u8] = b"trnm.cev0.hash.v0";
const NULLIFIER_KEY_DOMAIN: &[u8] = b"trnm.poco-bft.nullifier-key.v0";
const EMPTY_LEAF_DOMAIN: &[u8] = b"trnm.poco-bft.nullifier-empty-leaf.v0";
const OCCUPIED_LEAF_DOMAIN: &[u8] = b"trnm.poco-bft.nullifier-occupied-leaf.v0";
const NODE_DOMAIN: &[u8] = b"trnm.poco-bft.nullifier-node.v0";

pub(crate) const POCO_NULLIFIER_TREE_DEPTH_V0: usize = 256;
pub(crate) const POCO_NULLIFIER_PROOF_VERSION_V0: u16 = 0;
const POCO_NULLIFIER_PROOF_HEADER_BYTES_V0: usize = 2 + 2 + 2 + 32;
pub(crate) const POCO_NULLIFIER_PROOF_ENCODED_BYTES_V0: usize =
    POCO_NULLIFIER_PROOF_HEADER_BYTES_V0 + POCO_NULLIFIER_TREE_DEPTH_V0 * 32;

/// Stable family tag included in every derived sparse-Merkle key.
///
/// A digest from one authority family can therefore never be substituted for
/// the same 32 bytes in another family without breaking the committed path.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub(crate) enum PocoNullifierFamilyV0 {
    Certificate = 1,
    Tuple = 2,
    SettlementDecision = 3,
    MeterDecision = 4,
    EvidenceDecision = 5,
    ChallengeDecision = 6,
    GovernanceDecision = 7,
    RegistrationDecision = 8,
    ConsumerKeyDecision = 9,
    ConsumerKeyIdentity = 10,
    ConsumerNonceSummary = 11,
    MeterIdentity = 12,
    ValidatorConsensusKey = 13,
    ValidatorIdentity = 14,
}

impl PocoNullifierFamilyV0 {
    pub(crate) fn from_u8(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Certificate),
            2 => Ok(Self::Tuple),
            3 => Ok(Self::SettlementDecision),
            4 => Ok(Self::MeterDecision),
            5 => Ok(Self::EvidenceDecision),
            6 => Ok(Self::ChallengeDecision),
            7 => Ok(Self::GovernanceDecision),
            8 => Ok(Self::RegistrationDecision),
            9 => Ok(Self::ConsumerKeyDecision),
            10 => Ok(Self::ConsumerKeyIdentity),
            11 => Ok(Self::ConsumerNonceSummary),
            12 => Ok(Self::MeterIdentity),
            13 => Ok(Self::ValidatorConsensusKey),
            14 => Ok(Self::ValidatorIdentity),
            _ => anyhow::bail!("unknown PoCO nullifier family"),
        }
    }

    pub(crate) const fn code(self) -> u8 {
        self as u8
    }
}

/// Derives the actual sparse-tree path from one already-canonical 32-byte ID.
pub(crate) fn derive_poco_nullifier_key_v0(
    family: PocoNullifierFamilyV0,
    identifier: Hash32,
) -> Hash32 {
    let mut encoded = [0u8; 35];
    encoded[..2].copy_from_slice(&SCHEMA_VERSION_V0.to_be_bytes());
    encoded[2] = family.code();
    encoded[3..].copy_from_slice(&identifier);
    domain_hash(NULLIFIER_KEY_DOMAIN, &encoded)
}

/// Canonical uncompressed non-membership proof.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct PocoNullifierProofV0 {
    key: Hash32,
    siblings: [Hash32; POCO_NULLIFIER_TREE_DEPTH_V0],
}

impl core::fmt::Debug for PocoNullifierProofV0 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PocoNullifierProofV0")
            .field("key", &self.key)
            .field("sibling_count", &self.siblings.len())
            .finish()
    }
}

impl PocoNullifierProofV0 {
    pub(crate) const fn new(key: Hash32, siblings: [Hash32; POCO_NULLIFIER_TREE_DEPTH_V0]) -> Self {
        Self { key, siblings }
    }

    pub(crate) const fn key(&self) -> Hash32 {
        self.key
    }

    pub(crate) fn siblings(&self) -> &[Hash32; POCO_NULLIFIER_TREE_DEPTH_V0] {
        &self.siblings
    }

    /// Read-only evidence helper: reconstructs the root this proof claims for
    /// an absent leaf. The production verifier still compares that root to the
    /// authenticated accumulator before authorizing any update.
    pub(crate) fn non_membership_root(&self) -> Hash32 {
        self.root_from_leaf(empty_leaf_hash())
    }

    /// Frozen v0 layout:
    /// `schema:u16 || proof_version:u16 || depth:u16 || key:Hash32 ||
    ///  siblings[256]:Hash32`, all integers big-endian.
    pub(crate) fn canonical_bytes(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(POCO_NULLIFIER_PROOF_ENCODED_BYTES_V0);
        encoded.extend_from_slice(&SCHEMA_VERSION_V0.to_be_bytes());
        encoded.extend_from_slice(&POCO_NULLIFIER_PROOF_VERSION_V0.to_be_bytes());
        encoded.extend_from_slice(&(POCO_NULLIFIER_TREE_DEPTH_V0 as u16).to_be_bytes());
        encoded.extend_from_slice(&self.key);
        for sibling in &self.siblings {
            encoded.extend_from_slice(sibling);
        }
        debug_assert_eq!(encoded.len(), POCO_NULLIFIER_PROOF_ENCODED_BYTES_V0);
        encoded
    }

    pub(crate) fn decode_exact(encoded: &[u8]) -> Result<Self> {
        ensure!(
            encoded.len() == POCO_NULLIFIER_PROOF_ENCODED_BYTES_V0,
            "PoCO nullifier proof length is not canonical"
        );

        let schema_version =
            u16::from_be_bytes(encoded[0..2].try_into().expect("fixed proof header slice"));
        ensure!(
            schema_version == SCHEMA_VERSION_V0,
            "unsupported PoCO nullifier proof schema"
        );
        let proof_version =
            u16::from_be_bytes(encoded[2..4].try_into().expect("fixed proof header slice"));
        ensure!(
            proof_version == POCO_NULLIFIER_PROOF_VERSION_V0,
            "unsupported PoCO nullifier proof version"
        );
        let depth = u16::from_be_bytes(encoded[4..6].try_into().expect("fixed proof header slice"));
        ensure!(
            usize::from(depth) == POCO_NULLIFIER_TREE_DEPTH_V0,
            "PoCO nullifier proof depth is not canonical"
        );

        let key = encoded[6..38]
            .try_into()
            .expect("fixed nullifier key slice");
        let mut siblings = [[0u8; 32]; POCO_NULLIFIER_TREE_DEPTH_V0];
        for (level, sibling) in siblings.iter_mut().enumerate() {
            let start = POCO_NULLIFIER_PROOF_HEADER_BYTES_V0
                .checked_add(level.checked_mul(32).context("proof offset overflow")?)
                .context("proof offset overflow")?;
            let end = start.checked_add(32).context("proof offset overflow")?;
            sibling.copy_from_slice(
                encoded
                    .get(start..end)
                    .context("PoCO nullifier proof is truncated")?,
            );
        }
        Ok(Self { key, siblings })
    }

    fn root_from_leaf(&self, leaf: Hash32) -> Hash32 {
        self.siblings
            .iter()
            .enumerate()
            .fold(leaf, |current, (level, sibling)| {
                if path_bit_lsb_first(&self.key, level) {
                    node_hash(level, *sibling, current)
                } else {
                    node_hash(level, current, *sibling)
                }
            })
    }
}

/// Authenticated accumulator head. The root and count must be committed
/// together by the outer PoCO state transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PocoNullifierAccumulatorV0 {
    root: Hash32,
    count: u64,
}

impl PocoNullifierAccumulatorV0 {
    pub(crate) fn empty() -> Self {
        Self {
            root: empty_poco_nullifier_root_v0(),
            count: 0,
        }
    }

    pub(crate) fn from_authenticated_parts(root: Hash32, count: u64) -> Result<Self> {
        let is_empty_root = root == empty_poco_nullifier_root_v0();
        ensure!(
            (count == 0) == is_empty_root,
            "PoCO nullifier root/count empty-state mismatch"
        );
        Ok(Self { root, count })
    }

    pub(crate) const fn root(self) -> Hash32 {
        self.root
    }

    pub(crate) const fn count(self) -> u64 {
        self.count
    }

    pub(crate) fn verify_non_membership(
        self,
        expected_key: Hash32,
        proof: &PocoNullifierProofV0,
    ) -> Result<()> {
        ensure!(
            proof.key == expected_key,
            "PoCO nullifier proof key mismatch"
        );
        ensure!(
            proof.root_from_leaf(empty_leaf_hash()) == self.root,
            "PoCO nullifier non-membership root mismatch"
        );
        Ok(())
    }

    /// Verifies that `expected_key` is absent and computes the one-key update.
    /// Count exhaustion is rejected before the 256-level proof walk.
    pub(crate) fn verify_non_membership_and_compute_insertion(
        self,
        expected_key: Hash32,
        proof: &PocoNullifierProofV0,
    ) -> Result<PocoNullifierInsertionV0> {
        let target_count = self
            .count
            .checked_add(1)
            .context("PoCO nullifier count exhausted")?;
        self.verify_non_membership(expected_key, proof)?;
        let target_root = proof.root_from_leaf(occupied_leaf_hash(expected_key));
        ensure!(
            target_root != self.root,
            "PoCO nullifier insertion did not change the root"
        );
        Ok(PocoNullifierInsertionV0 {
            key: expected_key,
            source_root: self.root,
            source_count: self.count,
            target_root,
            target_count,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PocoNullifierInsertionV0 {
    key: Hash32,
    source_root: Hash32,
    source_count: u64,
    target_root: Hash32,
    target_count: u64,
}

impl PocoNullifierInsertionV0 {
    pub(crate) const fn key(self) -> Hash32 {
        self.key
    }

    pub(crate) const fn source_root(self) -> Hash32 {
        self.source_root
    }

    pub(crate) const fn source_count(self) -> u64 {
        self.source_count
    }

    pub(crate) const fn target_root(self) -> Hash32 {
        self.target_root
    }

    pub(crate) const fn target_count(self) -> u64 {
        self.target_count
    }

    pub(crate) fn target_accumulator(self) -> Result<PocoNullifierAccumulatorV0> {
        PocoNullifierAccumulatorV0::from_authenticated_parts(self.target_root, self.target_count)
    }
}

pub(crate) fn empty_poco_nullifier_root_v0() -> Hash32 {
    default_hashes()[POCO_NULLIFIER_TREE_DEPTH_V0]
}

#[cfg(test)]
pub(crate) fn test_proof_after_single_insertion_v0(
    existing_key: Hash32,
    target_key: Hash32,
) -> Result<PocoNullifierProofV0> {
    ensure!(existing_key != target_key, "test nullifier keys collide");
    // Leaf-to-root paths first join at the highest differing bit. Using the
    // lowest differing bit would place the existing leaf in a subtree that
    // can diverge again above that level and therefore yields a false proof.
    let divergence = (0..POCO_NULLIFIER_TREE_DEPTH_V0)
        .rfind(|level| {
            path_bit_lsb_first(&existing_key, *level) != path_bit_lsb_first(&target_key, *level)
        })
        .context("distinct nullifier keys lack divergence")?;
    let mut existing_subtree = occupied_leaf_hash(existing_key);
    for level in 0..divergence {
        existing_subtree = if path_bit_lsb_first(&existing_key, level) {
            node_hash(level, default_hashes()[level], existing_subtree)
        } else {
            node_hash(level, existing_subtree, default_hashes()[level])
        };
    }
    let mut siblings = std::array::from_fn(|level| default_hashes()[level]);
    siblings[divergence] = existing_subtree;
    Ok(PocoNullifierProofV0::new(target_key, siblings))
}

/// Test-only authoring helper for the shared application-operation corpus.
///
/// The helper intentionally accepts already-derived sparse-tree keys, so the
/// production family/identifier derivation remains the only authority for key
/// construction.  It reuses the production leaf/node/default hash functions
/// above and refuses both duplicate occupied keys and an already-occupied
/// target.  The resulting proof is therefore suitable for exercising the
/// exact production verifier without duplicating the sparse-tree algorithm in
/// the fixture exporter or in Node.
#[cfg(test)]
pub(crate) fn test_non_membership_proof_for_keys_v0(
    occupied_keys: &[[u8; 32]],
    target_key: [u8; 32],
) -> Result<PocoNullifierProofV0> {
    use std::collections::{BTreeMap, BTreeSet};

    ensure!(
        occupied_keys.len() <= u64::MAX as usize,
        "test nullifier occupied-key count exceeds u64"
    );
    let unique = occupied_keys.iter().copied().collect::<BTreeSet<_>>();
    ensure!(
        unique.len() == occupied_keys.len(),
        "test nullifier occupied keys are duplicated"
    );
    ensure!(
        !unique.contains(&target_key),
        "test nullifier target key is already occupied"
    );

    // Nodes at `level` are indexed by the key with the lower `level` path
    // bits cleared.  Level zero is the occupied-leaf layer; after 256 folds
    // one root remains at index zero.
    let mut nodes = unique
        .into_iter()
        .map(|key| (key, occupied_leaf_hash(key)))
        .collect::<BTreeMap<_, _>>();
    let mut siblings = [[0u8; 32]; POCO_NULLIFIER_TREE_DEPTH_V0];
    let mut target_index = target_key;

    for (level, sibling_slot) in siblings.iter_mut().enumerate() {
        let byte = 31 - level / 8;
        let bit = 1u8 << (level % 8);
        let mut sibling_index = target_index;
        sibling_index[byte] ^= bit;
        *sibling_slot = nodes
            .get(&sibling_index)
            .copied()
            .unwrap_or(default_hashes()[level]);

        let mut parents = BTreeMap::new();
        let mut visited = BTreeSet::new();
        for index in nodes.keys().copied().collect::<Vec<_>>() {
            if !visited.insert(index) {
                continue;
            }
            let mut other = index;
            other[byte] ^= bit;
            visited.insert(other);
            let left_index = if path_bit_lsb_first(&index, level) {
                other
            } else {
                index
            };
            let right_index = if left_index == index { other } else { index };
            let left = nodes
                .get(&left_index)
                .copied()
                .unwrap_or(default_hashes()[level]);
            let right = nodes
                .get(&right_index)
                .copied()
                .unwrap_or(default_hashes()[level]);
            let mut parent_index = left_index;
            parent_index[byte] &= !bit;
            parents.insert(parent_index, node_hash(level, left, right));
        }
        target_index[byte] &= !bit;
        nodes = parents;
    }

    let proof = PocoNullifierProofV0::new(target_key, siblings);
    let expected_root = nodes
        .get(&[0u8; 32])
        .copied()
        .unwrap_or(default_hashes()[POCO_NULLIFIER_TREE_DEPTH_V0]);
    ensure!(
        proof.non_membership_root() == expected_root,
        "authored nullifier proof root differs from occupied-key root"
    );
    Ok(proof)
}

pub(crate) fn poco_nullifier_default_hash_v0(level: usize) -> Result<Hash32> {
    default_hashes()
        .get(level)
        .copied()
        .context("PoCO nullifier default-hash level exceeds tree depth")
}

fn default_hashes() -> &'static [Hash32; POCO_NULLIFIER_TREE_DEPTH_V0 + 1] {
    static DEFAULTS: OnceLock<[Hash32; POCO_NULLIFIER_TREE_DEPTH_V0 + 1]> = OnceLock::new();
    DEFAULTS.get_or_init(|| {
        let mut defaults = [[0u8; 32]; POCO_NULLIFIER_TREE_DEPTH_V0 + 1];
        defaults[0] = empty_leaf_hash();
        for level in 0..POCO_NULLIFIER_TREE_DEPTH_V0 {
            defaults[level + 1] = node_hash(level, defaults[level], defaults[level]);
        }
        defaults
    })
}

fn empty_leaf_hash() -> Hash32 {
    domain_hash(EMPTY_LEAF_DOMAIN, &SCHEMA_VERSION_V0.to_be_bytes())
}

fn occupied_leaf_hash(key: Hash32) -> Hash32 {
    let mut encoded = [0u8; 34];
    encoded[..2].copy_from_slice(&SCHEMA_VERSION_V0.to_be_bytes());
    encoded[2..].copy_from_slice(&key);
    domain_hash(OCCUPIED_LEAF_DOMAIN, &encoded)
}

fn node_hash(level: usize, left: Hash32, right: Hash32) -> Hash32 {
    let level = u32::try_from(level).expect("fixed nullifier tree level fits u32");
    let mut encoded = [0u8; 70];
    encoded[..2].copy_from_slice(&SCHEMA_VERSION_V0.to_be_bytes());
    encoded[2..6].copy_from_slice(&level.to_be_bytes());
    encoded[6..38].copy_from_slice(&left);
    encoded[38..].copy_from_slice(&right);
    domain_hash(NODE_DOMAIN, &encoded)
}

fn path_bit_lsb_first(key: &Hash32, level: usize) -> bool {
    debug_assert!(level < POCO_NULLIFIER_TREE_DEPTH_V0);
    let byte = key[31 - level / 8];
    let bit = level % 8;
    ((byte >> bit) & 1) == 1
}

fn domain_hash(domain: &[u8], encoded: &[u8]) -> Hash32 {
    let mut hasher = Sha256::new();
    for frame in [HASH_PREFIX, domain, encoded] {
        let length = u32::try_from(frame.len()).expect("bounded CEV0 hash frame fits u32");
        hasher.update(length.to_be_bytes());
        hasher.update(frame);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash32(fill: u8) -> Hash32 {
        [fill; 32]
    }

    fn empty_proof(key: Hash32) -> PocoNullifierProofV0 {
        let siblings = std::array::from_fn(|level| default_hashes()[level]);
        PocoNullifierProofV0::new(key, siblings)
    }

    #[test]
    fn empty_root_and_lsb_first_path_are_frozen() {
        assert_eq!(
            empty_poco_nullifier_root_v0(),
            poco_nullifier_default_hash_v0(POCO_NULLIFIER_TREE_DEPTH_V0).unwrap()
        );
        assert_ne!(
            poco_nullifier_default_hash_v0(0).unwrap(),
            poco_nullifier_default_hash_v0(1).unwrap()
        );
        assert!(poco_nullifier_default_hash_v0(257).is_err());

        let mut key = [0u8; 32];
        key[31] = 0b0000_0010;
        key[0] = 0b1000_0000;
        assert!(!path_bit_lsb_first(&key, 0));
        assert!(path_bit_lsb_first(&key, 1));
        assert!(path_bit_lsb_first(&key, 255));
    }

    #[test]
    fn families_have_stable_distinct_keys() {
        let families = [
            PocoNullifierFamilyV0::Certificate,
            PocoNullifierFamilyV0::Tuple,
            PocoNullifierFamilyV0::SettlementDecision,
            PocoNullifierFamilyV0::MeterDecision,
            PocoNullifierFamilyV0::EvidenceDecision,
            PocoNullifierFamilyV0::ChallengeDecision,
            PocoNullifierFamilyV0::GovernanceDecision,
            PocoNullifierFamilyV0::RegistrationDecision,
            PocoNullifierFamilyV0::ConsumerKeyDecision,
            PocoNullifierFamilyV0::ConsumerKeyIdentity,
            PocoNullifierFamilyV0::ConsumerNonceSummary,
            PocoNullifierFamilyV0::MeterIdentity,
            PocoNullifierFamilyV0::ValidatorConsensusKey,
            PocoNullifierFamilyV0::ValidatorIdentity,
        ];
        let mut keys = families
            .into_iter()
            .map(|family| {
                assert_eq!(
                    PocoNullifierFamilyV0::from_u8(family.code()).unwrap(),
                    family
                );
                derive_poco_nullifier_key_v0(family, hash32(7))
            })
            .collect::<Vec<_>>();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), 14);
        assert!(PocoNullifierFamilyV0::from_u8(0).is_err());
        assert!(PocoNullifierFamilyV0::from_u8(15).is_err());
    }

    #[test]
    fn empty_non_membership_inserts_once_and_replay_fails() {
        let key = derive_poco_nullifier_key_v0(PocoNullifierFamilyV0::Certificate, hash32(11));
        let proof = empty_proof(key);
        let source = PocoNullifierAccumulatorV0::empty();
        source.verify_non_membership(key, &proof).unwrap();

        let insertion = source
            .verify_non_membership_and_compute_insertion(key, &proof)
            .unwrap();
        assert_eq!(insertion.key(), key);
        assert_eq!(insertion.source_root(), source.root());
        assert_eq!(insertion.source_count(), 0);
        assert_eq!(insertion.target_count(), 1);
        assert_ne!(insertion.target_root(), source.root());

        let target = insertion.target_accumulator().unwrap();
        assert_eq!(target.count(), 1);
        assert!(target.verify_non_membership(key, &proof).is_err());
        assert!(target
            .verify_non_membership_and_compute_insertion(key, &proof)
            .is_err());
    }

    #[test]
    fn sequential_test_proof_joins_at_highest_differing_bit() {
        let existing =
            derive_poco_nullifier_key_v0(PocoNullifierFamilyV0::MeterDecision, hash32(41));
        let target = derive_poco_nullifier_key_v0(PocoNullifierFamilyV0::MeterIdentity, hash32(42));
        let first = empty_proof(existing);
        let after_first = PocoNullifierAccumulatorV0::empty()
            .verify_non_membership_and_compute_insertion(existing, &first)
            .unwrap()
            .target_accumulator()
            .unwrap();
        let second = test_proof_after_single_insertion_v0(existing, target).unwrap();
        after_first.verify_non_membership(target, &second).unwrap();
        assert_eq!(second.key(), target);
    }

    #[test]
    fn wrong_sibling_key_and_root_fail_closed() {
        let key = derive_poco_nullifier_key_v0(PocoNullifierFamilyV0::Tuple, hash32(21));
        let source = PocoNullifierAccumulatorV0::empty();

        let mut wrong_sibling = empty_proof(key);
        wrong_sibling.siblings[17][4] ^= 0x80;
        assert!(source.verify_non_membership(key, &wrong_sibling).is_err());

        let other_key = derive_poco_nullifier_key_v0(PocoNullifierFamilyV0::Tuple, hash32(22));
        let proof = empty_proof(key);
        assert!(source.verify_non_membership(other_key, &proof).is_err());

        let mut wrong_root = source.root();
        wrong_root[0] ^= 1;
        let wrong_source = PocoNullifierAccumulatorV0::from_authenticated_parts(wrong_root, 1)
            .expect("nonempty authenticated parts");
        assert!(wrong_source.verify_non_membership(key, &proof).is_err());
    }

    #[test]
    fn proof_codec_is_exact_and_rejects_header_drift() {
        let key =
            derive_poco_nullifier_key_v0(PocoNullifierFamilyV0::GovernanceDecision, hash32(31));
        let proof = empty_proof(key);
        let encoded = proof.canonical_bytes();
        assert_eq!(encoded.len(), POCO_NULLIFIER_PROOF_ENCODED_BYTES_V0);
        assert_eq!(PocoNullifierProofV0::decode_exact(&encoded).unwrap(), proof);

        for prefix in 0..encoded.len() {
            assert!(PocoNullifierProofV0::decode_exact(&encoded[..prefix]).is_err());
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(PocoNullifierProofV0::decode_exact(&trailing).is_err());

        for range in [0..2, 2..4, 4..6] {
            let mut drifted = encoded.clone();
            drifted[range].fill(0xff);
            assert!(PocoNullifierProofV0::decode_exact(&drifted).is_err());
        }
    }

    #[test]
    fn root_count_binding_and_count_exhaustion_fail_closed() {
        let empty_root = empty_poco_nullifier_root_v0();
        assert!(PocoNullifierAccumulatorV0::from_authenticated_parts(empty_root, 1).is_err());
        assert!(PocoNullifierAccumulatorV0::from_authenticated_parts(hash32(1), 0).is_err());

        let exhausted =
            PocoNullifierAccumulatorV0::from_authenticated_parts(hash32(1), u64::MAX).unwrap();
        let key =
            derive_poco_nullifier_key_v0(PocoNullifierFamilyV0::RegistrationDecision, hash32(41));
        assert!(exhausted
            .verify_non_membership_and_compute_insertion(key, &empty_proof(key))
            .unwrap_err()
            .to_string()
            .contains("count exhausted"));
    }
}
