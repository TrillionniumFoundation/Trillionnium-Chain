#![forbid(unsafe_code)]
//! Candidate-only versioned sparse application tree.
//!
//! This standalone Rust verifier mirrors the candidate Protocol-09 state-tree
//! domains and 256-bit path ordering. It deliberately carries no Node, Order,
//! finality, checkpoint, signer, settlement, or activation authority.

use std::collections::{BTreeMap, BTreeSet};

pub const DEPTH_V1: usize = 256;
pub const MAX_VALUE_BYTES_V1: usize = 4 * 1024 * 1024;
pub const APPLICATION_JMT_IMPLEMENTATION_CANDIDATE_V1: bool = true;
pub const CANONICAL_APPLICATION_JMT_AUTHORITY_V1: bool = false;
pub const ORDER_FINALITY_AUTHORITY_V1: bool = false;
pub const PRODUCTION_ACTIVATION_V1: bool = false;

type Hash32 = [u8; 32];
type NodeIndex = [u8; 32];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateRecordV1 {
    pub object_kind: u16,
    pub object_id: [u8; 32],
    pub object_version: u64,
    pub value: Vec<u8>,
}

impl StateRecordV1 {
    pub fn new(
        object_kind: u16,
        object_id: [u8; 32],
        object_version: u64,
        value: Vec<u8>,
    ) -> Result<Self, ApplicationJmtErrorV1> {
        if object_kind == 0 || value.len() > MAX_VALUE_BYTES_V1 {
            return Err(ApplicationJmtErrorV1::InvalidRecord);
        }
        Ok(Self {
            object_kind,
            object_id,
            object_version,
            value,
        })
    }

    pub fn key(&self) -> Hash32 {
        state_key_v1(self.object_kind, self.object_id)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SparseProofV1 {
    pub object_version: Option<u64>,
    pub value: Option<Vec<u8>>,
    pub siblings: Vec<Hash32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VersionedWriteV1 {
    Put(StateRecordV1),
    Delete {
        object_kind: u16,
        object_id: [u8; 32],
    },
}

impl VersionedWriteV1 {
    fn key(&self) -> Result<Hash32, ApplicationJmtErrorV1> {
        match self {
            Self::Put(record) => Ok(record.key()),
            Self::Delete {
                object_kind,
                object_id,
            } => {
                if *object_kind == 0 {
                    Err(ApplicationJmtErrorV1::InvalidRecord)
                } else {
                    Ok(state_key_v1(*object_kind, *object_id))
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationJmtErrorV1 {
    InvalidRecord,
    DuplicateStateKey,
    StaleParent,
    VersionSequence,
    WriteVersionMismatch,
    MissingVersion,
    MissingObject,
    ObjectAlreadyPresent,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VersionedApplicationTreeV1 {
    latest_version: Option<u64>,
    versions: BTreeMap<u64, BTreeMap<Hash32, StateRecordV1>>,
    roots: BTreeMap<u64, Hash32>,
}

impl VersionedApplicationTreeV1 {
    pub fn latest_version(&self) -> Option<u64> {
        self.latest_version
    }

    pub fn commit(
        &mut self,
        parent_version: Option<u64>,
        new_version: u64,
        mut writes: Vec<VersionedWriteV1>,
    ) -> Result<Hash32, ApplicationJmtErrorV1> {
        if parent_version != self.latest_version {
            return Err(ApplicationJmtErrorV1::StaleParent);
        }
        match self.latest_version {
            None if new_version != 0 => return Err(ApplicationJmtErrorV1::VersionSequence),
            Some(latest) if latest.checked_add(1) != Some(new_version) => {
                return Err(ApplicationJmtErrorV1::VersionSequence)
            }
            _ => {}
        }

        writes.sort_by_key(|write| write.key().unwrap_or([0; 32]));
        let mut previous = None;
        for write in &writes {
            let key = write.key()?;
            if previous == Some(key) {
                return Err(ApplicationJmtErrorV1::DuplicateStateKey);
            }
            previous = Some(key);
            if let VersionedWriteV1::Put(record) = write {
                if record.object_version != new_version {
                    return Err(ApplicationJmtErrorV1::WriteVersionMismatch);
                }
            }
        }

        let mut snapshot = match parent_version {
            Some(parent) => self
                .versions
                .get(&parent)
                .cloned()
                .ok_or(ApplicationJmtErrorV1::MissingVersion)?,
            None => BTreeMap::new(),
        };
        for write in writes {
            match write {
                VersionedWriteV1::Put(record) => {
                    snapshot.insert(record.key(), record);
                }
                VersionedWriteV1::Delete {
                    object_kind,
                    object_id,
                } => {
                    let key = state_key_v1(object_kind, object_id);
                    if snapshot.remove(&key).is_none() {
                        return Err(ApplicationJmtErrorV1::MissingObject);
                    }
                }
            }
        }

        let root = sparse_root_v1(snapshot.values().cloned())?;
        self.versions.insert(new_version, snapshot);
        self.roots.insert(new_version, root);
        self.latest_version = Some(new_version);
        Ok(root)
    }

    pub fn root(&self, version: u64) -> Result<Hash32, ApplicationJmtErrorV1> {
        self.roots
            .get(&version)
            .copied()
            .ok_or(ApplicationJmtErrorV1::MissingVersion)
    }

    pub fn record(
        &self,
        version: u64,
        object_kind: u16,
        object_id: [u8; 32],
    ) -> Result<&StateRecordV1, ApplicationJmtErrorV1> {
        let snapshot = self
            .versions
            .get(&version)
            .ok_or(ApplicationJmtErrorV1::MissingVersion)?;
        snapshot
            .get(&state_key_v1(object_kind, object_id))
            .ok_or(ApplicationJmtErrorV1::MissingObject)
    }

    pub fn membership_proof(
        &self,
        version: u64,
        object_kind: u16,
        object_id: [u8; 32],
    ) -> Result<SparseProofV1, ApplicationJmtErrorV1> {
        let snapshot = self
            .versions
            .get(&version)
            .ok_or(ApplicationJmtErrorV1::MissingVersion)?;
        let key = state_key_v1(object_kind, object_id);
        let record = snapshot
            .get(&key)
            .cloned()
            .ok_or(ApplicationJmtErrorV1::MissingObject)?;
        proof_for_key_v1(snapshot.values().cloned(), key, Some(record))
    }

    pub fn nonmembership_proof(
        &self,
        version: u64,
        object_kind: u16,
        object_id: [u8; 32],
    ) -> Result<SparseProofV1, ApplicationJmtErrorV1> {
        if object_kind == 0 {
            return Err(ApplicationJmtErrorV1::InvalidRecord);
        }
        let snapshot = self
            .versions
            .get(&version)
            .ok_or(ApplicationJmtErrorV1::MissingVersion)?;
        let key = state_key_v1(object_kind, object_id);
        if snapshot.contains_key(&key) {
            return Err(ApplicationJmtErrorV1::ObjectAlreadyPresent);
        }
        proof_for_key_v1(snapshot.values().cloned(), key, None)
    }
}

pub fn state_key_v1(object_kind: u16, object_id: [u8; 32]) -> Hash32 {
    let mut payload = Vec::with_capacity(34);
    payload.extend_from_slice(&object_kind.to_le_bytes());
    payload.extend_from_slice(&object_id);
    digest_v1("trnm.poco-ai.state-key.v1", &payload)
}

pub fn sparse_root_v1(
    records: impl IntoIterator<Item = StateRecordV1>,
) -> Result<Hash32, ApplicationJmtErrorV1> {
    let records = checked_records(records)?;
    let empties = empty_hashes_v1();
    if records.is_empty() {
        return Ok(empties[DEPTH_V1]);
    }

    let mut current = BTreeMap::<NodeIndex, Hash32>::new();
    for record in records {
        current.insert(record.key(), leaf_hash_v1(&record));
    }
    for level in 0..DEPTH_V1 {
        current = parent_level_v1(&current, level, &empties);
    }
    Ok(current.get(&[0; 32]).copied().unwrap_or(empties[DEPTH_V1]))
}

pub fn verify_membership_v1(
    object_kind: u16,
    object_id: [u8; 32],
    proof: &SparseProofV1,
    expected_root: Hash32,
) -> bool {
    let (Some(object_version), Some(value)) = (proof.object_version, proof.value.as_ref()) else {
        return false;
    };
    if object_kind == 0 || value.len() > MAX_VALUE_BYTES_V1 || proof.siblings.len() != DEPTH_V1 {
        return false;
    }
    let Ok(record) = StateRecordV1::new(object_kind, object_id, object_version, value.clone()) else {
        return false;
    };
    verify_from_leaf_v1(record.key(), leaf_hash_v1(&record), &proof.siblings, expected_root)
}

pub fn verify_nonmembership_v1(
    object_kind: u16,
    object_id: [u8; 32],
    proof: &SparseProofV1,
    expected_root: Hash32,
) -> bool {
    if object_kind == 0
        || proof.object_version.is_some()
        || proof.value.is_some()
        || proof.siblings.len() != DEPTH_V1
    {
        return false;
    }
    let empties = empty_hashes_v1();
    verify_from_leaf_v1(
        state_key_v1(object_kind, object_id),
        empties[0],
        &proof.siblings,
        expected_root,
    )
}

fn checked_records(
    records: impl IntoIterator<Item = StateRecordV1>,
) -> Result<Vec<StateRecordV1>, ApplicationJmtErrorV1> {
    let mut rows = records.into_iter().collect::<Vec<_>>();
    for record in &rows {
        if record.object_kind == 0 || record.value.len() > MAX_VALUE_BYTES_V1 {
            return Err(ApplicationJmtErrorV1::InvalidRecord);
        }
    }
    rows.sort_by_key(StateRecordV1::key);
    for pair in rows.windows(2) {
        if pair[0].key() == pair[1].key() {
            return Err(ApplicationJmtErrorV1::DuplicateStateKey);
        }
    }
    Ok(rows)
}

fn proof_for_key_v1(
    records: impl IntoIterator<Item = StateRecordV1>,
    key: Hash32,
    target: Option<StateRecordV1>,
) -> Result<SparseProofV1, ApplicationJmtErrorV1> {
    let records = checked_records(records)?;
    let empties = empty_hashes_v1();
    let mut current = BTreeMap::<NodeIndex, Hash32>::new();
    for record in records {
        current.insert(record.key(), leaf_hash_v1(&record));
    }
    let mut target_index = key;
    let mut siblings = Vec::with_capacity(DEPTH_V1);
    for level in 0..DEPTH_V1 {
        siblings.push(
            current
                .get(&toggle_low_bit_v1(target_index))
                .copied()
                .unwrap_or(empties[level]),
        );
        current = parent_level_v1(&current, level, &empties);
        target_index = shift_right_one_v1(target_index);
    }
    Ok(match target {
        Some(record) => SparseProofV1 {
            object_version: Some(record.object_version),
            value: Some(record.value),
            siblings,
        },
        None => SparseProofV1 {
            object_version: None,
            value: None,
            siblings,
        },
    })
}

fn parent_level_v1(
    current: &BTreeMap<NodeIndex, Hash32>,
    level: usize,
    empties: &[Hash32],
) -> BTreeMap<NodeIndex, Hash32> {
    let parents = current
        .keys()
        .copied()
        .map(shift_right_one_v1)
        .collect::<BTreeSet<_>>();
    let mut output = BTreeMap::new();
    for parent in parents {
        let left_index = shift_left_one_v1(parent, false);
        let right_index = shift_left_one_v1(parent, true);
        let left = current.get(&left_index).copied().unwrap_or(empties[level]);
        let right = current
            .get(&right_index)
            .copied()
            .unwrap_or(empties[level]);
        output.insert(parent, node_hash_v1(level, left, right));
    }
    output
}

fn verify_from_leaf_v1(
    key: Hash32,
    mut running: Hash32,
    siblings: &[Hash32],
    expected_root: Hash32,
) -> bool {
    for (level, sibling) in siblings.iter().copied().enumerate() {
        running = if low_bit_at_v1(key, level) {
            node_hash_v1(level, sibling, running)
        } else {
            node_hash_v1(level, running, sibling)
        };
    }
    running == expected_root
}

fn leaf_hash_v1(record: &StateRecordV1) -> Hash32 {
    let mut payload = Vec::with_capacity(32 + 2 + 8 + 4 + record.value.len());
    payload.extend_from_slice(&record.key());
    payload.extend_from_slice(&record.object_kind.to_le_bytes());
    payload.extend_from_slice(&record.object_version.to_le_bytes());
    payload.extend_from_slice(
        &u32::try_from(record.value.len())
            .expect("bounded state value length")
            .to_le_bytes(),
    );
    payload.extend_from_slice(&record.value);
    digest_v1("trnm.poco-ai.state-leaf.v1", &payload)
}

fn empty_hashes_v1() -> Vec<Hash32> {
    let mut values = Vec::with_capacity(DEPTH_V1 + 1);
    values.push(digest_v1(
        "trnm.poco-ai.state-empty-leaf.v1",
        &0_u16.to_le_bytes(),
    ));
    for level in 0..DEPTH_V1 {
        values.push(node_hash_v1(level, values[level], values[level]));
    }
    values
}

fn node_hash_v1(level: usize, left: Hash32, right: Hash32) -> Hash32 {
    let mut payload = Vec::with_capacity(66);
    payload.extend_from_slice(
        &u16::try_from(level)
            .expect("sparse-tree level fits u16")
            .to_le_bytes(),
    );
    payload.extend_from_slice(&left);
    payload.extend_from_slice(&right);
    digest_v1("trnm.poco-ai.state-node.v1", &payload)
}

fn low_bit_at_v1(value: Hash32, level: usize) -> bool {
    let byte = 31 - level / 8;
    ((value[byte] >> (level % 8)) & 1) == 1
}

fn toggle_low_bit_v1(mut value: NodeIndex) -> NodeIndex {
    value[31] ^= 1;
    value
}

fn shift_right_one_v1(value: NodeIndex) -> NodeIndex {
    let mut output = [0; 32];
    let mut carry = 0_u8;
    for (index, byte) in value.into_iter().enumerate() {
        output[index] = (byte >> 1) | carry;
        carry = (byte & 1) << 7;
    }
    output
}

fn shift_left_one_v1(value: NodeIndex, low_bit: bool) -> NodeIndex {
    let mut output = [0; 32];
    let mut carry = u8::from(low_bit);
    for index in (0..32).rev() {
        output[index] = (value[index] << 1) | carry;
        carry = value[index] >> 7;
    }
    output
}

fn digest_v1(domain: &str, payload: &[u8]) -> Hash32 {
    let domain = domain.as_bytes();
    let mut framed = Vec::with_capacity(4 + domain.len() + payload.len());
    framed.extend_from_slice(
        &u32::try_from(domain.len())
            .expect("digest domain length fits u32")
            .to_le_bytes(),
    );
    framed.extend_from_slice(domain);
    framed.extend_from_slice(payload);
    sha256_v1(&framed)
}

fn sha256_v1(input: &[u8]) -> Hash32 {
    const INITIAL: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    const ROUND: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    let bit_length = u64::try_from(input.len())
        .expect("SHA-256 input length fits u64")
        .checked_mul(8)
        .expect("SHA-256 bit length fits u64");
    let mut padded = input.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_length.to_be_bytes());

    let mut state = INITIAL;
    for block in padded.chunks_exact(64) {
        let mut words = [0_u32; 64];
        for (index, word) in words.iter_mut().take(16).enumerate() {
            let start = index * 4;
            *word = u32::from_be_bytes(
                block[start..start + 4]
                    .try_into()
                    .expect("SHA-256 word width"),
            );
        }
        for index in 16..64 {
            let small0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let small1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(small0)
                .wrapping_add(words[index - 7])
                .wrapping_add(small1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let big1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(big1)
                .wrapping_add(choose)
                .wrapping_add(ROUND[index])
                .wrapping_add(words[index]);
            let big0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = big0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    let mut output = [0; 32];
    for (index, word) in state.into_iter().enumerate() {
        output[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: u8) -> [u8; 32] {
        [value; 32]
    }

    fn hash(hex: &str) -> Hash32 {
        assert_eq!(hex.len(), 64);
        let mut output = [0; 32];
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
                .expect("valid test hash");
        }
        output
    }

    #[test]
    fn sha256_and_protocol09_fixed_vectors_match() {
        assert_eq!(
            sha256_v1(b"abc"),
            hash("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(
            empty_hashes_v1()[DEPTH_V1],
            hash("e7973f7b9e655388bbab7edf097ba7fbf16befe699b1be1530fa7b46ed19d49c")
        );
        let records = vec![
            StateRecordV1::new(1, id(1), 1, b"alpha".to_vec()).expect("record"),
            StateRecordV1::new(2, id(2), 1, b"beta".to_vec()).expect("record"),
            StateRecordV1::new(3, id(3), 2, b"gamma".to_vec()).expect("record"),
        ];
        assert_eq!(
            sparse_root_v1(records).expect("root"),
            hash("6e6e92f5eebb5d58a405e0158bffbe38816dbf3d77f9342b89d02f49f2d0770a")
        );
    }

    #[test]
    fn versioned_membership_nonmembership_and_prior_isolation_hold() {
        let mut tree = VersionedApplicationTreeV1::default();
        let root0 = tree
            .commit(
                None,
                0,
                vec![
                    VersionedWriteV1::Put(
                        StateRecordV1::new(1, id(1), 0, b"one-v0".to_vec())
                            .expect("record"),
                    ),
                    VersionedWriteV1::Put(
                        StateRecordV1::new(2, id(2), 0, b"two-v0".to_vec())
                            .expect("record"),
                    ),
                ],
            )
            .expect("version zero");
        let proof0 = tree.membership_proof(0, 1, id(1)).expect("proof");
        assert!(verify_membership_v1(1, id(1), &proof0, root0));

        let root1 = tree
            .commit(
                Some(0),
                1,
                vec![
                    VersionedWriteV1::Put(
                        StateRecordV1::new(1, id(1), 1, b"one-v1".to_vec())
                            .expect("record"),
                    ),
                    VersionedWriteV1::Put(
                        StateRecordV1::new(3, id(3), 1, b"three-v1".to_vec())
                            .expect("record"),
                    ),
                ],
            )
            .expect("version one");
        assert_ne!(root0, root1);
        assert_eq!(tree.root(0).expect("old root"), root0);
        assert_eq!(tree.record(0, 1, id(1)).expect("old record").value, b"one-v0");
        assert_eq!(tree.record(1, 1, id(1)).expect("new record").value, b"one-v1");

        let membership = tree.membership_proof(1, 3, id(3)).expect("membership");
        assert!(verify_membership_v1(3, id(3), &membership, root1));
        let absence = tree
            .nonmembership_proof(1, 4, id(4))
            .expect("nonmembership");
        assert!(verify_nonmembership_v1(4, id(4), &absence, root1));
        assert!(!verify_membership_v1(4, id(4), &absence, root1));
        assert!(!verify_nonmembership_v1(3, id(3), &membership, root1));
    }

    #[test]
    fn stale_duplicate_version_and_proof_mutants_fail_closed() {
        let mut tree = VersionedApplicationTreeV1::default();
        let root0 = tree
            .commit(
                None,
                0,
                vec![VersionedWriteV1::Put(
                    StateRecordV1::new(1, id(1), 0, b"value".to_vec()).expect("record"),
                )],
            )
            .expect("version zero");
        assert_eq!(
            tree.commit(Some(9), 1, Vec::new()),
            Err(ApplicationJmtErrorV1::StaleParent)
        );
        assert_eq!(
            tree.commit(Some(0), 2, Vec::new()),
            Err(ApplicationJmtErrorV1::VersionSequence)
        );
        assert_eq!(
            tree.commit(
                Some(0),
                1,
                vec![VersionedWriteV1::Put(
                    StateRecordV1::new(2, id(2), 7, b"wrong-version".to_vec())
                        .expect("record"),
                )],
            ),
            Err(ApplicationJmtErrorV1::WriteVersionMismatch)
        );
        let duplicate = StateRecordV1::new(2, id(2), 1, b"duplicate".to_vec())
            .expect("record");
        assert_eq!(
            tree.commit(
                Some(0),
                1,
                vec![
                    VersionedWriteV1::Put(duplicate.clone()),
                    VersionedWriteV1::Put(duplicate),
                ],
            ),
            Err(ApplicationJmtErrorV1::DuplicateStateKey)
        );

        let mut proof = tree.membership_proof(0, 1, id(1)).expect("proof");
        proof.siblings[0][0] ^= 1;
        assert!(!verify_membership_v1(1, id(1), &proof, root0));
        let mut proof = tree.membership_proof(0, 1, id(1)).expect("proof");
        proof.value = Some(b"tampered".to_vec());
        assert!(!verify_membership_v1(1, id(1), &proof, root0));
        assert!(!verify_membership_v1(1, id(1), &proof, [0; 32]));
    }

    #[test]
    fn deletion_is_versioned_and_authority_flags_remain_false() {
        let mut tree = VersionedApplicationTreeV1::default();
        tree.commit(
            None,
            0,
            vec![VersionedWriteV1::Put(
                StateRecordV1::new(9, id(9), 0, b"delete-me".to_vec()).expect("record"),
            )],
        )
        .expect("version zero");
        let root1 = tree
            .commit(
                Some(0),
                1,
                vec![VersionedWriteV1::Delete {
                    object_kind: 9,
                    object_id: id(9),
                }],
            )
            .expect("delete version");
        let proof = tree
            .nonmembership_proof(1, 9, id(9))
            .expect("nonmembership");
        assert!(verify_nonmembership_v1(9, id(9), &proof, root1));
        assert!(APPLICATION_JMT_IMPLEMENTATION_CANDIDATE_V1);
        assert!(!CANONICAL_APPLICATION_JMT_AUTHORITY_V1);
        assert!(!ORDER_FINALITY_AUTHORITY_V1);
        assert!(!PRODUCTION_ACTIVATION_V1);
    }
}
