//! Exact development wire contract. Decoded values are NOT signature-verified authority.
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
pub type Hash = [u8; 32];
pub const HEADER_BYTES: usize = 318;
pub const MAX_TX_BYTES: usize = 2048;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    Length,
    Version,
    Noncanonical,
    Limit,
    KeyCollision,
}
pub fn hash(tag: &[u8], parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    h.update(b"TRNM-PON1\0");
    h.update((tag.len() as u16).to_le_bytes());
    h.update(tag);
    for p in parts {
        h.update((p.len() as u32).to_le_bytes());
        h.update(p);
    }
    h.finalize().into()
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub network: Hash,
    pub parameters: Hash,
    pub parent: Hash,
    pub height: u64,
    pub timestamp: u64,
    pub target: Hash,
    pub miner: Hash,
    pub transactions: Hash,
    pub state: Hash,
    pub receipts: Hash,
    pub work_task: Hash,
    pub nonce: u64,
}
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let end = self.pos.checked_add(N).ok_or(WireError::Length)?;
        let result = self
            .bytes
            .get(self.pos..end)
            .ok_or(WireError::Length)?
            .try_into()
            .map_err(|_| WireError::Length)?;
        self.pos = end;
        Ok(result)
    }
    fn number(&mut self) -> Result<u64, WireError> {
        Ok(u64::from_le_bytes(self.take()?))
    }
}
impl Header {
    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(HEADER_BYTES);
        o.extend(b"PNH1");
        o.extend(1_u16.to_le_bytes());
        for h in [self.network, self.parameters, self.parent] {
            o.extend(h)
        }
        o.extend(self.height.to_le_bytes());
        o.extend(self.timestamp.to_le_bytes());
        for h in [
            self.target,
            self.miner,
            self.transactions,
            self.state,
            self.receipts,
            self.work_task,
        ] {
            o.extend(h)
        }
        o.extend(self.nonce.to_le_bytes());
        o
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() != HEADER_BYTES {
            return Err(WireError::Length);
        }
        let mut r = Reader { bytes, pos: 0 };
        if r.take::<4>()? != *b"PNH1" || r.take::<2>()? != 1_u16.to_le_bytes() {
            return Err(WireError::Version);
        }
        Ok(Self {
            network: r.take()?,
            parameters: r.take()?,
            parent: r.take()?,
            height: r.number()?,
            timestamp: r.number()?,
            target: r.take()?,
            miner: r.take()?,
            transactions: r.take()?,
            state: r.take()?,
            receipts: r.take()?,
            work_task: r.take()?,
            nonce: r.number()?,
        })
    }
    pub fn challenge(&self) -> Hash {
        hash(b"challenge", &[&self.encode()])
    }
    pub fn block_id(&self, trace: Hash) -> Hash {
        hash(b"block", &[&self.encode(), &trace])
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub network: Hash,
    pub sender: Hash,
    pub nonce: u64,
    pub expiry: u64,
    pub fee_limit: u64,
    pub tag: u8,
    pub payload: Vec<u8>,
    pub signature: [u8; 64],
}
fn payload_len(tag: u8, p: &[u8]) -> Result<(), WireError> {
    let size = match tag {
        1 => 40,
        2 => 80,
        3 => 32,
        4 | 5 => 64,
        6 => 176,
        7 => 104,
        8 => {
            if p.len() < 145 {
                return Err(WireError::Length);
            }
            let count = p[144] as usize;
            if !(1..=16).contains(&count) {
                return Err(WireError::Limit);
            }
            if p.len() != 145 + count * 40 {
                return Err(WireError::Length);
            }
            for i in 1..count {
                if p[145 + (i - 1) * 40..177 + (i - 1) * 40] >= p[145 + i * 40..177 + i * 40] {
                    return Err(WireError::Noncanonical);
                }
            }
            145 + count * 40
        }
        10 => 112,
        11 => 136,
        12 => 32,
        // Decoding this candidate payload does not activate it in historical contexts.
        13 => crate::qualified_work_task::SIGNED_TASK_BYTES,
        14 => 96,
        15 => 168,
        16 => {
            if p.len() < 36 {
                return Err(WireError::Length);
            }
            let first = u16::from_le_bytes([p[32], p[33]]) as usize;
            if !(159..=512).contains(&first) || p.len() < 36 + first {
                return Err(WireError::Length);
            }
            let offset = 34 + first;
            let second = u16::from_le_bytes([p[offset], p[offset + 1]]) as usize;
            if !(159..=512).contains(&second) {
                return Err(WireError::Length);
            }
            36 + first + second
        }
        17 => 128,
        18 | 19 => crate::qualified_work_task::lifecycle_v2::DEMAND_LEASE_BYTES,
        20 => crate::qualified_work_task::lifecycle_v2::DEMAND_REVOCATION_BYTES,
        21 => crate::qualified_work_task::lifecycle_v2::LIFECYCLE_TASK_BYTES,
        22 => crate::qualified_work_task::lifecycle_v3::ATOMIC_RENEW_BYTES,
        23 => {
            crate::integer_factor_v2::FactorWitnessV2::decode(p)?;
            p.len()
        }
        9 => {
            if p.len() < 73 {
                return Err(WireError::Length);
            }
            let n = p[72] as usize;
            if n > 8 {
                return Err(WireError::Limit);
            }
            73 + n * 32
        }
        _ => return Err(WireError::Version),
    };
    if p.len() != size {
        return Err(WireError::Length);
    }
    Ok(())
}
impl Envelope {
    pub fn unsigned(&self) -> Result<Vec<u8>, WireError> {
        payload_len(self.tag, &self.payload)?;
        if self.nonce == 0 || self.fee_limit > 10_000_000 {
            return Err(WireError::Noncanonical);
        }
        let mut o = Vec::with_capacity(159 + self.payload.len());
        o.extend(b"PNX1");
        o.extend(self.network);
        o.extend(self.sender);
        o.extend(self.nonce.to_le_bytes());
        o.extend(self.expiry.to_le_bytes());
        o.extend(self.fee_limit.to_le_bytes());
        o.push(self.tag);
        o.extend((self.payload.len() as u16).to_le_bytes());
        o.extend(&self.payload);
        Ok(o)
    }
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut o = self.unsigned()?;
        o.extend(self.signature);
        Ok(o)
    }
    pub fn signing_digest(&self) -> Result<Hash, WireError> {
        Ok(hash(b"tx-sign", &[&self.unsigned()?]))
    }
    pub fn id(&self) -> Result<Hash, WireError> {
        Ok(hash(b"tx-id", &[&self.encode()?]))
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() > MAX_TX_BYTES {
            return Err(WireError::Limit);
        }
        if bytes.len() < 159 {
            return Err(WireError::Length);
        }
        let mut r = Reader { bytes, pos: 0 };
        if r.take::<4>()? != *b"PNX1" {
            return Err(WireError::Version);
        }
        let (network, sender, nonce, expiry, fee_limit) =
            (r.take()?, r.take()?, r.number()?, r.number()?, r.number()?);
        let tag = r.take::<1>()?[0];
        let len = u16::from_le_bytes(r.take()?) as usize;
        if bytes.len() != 159 + len {
            return Err(WireError::Length);
        }
        let payload = bytes[r.pos..r.pos + len].to_vec();
        r.pos += len;
        let signature = r.take()?;
        let out = Self {
            network,
            sender,
            nonce,
            expiry,
            fee_limit,
            tag,
            payload,
            signature,
        };
        out.unsigned()?;
        Ok(out)
    }
}
/// Canonical sparse Merkle root. Values are byte strings; callers enforce value schemas.
/// Missing leaves are distinct from present empty values. Hash-key collisions reject.
pub fn state_root(values: &BTreeMap<Vec<u8>, Vec<u8>>) -> Result<Hash, WireError> {
    if values.len() > 65_536 {
        return Err(WireError::Limit);
    }
    match state_root_from_entries(values.iter().map(Ok::<_, std::convert::Infallible>)) {
        Ok(root) => Ok(root),
        Err(StateRootInputError::Wire(error)) => Err(error),
        Err(StateRootInputError::Input(impossible)) => match impossible {},
    }
}

/// Input failures remain distinct from the fixed wire bounds. No partial root
/// escapes a failed iterator, and a supplied root is never an admission token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateRootInputError<E> {
    Input(E),
    Wire(WireError),
}

/// Consume each borrowed key/owned-or-borrowed encoding once. Retain only the
/// fixed-size path and leaf hashes needed for hash-path sorting, not a second
/// ordered map of all key/value bytes. This remains O(N) hash storage and full
/// sparse-tree work; it neither removes the state cap nor skips any leaf.
///
/// Callers requiring canonical-value errors to precede wire limits must validate
/// their complete value grammar before entering this wire-level operation.
pub fn state_root_from_entries<K, V, E>(
    entries: impl IntoIterator<Item = Result<(K, V), E>>,
) -> Result<Hash, StateRootInputError<E>>
where
    K: AsRef<[u8]>,
    V: AsRef<[u8]>,
{
    let mut leaves = Vec::new();
    for row in entries {
        let (key, value) = row.map_err(StateRootInputError::Input)?;
        let (key, value) = (key.as_ref(), value.as_ref());
        if leaves.len() == 65_536 || key.len() > 160 || value.len() > 4096 {
            return Err(StateRootInputError::Wire(WireError::Limit));
        }
        leaves.push((
            hash(b"state-key", &[key]),
            hash(b"state-leaf", &[key, value]),
        ));
    }
    state_root_from_hashes(leaves).map_err(StateRootInputError::Wire)
}

fn state_root_from_hashes(mut leaves: Vec<(Hash, Hash)>) -> Result<Hash, WireError> {
    leaves.sort_unstable_by_key(|x| x.0);
    if leaves.windows(2).any(|p| p[0].0 == p[1].0) {
        return Err(WireError::KeyCollision);
    }
    let mut empty = [[0; 32]; 257];
    empty[256] = hash(b"state-empty", &[]);
    for d in (0..256).rev() {
        empty[d] = hash(b"state-node", &[&empty[d + 1], &empty[d + 1]])
    }
    fn root(xs: &[(Hash, Hash)], depth: usize, empty: &[Hash; 257]) -> Hash {
        if xs.is_empty() {
            return empty[depth];
        }
        if depth == 256 {
            return xs[0].1;
        }
        let split = xs.partition_point(|x| (x.0[depth / 8] & (128 >> (depth % 8))) == 0);
        hash(
            b"state-node",
            &[
                &root(&xs[..split], depth + 1, empty),
                &root(&xs[split..], depth + 1, empty),
            ],
        )
    }
    Ok(root(&leaves, 0, &empty))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn header_exact_and_context_bound() {
        let mut h = Header {
            network: [1; 32],
            parameters: [2; 32],
            parent: [3; 32],
            height: 1,
            timestamp: 1800000010,
            target: [15; 32],
            miner: [4; 32],
            transactions: [5; 32],
            state: [6; 32],
            receipts: [7; 32],
            work_task: [8; 32],
            nonce: 0,
        };
        assert_eq!(h.encode().len(), HEADER_BYTES);
        assert_eq!(Header::decode(&h.encode()).unwrap(), h);
        let before = h.challenge();
        h.nonce += 1;
        assert_ne!(before, h.challenge());
        let mut b = h.encode();
        b.push(0);
        assert_eq!(Header::decode(&b).unwrap_err(), WireError::Length);
    }
    #[test]
    fn every_tx_tag_has_an_exact_payload() {
        for (tag, n) in [
            (1, 40),
            (2, 80),
            (3, 32),
            (4, 64),
            (5, 64),
            (6, 176),
            (7, 104),
            (9, 73),
            (10, 112),
            (11, 136),
            (12, 32),
        ] {
            let e = Envelope {
                network: [1; 32],
                sender: [2; 32],
                nonce: 1,
                expiry: 10,
                fee_limit: 10000,
                tag,
                payload: vec![0; n],
                signature: [3; 64],
            };
            let b = e.encode().unwrap();
            assert_eq!(Envelope::decode(&b).unwrap(), e);
            for end in 0..b.len() {
                assert!(Envelope::decode(&b[..end]).is_err());
            }
            let mut b = b;
            b.push(0);
            assert!(Envelope::decode(&b).is_err());
        }
    }
    #[test]
    fn contribution_without_signed_round_is_not_revision3_wire() {
        assert_eq!(payload_len(6, &[0; 168]), Err(WireError::Length));
        assert!(payload_len(6, &[0; 176]).is_ok());
        assert_eq!(payload_len(6, &[0; 177]), Err(WireError::Length));
    }

    #[test]
    fn release_payload_is_bounded_and_sorted() {
        let mut p = vec![0; 185];
        p[144] = 1;
        assert!(payload_len(8, &p).is_ok());
        p[144] = 0;
        assert_eq!(payload_len(8, &p), Err(WireError::Limit));
        p = vec![0; 225];
        p[144] = 2;
        assert_eq!(payload_len(8, &p), Err(WireError::Noncanonical));
        p[185] = 1;
        assert!(payload_len(8, &p).is_ok());
    }
    #[test]
    fn sparse_root_is_order_independent_and_value_sensitive() {
        let mut a = BTreeMap::new();
        a.insert(b"a".to_vec(), b"1".to_vec());
        a.insert(b"b".to_vec(), b"2".to_vec());
        let r = state_root(&a).unwrap();
        a.insert(b"b".to_vec(), b"3".to_vec());
        assert_ne!(r, state_root(&a).unwrap());
        assert_ne!(r, state_root(&BTreeMap::new()).unwrap());
    }
}

#[cfg(test)]
mod streamed_state_root_tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    // Exact pre-refactor complete-map algorithm, including its independent
    // sparse recursion. It does not call the streamed hash-root implementation.
    fn original_state_root(values: &BTreeMap<Vec<u8>, Vec<u8>>) -> Result<Hash, WireError> {
        if values.len() > 65_536 {
            return Err(WireError::Limit);
        }
        let mut leaves = Vec::with_capacity(values.len());
        for (k, v) in values {
            if k.len() > 160 || v.len() > 4096 {
                return Err(WireError::Limit);
            }
            leaves.push((hash(b"state-key", &[k]), hash(b"state-leaf", &[k, v])));
        }
        leaves.sort_unstable_by_key(|x| x.0);
        if leaves.windows(2).any(|p| p[0].0 == p[1].0) {
            return Err(WireError::KeyCollision);
        }
        let mut empty = [[0; 32]; 257];
        empty[256] = hash(b"state-empty", &[]);
        for d in (0..256).rev() {
            empty[d] = hash(b"state-node", &[&empty[d + 1], &empty[d + 1]])
        }
        fn root(xs: &[(Hash, Hash)], depth: usize, empty: &[Hash; 257]) -> Hash {
            if xs.is_empty() {
                return empty[depth];
            }
            if depth == 256 {
                return xs[0].1;
            }
            let split = xs.partition_point(|x| (x.0[depth / 8] & (128 >> (depth % 8))) == 0);
            hash(
                b"state-node",
                &[
                    &root(&xs[..split], depth + 1, empty),
                    &root(&xs[split..], depth + 1, empty),
                ],
            )
        }
        Ok(root(&leaves, 0, &empty))
    }

    fn fixture(count: usize) -> BTreeMap<Vec<u8>, Vec<u8>> {
        (0..count)
            .map(|i| {
                (
                    format!("key-{i:05}").into_bytes(),
                    (i as u64).to_le_bytes().to_vec(),
                )
            })
            .collect()
    }

    #[test]
    fn streamed_state_root_preserves_original_sparse_tree_for_all_input_orders() {
        for count in [0, 1, 2, 3, 7, 16, 31, 32, 33, 128, 257, 1025] {
            let values = fixture(count);
            let expected = original_state_root(&values).unwrap();
            assert_eq!(state_root(&values).unwrap(), expected);
            for reverse in [false, true] {
                let mut rows: Vec<_> = values.iter().collect();
                if reverse {
                    rows.reverse();
                }
                assert_eq!(
                    state_root_from_entries(rows.into_iter().map(Ok::<_, ()>)).unwrap(),
                    expected
                );
            }
        }
        let absent = BTreeMap::new();
        let empty = BTreeMap::from([(Vec::new(), Vec::new())]);
        assert_ne!(state_root(&absent).unwrap(), state_root(&empty).unwrap());
        assert_eq!(
            state_root(&empty).unwrap(),
            original_state_root(&empty).unwrap()
        );
    }

    #[test]
    fn streamed_state_root_refuses_duplicate_limit_and_truncated_producer_errors() {
        let duplicate = [(b"key", b"one"), (b"key", b"two")];
        assert_eq!(
            state_root_from_entries(duplicate.into_iter().map(Ok::<_, ()>)),
            Err(StateRootInputError::Wire(WireError::KeyCollision))
        );
        for (key, value) in [(vec![0; 161], vec![0]), (vec![0], vec![0; 4097])] {
            assert_eq!(
                state_root_from_entries([Ok::<_, ()>((key, value))]),
                Err(StateRootInputError::Wire(WireError::Limit))
            );
        }
        let over = (0..65_537u64).map(|i| Ok::<_, ()>((i.to_le_bytes(), [0u8])));
        assert_eq!(
            state_root_from_entries(over),
            Err(StateRootInputError::Wire(WireError::Limit))
        );
        for cut in [0, 1, 255, 256, 257] {
            let rows = (0..258u64).map(|i| {
                if i == cut {
                    Err("source-cancelled")
                } else {
                    Ok((i.to_le_bytes(), [0u8]))
                }
            });
            assert_eq!(
                state_root_from_entries(rows),
                Err(StateRootInputError::Input("source-cancelled"))
            );
        }
        let boundary = BTreeMap::from([(vec![255; 160], vec![255; 4096])]);
        assert_eq!(state_root(&boundary), original_state_root(&boundary));
    }

    #[test]
    fn streamed_state_root_drops_each_owned_encoding_before_requesting_the_next() {
        struct Encoded {
            bytes: Vec<u8>,
            live: Rc<Cell<usize>>,
        }
        impl AsRef<[u8]> for Encoded {
            fn as_ref(&self) -> &[u8] {
                &self.bytes
            }
        }
        impl Drop for Encoded {
            fn drop(&mut self) {
                self.live.set(self.live.get() - 1);
            }
        }
        let live = Rc::new(Cell::new(0));
        let values = fixture(257);
        let rows = values.iter().map(|(key, bytes)| {
            assert_eq!(
                live.get(),
                0,
                "the previous encoded payload must be released"
            );
            live.set(1);
            Ok::<_, ()>((
                key,
                Encoded {
                    bytes: bytes.clone(),
                    live: live.clone(),
                },
            ))
        });
        assert_eq!(
            state_root_from_entries(rows).unwrap(),
            original_state_root(&values).unwrap()
        );
        assert_eq!(live.get(), 0);
    }
}
