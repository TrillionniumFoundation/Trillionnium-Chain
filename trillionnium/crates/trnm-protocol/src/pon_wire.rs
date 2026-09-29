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
            (6, 168),
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
