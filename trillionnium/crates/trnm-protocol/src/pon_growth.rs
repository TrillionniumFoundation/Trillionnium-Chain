//! Explicit permanent-account header. PNH1 encoding and domains stay unchanged.
use crate::pon_wire::{hash, Hash, Header, WireError, HEADER_BYTES};

pub const GROWTH_HEADER_BYTES: usize = 4 + HEADER_BYTES + 32;
pub const WIRE_PROFILE: &[u8] = b"PGH2/PNP2/AAM1/local-working-v2";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrowthHeader {
    pub ledger: Header,
    pub witness: Hash,
}
impl GrowthHeader {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(GROWTH_HEADER_BYTES);
        out.extend(b"PGH2");
        out.extend(self.ledger.encode());
        out.extend(self.witness);
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() != GROWTH_HEADER_BYTES {
            return Err(WireError::Length);
        }
        if bytes[..4] != *b"PGH2" {
            return Err(WireError::Version);
        }
        Ok(Self {
            ledger: Header::decode(&bytes[4..4 + HEADER_BYTES])?,
            witness: bytes[4 + HEADER_BYTES..]
                .try_into()
                .map_err(|_| WireError::Length)?,
        })
    }
    pub fn challenge(&self) -> Hash {
        hash(b"permanent-account-growth-challenge-v2", &[&self.encode()])
    }
    pub fn block_id(&self, trace: Hash) -> Hash {
        hash(
            b"permanent-account-growth-block-v2",
            &[&self.encode(), &trace],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_growth_v2_header_fixed_vector_and_domain_separation() {
        let header = GrowthHeader {
            ledger: Header {
                network: [1; 32],
                parameters: [2; 32],
                parent: [3; 32],
                height: 7,
                timestamp: 11,
                target: [4; 32],
                miner: [5; 32],
                transactions: [6; 32],
                state: [7; 32],
                receipts: [8; 32],
                work_task: [9; 32],
                nonce: 13,
            },
            witness: [10; 32],
        };
        let encoded = header.encode();
        assert_eq!(encoded.len(), 354);
        assert_eq!(GrowthHeader::decode(&encoded).unwrap(), header);
        // These vectors were independently encoded with Python struct/hashlib,
        // including each domain/part-length field, rather than this encoder.
        assert_eq!(
            hex::encode(header.challenge()),
            "8f051f34d44a6385e3c386325c2d82091d2563b40ce4443f1056ef5abf633208"
        );
        assert_eq!(
            hex::encode(header.block_id([11; 32])),
            "4b87b9fca8d5a0eeec486d9eef108b445d28998fe5db3cc0f4f6dea6db9a22eb"
        );
        assert_eq!(
            hex::encode(header.ledger.challenge()),
            "ac255d77ec6355f0382a5cbe1ac003e692e4802c00ccc9468c759869a1b8421d"
        );
        assert!(Header::decode(&encoded).is_err());
        assert!(GrowthHeader::decode(&header.ledger.encode()).is_err());
        for length in [0, 4, 318, 353] {
            assert!(GrowthHeader::decode(&encoded[..length]).is_err());
        }
        let mut appended = encoded.clone();
        appended.push(0);
        assert!(GrowthHeader::decode(&appended).is_err());
        for index in [0, 4, 8, 321, 353] {
            let mut changed = encoded.clone();
            changed[index] ^= 1;
            match GrowthHeader::decode(&changed) {
                Ok(changed) => {
                    assert_ne!(changed.challenge(), header.challenge());
                    assert_ne!(changed.block_id([11; 32]), header.block_id([11; 32]));
                }
                Err(WireError::Version) => {}
                Err(other) => panic!("unexpected valid-length mutation: {other:?}"),
            }
        }
    }
}
