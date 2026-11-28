use std::io::{self, Read, Write};

use trnm_data_availability::{
    DaAuthorAuthorityV1, DaCommitteeDescriptorV1, DaErrorCodeV1, DaPolicyV1,
};

fn main() -> io::Result<()> {
    let mut stream = io::stdin().lock();
    let mut output = io::stdout().lock();
    loop {
        let mut size_bytes = [0; 4];
        if stream.read(&mut size_bytes[..1])? == 0 {
            return Ok(());
        }
        stream.read_exact(&mut size_bytes[1..])?;
        let size = u32::from_le_bytes(size_bytes) as usize;
        assert!((177..=1_048_577).contains(&size));
        let mut raw = vec![0; size];
        stream.read_exact(&mut raw)?;
        let end = u32::from_le_bytes(raw[size - 4..].try_into().unwrap()) as usize;
        let footer = size - 40;
        assert!(end >= 133 && end + 4 <= footer);
        let committee = borsh::from_slice::<DaCommitteeDescriptorV1>(&raw[..end]).unwrap();
        let authors = borsh::from_slice::<Vec<DaAuthorAuthorityV1>>(&raw[end..footer]).unwrap();
        assert_eq!(borsh::to_vec(&committee).unwrap(), raw[..end]);
        assert_eq!(borsh::to_vec(&authors).unwrap(), raw[end..footer]);
        let word = |i: usize| u32::from_le_bytes(raw[footer+i..footer+i+4].try_into().unwrap());
        let wide = |i: usize| u64::from_le_bytes(raw[footer+i..footer+i+8].try_into().unwrap());
        let original = DaPolicyV1::new_transaction_batch(
            &committee, authors, word(0), word(4), word(8), wide(12), wide(20), wide(28),
        );
        let (code, body) = match original {
            Ok(policy) => {
                let mut bytes = borsh::to_vec(&policy).unwrap();
                let hash = policy.policy_hash().unwrap();
                bytes.extend_from_slice(hash.as_bytes());
                (0u8, bytes)
            }
            Err(err) => {
                use DaErrorCodeV1::*;
                let (kind, code) = match err.message() {
                    "invalid DA author authority" => (InvalidBounds, 3),
                    "author key is not strict Ed25519" => (InvalidSignature, 6),
                    "weak author key is forbidden" => (InvalidSignature, 7),
                    "invalid DA member definition" => (InvalidCommittee, 201),
                    "invalid DA member Ed25519 key" => (InvalidCommittee, 202),
                    "weak DA member key is forbidden" => (InvalidCommittee, 203),
                    "DA committee must not be empty" => (InvalidCommittee, 204),
                    "DA members must be strictly ordered with unique keys" => (InvalidCommittee, 205),
                    "DA committee weight overflow" => (ArithmeticOverflow, 206),
                    "unsupported context version" => (InvalidContext, 208),
                    "chain ID must be bounded nonempty ASCII" => (InvalidContext, 209),
                    "invalid committee bounds" => (InvalidCommittee, 210),
                    "committee quorum calculation overflow" => (ArithmeticOverflow, 211),
                    "committee threshold is not floor(2W/3)+1" => (InvalidCommittee, 212),
                    "ArtifactEvidence is outside this candidate tranche" => (UnsupportedNamespace, 213),
                    "unknown DA namespace" => (UnsupportedNamespace, 214),
                    "invalid transaction-batch DA policy" => (InvalidBounds, 215),
                    "chunk bound exceeds batch bound" => (InvalidBounds, 216),
                    "authorities must be canonical and within committee limits" => (InvalidBounds, 217),
                    "DA policy requires an author authority" => (InvalidBounds, 218),
                    unexpected => panic!("Unexpected original DA policy result {unexpected:?}"),
                };
                assert_eq!(err.code(), kind);
                (code, Vec::new())
            }
        };
        output.write_all(&[code])?;
        output.write_all(&(body.len() as u32).to_le_bytes())?;
        output.write_all(&body)?;
    }
}
