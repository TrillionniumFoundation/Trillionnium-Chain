use std::io::{self, Read, Write};

use trnm_data_availability::{DaCommitteeDescriptorV1, DaErrorCodeV1};

fn main() -> io::Result<()> {
    let mut stream = io::stdin().lock();
    let mut out = io::stdout().lock();
    loop {
        let mut len = [0; 4];
        if stream.read(&mut len[..1])? == 0 {
            return Ok(());
        }
        stream.read_exact(&mut len[1..])?;
        let size = u32::from_le_bytes(len) as usize;
        assert!((133..=1_048_577).contains(&size));
        let mut frame = vec![0; size];
        stream.read_exact(&mut frame)?;
        let wire: DaCommitteeDescriptorV1 =
            borsh::from_slice(&frame).expect("typed committee descriptor observation");
        assert_eq!(borsh::to_vec(&wire).unwrap(), frame);
        let (code, bytes) = match wire.committee_id() {
            Ok(id) => {
                let bytes = borsh::to_vec(&id).unwrap();
                assert_eq!(&bytes, id.as_bytes());
                assert_eq!(wire.member(wire.members()[0].definition_hash()), wire.members().first());
                (0_u8, bytes)
            }
            Err(err) => {
                let (expected, code) = match err.message() {
                    "invalid DA member definition" => (DaErrorCodeV1::InvalidCommittee, 201),
                    "invalid DA member Ed25519 key" => (DaErrorCodeV1::InvalidCommittee, 202),
                    "weak DA member key is forbidden" => (DaErrorCodeV1::InvalidCommittee, 203),
                    "DA committee must not be empty" => (DaErrorCodeV1::InvalidCommittee, 204),
                    "DA members must be strictly ordered with unique keys" => {
                        (DaErrorCodeV1::InvalidCommittee, 205)
                    }
                    "DA committee weight overflow" => (DaErrorCodeV1::ArithmeticOverflow, 206),
                    "unsupported context version" => (DaErrorCodeV1::InvalidContext, 208),
                    "chain ID must be bounded nonempty ASCII" => (DaErrorCodeV1::InvalidContext, 209),
                    "invalid committee bounds" => (DaErrorCodeV1::InvalidCommittee, 210),
                    "committee quorum calculation overflow" => {
                        (DaErrorCodeV1::ArithmeticOverflow, 211)
                    }
                    "committee threshold is not floor(2W/3)+1" => {
                        (DaErrorCodeV1::InvalidCommittee, 212)
                    }
                    "ArtifactEvidence is outside this candidate tranche" => {
                        (DaErrorCodeV1::UnsupportedNamespace, 213)
                    }
                    "unknown DA namespace" => (DaErrorCodeV1::UnsupportedNamespace, 214),
                    unexpected => panic!("Unexpected original committee ID result {unexpected:?}"),
                };
                assert_eq!(err.code(), expected);
                (code, Vec::new())
            }
        };
        out.write_all(&[code])?;
        out.write_all(&(bytes.len() as u32).to_le_bytes())?;
        out.write_all(&bytes)?;
    }
}
