use std::io::{self, Read, Write};

use borsh::BorshDeserialize;
use trnm_data_availability::{
    DaCommitteeDescriptorV1, DaErrorCodeV1, DaMemberV1, Hash32V1, ProtocolContextV1,
};

struct Request {
    context: ProtocolContextV1,
    epoch: u64,
    members: Vec<DaMemberV1>,
    retention_epochs: u32,
    max_author_bytes: u64,
    max_batch_bytes: u64,
    max_batch_items: u32,
    max_outstanding_sequences: u32,
}

impl BorshDeserialize for Request {
    fn deserialize_reader<R: Read>(reader: &mut R) -> io::Result<Self> {
        Ok(Self {
            context: ProtocolContextV1::deserialize_reader(reader)?,
            epoch: u64::deserialize_reader(reader)?,
            members: Vec::<DaMemberV1>::deserialize_reader(reader)?,
            retention_epochs: u32::deserialize_reader(reader)?,
            max_author_bytes: u64::deserialize_reader(reader)?,
            max_batch_bytes: u64::deserialize_reader(reader)?,
            max_batch_items: u32::deserialize_reader(reader)?,
            max_outstanding_sequences: u32::deserialize_reader(reader)?,
        })
    }
}

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
        assert!((114..=1_048_576).contains(&size));
        let mut frame = vec![0; size];
        stream.read_exact(&mut frame)?;
        let q: Request = borsh::from_slice(&frame).expect("typed constructor observation");
        let result = DaCommitteeDescriptorV1::new_transaction_batch(
            q.context,
            q.epoch,
            q.members,
            q.retention_epochs,
            q.max_author_bytes,
            q.max_batch_bytes,
            q.max_batch_items,
            q.max_outstanding_sequences,
        );
        let (code, bytes) = match result {
            Ok(value) => {
                for member in value.members() {
                    let encoded = borsh::to_vec(member).unwrap();
                    let (validator, at) = match encoded[50] {
                        0 => (None, 51),
                        1 => {
                            let n =
                                u32::from_le_bytes(encoded[51..55].try_into().unwrap()) as usize;
                            (Some(encoded[55..55 + n].to_vec()), 55 + n)
                        }
                        _ => unreachable!(),
                    };
                    let storage = Hash32V1::new(encoded[at..at + 32].try_into().unwrap());
                    let bond = Hash32V1::new(encoded[at + 32..at + 64].try_into().unwrap());
                    let rebuilt =
                        DaMemberV1::new(*member.public_key(), member.weight(), validator, storage, bond)
                            .unwrap();
                    assert_eq!(&rebuilt, member);
                }
                let bytes = borsh::to_vec(&value).unwrap();
                assert_eq!(
                    borsh::from_slice::<DaCommitteeDescriptorV1>(&bytes).unwrap(),
                    value
                );
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
                    "committee quorum multiplication overflow" => {
                        (DaErrorCodeV1::ArithmeticOverflow, 207)
                    }
                    "unsupported context version" => (DaErrorCodeV1::InvalidContext, 208),
                    "chain ID must be bounded nonempty ASCII" => (DaErrorCodeV1::InvalidContext, 209),
                    "invalid committee bounds" => (DaErrorCodeV1::InvalidCommittee, 210),
                    unexpected => panic!("Unexpected original committee result {unexpected:?}"),
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
