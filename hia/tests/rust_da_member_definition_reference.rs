use std::io::{self, Read, Write};
use trnm_data_availability::{DaErrorCodeV1, DaMemberV1, Hash32V1};

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
        assert!((113..=1_048_576).contains(&size));
        let mut frame = vec![0; size];
        stream.read_exact(&mut frame)?;
        let key: [u8; 32] = frame[..32].try_into().unwrap();
        let weight = u128::from_le_bytes(frame[32..48].try_into().unwrap());
        let (validator, at) = match frame[48] {
            0 => (None, 49),
            1 => {
                let n = u32::from_le_bytes(frame[49..53].try_into().unwrap()) as usize;
                (Some(frame[53..53+n].to_vec()), 53+n)
            }
            _ => panic!("test may only construct an actual typed Option"),
        };
        assert_eq!(frame.len(), at+64);
        let storage = Hash32V1::new(frame[at..at+32].try_into().unwrap());
        let bond = Hash32V1::new(frame[at+32..].try_into().unwrap());
        let result = DaMemberV1::new(key, weight, validator, storage, bond);
        let (code, bytes) = match result {
            Ok(value) => {
                assert_eq!(value.public_key(), &key);
                assert_eq!(value.weight(), weight);
                let encoded = borsh::to_vec(&value).unwrap();
                assert_eq!(borsh::from_slice::<DaMemberV1>(&encoded).unwrap(), value);
                assert_eq!(&encoded[encoded.len()-32..], value.definition_hash().as_bytes());
                (0_u8, encoded)
            }
            Err(err) => {
                assert_eq!(err.code(), DaErrorCodeV1::InvalidCommittee);
                let code = match err.message() {
                    "DA member weight must be positive" => 201,
                    "DA member key is not strict Ed25519" => 202,
                    "weak DA member key is forbidden" => 203,
                    unexpected => panic!("Unexpected original member result {unexpected:?}"),
                };
                (code, Vec::new())
            }
        };
        out.write_all(&[code])?;
        out.write_all(&(bytes.len() as u32).to_le_bytes())?;
        out.write_all(&bytes)?;
    }
}
