use std::io::{self, Read, Write};
use trnm_data_availability::{DaAuthorAuthorityV1, DaErrorCodeV1};

fn main() -> io::Result<()> {
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    loop {
        let mut length = [0; 4];
        if input.read(&mut length[..1])? == 0 {
            return Ok(());
        }
        input.read_exact(&mut length[1..])?;
        let n = u32::from_le_bytes(length) as usize;
        assert!((60..=1024).contains(&n));
        let mut raw = vec![0; n];
        input.read_exact(&mut raw)?;
        let pubkey: [u8; 32] = raw[..32].try_into().unwrap();
        let first = u64::from_le_bytes(raw[32..40].try_into().unwrap());
        let max = u64::from_le_bytes(raw[40..48].try_into().unwrap());
        let quota = u64::from_le_bytes(raw[48..56].try_into().unwrap());
        let count = u32::from_le_bytes(raw[56..60].try_into().unwrap());
        let id = &raw[60..];
        let (code, value) = match DaAuthorAuthorityV1::new(id.to_vec(), pubkey, first, max, quota, count) {
            Ok(author) => {
                assert_eq!(author.author_id(), id);
                assert_eq!(author.public_key(), &pubkey);
                assert_eq!(author.first_sequence(), first);
                assert_eq!(author.maximum_sequence(), max);
                assert_eq!(author.max_author_bytes(), quota);
                assert_eq!(author.max_outstanding_sequences(), count);
                let bytes = borsh::to_vec(&author).expect("original Borsh derives value");
                assert_eq!(borsh::from_slice::<DaAuthorAuthorityV1>(&bytes).unwrap(), author);
                (0_u8, bytes)
            }
            Err(error) => {
                let code = match (error.code(), error.message()) {
                    (DaErrorCodeV1::InvalidBounds, "invalid DA author authority") => 3,
                    (DaErrorCodeV1::InvalidSignature, "author key is not strict Ed25519") => 6,
                    (DaErrorCodeV1::InvalidSignature, "weak author key is forbidden") => 7,
                    other => panic!("unknown original result: {other:?}"),
                };
                (code, Vec::new())
            }
        };
        output.write_all(&[code])?;
        output.write_all(&(value.len() as u32).to_le_bytes())?;
        output.write_all(&value)?;
    }
}
