use std::io::{self, Read, Write};
use trnm_data_availability::{DaErrorCodeV1, Hash32V1, ProtocolContextV1};

fn main() -> io::Result<()> {
    let mut stdin = io::stdin().lock();
    let mut output = io::stdout().lock();
    loop {
        let mut length = [0; 4];
        if stdin.read(&mut length[..1])? == 0 {
            return Ok(());
        }
        stdin.read_exact(&mut length[1..])?;
        let n = u32::from_le_bytes(length) as usize;
        assert!((64..=2048).contains(&n));
        let mut input = vec![0; n];
        stdin.read_exact(&mut input)?;
        let genesis = Hash32V1::new(input[..32].try_into().unwrap());
        let stack = Hash32V1::new(input[32..64].try_into().unwrap());
        let chain = std::str::from_utf8(&input[64..]).unwrap();
        match ProtocolContextV1::new(genesis, chain, stack) {
            Ok(context) => {
                assert_eq!(context.genesis_hash(), genesis);
                assert_eq!(context.stack_profile_hash(), stack);
                assert_eq!(context.chain_id(), chain);
                assert_eq!(context.protocol_version(), 1);
                let raw = borsh::to_vec(&context).unwrap();
                assert_eq!(
                    borsh::from_slice::<ProtocolContextV1>(&raw).unwrap(),
                    context
                );
                output.write_all(&[0])?;
                output.write_all(&(raw.len() as u32).to_le_bytes())?;
                output.write_all(&raw)?;
            }
            Err(error) => {
                assert_eq!(error.code(), DaErrorCodeV1::InvalidContext);
                assert_eq!(error.message(), "chain ID must be bounded nonempty ASCII");
                output.write_all(&[2, 0, 0, 0, 0])?;
            }
        }
    }
}
