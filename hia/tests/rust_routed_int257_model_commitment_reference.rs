use std::io::{self, Read, Write};

use trnm_crypto_primitives::pon_routed_int257_grouped::{Model, PreparedModel, DIM};

fn row(stream: &[u8], at: &mut usize) -> [i32; DIM] {
    std::array::from_fn(|_| {
        let value = i32::from_le_bytes(stream[*at..*at + 4].try_into().unwrap());
        *at += 4;
        value
    })
}

fn main() -> io::Result<()> {
    let mut input = io::stdin().lock();
    let mut out = io::stdout().lock();
    loop {
        let mut len = [0; 4];
        if input.read(&mut len[..1])? == 0 {
            return Ok(());
        }
        input.read_exact(&mut len[1..])?;
        assert_eq!(u32::from_le_bytes(len), 15452);
        let mut bytes = vec![0; 15452];
        input.read_exact(&mut bytes)?;
        let version: [u8; 32] = bytes[..32].try_into().unwrap();
        let mut at = 32;
        let base = std::array::from_fn(|_| row(&bytes, &mut at));
        let router = std::array::from_fn(|_| row(&bytes, &mut at));
        let deltas = std::array::from_fn(|_| std::array::from_fn(|_| row(&bytes, &mut at)));
        assert_eq!(at, bytes.len());
        let result = PreparedModel::new(Model {
            version,
            base,
            router,
            deltas,
        });
        match result {
            Ok(prepared) => {
                out.write_all(&[0])?;
                out.write_all(&32_u32.to_le_bytes())?;
                out.write_all(&prepared.commitment())?;
            }
            Err("MODEL_COEFFICIENT") => {
                out.write_all(&[3])?;
                out.write_all(&0_u32.to_le_bytes())?;
            }
            Err(code) => panic!("Unexpected pure model commitment comparator result: {code}"),
        }
    }
}
