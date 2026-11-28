use std::io::{self, Read, Write};
use trnm_crypto_primitives::pon_routed_int257_grouped::{
    AdapterFactors, Matrix, Model, PreparedModel, DIM,
};

fn slice(raw: &[u8], at: usize) -> [u8; 4] {
    raw[at..at + 4].try_into().unwrap()
}

fn int(raw: &[u8], at: usize) -> i32 {
    i32::from_le_bytes(slice(raw, at))
}

fn count(raw: &[u8], at: usize) -> usize {
    let n = u32::from_le_bytes(slice(raw, at)) as usize;
    assert!(n <= 9);
    n
}

fn observe(raw: &[u8]) -> (u8, Vec<u8>) {
    let matrix = |index| -> Matrix {
        std::array::from_fn(|row| {
            std::array::from_fn(|col| int(raw, 32 + ((index * 3 + row) * DIM + col) * 4))
        })
    };
    let model = match PreparedModel::new(Model {
        version: raw[..32].try_into().unwrap(),
        base: matrix(0),
        router: matrix(1),
        deltas: std::array::from_fn(|e| matrix(e + 2)),
    }) {
        Ok(model) => model,
        Err("MODEL_COEFFICIENT") => return (3, Vec::new()),
        Err(s) => panic!("unexpected original model status: {s}"),
    };
    let factors = std::array::from_fn(|expert| {
        let p = 15452 + expert * 8336;
        let rank = count(raw, p);
        AdapterFactors {
            up: std::array::from_fn(|row| {
                let len = count(raw, p + 4 + row * 4);
                (0..len)
                    .map(|k| {
                        // The ninth slot is only a dummy typed value within
                        // a malformed row. The original checks length first.
                        if k >= 8 {
                            0
                        } else {
                            int(raw, p + 16 + row * 32 + k * 4)
                        }
                    })
                    .collect()
            }),
            down: (0..rank)
                .map(|k| {
                    std::array::from_fn(|col| {
                        if k >= 8 {
                            0
                        } else {
                            int(raw, p + 112 + (k * DIM + col) * 4)
                        }
                    })
                })
                .collect(),
        }
    });
    match model.prepare_factors(factors) {
        Ok(prepared) => {
            assert_eq!(prepared.model_commitment(), model.commitment());
            let mut out = prepared.preparation_macs().to_le_bytes().to_vec();
            out.extend(prepared.ranks().map(|r| u8::try_from(r).unwrap()));
            (0, out)
        }
        Err("FACTOR_COEFFICIENT") => (8, Vec::new()),
        Err("FACTOR_RANK") => (9, Vec::new()),
        Err("FACTOR_SHAPE") => (10, Vec::new()),
        Err("FACTOR_NOT_SAME_DELTA") => (11, Vec::new()),
        Err(s) => panic!("unexpected original factor status: {s}"),
    }
}

fn main() {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input).unwrap();
    assert_eq!(input.len() % 40460, 0);
    let mut output = io::stdout().lock();
    for raw in input.chunks_exact(40460) {
        let (s, data) = observe(raw);
        output.write_all(&[s]).unwrap();
        output.write_all(&data).unwrap();
    }
}
