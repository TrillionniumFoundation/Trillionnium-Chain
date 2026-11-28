use std::io::{self, Read, Write};
use trnm_crypto_primitives::pon_routed_int257_grouped::{
    AdapterFactors, Context, Matrix, Model, PreparedModel, Request, DIM,
};

fn int(input: &[u8], at: usize) -> i32 {
    i32::from_le_bytes(input[at..at + 4].try_into().unwrap())
}

fn u32_at(input: &[u8], at: usize) -> usize {
    u32::from_le_bytes(input[at..at + 4].try_into().unwrap()) as usize
}

fn checked_arity(raw: &[u8], at: usize) -> usize {
    let n = u32_at(raw, at);
    assert!(n <= 9);
    n
}

fn original(raw: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mat = |m| -> Matrix {
        std::array::from_fn(|r| std::array::from_fn(|k| int(raw, 32 + 4 * ((m * 3 + r) * DIM + k))))
    };
    let model = PreparedModel::new(Model {
        version: raw[..32].try_into().unwrap(),
        base: mat(0),
        router: mat(1),
        deltas: std::array::from_fn(|e| mat(e + 2)),
    })?;
    let adapters = std::array::from_fn(|e| {
        let at = 15452 + e * 8336;
        let rank = checked_arity(raw, at);
        let up = std::array::from_fn(|row| {
            (0..checked_arity(raw, at + 4 * (row + 1)))
                .map(|k| {
                    if k >= 8 {
                        0
                    } else {
                        int(raw, at + 16 + 32 * row + 4 * k)
                    }
                })
                .collect()
        });
        let down = (0..rank)
            .map(|k| {
                std::array::from_fn(|column| {
                    if k >= 8 {
                        0
                    } else {
                        int(raw, at + 112 + 4 * (k * DIM + column))
                    }
                })
            })
            .collect();
        AdapterFactors { up, down }
    });
    let factors = model.prepare_factors(adapters)?;
    let context = Context {
        chain: [21; 32],
        parent: [8; 32],
        challenge: [33; 32],
        batch_id: [1; 32],
    };
    let count = u32_at(raw, 40460);
    assert_eq!(raw.len(), 40464 + count * 1028);
    let requests = raw[40464..]
        .chunks_exact(1028)
        .enumerate()
        .map(|(i, row)| {
            let mut id = [0; 32];
            id[0] = u8::try_from(i).unwrap();
            Request {
                id,
                scope: [42; 32],
                arrival_ns: 3,
                deadline_ns: 11,
                x: std::array::from_fn(|k| int(row, 4 * k)),
            }
        })
        .collect::<Vec<_>>();
    let (batch, _) = model.prepare_batch(&context, &requests, 5)?;
    let (p, counts) = model.factored(&batch, &factors)?;
    let mut result = Vec::new();
    for n in [
        p.useful_dense_macs,
        p.padded_macs,
        p.nonempty_expert_groups as u64,
        p.groups[0].len() as u64,
        p.groups[1].len() as u64,
        p.groups[2].len() as u64,
    ] {
        result.extend(n.to_le_bytes());
    }
    for i in 0..count {
        for n in p.router_outputs[i].iter().chain(p.logits[i].iter()) {
            result.extend(n.to_le_bytes());
        }
        result.push(p.routes[i].try_into().unwrap());
        result.push(p.predictions[i].try_into().unwrap());
    }
    for group in p.groups {
        result.extend(group.into_iter().map(|i| u8::try_from(i).unwrap()));
    }
    for n in [
        counts.router_macs(),
        counts.base_macs(),
        counts.adapter_macs(),
        counts.output_additions(),
        counts.execution_macs(),
    ] {
        result.extend(n.to_le_bytes());
    }
    Ok(result)
}

fn main() {
    let mut raw = Vec::new();
    io::stdin().read_to_end(&mut raw).unwrap();
    let mut raw = raw.as_slice();
    let mut dst = io::stdout().lock();
    while !raw.is_empty() {
        let n = u32_at(raw, 0);
        assert!((40464..=40464 + 65 * 1028).contains(&n));
        let row = &raw[4..4 + n];
        raw = &raw[4 + n..];
        let (status, payload) = match original(row) {
            Ok(bytes) => (0, bytes),
            Err(code) => {
                let s = match code {
                    "MODEL_COEFFICIENT" => 3,
                    "BATCH_SIZE" => 4,
                    "INPUT_RANGE_BIAS" => 7,
                    "FACTOR_COEFFICIENT" => 8,
                    "FACTOR_RANK" => 9,
                    "FACTOR_SHAPE" => 10,
                    "FACTOR_NOT_SAME_DELTA" => 11,
                    "FACTOR_OUTPUT_BOUND" => 12,
                    e => panic!("unexpected original local result: {e}"),
                };
                (s, Vec::new())
            }
        };
        dst.write_all(&[status]).unwrap();
        dst.write_all(&(payload.len() as u32).to_le_bytes())
            .unwrap();
        dst.write_all(&payload).unwrap();
    }
}
