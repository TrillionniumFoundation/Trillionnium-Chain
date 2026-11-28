use std::io::{self, Read, Write};
use trnm_crypto_primitives::pon_routed_int257_grouped::{
    Context, Model, PreparedModel, Product, Request, DIM,
};

fn u32_at(v: &[u8], at: usize) -> usize {
    u32::from_le_bytes(v[at..at + 4].try_into().unwrap()) as usize
}

fn row(v: &[u8], at: &mut usize) -> [i32; DIM] {
    std::array::from_fn(|_| {
        let value = i32::from_le_bytes(v[*at..*at + 4].try_into().unwrap());
        *at += 4;
        value
    })
}

fn encode(p: Product, n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for value in [
        p.useful_dense_macs,
        p.padded_macs,
        p.nonempty_expert_groups as u64,
        p.groups[0].len() as u64,
        p.groups[1].len() as u64,
        p.groups[2].len() as u64,
    ] {
        out.extend(value.to_le_bytes());
    }
    for i in 0..n {
        for logit in p.logits[i] {
            out.extend(logit.to_le_bytes());
        }
        out.push(u8::try_from(p.routes[i]).unwrap());
        out.push(u8::try_from(p.predictions[i]).unwrap());
        for score in p.router_outputs[i] {
            out.extend(score.to_le_bytes());
        }
    }
    for g in p.groups {
        out.extend(g.into_iter().map(|i| u8::try_from(i).unwrap()));
    }
    assert_eq!(out.len(), 48 + 51 * n);
    out
}

fn original(v: &[u8]) -> Result<Vec<u8>, &'static str> {
    let total = u32_at(v, 0);
    let mut at = 4;
    let model = PreparedModel::new(Model {
        version: [5; 32],
        base: std::array::from_fn(|_| row(v, &mut at)),
        router: std::array::from_fn(|_| row(v, &mut at)),
        deltas: std::array::from_fn(|_| std::array::from_fn(|_| row(v, &mut at))),
    })?;
    let table = 15424 + total * DIM * 4;
    assert_eq!(v.len(), table + 20);
    let children = u32_at(v, table);
    assert!((1..=4).contains(&children) && total <= 64);
    let context = Context {
        chain: [1; 32],
        parent: [2; 32],
        challenge: [3; 32],
        batch_id: [4; 32],
    };
    let mut result = vec![0; 32];
    for child in 0..children {
        let n = u32_at(v, table + 4 + child * 4);
        let requests: Vec<_> = (0..n)
            .map(|i| {
                let mut id = [0; 32];
                id[0] = i as u8;
                Request {
                    id,
                    scope: [9; 32],
                    arrival_ns: 10,
                    deadline_ns: 21,
                    x: row(v, &mut at),
                }
            })
            .collect();
        let (batch, _) = model.prepare_batch(&context, &requests, 20)?;
        let (product, _) = model.grouped(&batch)?;
        let bytes = encode(product, n);
        result[child * 8..child * 8 + 8].copy_from_slice(&(bytes.len() as u64).to_le_bytes());
        result.extend(bytes);
    }
    assert_eq!(at, table);
    Ok(result)
}

fn main() {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input).unwrap();
    let mut input = input.as_slice();
    let mut out = io::stdout().lock();
    while !input.is_empty() {
        let n = u32_at(input, 0);
        let frame = &input[4..4 + n];
        input = &input[4 + n..];
        let (status, data) = match original(frame) {
            Ok(data) => (0, data),
            Err("MODEL_COEFFICIENT") => (3, Vec::new()),
            Err("BATCH_SIZE") => (4, Vec::new()),
            Err("INPUT_RANGE_BIAS") => (5, Vec::new()),
            Err(other) => panic!("unexpected original child status: {other}"),
        };
        out.write_all(&[status]).unwrap();
        out.write_all(&(data.len() as u32).to_le_bytes()).unwrap();
        out.write_all(&data).unwrap();
    }
}
