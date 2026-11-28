use std::io::{self, Read, Write};

use trnm_crypto_primitives::pon_routed_int257_grouped::{
    Context, Model, PreparedModel, Request, DIM,
};

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
        let length = u32::from_le_bytes(len) as usize;
        assert!((15424..=82244).contains(&length));
        let mut bytes = vec![0; length];
        input.read_exact(&mut bytes)?;
        let n = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
        assert_eq!(length, 15424 + n * DIM * 4);
        let mut at = 4;
        let base = std::array::from_fn(|_| row(&bytes, &mut at));
        let router = std::array::from_fn(|_| row(&bytes, &mut at));
        let deltas = std::array::from_fn(|_| std::array::from_fn(|_| row(&bytes, &mut at)));
        let requests: Vec<_> = (0..n)
            .map(|i| {
                let mut id = [0; 32];
                id[0] = i as u8;
                Request {
                    id,
                    scope: [9; 32],
                    arrival_ns: 10,
                    deadline_ns: 21,
                    x: row(&bytes, &mut at),
                }
            })
            .collect();
        assert_eq!(at, length);
        let context = Context {
            chain: [1; 32],
            parent: [2; 32],
            challenge: [3; 32],
            batch_id: [4; 32],
        };
        let model = Model {
            version: [5; 32],
            base,
            router,
            deltas,
        };
        let result = PreparedModel::new(model).and_then(|model| {
            let (batch, _) = model.prepare_batch(&context, &requests, 20)?;
            model.grouped(&batch).map(|(product, _phase)| product)
        });
        let (status, data) = match result {
            Ok(product) => {
                assert_eq!(product.routes.len(), n);
                assert_eq!(product.predictions.len(), n);
                assert_eq!(product.logits.len(), n);
                assert_eq!(product.router_outputs.len(), n);
                let mut value = Vec::with_capacity(48 + n * 51);
                let header = [
                    product.useful_dense_macs,
                    product.padded_macs,
                    product.nonempty_expert_groups as u64,
                    product.groups[0].len() as u64,
                    product.groups[1].len() as u64,
                    product.groups[2].len() as u64,
                ];
                for field in header {
                    value.extend_from_slice(&field.to_le_bytes());
                }
                for (i, logits) in product.logits.iter().enumerate() {
                    for logit in logits {
                        value.extend_from_slice(&logit.to_le_bytes());
                    }
                    value.push(u8::try_from(product.routes[i]).unwrap());
                    value.push(u8::try_from(product.predictions[i]).unwrap());
                    for score in product.router_outputs[i] {
                        value.extend_from_slice(&score.to_le_bytes());
                    }
                }
                for group in &product.groups {
                    for &index in group {
                        value.push(u8::try_from(index).unwrap());
                    }
                }
                assert_eq!(value.len(), 48 + n * 51);
                (0, value)
            }
            Err("MODEL_COEFFICIENT") => (3, Vec::new()),
            Err("BATCH_SIZE") => (4, Vec::new()),
            Err("INPUT_RANGE_BIAS") => (5, Vec::new()),
            Err(code) => panic!("Unexpected pure grouped comparator result: {code}"),
        };
        out.write_all(&[status])?;
        out.write_all(&(data.len() as u32).to_le_bytes())?;
        out.write_all(&data)?;
    }
}
