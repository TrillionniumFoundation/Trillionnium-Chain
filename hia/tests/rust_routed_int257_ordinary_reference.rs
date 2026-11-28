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
            model.ordinary(&batch)
        });
        let (status, data) = match result {
            Ok(ordinary) => {
                assert_eq!(ordinary.routes.len(), n);
                assert_eq!(ordinary.predictions.len(), n);
                assert_eq!(ordinary.logits.len(), n);
                let mut value = Vec::with_capacity(n * 26);
                for (i, logits) in ordinary.logits.iter().enumerate() {
                    for logit in logits {
                        value.extend_from_slice(&logit.to_le_bytes());
                    }
                    value.push(u8::try_from(ordinary.routes[i]).unwrap());
                    value.push(u8::try_from(ordinary.predictions[i]).unwrap());
                }
                (0, value)
            }
            Err("MODEL_COEFFICIENT") => (3, Vec::new()),
            Err("BATCH_SIZE") => (4, Vec::new()),
            Err("INPUT_RANGE_BIAS") => (5, Vec::new()),
            Err(code) => panic!("Unexpected pure ordinary comparator result: {code}"),
        };
        out.write_all(&[status])?;
        out.write_all(&(data.len() as u32).to_le_bytes())?;
        out.write_all(&data)?;
    }
}
