// No optimizer, user material, owner, hashing, persistence or release logic.
use std::io::{self, Write};
use trnm_pon_node::cell_native_v1::{canonical, Model, DIM, MODEL_SCHEMA};

const WORDS: usize = 5 * 3 * DIM;
const BOUND: i64 = 32_767;

fn main() {
    let boundaries = [
        -32767, -10000, -9999, -1000, -999, -100, -99, -10, -9, -1, 0, 1, 9, 10,
        99, 100, 999, 1000, 9999, 10000, 32767,
    ];
    let mut random = 0x4b261088u64;
    let mut out = io::stdout().lock();
    for case in 0..33 {
        let mut values = [0i64; WORDS];
        for (i, item) in values.iter_mut().enumerate() {
            let group = i / (3 * DIM);
            let row = (i / DIM) % 3;
            let column = i % DIM;
            *item = match case {
                0 => 0,
                1 => -BOUND,
                2 => BOUND,
                3 => boundaries[(i + group + row + column) % boundaries.len()],
                4 if column == 0 => 1000 * (group as i64 + 1) + row as i64,
                4 if column == DIM - 1 => -1000 * (group as i64 + 1) - row as i64,
                4 => 0,
                5 if group == 0 => -BOUND,
                5 if group == 4 => BOUND,
                5 => 0,
                6 if i == WORDS - 1 => -BOUND,
                6 => 0,
                7 if i == WORDS - 1 => BOUND,
                7 => 0,
                _ => {
                    random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
                    if (i + case) % 11 == 0 {
                        boundaries[((random >> 28) as usize) % boundaries.len()]
                    } else {
                        ((random >> 32) % 65535) as i64 - BOUND
                    }
                }
            };
        }
        let mut matrices: Vec<Vec<Vec<i64>>> = values
            .chunks_exact(3 * DIM)
            .map(|m| m.chunks_exact(DIM).map(|v| v.to_vec()).collect())
            .collect();
        let router = matrices.pop().unwrap();
        let base = matrices.remove(0);
        assert_eq!(matrices.len(), 3);
        let model = Model {
            schema: MODEL_SCHEMA.to_owned(),
            base,
            router,
            deltas: matrices,
        };
        let bytes = canonical(&model).unwrap();
        out.write_all(&(bytes.len() as u32).to_le_bytes()).unwrap();
        for v in values {
            out.write_all(&v.to_le_bytes()).unwrap();
        }
        out.write_all(&bytes).unwrap();
    }
}
