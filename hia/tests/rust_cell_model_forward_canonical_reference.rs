// Original serializer for exact inert candidates supplied as little-endian weights.
use std::io::{self, Read, Write};
use trnm_pon_node::cell_native_v1::{canonical, Model, DIM, MODEL_SCHEMA};

fn main() -> io::Result<()> {
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    let mut frame = [0u8; 8 * 5 * 3 * DIM];
    loop {
        if input.read(&mut frame[..1])? == 0 {
            return Ok(());
        }
        input.read_exact(&mut frame[1..])?;
        let values: Vec<_> = frame
            .chunks_exact(8)
            .map(|word| i64::from_le_bytes(word.try_into().unwrap()))
            .collect();
        assert!(values.iter().all(|value| (-32767..=32767).contains(value)));
        let mut matrices: Vec<Vec<Vec<i64>>> = values
            .chunks_exact(3 * DIM)
            .map(|matrix| matrix.chunks_exact(DIM).map(|row| row.to_vec()).collect())
            .collect();
        let router = matrices.pop().unwrap();
        let base = matrices.remove(0);
        let model = Model {
            schema: MODEL_SCHEMA.into(),
            base,
            router,
            deltas: matrices,
        };
        let bytes = canonical(&model).unwrap();
        output.write_all(&(bytes.len() as u32).to_le_bytes())?;
        output.write_all(&bytes)?;
    }
}
