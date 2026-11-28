use std::io::{self, Write};
use trnm_pon_node::cell_native_v1::{canonical, CellState, STATE_SCHEMA};

fn main() {
    let base = CellState {
        cell_id: "00".repeat(32), generation: 13, memory: vec![0, -1, 1],
        model_artifact: "a4".repeat(32), optimizer: None, remaining_steps: 42,
        rng_counter: 5, rng_seed: "cc".repeat(32), schema: STATE_SCHEMA.to_owned(),
        scope: "synthetic-local".to_owned(), sequence: 97,
    };
    let mut variants = vec![base.clone()];
    let mut extrema = base.clone();
    extrema.memory = [i64::MIN, i64::MAX, -100, 10].repeat(8);
    extrema.generation = u64::MAX;
    extrema.remaining_steps = u64::MAX - 1;
    extrema.rng_counter = 10;
    extrema.sequence = 0;
    variants.push(extrema);
    let mut blank = base.clone();
    blank.memory.clear();
    blank.cell_id.clear();
    blank.model_artifact.clear();
    blank.rng_seed.clear();
    blank.schema.clear();
    blank.scope.clear();
    variants.push(blank);
    let mut escaped = base.clone();
    let widest = "\0".repeat(256);
    escaped.cell_id = widest.clone();
    escaped.model_artifact = widest.clone();
    escaped.rng_seed = widest.clone();
    escaped.schema = widest.clone();
    escaped.scope = (0..=127).map(char::from).collect();
    variants.push(escaped);
    let mut large = base.clone();
    large.cell_id = widest.clone();
    large.model_artifact = widest.clone();
    large.rng_seed = widest.clone();
    large.schema = widest.clone();
    large.scope = widest;
    large.memory = vec![i64::MIN; 32];
    large.generation = u64::MAX;
    large.remaining_steps = u64::MAX;
    large.rng_counter = u64::MAX;
    large.sequence = u64::MAX;
    variants.push(large);
    let mut non_ascii = base.clone();
    non_ascii.scope.push('é');
    variants.push(non_ascii);
    let mut out = io::stdout().lock();
    for s in variants {
        out.write_all(b"CSV1\0\0\0\0").unwrap();
        let fields = [&s.cell_id, &s.model_artifact, &s.rng_seed, &s.schema, &s.scope];
        for txt in fields { out.write_all(&(txt.len() as u64).to_le_bytes()).unwrap(); }
        for v in [s.memory.len() as u64, s.generation, s.remaining_steps, s.rng_counter, s.sequence] {
            out.write_all(&v.to_le_bytes()).unwrap();
        }
        for v in &s.memory { out.write_all(&v.to_le_bytes()).unwrap(); }
        for txt in fields { out.write_all(txt.as_bytes()).unwrap(); }
        let result = match canonical(&s) {
            Ok(bytes) => bytes,
            Err(e) => { assert_eq!(e.to_string(), "CELL_JSON_ASCII"); vec![] },
        };
        out.write_all(&(result.len() as u64).to_le_bytes()).unwrap();
        out.write_all(&result).unwrap();
    }
}
