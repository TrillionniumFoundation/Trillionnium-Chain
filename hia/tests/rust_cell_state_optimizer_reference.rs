use std::io::{self, Write};
use trnm_pon_node::cell_native_v1::{canonical, CellState, Optimizer, DIM, OPTIMIZER_SCHEMA, STATE_SCHEMA};

fn row(out: &mut impl Write, state: &CellState) {
    let opt = state.optimizer.as_ref().unwrap();
    let fields = [&state.cell_id, &state.model_artifact, &state.rng_seed, &state.schema, &state.scope];
    let mut frame = b"CSO1\0\0\0\0".to_vec();
    for txt in fields { frame.extend_from_slice(&(txt.len() as u64).to_le_bytes()); }
    for x in [state.memory.len() as u64, state.generation, state.remaining_steps,
              state.rng_counter, state.sequence] {
        frame.extend_from_slice(&x.to_le_bytes());
    }
    for x in &state.memory { frame.extend_from_slice(&x.to_le_bytes()); }
    for txt in fields { frame.extend_from_slice(txt.as_bytes()); }
    for matrix in std::iter::once(&opt.base).chain(&opt.deltas) {
        assert_eq!(matrix.len(), 3);
        for row in matrix {
            assert_eq!(row.len(), DIM);
            for x in row { frame.extend_from_slice(&x.to_le_bytes()); }
        }
    }
    frame.extend_from_slice(&opt.step.to_le_bytes());
    let wire = canonical(state).unwrap();
    out.write_all(&(frame.len() as u32).to_le_bytes()).unwrap();
    out.write_all(&(wire.len() as u32).to_le_bytes()).unwrap();
    out.write_all(&frame).unwrap();
    out.write_all(&wire).unwrap();
}

fn main() {
    let make = |offset| (0..3).map(|r| (0..DIM).map(|i|
        [0, i64::MIN, i64::MAX, -1, 1, -10, 10, 99, -100][(i+2*r+offset)%9]
    ).collect::<Vec<_>>()).collect::<Vec<_>>();
    let original = CellState {
        schema: STATE_SCHEMA.to_owned(), cell_id: "aa".repeat(32), generation: 2,
        scope: "local\nquoted/\"state".to_owned(), model_artifact: "bb".repeat(32),
        memory: vec![-19, 0, 19], rng_seed: "cc".repeat(32), rng_counter: 3,
        remaining_steps: 5, sequence: 7, optimizer: Some(Optimizer {
            schema: OPTIMIZER_SCHEMA.to_owned(), step: u64::MAX, base: make(0),
            deltas: (1..=3).map(make).collect(),
        }),
    };
    let mut out = io::stdout().lock();
    row(&mut out, &original);
    let mut swapped = original.clone();
    let opt = swapped.optimizer.as_mut().unwrap();
    opt.deltas.swap(0, 2);
    row(&mut out, &swapped);
    let mut stepped = original.clone();
    stepped.optimizer.as_mut().unwrap().step = 0;
    row(&mut out, &stepped);
    let mut max = original.clone();
    max.cell_id = "\0".repeat(256);
    max.model_artifact = max.cell_id.clone();
    max.rng_seed = max.cell_id.clone();
    max.schema = max.cell_id.clone();
    max.scope = max.cell_id.clone();
    max.memory = vec![i64::MIN; 32];
    max.generation = u64::MAX;
    max.rng_counter = u64::MAX;
    max.remaining_steps = u64::MAX;
    max.sequence = u64::MAX;
    let opt = max.optimizer.as_mut().unwrap();
    opt.base = vec![vec![i64::MIN; DIM]; 3];
    opt.deltas = vec![opt.base.clone(); 3];
    row(&mut out, &max);
}
