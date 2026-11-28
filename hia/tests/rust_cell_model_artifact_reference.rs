//! Generate inert exact original typed models; never train or execute them.
use std::io::{self, Write};
use trnm_pon_node::cell_native_v1::{canonical, model_artifact, Model, DIM, MODEL_SCHEMA};

fn fixture(f: impl Fn(usize, usize, usize) -> i64) -> Model {
    let matrix = |m| (0..3).map(|r| (0..DIM).map(|c| f(m,r,c)).collect()).collect();
    Model { schema: MODEL_SCHEMA.to_owned(), base: matrix(0), router: matrix(4),
            deltas: (1..=3).map(matrix).collect() }
}

fn row(out: &mut impl Write, m: &Model) {
    let wire = canonical(m).unwrap();
    let (code, digest) = match model_artifact(m) {
        Ok(hex) => {
            assert_eq!(hex.len(), 64);
            (0u32, (0..32).map(|i| u8::from_str_radix(&hex[i*2..i*2+2],16).unwrap()).collect())
        }
        Err(e) => {
            let status = match e.to_string().as_str() {
                "CELL_MODEL_SCHEMA" => 1,
                "CELL_MATRIX_SHAPE_OR_RANGE" => 2,
                "CELL_MODEL_DELTAS" => 3,
                s => panic!("unexpected original model refusal {s}"),
            };
            (status, Vec::<u8>::new())
        }
    };
    out.write_all(&code.to_le_bytes()).unwrap();
    out.write_all(&(wire.len() as u32).to_le_bytes()).unwrap();
    out.write_all(&wire).unwrap();
    out.write_all(&digest).unwrap();
}

fn main() {
    let mut out = io::stdout().lock();
    let zero = fixture(|_,_,_| 0);
    let full = fixture(|_,_,_| -32767);
    assert_eq!(canonical(&zero).unwrap().len(), 7830);
    assert_eq!(canonical(&full).unwrap().len(), 27105);
    let mixed = fixture(|m,r,c| [0,1,-1,9,-10,99,-100,32767,-32767][(3*m+7*r+c)%9]);
    for m in [&zero, &full, &mixed] { row(&mut out,m); }
    let mut swapped=mixed.clone();
    swapped.deltas.swap(0,2);
    row(&mut out,&swapped);
    let mut changed=mixed.clone();
    changed.router[2][DIM-1]=32766;
    row(&mut out,&changed);

    let mut bad=mixed.clone();
    bad.schema.push_str("-different-profile");
    row(&mut out,&bad);
    let mut bad=mixed.clone();
    bad.base[2].pop();
    row(&mut out,&bad);
    let mut bad=mixed.clone();
    bad.router.pop();
    row(&mut out,&bad);
    let mut bad=mixed.clone();
    bad.deltas.pop();
    row(&mut out,&bad);
    let mut bad=mixed.clone();
    bad.deltas[1].push(vec![1;DIM]);
    row(&mut out,&bad);
    let mut bad=mixed.clone();
    bad.base[2][DIM-1]=32768;
    row(&mut out,&bad);
    let mut bad=mixed.clone();
    bad.deltas[2][0][0]=-32768;
    row(&mut out,&bad);
}
