// This comparator's only original code is injected from hash-bound exact
// declarations and scalar spans. It does not link the proof-owning crate.
use std::io::{self, Read, Write};

// @CELL_CONSTANT_AND_TYPED_DECLARATIONS@
// @CELL_WEIGHTS_ORDER@
// @PURE_ROUTED_DOT@

fn read_row(raw: &[u8], cursor: &mut usize) -> [i64; DIM] {
    std::array::from_fn(|_| {
        let coordinate =
            i32::from_le_bytes(raw[*cursor..*cursor + 4].try_into().expect("one i32"));
        *cursor += 4;
        i64::from(coordinate)
    })
}

fn original_products(raw: &[u8], out: &mut impl Write) -> io::Result<()> {
    let n = u32::from_le_bytes(raw[0..4].try_into().expect("n")) as usize;
    assert!((1..=64).contains(&n));
    assert_eq!(raw.len(), 15424 + 1028 * n);
    let mut cursor = 4;
    let mut matrix = || -> Matrix { (0..3).map(|_| read_row(raw, &mut cursor).to_vec()).collect() };
    let model = Model {
        schema: MODEL_SCHEMA.into(),
        base: matrix(),
        router: matrix(),
        deltas: (0..3).map(|_| matrix()).collect(),
    };
    assert_eq!(model.schema, MODEL_SCHEMA);
    let features: Vec<_> = (0..n).map(|_| read_row(raw, &mut cursor)).collect();
    assert_eq!(cursor, raw.len());
    let ordered = weights(&model);
    assert_eq!(ordered.len(), 15);
    for row in &features {
        assert_eq!(row[256], 8);
        assert!(row[..256].iter().map(|v| v.abs()).sum::<i64>() <= 1024);
        let x: [i32; DIM] = row.map(|value| i32::try_from(value).expect("exact narrowing"));
        for weight in &ordered {
            let w: [i32; DIM] =
                std::array::from_fn(|i| i32::try_from(weight[i]).expect("exact narrowing"));
            let value = dot(&w, &x);
            // @CELL_SCALAR_EXPRESSION@
            assert_eq!(value, scalar);
            out.write_all(&value.to_le_bytes())?;
        }
    }
    Ok(())
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
        assert!((16452..=81216).contains(&length));
        let mut wire = vec![0; length];
        input.read_exact(&mut wire)?;
        original_products(&wire, &mut out)?;
    }
}
