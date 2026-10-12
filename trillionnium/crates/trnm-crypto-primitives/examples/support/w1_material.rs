//! Deterministic diagnostic inputs shared only by the reused-cost example.
use std::{error::Error, fs, path::Path};
use trnm_crypto_primitives::pon_work::*;

pub struct Material {
    pub name: &'static str,
    pub source: &'static str,
    pub a: Vec<u32>,
    pub b: Vec<u32>,
}

fn multiply(a: u32, b: u32) -> u32 {
    ((u128::from(a) * u128::from(b)) % Q) as u32
}
fn inverse(mut power: u32) -> u32 {
    let mut result = 1;
    let mut exponent = (Q - 2) as u64;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = multiply(result, power);
        }
        power = multiply(power, power);
        exponent >>= 1;
    }
    result
}
pub fn rank(matrix: &[u32]) -> usize {
    let mut rows: Vec<_> = matrix.chunks_exact(N).map(<[u32]>::to_vec).collect();
    let mut rank = 0;
    for column in 0..N {
        let Some(pivot) = (rank..N).find(|row| rows[*row][column] != 0) else {
            continue;
        };
        rows.swap(rank, pivot);
        let reciprocal = inverse(rows[rank][column]);
        for value in &mut rows[rank][column..] {
            *value = multiply(*value, reciprocal);
        }
        let pivot_row = rows[rank].clone();
        for row in rows.iter_mut().skip(rank + 1) {
            let scale = row[column];
            for index in column..N {
                row[index] = ((u128::from(row[index]) + Q
                    - u128::from(multiply(scale, pivot_row[index])))
                    % Q) as u32;
            }
        }
        rank += 1;
    }
    rank
}
fn full_rank(label: u8) -> Vec<u32> {
    for generation in 0u32..32 {
        let mut values = Vec::with_capacity(CELLS);
        for counter in 0u32..1024 {
            for bytes in hash(
                b"comparison-material",
                &[&[label], &generation.to_le_bytes(), &counter.to_le_bytes()],
            )
            .chunks_exact(4)
            {
                let value = u32::from_le_bytes(bytes.try_into().unwrap());
                if u128::from(value) < Q {
                    values.push(value);
                }
                if values.len() == CELLS {
                    break;
                }
            }
            if values.len() == CELLS {
                break;
            }
        }
        if values.len() == CELLS && rank(&values) == N {
            return values;
        }
    }
    panic!("bounded full-rank material construction exhausted");
}
fn decode_material(path: &Path) -> Result<Vec<u32>, Box<dyn Error>> {
    // Bound the actual read, including files that grow or are not regular files.
    use std::io::Read;
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take((CELLS * 4 + 1) as u64)
        .read_to_end(&mut bytes)?;
    decode_bytes(&bytes)
}
fn decode_bytes(bytes: &[u8]) -> Result<Vec<u32>, Box<dyn Error>> {
    if bytes.len() != CELLS * 4 {
        return Err("material must contain exactly 16384 bytes".into());
    }
    let values: Vec<_> = bytes
        .chunks_exact(4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .collect();
    task_id(&values, &values).map_err(|_| "noncanonical matrix material")?;
    Ok(values)
}
pub fn materials(
    model: Option<&Path>,
    input: Option<&Path>,
) -> Result<Vec<Material>, Box<dyn Error>> {
    if model.is_some() != input.is_some() {
        return Err("--model and --input must be supplied together".into());
    }
    let mut cases = vec![
        Material {
            name: "periodic-dense-fixture",
            source: "synthetic-fixture",
            a: (0..CELLS).map(|i| (i % 31) as u32).collect(),
            b: (0..CELLS).map(|i| ((i * 7) % 37) as u32).collect(),
        },
        Material {
            name: "full-rank-field",
            source: "hash-generated-rank-checked",
            a: full_rank(0),
            b: full_rank(1),
        },
        Material {
            name: "zero",
            source: "synthetic-fixture",
            a: vec![0; CELLS],
            b: vec![0; CELLS],
        },
        Material {
            name: "identity",
            source: "synthetic-fixture",
            a: (0..CELLS).map(|i| u32::from(i / N == i % N)).collect(),
            b: (0..CELLS).map(|i| u32::from(i / N == i % N)).collect(),
        },
        Material {
            name: "rank-one",
            source: "synthetic-fixture",
            a: (0..CELLS)
                .map(|i| ((i / N + 1) * (i % N + 1)) as u32)
                .collect(),
            b: (0..CELLS)
                .map(|i| ((i / N + 2) * (i % N + 1)) as u32)
                .collect(),
        },
        Material {
            name: "sparse-diagonal",
            source: "synthetic-fixture",
            a: (0..CELLS)
                .map(|i| {
                    if i / N == i % N {
                        (i / N + 1) as u32
                    } else {
                        0
                    }
                })
                .collect(),
            b: (0..CELLS)
                .map(|i| {
                    if i / N == i % N {
                        (i / N + 2) as u32
                    } else {
                        0
                    }
                })
                .collect(),
        },
    ];
    cases.push(Material {
        name: "continuity-maintenance-v1",
        source: "synthetic-fixture",
        a: (0..CELLS).map(|i| ((13 * i + 17) % 257) as u32).collect(),
        b: (0..CELLS).map(|i| ((29 * i + 31) % 263) as u32).collect(),
    });
    if let (Some(model), Some(input)) = (model, input) {
        cases.push(Material {
            name: "supplied-material",
            source: "caller-supplied-provenance-not-verified",
            a: decode_material(model)?,
            b: decode_material(input)?,
        });
    }
    Ok(cases)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn material_bytes_require_exact_length_and_canonical_field_values() {
        assert!(decode_bytes(&vec![0; CELLS * 4 - 1]).is_err());
        assert!(decode_bytes(&vec![0; CELLS * 4 + 1]).is_err());
        assert!(decode_bytes(&vec![255; CELLS * 4]).is_err());
        assert_eq!(decode_bytes(&vec![0; CELLS * 4]).unwrap(), vec![0; CELLS]);
        assert!(materials(Some(Path::new("unread-unpaired-model")), None).is_err());
        assert!(materials(None, Some(Path::new("unread-unpaired-input"))).is_err());
    }

    #[test]
    fn default_materials_include_exact_continuity_fixture_and_reported_ranks() {
        let cases = materials(None, None).unwrap();
        assert_eq!(cases.len(), 7);
        assert_eq!((rank(&cases[0].a), rank(&cases[0].b)), (31, 37));
        assert_eq!((rank(&cases[1].a), rank(&cases[1].b)), (N, N));
        let continuity = &cases[6];
        assert_eq!(continuity.name, "continuity-maintenance-v1");
        assert_eq!(continuity.source, "synthetic-fixture");
        assert_eq!((rank(&continuity.a), rank(&continuity.b)), (56, 32));
        for i in 0..CELLS {
            assert_eq!(continuity.a[i], ((13 * i + 17) % 257) as u32);
            assert_eq!(continuity.b[i], ((29 * i + 31) % 263) as u32);
        }
    }
}
