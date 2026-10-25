//! Research-only complete producers. Production W1 modules are not modified.
//! The general integer-paired arm lifts the existing maintenance-only integer
//! identity to all canonical inputs; its arithmetic count is not a cost bound.
use sha2::{Digest, Sha256};
use trnm_crypto_primitives::pon_work::{
    self,
    blocked_one_zero::BlockedOneZeroRankOnePreparedTask,
    blocked_zero::BlockedZeroPreparedTask,
    blocked_zero_paired::BlockedZeroPairedPreparedTask,
    maintenance_limb::MaintenanceLimbPreparedTask,
    maintenance_periodic::MaintenancePeriodicPreparedTask,
    maintenance_prefix::{MaintenanceIntegerPairedPreparedTask, MaintenancePrefixPreparedTask},
    paired_product::PairedPreparedTask,
    structured::{StructuredPreparedTask, TileKernel, TiledPreparedTask},
    Hash, PreparedTask, WorkError, N, PROOF_BYTES, Q, R,
};

pub const ARMS: [&str; 14] = [
    "scalar-original",
    "prepared-generic",
    "prepared-structured",
    "tiled-classical",
    "tiled-strassen-one-level",
    "paired-product",
    "blocked-zero",
    "blocked-zero-integer-paired",
    "blocked-one-zero-rank-one",
    "maintenance-periodic",
    "maintenance-integer-paired",
    "maintenance-prefix",
    "maintenance-limb",
    "integer-paired-general",
];

pub enum Producer {
    Scalar(Vec<u32>, Vec<u32>),
    Generic(Box<PreparedTask>),
    Structured(Box<StructuredPreparedTask>),
    Tiled(Box<TiledPreparedTask>),
    Paired(Box<PairedPreparedTask>),
    Zero(Box<BlockedZeroPreparedTask>),
    ZeroPaired(Box<BlockedZeroPairedPreparedTask>),
    OneZero(Box<BlockedOneZeroRankOnePreparedTask>),
    Periodic(Box<MaintenancePeriodicPreparedTask>),
    Integer(Box<MaintenanceIntegerPairedPreparedTask>),
    Prefix(Box<MaintenancePrefixPreparedTask>),
    Limb(Box<MaintenanceLimbPreparedTask>),
    General(Box<IntegerPairedGeneral>),
}

impl Producer {
    pub fn new(index: usize, a: &[u32], b: &[u32]) -> Result<Option<Self>, WorkError> {
        Ok(match index {
            0 => {
                pon_work::task_id(a, b)?;
                Some(Self::Scalar(a.to_vec(), b.to_vec()))
            }
            1 => Some(Self::Generic(Box::new(PreparedTask::new(a, b)?))),
            2 => StructuredPreparedTask::new(a, b)?.map(|p| Self::Structured(Box::new(p))),
            3 | 4 => Some(Self::Tiled(Box::new(TiledPreparedTask::new(
                a,
                b,
                if index == 3 {
                    TileKernel::Classical
                } else {
                    TileKernel::StrassenOneLevel
                },
            )?))),
            5 => Some(Self::Paired(Box::new(PairedPreparedTask::new(a, b)?))),
            6 => BlockedZeroPreparedTask::new(a, b)?.map(|p| Self::Zero(Box::new(p))),
            7 => BlockedZeroPairedPreparedTask::new(a, b)?.map(|p| Self::ZeroPaired(Box::new(p))),
            8 => BlockedOneZeroRankOnePreparedTask::new(a, b)?.map(|p| Self::OneZero(Box::new(p))),
            9 => MaintenancePeriodicPreparedTask::new(a, b)?.map(|p| Self::Periodic(Box::new(p))),
            10 => {
                MaintenanceIntegerPairedPreparedTask::new(a, b)?.map(|p| Self::Integer(Box::new(p)))
            }
            11 => MaintenancePrefixPreparedTask::new(a, b)?.map(|p| Self::Prefix(Box::new(p))),
            12 => MaintenanceLimbPreparedTask::new(a, b)?.map(|p| Self::Limb(Box::new(p))),
            13 => Some(Self::General(Box::new(IntegerPairedGeneral::new(a, b)?))),
            _ => return Err(WorkError::Task),
        })
    }

    pub fn prove(&self, challenge: Hash) -> Result<Vec<u8>, WorkError> {
        match self {
            Self::Scalar(a, b) => pon_work::prove(challenge, a, b),
            Self::Generic(p) => p.prove(challenge),
            Self::Structured(p) => p.prove(challenge),
            Self::Tiled(p) => p.prove(challenge),
            Self::Paired(p) => p.prove(challenge),
            Self::Zero(p) => p.prove(challenge),
            Self::ZeroPaired(p) => p.prove(challenge),
            Self::OneZero(p) => p.prove(challenge),
            Self::Periodic(p) => p.prove(challenge),
            Self::Integer(p) => p.prove(challenge),
            Self::Prefix(p) => p.prove(challenge),
            Self::Limb(p) => p.prove(challenge),
            Self::General(p) => p.prove(challenge),
        }
    }
}

/// Complete canonical W1 proof generator, with no externally supplied product,
/// trace, target result, verifier facts, admission capability or hardware claim.
pub struct IntegerPairedGeneral {
    a: Vec<u32>,
    b: Vec<u32>,
    prefix: Vec<u8>,
}

fn reduce(value: u128) -> u32 {
    // Exact q=2^32-5 fold. Integer pairing subtracts its unreduced factors
    // before calling this function, so the remainder input stays below 2^70.
    debug_assert!(value < 1_u128 << 70);
    let first = u64::from(value as u32) + 5 * ((value >> 32) as u64);
    let second = u64::from(first as u32) + 5 * (first >> 32);
    if second >= Q as u64 {
        (second - Q as u64) as u32
    } else {
        second as u32
    }
}

fn factor(values: &[u32]) -> u128 {
    values
        .chunks_exact(2)
        .map(|p| u128::from(p[0]) * u128::from(p[1]))
        .sum()
}

fn dot(a: &[u32], b: &[u32], af: u128, bf: u128, prior: u32) -> u32 {
    let mut sum = u128::from(prior);
    for (x, y) in a.chunks_exact(2).zip(b.chunks_exact(2)) {
        // The sums need 33 bits and the sum of cross products needs up to
        // 71 bits for inner=64. A u64 implementation would silently be wrong.
        sum += (u128::from(x[0]) + u128::from(y[1])) * (u128::from(x[1]) + u128::from(y[0]));
    }
    reduce(sum - af - bf)
}

fn transpose(values: &[u32], rows: usize, columns: usize) -> Vec<u32> {
    let mut out = vec![0; values.len()];
    for i in 0..rows {
        for j in 0..columns {
            out[j * rows + i] = values[i * columns + j];
        }
    }
    out
}

fn multiply(a: &[u32], b: &[u32], rows: usize, inner: usize, columns: usize) -> Vec<u32> {
    let bt = transpose(b, inner, columns);
    let af: Vec<_> = a.chunks_exact(inner).map(factor).collect();
    let bf: Vec<_> = bt.chunks_exact(inner).map(factor).collect();
    let mut out = vec![0; rows * columns];
    for i in 0..rows {
        for j in 0..columns {
            out[i * columns + j] = dot(
                &a[i * inner..(i + 1) * inner],
                &bt[j * inner..(j + 1) * inner],
                af[i],
                bf[j],
                0,
            );
        }
    }
    out
}

fn expand(challenge: Hash, label: u8) -> Result<Vec<u32>, WorkError> {
    let mut out = Vec::with_capacity(N * R);
    for counter in 0u32..128 {
        let bytes = pon_work::hash(b"noise", &[&challenge, &[label], &counter.to_le_bytes()]);
        for word in bytes.chunks_exact(4) {
            let value = u32::from_le_bytes(word.try_into().expect("four-byte word"));
            if u128::from(value) < Q {
                out.push(value);
                if out.len() == N * R {
                    return Ok(out);
                }
            }
        }
    }
    Err(WorkError::NoiseBudget)
}

impl IntegerPairedGeneral {
    pub fn new(a: &[u32], b: &[u32]) -> Result<Self, WorkError> {
        // Use the original public validation, including all material bytes.
        pon_work::task_id(a, b)?;
        let product = multiply(a, b, N, N, N);
        let mut prefix = Vec::with_capacity(PROOF_BYTES);
        prefix.extend_from_slice(b"PNW1");
        for value in a.iter().chain(b).chain(&product) {
            prefix.extend_from_slice(&value.to_le_bytes());
        }
        Ok(Self {
            a: a.to_vec(),
            b: b.to_vec(),
            prefix,
        })
    }

    pub fn prove(&self, challenge: Hash) -> Result<Vec<u8>, WorkError> {
        let el = expand(challenge, 0)?;
        let er = expand(challenge, 1)?;
        let fl = expand(challenge, 2)?;
        let fr = expand(challenge, 3)?;
        let e = multiply(&el, &er, N, R, N);
        let f = multiply(&fl, &fr, N, R, N);
        let ap: Vec<_> = self
            .a
            .iter()
            .zip(e)
            .map(|(a, e)| reduce(u128::from(*a) + u128::from(e)))
            .collect();
        let bp: Vec<_> = self
            .b
            .iter()
            .zip(f)
            .map(|(b, f)| reduce(u128::from(*b) + u128::from(f)))
            .collect();
        let bt = transpose(&bp, N, N);
        let mut row_factors = [[0; N / R]; N];
        let mut column_factors = [[0; N / R]; N];
        for (matrix, factors) in [(&ap, &mut row_factors), (&bt, &mut column_factors)] {
            for row in 0..N {
                for block in 0..N / R {
                    factors[row][block] =
                        factor(&matrix[row * N + block * R..row * N + (block + 1) * R]);
                }
            }
        }
        let mut trace = Sha256::new();
        trace.update(b"TRNM-PON-TRACE1\0");
        trace.update(challenge);
        for bi in 0..N / R {
            for bj in 0..N / R {
                let mut cells = [0; R * R];
                let mut bytes = [0; R * R * 4];
                for bk in 0..N / R {
                    for i in 0..R {
                        let row = bi * R + i;
                        for j in 0..R {
                            let column = bj * R + j;
                            let pos = i * R + j;
                            cells[pos] = dot(
                                &ap[row * N + bk * R..row * N + (bk + 1) * R],
                                &bt[column * N + bk * R..column * N + (bk + 1) * R],
                                row_factors[row][bk],
                                column_factors[column][bk],
                                cells[pos],
                            );
                            bytes[pos * 4..pos * 4 + 4].copy_from_slice(&cells[pos].to_le_bytes());
                        }
                    }
                    trace.update(bytes);
                }
            }
        }
        let mut proof = self.prefix.clone();
        proof.extend_from_slice(&trace.finalize());
        Ok(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trnm_crypto_primitives::pon_work::CELLS;

    #[test]
    fn integer_pairing_extreme_words_preserve_exact_dot_products() {
        for inner in [R, N] {
            for a_value in [0, 1, Q as u32 - 2, Q as u32 - 1] {
                for b_value in [0, 1, Q as u32 - 2, Q as u32 - 1] {
                    let a = vec![a_value; inner];
                    let b = vec![b_value; inner];
                    for prior in [0, Q as u32 - 1] {
                        let expected = (u128::from(prior)
                            + inner as u128 * u128::from(a_value) * u128::from(b_value))
                            % Q;
                        assert_eq!(
                            u128::from(dot(&a, &b, factor(&a), factor(&b), prior)),
                            expected
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn general_complete_proofs_match_scalar_and_both_full_verifiers() {
        let mut families = crate::materials().unwrap();
        families.push(crate::w1_material::Material {
            name: "near-q-full-rank",
            source: "boundary-test",
            a: (0..CELLS)
                .map(|p| Q as u32 - 1 - u32::from(p / N == p % N))
                .collect(),
            b: (0..CELLS)
                .map(|p| Q as u32 - 2 - u32::from(p / N == p % N))
                .collect(),
        });
        let last = families.last().unwrap();
        assert_eq!(crate::w1_material::rank(&last.a), N);
        assert_eq!(crate::w1_material::rank(&last.b), N);
        for material in families {
            let prepared = IntegerPairedGeneral::new(&material.a, &material.b).unwrap();
            let task = pon_work::task_id(&material.a, &material.b).unwrap();
            for challenge in [[0; 32], [255; 32]] {
                let proof = prepared.prove(challenge).unwrap();
                assert_eq!(
                    proof,
                    pon_work::prove(challenge, &material.a, &material.b).unwrap(),
                    "{}",
                    material.name
                );
                let ordinary = pon_work::verify(challenge, task, [255; 32], &proof).unwrap();
                let reference =
                    pon_work::verify_reference(challenge, task, [255; 32], &proof).unwrap();
                assert_eq!(ordinary.ticket(), reference.ticket());
                assert_eq!(ordinary.product(), reference.product());
            }
        }
        assert!(IntegerPairedGeneral::new(&[], &vec![0; CELLS]).is_err());
        assert!(IntegerPairedGeneral::new(&vec![Q as u32; CELLS], &vec![0; CELLS]).is_err());
    }
}
