//! Research-only decomposition of the already prepared integer-paired producer.
//! Identical arithmetic and SHA transcript; the caller may assemble PNW1 after
//! the ticket test. This supplies no lower bound or production authorization.
use sha2::{Digest, Sha256};
use trnm_crypto_primitives::pon_work::{self, Hash, WorkError, N, PROOF_BYTES, Q, R};

pub struct DeferredPrepared {
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

impl DeferredPrepared {
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

    pub fn trace(&self, challenge: Hash) -> Result<Hash, WorkError> {
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
        Ok(trace.finalize().into())
    }

    pub fn assemble(&self, trace: Hash) -> Vec<u8> {
        let mut proof = self.prefix.clone();
        proof.extend_from_slice(&trace);
        proof
    }
}
