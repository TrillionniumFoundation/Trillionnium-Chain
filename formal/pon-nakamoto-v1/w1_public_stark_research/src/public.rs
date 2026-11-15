//! Bounded public statement and deterministic relation wiring.
//!
//! SHA claims and arithmetic intermediates are untrusted public data. The
//! verifier builds the two AIRs from these bytes itself. It does not recompute
//! a native hash, matrix product, or accept a proof-supplied verification key.

use crate::arith_air::{Dot8Air, Dot8Row, FULL_REAL_ROWS, Q};
use crate::sha_plan::{
    HEADER_BYTES, HashClaims, INPUT_BYTES, PREFIX_BYTES, ShaPlan, W1ShaPublic, honest_claims,
};

pub const N: usize = 64;
pub const CELLS: usize = N * N;
pub const PUBLIC_MAGIC: &[u8; 8] = b"W1P3PUB1";
pub const HASH_CLAIMS_BYTES: usize = 32 * (1 + 4 * 128 + 2);
pub const ARITHMETIC_CLAIMS_WORDS: usize = (4 + 7) * CELLS;
pub const PUBLIC_BYTES: usize =
    8 + INPUT_BYTES + PREFIX_BYTES + HASH_CLAIMS_BYTES + 4 * ARITHMETIC_CLAIMS_WORDS;

#[derive(Clone, Debug)]
pub struct ArithmeticClaims {
    pub e: Vec<u32>,
    pub f: Vec<u32>,
    pub a_hat: Vec<u32>,
    pub b_hat: Vec<u32>,
    /// First seven complete AB prefixes, group-major. The eighth goal is C.
    pub ab_prefixes: Vec<u32>,
}

#[derive(Clone, Debug)]
pub struct PublicStatement {
    pub raw: Vec<u8>,
    pub prefix: Vec<u8>,
    pub hashes: HashClaims,
    pub arithmetic: ArithmeticClaims,
}

pub struct Expected {
    pub header: [u8; HEADER_BYTES],
    pub artifacts: [u8; 64],
}

impl Expected {
    pub fn from_bytes(header: &[u8], artifacts: &[u8]) -> Result<Self, &'static str> {
        Ok(Self {
            header: header.try_into().map_err(|_| "expected header length")?,
            artifacts: artifacts
                .try_into()
                .map_err(|_| "expected artifacts length")?,
        })
    }
}

fn canonical_words(bytes: &[u8]) -> Result<Vec<u32>, &'static str> {
    if !bytes.len().is_multiple_of(4) {
        return Err("word alignment");
    }
    bytes
        .chunks_exact(4)
        .map(|x| {
            let word = u32::from_le_bytes(x.try_into().unwrap());
            if u64::from(word) < Q {
                Ok(word)
            } else {
                Err("noncanonical public word")
            }
        })
        .collect()
}

/// This public deterministic sampler selects exactly the original accepted
/// u32 words. Every underlying digest is separately constrained in SHA AIR.
pub fn selected_noise(hashes: &HashClaims) -> Result<[Vec<u32>; 4], &'static str> {
    let mut factors: [Vec<u32>; 4] = core::array::from_fn(|_| Vec::with_capacity(512));
    for (label, factor) in factors.iter_mut().enumerate() {
        'digests: for digest in &hashes.noise[label] {
            for bytes in digest.chunks_exact(4) {
                let word = u32::from_le_bytes(bytes.try_into().unwrap());
                if u64::from(word) < Q {
                    factor.push(word);
                    if factor.len() == 512 {
                        break 'digests;
                    }
                }
            }
        }
        if factor.len() != 512 {
            return Err("original noise budget exhausted");
        }
    }
    Ok(factors)
}

fn unpack_original_prefix(bytes: &[u8]) -> Result<Vec<u32>, &'static str> {
    if bytes.len() != PREFIX_BYTES {
        return Err("prefix length");
    }
    let words = canonical_words(bytes)?;
    let mut out = vec![0; 8 * CELLS];
    let mut offset = 0;
    for bi in 0..8 {
        for bj in 0..8 {
            for bk in 0..8 {
                for i in 0..8 {
                    for j in 0..8 {
                        out[bk * CELLS + (8 * bi + i) * N + 8 * bj + j] = words[offset];
                        offset += 1;
                    }
                }
            }
        }
    }
    Ok(out)
}

impl PublicStatement {
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != PUBLIC_BYTES || &bytes[..8] != PUBLIC_MAGIC {
            return Err("public framing");
        }
        let mut pos = 8;
        let raw = bytes[pos..pos + INPUT_BYTES].to_vec();
        pos += INPUT_BYTES;
        let prefix = bytes[pos..pos + PREFIX_BYTES].to_vec();
        pos += PREFIX_BYTES;
        let mut hash = || {
            let out = bytes[pos..pos + 32].try_into().unwrap();
            pos += 32;
            out
        };
        let challenge = hash();
        let noise = core::array::from_fn(|_| core::array::from_fn(|_| hash()));
        let ticket = hash();
        let work_id = hash();
        let hashes = HashClaims {
            challenge,
            noise,
            ticket,
            work_id,
        };
        let mut words = |n: usize| {
            let out = canonical_words(&bytes[pos..pos + 4 * n]);
            pos += 4 * n;
            out
        };
        let arithmetic = ArithmeticClaims {
            e: words(CELLS)?,
            f: words(CELLS)?,
            a_hat: words(CELLS)?,
            b_hat: words(CELLS)?,
            ab_prefixes: words(7 * CELLS)?,
        };
        debug_assert_eq!(pos, bytes.len());
        Ok(Self {
            raw,
            prefix,
            hashes,
            arithmetic,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, &'static str> {
        self.check_lengths_and_words()?;
        let mut out = Vec::with_capacity(PUBLIC_BYTES);
        out.extend_from_slice(PUBLIC_MAGIC);
        out.extend_from_slice(&self.raw);
        out.extend_from_slice(&self.prefix);
        out.extend_from_slice(&self.hashes.challenge);
        for label in &self.hashes.noise {
            for digest in label {
                out.extend_from_slice(digest);
            }
        }
        out.extend_from_slice(&self.hashes.ticket);
        out.extend_from_slice(&self.hashes.work_id);
        for words in [
            &self.arithmetic.e,
            &self.arithmetic.f,
            &self.arithmetic.a_hat,
            &self.arithmetic.b_hat,
            &self.arithmetic.ab_prefixes,
        ] {
            for word in words {
                out.extend_from_slice(&word.to_le_bytes());
            }
        }
        assert_eq!(out.len(), PUBLIC_BYTES);
        Ok(out)
    }

    fn check_lengths_and_words(&self) -> Result<(), &'static str> {
        if self.raw.len() != INPUT_BYTES || self.prefix.len() != PREFIX_BYTES {
            return Err("statement length");
        }
        for data in [
            &self.arithmetic.e,
            &self.arithmetic.f,
            &self.arithmetic.a_hat,
            &self.arithmetic.b_hat,
        ] {
            if data.len() != CELLS {
                return Err("matrix claim length");
            }
        }
        if self.arithmetic.ab_prefixes.len() != 7 * CELLS {
            return Err("AB prefix claim length");
        }
        for data in [
            &self.arithmetic.e,
            &self.arithmetic.f,
            &self.arithmetic.a_hat,
            &self.arithmetic.b_hat,
            &self.arithmetic.ab_prefixes,
        ] {
            if data.iter().any(|&x| u64::from(x) >= Q) {
                return Err("noncanonical arithmetic claim");
            }
        }
        canonical_words(&self.raw[HEADER_BYTES + 4..INPUT_BYTES - 32])?;
        canonical_words(&self.prefix)?;
        Ok(())
    }

    /// Constructs all verifier-owned deterministic checks and preprocessing.
    /// No SHA digest or matrix product is evaluated by this function.
    pub fn plans(&self, expected: &Expected) -> Result<(ShaPlan, Dot8Air), String> {
        self.check_lengths_and_words()?;
        let sha = ShaPlan::from_w1(W1ShaPublic {
            raw: &self.raw,
            prefix: &self.prefix,
            expected_header: &expected.header,
            expected_artifacts: &expected.artifacts,
            claims: &self.hashes,
        })
        .map_err(|x| x.to_string())?;
        let target: [u8; 32] = expected.header[118..150].try_into().unwrap();
        if target == [0; 32] {
            return Err("zero target".into());
        }
        if self.hashes.ticket > target {
            return Err("ticket target".into());
        }
        let factors = selected_noise(&self.hashes)?;
        let matrices = canonical_words(&self.raw[HEADER_BYTES + 4..INPUT_BYTES - 32])?;
        let a = &matrices[..CELLS];
        let b = &matrices[CELLS..2 * CELLS];
        let c = &matrices[2 * CELLS..];
        let prefix = unpack_original_prefix(&self.prefix)?;
        let claims = &self.arithmetic;
        let mut rows = Vec::with_capacity(FULL_REAL_ROWS);
        // Every dense factor product E and F is constrained.
        for (left, right, goal) in [
            (&factors[0], &factors[1], &claims.e),
            (&factors[2], &factors[3], &claims.f),
        ] {
            for i in 0..N {
                for j in 0..N {
                    rows.push(Dot8Row {
                        left: core::array::from_fn(|k| left[i * 8 + k]),
                        right: core::array::from_fn(|k| right[k * N + j]),
                        start: 0,
                        goal: goal[i * N + j],
                    });
                }
            }
        }
        // Public Ahat/Bhat claims are linked by constrained additions.
        for cell in 0..CELLS {
            rows.push(Dot8Row::addition(
                a[cell],
                claims.e[cell],
                claims.a_hat[cell],
            ));
            rows.push(Dot8Row::addition(
                b[cell],
                claims.f[cell],
                claims.b_hat[cell],
            ));
        }
        // Every original cumulative noisy prefix and its predecessor is used.
        for group in 0..8 {
            for i in 0..N {
                for j in 0..N {
                    let cell = i * N + j;
                    rows.push(Dot8Row {
                        left: core::array::from_fn(|k| claims.a_hat[i * N + group * 8 + k]),
                        right: core::array::from_fn(|k| claims.b_hat[(group * 8 + k) * N + j]),
                        start: if group == 0 {
                            0
                        } else {
                            prefix[(group - 1) * CELLS + cell]
                        },
                        goal: prefix[group * CELLS + cell],
                    });
                }
            }
        }
        // Complete AB=C, in eight exact reductions. No projection is used.
        for group in 0..8 {
            for i in 0..N {
                for j in 0..N {
                    let cell = i * N + j;
                    rows.push(Dot8Row {
                        left: core::array::from_fn(|k| a[i * N + group * 8 + k]),
                        right: core::array::from_fn(|k| b[(group * 8 + k) * N + j]),
                        start: if group == 0 {
                            0
                        } else {
                            claims.ab_prefixes[(group - 1) * CELLS + cell]
                        },
                        goal: if group == 7 {
                            c[cell]
                        } else {
                            claims.ab_prefixes[group * CELLS + cell]
                        },
                    });
                }
            }
        }
        assert_eq!(rows.len(), FULL_REAL_ROWS);
        Ok((sha, Dot8Air::new(rows)?))
    }

    /// Honest public witness construction. This is prover work and is timed.
    pub fn honest(raw: Vec<u8>, prefix: Vec<u8>) -> Result<Self, String> {
        if raw.len() != INPUT_BYTES || prefix.len() != PREFIX_BYTES {
            return Err("fixture length".into());
        }
        let hashes = honest_claims(&raw).map_err(|x| x.to_string())?;
        let factors = selected_noise(&hashes)?;
        let matrices = canonical_words(&raw[HEADER_BYTES + 4..INPUT_BYTES - 32])?;
        let a = &matrices[..CELLS];
        let b = &matrices[CELLS..2 * CELLS];
        let dense = |l: &[u32], r: &[u32]| -> Vec<u32> {
            (0..CELLS)
                .map(|cell| {
                    let i = cell / N;
                    let j = cell % N;
                    let sum: u128 = (0..8)
                        .map(|k| u128::from(l[i * 8 + k]) * u128::from(r[k * N + j]))
                        .sum();
                    (sum % u128::from(Q)) as u32
                })
                .collect()
        };
        let e = dense(&factors[0], &factors[1]);
        let f = dense(&factors[2], &factors[3]);
        let a_hat = a
            .iter()
            .zip(&e)
            .map(|(&x, &y)| ((u64::from(x) + u64::from(y)) % Q) as u32)
            .collect();
        let b_hat = b
            .iter()
            .zip(&f)
            .map(|(&x, &y)| ((u64::from(x) + u64::from(y)) % Q) as u32)
            .collect();
        let mut ab_prefixes = vec![0; 7 * CELLS];
        for group in 0..7 {
            for i in 0..N {
                for j in 0..N {
                    let cell = i * N + j;
                    let old = if group == 0 {
                        0
                    } else {
                        ab_prefixes[(group - 1) * CELLS + cell]
                    };
                    let sum = (0..8).fold(u128::from(old), |s, k| {
                        s + u128::from(a[i * N + group * 8 + k])
                            * u128::from(b[(group * 8 + k) * N + j])
                    });
                    ab_prefixes[group * CELLS + cell] = (sum % u128::from(Q)) as u32;
                }
            }
        }
        Ok(Self {
            raw,
            prefix,
            hashes,
            arithmetic: ArithmeticClaims {
                e,
                f,
                a_hat,
                b_hat,
                ab_prefixes,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_noise_rejection_selection_and_budget_are_preserved() {
        let mut claims = HashClaims {
            challenge: [0; 32],
            noise: [[[0; 32]; 128]; 4],
            ticket: [0; 32],
            work_id: [0; 32],
        };
        claims.noise[0][0][..4].copy_from_slice(&(Q as u32).to_le_bytes());
        claims.noise[0][0][4..8].copy_from_slice(&7u32.to_le_bytes());
        let factors = selected_noise(&claims).unwrap();
        assert_eq!(factors[0][0], 7);
        assert_eq!(factors[0].len(), 512);
        claims.noise[2] = [[255; 32]; 128];
        assert!(selected_noise(&claims).is_err());
    }

    #[test]
    fn public_parser_refuses_wrong_length_before_allocation() {
        assert!(PublicStatement::decode(&[]).is_err());
        assert!(PublicStatement::decode(&vec![0; PUBLIC_BYTES + 1]).is_err());
    }

    #[test]
    fn original_prefix_order_is_grouped_without_losing_any_word() {
        let bytes: Vec<u8> = (0..32768u32).flat_map(u32::to_le_bytes).collect();
        let grouped = unpack_original_prefix(&bytes).unwrap();
        assert_eq!(grouped[0], 0);
        assert_eq!(grouped[CELLS], 64);
        assert_eq!(grouped[8], 512);
        assert_eq!(grouped[8 * N], 4096);
        assert_eq!(*grouped.last().unwrap(), 32767);
    }
}
