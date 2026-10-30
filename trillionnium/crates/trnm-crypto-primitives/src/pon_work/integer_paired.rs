//! Exact integer paired products for experimental producers. These helpers are
//! not verifier logic and never change the older field-paired producer.
use super::{producer_reduce, N};

pub(super) fn factor(values: &[u32]) -> u128 {
    debug_assert!(values.len().is_multiple_of(2) && values.len() <= N);
    values
        .chunks_exact(2)
        .map(|pair| u128::from(pair[0]) * u128::from(pair[1]))
        .sum()
}

// Over integers, (x0+y1)(x1+y0)-x0*x1-y0*y1 = x0*y0+x1*y1.
// Cast BEFORE addition: the unreduced pair sums require 33 bits. For inner=8,
// the accumulated pre-subtraction sum is <2^68. For inner=64 it is <2^71,
// and must not enter producer_reduce until both exact factors are subtracted.
// The subtractions are nonnegative even with a canonical prior. Their result
// equals prior+sum(x*y) <2^70 for every supported inner<=64 and canonical input.
pub(super) fn dot(
    left: &[u32],
    right: &[u32],
    left_factor: u128,
    right_factor: u128,
    prior: u32,
) -> u32 {
    debug_assert_eq!(left.len(), right.len());
    debug_assert!(left.len().is_multiple_of(2) && left.len() <= N);
    let mut sum = u128::from(prior);
    for (x, y) in left.chunks_exact(2).zip(right.chunks_exact(2)) {
        sum += (u128::from(x[0]) + u128::from(y[1])) * (u128::from(x[1]) + u128::from(y[0]));
    }
    debug_assert!(sum >= left_factor + right_factor);
    producer_reduce(sum - left_factor - right_factor)
}

pub(super) fn transpose(matrix: &[u32], rows: usize, columns: usize) -> Vec<u32> {
    let mut output = vec![0; matrix.len()];
    for row in 0..rows {
        for column in 0..columns {
            output[column * rows + row] = matrix[row * columns + column];
        }
    }
    output
}

#[derive(Clone, Copy)]
pub(super) enum ProductProgress {
    Factor { operand: u8, row: usize },
    Row { row: usize },
}

pub(super) fn mul<E>(
    left: &[u32],
    right: &[u32],
    rows: usize,
    inner: usize,
    columns: usize,
    mut progress: impl FnMut(ProductProgress) -> Result<(), E>,
) -> Result<Vec<u32>, E> {
    let transposed = transpose(right, inner, columns);
    let mut left_factors = Vec::with_capacity(rows);
    let mut right_factors = Vec::with_capacity(columns);
    for (row, values) in left.chunks_exact(inner).enumerate() {
        progress(ProductProgress::Factor { operand: 0, row })?;
        left_factors.push(factor(values));
    }
    for (row, values) in transposed.chunks_exact(inner).enumerate() {
        progress(ProductProgress::Factor { operand: 1, row })?;
        right_factors.push(factor(values));
    }
    let mut output = vec![0; rows * columns];
    for row in 0..rows {
        progress(ProductProgress::Row { row })?;
        for column in 0..columns {
            output[row * columns + column] = dot(
                &left[row * inner..(row + 1) * inner],
                &transposed[column * inner..(column + 1) * inner],
                left_factors[row],
                right_factors[column],
                0,
            );
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pon_work::{Q, R};

    #[test]
    fn unreduced_integer_pairs_cover_extremes_and_nonnegative_subtraction() {
        let values = [0, 1, 2, Q as u32 - 2, Q as u32 - 1];
        for a0 in values {
            for a1 in values {
                for b0 in values {
                    for b1 in values {
                        let left = [a0, a1];
                        let right = [b0, b1];
                        for prior in values {
                            let expected = (u128::from(prior)
                                + u128::from(a0) * u128::from(b0)
                                + u128::from(a1) * u128::from(b1))
                                % Q;
                            assert_eq!(
                                dot(&left, &right, factor(&left), factor(&right), prior),
                                expected as u32
                            );
                        }
                    }
                }
            }
        }
        for inner in [R, N] {
            let maximum = vec![Q as u32 - 1; inner];
            let sparse: Vec<_> = (0..inner)
                .map(|index| if index % 2 == 0 { Q as u32 - 1 } else { 0 })
                .collect();
            let reverse: Vec<_> = sparse.iter().rev().copied().collect();
            for (left, right) in [(&maximum, &maximum), (&sparse, &reverse)] {
                for prior in values {
                    let expected = (u128::from(prior)
                        + left
                            .iter()
                            .zip(right)
                            .map(|(&x, &y)| u128::from(x) * u128::from(y))
                            .sum::<u128>())
                        % Q;
                    assert_eq!(
                        dot(left, right, factor(left), factor(right), prior),
                        expected as u32
                    );
                }
            }
        }
    }
}
