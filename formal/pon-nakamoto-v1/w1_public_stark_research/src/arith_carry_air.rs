//! Exact eight-term arithmetic with base-2^16 carries.
//!
//! This research AIR preserves `Dot8Row` semantics while replacing eight
//! quotient/remainder decompositions with one 35-bit whole-row quotient and
//! two bounded carries. Products themselves are evaluated in 16-bit limbs:
//! no whole 8-product sum is ever evaluated as one Goldilocks expression.
//! See CARRY_BACKEND.md for the integer lifting and completeness bounds.

use p3_air::utils::pack_bits_le;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;

use crate::arith_air::{Dot8Row, FULL_REAL_ROWS, Q};

pub const LIMB_BASE: u64 = 1 << 16;
pub const QUOTIENT_BITS: usize = 35;
pub const LOW_CARRY_BITS: usize = 19;
pub const HIGH_CARRY_BITS: usize = 20;
pub const CARRY_WIDTH: usize = QUOTIENT_BITS + LOW_CARRY_BITS + HIGH_CARRY_BITS;
pub const CARRY_PREPROCESSED_WIDTH: usize = 36;
const LOW_CARRY_OFFSET: usize = QUOTIENT_BITS;
const HIGH_CARRY_OFFSET: usize = QUOTIENT_BITS + LOW_CARRY_BITS;

#[derive(Clone, Debug)]
pub struct Dot8CarryAir {
    rows: Vec<Dot8Row>,
    height: usize,
}

fn limbs(value: u32) -> (u64, u64) {
    (u64::from(value) & (LIMB_BASE - 1), u64::from(value) >> 16)
}

impl Dot8CarryAir {
    pub fn new(rows: Vec<Dot8Row>) -> Result<Self, &'static str> {
        if rows.is_empty() || rows.len() > FULL_REAL_ROWS {
            return Err("arithmetic row count");
        }
        if rows.iter().any(|row| !row.canonical()) {
            return Err("noncanonical public arithmetic word");
        }
        let height = rows.len().next_power_of_two().max(4);
        Ok(Self { rows, height })
    }

    pub fn real_rows(&self) -> usize {
        self.rows.len()
    }
    pub fn trace_height(&self) -> usize {
        self.height
    }
    pub fn rows(&self) -> &[Dot8Row] {
        &self.rows
    }

    pub fn generate_trace(&self) -> RowMajorMatrix<Goldilocks> {
        let mut values = vec![Goldilocks::ZERO; self.height * CARRY_WIDTH];
        for (row_index, row) in self.rows.iter().enumerate() {
            let total = row
                .left
                .iter()
                .zip(row.right)
                .fold(u128::from(row.start), |sum, (&a, b)| {
                    sum + u128::from(a) * u128::from(b)
                });
            let quotient = (total / u128::from(Q)) as u64;
            let (start_low, start_high) = limbs(row.start);
            let (goal_low, goal_high) = limbs(row.goal);
            let mut low = start_low + 5 * (quotient & (LIMB_BASE - 1));
            let mut middle = start_high + 5 * ((quotient >> 16) & (LIMB_BASE - 1));
            for (&a, b) in row.left.iter().zip(row.right) {
                let (al, ah) = limbs(a);
                let (bl, bh) = limbs(b);
                low += al * bl;
                middle += al * bh + ah * bl;
            }
            // Saturation permits generating a rejecting trace for a false
            // canonical row instead of panicking on a malicious goal.
            let low_carry = low.saturating_sub(goal_low) / LIMB_BASE;
            let high_carry = (middle + low_carry).saturating_sub(goal_high) / LIMB_BASE;
            debug_assert!(quotient < 1 << QUOTIENT_BITS);
            debug_assert!(low_carry < 1 << LOW_CARRY_BITS);
            debug_assert!(high_carry < 1 << HIGH_CARRY_BITS);
            let out = &mut values[row_index * CARRY_WIDTH..(row_index + 1) * CARRY_WIDTH];
            for (value, start, bits) in [
                (quotient, 0, QUOTIENT_BITS),
                (low_carry, LOW_CARRY_OFFSET, LOW_CARRY_BITS),
                (high_carry, HIGH_CARRY_OFFSET, HIGH_CARRY_BITS),
            ] {
                for bit in 0..bits {
                    out[start + bit] = Goldilocks::from_bool((value >> bit) & 1 == 1);
                }
            }
        }
        RowMajorMatrix::new(values, CARRY_WIDTH)
    }
}

impl BaseAir<Goldilocks> for Dot8CarryAir {
    fn width(&self) -> usize {
        CARRY_WIDTH
    }
    fn preprocessed_width(&self) -> usize {
        CARRY_PREPROCESSED_WIDTH
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Goldilocks>> {
        let mut values = vec![Goldilocks::ZERO; self.height * CARRY_PREPROCESSED_WIDTH];
        for (i, row) in self.rows.iter().enumerate() {
            let out = &mut values[i * CARRY_PREPROCESSED_WIDTH..(i + 1) * CARRY_PREPROCESSED_WIDTH];
            for j in 0..8 {
                let (al, ah) = limbs(row.left[j]);
                let (bl, bh) = limbs(row.right[j]);
                for (offset, value) in [al, ah, bl, bh].into_iter().enumerate() {
                    out[4 * j + offset] = Goldilocks::from_u64(value);
                }
            }
            let (sl, sh) = limbs(row.start);
            let (gl, gh) = limbs(row.goal);
            for (offset, value) in [sl, sh, gl, gh].into_iter().enumerate() {
                out[32 + offset] = Goldilocks::from_u64(value);
            }
        }
        Some(RowMajorMatrix::new(values, CARRY_PREPROCESSED_WIDTH))
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
    fn num_public_values(&self) -> usize {
        0
    }
}

impl<AB: AirBuilder<F = Goldilocks>> Air<AB> for Dot8CarryAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let bits = main.current_slice();
        let public = builder.preprocessed().current_slice().to_vec();
        for &bit in bits {
            builder.assert_bool(bit);
        }
        let q0 = pack_bits_le::<AB::Expr, _, _>(bits[..16].iter().copied());
        let q1 = pack_bits_le::<AB::Expr, _, _>(bits[16..32].iter().copied());
        let q2 = pack_bits_le::<AB::Expr, _, _>(bits[32..QUOTIENT_BITS].iter().copied());
        let c0 = pack_bits_le::<AB::Expr, _, _>(
            bits[LOW_CARRY_OFFSET..HIGH_CARRY_OFFSET].iter().copied(),
        );
        let c1 = pack_bits_le::<AB::Expr, _, _>(bits[HIGH_CARRY_OFFSET..].iter().copied());
        let base = Goldilocks::from_u64(LIMB_BASE);
        let five = Goldilocks::from_u8(5);
        let mut low = AB::Expr::from(public[32]) + q0.clone() * five;
        let mut middle = AB::Expr::from(public[33]) + q1.clone() * five + c0.clone();
        let mut high = q2.clone() * five + c1.clone();
        for j in 0..8 {
            let al = AB::Expr::from(public[4 * j]);
            let ah = AB::Expr::from(public[4 * j + 1]);
            let bl = AB::Expr::from(public[4 * j + 2]);
            let bh = AB::Expr::from(public[4 * j + 3]);
            low += al.clone() * bl.clone();
            middle += al * bh.clone() + ah.clone() * bl;
            high += ah * bh;
        }
        builder.assert_eq(low, AB::Expr::from(public[34]) + c0 * base);
        builder.assert_eq(middle, AB::Expr::from(public[35]) + c1 * base);
        builder.assert_eq(
            high,
            q0 + q1 * base + q2 * Goldilocks::from_u64(LIMB_BASE * LIMB_BASE),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::check_constraints;

    fn rejects(air: &Dot8CarryAir, trace: &RowMajorMatrix<Goldilocks>) {
        assert!(std::panic::catch_unwind(|| check_constraints(air, trace, &[])).is_err());
    }

    #[test]
    fn maximum_canonical_inputs_and_boundary_additions_are_exact() {
        let rows = vec![
            Dot8Row {
                left: [Q as u32 - 1; 8],
                right: [Q as u32 - 1; 8],
                start: Q as u32 - 1,
                goal: 7,
            },
            Dot8Row::addition(Q as u32 - 1, Q as u32 - 1, Q as u32 - 2),
            Dot8Row::addition(65_535, 1, 65_536),
            Dot8Row::addition(0, 0, 0),
            Dot8Row::addition(Q as u32 - 1, 1, 0),
        ];
        assert!(rows.iter().all(Dot8Row::integer_holds));
        let air = Dot8CarryAir::new(rows).unwrap();
        check_constraints(&air, &air.generate_trace(), &[]);
    }

    #[test]
    fn prior_whole_dot_goldilocks_alias_is_rejected() {
        let air = Dot8CarryAir::new(vec![Dot8Row {
            left: [Q as u32 - 1; 8],
            right: [Q as u32 - 1; 8],
            start: 0,
            goal: 4_294_967_278,
        }])
        .unwrap();
        assert!(!air.rows()[0].integer_holds());
        rejects(&air, &air.generate_trace());
    }

    #[test]
    fn each_witness_bit_and_nonboolean_value_are_checked() {
        let air = Dot8CarryAir::new(vec![Dot8Row {
            left: [Q as u32 - 1; 8],
            right: [Q as u32 - 1; 8],
            start: Q as u32 - 1,
            goal: 7,
        }])
        .unwrap();
        for bit in 0..CARRY_WIDTH {
            let mut trace = air.generate_trace();
            trace.values[bit] = Goldilocks::ONE - trace.values[bit];
            rejects(&air, &trace);
        }
        let mut trace = air.generate_trace();
        trace.values[HIGH_CARRY_OFFSET] = Goldilocks::TWO;
        rejects(&air, &trace);
    }

    #[test]
    fn canonical_false_goals_and_noncanonical_public_words_are_rejected() {
        let air = Dot8CarryAir::new(vec![Dot8Row::addition(0, 0, Q as u32 - 1)]).unwrap();
        rejects(&air, &air.generate_trace());
        assert!(Dot8CarryAir::new(vec![Dot8Row::addition(Q as u32, 0, 0)]).is_err());
        assert!(Dot8CarryAir::new(vec![Dot8Row::addition(0, 0, Q as u32)]).is_err());
    }

    #[test]
    fn deterministic_rows_match_independent_u128_relation() {
        let mut state = 0x66e7_0de8_0000_0061u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state % Q) as u32
        };
        let mut rows = Vec::new();
        for _ in 0..2_048 {
            let left = std::array::from_fn(|_| next());
            let right = std::array::from_fn(|_| next());
            let start = next();
            let total = left
                .iter()
                .zip(right)
                .fold(u128::from(start), |s, (&a, b)| {
                    s + u128::from(a) * u128::from(b)
                });
            rows.push(Dot8Row {
                left,
                right,
                start,
                goal: (total % u128::from(Q)) as u32,
            });
        }
        let air = Dot8CarryAir::new(rows).unwrap();
        check_constraints(&air, &air.generate_trace(), &[]);
    }
}
