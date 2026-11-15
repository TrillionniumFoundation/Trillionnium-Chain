//! Exact eight-term arithmetic over q inside the Goldilocks proof field.
//!
//! Each product has 32-bit quotient and remainder witnesses. Intermediates
//! need not be canonical modulo q: their bounded integer equations imply the
//! correct congruence, and the public start/goal are canonical. The eight-term
//! sum is formed only AFTER reducing each individual product, avoiding a
//! whole-dot Goldilocks wraparound.

use p3_air::utils::pack_bits_le;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;

pub const Q: u64 = 4_294_967_291;
pub const DOT8_WIDTH: usize = 8 * 64 + 4;
pub const DOT8_PREPROCESSED_WIDTH: usize = 18;
pub const FULL_REAL_ROWS: usize = 81_920;
pub const FULL_PADDED_ROWS: usize = 131_072;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dot8Row {
    pub left: [u32; 8],
    pub right: [u32; 8],
    pub start: u32,
    pub goal: u32,
}

impl Dot8Row {
    pub fn addition(a: u32, b: u32, goal: u32) -> Self {
        let mut left = [0; 8];
        let mut right = [0; 8];
        left[0] = 1;
        left[1] = 1;
        right[0] = a;
        right[1] = b;
        Self {
            left,
            right,
            start: 0,
            goal,
        }
    }

    pub fn canonical(&self) -> bool {
        self.left
            .iter()
            .chain(self.right.iter())
            .chain([&self.start, &self.goal])
            .all(|&word| u64::from(word) < Q)
    }

    /// Independent integer diagnostic, never called by STARK verification.
    pub fn integer_holds(&self) -> bool {
        let total = self
            .left
            .iter()
            .zip(self.right)
            .fold(u128::from(self.start), |sum, (&a, b)| {
                sum + u128::from(a) * u128::from(b)
            });
        self.canonical() && total % u128::from(Q) == u128::from(self.goal)
    }
}

#[derive(Clone, Debug)]
pub struct Dot8Air {
    rows: Vec<Dot8Row>,
    height: usize,
}

impl Dot8Air {
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
        let mut values = vec![Goldilocks::ZERO; self.height * DOT8_WIDTH];
        for (row_index, row) in self.rows.iter().enumerate() {
            let out = &mut values[row_index * DOT8_WIDTH..(row_index + 1) * DOT8_WIDTH];
            let mut sum = u64::from(row.start);
            for i in 0..8 {
                let product = u64::from(row.left[i]) * u64::from(row.right[i]);
                let quotient = product / Q;
                let remainder = product % Q;
                sum += remainder;
                for bit in 0..32 {
                    out[i * 64 + bit] = Goldilocks::from_bool((quotient >> bit) & 1 == 1);
                    out[i * 64 + 32 + bit] = Goldilocks::from_bool((remainder >> bit) & 1 == 1);
                }
            }
            let carry = sum / Q;
            debug_assert!(carry <= 8);
            for bit in 0..4 {
                out[512 + bit] = Goldilocks::from_bool((carry >> bit) & 1 == 1);
            }
        }
        RowMajorMatrix::new(values, DOT8_WIDTH)
    }
}

impl BaseAir<Goldilocks> for Dot8Air {
    fn width(&self) -> usize {
        DOT8_WIDTH
    }
    fn preprocessed_width(&self) -> usize {
        DOT8_PREPROCESSED_WIDTH
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Goldilocks>> {
        let mut values = vec![Goldilocks::ZERO; self.height * DOT8_PREPROCESSED_WIDTH];
        for (i, row) in self.rows.iter().enumerate() {
            let out = &mut values[i * DOT8_PREPROCESSED_WIDTH..(i + 1) * DOT8_PREPROCESSED_WIDTH];
            for j in 0..8 {
                out[2 * j] = Goldilocks::from_u32(row.left[j]);
                out[2 * j + 1] = Goldilocks::from_u32(row.right[j]);
            }
            out[16] = Goldilocks::from_u32(row.start);
            out[17] = Goldilocks::from_u32(row.goal);
        }
        Some(RowMajorMatrix::new(values, DOT8_PREPROCESSED_WIDTH))
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

impl<AB: AirBuilder<F = Goldilocks>> Air<AB> for Dot8Air {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let bits = main.current_slice();
        let public = builder.preprocessed().current_slice().to_vec();
        for &bit in bits {
            builder.assert_bool(bit);
        }
        let q = Goldilocks::from_u64(Q);
        let mut sum = AB::Expr::from(public[16]);
        for i in 0..8 {
            let quotient =
                pack_bits_le::<AB::Expr, _, _>(bits[i * 64..i * 64 + 32].iter().copied());
            let remainder =
                pack_bits_le::<AB::Expr, _, _>(bits[i * 64 + 32..(i + 1) * 64].iter().copied());
            builder.assert_eq(
                public[2 * i] * public[2 * i + 1],
                quotient * q + remainder.clone(),
            );
            sum += remainder;
        }
        let carry = pack_bits_le::<AB::Expr, _, _>(bits[512..516].iter().copied());
        builder.assert_eq(sum, AB::Expr::from(public[17]) + carry * q);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::check_constraints;

    fn rejects(air: &Dot8Air, trace: &RowMajorMatrix<Goldilocks>) {
        assert!(std::panic::catch_unwind(|| check_constraints(air, trace, &[])).is_err());
    }

    #[test]
    fn maximum_inputs_and_addition_are_integer_exact() {
        let rows = vec![
            Dot8Row {
                left: [Q as u32 - 1; 8],
                right: [Q as u32 - 1; 8],
                start: Q as u32 - 1,
                goal: 7,
            },
            Dot8Row::addition(Q as u32 - 1, Q as u32 - 1, Q as u32 - 2),
        ];
        assert!(rows.iter().all(Dot8Row::integer_holds));
        let air = Dot8Air::new(rows).unwrap();
        check_constraints(&air, &air.generate_trace(), &[]);
    }

    #[test]
    fn prior_whole_dot_goldilocks_alias_is_rejected() {
        let air = Dot8Air::new(vec![Dot8Row {
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
    fn nonboolean_bit_and_wrong_quotient_are_rejected() {
        let air = Dot8Air::new(vec![Dot8Row::addition(7, 9, 16)]).unwrap();
        let mut trace = air.generate_trace();
        trace.values[0] = Goldilocks::TWO;
        rejects(&air, &trace);
        let mut trace = air.generate_trace();
        trace.values[0] = Goldilocks::ONE;
        rejects(&air, &trace);
    }

    #[test]
    fn public_noncanonical_words_are_refused() {
        assert!(Dot8Air::new(vec![Dot8Row::addition(Q as u32, 0, 0)]).is_err());
        assert!(Dot8Air::new(vec![Dot8Row::addition(0, 0, Q as u32)]).is_err());
    }

    #[test]
    fn bounded_noncanonical_intermediate_is_an_equivalent_representation() {
        let mut left = [0; 8];
        let mut right = [0; 8];
        left[0] = Q as u32 - 1;
        right[0] = Q as u32 - 1;
        let air = Dot8Air::new(vec![Dot8Row {
            left,
            right,
            start: 0,
            goal: 1,
        }])
        .unwrap();
        let mut trace = air.generate_trace();
        // (q-1)^2 = q(q-3) + (q+1). Its sum quotient is one.
        for bit in 0..32 {
            trace.values[bit] = Goldilocks::from_bool(((Q - 3) >> bit) & 1 == 1);
            trace.values[32 + bit] = Goldilocks::from_bool(((Q + 1) >> bit) & 1 == 1);
        }
        trace.values[512] = Goldilocks::ONE;
        check_constraints(&air, &trace, &[]);
    }
}
