//! SHA-256 with its public message schedule independently reconstructed.
//!
//! Every input block remains the exact canonical padded block in `ShaPlan`.
//! The verifier expands its 64 schedule words into fixed 16-bit limbs; neither
//! this table nor any verifier key is accepted from the proof. All 64 rounds,
//! initial states, cross-block links and final digests remain AIR constraints.
//!
//! The compression constraints and trace generation below adapt Plonky3
//! `p3-sha256-air` 0.8.0 (MIT OR Apache-2.0), preserving their formulas.
//! Source hashes and the projection/extension argument are recorded in
//! `PUBLIC_SCHEDULE_BACKEND.md`. Only the public schedule constraints/columns
//! are removed. This is a research-only relation reduction, not a new security
//! theorem or a native digest acceptance path.

use crate::sha_plan::{ShaPlan, padded_blocks};
use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use p3_air::utils::{pack_bits_le, u32_to_bits_le};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::integers::QuotientMap;
use p3_field::{Dup, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;
use p3_sha256_air::{
    BITS_PER_LIMB, BLOCK_WORDS, CHAIN_LEN, NUM_COMPRESSION_ROUNDS, SHA256_IV, SHA256_K,
    STATE_WORDS, Sha256RoundCols, U32_LIMBS, WORD_BITS,
};

pub const SCHEDULE_PREPROCESSED_WIDTH: usize = 139;
const fn u32_to_limbs(word: u32) -> [u16; 2] {
    [word as u16, (word >> 16) as u16]
}
const FIRST: usize = 128;
const CHAIN: usize = 129;
const OUTPUT: usize = 130;
const DIGEST: usize = 131;

/// The remaining official row columns, in their original relative order.
#[repr(C)]
pub struct ScheduledShaCols<T> {
    pub h_in: [[T; 2]; 8],
    pub a_chain: [[T; 32]; 68],
    pub e_chain: [[T; 32]; 68],
    pub rounds: [Sha256RoundCols<T>; 64],
    pub h_out: [[T; 32]; 8],
}

pub const SCHEDULE_SHA_WIDTH: usize = size_of::<ScheduledShaCols<u8>>();
const _: () = assert!(SCHEDULE_SHA_WIDTH == 5392);

impl<T> Borrow<ScheduledShaCols<T>> for [T] {
    fn borrow(&self) -> &ScheduledShaCols<T> {
        assert_eq!(self.len(), SCHEDULE_SHA_WIDTH);
        // SAFETY: repr(C) consists only of flat T arrays, and the exact row
        // length and alignment are checked before the reference is returned.
        let (prefix, rows, suffix) = unsafe { self.align_to::<ScheduledShaCols<T>>() };
        assert!(prefix.is_empty() && suffix.is_empty());
        assert_eq!(rows.len(), 1);
        &rows[0]
    }
}
impl<T> BorrowMut<ScheduledShaCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut ScheduledShaCols<T> {
        assert_eq!(self.len(), SCHEDULE_SHA_WIDTH);
        // SAFETY: the same layout argument as the shared row view applies.
        let (prefix, rows, suffix) = unsafe { self.align_to_mut::<ScheduledShaCols<T>>() };
        assert!(prefix.is_empty() && suffix.is_empty());
        assert_eq!(rows.len(), 1);
        &mut rows[0]
    }
}

/// Exact SHA-256 public expansion; no compression state or digest is computed.
/// Callers supply the canonical big-endian words of the padded message block.
pub fn expand_schedule(block: [u32; 16]) -> [u32; 64] {
    let mut words = [0u32; 64];
    words[..16].copy_from_slice(&block);
    for t in 16..64 {
        let a = words[t - 15];
        let b = words[t - 2];
        let s0 = a.rotate_right(7) ^ a.rotate_right(18) ^ (a >> 3);
        let s1 = b.rotate_right(17) ^ b.rotate_right(19) ^ (b >> 10);
        words[t] = s1
            .wrapping_add(words[t - 7])
            .wrapping_add(s0)
            .wrapping_add(words[t - 16]);
    }
    words
}

#[derive(Clone, Debug)]
pub struct ScheduledShaAir {
    preprocessed: RowMajorMatrix<Goldilocks>,
    inputs: Vec<[u32; 24]>,
    real_compressions: usize,
}

impl ScheduledShaAir {
    /// Builds preprocessing from public messages and constructs honest SHA
    /// compression inputs for the prover. The hash computations below are
    /// witness generation only; they do not test or certify claimed outputs.
    ///
    /// For a verifier that only needs preprocessing, use `public_only` so that
    /// no SHA compression is executed at all during AIR construction.
    pub fn new(plan: &ShaPlan) -> Self {
        Self::build(plan, true)
    }

    pub fn public_only(plan: &ShaPlan) -> Self {
        Self::build(plan, false)
    }

    fn build(plan: &ShaPlan, with_witness: bool) -> Self {
        let rows = plan.padded_compressions();
        let mut preprocessed = vec![Goldilocks::ZERO; rows * SCHEDULE_PREPROCESSED_WIDTH];
        let mut inputs = if with_witness {
            Vec::with_capacity(rows)
        } else {
            Vec::new()
        };
        let mut row_index = 0;
        for message in plan.messages() {
            let blocks = padded_blocks(&message.bytes).expect("plan checked message lengths");
            let mut h_in = SHA256_IV;
            for (block_index, block) in blocks.iter().enumerate() {
                let row = &mut preprocessed[row_index * SCHEDULE_PREPROCESSED_WIDTH
                    ..(row_index + 1) * SCHEDULE_PREPROCESSED_WIDTH];
                let mut input = [0u32; 24];
                for word in 0..16 {
                    input[word] =
                        u32::from_be_bytes(block[word * 4..word * 4 + 4].try_into().unwrap());
                }
                let schedule =
                    expand_schedule(input[..16].try_into().expect("16 public block words"));
                for (word, value) in schedule.into_iter().enumerate() {
                    row[2 * word] = Goldilocks::from_u16(value as u16);
                    row[2 * word + 1] = Goldilocks::from_u16((value >> 16) as u16);
                }
                row[FIRST] = Goldilocks::from_bool(block_index == 0);
                row[CHAIN] = Goldilocks::from_bool(block_index + 1 < blocks.len());
                row[OUTPUT] = Goldilocks::from_bool(block_index + 1 == blocks.len());
                if block_index + 1 == blocks.len() {
                    for word in 0..8 {
                        row[DIGEST + word] = Goldilocks::from_u32(u32::from_be_bytes(
                            message.expected_digest[word * 4..word * 4 + 4]
                                .try_into()
                                .unwrap(),
                        ));
                    }
                }
                if with_witness {
                    input[16..24].copy_from_slice(&h_in);
                    inputs.push(input);
                    // sha2 0.10's raw compression is used only to populate the
                    // witness input chaining states. The AIR constrains them.
                    let block = sha2::digest::generic_array::GenericArray::clone_from_slice(block);
                    sha2::compress256(&mut h_in, core::slice::from_ref(&block));
                }
                row_index += 1;
            }
        }
        assert_eq!(row_index, plan.real_compressions());
        for padding in row_index..rows {
            // Valid independent zero-block compressions. Padding cannot feed
            // a real hash: its chain selector is zero and its IV is fixed.
            preprocessed[padding * SCHEDULE_PREPROCESSED_WIDTH + FIRST] = Goldilocks::ONE;
            if with_witness {
                let mut input = [0u32; 24];
                input[16..24].copy_from_slice(&SHA256_IV);
                inputs.push(input);
            }
        }
        Self {
            preprocessed: RowMajorMatrix::new(preprocessed, SCHEDULE_PREPROCESSED_WIDTH),
            inputs,
            real_compressions: plan.real_compressions(),
        }
    }

    pub fn generate_trace(&self) -> RowMajorMatrix<Goldilocks> {
        assert!(
            !self.inputs.is_empty(),
            "public-only AIR cannot generate a witness"
        );
        // Do not eagerly reserve the full LDE in this constructor. The PCS
        // controls its own allocations, which must be measured separately.
        generate_scheduled_trace_rows(&self.inputs)
    }

    pub fn real_compressions(&self) -> usize {
        self.real_compressions
    }

    pub fn trace_height(&self) -> usize {
        self.preprocessed.values.len() / SCHEDULE_PREPROCESSED_WIDTH
    }
}

impl BaseAir<Goldilocks> for ScheduledShaAir {
    fn width(&self) -> usize {
        SCHEDULE_SHA_WIDTH
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Goldilocks>> {
        Some(self.preprocessed.clone())
    }

    fn preprocessed_width(&self) -> usize {
        SCHEDULE_PREPROCESSED_WIDTH
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        // h_in is the first 8 x 2 scalar columns of the repr(C) official row.
        (0..16).collect()
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        // Official compression degree 3; selector * linear boundary degree 2;
        // transition selector * chain flag * linear link degree 3.
        Some(3)
    }

    fn num_public_values(&self) -> usize {
        0
    }
}

impl<AB: AirBuilder<F = Goldilocks>> Air<AB> for ScheduledShaAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &ScheduledShaCols<AB::Var> = main.current_slice().borrow();
        let next = main.next_slice();
        let preprocessed = builder.preprocessed().current_slice().to_vec();
        eval_bit_range_checks(builder, local);
        eval_initial_state(builder, local);
        eval_compression(builder, local, &preprocessed[..128]);
        eval_finalization(builder, local);
        for word in 0..8 {
            for limb in 0..2 {
                builder.when(preprocessed[FIRST]).assert_eq(
                    local.h_in[word][limb],
                    Goldilocks::from_u16((SHA256_IV[word] >> (16 * limb)) as u16),
                );
                let output_limb = pack_bits_le::<AB::Expr, _, _>(
                    local.h_out[word][16 * limb..16 * (limb + 1)]
                        .iter()
                        .copied(),
                );
                builder
                    .when_transition()
                    .when(preprocessed[CHAIN])
                    .assert_eq(next[2 * word + limb], output_limb);
            }
            builder.when(preprocessed[OUTPUT]).assert_eq(
                pack_bits_le::<AB::Expr, _, _>(local.h_out[word].iter().copied()),
                preprocessed[DIGEST + word],
            );
        }
    }
}

fn eval_bit_range_checks<AB: AirBuilder>(builder: &mut AB, local: &ScheduledShaCols<AB::Var>) {
    // Range-check the `a` chain.
    // - Indices 0..4 cover the input state bits;
    // - Indices 4..68 cover every `new_a` produced by the compression loop.
    for word in &local.a_chain {
        builder.assert_bools(*word);
    }
    // Symmetric range check for the `e` chain.
    for word in &local.e_chain {
        builder.assert_bools(*word);
    }

    // Range-check the output chaining state.
    //
    // Invariant: nothing downstream re-derives `h_out`.
    // These booleans are the only thing bounding its two limbs by `2^16`.
    for word in &local.h_out {
        builder.assert_bools(*word);
    }
}

/// Assert that each packed `H[i]` agrees with the matching chain entry.
///
/// Layout mirrored from the columns module:
///
/// ```text
///     H_0 <-> a_chain[3]   H_4 <-> e_chain[3]
///     H_1 <-> a_chain[2]   H_5 <-> e_chain[2]
///     H_2 <-> a_chain[1]   H_6 <-> e_chain[1]
///     H_3 <-> a_chain[0]   H_7 <-> e_chain[0]
/// ```
fn eval_initial_state<AB: AirBuilder>(builder: &mut AB, local: &ScheduledShaCols<AB::Var>) {
    // Words H_0..H_3 live in the reversed prefix of the `a` chain.
    for i in 0..4 {
        // The chain stores (d, c, b, a) at indices (0, 1, 2, 3), so invert.
        let chain_idx = 3 - i;
        let bits = &local.a_chain[chain_idx];
        assert_packed_equals_bits::<AB>(builder, &local.h_in[i], bits);
    }
    // Words H_4..H_7 live in the reversed prefix of the `e` chain.
    for i in 0..4 {
        let chain_idx = 3 - i;
        let bits = &local.e_chain[chain_idx];
        assert_packed_equals_bits::<AB>(builder, &local.h_in[4 + i], bits);
    }
}

fn eval_compression<AB: AirBuilder>(
    builder: &mut AB,
    local: &ScheduledShaCols<AB::Var>,
    schedule: &[AB::Var],
) {
    for (t, round) in local.rounds.iter().enumerate() {
        // Read the eight working variables for round `t` from the chains.
        //
        //     chain[t + 3]  -->  slot a (or e)
        //     chain[t + 2]  -->  slot b (or f)
        //     chain[t + 1]  -->  slot c (or g)
        //     chain[t + 0]  -->  slot d (or h)
        let a_bits = &local.a_chain[t + 3];
        let b_bits = &local.a_chain[t + 2];
        let c_bits = &local.a_chain[t + 1];
        let d_bits = &local.a_chain[t];
        let e_bits = &local.e_chain[t + 3];
        let f_bits = &local.e_chain[t + 2];
        let g_bits = &local.e_chain[t + 1];
        let h_bits = &local.e_chain[t];

        // big_sigma1 check: reduces to a per-bit XOR3 of rotated `e` bits.
        assert_sigma_matches::<AB>(builder, e_bits, [6, 11, 25], &round.sigma1_e);

        // Ch check: disjoint AND-terms collapse the XOR to an addition.
        //
        //     Ch_i = e_i * f_i + (1 - e_i) * g_i
        assert_ch_matches::<AB>(builder, e_bits, f_bits, g_bits, &round.ch);

        // Three-term add: tmp1 = big_sigma1 + ch + h.
        let ch_expr: [AB::Expr; U32_LIMBS] = round.ch.map(Into::into);
        let h_packed_expr = pack_word::<AB>(h_bits);
        add3(
            builder,
            &round.tmp1,
            &round.sigma1_e,
            &ch_expr,
            &h_packed_expr,
        );

        // Inject K[t] as a constant expression, one 16-bit limb at a time.
        let k_expr: [AB::Expr; U32_LIMBS] = [
            // Low 16 bits of K[t].
            AB::Expr::from_u32(SHA256_K[t] & 0xFFFF),
            // High 16 bits of K[t].
            AB::Expr::from_u32(SHA256_K[t] >> BITS_PER_LIMB),
        ];
        // Three-term add: T1 = tmp1 + K[t] + W[t].
        let w_packed_expr: [AB::Expr; U32_LIMBS] =
            [schedule[2 * t].into(), schedule[2 * t + 1].into()];
        add3(builder, &round.t1, &round.tmp1, &k_expr, &w_packed_expr);

        // big_sigma0 check: per-bit XOR3 of rotated `a` bits.
        assert_sigma_matches::<AB>(builder, a_bits, [2, 13, 22], &round.sigma0_a);

        // Maj check: degree-3 identity `a * b + c * (a XOR b)`.
        assert_maj_matches::<AB>(builder, a_bits, b_bits, c_bits, &round.maj);

        // Three-term add straight into the next `a`-chain slot.
        //
        //     pack(a_chain[t + 4]) = T_1 + big_sigma_0 + maj
        //
        // Fuses the spec's two-step update into one add (see the header doc).
        // Output limbs are in `[0, 2^16)` because the chain slot is already
        // boolean-checked.
        let new_a_packed_expr = pack_word::<AB>(&local.a_chain[t + 4]);
        let sigma0_a_expr: [AB::Expr; U32_LIMBS] = round.sigma0_a.map(Into::into);
        let maj_expr: [AB::Expr; U32_LIMBS] = round.maj.map(Into::into);
        add3_expr_out(
            builder,
            &new_a_packed_expr,
            &round.t1,
            &sigma0_a_expr,
            &maj_expr,
        );

        // Two-term add directly into the next `e`-chain slot:
        //     pack(e_chain[t + 4]) = d + T1.
        let new_e_packed_expr = pack_word::<AB>(&local.e_chain[t + 4]);
        let d_packed_expr = pack_word::<AB>(d_bits);
        add2_expr_out(builder, &new_e_packed_expr, &round.t1, &d_packed_expr);
    }
}

/// Enforce `H_out[i] = H_in[i] + final_state[i] (mod 2^32)`.
///
/// The final working variables sit at the tail of the two chains:
///
/// ```text
///     final a = a_chain[67]    final e = e_chain[67]
///     final b = a_chain[66]    final f = e_chain[66]
///     final c = a_chain[65]    final g = e_chain[65]
///     final d = a_chain[64]    final h = e_chain[64]
/// ```
///
/// # Soundness
///
/// The add helpers pin exactly two facts about their output word:
///
/// ```text
///     acc    = out    - in_0    - in_1       in {0, -2^32}
///     acc_16 = out[0] - in_0[0] - in_1[0]    in {0, -2^16}
/// ```
///
/// Neither rules out moving `2^16` from the low limb into the high one:
///
/// ```text
///     out[0] -= 2^16   ->   acc_16 shifts by -2^16
///     out[1] += 1      ->   acc    unchanged
/// ```
///
/// Both checks still hold whenever the honest low-limb carry is `0`.
///
/// So the helper alone admits two limb decompositions per output word.
///
/// One of them puts a limb outside `[0, 2^16)`.
///
/// For an intermediate such as `t1` the alias is harmless:
///
/// - Its consumer's output is repacked from boolean-checked bits.
/// - That consumer's `acc_16` check pins its own low limb modulo `2^16`.
/// - The alias shifts by a multiple of `2^16`, so it cancels there.
///
/// `h_out` has no consumer.
///
/// Committing it as bits makes both limbs 16-bit by construction.
fn eval_finalization<AB: AirBuilder>(builder: &mut AB, local: &ScheduledShaCols<AB::Var>) {
    // H'_0..H'_3 are obtained by adding H[i] and the tail of the `a` chain.
    for i in 0..4 {
        let final_bits = &local.a_chain[CHAIN_LEN - 1 - i];
        let packed_expr = pack_word::<AB>(final_bits);
        let h_out_expr = pack_word::<AB>(&local.h_out[i]);
        add2_expr_out(builder, &h_out_expr, &local.h_in[i], &packed_expr);
    }
    // H'_4..H'_7 are obtained by adding H[i] and the tail of the `e` chain.
    for i in 0..4 {
        let final_bits = &local.e_chain[CHAIN_LEN - 1 - i];
        let packed_expr = pack_word::<AB>(final_bits);
        let h_out_expr = pack_word::<AB>(&local.h_out[4 + i]);
        add2_expr_out(builder, &h_out_expr, &local.h_in[4 + i], &packed_expr);
    }
}

/// Pack a 32-bit word of boolean-valued columns into a 2-limb expression.
///
/// # Arguments
///
/// - `bits`: 32 boolean columns in little-endian order.
///
/// # Returns
///
/// A two-element array `[lo_expr, hi_expr]` where:
/// - `lo_expr` equals `sum_{i=0}^{15} 2^i * bits[i]`.
/// - `hi_expr` equals `sum_{i=0}^{15} 2^i * bits[16 + i]`.
#[inline]
fn pack_word<AB: AirBuilder>(bits: &[AB::Var; WORD_BITS]) -> [AB::Expr; U32_LIMBS] {
    [
        // Low limb: bits 0..16.
        pack_bits_le::<AB::Expr, _, _>(bits[..BITS_PER_LIMB].iter().copied()),
        // High limb: bits 16..32.
        pack_bits_le::<AB::Expr, _, _>(bits[BITS_PER_LIMB..].iter().copied()),
    ]
}

/// Assert `packed` equals the packing of `bits`.
///
/// Bridges the packed and unpacked views of a single 32-bit word.
#[inline]
fn assert_packed_equals_bits<AB: AirBuilder>(
    builder: &mut AB,
    packed: &[AB::Var; U32_LIMBS],
    bits: &[AB::Var; WORD_BITS],
) {
    // Re-derive the packed expression from the bits.
    let [lo, hi] = pack_word::<AB>(bits);
    // Emit one equality per limb.
    builder.assert_zeros([packed[0].into() - lo, packed[1].into() - hi]);
}

/// Wrapper around `p3_air::utils::add3`.
#[inline]
fn add3<AB: AirBuilder>(
    builder: &mut AB,
    a: &[AB::Var; U32_LIMBS],
    b: &[AB::Var; U32_LIMBS],
    c: &[AB::Expr; U32_LIMBS],
    d: &[AB::Expr; U32_LIMBS],
) {
    p3_air::utils::add3(builder, a, b, c, d);
}

/// Variant of `add2` where the output `a` is supplied as an expression.
///
/// # Soundness
///
/// The upstream `add2` proof needs every limb in `[0, 2^16)`.
///
/// - `b`, `c`: inherited from their callers.
/// - `a`: a sum of 16 boolean bits × `2^i`, so each limb is in `[0, 2^16)` by construction.
///
/// # Arguments
///
/// - `a`: output as a 2-limb expression.
/// - `b`: committed addend.
/// - `c`: addend expression.
///
/// # Constraint degree
///
/// Two degree-2 constraints.
#[inline]
fn add2_expr_out<AB: AirBuilder>(
    builder: &mut AB,
    a: &[AB::Expr; U32_LIMBS],
    b: &[AB::Var; U32_LIMBS],
    c: &[AB::Expr; U32_LIMBS],
) {
    // Materialize 2^16 and 2^32 as field constants.
    let two_16 = <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield::from_canonical_checked(
        1 << BITS_PER_LIMB,
    )
    .expect("characteristic must exceed 2^17");
    let two_32 = two_16.square();

    // 16-bit accumulator: difference of the low limbs.
    let acc_16 = a[0].dup() - b[0] - c[0].dup();
    // 32-bit accumulator: build up from the 16-bit limb plus the high limb
    // shifted by 2^16.
    let acc_32 = a[1].dup() - b[1] - c[1].dup();
    let acc = acc_16.dup() + acc_32.mul_2exp_u64(BITS_PER_LIMB as u64);

    builder.assert_zeros([
        // 32-bit overflow check: forces acc ∈ {0, -2^32} mod P.
        acc.dup() * (acc + AB::Expr::from_prime_subfield(two_32)),
        // 16-bit overflow check: forces acc_16 ∈ {0, -2^16} mod P.
        acc_16.dup() * (acc_16 + AB::Expr::from_prime_subfield(two_16)),
    ]);
}

/// Variant of `add3` where the output `a` is supplied as an expression.
///
/// # Soundness
///
/// Same argument as the two-addend variant: `a`'s limbs are in `[0, 2^16)`
/// whenever it is built from boolean-checked bits.
///
/// # Constraint degree
///
/// Two degree-3 constraints.
#[inline]
fn add3_expr_out<AB: AirBuilder>(
    builder: &mut AB,
    a: &[AB::Expr; U32_LIMBS],
    b: &[AB::Var; U32_LIMBS],
    c: &[AB::Expr; U32_LIMBS],
    d: &[AB::Expr; U32_LIMBS],
) {
    // Materialize 2^16 and 2^32.
    let two_16 = <AB::Expr as PrimeCharacteristicRing>::PrimeSubfield::from_canonical_checked(
        1 << BITS_PER_LIMB,
    )
    .expect("characteristic must exceed 3 * 2^16");
    let two_32 = two_16.square();

    // 16-bit accumulator with four addends.
    let acc_16 = a[0].dup() - b[0] - c[0].dup() - d[0].dup();
    let acc_32 = a[1].dup() - b[1] - c[1].dup() - d[1].dup();
    let acc = acc_16.dup() + acc_32.mul_2exp_u64(BITS_PER_LIMB as u64);

    builder.assert_zeros([
        // Cubic check at the 32-bit level: forces acc ∈ {0, -2^32, -2*2^32}.
        acc.dup()
            * (acc.dup() + AB::Expr::from_prime_subfield(two_32))
            * (acc + AB::Expr::from_prime_subfield(two_32.double())),
        // Cubic check at the 16-bit limb level.
        acc_16.dup()
            * (acc_16.dup() + AB::Expr::from_prime_subfield(two_16))
            * (acc_16 + AB::Expr::from_prime_subfield(two_16.double())),
    ]);
}

/// Packed XOR3 of rotated, already Boolean-constrained state bits.
fn assert_sigma_matches<AB: AirBuilder>(
    builder: &mut AB,
    bits: &[AB::Var; WORD_BITS],
    rotations: [usize; 3],
    packed: &[AB::Var; U32_LIMBS],
) {
    let mut built = [AB::Expr::ZERO, AB::Expr::ZERO];
    for (limb, slot) in built.iter_mut().enumerate() {
        let mut acc = AB::Expr::ZERO;
        for i in (16 * limb..16 * (limb + 1)).rev() {
            let x: AB::Expr = bits[(i + rotations[0]) % 32].into();
            let y: AB::Expr = bits[(i + rotations[1]) % 32].into();
            let z: AB::Expr = bits[(i + rotations[2]) % 32].into();
            acc = acc.double() + x.xor3(&y, &z);
        }
        *slot = acc;
    }
    let [lo, hi] = built;
    builder.assert_zeros([packed[0].into() - lo, packed[1].into() - hi]);
}

/// Assert `packed` equals `Ch(e, f, g)` in packed form.
///
/// # Algorithm
///
/// The two AND-terms are disjoint on boolean inputs, so the XOR collapses to
/// an addition:
///
/// ```text
///     Ch_i = e_i * f_i + (1 - e_i) * g_i
/// ```
///
/// That bit expression has degree 2, so the packed constraint has degree 2.
fn assert_ch_matches<AB: AirBuilder>(
    builder: &mut AB,
    e: &[AB::Var; WORD_BITS],
    f: &[AB::Var; WORD_BITS],
    g: &[AB::Var; WORD_BITS],
    packed: &[AB::Var; U32_LIMBS],
) {
    let mut built: [AB::Expr; U32_LIMBS] = [AB::Expr::ZERO, AB::Expr::ZERO];
    for (limb, slot) in built.iter_mut().enumerate() {
        let lo = limb * BITS_PER_LIMB;
        let hi = lo + BITS_PER_LIMB;
        let mut acc = AB::Expr::ZERO;
        // Horner, high to low bit.
        for i in (lo..hi).rev() {
            // Pull the three operand bits into expressions.
            let ei: AB::Expr = e[i].into();
            let fi: AB::Expr = f[i].into();
            let gi: AB::Expr = g[i].into();
            // Degree-2 bit identity equivalent to (e AND f) XOR (NOT e AND g).
            let ch_i = ei.dup() * fi + (AB::Expr::ONE - ei) * gi;
            // Horner step.
            acc = acc.double() + ch_i;
        }
        *slot = acc;
    }

    let [built_lo, built_hi] = built;
    builder.assert_zeros([packed[0].into() - built_lo, packed[1].into() - built_hi]);
}

/// Assert `packed` equals `Maj(a, b, c)` in packed form.
///
/// # Algorithm
///
/// The boolean majority of three inputs satisfies:
///
/// ```text
///     Maj_i = a_i * b_i + c_i * (a_i XOR b_i)
///           = a_i * b_i + c_i * (a_i + b_i - 2 * a_i * b_i)
/// ```
///
/// That expression has degree 3 per bit.
fn assert_maj_matches<AB: AirBuilder>(
    builder: &mut AB,
    a: &[AB::Var; WORD_BITS],
    b: &[AB::Var; WORD_BITS],
    c: &[AB::Var; WORD_BITS],
    packed: &[AB::Var; U32_LIMBS],
) {
    let mut built: [AB::Expr; U32_LIMBS] = [AB::Expr::ZERO, AB::Expr::ZERO];
    for (limb, slot) in built.iter_mut().enumerate() {
        let lo = limb * BITS_PER_LIMB;
        let hi = lo + BITS_PER_LIMB;
        let mut acc = AB::Expr::ZERO;
        // Horner, high to low bit.
        for i in (lo..hi).rev() {
            // Pull the three operand bits into expressions.
            let ai: AB::Expr = a[i].into();
            let bi: AB::Expr = b[i].into();
            let ci: AB::Expr = c[i].into();
            // Degree-3 identity: `a*b + c * xor(a, b)` matches the bitwise
            // majority on boolean inputs.
            let maj_i = ai.dup() * bi.dup() + ci * ai.xor(&bi);
            // Horner step.
            acc = acc.double() + maj_i;
        }
        *slot = acc;
    }

    let [built_lo, built_hi] = built;
    builder.assert_zeros([packed[0].into() - built_lo, packed[1].into() - built_hi]);
}

fn generate_scheduled_trace_rows<F: PrimeField64>(inputs: &[[u32; 24]]) -> RowMajorMatrix<F> {
    assert!(inputs.len().is_power_of_two());
    let mut values = F::zero_vec(inputs.len() * SCHEDULE_SHA_WIDTH);
    values
        .par_chunks_exact_mut(SCHEDULE_SHA_WIDTH)
        .zip(inputs.par_iter())
        .for_each(|(row, input)| {
            generate_scheduled_trace_row(row.borrow_mut(), *input);
        });
    RowMajorMatrix::new(values, SCHEDULE_SHA_WIDTH)
}

fn generate_scheduled_trace_row<F: PrimeField64>(row: &mut ScheduledShaCols<F>, input: [u32; 24]) {
    // Step 1: unpack the input into a block and a chaining state.
    let block: [u32; BLOCK_WORDS] = core::array::from_fn(|i| input[i]);
    let h_in: [u32; STATE_WORDS] = core::array::from_fn(|i| input[BLOCK_WORDS + i]);

    // Commit the input chaining state in packed form - one entry per H word.
    row.h_in = h_in.map(|h| u32_to_limbs(h).map(F::from_u16));

    let w_words = expand_schedule(block);

    // Step 3: compression loop.
    //
    // Chain prefix: indices 0..4 hold (d, c, b, a) of the initial state -
    // that is H[3..=0] for the `a` chain and H[7..=4] for the `e` chain.
    row.a_chain[0] = u32_to_bits_le(h_in[3]);
    row.a_chain[1] = u32_to_bits_le(h_in[2]);
    row.a_chain[2] = u32_to_bits_le(h_in[1]);
    row.a_chain[3] = u32_to_bits_le(h_in[0]);
    row.e_chain[0] = u32_to_bits_le(h_in[7]);
    row.e_chain[1] = u32_to_bits_le(h_in[6]);
    row.e_chain[2] = u32_to_bits_le(h_in[5]);
    row.e_chain[3] = u32_to_bits_le(h_in[4]);

    // Working variables, initialised from the input state in canonical
    // SHA-256 order.
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = h_in;

    for t in 0..NUM_COMPRESSION_ROUNDS {
        let round: &mut Sha256RoundCols<F> = &mut row.rounds[t];

        // big_sigma1(e) = ROTR_6(e) XOR ROTR_11(e) XOR ROTR_25(e).
        let sigma1_e = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);

        // Ch(e, f, g) = (e AND f) XOR (NOT e AND g).
        let ch = (e & f) ^ ((!e) & g);

        // Partial sum: tmp1 = h + big_sigma1 + Ch.
        let tmp1 = h.wrapping_add(sigma1_e).wrapping_add(ch);

        // T1 = tmp1 + K[t] + W[t].
        let t1 = tmp1.wrapping_add(SHA256_K[t]).wrapping_add(w_words[t]);

        // big_sigma0(a) = ROTR_2(a) XOR ROTR_13(a) XOR ROTR_22(a).
        let sigma0_a = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);

        // Maj(a, b, c) = (a AND b) XOR (a AND c) XOR (b AND c).
        let maj = (a & b) ^ (a & c) ^ (b & c);

        // Shifted slots for the next round.
        //
        // Mirrors the fused AIR add: `new_a = T_1 + big_sigma_0 + maj`
        // replaces the spec's two-step `T_2 = big_sigma_0 + maj; new_a = T_1 + T_2`.
        let new_a = t1.wrapping_add(sigma0_a).wrapping_add(maj);
        let new_e = d.wrapping_add(t1);

        // Commit every packed intermediate for this round.
        //
        // `new_a` / `new_e`: bit form only — written into the next chain
        // slot below. The AIR re-packs from those bits on demand.
        round.sigma1_e = u32_to_limbs(sigma1_e).map(F::from_u16);
        round.ch = u32_to_limbs(ch).map(F::from_u16);
        round.tmp1 = u32_to_limbs(tmp1).map(F::from_u16);
        round.t1 = u32_to_limbs(t1).map(F::from_u16);
        round.sigma0_a = u32_to_limbs(sigma0_a).map(F::from_u16);
        round.maj = u32_to_limbs(maj).map(F::from_u16);

        // Extend the chains so the next round can read the shifted variables
        // directly.
        row.a_chain[t + 4] = u32_to_bits_le(new_a);
        row.e_chain[t + 4] = u32_to_bits_le(new_e);

        // Apply the SHA-256 working-variable shift.
        h = g;
        g = f;
        f = e;
        e = new_e;
        d = c;
        c = b;
        b = a;
        a = new_a;
    }
    // Sanity check: the chain length matches the expected extent.
    debug_assert_eq!(CHAIN_LEN, 4 + NUM_COMPRESSION_ROUNDS);

    // Step 4: finalization.
    //
    // After the loop the working variables line up with the tail of the two
    // chains:
    //     (a, b, c, d) = (a_chain[67], a_chain[66], a_chain[65], a_chain[64])
    //     (e, f, g, h) = (e_chain[67], e_chain[66], e_chain[65], e_chain[64])
    let final_state: [u32; STATE_WORDS] = [a, b, c, d, e, f, g, h];
    for i in 0..STATE_WORDS {
        // Output word i = H[i] + final_state[i] (mod 2^32).
        //
        // Bit form: the AIR repacks it for the addition check.
        // The bits are what bound the two 16-bit limbs.
        let h_out_word = h_in[i].wrapping_add(final_state[i]);
        row.h_out[i] = u32_to_bits_le(h_out_word);
    }
}

#[cfg(test)]
mod tests {
    use p3_air::check_constraints;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::sha_plan::HashMessage;

    fn plan() -> ShaPlan {
        let messages = [b"abc".to_vec(), (0..120).collect::<Vec<u8>>()]
            .into_iter()
            .enumerate()
            .map(|(i, bytes)| HashMessage {
                name: format!("case-{i}"),
                expected_digest: Sha256::digest(&bytes).into(),
                bytes,
            })
            .collect();
        ShaPlan::for_public_messages(messages).unwrap()
    }

    fn rejects(air: &ScheduledShaAir, trace: &RowMajorMatrix<Goldilocks>) {
        assert!(std::panic::catch_unwind(|| check_constraints(air, trace, &[])).is_err());
    }

    fn compress(input: [u32; 24]) -> [u32; 8] {
        let mut state: [u32; 8] = input[16..24].try_into().unwrap();
        let mut bytes = [0u8; 64];
        for i in 0..16 {
            bytes[4 * i..4 * i + 4].copy_from_slice(&input[i].to_be_bytes());
        }
        let block = sha2::digest::generic_array::GenericArray::clone_from_slice(&bytes);
        sha2::compress256(&mut state, core::slice::from_ref(&block));
        state
    }

    fn change_claimed_output(air: &mut ScheduledShaAir, row: usize, output: [u32; 8]) {
        for (word, value) in output.into_iter().enumerate() {
            air.preprocessed.values[row * SCHEDULE_PREPROCESSED_WIDTH + DIGEST + word] =
                Goldilocks::from_u32(value);
        }
    }

    #[test]
    fn honest_complete_messages_and_hash_free_public_construction() {
        let plan = plan();
        let air = ScheduledShaAir::new(&plan);
        let public = ScheduledShaAir::public_only(&plan);
        assert_eq!(air.preprocessed.values, public.preprocessed.values);
        assert_eq!(air.trace_height(), 4);
        assert_eq!(air.real_compressions(), 4);
        assert!(public.inputs.is_empty());
        check_constraints(&air, &air.generate_trace(), &[]);
    }

    #[test]
    fn changed_public_digest_rejects_valid_compressions() {
        let plan = plan();
        let trace = ScheduledShaAir::new(&plan).generate_trace();
        let mut messages = plan.messages().to_vec();
        messages[1].expected_digest[31] ^= 1;
        let changed = ShaPlan::for_public_messages(messages).unwrap();
        rejects(&ScheduledShaAir::public_only(&changed), &trace);
    }

    #[test]
    fn changed_public_message_rejects_valid_compressions() {
        let plan = plan();
        let trace = ScheduledShaAir::new(&plan).generate_trace();
        let mut messages = plan.messages().to_vec();
        messages[1].bytes[119] ^= 1;
        let changed = ShaPlan::for_public_messages(messages).unwrap();
        rejects(&ScheduledShaAir::public_only(&changed), &trace);
    }

    #[test]
    fn recomputed_compressions_with_broken_chain_reject() {
        let mut air = ScheduledShaAir::new(&plan());
        // Keep every row an individually valid compression, but make the
        // third row use a state unrelated to its previous compression. Update
        // all later rows and the claimed final digest, so the ONLY broken
        // condition is the wrapper's link from row 1 to row 2.
        air.inputs[2][16] ^= 1;
        let state = compress(air.inputs[2]);
        air.inputs[3][16..24].copy_from_slice(&state);
        let output = compress(air.inputs[3]);
        change_claimed_output(&mut air, 3, output);
        let trace = air.generate_trace();
        check_constraints(
            &p3_sha256_air::Sha256Air,
            &p3_sha256_air::generate_trace_rows::<Goldilocks>(air.inputs.clone(), 0),
            &[],
        );
        rejects(&air, &trace);
    }

    #[test]
    fn recomputed_compressions_with_wrong_iv_reject() {
        let mut air = ScheduledShaAir::new(&plan());
        air.inputs[0][16] ^= 1;
        let output = compress(air.inputs[0]);
        change_claimed_output(&mut air, 0, output);
        let trace = air.generate_trace();
        check_constraints(
            &p3_sha256_air::Sha256Air,
            &p3_sha256_air::generate_trace_rows::<Goldilocks>(air.inputs.clone(), 0),
            &[],
        );
        rejects(&air, &trace);
    }

    #[test]
    fn recomputed_compression_with_wrong_padding_rejects() {
        let mut air = ScheduledShaAir::new(&plan());
        // Change the SHA bit-length word and its final digest together. Every
        // compression remains valid; canonical message padding must reject.
        air.inputs[0][15] ^= 1;
        let output = compress(air.inputs[0]);
        change_claimed_output(&mut air, 0, output);
        let trace = air.generate_trace();
        check_constraints(
            &p3_sha256_air::Sha256Air,
            &p3_sha256_air::generate_trace_rows::<Goldilocks>(air.inputs.clone(), 0),
            &[],
        );
        rejects(&air, &trace);
    }

    #[test]
    fn changed_compression_bit_rejects() {
        let air = ScheduledShaAir::new(&plan());
        let mut trace = air.generate_trace();
        trace.values[20] += Goldilocks::ONE;
        rejects(&air, &trace);
    }

    #[test]
    fn every_retained_column_matches_official_trace_projection() {
        use p3_matrix::Matrix;
        let air = ScheduledShaAir::new(&plan());
        let trace = air.generate_trace();
        let official = p3_sha256_air::generate_trace_rows::<Goldilocks>(air.inputs.clone(), 0);
        for row_index in 0..trace.height() {
            let old_row = official.row_slice(row_index).unwrap();
            let official_row: &p3_sha256_air::Sha256Cols<Goldilocks> = old_row.as_ref().borrow();
            let mut projected = Vec::with_capacity(SCHEDULE_SHA_WIDTH);
            projected.extend(official_row.h_in.into_iter().flatten());
            projected.extend(official_row.a_chain.into_iter().flatten());
            projected.extend(official_row.e_chain.into_iter().flatten());
            for round in &official_row.rounds {
                for pair in [
                    round.sigma1_e,
                    round.ch,
                    round.tmp1,
                    round.t1,
                    round.sigma0_a,
                    round.maj,
                ] {
                    projected.extend(pair);
                }
            }
            projected.extend(official_row.h_out.into_iter().flatten());
            assert_eq!(
                projected.as_slice(),
                trace.row_slice(row_index).unwrap().as_ref()
            );
            let schedule = expand_schedule(air.inputs[row_index][..16].try_into().unwrap());
            for (t, word) in schedule.into_iter().enumerate() {
                let expected = u32_to_bits_le::<Goldilocks>(word);
                assert_eq!(official_row.w[t], expected);
            }
        }
    }

    #[test]
    fn changed_preprocessed_schedule_limb_rejects() {
        let mut air = ScheduledShaAir::new(&plan());
        let trace = air.generate_trace();
        air.preprocessed.values[2 * 63 + 1] += Goldilocks::ONE;
        rejects(&air, &trace);
    }

    #[test]
    fn first_last_round_and_nonboolean_mutations_reject() {
        let air = ScheduledShaAir::new(&plan());
        for index in [
            16usize,
            16 + 68 * 32,
            16 + 2 * 68 * 32,
            SCHEDULE_SHA_WIDTH - 1,
        ] {
            let mut trace = air.generate_trace();
            trace.values[index] += Goldilocks::from_u32(2);
            rejects(&air, &trace);
        }
    }
}
