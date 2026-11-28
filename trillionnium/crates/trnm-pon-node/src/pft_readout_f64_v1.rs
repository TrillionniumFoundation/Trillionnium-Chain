//! Bounded typed PFT preparation, separate from int257, TMT1 and native adoption.
//! Digest labels and caller-supplied comparison bytes do not authenticate sources.
//! The execution owner must separately verify SHA pins, authorization and budgets.
//! Arithmetic assumes ordinary IEEE binary64 RN multiplication, without fast-math.

use std::cmp::Ordering;
use std::sync::Arc;

pub const MODEL_SCHEMA: &str = "trnm.pft.typed-f64-readout.v1";
pub const INPUT_SCHEMA: &str = "trnm.pft.typed-f64-input.v1";
pub const FAMILY: &str = "hcsn-pft-readout-research-v1";
pub const PROFILE: &str = "trnm.pft.binary64-rounded-products-exact-sum-rne.v1";
const LIMBS: usize = 33; // 2112 bits > 2098 product bits + log2(1024) terms.
const FRACTION: u64 = (1_u64 << 52) - 1;
type Magnitude = [u64; LIMBS];
type Result<T> = std::result::Result<T, PftErrorV1>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PftErrorV1 {
    Contract,
    Shape,
    InputConsistency,
    NumericInput,
    ProductOverflow,
    ProductUnderflow,
    SumOverflow,
    SumUnderflow,
    Capacity,
}

/// Comparison labels only. Callers controlling expected and actual can forge both.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PftModelDescriptorV1 {
    pub schema: String,
    pub family: String,
    pub numeric_profile: String,
    pub candidate_sha256: [u8; 32],
    pub contract_sha256: [u8; 32],
    pub head: [u8; 32],
    pub weight_sha256: [u8; 32],
    pub feature_program_sha256: [u8; 32],
    pub normalization_sha256: [u8; 32],
    pub time_semantics_sha256: [u8; 32],
    pub dimension: u32,
    pub outputs: u32,
}

impl PftModelDescriptorV1 {
    fn validate(&self) -> Result<()> {
        if self.schema != MODEL_SCHEMA
            || self.family != FAMILY
            || self.numeric_profile != PROFILE
            || [
                self.candidate_sha256,
                self.contract_sha256,
                self.head,
                self.weight_sha256,
                self.feature_program_sha256,
                self.normalization_sha256,
                self.time_semantics_sha256,
            ]
            .contains(&[0; 32])
        {
            return Err(PftErrorV1::Contract);
        }
        if !(1..=1024).contains(&self.dimension) || !(1..=32).contains(&self.outputs) {
            return Err(PftErrorV1::Shape);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PftInputDescriptorV1 {
    pub schema: String,
    pub candidate_sha256: [u8; 32],
    pub weight_sha256: [u8; 32],
    pub contract_sha256: [u8; 32],
    pub feature_program_sha256: [u8; 32],
    pub normalization_sha256: [u8; 32],
    pub time_semantics_sha256: [u8; 32],
    pub request_id: [u8; 32],
    pub source_sha256: [u8; 32],
    pub row_ids_sha256: [u8; 32],
    pub feature_packet_sha256: [u8; 32],
    pub rows: u32,
    pub dimension: u32,
}

impl PftInputDescriptorV1 {
    fn validate(&self, model: &PftModelDescriptorV1) -> Result<()> {
        if self.schema != INPUT_SCHEMA
            || self.candidate_sha256 != model.candidate_sha256
            || self.weight_sha256 != model.weight_sha256
            || self.contract_sha256 != model.contract_sha256
            || self.feature_program_sha256 != model.feature_program_sha256
            || self.normalization_sha256 != model.normalization_sha256
            || self.time_semantics_sha256 != model.time_semantics_sha256
            || [
                self.request_id,
                self.source_sha256,
                self.row_ids_sha256,
                self.feature_packet_sha256,
            ]
            .contains(&[0; 32])
        {
            return Err(PftErrorV1::Contract);
        }
        if !(1..=256).contains(&self.rows) || self.dimension != model.dimension {
            return Err(PftErrorV1::Shape);
        }
        Ok(())
    }
}

pub struct PreparedPftReadoutV1 {
    descriptor: PftModelDescriptorV1,
    weights: Arc<[f64]>,
}

pub struct PreparedPftInputV1 {
    model: PftModelDescriptorV1,
    weights: Arc<[f64]>,
    descriptor: PftInputDescriptorV1,
    features: Vec<f64>,
}

pub struct PftPredictionV1 {
    rows: u32,
    outputs: u32,
    values: Vec<f64>,
}

impl PftPredictionV1 {
    pub fn shape(&self) -> [u32; 2] {
        [self.rows, self.outputs]
    }

    pub fn values(&self) -> &[f64] {
        &self.values
    }

    pub fn to_le_bytes(&self) -> Vec<u8> {
        self.values
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect()
    }
}

impl PreparedPftReadoutV1 {
    pub fn prepare(
        actual: &PftModelDescriptorV1,
        bytes: &[u8],
        expected: &PftModelDescriptorV1,
        expected_bytes: &[u8],
    ) -> Result<Self> {
        actual.validate()?;
        expected.validate()?;
        if actual != expected {
            return Err(PftErrorV1::InputConsistency);
        }
        let weights = consistent_values(
            bytes,
            expected_bytes,
            actual.dimension as usize * actual.outputs as usize,
        )?;
        Ok(Self {
            descriptor: actual.clone(),
            weights: weights.into(),
        })
    }

    pub fn descriptor(&self) -> &PftModelDescriptorV1 {
        &self.descriptor
    }

    pub fn prepare_input(
        &self,
        actual: &PftInputDescriptorV1,
        bytes: &[u8],
        expected: &PftInputDescriptorV1,
        expected_bytes: &[u8],
    ) -> Result<PreparedPftInputV1> {
        actual.validate(&self.descriptor)?;
        expected.validate(&self.descriptor)?;
        if actual != expected {
            return Err(PftErrorV1::InputConsistency);
        }
        let features = consistent_values(
            bytes,
            expected_bytes,
            actual.rows as usize * actual.dimension as usize,
        )?;
        Ok(PreparedPftInputV1 {
            model: self.descriptor.clone(),
            weights: Arc::clone(&self.weights),
            descriptor: actual.clone(),
            features,
        })
    }

    /// Pure bounded readout. This does not select a model, authorize use or act.
    pub fn predict(&self, input: &PreparedPftInputV1) -> Result<PftPredictionV1> {
        if input.model != self.descriptor || !Arc::ptr_eq(&input.weights, &self.weights) {
            return Err(PftErrorV1::InputConsistency);
        }
        let d = self.descriptor.dimension as usize;
        let m = self.descriptor.outputs as usize;
        let rows = input.descriptor.rows as usize;
        let mut values = Vec::with_capacity(rows * m);
        for row in 0..rows {
            for col in 0..m {
                let mut positive = [0; LIMBS];
                let mut negative = [0; LIMBS];
                for k in 0..d {
                    let a = input.features[row * d + k];
                    let b = self.weights[k * m + col];
                    // No floating add exists to contract with this multiplication.
                    let product = a * b;
                    if !product.is_finite() {
                        return Err(PftErrorV1::ProductOverflow);
                    }
                    if a != 0.0 && b != 0.0 && (product == 0.0 || !product.is_normal()) {
                        return Err(PftErrorV1::ProductUnderflow);
                    }
                    if product != 0.0 {
                        let target = if product.is_sign_negative() {
                            &mut negative
                        } else {
                            &mut positive
                        };
                        accumulate(target, product.to_bits())?;
                    }
                }
                values.push(rounded_difference(positive, negative)?);
            }
        }
        Ok(PftPredictionV1 {
            rows: input.descriptor.rows,
            outputs: self.descriptor.outputs,
            values,
        })
    }
}

fn consistent_values(bytes: &[u8], expected: &[u8], elements: usize) -> Result<Vec<f64>> {
    if bytes.len() != elements * 8 || expected.len() != elements * 8 {
        return Err(PftErrorV1::Shape);
    }
    if bytes != expected {
        return Err(PftErrorV1::InputConsistency);
    }
    bytes
        .chunks_exact(8)
        .map(|chunk| {
            let mut raw = [0; 8];
            raw.copy_from_slice(chunk);
            let value = f64::from_le_bytes(raw);
            if !value.is_finite() || (value != 0.0 && !value.is_normal()) {
                return Err(PftErrorV1::NumericInput);
            }
            Ok(value)
        })
        .collect()
}

fn add_word(magnitude: &mut Magnitude, mut index: usize, mut word: u64) -> Result<()> {
    while word != 0 {
        let slot = magnitude.get_mut(index).ok_or(PftErrorV1::Capacity)?;
        let (sum, carry) = slot.overflowing_add(word);
        *slot = sum;
        word = u64::from(carry);
        index += 1;
    }
    Ok(())
}

fn accumulate(magnitude: &mut Magnitude, bits: u64) -> Result<()> {
    let significand = (bits & FRACTION) | (1_u64 << 52);
    let shift = ((bits >> 52) & 0x7ff) as usize - 1;
    let index = shift / 64;
    let offset = shift % 64;
    add_word(magnitude, index, significand << offset)?;
    if offset != 0 {
        add_word(magnitude, index + 1, significand >> (64 - offset))?;
    }
    Ok(())
}

fn rounded_difference(positive: Magnitude, negative: Magnitude) -> Result<f64> {
    let ordering = positive.iter().rev().cmp(negative.iter().rev());
    if ordering == Ordering::Equal {
        return Ok(0.0);
    }
    let (mut magnitude, smaller, sign) = if ordering == Ordering::Greater {
        (positive, negative, 0_u64)
    } else {
        (negative, positive, 1_u64 << 63)
    };
    let mut borrow = false;
    for (large, small) in magnitude.iter_mut().zip(smaller) {
        let (difference, b1) = large.overflowing_sub(small);
        let (difference, b2) = difference.overflowing_sub(u64::from(borrow));
        *large = difference;
        borrow = b1 || b2;
    }
    let index = magnitude
        .iter()
        .rposition(|word| *word != 0)
        .ok_or(PftErrorV1::Capacity)?;
    let mut top = index * 64 + (63 - magnitude[index].leading_zeros() as usize);
    if top < 52 {
        return Err(PftErrorV1::SumUnderflow);
    }
    let shift = top - 52;
    let index = shift / 64;
    let offset = shift % 64;
    let mut significand = magnitude[index] >> offset;
    if offset > 11 {
        significand |= magnitude[index + 1] << (64 - offset);
    }
    significand &= (1_u64 << 53) - 1;
    if shift != 0 {
        let half = shift - 1;
        let halfway = magnitude[half / 64] & (1_u64 << (half % 64)) != 0;
        let sticky = magnitude[..half / 64].iter().any(|word| *word != 0)
            || magnitude[half / 64] & ((1_u64 << (half % 64)) - 1) != 0;
        if halfway && (sticky || significand & 1 != 0) {
            significand += 1;
            if significand == 1_u64 << 53 {
                significand >>= 1;
                top += 1;
            }
        }
    }
    let exponent = top - 51;
    if exponent >= 0x7ff {
        return Err(PftErrorV1::SumOverflow);
    }
    Ok(f64::from_bits(
        sign | ((exponent as u64) << 52) | (significand & FRACTION),
    ))
}

#[cfg(test)]
#[path = "pft_readout_f64_v1/tests.rs"]
mod tests;
