//! Explicit, read-only DAA research candidate. No native Node, genesis, header,
//! fork choice, storage, or production code calls this module.
//!
//! This implements the fixed-point ASERT polynomial for *full integer targets*
//! rather than Bitcoin's compact nBits codec. This is a separate experimental
//! byte/rounding contract; agreement with an independent oracle and hostile
//! schedule testing is required before selecting a new consensus revision.
use crate::{ensure, Result};

const RADIX: i128 = 65_536;
const MAX_SIGNED_EXPONENT_ABS: i128 = 1_i128 << 118;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AsertResearchInputV1 {
    pub anchor_target: [u8; 32],
    pub pow_limit: [u8; 32],
    /// Timestamp of the parent of the anchor block.
    pub anchor_parent_time: u64,
    /// Height of the first block governed by this anchor.
    pub anchor_height: u64,
    /// Height/timestamp of the validated parent of the block being mined.
    pub parent_height: u64,
    pub parent_time: u64,
    pub target_spacing_seconds: u64,
    pub half_life_seconds: u64,
}

/// The caller may pass either parent-header time or the *separately frozen*
/// MTP11 of the parent and anchor-parent. Do not mix anchor clocks.
/// No wall-clock or received packet ever selects this experiment's inputs.
pub fn asert_target_research_v1(input: AsertResearchInputV1) -> Result<[u8; 32]> {
    ensure(
        input.anchor_target != [0; 32]
            && input.pow_limit != [0; 32]
            && input.anchor_target <= input.pow_limit
            && input.target_spacing_seconds > 0
            && input.half_life_seconds > 0
            && input.anchor_height > 0
            && input.parent_height >= input.anchor_height,
        "DAA_RESEARCH_PARAMETERS",
    )?;
    let span = input
        .parent_height
        .checked_sub(input.anchor_height)
        .and_then(|n| n.checked_add(1))
        .and_then(|n| n.checked_mul(input.target_spacing_seconds))
        .ok_or("DAA_RESEARCH_RANGE")?;
    let residual = (input.parent_time as i128)
        .checked_sub(input.anchor_parent_time as i128)
        .and_then(|d| d.checked_sub(span as i128))
        .ok_or("DAA_RESEARCH_RANGE")?;
    ensure(
        residual > -MAX_SIGNED_EXPONENT_ABS && residual < MAX_SIGNED_EXPONENT_ABS,
        "DAA_RESEARCH_RANGE",
    )?;
    // Rust signed integer division truncates toward zero, as required by
    // the ASERT reference. div_euclid below is intentionally FLOOR for
    // splitting the fixed-point exponent (including negative values).
    let exponent = residual.checked_mul(RADIX).ok_or("DAA_RESEARCH_RANGE")?
        / i128::from(input.half_life_seconds);
    let shifts = exponent.div_euclid(RADIX);
    let x = exponent.rem_euclid(RADIX) as u128;
    let factor = (((195_766_423_245_049_u128 * x
        + 971_821_376_u128 * x * x
        + 5_127_u128 * x * x * x
        + (1_u128 << 47))
        >> 48)
        + RADIX as u128) as u64;
    // No huge allocation/shifting from hostile time/height input. Above this
    // interval the nonzero anchor target necessarily saturates the pow limit;
    // below it the positive integer target becomes zero, clamped to one.
    if shifts >= 512 {
        return Ok(input.pow_limit);
    }
    if shifts <= -512 {
        return Ok(hardest_target());
    }
    let mut words = mul_target_by_u64(input.anchor_target, factor);
    if shifts >= 0 {
        words = match shift_left_checked(words, shifts as usize) {
            Some(value) => value,
            None => return Ok(input.pow_limit),
        };
    } else {
        words = shift_right(words, (-shifts) as usize);
    }
    words = shift_right(words, 16);
    if words[4..].iter().any(|n| *n != 0) {
        return Ok(input.pow_limit);
    }
    let mut out = [0_u8; 32];
    for (i, limb) in words[..4].iter().enumerate() {
        out[24 - i * 8..32 - i * 8].copy_from_slice(&limb.to_be_bytes());
    }
    Ok(if out == [0; 32] {
        hardest_target()
    } else {
        out.min(input.pow_limit)
    })
}

fn hardest_target() -> [u8; 32] {
    let mut out = [0_u8; 32];
    out[31] = 1;
    out
}

/// 512-bit scratch, little-endian limbs, no new dependency and no floats.
fn mul_target_by_u64(target: [u8; 32], factor: u64) -> [u64; 8] {
    let mut words = [0_u64; 8];
    let mut carry = 0_u128;
    for (i, out) in words[..4].iter_mut().enumerate() {
        let a = u64::from_be_bytes(target[24 - i * 8..32 - i * 8].try_into().unwrap());
        let value = u128::from(a) * u128::from(factor) + carry;
        *out = value as u64;
        carry = value >> 64;
    }
    words[4] = carry as u64;
    words
}

fn shift_left_checked(words: [u64; 8], amount: usize) -> Option<[u64; 8]> {
    if amount >= 512 {
        return if words == [0; 8] { Some(words) } else { None };
    }
    let whole = amount / 64;
    let fraction = amount % 64;
    let mut result = [0_u64; 8];
    for (i, value) in words.into_iter().enumerate() {
        if value == 0 {
            continue;
        }
        let position = i + whole;
        if position >= 8 {
            return None;
        }
        result[position] |= value << fraction;
        if fraction != 0 {
            let carry = value >> (64 - fraction);
            if carry != 0 {
                if position == 7 {
                    return None;
                }
                result[position + 1] |= carry;
            }
        }
    }
    Some(result)
}

fn shift_right(words: [u64; 8], amount: usize) -> [u64; 8] {
    if amount >= 512 {
        return [0; 8];
    }
    let whole = amount / 64;
    let fraction = amount % 64;
    let mut result = [0_u64; 8];
    for (i, value) in words.into_iter().enumerate().skip(whole) {
        let position = i - whole;
        result[position] |= value >> fraction;
        if fraction != 0 && position > 0 {
            result[position - 1] |= value << (64 - fraction);
        }
    }
    result
}

/// Median of the *caller-verified* parent-first ancestor window. This is a
/// clock observation only: it does not itself grant time or parent validity.
pub fn median_parent_time_research_v1(ancestors: &[u64]) -> Result<u64> {
    ensure(
        (1..=11).contains(&ancestors.len()),
        "DAA_RESEARCH_ANCESTORS",
    )?;
    let mut ordered = ancestors.to_vec();
    ordered.sort_unstable();
    Ok(ordered[ordered.len() / 2])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> AsertResearchInputV1 {
        let mut anchor = [0; 32];
        anchor[15] = 1; // Exactly 2^128.
        AsertResearchInputV1 {
            anchor_target: anchor,
            pow_limit: [255; 32],
            anchor_parent_time: 0,
            anchor_height: 1,
            parent_height: 11,
            parent_time: 110,
            target_spacing_seconds: 10,
            half_life_seconds: 7200,
        }
    }

    #[test]
    fn exact_zero_positive_and_negative_half_life() {
        let steady = input();
        assert_eq!(
            asert_target_research_v1(steady).unwrap(),
            steady.anchor_target
        );
        let mut slow = steady;
        slow.parent_time += 7200;
        let mut twice = [0; 32];
        twice[15] = 2;
        assert_eq!(asert_target_research_v1(slow).unwrap(), twice);
        let mut fast = steady;
        fast.parent_height += 720;
        let mut half = [0; 32];
        half[16] = 128; // 2^127.
        assert_eq!(asert_target_research_v1(fast).unwrap(), half);
    }

    #[test]
    fn saturation_bounds_and_research_refusal() {
        let mut p = input();
        p.pow_limit = p.anchor_target;
        p.parent_time += 7200;
        assert_eq!(asert_target_research_v1(p).unwrap(), p.pow_limit);
        p.anchor_target = [0; 32];
        assert!(asert_target_research_v1(p).is_err());
        let mut q = input();
        q.parent_height = 0;
        assert!(asert_target_research_v1(q).is_err());
        assert!(median_parent_time_research_v1(&[]).is_err());
        assert!(median_parent_time_research_v1(&[1; 12]).is_err());
    }

    #[test]
    fn mtp_clock_is_sorted_not_maximum_or_last() {
        assert_eq!(
            median_parent_time_research_v1(&[1000, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]).unwrap(),
            10
        );
        assert_eq!(median_parent_time_research_v1(&[12, 9, 100]).unwrap(), 12);
    }

    #[test]
    fn python_and_native_full_target_asert_agree_on_frozen_vectors() {
        // These literal outputs are independently calculated from the
        // stdlib-only Python reference, not from any PoN consensus code path.
        let reference: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../formal/pon-nakamoto-v1/vectors/daa-research-v1.json"
        ))
        .unwrap();
        assert_eq!(reference["production_consensus_activation"], false);
        let hex32 = |s: &str| -> [u8; 32] { hex::decode(s).unwrap().try_into().unwrap() };
        let anchor = hex32(reference["anchor_target_hex"].as_str().unwrap());
        let pow_limit = hex32(reference["pow_limit_hex"].as_str().unwrap());
        for row in reference["cases"].as_array().unwrap() {
            let input = AsertResearchInputV1 {
                anchor_target: anchor,
                pow_limit,
                anchor_parent_time: reference["anchor_parent_time"].as_u64().unwrap(),
                anchor_height: reference["anchor_height"].as_u64().unwrap(),
                parent_height: row["parent_height"].as_u64().unwrap(),
                parent_time: row["parent_time"].as_u64().unwrap(),
                target_spacing_seconds: reference["spacing_seconds"].as_u64().unwrap(),
                half_life_seconds: reference["half_life_seconds"].as_u64().unwrap(),
            };
            assert_eq!(
                asert_target_research_v1(input).unwrap(),
                hex32(row["expected_target_hex"].as_str().unwrap()),
                "frozen ASERT research vector: {}",
                row["name"].as_str().unwrap()
            );
        }
    }
}
