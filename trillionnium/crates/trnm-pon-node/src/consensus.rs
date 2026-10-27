//! M02 pure required-work arithmetic. No peer, database, signature or model calls.
use crate::{ensure, Result};
use std::cmp::Ordering;

/// Fixed 512-bit unsigned integer; limb order is internal, stored bytes are big endian.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Work([u64; 8]);
impl Ord for Work {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.iter().rev().cmp(other.0.iter().rev())
    }
}
impl PartialOrd for Work {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Work {
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        let mut words = [0; 8];
        for (i, word) in words.iter_mut().enumerate() {
            let mut part = [0; 8];
            part.copy_from_slice(&bytes[56 - i * 8..64 - i * 8]);
            *word = u64::from_be_bytes(part);
        }
        Self(words)
    }
    pub fn bytes(self) -> [u8; 64] {
        let mut out = [0; 64];
        for (i, word) in self.0.iter().enumerate() {
            out[56 - i * 8..64 - i * 8].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
    pub fn from_target(target: [u8; 32]) -> Self {
        let mut bytes = [0; 64];
        bytes[32..].copy_from_slice(&target);
        Self::from_bytes(bytes)
    }
    pub fn target(self) -> Result<[u8; 32]> {
        ensure(self.0[4..] == [0; 4], "TARGET_OVERFLOW")?;
        let mut out = [0; 32];
        out.copy_from_slice(&self.bytes()[32..]);
        Ok(out)
    }
    fn small(value: u64) -> Self {
        let mut out = Self::default();
        out.0[0] = value;
        out
    }
    pub fn checked_add(self, rhs: Self) -> Result<Self> {
        let mut out = [0; 8];
        let mut carry = 0u128;
        for (i, word) in out.iter_mut().enumerate() {
            let value = self.0[i] as u128 + rhs.0[i] as u128 + carry;
            *word = value as u64;
            carry = value >> 64;
        }
        ensure(carry == 0, "CHAINWORK_OVERFLOW")?;
        Ok(Self(out))
    }
    pub fn checked_sub(self, rhs: Self) -> Result<Self> {
        ensure(self >= rhs, "CHAINWORK_UNDERFLOW")?;
        Ok(self.wrapping_sub(rhs))
    }
    fn wrapping_sub(self, rhs: Self) -> Self {
        let mut out = [0; 8];
        let mut borrow = false;
        for (i, word) in out.iter_mut().enumerate() {
            let (a, b1) = self.0[i].overflowing_sub(rhs.0[i]);
            let (b, b2) = a.overflowing_sub(u64::from(borrow));
            *word = b;
            borrow = b1 || b2;
        }
        Self(out)
    }
    #[cfg(test)]
    fn shifted(self, bit: u64) -> (Self, bool) {
        let mut out = [0; 8];
        let mut carry = bit;
        for (i, word) in out.iter_mut().enumerate() {
            *word = (self.0[i] << 1) | carry;
            carry = self.0[i] >> 63;
        }
        (Self(out), carry != 0)
    }
    fn divided(self, divisor: Self) -> Result<Self> {
        ensure(divisor != Self::default(), "DIVISION_BY_ZERO")?;
        if self < divisor {
            return Ok(Self::default());
        }
        // Align the actual divisor to the numerator's most significant bit.
        // No target/work/context verdict is cached. The remainder and aligned
        // divisor fit 512 bits: their top bit never exceeds self's top bit.
        let bits = |value: Self| {
            value
                .0
                .iter()
                .rposition(|word| *word != 0)
                .map_or(0, |i| i * 64 + (64 - value.0[i].leading_zeros() as usize))
        };
        let shift = bits(self) - bits(divisor);
        let mut aligned = [0; 8];
        let words = shift / 64;
        let offset = shift % 64;
        for (i, value) in divisor.0.iter().copied().enumerate().take(8 - words) {
            aligned[i + words] |= value << offset;
            if offset != 0 && i + words + 1 < 8 {
                aligned[i + words + 1] |= value >> (64 - offset);
            }
        }
        let mut aligned = Self(aligned);
        let mut remainder = self;
        let mut quotient = Self::default();
        for bit in (0..=shift).rev() {
            if remainder >= aligned {
                remainder = remainder.wrapping_sub(aligned);
                quotient.0[bit / 64] |= 1u64 << (bit % 64);
            }
            // All right shifts use the next still-unmodified higher limb.
            for i in 0..8 {
                aligned.0[i] =
                    (aligned.0[i] >> 1) | if i + 1 < 8 { aligned.0[i + 1] << 63 } else { 0 };
            }
        }
        Ok(quotient)
    }
    pub fn mul_small(self, value: u64) -> Result<Self> {
        let mut out = [0; 8];
        let mut carry = 0u128;
        for (i, word) in out.iter_mut().enumerate() {
            let next = (self.0[i] as u128) * (value as u128) + carry;
            *word = next as u64;
            carry = next >> 64;
        }
        ensure(carry == 0, "CHAINWORK_OVERFLOW")?;
        Ok(Self(out))
    }
}

pub fn required_work(target: [u8; 32]) -> Result<Work> {
    ensure(target != [0; 32], "TARGET")?;
    let denominator = Work::from_target(target).checked_add(Work::small(1))?;
    let mut numerator = Work::default();
    numerator.0[4] = 1;
    numerator.divided(denominator)
}

pub fn retarget(
    parent: [u8; 32],
    first: u64,
    last: u64,
    interval: u64,
    spacing: u64,
    pow_limit: [u8; 32],
) -> Result<[u8; 32]> {
    ensure(
        interval >= 16 && spacing > 0 && parent != [0; 32] && parent <= pow_limit,
        "TARGET_PARAMETERS",
    )?;
    let desired = (interval - 1)
        .checked_mul(spacing)
        .ok_or("TARGET_PARAMETERS")?;
    let upper = desired.checked_mul(4).ok_or("TARGET_PARAMETERS")?;
    let lower = desired / 4 + u64::from(desired % 4 != 0);
    let observed = last.saturating_sub(first).max(1).clamp(lower, upper);
    let adjusted = Work::from_target(parent)
        .mul_small(observed)?
        .divided(Work::small(desired))?;
    adjusted
        .max(Work::small(1))
        .min(Work::from_target(pow_limit))
        .target()
}

/// `ancestors` is the locally validated parent-first window, including genesis as needed.
pub fn check_time(candidate: u64, ancestors: &[u64], now: u64, skew: u64) -> Result<()> {
    ensure(!ancestors.is_empty(), "UNKNOWN_PARENT")?;
    let mut recent: Vec<_> = ancestors.iter().take(11).copied().collect();
    recent.sort_unstable();
    ensure(candidate > recent[recent.len() / 2], "TIME")?;
    ensure(
        candidate as u128 <= now as u128 + skew as u128,
        "TIME_DEFERRED",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    // Independent original fixed-width restoring division. Keep its full
    // 512-round loop and overflow handling; do not call the aligned kernel.
    fn original_division(numerator: Work, divisor: Work) -> Result<Work> {
        ensure(divisor != Work::default(), "DIVISION_BY_ZERO")?;
        let mut remainder = Work::default();
        let mut quotient = Work::default();
        for bit in (0..512).rev() {
            let (shifted, overflow) = remainder.shifted((numerator.0[bit / 64] >> (bit % 64)) & 1);
            remainder = shifted;
            if overflow || remainder >= divisor {
                remainder = remainder.wrapping_sub(divisor);
                quotient.0[bit / 64] |= 1u64 << (bit % 64);
            }
        }
        Ok(quotient)
    }

    fn compare_division(numerator: Work, divisor: Work) {
        let original = original_division(numerator, divisor)
            .map(Work::bytes)
            .map_err(|error| error.to_string());
        let candidate = numerator
            .divided(divisor)
            .map(Work::bytes)
            .map_err(|error| error.to_string());
        assert_eq!(candidate, original, "n={numerator:?} d={divisor:?}");
    }

    #[test]
    fn aligned_division_preserves_all_512_shift_and_limb_boundaries() {
        let max = Work::from_bytes([255; 64]);
        compare_division(Work::default(), Work::default());
        compare_division(max, Work::default());
        for bit in 0..512 {
            let mut power = Work::default();
            power.0[bit / 64] = 1u64 << (bit % 64);
            let previous = power.wrapping_sub(Work::small(1));
            for numerator in [Work::default(), Work::small(1), previous, power, max] {
                compare_division(numerator, power);
            }
            compare_division(power, max);
            if bit != 0 {
                compare_division(max, previous);
                compare_division(power, previous);
            }
            let next = power.checked_add(Work::small(1)).unwrap();
            compare_division(max, next);
            compare_division(power, next);
        }
    }

    #[test]
    fn aligned_division_matches_original_for_wide_arbitrary_operands() {
        let mut seed = 0x62b7_f30a_c985_1d4eu64;
        let mut word = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for case in 0..1024 {
            let mut numerator = Work(std::array::from_fn(|_| word()));
            let mut divisor = Work(std::array::from_fn(|_| word()));
            // Exercise all effective widths, not just uniformly full-width
            // inputs whose quotient is usually zero or one.
            for i in (case % 8 + 1)..8 {
                numerator.0[i] = 0;
            }
            for i in ((case / 8) % 8 + 1)..8 {
                divisor.0[i] = 0;
            }
            compare_division(numerator, divisor);
            compare_division(divisor, numerator);
            compare_division(numerator, numerator);
        }
    }

    #[test]
    fn aligned_required_work_and_retarget_match_original_arithmetic() {
        let mut numerator = Work::default();
        numerator.0[4] = 1;
        for bit in 0..256 {
            let mut power = Work::default();
            power.0[bit / 64] = 1u64 << (bit % 64);
            let mut targets = vec![power, power.checked_add(Work::small(1)).unwrap()];
            if bit != 0 {
                targets.push(power.wrapping_sub(Work::small(1)));
            }
            for target in targets {
                let bytes = target.target().unwrap();
                assert_eq!(
                    required_work(bytes).unwrap(),
                    original_division(numerator, target.checked_add(Work::small(1)).unwrap())
                        .unwrap()
                );
                for (first, last) in [
                    (100, 0),
                    (100, 100),
                    (100, 101),
                    (100, 249),
                    (100, 250),
                    (100, 251),
                    (0, u64::MAX),
                ] {
                    let observed = last.saturating_sub(first).max(1).clamp(38, 600);
                    let original =
                        original_division(target.mul_small(observed).unwrap(), Work::small(150))
                            .unwrap()
                            .max(Work::small(1))
                            .min(Work::from_target([255; 32]))
                            .target()
                            .unwrap();
                    assert_eq!(
                        retarget(bytes, first, last, 16, 10, [255; 32]).unwrap(),
                        original
                    );
                }
            }
        }
    }

    #[test]
    fn exact_extreme_work_and_overflow() {
        assert!(required_work([0; 32]).is_err());
        assert_eq!(required_work([255; 32]).unwrap(), Work::small(1));
        let mut half = [255; 32];
        half[0] = 127;
        assert_eq!(required_work(half).unwrap(), Work::small(2));
        let mut one = [0; 32];
        one[31] = 1;
        let mut expected = [0; 64];
        expected[32] = 128;
        assert_eq!(required_work(one).unwrap().bytes(), expected);
        assert!(Work::from_bytes([255; 64])
            .checked_add(Work::small(1))
            .is_err());
        assert!(Work::small(1).checked_sub(Work::small(2)).is_err());
    }
    #[test]
    fn full_width_division_matches_small_and_high_operands() {
        for a in [0, 1, 2, u64::MAX - 1, u64::MAX] {
            for b in [1, 2, 3, u64::MAX] {
                assert_eq!(
                    Work::small(a).divided(Work::small(b)).unwrap(),
                    Work::small(a / b)
                );
            }
        }
        let max = Work::from_bytes([255; 64]);
        assert_eq!(max.divided(max).unwrap(), Work::small(1));
        assert_eq!(
            max.divided(max.wrapping_sub(Work::small(1))).unwrap(),
            Work::small(1)
        );
    }
    #[test]
    fn time_deferred_is_not_consensus_invalidity() {
        assert_eq!(
            check_time(200, &[100, 101, 99], 50, 120)
                .unwrap_err()
                .to_string(),
            "TIME_DEFERRED"
        );
        check_time(200, &[100, 101, 99], 200, 120).unwrap();
        assert!(check_time(100, &[100, 101, 99], 200, 120).is_err());
        check_time(u64::MAX, &[1], u64::MAX, 120).unwrap();
    }
}

/// Isolated, non-activated research arithmetic. No Node, CLI, packet or genesis
/// routes to this function. Existing `retarget` and timestamp validity are unchanged.
/// A dedicated new consensus revision, independent vectors and operator qualification
/// would be required before this could ever select an expected block target.
pub mod daa_research {
    use super::{ensure, Result, Work};

    /// Fixed-anchor ASERT (aserti3-2d polynomial), with exact PoN u256 targets.
    /// Unlike BCH nBits this interface does not compact-round the resulting target.
    /// The caller explicitly supplies its authenticated branch parent time: either
    /// the raw timestamp or MTP11. It is NOT permitted to trust a received target.
    #[derive(Clone, Copy, Debug)]
    pub struct AsertInputs {
        pub anchor_target: [u8; 32],
        pub anchor_parent_time: u64,
        pub evaluation_parent_time: u64,
        pub anchor_height: u64,
        pub candidate_height: u64,
        pub spacing: u64,
        pub half_life: u64,
        pub pow_limit: [u8; 32],
    }

    fn left_shift(value: Work, shift: usize) -> Option<Work> {
        if shift >= 512 {
            return None;
        }
        let words = shift / 64;
        let bits = shift % 64;
        let mut result = [0_u64; 8];
        for (i, part) in value.0.iter().copied().enumerate() {
            if part == 0 {
                continue;
            }
            let j = i + words;
            if j >= 8 {
                return None;
            }
            result[j] |= part << bits;
            if bits > 0 {
                let carry = part >> (64 - bits);
                if carry != 0 {
                    if j + 1 == 8 {
                        return None;
                    }
                    result[j + 1] |= carry;
                }
            }
        }
        Some(Work(result))
    }

    fn right_shift(value: Work, shift: usize) -> Work {
        if shift >= 512 {
            return Work::default();
        }
        let words = shift / 64;
        let bits = shift % 64;
        let mut result = [0_u64; 8];
        for (i, slot) in result.iter_mut().enumerate().take(8 - words) {
            *slot = value.0[i + words] >> bits;
            if bits > 0 && i + words + 1 < 8 {
                *slot |= value.0[i + words + 1] << (64 - bits);
            }
        }
        Work(result)
    }

    pub fn asert_target(input: AsertInputs) -> Result<[u8; 32]> {
        let anchor = Work::from_target(input.anchor_target);
        let maximum = Work::from_target(input.pow_limit);
        ensure(
            anchor >= Work::small(1)
                && anchor <= maximum
                && input.anchor_height > 0
                && input.candidate_height > input.anchor_height
                && input.spacing > 0
                && input.half_life > 0,
            "ASERT_RESEARCH_PARAMETERS",
        )?;
        // For candidate height h, the ideal interval count is h-anchor_height.
        // Signed deviation uses a checked i128, never wrapping a u64 timestamp.
        let intervals = i128::from(input.candidate_height - input.anchor_height);
        let ideal = intervals
            .checked_mul(i128::from(input.spacing))
            .ok_or("ASERT_RESEARCH_RANGE")?;
        let deviation = i128::from(input.evaluation_parent_time)
            .checked_sub(i128::from(input.anchor_parent_time))
            .and_then(|value| value.checked_sub(ideal))
            .ok_or("ASERT_RESEARCH_RANGE")?;
        let scaled = deviation.checked_mul(65_536).ok_or("ASERT_RESEARCH_RANGE")?;
        let exponent = scaled / i128::from(input.half_life); // truncate toward zero
        let shifts = exponent.div_euclid(65_536);
        let fractional = exponent.rem_euclid(65_536);
        // Original aserti3-2d approximation. i128 avoids u64 intermediate
        // overflow and preserves exact bit shifts for all fractional values.
        let factor = ((195_766_423_245_049_i128 * fractional
            + 971_821_376_i128 * fractional * fractional
            + 5_127_i128 * fractional * fractional * fractional
            + (1_i128 << 47))
            >> 48)
            + 65_536;
        ensure((65_536..=131_072).contains(&factor), "ASERT_RESEARCH_FACTOR")?;
        if shifts >= 256 {
            return Ok(input.pow_limit);
        }
        if shifts <= -512 {
            return Work::small(1).target();
        }
        let base = anchor.mul_small(factor as u64)?;
        let changed = if shifts >= 0 {
            match left_shift(base, shifts as usize) {
                Some(value) => value,
                None => return Ok(input.pow_limit),
            }
        } else {
            right_shift(base, (-shifts) as usize)
        };
        right_shift(changed, 16)
            .max(Work::small(1))
            .min(maximum)
            .target()
    }
}

#[cfg(test)]
mod daa_research_tests {
    use super::{check_time, daa_research::{asert_target, AsertInputs}, retarget, Work};

    fn target(hex_text: &str) -> [u8; 32] {
        let mut out = [0_u8; 32];
        hex::decode_to_slice(hex_text, &mut out).unwrap();
        out
    }
    fn base() -> [u8; 32] {
        let mut value = [0_u8; 32];
        value[4] = 0x10; // 2^220
        value
    }
    fn cap() -> [u8; 32] {
        let mut value = [255_u8; 32];
        value[0] = 0;
        value[1] = 0; // 2^240-1
        value
    }
    fn sample(before: u64, parent: u64, anchor_height: u64,
              height: u64, spacing: u64, half_life: u64) -> AsertInputs {
        AsertInputs { anchor_target: base(), anchor_parent_time: before,
            evaluation_parent_time: parent, anchor_height,
            candidate_height: height, spacing, half_life, pow_limit: cap() }
    }

    #[test]
    fn independent_python_vectors_agree_with_native_fixed_point_arithmetic() {
        // Values frozen from separately implemented unbounded Python oracle.
        for (input, expected) in [
            (sample(0, 10, 1, 2, 10, 7200),
             "0000000010000000000000000000000000000000000000000000000000000000"),
            (sample(0, 20, 1, 2, 10, 7200),
             "000000001003f000000000000000000000000000000000000000000000000000"),
            (sample(0, 0, 1, 2, 10, 7200),
             "000000000ffc1000000000000000000000000000000000000000000000000000"),
            (sample(0, 2000, 1, 80, 10, 7200),
             "0000000011fa7000000000000000000000000000000000000000000000000000"),
            (sample(0, 800, 1, 80, 10, 7200),
             "000000001003f000000000000000000000000000000000000000000000000000"),
            (sample(2000, 1800, 1, 100, 10, 3600),
             "000000000cb95000000000000000000000000000000000000000000000000000"),
            (sample(0, 1 << 20, 1, 2, 10, 3600),
             "0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            (sample(1 << 20, 0, 1, 2, 10, 3600),
             "0000000000000000000000000000000000000000000000000000000000000001"),
        ] {
            assert_eq!(asert_target(input).unwrap(), target(expected));
        }
    }

    #[test]
    fn bad_ranges_and_context_are_rejected_without_any_old_rule_change() {
        let mut input = sample(0, 10, 1, 2, 10, 7200);
        input.half_life = 0;
        assert_eq!(asert_target(input).unwrap_err().to_string(),
                   "ASERT_RESEARCH_PARAMETERS");
        input = sample(0, 10, 1, 2, 10, 7200);
        input.candidate_height = input.anchor_height;
        assert!(asert_target(input).is_err());
        input = sample(0, 10, 1, 2, 10, 7200);
        input.anchor_target = cap();
        input.pow_limit = base();
        assert!(asert_target(input).is_err());
        input = sample(u64::MAX, 0, 1, u64::MAX, u64::MAX, 1);
        assert_eq!(asert_target(input).unwrap_err().to_string(),
                   "ASERT_RESEARCH_RANGE");
        let old = retarget(base(), 0, 600, 16, 10, cap()).unwrap();
        assert_eq!(old, Work::from_target(base()).mul_small(4).unwrap().target().unwrap());
    }

    #[test]
    fn eighty_legal_timestamp_checks_show_endpoint_response_not_valid_w1_mining() {
        let mut timestamps = vec![0_u64];
        let mut current = base();
        for h in 1..=80_u64 {
            let recent: Vec<_> = timestamps.iter().rev().copied().take(11).collect();
            let mut median = recent.clone();
            median.sort_unstable();
            let ts = if h % 16 == 15 { 2000 } else { median[median.len() / 2] + 1 };
            check_time(ts, &recent, 2000, 120).unwrap();
            if h % 16 == 0 {
                current = retarget(current, timestamps[(h-16) as usize],
                                   timestamps[(h-1) as usize], 16, 10, cap()).unwrap();
            }
            timestamps.push(ts);
        }
        assert_eq!(current,
                   Work::from_target(base()).mul_small(1024).unwrap().target().unwrap());
        let raw = asert_target(sample(0, timestamps[79], 1, 80, 10, 7200)).unwrap();
        let mtp = asert_target(sample(0, 16, 1, 80, 10, 7200)).unwrap();
        assert_eq!(raw, target("0000000011fa7000000000000000000000000000000000000000000000000000"));
        assert_eq!(mtp, target("000000000eda5000000000000000000000000000000000000000000000000000"));
        // Checks valid header times ONLY, no signed blocks, W1 proofs or mining claims.
    }
}

#[cfg(test)]
mod daa_extreme_vectors {
    use super::daa_research::{asert_target, AsertInputs};
    use sha2::{Digest, Sha256};

    /// 512 deterministically generated observations frozen from the independent
    /// Python big-integer implementation. No W1 proof or activated profile.
    #[test]
    fn signed_exponent_shift_boundaries_match_independent_python_digest() {
        let mut state = 0x62b7_f30a_c985_1d4e_u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut anchor_target = [0_u8; 32];
        anchor_target[4] = 0x10; // 2^220
        let mut pow_limit = [255_u8; 32];
        pow_limit[0] = 0;
        pow_limit[1] = 0; // 2^240 - 1
        let mut digest = Sha256::new();
        for i in 0..512_u64 {
            let candidate_height = 2 + next() % 1000;
            let anchor_parent_time = 1_000_000 + next() % 100_000;
            let deviation = (next() % 100_000) as i64 - 50_000;
            let mut parent_time = (anchor_parent_time as i64
                + ((candidate_height - 1) * 10) as i64 + deviation) as u64;
            if i % 17 == 0 {
                parent_time = u64::MAX;
            }
            if i % 19 == 0 {
                parent_time = 0;
            }
            let half_life = [3600, 7200, 14400, 28800, 1][(i % 5) as usize];
            let value = asert_target(AsertInputs {
                anchor_target,
                anchor_parent_time,
                evaluation_parent_time: parent_time,
                anchor_height: 1,
                candidate_height,
                spacing: 10,
                half_life,
                pow_limit,
            }).unwrap();
            digest.update(value);
        }
        assert_eq!(
            hex::encode(digest.finalize()),
            "6be87e237c37aec8c50af8d4eaf9e14a0ca60e7dc69f18143ede1ef70c420c97"
        );
    }
}
/// Isolated, non-activated ASERT ancestry observer. Installed consensus
/// expected_target never calls this module. Callers must supply records from
/// an independently validated native Node, not unauthenticated P2P headers.
pub mod daa_branch_research {
    use super::daa_research::{asert_target, AsertInputs};
    use crate::{ensure, Packet, Result};
    use trnm_protocol::pon_wire::Hash;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ParentClock {
        Raw,
        Median11,
    }

    #[derive(Clone, Copy, Debug)]
    pub struct AnchoredResearchContext {
        pub network: Hash,
        pub parameters: Hash,
        pub genesis: Hash,
        pub genesis_timestamp: u64,
        pub anchor_block: Hash,
        pub anchor_target: Hash,
        pub anchor_height: u64,
        pub spacing: u64,
        pub half_life: u64,
        pub pow_limit: Hash,
        pub parent_clock: ParentClock,
        pub max_ancestor_reads: usize,
    }

    /// Compute a shadow target from a linked observed ancestry.
    /// read_verified supplies the complete stored Packet; the observed
    /// packet ID is recomputed here before trusting its Header. The caller
    /// still owns full W1 verification, genesis time and state provenance.
    /// A future consensus revision needs a committed and reviewed context.
    pub fn shadow_target_from_ancestry(
        context: AnchoredResearchContext,
        observed_parent: Hash,
        mut read_verified: impl FnMut(Hash) -> Result<Packet>,
    ) -> Result<Hash> {
        ensure(
            context.anchor_height == 1
                && context.anchor_block != context.genesis
                && context.genesis != [0; 32]
                && context.network != [0; 32]
                && context.parameters != [0; 32]
                && (1..=4096).contains(&context.max_ancestor_reads)
                && context.spacing > 0
                && context.half_life > 0,
            "ASERT_BRANCH_CONTEXT",
        )?;
        let mut cursor = observed_parent;
        let mut previous_height = None;
        let mut parent_height = None;
        let mut parent_timestamp = None;
        let mut observed_times = Vec::with_capacity(11);
        for _ in 0..context.max_ancestor_reads {
            ensure(cursor != context.genesis, "ASERT_ANCHOR_MISSING")?;
            let packet = read_verified(cursor)?;
            let actual_id = packet.id()?;
            let header = packet.header;
            ensure(
                actual_id == cursor
                    && header.network == context.network
                    && header.parameters == context.parameters
                    && header.height >= context.anchor_height,
                "ASERT_ANCESTRY_CONTEXT",
            )?;
            if let Some(next_height) = previous_height {
                ensure(
                    header.height.checked_add(1) == Some(next_height),
                    "ASERT_ANCESTRY_HEIGHT",
                )?;
            }
            if parent_height.is_none() {
                parent_height = Some(header.height);
                parent_timestamp = Some(header.timestamp);
            }
            if observed_times.len() < 11 {
                observed_times.push(header.timestamp);
            }
            if cursor == context.anchor_block {
                ensure(
                    header.height == context.anchor_height
                        && header.parent == context.genesis
                        && header.target == context.anchor_target,
                    "ASERT_ANCHOR_BINDING",
                )?;
                if observed_times.len() < 11 {
                    observed_times.push(context.genesis_timestamp);
                }
                let selected_time = match context.parent_clock {
                    ParentClock::Raw => parent_timestamp.ok_or("ASERT_ANCESTRY_EMPTY")?,
                    ParentClock::Median11 => {
                        observed_times.sort_unstable();
                        observed_times[observed_times.len() / 2]
                    }
                };
                return asert_target(AsertInputs {
                    anchor_target: context.anchor_target,
                    anchor_parent_time: context.genesis_timestamp,
                    evaluation_parent_time: selected_time,
                    anchor_height: context.anchor_height,
                    candidate_height: parent_height
                        .ok_or("ASERT_ANCESTRY_EMPTY")?
                        .checked_add(1)
                        .ok_or("ASERT_ANCESTRY_HEIGHT")?,
                    spacing: context.spacing,
                    half_life: context.half_life,
                    pow_limit: context.pow_limit,
                });
            }
            previous_height = Some(header.height);
            cursor = header.parent;
        }
        Err("ASERT_ANCESTRY_BUDGET".into())
    }
}


/// Non-activated parent-derived ASERT anchor projection. This is not a
/// VerifiedWork, validated-header, persistence or consensus authority. The
/// caller must independently validate original parent and new W1 Packet before
/// passing a research observation; no Node expected-target path calls this.
#[cfg(test)]
mod anchor_projection_research {
    use super::{daa_research, ensure, Result};
    use sha2::{Digest, Sha256};

    type Hash = [u8; 32];

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum Clock {
        Raw,
        Median11,
    }

    #[derive(Clone, Debug)]
    pub struct Context {
        pub network: Hash,
        pub parameters: Hash,
        pub genesis: Hash,
        pub rule_commitment: Hash,
        pub genesis_timestamp: u64,
        pub activation_height: u64,
        pub target_spacing: u64,
        pub half_life: u64,
        pub pow_limit: Hash,
        pub clock: Clock,
    }

    impl Context {
        pub fn id(&self) -> Result<Hash> {
            ensure(
                self.network != [0; 32]
                    && self.parameters != [0; 32]
                    && self.genesis != [0; 32]
                    && self.rule_commitment != [0; 32]
                    && self.activation_height > 0
                    && self.activation_height < u64::MAX
                    && self.target_spacing > 0
                    && self.half_life > 0
                    && self.pow_limit != [0; 32],
                "DAA_PROJECTION_CONTEXT",
            )?;
            let mut digest = Sha256::new();
            digest.update(b"TRNM-PON-DAA-PROJECTION-CONTEXT-V1\0");
            digest.update(self.network);
            digest.update(self.parameters);
            digest.update(self.genesis);
            digest.update(self.rule_commitment);
            for value in [
                self.genesis_timestamp,
                self.activation_height,
                self.target_spacing,
                self.half_life,
            ] {
                digest.update(value.to_be_bytes());
            }
            digest.update(self.pow_limit);
            digest.update(match self.clock {
                Clock::Raw => b"raw".as_slice(),
                Clock::Median11 => b"mtp11".as_slice(),
            });
            Ok(digest.finalize().into())
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Observation {
        pub block_id: Hash,
        pub parent_id: Hash,
        pub network: Hash,
        pub parameters: Hash,
        pub height: u64,
        pub timestamp: u64,
        pub target: Hash,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct Anchor {
        pub block: Hash,
        pub predecessor: Hash,
        pub height: u64,
        pub target: Hash,
        pub predecessor_raw: u64,
        pub predecessor_median: u64,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct Projection {
        pub block_id: Hash,
        pub parent_id: Hash,
        pub height: u64,
        pub timestamp: u64,
        pub target: Hash,
        pub context_id: Hash,
        pub parent_commitment: Hash,
        pub times_parent_first: Vec<u64>,
        pub anchor: Option<Anchor>,
        pub commitment: Hash,
    }

    fn median(times: &[u64]) -> Result<u64> {
        ensure(!times.is_empty() && times.len() <= 11, "DAA_PROJECTION_WINDOW")?;
        let mut sorted = times.to_vec();
        sorted.sort_unstable();
        Ok(sorted[sorted.len() / 2])
    }

    impl Projection {
        fn computed_commitment(&self) -> Result<Hash> {
            ensure(
                (1..=11).contains(&self.times_parent_first.len()),
                "DAA_PROJECTION_WINDOW",
            )?;
            let mut digest = Sha256::new();
            digest.update(b"TRNM-PON-DAA-LOCAL-PROJECTION-V1\0");
            digest.update(self.context_id);
            digest.update(self.block_id);
            digest.update(self.parent_id);
            digest.update(self.parent_commitment);
            digest.update(self.height.to_be_bytes());
            digest.update(self.timestamp.to_be_bytes());
            digest.update(self.target);
            digest.update([self.times_parent_first.len() as u8]);
            for t in &self.times_parent_first {
                digest.update(t.to_be_bytes());
            }
            if let Some(anchor) = &self.anchor {
                digest.update([1]);
                digest.update(anchor.block);
                digest.update(anchor.predecessor);
                digest.update(anchor.height.to_be_bytes());
                digest.update(anchor.target);
                digest.update(anchor.predecessor_raw.to_be_bytes());
                digest.update(anchor.predecessor_median.to_be_bytes());
            } else {
                digest.update([0]);
            }
            Ok(digest.finalize().into())
        }

        fn check_local(&self, ctx: &Context) -> Result<()> {
            ensure(
                self.context_id == ctx.id()?
                    && self.commitment == self.computed_commitment()?,
                "DAA_PROJECTION_INTEGRITY",
            )
        }

        pub fn genesis(ctx: &Context) -> Result<Self> {
            let mut row = Self {
                block_id: ctx.genesis,
                parent_id: [0; 32],
                height: 0,
                timestamp: ctx.genesis_timestamp,
                target: ctx.pow_limit,
                context_id: ctx.id()?,
                parent_commitment: [0; 32],
                times_parent_first: vec![ctx.genesis_timestamp],
                anchor: None,
                commitment: [0; 32],
            };
            row.commitment = row.computed_commitment()?;
            Ok(row)
        }

        /// Only a local continuation of a previously verified parent; this
        /// DOES NOT establish that the given observation contains valid work.
        pub fn append(&self, ctx: &Context, h: Observation) -> Result<Self> {
            self.check_local(ctx)?;
            ensure(
                h.block_id != [0; 32]
                    && h.block_id != ctx.genesis
                    && h.block_id != h.parent_id
                    && h.parent_id == self.block_id
                    && h.network == ctx.network
                    && h.parameters == ctx.parameters
                    && h.height == self.height.checked_add(1).ok_or("DAA_PROJECTION_HEIGHT")?
                    && h.target != [0; 32]
                    && h.target <= ctx.pow_limit,
                "DAA_PROJECTION_OBSERVATION",
            )?;
            let anchor = if h.height == ctx.activation_height {
                Some(Anchor {
                    block: h.block_id,
                    predecessor: h.parent_id,
                    height: h.height,
                    target: h.target,
                    predecessor_raw: self.timestamp,
                    predecessor_median: median(&self.times_parent_first)?,
                })
            } else {
                self.anchor.clone()
            };
            ensure(
                (h.height < ctx.activation_height && anchor.is_none())
                    || (h.height >= ctx.activation_height && anchor.is_some()),
                "DAA_PROJECTION_ANCHOR",
            )?;
            let mut times = Vec::with_capacity(11);
            times.push(h.timestamp);
            times.extend(self.times_parent_first.iter().take(10).copied());
            let mut row = Self {
                block_id: h.block_id,
                parent_id: h.parent_id,
                height: h.height,
                timestamp: h.timestamp,
                target: h.target,
                context_id: self.context_id,
                parent_commitment: self.commitment,
                times_parent_first: times,
                anchor,
                commitment: [0; 32],
            };
            row.commitment = row.computed_commitment()?;
            Ok(row)
        }

        pub fn shadow_target(&self, ctx: &Context) -> Result<Hash> {
            self.check_local(ctx)?;
            let anchor = self.anchor.as_ref().ok_or("DAA_PROJECTION_NOT_ACTIVE")?;
            let candidate_height = self.height.checked_add(1).ok_or("DAA_PROJECTION_HEIGHT")?;
            let (before, observed) = match ctx.clock {
                Clock::Raw => (anchor.predecessor_raw, self.timestamp),
                Clock::Median11 => (anchor.predecessor_median, median(&self.times_parent_first)?),
            };
            daa_research::asert_target(daa_research::AsertInputs {
                anchor_target: anchor.target,
                anchor_parent_time: before,
                evaluation_parent_time: observed,
                anchor_height: anchor.height,
                candidate_height,
                spacing: ctx.target_spacing,
                half_life: ctx.half_life,
                pow_limit: ctx.pow_limit,
            })
        }
    }
}

#[cfg(test)]
mod daa_anchor_projection_research_tests {
    use super::anchor_projection_research::{Clock, Context, Observation, Projection};
    use sha2::{Digest, Sha256};

    fn sha(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }
    fn fixture(clock: Clock) -> Context {
        let mut cap = [255u8; 32];
        cap[0] = 3;
        Context {
            network: sha(b"projected-net"),
            parameters: sha(b"projected-parameters"),
            genesis: sha(b"projected-genesis"),
            rule_commitment: sha(b"projected-rule"),
            genesis_timestamp: 1_700_000_000,
            activation_height: 16,
            target_spacing: 10,
            half_life: 7200,
            pow_limit: cap,
            clock,
        }
    }
    fn base() -> [u8; 32] {
        let mut out = [0; 32];
        out[4] = 0x10;
        out
    }

    #[test]
    fn long_shadow_matches_python_raw_and_mtp11_hashes_without_changing_node() {
        for (clock, expected_digest) in [
            (Clock::Raw, "491ae11c0736a71af9c3fa0bc9ad26a297929f0ea8c303104e2b9df0125fb0e2"),
            (Clock::Median11, "949f2322a9a1c4e98bbdd27abbe4b00dd0495cb4c12513db8542893815ea615a"),
        ] {
            let ctx = fixture(clock);
            let mut parent = Projection::genesis(&ctx).unwrap();
            let mut witness = Sha256::new();
            assert!(parent.shadow_target(&ctx).is_err());
            for height in 1..=12_000u64 {
                let timestamp = ctx.genesis_timestamp + height * ctx.target_spacing;
                let mut material = Vec::with_capacity(48);
                material.extend(parent.block_id);
                material.extend(height.to_be_bytes());
                material.extend(timestamp.to_be_bytes());
                let block_id = sha(&material);
                let current = parent.append(
                    &ctx,
                    Observation {
                        block_id,
                        parent_id: parent.block_id,
                        network: ctx.network,
                        parameters: ctx.parameters,
                        height,
                        timestamp,
                        target: base(),
                    },
                ).unwrap();
                witness.update(current.commitment);
                assert!(current.times_parent_first.len() <= 11);
                if height >= ctx.activation_height {
                    assert_eq!(current.shadow_target(&ctx).unwrap(), base());
                }
                parent = current;
            }
            assert_eq!(hex::encode(witness.finalize()), expected_digest);
        }
    }

    #[test]
    fn branch_crossing_activation_retains_independent_anchor_without_election() {
        let ctx = fixture(Clock::Median11);
        let mut common = Projection::genesis(&ctx).unwrap();
        for height in 1..15u64 {
            let mut raw = Vec::new();
            raw.extend(common.block_id);
            raw.extend(height.to_be_bytes());
            let id = sha(&raw);
            common = common.append(&ctx, Observation {
                block_id: id, parent_id: common.block_id,
                network: ctx.network, parameters: ctx.parameters,
                height, timestamp: ctx.genesis_timestamp + 10 * height,
                target: base(),
            }).unwrap();
        }
        let mut tips = Vec::new();
        for variant in [1u64, 7u64] {
            let mut parent = common.clone();
            for height in 15..80u64 {
                let mut raw = Vec::new();
                raw.extend(parent.block_id);
                raw.extend(height.to_be_bytes());
                raw.extend(variant.to_be_bytes());
                let id = sha(&raw);
                parent = parent.append(&ctx, Observation {
                    block_id: id, parent_id: parent.block_id,
                    network: ctx.network, parameters: ctx.parameters,
                    height, timestamp: ctx.genesis_timestamp + 10 * height
                        + variant * (height - 14),
                    target: base(),
                }).unwrap();
            }
            tips.push(parent);
        }
        assert_ne!(tips[0].anchor, tips[1].anchor);
        assert_ne!(tips[0].shadow_target(&ctx).unwrap(),
                   tips[1].shadow_target(&ctx).unwrap());
        // Examining another fork never mutates the exact original branch.
        assert_eq!(tips[0].shadow_target(&ctx).unwrap(),
                   tips[0].shadow_target(&ctx).unwrap());
    }

    #[test]
    fn projected_parent_context_and_mutation_fail_before_shadow_work() {
        let ctx = fixture(Clock::Raw);
        let genesis = Projection::genesis(&ctx).unwrap();
        let observation = Observation {
            block_id: sha(b"child"),
            parent_id: ctx.genesis,
            network: ctx.network,
            parameters: ctx.parameters,
            height: 1,
            timestamp: ctx.genesis_timestamp + 10,
            target: base(),
        };
        let first = genesis.append(&ctx, observation).unwrap();
        let mut corrupted = first.clone();
        corrupted.timestamp += 1;
        assert!(corrupted.shadow_target(&ctx).is_err());
        assert!(corrupted.append(&ctx, Observation { height: 2, ..observation }).is_err());
        assert!(genesis.append(&ctx, Observation { height: 2, ..observation }).is_err());
        assert!(genesis.append(&ctx, Observation { network: [0; 32], ..observation }).is_err());
        let mut changed = ctx.clone();
        changed.rule_commitment = sha(b"another version");
        assert!(first.append(&changed, Observation { height: 2, ..observation }).is_err());
    }
}


/// Future-height ASERT projection from a fully verified native W1 ancestry.
/// RESEARCH ONLY: no installed Node target selector calls this module. The
/// activation block remains subject to the historical DAA; its successor is
/// the first shadow candidate. The candidate branch determines the anchor.
pub mod daa_activation_research {
    use super::{daa_research::{asert_target, AsertInputs}, daa_branch_research::ParentClock, ensure, Result};
    use crate::Packet;
    use trnm_protocol::pon_wire::Hash;

    #[derive(Clone, Copy, Debug)]
    pub struct Context {
        pub network: Hash,
        pub parameters: Hash,
        pub genesis: Hash,
        pub genesis_timestamp: u64,
        pub rule_commitment: Hash,
        pub activation_height: u64,
        pub spacing: u64,
        pub half_life: u64,
        pub pow_limit: Hash,
        pub clock: ParentClock,
        pub max_reads: usize,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Projection {
        pub anchor_block: Hash,
        pub anchor_parent: Hash,
        pub anchor_target: Hash,
        pub anchor_parent_time: u64,
        pub observed_parent_time: u64,
        pub candidate_height: u64,
        pub target: Hash,
        pub reads: usize,
    }

    fn median11(times: &[u64]) -> Result<u64> {
        ensure((1..=11).contains(&times.len()), "ASERT_MTP_WINDOW")?;
        let mut sorted = times.to_vec();
        sorted.sort_unstable();
        Ok(sorted[sorted.len() / 2])
    }

    pub fn shadow_from_verified_ancestry(
        ctx: Context,
        observed_parent: Hash,
        mut read_verified: impl FnMut(Hash) -> Result<Packet>,
    ) -> Result<Projection> {
        ensure(ctx.network != [0;32] && ctx.parameters != [0;32]
            && ctx.genesis != [0;32] && ctx.rule_commitment != [0;32]
            && observed_parent != ctx.genesis && ctx.activation_height > 0
            && ctx.activation_height < u64::MAX && ctx.spacing > 0
            && ctx.half_life > 0 && ctx.pow_limit != [0;32]
            && (1..=4096).contains(&ctx.max_reads), "ASERT_ACTIVATION_CONTEXT")?;
        let mut cursor = observed_parent;
        let mut expected_height: Option<u64> = None;
        let mut parent_height = None;
        let mut parent_raw = None;
        let mut parent_window = Vec::with_capacity(11);
        let mut anchor_id = None;
        let mut anchor_parent = None;
        let mut anchor_target = None;
        let mut anchor_parent_raw = None;
        let mut anchor_window = Vec::with_capacity(11);
        let mut saw_predecessor = false;
        let mut reads = 0usize;

        // Deliberate O(height), bounded genesis replay rather than a magic
        // ancestor cache. A future production candidate needs an authenticated
        // index, resource budgets and a separate consensus version.
        loop {
            if cursor == ctx.genesis {
                ensure(expected_height == Some(0), "ASERT_GENESIS_HEIGHT")?;
                if anchor_parent == Some(ctx.genesis) {
                    anchor_parent_raw = Some(ctx.genesis_timestamp);
                    saw_predecessor = true;
                }
                if parent_window.len() < 11 { parent_window.push(ctx.genesis_timestamp); }
                if saw_predecessor && anchor_window.len() < 11 {
                    anchor_window.push(ctx.genesis_timestamp);
                }
                break;
            }
            ensure(reads < ctx.max_reads, "ASERT_ANCESTRY_BUDGET")?;
            let packet = read_verified(cursor)?;
            ensure(packet.id()? == cursor, "ASERT_PACKET_ID")?;
            let header = packet.header;
            ensure(header.network == ctx.network && header.parameters == ctx.parameters
                && header.height > 0 && header.parent != cursor
                && header.target != [0;32] && header.target <= ctx.pow_limit,
                "ASERT_ANCESTRY_CONTEXT")?;
            if let Some(height) = expected_height {
                ensure(header.height == height, "ASERT_ANCESTRY_HEIGHT")?;
            }
            if parent_height.is_none() {
                ensure(header.height >= ctx.activation_height && header.height < u64::MAX,
                    "ASERT_NOT_ACTIVE")?;
                parent_height = Some(header.height);
                parent_raw = Some(header.timestamp);
            }
            if parent_window.len() < 11 { parent_window.push(header.timestamp); }
            if header.height == ctx.activation_height {
                anchor_id = Some(cursor);
                anchor_parent = Some(header.parent);
                anchor_target = Some(header.target);
            }
            if header.height.checked_add(1) == Some(ctx.activation_height)
                && anchor_id.is_some() {
                ensure(anchor_parent == Some(cursor), "ASERT_ANCHOR_PARENT")?;
                anchor_parent_raw = Some(header.timestamp);
                saw_predecessor = true;
            }
            if saw_predecessor && anchor_window.len() < 11 {
                anchor_window.push(header.timestamp);
            }
            expected_height = header.height.checked_sub(1);
            cursor = header.parent;
            reads += 1;
        }
        let anchor_block = anchor_id.ok_or("ASERT_ANCHOR_MISSING")?;
        let anchor_parent = anchor_parent.ok_or("ASERT_ANCHOR_PARENT")?;
        let anchor_target = anchor_target.ok_or("ASERT_ANCHOR_MISSING")?;
        let candidate_height = parent_height.ok_or("ASERT_ANCESTRY_EMPTY")?
            .checked_add(1).ok_or("ASERT_ANCESTRY_HEIGHT")?;
        let (anchor_parent_time, observed_parent_time) = match ctx.clock {
            ParentClock::Raw => (anchor_parent_raw.ok_or("ASERT_ANCHOR_PARENT_TIME")?,
                parent_raw.ok_or("ASERT_ANCESTRY_EMPTY")?),
            ParentClock::Median11 => (median11(&anchor_window)?, median11(&parent_window)?),
        };
        let target = asert_target(AsertInputs {
            anchor_target, anchor_parent_time,
            evaluation_parent_time: observed_parent_time,
            anchor_height: ctx.activation_height,
            candidate_height, spacing: ctx.spacing,
            half_life: ctx.half_life, pow_limit: ctx.pow_limit,
        })?;
        Ok(Projection {
            anchor_block, anchor_parent, anchor_target, anchor_parent_time,
            observed_parent_time, candidate_height, target, reads,
        })
    }
}
