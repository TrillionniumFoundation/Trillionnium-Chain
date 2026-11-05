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
