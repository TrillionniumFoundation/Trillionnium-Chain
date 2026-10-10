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
        let mut remainder = Self::default();
        let mut quotient = Self::default();
        for bit in (0..512).rev() {
            let (shifted, overflow) = remainder.shifted((self.0[bit / 64] >> (bit % 64)) & 1);
            remainder = shifted;
            if overflow || remainder >= divisor {
                remainder = remainder.wrapping_sub(divisor);
                quotient.0[bit / 64] |= 1u64 << (bit % 64);
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
