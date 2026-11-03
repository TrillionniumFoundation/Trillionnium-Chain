
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
