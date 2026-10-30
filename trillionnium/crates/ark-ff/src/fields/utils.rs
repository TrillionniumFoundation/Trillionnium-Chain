/// Calculates the k-adicity of n, i.e., the number of trailing 0s in a base-k
/// representation.
pub fn k_adicity(k: u64, mut n: u64) -> u32 {
    let mut r = 0;
    while n > 1 {
        // A radix of one cannot reduce n; zero cannot be a divisor.
        assert!(k >= 2, "adicity base must be at least two");
        if n.is_multiple_of(k) {
            r += 1;
            n /= k;
        } else {
            return r;
        }
    }
    r
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::k_adicity;

    #[test]
    fn test_k_adicity_valid_bases_and_original_small_input_returns() {
        for (base, value, expected) in [
            (2, 8, 3),
            (3, 81, 4),
            (3, 82, 0),
            (2, u64::MAX, 0),
            (u64::MAX, u64::MAX, 1),
            (0, 0, 0),
            (0, 1, 0),
            (1, 0, 0),
            (1, 1, 0),
        ] {
            assert_eq!(k_adicity(base, value), expected);
        }
    }

    #[test]
    fn test_k_adicity_rejects_zero_base_when_division_is_required() {
        assert!(std::panic::catch_unwind(|| k_adicity(0, 2)).is_err());
    }

    #[test]
    fn test_k_adicity_rejects_base_one_instead_of_entering_nonprogress_loop() {
        for value in [2, u64::MAX] {
            assert!(std::panic::catch_unwind(|| k_adicity(1, value)).is_err());
        }
    }
}
