pub(crate) fn parse_env_numeric(name: &str) -> Option<String> {
    std::env::var(name).ok().and_then(|v| {
        let trimmed = v.trim();
        if trimmed.is_empty() {
            return None;
        }

        let unquoted = trimmed
            .strip_prefix('"')
            .and_then(|inner| inner.strip_suffix('"'))
            .or_else(|| {
                trimmed
                    .strip_prefix('\'')
                    .and_then(|inner| inner.strip_suffix('\''))
            })
            .map(str::trim)
            .unwrap_or(trimmed);
        if unquoted.is_empty() {
            return None;
        }

        // Accept common human-friendly separators in ops configs.
        if unquoted.contains('_') || unquoted.contains(',') {
            let mut compact = String::with_capacity(unquoted.len());
            for ch in unquoted.chars() {
                if ch != '_' && ch != ',' {
                    compact.push(ch);
                }
            }
            if compact.is_empty() {
                None
            } else {
                Some(compact)
            }
        } else {
            Some(unquoted.to_owned())
        }
    })
}

#[inline]
pub(crate) fn parse_env_usize(name: &str) -> Option<usize> {
    parse_env_numeric(name).and_then(|v| {
        let normalized = v.strip_prefix('+').unwrap_or(&v);
        (!normalized.is_empty())
            .then(|| normalized.parse::<usize>().ok())
            .flatten()
    })
}

#[inline]
pub(crate) fn parse_grouped_env_usize(name: &str) -> Option<usize> {
    std::env::var(name).ok().and_then(|v| {
        let trimmed = v.trim();
        if trimmed.is_empty() {
            return None;
        }

        let unquoted = trimmed
            .strip_prefix('"')
            .and_then(|inner| inner.strip_suffix('"'))
            .or_else(|| {
                trimmed
                    .strip_prefix('\'')
                    .and_then(|inner| inner.strip_suffix('\''))
            })
            .map(str::trim)
            .unwrap_or(trimmed);
        if unquoted.is_empty() {
            return None;
        }

        let compact: String = unquoted.chars().filter(|&ch| ch != '_').collect();
        if compact.is_empty() || compact.chars().all(|ch| ch == ',') {
            return None;
        }

        let normalized = compact.strip_prefix('+').unwrap_or(&compact);
        if normalized.is_empty() {
            return None;
        }

        if normalized.contains(',') {
            let mut parts = normalized.split(',');
            let first = parts.next().unwrap_or("");
            let rest: Vec<&str> = parts.collect();
            let comma_is_grouping = !first.is_empty()
                && first.chars().all(|ch| ch.is_ascii_digit())
                && rest.iter().all(|segment| {
                    segment.len() == 3 && segment.chars().all(|ch| ch.is_ascii_digit())
                });
            if !comma_is_grouping {
                return None;
            }
            return normalized.replace(',', "").parse::<usize>().ok();
        }

        normalized.parse::<usize>().ok()
    })
}

#[inline]
pub(crate) fn parse_env_f64(name: &str) -> Option<f64> {
    std::env::var(name).ok().and_then(|v| {
        let trimmed = v.trim();
        if trimmed.is_empty() {
            return None;
        }

        let unquoted = trimmed
            .strip_prefix('"')
            .and_then(|inner| inner.strip_suffix('"'))
            .or_else(|| {
                trimmed
                    .strip_prefix('\'')
                    .and_then(|inner| inner.strip_suffix('\''))
            })
            .map(str::trim)
            .unwrap_or(trimmed);
        if unquoted.is_empty() {
            return None;
        }

        let mut compact = String::with_capacity(unquoted.len());
        for ch in unquoted.chars() {
            if ch != '_' {
                compact.push(ch);
            }
        }
        if compact.is_empty() || compact.chars().all(|ch| ch == ',') {
            return None;
        }

        let percent = compact.ends_with('%');
        let numeric = if percent {
            compact.strip_suffix('%').unwrap_or(&compact)
        } else {
            &compact
        };
        if numeric.is_empty() {
            return None;
        }

        let normalized = if numeric.contains(',') && !numeric.contains('.') {
            let comma_count = numeric.chars().filter(|&ch| ch == ',').count();
            if comma_count == 1 {
                let (whole, frac) = numeric.split_once(',').unwrap_or((numeric, ""));
                let whole_is_optional_sign = whole.is_empty() || whole == "+" || whole == "-";
                if whole_is_optional_sign
                    && !frac.is_empty()
                    && frac.chars().all(|ch| ch.is_ascii_digit())
                {
                    let sign = if whole == "-" { "-" } else { "" };
                    format!("{sign}0.{frac}")
                } else if !whole.is_empty()
                    && !frac.is_empty()
                    && whole
                        .chars()
                        .all(|ch| ch == '+' || ch == '-' || ch.is_ascii_digit())
                    && frac.chars().all(|ch| ch.is_ascii_digit())
                {
                    let whole_digits = whole.trim_start_matches(['+', '-']);
                    let whole_is_zero =
                        !whole_digits.is_empty() && whole_digits.chars().all(|ch| ch == '0');
                    let comma_is_grouping = frac.len() == 3
                        && whole.chars().any(|ch| ch.is_ascii_digit())
                        && !whole_is_zero;
                    if comma_is_grouping {
                        numeric.replace(',', "")
                    } else {
                        numeric.replace(',', ".")
                    }
                } else {
                    numeric.replace(',', "")
                }
            } else {
                let mut parts = numeric.split(',');
                let whole = parts.next().unwrap_or("");
                let frac_or_groups: Vec<&str> = parts.collect();
                let comma_is_grouping = !whole.is_empty()
                    && whole
                        .chars()
                        .all(|ch| ch == '+' || ch == '-' || ch.is_ascii_digit())
                    && whole.chars().any(|ch| ch.is_ascii_digit())
                    && frac_or_groups.iter().all(|segment| {
                        segment.len() == 3 && segment.chars().all(|ch| ch.is_ascii_digit())
                    });
                if !comma_is_grouping {
                    return None;
                }
                numeric.replace(',', "")
            }
        } else {
            numeric.replace(',', "")
        };

        let parsed = normalized.parse::<f64>().ok()?;
        if !parsed.is_finite() {
            return None;
        }
        let value = if percent { parsed / 100.0 } else { parsed };
        value.is_finite().then_some(value)
    })
}

pub(crate) fn aggr_scan_window() -> usize {
    const DEFAULT_SCAN_WINDOW: usize = 0;
    const MAX_SCAN_WINDOW: usize = 4096;

    parse_grouped_env_usize("TRNM_AGGR_SCAN_WINDOW")
        .map(|v| v.min(MAX_SCAN_WINDOW))
        .filter(|&v| v > 0)
        .unwrap_or_else(|| {
            if aggr_deep_scan_enabled() {
                DEFAULT_SCAN_WINDOW
            } else {
                0
            }
        })
}

pub(crate) fn env_toggle_enabled(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| {
            let trimmed = v.trim();
            let unquoted = trimmed
                .strip_prefix('"')
                .and_then(|inner| inner.strip_suffix('"'))
                .or_else(|| {
                    trimmed
                        .strip_prefix('\'')
                        .and_then(|inner| inner.strip_suffix('\''))
                })
                .unwrap_or(trimmed);
            let s = unquoted.trim().to_ascii_lowercase();
            if s.is_empty() || s.chars().all(|ch| ch == '_' || ch == ',') {
                return default;
            }
            !(s == "0" || s == "false" || s == "off" || s == "no")
        })
        .unwrap_or(default)
}

pub(crate) fn aggr_skip_empty_stage_checks() -> bool {
    env_toggle_enabled("TRNM_AGGR_SKIP_EMPTY_STAGE_CHECKS", true)
}

pub(crate) fn aggr_deep_scan_enabled() -> bool {
    env_toggle_enabled("TRNM_AGGR_DEEP_SCAN", false)
}

pub(crate) fn aggr_scan_round_robin_enabled() -> bool {
    env_toggle_enabled("TRNM_AGGR_SCAN_ROUND_ROBIN", true)
}

pub(crate) fn aggr_scan_round_robin_seed() -> usize {
    parse_grouped_env_usize("TRNM_AGGR_SCAN_RR_SEED").unwrap_or(0)
}

pub(crate) fn auto_hot_streak_threshold() -> f64 {
    parse_env_f64("TRNM_AUTO_HOT_STREAK_RATIO")
        .map(|v| v.clamp(0.0, 1.0))
        .unwrap_or(0.22)
}

pub(crate) fn auto_reorder_min_margin() -> f64 {
    parse_env_f64("TRNM_AUTO_REORDER_MIN_MARGIN")
        .map(|v| v.clamp(0.0, 1.0))
        .unwrap_or(0.04)
}

pub(crate) fn auto_reorder_min_hot_key_share() -> f64 {
    parse_env_f64("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE")
        .map(|v| v.clamp(0.0, 1.0))
        .unwrap_or(0.0075)
}

pub(crate) fn hot_bucket_count() -> usize {
    parse_env_usize("TRNM_HOT_BUCKETS")
        .map(|v| v.clamp(4, 64))
        .unwrap_or(8)
}

pub(crate) fn auto_min_expected_gain_score() -> f64 {
    parse_env_f64("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE")
        .map(|v| v.clamp(0.0, 1.0))
        .unwrap_or(0.01)
}

pub(crate) fn auto_adaptive_min_batch_len() -> usize {
    const DEFAULT_MIN_BATCH_LEN: usize = 512;
    const MIN_BATCH_LEN_FLOOR: usize = 64;
    const MIN_BATCH_LEN_CEIL: usize = 4096;

    parse_grouped_env_usize("TRNM_AUTO_MIN_BATCH_LEN")
        .map(|v| v.clamp(MIN_BATCH_LEN_FLOOR, MIN_BATCH_LEN_CEIL))
        .unwrap_or(DEFAULT_MIN_BATCH_LEN)
}

pub(crate) fn auto_adaptive_sample_len(batch_len: usize) -> usize {
    const MAX_SAMPLE_LEN: usize = 2048;
    const MIN_SAMPLE_LEN_FLOOR: usize = 64;
    const MIN_SAMPLE_LEN_CEIL: usize = MAX_SAMPLE_LEN;

    let configured = parse_grouped_env_usize("TRNM_AUTO_SAMPLE_LEN")
        .map(|v| v.clamp(MIN_SAMPLE_LEN_FLOOR, MIN_SAMPLE_LEN_CEIL))
        .unwrap_or(MAX_SAMPLE_LEN);

    batch_len.min(configured)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    struct EnvGuard {
        name: &'static str,
        old: Option<String>,
    }

    impl EnvGuard {
        fn set(name: &'static str, value: &str) -> Self {
            let old = std::env::var(name).ok();
            unsafe {
                std::env::set_var(name, value);
            }
            Self { name, old }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.old {
                Some(value) => unsafe {
                    std::env::set_var(self.name, value);
                },
                None => unsafe {
                    std::env::remove_var(self.name);
                },
            }
        }
    }

    fn env_lock() -> MutexGuard<'static, ()> {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        match ENV_LOCK.get_or_init(|| Mutex::new(())).lock() {
            Ok(guard) => guard,
            Err(err) => err.into_inner(),
        }
    }

    #[test]
    fn parse_env_f64_accepts_leading_comma_decimals_and_percentages() {
        let _env = env_lock();

        let _decimal = EnvGuard::set("TRNM_TEST_F64", " '+,125' ");
        assert_eq!(parse_env_f64("TRNM_TEST_F64"), Some(0.125));
        drop(_decimal);

        let _percent = EnvGuard::set("TRNM_TEST_F64", " \"+,5%\" ");
        assert_eq!(parse_env_f64("TRNM_TEST_F64"), Some(0.005));
    }

    #[test]
    fn parse_grouped_env_usize_accepts_quoted_plus_prefixed_comma_grouped_values() {
        let _env = env_lock();
        let _value = EnvGuard::set("TRNM_TEST_USIZE", " '+1,536' ");

        assert_eq!(parse_grouped_env_usize("TRNM_TEST_USIZE"), Some(1536));
    }

    #[test]
    fn auto_adaptive_sample_len_preserves_empty_batches_under_env_floor() {
        let _env = env_lock();
        let _sample = EnvGuard::set("TRNM_AUTO_SAMPLE_LEN", "8");

        assert_eq!(auto_adaptive_sample_len(0), 0);
        assert_eq!(auto_adaptive_sample_len(32), 32);
        assert_eq!(auto_adaptive_sample_len(5000), 64);
    }
}
