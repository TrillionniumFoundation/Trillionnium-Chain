pub(crate) fn percentile(mut vals: Vec<u128>, p: f64) -> u128 {
    if vals.is_empty() {
        return 0;
    }
    vals.sort_unstable();
    let idx = ((vals.len() - 1) as f64 * p).round() as usize;
    vals[idx.min(vals.len() - 1)]
}

pub(crate) fn max_or_zero(vals: &[u128]) -> u128 {
    vals.iter().copied().max().unwrap_or(0)
}

pub(crate) fn average_or_zero(vals: &[u128]) -> u128 {
    if vals.is_empty() {
        0
    } else {
        vals.iter().copied().sum::<u128>() / vals.len() as u128
    }
}

pub(crate) fn ratio_ppm(numerator: u128, denominator: u128) -> u128 {
    if denominator == 0 {
        0
    } else {
        numerator.saturating_mul(1_000_000) / denominator
    }
}

pub(crate) fn ratio_ppm_u64(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        0
    } else {
        numerator.saturating_mul(1_000_000) / denominator
    }
}

pub(crate) fn ratio_percent_bps(numerator: u128, denominator: u128) -> u128 {
    if denominator == 0 {
        0
    } else {
        numerator.saturating_mul(10_000) / denominator
    }
}

pub(crate) fn ratio_milli_u64(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        0
    } else {
        numerator.saturating_mul(1_000) / denominator
    }
}

pub(crate) fn finality_budget_share_ppm(density_avg_milli: u64, finality_avg_ms: u128) -> u64 {
    let finality_avg_ms_u64 = u64::try_from(finality_avg_ms).unwrap_or(u64::MAX);
    let finality_budget_milli = finality_avg_ms_u64.saturating_mul(1_000);
    ratio_ppm_u64(density_avg_milli, finality_budget_milli)
}

pub(crate) fn wall_time_share_ppm(
    total_ms: u64,
    committed_heights: u64,
    finality_avg_ms: u128,
) -> u64 {
    if committed_heights == 0 {
        return 0;
    }
    let finality_avg_ms_u64 = u64::try_from(finality_avg_ms).unwrap_or(u64::MAX);
    let total_budget_ms = committed_heights.saturating_mul(finality_avg_ms_u64);
    ratio_ppm_u64(total_ms, total_budget_ms)
}

pub(crate) fn gap_percent_bps(total: u128, component_a: u128, component_b: u128) -> u128 {
    if total == 0 {
        return 0;
    }
    total
        .saturating_sub(component_a.saturating_add(component_b))
        .saturating_mul(10_000)
        / total
}
