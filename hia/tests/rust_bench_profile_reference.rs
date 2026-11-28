//! Qualification adapter: calls the entire unchanged executor include!.
use std::io::{self, BufRead};

#[allow(dead_code)]
mod original {
    include!(env!("TRNM_EXECUTOR_SOURCE"));
}

fn float(value: f64) -> String {
    format!("{:016x}|{value:.4}", value.to_bits())
}
fn integer(value: usize) -> String {
    format!("{value:016x}|{value}")
}
fn stage(value: &str) -> String {
    let code: u64 = match value {
        "none" => 0,
        "ww" => 1,
        "wr" => 2,
        "rw" => 3,
        "mixed" => 4,
        _ => panic!("unknown original stage"),
    };
    format!("{code:016x}|{value}")
}
fn profile(words: &[u64]) -> String {
    assert_eq!(words.len(), 17);
    let p = original::GroupingProfile {
        tx_count: words[0] as usize,
        group_count: words[1] as usize,
        grouped_count: words[2] as usize,
        max_group_size: words[3] as usize,
        min_group_size: words[4] as usize,
        avg_group_size: f64::from_bits(words[5]),
        hot_object_share: f64::from_bits(words[6]),
        conflict_checks: words[7] as usize,
        conflict_hits: words[8] as usize,
        candidate_groups_scanned: words[9] as usize,
        retry_fallback_new_groups: words[10] as usize,
        stage_ww_checks: words[11] as usize,
        stage_ww_hits: words[12] as usize,
        stage_wr_checks: words[13] as usize,
        stage_wr_hits: words[14] as usize,
        stage_rw_checks: words[15] as usize,
        stage_rw_hits: words[16] as usize,
    };
    [
        float(p.conflict_checks_per_tx()),
        float(p.conflict_hits_per_tx()),
        float(p.candidate_groups_per_tx()),
        float(p.retry_fallback_new_group_share()),
        float(p.retry_fallback_share_of_new_groups()),
        float(p.retry_fallback_share_of_retry_hits()),
        float(p.retry_fallback_scan_share()),
        float(p.retry_pressure()),
        integer(p.reused_group_placements()),
        float(p.reused_group_share()),
        float(p.new_group_share()),
        float(p.candidate_groups_per_retry_hit()),
        float(p.candidate_groups_per_reused_placement()),
        float(p.retry_scan_reuse_rate()),
        float(p.retry_reuse_salvage_rate()),
        float(p.retry_scan_hit_rate()),
        integer(p.retry_scan_misses()),
        float(p.retry_scan_miss_rate()),
        float(p.retry_scan_misses_per_tx()),
        float(p.retry_scan_misses_per_group()),
        float(p.retry_scan_overhang_per_hit()),
        float(p.retry_scan_overhang_per_reused_placement()),
        float(p.retry_fallback_share_of_retry_misses()),
        float(p.ww_retry_hit_rate()),
        float(p.wr_retry_hit_rate()),
        float(p.rw_retry_hit_rate()),
        float(p.ww_retry_hits_per_tx()),
        float(p.wr_retry_hits_per_tx()),
        float(p.rw_retry_hits_per_tx()),
        float(p.ww_retry_share()),
        float(p.wr_retry_share()),
        float(p.rw_retry_share()),
        stage(p.dominant_retry_stage()),
        float(p.dominant_retry_share()),
        float(p.dominant_attributed_retry_share()),
        integer(p.dominant_retry_lead_hits()),
        float(p.dominant_retry_lead_share()),
        float(p.dominant_attributed_retry_lead_share()),
        integer(p.attributed_retry_hits()),
        integer(p.unattributed_retry_hits()),
        float(p.unattributed_retry_share()),
        float(p.retry_attribution_coverage()),
        integer(p.retry_stage_overlap_hits()),
        float(p.retry_stage_overlap_share()),
        float(p.retry_stage_overlap_share_of_attributed()),
        integer(p.singly_attributed_retry_hits()),
        float(p.singly_attributed_retry_share()),
        float(p.singly_attributed_retry_share_of_attributed()),
        float(p.retry_stage_concentration()),
        float(p.retry_stage_mix_entropy()),
        float(if p.conflict_checks == 0 {
            0.0
        } else {
            p.conflict_hits as f64 / p.conflict_checks as f64
        }),
    ]
    .join(" ")
}

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let mut parts = line.split_whitespace();
        let mode = parts.next().unwrap();
        let words: Vec<u64> = parts.map(|s| u64::from_str_radix(s, 16).unwrap()).collect();
        let answer = std::panic::catch_unwind(|| match mode {
            "L" => {
                assert_eq!(words.len(), 1);
                float(f64::from_bits(words[0]).ln())
            }
            "F" => {
                assert_eq!(words.len(), 1);
                float(f64::from_bits(words[0]))
            }
            "P" => profile(&words),
            _ => panic!("unknown adapter mode"),
        });
        match answer {
            Ok(value) => println!("ok {value}"),
            Err(_) => println!("panic"),
        }
    }
}
