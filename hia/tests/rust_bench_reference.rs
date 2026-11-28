//! Transport around the unchanged original bench. No workload, scheduler,
//! digest, or profile algorithm is copied into this qualification adapter.
use std::io::{self, BufRead};

#[allow(dead_code)]
mod original {
    include!(env!("TRNM_BENCH_SOURCE"));

    fn word(out: &mut Vec<u8>, value: u64) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    pub fn observe(words: &[u64]) -> String {
        assert_eq!(words.len(), 6);
        let workload = match words[0] {
            0 => Workload::Classic,
            1 => Workload::Mixed,
            2 => Workload::HotStreak,
            _ => panic!("invalid test workload"),
        };
        let strategy = match words[5] {
            0 => StrategyArg::Original,
            1 => StrategyArg::FootprintDesc,
            2 => StrategyArg::WriteFirst,
            3 => StrategyArg::WriteLast,
            4 => StrategyArg::HotBucketInterleave,
            5 => StrategyArg::AutoAdaptive,
            6 => StrategyArg::AggressiveGreedy,
            _ => panic!("invalid test strategy"),
        };
        let n = (words[1] as usize).max(1);
        let keys = (words[2] as usize).max(1);
        let fan = (words[3] as usize).max(1);
        let every = (words[4] as usize).max(1);
        let txs = match workload {
            Workload::Classic => build_classic_txs(n, keys),
            Workload::Mixed => build_mixed_txs(n, keys, fan, every),
            Workload::HotStreak => build_hot_streak_txs(n, keys, fan, every),
        };
        let mut frame = b"EXSCH001".to_vec();
        for value in [
            0,
            words[5],
            n as u64,
            6,
            8,
            512,
            2048,
            0,
            0,
            0.22_f64.to_bits(),
            0.04_f64.to_bits(),
            0.0075_f64.to_bits(),
            0.01_f64.to_bits(),
            0,
            0,
        ] {
            word(&mut frame, value);
        }
        for tx in &txs {
            for value in [
                tx.id,
                tx.read_set.len() as u64,
                tx.write_set.len() as u64,
                tx.payload.len() as u64,
            ] {
                word(&mut frame, value);
            }
            for object in tx.read_set.iter().chain(&tx.write_set) {
                word(&mut frame, object.id);
                word(&mut frame, object.version);
            }
            frame.extend_from_slice(&tx.payload);
        }
        let (groups, p) = build_parallel_groups_profile_with_strategy(&txs, strategy.into());
        let mut answer = b"EXSCOUT1".to_vec();
        let decision = if matches!(strategy, StrategyArg::AutoAdaptive) {
            Some(auto_adaptive_decision(&txs))
        } else {
            None
        };
        let selected = match &decision {
            Some(d) => {
                if d.use_hot_bucket {
                    4
                } else {
                    0
                }
            }
            None => words[5],
        };
        for value in [
            0,
            n as u64,
            groups.len() as u64,
            selected,
            p.tx_count as u64,
            p.group_count as u64,
            p.grouped_count as u64,
            p.max_group_size as u64,
            p.min_group_size as u64,
            p.avg_group_size.to_bits(),
            p.hot_object_share.to_bits(),
            p.conflict_checks as u64,
            p.conflict_hits as u64,
            p.candidate_groups_scanned as u64,
            p.retry_fallback_new_groups as u64,
            p.stage_ww_checks as u64,
            p.stage_ww_hits as u64,
            p.stage_wr_checks as u64,
            p.stage_wr_hits as u64,
            p.stage_rw_checks as u64,
            p.stage_rw_hits as u64,
        ] {
            word(&mut answer, value);
        }
        let adaptive = decision
            .map(|d| {
                let reason = match d.reason {
                    "small_batch" => 1,
                    "insufficient_sample" => 2,
                    "hotspot_detected" => 3,
                    "low_hot_key_share" => 4,
                    "low_expected_gain" => 5,
                    "below_streak_budget" => 6,
                    _ => panic!("unknown adaptive reason: {}", d.reason),
                };
                [
                    u64::from(d.use_hot_bucket),
                    reason,
                    d.sample_len as u64,
                    d.streak_ratio.to_bits(),
                    d.streak_threshold.to_bits(),
                    d.min_margin.to_bits(),
                    d.hot_key_share.to_bits(),
                    d.min_hot_key_share.to_bits(),
                    d.expected_gain_score.to_bits(),
                    d.min_expected_gain_score.to_bits(),
                ]
            })
            .unwrap_or([0; 10]);
        for value in adaptive {
            word(&mut answer, value);
        }
        let mut count = 0;
        word(&mut answer, 0);
        for group in &groups {
            count += group.len() as u64;
            word(&mut answer, count);
        }
        for group in &groups {
            for tx in group {
                word(&mut answer, tx.id);
            }
        }
        format!(
            "{}\t{}\t{}\t{}",
            hex_digest(frame),
            workload_input_digest(&txs),
            grouping_digest(&groups),
            hex_digest(answer)
        )
    }
}

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let words = line
            .split_whitespace()
            .map(|s| s.parse::<u64>().unwrap())
            .collect::<Vec<_>>();
        println!("{}", original::observe(&words));
    }
}
