//! Adapter only: all scheduling/conflict/decision code is the unchanged
//! trnm-executor Cargo library. The transport uses the native candidate frame;
//! the test corpus assigns a unique opaque payload to identify returned clones.
use std::collections::HashMap;
use std::io::{self, Read, Write};
use trnm_executor::{auto_adaptive_decision, build_parallel_groups,
    build_parallel_groups_profile, build_parallel_groups_profile_with_strategy,
    detect_conflict, AutoAdaptiveDecision, GroupingProfile, GroupingStrategy};
use trnm_types::{ObjectRef, Tx};

fn word(raw: &[u8], position: usize) -> Result<u64, &'static str> {
    let part = raw.get(position..position.checked_add(8).ok_or("overflow")?)
        .ok_or("truncated word")?;
    Ok(u64::from_le_bytes(part.try_into().map_err(|_| "word extent")?))
}

fn put(raw: &mut [u8], position: usize, value: u64) {
    raw[position..position+8].copy_from_slice(&value.to_le_bytes());
}

fn parse(raw: &[u8]) -> Result<(u64, u64, Vec<Tx>), &'static str> {
    if raw.len() < 128 || &raw[..8] != b"EXSCH001" { return Err("bad header"); }
    let operation = word(raw, 8)?;
    let strategy = word(raw, 16)?;
    let count = usize::try_from(word(raw, 24)?).map_err(|_| "count overflow")?;
    if operation > 2 || strategy > 6 || (operation == 1 && count != 2)
        || word(raw, 32)? > 7 || word(raw, 112)? != 0 || word(raw, 120)? != 0 {
        return Err("unsupported header");
    }
    for (position, low, high) in [(40,4,64),(48,64,4096),(56,64,2048),(64,0,4096)] {
        let value = word(raw, position)?;
        if value < low || value > high { return Err("invalid effective integer config"); }
    }
    for position in [80,88,96,104] {
        let value = f64::from_bits(word(raw, position)?);
        if !value.is_finite() || !(0.0..=1.0).contains(&value) {
            return Err("invalid effective binary64 config");
        }
    }
    if count > (raw.len()-128)/32 { return Err("count exceeds frame"); }
    let mut position = 128usize;
    let mut txs = Vec::with_capacity(count);
    for _ in 0..count {
        let identity = word(raw, position)?;
        let reads = usize::try_from(word(raw, position+8)?).map_err(|_| "read count")?;
        let writes = usize::try_from(word(raw, position+16)?).map_err(|_| "write count")?;
        let payload = usize::try_from(word(raw, position+24)?).map_err(|_| "payload count")?;
        position = position.checked_add(32).ok_or("overflow")?;
        let references = reads.checked_add(writes).ok_or("overflow")?;
        if references > raw.len().saturating_sub(position)/16 { return Err("reference extent"); }
        let mut refs = Vec::with_capacity(references);
        for _ in 0..references {
            refs.push(ObjectRef {id: word(raw, position)?, version: word(raw, position+8)?});
            position += 16;
        }
        let payload_end = position.checked_add(payload).ok_or("overflow")?;
        let data = raw.get(position..payload_end).ok_or("payload extent")?.to_vec();
        position = payload_end;
        txs.push(Tx {id: identity, read_set: refs[..reads].to_vec(),
                     write_set: refs[reads..].to_vec(), payload: data});
    }
    if position != raw.len() { return Err("trailing bytes"); }
    Ok((operation, strategy, txs))
}

fn configure(raw: &[u8]) -> Result<(), &'static str> {
    let flags = word(raw, 32)?;
    for (name, bit) in [("TRNM_AGGR_DEEP_SCAN",1),
                        ("TRNM_AGGR_SKIP_EMPTY_STAGE_CHECKS",2),
                        ("TRNM_AGGR_SCAN_ROUND_ROBIN",4)] {
        std::env::set_var(name, if flags & bit != 0 { "true" } else { "false" });
    }
    for (name, position) in [("TRNM_HOT_BUCKETS",40), ("TRNM_AUTO_MIN_BATCH_LEN",48),
        ("TRNM_AUTO_SAMPLE_LEN",56), ("TRNM_AGGR_SCAN_WINDOW",64),
        ("TRNM_AGGR_SCAN_RR_SEED",72)] {
        std::env::set_var(name, word(raw, position)?.to_string());
    }
    for (name, position) in [("TRNM_AUTO_HOT_STREAK_RATIO",80),
        ("TRNM_AUTO_REORDER_MIN_MARGIN",88), ("TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE",96),
        ("TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE",104)] {
        // Round-trip decimal representation, including -0 and subnormals.
        // The original parser is still executed; no hidden replacement occurs.
        std::env::set_var(name, f64::from_bits(word(raw, position)?).to_string());
    }
    Ok(())
}

fn profile_words(profile: &GroupingProfile) -> [u64;17] {
    [profile.tx_count as u64, profile.group_count as u64, profile.grouped_count as u64,
     profile.max_group_size as u64, profile.min_group_size as u64,
     profile.avg_group_size.to_bits(), profile.hot_object_share.to_bits(),
     profile.conflict_checks as u64, profile.conflict_hits as u64,
     profile.candidate_groups_scanned as u64, profile.retry_fallback_new_groups as u64,
     profile.stage_ww_checks as u64, profile.stage_ww_hits as u64,
     profile.stage_wr_checks as u64, profile.stage_wr_hits as u64,
     profile.stage_rw_checks as u64, profile.stage_rw_hits as u64]
}

fn decision_words(decision: &AutoAdaptiveDecision) -> [u64;10] {
    let reason = match decision.reason {
        "small_batch" => 1, "insufficient_sample" => 2, "hotspot_detected" => 3,
        "low_hot_key_share" => 4, "low_expected_gain" => 5,
        "below_streak_budget" => 6, _ => panic!("unknown original reason")};
    [u64::from(decision.use_hot_bucket), reason, decision.sample_len as u64,
     decision.streak_ratio.to_bits(), decision.streak_threshold.to_bits(),
     decision.min_margin.to_bits(), decision.hot_key_share.to_bits(),
     decision.min_hot_key_share.to_bits(), decision.expected_gain_score.to_bits(),
     decision.min_expected_gain_score.to_bits()]
}

fn execute(raw: &[u8]) -> Result<Vec<u8>, &'static str> {
    let (operation, strategy, txs) = parse(raw)?;
    configure(raw)?;
    let variants = [GroupingStrategy::Original, GroupingStrategy::FootprintDesc,
        GroupingStrategy::WriteFirst, GroupingStrategy::WriteLast,
        GroupingStrategy::HotBucketInterleave, GroupingStrategy::AutoAdaptive,
        GroupingStrategy::AggressiveGreedy];
    let mut selected = strategy;
    let mut decision = [0u64;10];
    let mut profile = [0u64;17];
    let mut groups: Vec<Vec<Tx>> = Vec::new();
    let mut count = 0;
    if operation == 1 {
        count = u64::from(detect_conflict(&txs[0], &txs[1]));
    } else {
        if operation == 2 || (strategy == 5 && !txs.is_empty()) {
            let observed = auto_adaptive_decision(&txs);
            decision = decision_words(&observed);
            if operation == 0 { selected = if observed.use_hot_bucket {4} else {0}; }
        }
        if operation == 0 {
            let (observed_groups, observed_profile) =
                build_parallel_groups_profile_with_strategy(&txs, variants[strategy as usize]);
            if strategy == 0 {
                // Also exercise both public Original wrappers without replacing
                // any private implementation or version validation helper.
                assert_eq!(build_parallel_groups(&txs), observed_groups);
                let (wrapper_groups, wrapper_profile) = build_parallel_groups_profile(&txs);
                assert_eq!(wrapper_groups, observed_groups);
                assert_eq!(profile_words(&wrapper_profile), profile_words(&observed_profile));
            }
            groups = observed_groups;
            profile = profile_words(&observed_profile);
            count = groups.len() as u64;
        }
    }
    let size = if operation == 0 {264 + 8 * (txs.len()+groups.len())} else {256};
    let mut result = vec![0u8;size];
    result[..8].copy_from_slice(b"EXSCOUT1");
    for (position, value) in [(8,operation),(16,txs.len() as u64),(24,count),(32,selected)] {
        put(&mut result, position, value);
    }
    for (index, value) in profile.into_iter().enumerate() { put(&mut result, 40+8*index, value); }
    for (index, value) in decision.into_iter().enumerate() { put(&mut result, 176+8*index, value); }
    if operation == 0 {
        let mut by_payload: HashMap<&[u8],usize> = HashMap::new();
        for (index, tx) in txs.iter().enumerate() {
            if by_payload.insert(&tx.payload,index).is_some() {
                return Err("oracle test corpus requires unique opaque payloads");
            }
        }
        let mut seen = vec![false;txs.len()];
        let mut cursor = 0;
        let indices = 264+8*groups.len();
        for (group_index, group) in groups.iter().enumerate() {
            put(&mut result, 256+8*group_index, cursor as u64);
            for tx in group {
                let index = *by_payload.get(tx.payload.as_slice()).ok_or("changed payload")?;
                if seen[index] || tx != &txs[index] { return Err("changed or duplicate transaction"); }
                seen[index] = true;
                put(&mut result, indices+8*cursor, index as u64);
                cursor += 1;
            }
        }
        if cursor != txs.len() || seen.iter().any(|value| !value) { return Err("lost transaction"); }
        put(&mut result, 256+8*groups.len(), cursor as u64);
    }
    Ok(result)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if usize::BITS != 64 { return Err("reference qualification requires the original x64 usize domain".into()); }
    // Panics are recorded as panics, never recast as a successful reference call.
    std::panic::set_hook(Box::new(|_| {}));
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    loop {
        let mut length = [0u8;8];
        let first = input.read(&mut length[..1])?;
        if first == 0 { break; }
        input.read_exact(&mut length[1..])?;
        let size = usize::try_from(u64::from_le_bytes(length))?;
        if size > 64 << 20 { return Err("oracle transport development budget exceeded".into()); }
        let mut raw = vec![0u8;size];
        input.read_exact(&mut raw)?;
        let (status, payload) = match std::panic::catch_unwind(|| execute(&raw)) {
            Ok(Ok(value)) => (0u64, value),
            Err(_) => (1u64, b"original Rust panic".to_vec()),
            Ok(Err(reason)) => (2u64, reason.as_bytes().to_vec()),
        };
        output.write_all(&status.to_le_bytes())?;
        output.write_all(&(payload.len() as u64).to_le_bytes())?;
        output.write_all(&payload)?;
    }
    output.flush()?;
    Ok(())
}
