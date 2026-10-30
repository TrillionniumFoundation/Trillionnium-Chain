//! Shared real complete-W1 acquisition; no work/State or caller authority.
use super::{
    evidence,
    support::{signed_transfer as transfer, write_new as save},
};
use serde_json::{json, Value};
use std::{path::Path, time::Instant};
use trnm_crypto_primitives::pon_work::{self, PreparedTask};
use trnm_pon_node::{development_public, Node, Packet, Settings};
use trnm_protocol::pon_wire::hash;
pub(crate) const SEARCH_LIMIT: u64 = 4096;
pub(crate) const CAPACITY: usize = 4096;
pub(crate) const PREFIX_SECONDS: u64 = 1800;
pub(crate) const SCHEMA: &str = "public-v3-real-identity-prefix-v1";
pub(crate) const SCHEMA_V2: &str = "public-v3-real-identity-prefix-v2";

pub(crate) fn cpu() -> Option<u64> {
    use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
    let t = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ThreadCPUTime)).ok()?;
    u64::try_from(t.tv_sec)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(u64::try_from(t.tv_nsec).ok()?)
}
pub(crate) fn elapsed(start: Option<u64>) -> Option<u64> {
    cpu()?.checked_sub(start?)
}
pub(crate) fn seed(miner: &mut Node, settings: &Settings) -> Vec<Packet> {
    (0..4_u64)
        .map(|block| {
            let txs = (0..256_u64)
                .map(|slot| {
                    let nonce = block * 256 + slot + 1;
                    transfer(
                        settings,
                        nonce,
                        hash(b"multiprocess-funded-account-v1", &[&nonce.to_le_bytes()]),
                    )
                })
                .collect();
            let p = miner
                .make_consensus_maintenance(
                    miner.active().unwrap().0,
                    txs,
                    development_public(0).unwrap(),
                    settings.genesis_time() + (block + 1) * 10,
                    SEARCH_LIMIT,
                )
                .unwrap();
            let id = miner.admit(&p, settings.genesis_time() + 100_000).unwrap();
            miner.activate(id).unwrap();
            p
        })
        .collect()
}

pub(crate) fn nonce_start(index: usize) -> Option<u64> {
    2_000_000_u64.checked_add(u64::try_from(index).ok()?.checked_mul(SEARCH_LIMIT)?)
}
pub(crate) fn acquire(
    template: &Packet,
    producer: &PreparedTask,
    index: usize,
    path: &Path,
    end: Instant,
) -> Option<(Packet, Value)> {
    acquire_inner(template, producer, index, path, end, None)
}
pub(crate) fn acquire_v2(
    template: &Packet,
    producer: &PreparedTask,
    index: usize,
    path: &Path,
    end: Instant,
    budget: &mut evidence::Budget,
) -> Option<(Packet, Value)> {
    acquire_inner(template, producer, index, path, end, Some(budget))
}
fn acquire_inner(
    template: &Packet,
    producer: &PreparedTask,
    index: usize,
    path: &Path,
    end: Instant,
    mut budget: Option<&mut evidence::Budget>,
) -> Option<(Packet, Value)> {
    let v2 = budget.is_some();
    let schema = if v2 { SCHEMA_V2 } else { SCHEMA };
    let mut packet = template.clone();
    packet.header.state[0] ^= 1;
    let initial = nonce_start(index)?;
    let started_receipt = json!({"schema":schema,"index":index,
        "initial_nonce":initial,"attempt_limit":SEARCH_LIMIT,"template_header":hex::encode(template.header.encode())});
    let started_path = path.join(format!("{index:05}-started.json"));
    if let Some(b) = budget.as_deref_mut() {
        if b.poisoned || b.cap_reached || b.remaining() < 2 * evidence::CALL_BYTES {
            b.cap_reached = true;
            return None;
        }
        b.write(&started_path, &started_receipt, evidence::CALL_BYTES)
            .unwrap();
    } else {
        save(&started_path, &started_receipt);
    }
    let frame_limit = budget.as_ref().map(|b| {
        b.remaining()
            .saturating_sub(evidence::CALL_BYTES)
            .min(evidence::CONSTRUCTION_BYTES)
    });
    let started = Instant::now();
    let start_cpu = cpu();
    let mut attempts = Vec::new();
    let mut error = None;
    let mut winner = false;
    let mut attempt_bytes = 0;
    for offset in 0..SEARCH_LIMIT {
        if Instant::now() >= end {
            error = Some("outer-deadline".to_owned());
            break;
        }
        // Reserve the full successful proof, worst-case JSON row, winner packet,
        // and terminal metadata BEFORE prove. A discarded miss is forbidden.
        if frame_limit.is_some_and(|limit| {
            attempt_bytes + evidence::ATTEMPT_BYTES + evidence::FRAME_BYTES > limit
        }) {
            budget.as_deref_mut().unwrap().cap_reached = true;
            error = Some("evidence-cap".to_owned());
            break;
        }
        packet.header.nonce = initial.checked_add(offset)?;
        let trial_cpu = cpu();
        match producer.prove(packet.header.challenge()) {
            Ok(proof) => {
                let trace = &proof[proof.len() - 32..];
                let ticket = hash(b"ticket", &[&packet.header.challenge(), trace]);
                let hit = ticket <= packet.header.target;
                let mut row = json!({"nonce":packet.header.nonce,"trace":hex::encode(trace),
                    "ticket":hex::encode(ticket),"target_hit":hit,"thread_cpu_ns":elapsed(trial_cpu)});
                if v2 {
                    assert_eq!(proof.len(), pon_work::PROOF_BYTES);
                    row["proof"] = Value::String(hex::encode(&proof));
                    let bytes = evidence::encoded_bytes(&row).unwrap();
                    assert!(bytes <= evidence::ATTEMPT_BYTES);
                    attempt_bytes += bytes + 1;
                }
                attempts.push(row);
                if hit {
                    packet.proof = proof;
                    winner = true;
                    break;
                }
            }
            Err(e) => {
                attempts.push(json!({"nonce":packet.header.nonce,"error":format!("{e:?}"),"thread_cpu_ns":elapsed(trial_cpu)}));
                error = Some(format!("{e:?}"));
                break;
            }
        }
    }
    let construction_cpu = elapsed(start_cpu);
    let construction_wall = started.elapsed().as_nanos();
    let verification_cpu = cpu();
    let verified = winner
        && pon_work::verify(
            packet.header.challenge(),
            packet.header.work_task,
            packet.header.target,
            &packet.proof,
        )
        .is_ok();
    let reference = verified
        && pon_work::verify_reference(
            packet.header.challenge(),
            packet.header.work_task,
            packet.header.target,
            &packet.proof,
        )
        .is_ok();
    let wire = winner.then(|| packet.encode().unwrap());
    let mut receipt = json!({"schema":schema,"index":index,"initial_nonce":initial,"attempt_limit":SEARCH_LIMIT,
        "status":if error.is_some(){"producer-error"}else if winner{"winner"}else{"exhausted"},"error":error,
        "construction_thread_cpu_ns":construction_cpu,"construction_wall_ns":construction_wall,
        "verification_thread_cpu_ns":elapsed(verification_cpu),"production_verified":verified,"reference_verified":reference,
        "packet":wire.as_ref().map(hex::encode),
        "completion_identity":wire.as_ref().map(|w|hex::encode(hash(b"public-v3-complete-work-identity-v1", &[w])))});
    // Move the bounded array; serde_json::json! would clone every proof string.
    receipt["attempts"] = Value::Array(attempts);
    let construction_path = path.join(format!("{index:05}-construction.json"));
    if let Some(b) = budget {
        receipt["evidence_budget"] = json!({"stage_limit_bytes":b.limit,"stage_used_before_bytes":b.used,
            "per_construction_limit_bytes":evidence::CONSTRUCTION_BYTES,"frame_limit_bytes":frame_limit,
            "frame_reservation_bytes":evidence::FRAME_BYTES,"attempt_reservation_bytes":evidence::ATTEMPT_BYTES,
            "attempt_serialized_bytes":attempt_bytes,"working_buffer_limit_bytes":evidence::WORKING_BYTES,
            "successful_proof_bytes":pon_work::PROOF_BYTES,"cap_reached":b.cap_reached,
            "poisoned":b.poisoned,
            "buffer_scope":"bounded retained proof data and streamed JSON; not a total-process heap measurement"});
        b.write(&construction_path, &receipt, frame_limit.unwrap())
            .unwrap();
    } else {
        save(&construction_path, &receipt);
    }
    (verified && reference).then_some((packet, receipt))
}

pub(crate) fn valid_construction(row: &Value, template: &Packet, index: usize) -> bool {
    valid_construction_for(row, template, index, SCHEMA)
}
pub(crate) fn valid_construction_v2(row: &Value, template: &Packet, index: usize) -> bool {
    let factors_end = 4 + 2 * pon_work::CELLS * 4;
    let Some(packet) = row["packet"]
        .as_str()
        .and_then(|s| hex::decode(s).ok())
        .and_then(|w| Packet::decode(&w).ok())
    else {
        return false;
    };
    valid_construction_for(row, template, index, SCHEMA_V2)
        && row["evidence_budget"]["cap_reached"] == false
        && row["attempts"].as_array().is_some_and(|attempts| {
            attempts.iter().enumerate().all(|(offset, a)| {
                a["proof"]
                    .as_str()
                    .and_then(|s| hex::decode(s).ok())
                    .is_some_and(|p| {
                        p.len() == pon_work::PROOF_BYTES
                            && template.proof.get(..factors_end) == p.get(..factors_end)
                            && a["trace"] == hex::encode(&p[p.len() - 32..])
                            && (offset + 1 != attempts.len() || p == packet.proof)
                    })
            })
        })
}
fn valid_construction_for(row: &Value, template: &Packet, index: usize, schema: &str) -> bool {
    let Some(wire) = row["packet"].as_str().and_then(|s| hex::decode(s).ok()) else {
        return false;
    };
    let Ok(packet) = Packet::decode(&wire) else {
        return false;
    };
    let Some(attempts) = row["attempts"].as_array() else {
        return false;
    };
    let Some(initial) = nonce_start(index) else {
        return false;
    };
    let mut expected = template.header.clone();
    expected.state[0] ^= 1;
    expected.nonce = packet.header.nonce;
    row["schema"] == schema
        && row["index"] == index
        && row["initial_nonce"] == initial
        && row["attempt_limit"] == SEARCH_LIMIT
        && row["status"] == "winner"
        && row["error"].is_null()
        && row["production_verified"] == true
        && row["reference_verified"] == true
        && [
            "construction_thread_cpu_ns",
            "construction_wall_ns",
            "verification_thread_cpu_ns",
        ]
        .iter()
        .all(|k| row[k].as_u64().is_some_and(|n| n > 0))
        && !attempts.is_empty()
        && attempts.len() <= SEARCH_LIMIT as usize
        && expected.encode() == packet.header.encode()
        && attempts.iter().enumerate().all(|(offset, a)| {
            let mut h = expected.clone();
            h.nonce = initial + offset as u64;
            let Some(trace) = a["trace"]
                .as_str()
                .and_then(|s| hex::decode(s).ok())
                .filter(|t| t.len() == 32)
            else {
                return false;
            };
            let ticket = hash(b"ticket", &[&h.challenge(), &trace]);
            a["nonce"] == h.nonce
                && a["ticket"] == hex::encode(ticket)
                && a["thread_cpu_ns"].as_u64().is_some_and(|n| n > 0)
                && a["target_hit"] == (offset + 1 == attempts.len())
                && (ticket <= h.target) == (offset + 1 == attempts.len())
        })
        && packet.header.nonce == initial + attempts.len() as u64 - 1
        && attempts.last().unwrap()["trace"]
            == hex::encode(&packet.proof[packet.proof.len() - 32..])
        && row["completion_identity"]
            == hex::encode(hash(b"public-v3-complete-work-identity-v1", &[&wire]))
        && pon_work::verify(
            packet.header.challenge(),
            packet.header.work_task,
            packet.header.target,
            &packet.proof,
        )
        .is_ok()
        && pon_work::verify_reference(
            packet.header.challenge(),
            packet.header.work_task,
            packet.header.target,
            &packet.proof,
        )
        .is_ok()
}
