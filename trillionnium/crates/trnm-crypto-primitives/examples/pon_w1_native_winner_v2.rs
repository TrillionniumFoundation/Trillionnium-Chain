//! Research-only full native W1 nonce search with an externally fixed deadline.
//! The winner timestamp is captured at the native ticket predicate, before
//! publication and downstream proof work. Header/parent/Node admission is a
//! separate authority; this program never activates a consensus path.
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use trnm_crypto_primitives::pon_work::{self, Hash, CELLS, PROOF_BYTES};

const SCHEMA: &str = "TRNM-W1-NATIVE-WINNER2";
const HEADER_BYTES: usize = 318;
const MAX_ATTEMPTS: u64 = 10_000;

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(target_os = "linux")]
fn monotonic_ns() -> Result<u64> {
    use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
    let stamp = clock_gettime_dynamic(DynamicClockId::Known(ClockId::Monotonic))?;
    let seconds = u64::try_from(stamp.tv_sec)?;
    let nanos = u64::try_from(stamp.tv_nsec)?;
    ensure!(nanos < 1_000_000_000, "monotonic nanosecond range");
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|v| v.checked_add(nanos))
        .context("monotonic overflow")
}

#[cfg(not(target_os = "linux"))]
fn monotonic_ns() -> Result<u64> {
    bail!("actual Linux CLOCK_MONOTONIC required")
}

fn exact(path: &Path, bytes: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    File::open(path)?
        .take(bytes as u64 + 1)
        .read_to_end(&mut out)?;
    ensure!(out.len() == bytes, "exact input length: {}", path.display());
    Ok(out)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    let mut check = Vec::new();
    File::open(path)?
        .take(bytes.len() as u64 + 1)
        .read_to_end(&mut check)?;
    ensure!(check == bytes, "saved winner bytes changed");
    File::open(path.parent().context("winner output parent")?)?.sync_all()?;
    Ok(())
}

fn save_json(path: &Path, value: &Value) -> Result<()> {
    let mut raw = serde_json::to_vec(value)?;
    raw.push(b'\n');
    write_new(path, &raw)
}

fn decode_material(raw: &[u8]) -> Result<(Vec<u32>, Vec<u32>)> {
    ensure!(raw.len() == CELLS * 8, "exact A || B material length");
    let cells = raw
        .chunks_exact(4)
        .map(|b| u32::from_le_bytes(b.try_into().expect("four-byte chunk")))
        .collect::<Vec<_>>();
    let (a, b) = cells.split_at(CELLS);
    pon_work::task_id(a, b).map_err(|e| anyhow::anyhow!("noncanonical material: {e:?}"))?;
    Ok((a.to_vec(), b.to_vec()))
}

fn bound_deadline(deadline: u64, boot: &str, now: u64) -> Result<()> {
    let actual_boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    ensure!(
        actual_boot.trim() == boot,
        "original deadline clock identity mismatch"
    );
    let remaining = deadline
        .checked_sub(now)
        .context("original deadline exhausted")?;
    ensure!(
        (1..=7_200_000_000_000).contains(&remaining),
        "original deadline range"
    );
    Ok(())
}

fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(
        args.len() == 7,
        "MATERIAL EXPECTED_ARTIFACTS HEADER_TEMPLATE OUT ORIGINAL_DEADLINE_NS BOOT_ID MAX_ATTEMPTS"
    );
    let deadline: u64 = args[4].parse()?;
    let boot = &args[5];
    let limit: u64 = args[6].parse()?;
    ensure!(
        (1..=MAX_ATTEMPTS).contains(&limit),
        "bounded native attempt count"
    );
    let entered = monotonic_ns()?;
    bound_deadline(deadline, boot, entered)?;
    let material = exact(Path::new(&args[0]), CELLS * 8)?;
    let expected = exact(Path::new(&args[1]), 64)?;
    let template = exact(Path::new(&args[2]), HEADER_BYTES)?;
    let (a, b) = decode_material(&material)?;
    let task = pon_work::task_id(&a, &b).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    ensure!(
        template[278..310] == task,
        "header task differs from selected native material"
    );
    let actual_model = pon_work::hash(b"artifact", &[&material[..CELLS * 4]]);
    let actual_input = pon_work::hash(b"qualified-task-input-v1", &[&material[CELLS * 4..]]);
    ensure!(
        expected[..32] == actual_model && expected[32..] == actual_input,
        "independently selected A/B commitments mismatch"
    );
    let target: Hash = template[118..150].try_into()?;
    ensure!(
        target != [0; 32],
        "zero target is not a usable research search"
    );
    let first_nonce = u64::from_le_bytes(template[310..318].try_into()?);
    first_nonce
        .checked_add(limit - 1)
        .context("nonce range overflow")?;
    let out = PathBuf::from(&args[3]);
    fs::create_dir(&out)?;
    let intent = json!({"schema":SCHEMA,"entered_monotonic_ns":entered,
        "original_deadline_monotonic_ns":deadline,"original_deadline_boot_id":boot,
        "material_sha256":sha(&material),"expected_artifacts_sha256":sha(&expected),
        "header_template_sha256":sha(&template),"first_nonce":first_nonce,"maximum_attempts":limit,
        "pid":std::process::id(),"clock":"Linux CLOCK_MONOTONIC",
        "cgroup_membership":fs::read_to_string("/proc/self/cgroup")?,
        "parent_eligibility_checked":false,"node_admission":false,"production_qualified":false,
        "search_algorithm":"existing pon_work::prove, full native transcript, target predicate"});
    save_json(&out.join("intent.json"), &intent)?;
    let mut trials = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out.join("trials.jsonl"))?;
    let search_started = monotonic_ns()?;
    for attempt in 0..limit {
        let begin = monotonic_ns()?;
        if begin >= deadline {
            save_json(
                &out.join("result.json"),
                &json!({"schema":SCHEMA,"winner_observed":false,
                "attempts":attempt,"reason":"ORIGINAL_DEADLINE_EXHAUSTED",
                "original_deadline_monotonic_ns":deadline,"original_deadline_boot_id":boot}),
            )?;
            bail!("original deadline exhausted before native attempt");
        }
        let nonce = first_nonce + attempt;
        let mut header = template.clone();
        header[310..318].copy_from_slice(&nonce.to_le_bytes());
        let challenge = pon_work::hash(b"challenge", &[&header]);
        let proof = pon_work::prove(challenge, &a, &b)
            .map_err(|e| anyhow::anyhow!("native full prove: {e:?}"))?;
        ensure!(proof.len() == PROOF_BYTES, "native proof length");
        let trace: Hash = proof[PROOF_BYTES - 32..].try_into()?;
        let ticket = pon_work::hash(b"ticket", &[&challenge, &trace]);
        let hit = ticket <= target;
        // This actual native event precedes diagnostic hashing and persistence.
        let observed = monotonic_ns()?;
        let row = json!({"attempt":attempt,"nonce":nonce,"native_started_monotonic_ns":begin,
            "native_ticket_observed_monotonic_ns":observed,"ticket":hex::encode(ticket),
            "target_hit":hit,"before_original_deadline":observed < deadline});
        serde_json::to_writer(&mut trials, &row)?;
        trials.write_all(b"\n")?;
        trials.flush()?;
        if hit {
            let verified = pon_work::verify(challenge, task, target, &proof)
                .map_err(|e| anyhow::anyhow!("independent native replay rejected winner: {e:?}"))?;
            ensure!(verified.ticket() == ticket, "native replay changed ticket");
            let mut full = header.clone();
            full.extend_from_slice(&proof);
            write_new(&out.join("input.bin"), &full)?;
            write_new(&out.join("header.bin"), &header)?;
            write_new(&out.join("expected-artifacts.bin"), &expected)?;
            trials.sync_all()?;
            let saved = monotonic_ns()?;
            let winner = json!({"schema":SCHEMA,"winner_observed":true,"native_replay_verified":true,
                "nonce":nonce,"attempts":attempt+1,"native_winner_monotonic_ns":observed,
                "search_started_monotonic_ns":search_started,"winner_saved_monotonic_ns":saved,
                "original_deadline_monotonic_ns":deadline,"original_deadline_boot_id":boot,
                "native_ticket_before_deadline":observed < deadline,
                "winner_saved_before_deadline":saved < deadline,
                "ticket":hex::encode(ticket),"challenge":hex::encode(challenge),"task_id":hex::encode(task),
                "input_sha256":sha(&full),"header_sha256":sha(&header),
                "expected_artifacts_sha256":sha(&expected),"input_bytes":full.len(),
                "parent_eligibility_checked":false,"node_admission":false,
                "complete_zkvm_proof":false,"production_qualified":false});
            save_json(&out.join("result.json"), &winner)?;
            println!("{}", serde_json::to_string(&winner)?);
            ensure!(
                saved < deadline && monotonic_ns()? < deadline,
                "winner publication exceeded original deadline"
            );
            return Ok(());
        }
    }
    trials.sync_all()?;
    save_json(
        &out.join("result.json"),
        &json!({"schema":SCHEMA,"winner_observed":false,
        "attempts":limit,"reason":"FIXED_NONCE_RANGE_EXHAUSTED",
        "original_deadline_monotonic_ns":deadline,"original_deadline_boot_id":boot}),
    )?;
    bail!("fixed nonce range exhausted; no new seed or deadline selected")
}

fn main() -> Result<()> {
    run()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_material_rejects_noncanonical_and_incomplete_inputs() {
        assert!(decode_material(&vec![0; CELLS * 8 - 1]).is_err());
        assert!(decode_material(&vec![255; CELLS * 8]).is_err());
        let (a, b) = decode_material(&vec![0; CELLS * 8]).unwrap();
        assert_eq!((a.len(), b.len()), (CELLS, CELLS));
    }

    #[test]
    fn original_deadline_cannot_move_to_another_boot_or_gain_more_time() {
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
        let now = monotonic_ns().unwrap();
        assert!(bound_deadline(now + 1_000_000, "other-boot", now).is_err());
        assert!(bound_deadline(now, boot.trim(), now).is_err());
        assert!(bound_deadline(now + 7_200_000_000_001, boot.trim(), now).is_err());
        assert!(bound_deadline(now + 1_000_000, boot.trim(), now).is_ok());
    }
}
