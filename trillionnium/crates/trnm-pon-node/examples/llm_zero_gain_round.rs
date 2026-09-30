//! Real external CPU artifacts bind to a fresh native context. This negative
//! experiment never upgrades unsigned/same-operator ML reports into public truth.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};
use trnm_crypto_primitives::{
    qualified_work_task::{lifecycle_v2::verify_lifecycle_admission, TaskMaterial},
    sign_hex, signing_key_from_hex,
};
use trnm_mvcc_fee::{pon_executor::Config, public_evaluation};
use trnm_pon_node::{development_public, digest, Node, Result, Settings};
use trnm_protocol::{
    pon_wire::{hash, Envelope, Hash},
    qualified_work_task::lifecycle_v2::PROFILE,
};
const CONTROLS: [&str; 4] = [
    "current-backbone",
    "fresh-budget-matched-lora",
    "budget-matched-full-tune",
    "randomized-rank-matched-lora",
];
fn check(ok: bool, error: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(error.into())
    }
}
fn read(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let m = file.metadata()?;
    check(
        m.is_file() && m.nlink() == 1 && m.len() <= maximum,
        "INPUT_FILE",
    )?;
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    check(bytes.len() as u64 <= maximum, "INPUT_LIMIT")?;
    Ok(bytes)
}
fn json_file(path: &Path) -> Result<(Vec<u8>, Value)> {
    let raw = read(path, 2_097_152)?;
    let value: Value = serde_json::from_slice(&raw)?;
    let canonical = serde_json::to_vec(&value)?;
    check(
        raw.strip_suffix(b"\n").unwrap_or(&raw) == canonical,
        "INPUT_CANONICAL_JSON",
    )?;
    Ok((canonical, value))
}
fn ratio(value: &Value) -> Result<(u64, u64)> {
    let xs = value.as_array().ok_or("METRIC_RATIO")?;
    check(xs.len() == 2, "METRIC_RATIO")?;
    let n = xs[0].as_u64().ok_or("METRIC_RATIO")?;
    let d = xs[1].as_u64().ok_or("METRIC_RATIO")?;
    check(d > 0 && d <= 1_000_000 && n <= d, "METRIC_RATIO")?;
    Ok((n, d))
}
fn assess(value: &Value, roster: &Value) -> Result<()> {
    check(
        value["schema"] == "llm-runtime-actual-pilot-assessment-v1"
            && value["all_required_controls_executed"] == true
            && value["positive_vs_all_controls"] == false,
        "ACTUAL_PILOT_SCOPE",
    )?;
    for flag in [
        "public_network_ready",
        "authenticated_inference_accepted",
        "independent_accepted",
        "prospective_accepted",
        "public_reward_eligible",
    ] {
        check(value[flag] == false, "ACTUAL_PILOT_SCOPE")?;
    }
    check(
        roster["frozen_before_evaluation"] == true && value["experiment"] == roster["experiment"],
        "FROZEN_CONTROL_PLAN",
    )?;
    let scores = value["scores"].as_object().ok_or("CONTROL_MATRIX")?;
    let artifacts = roster["artifacts"].as_object().ok_or("CONTROL_MATRIX")?;
    check(scores.len() == 5 && artifacts.len() == 5, "CONTROL_MATRIX")?;
    let candidate = ratio(&scores.get("candidate").ok_or("CONTROL_MATRIX")?["evaluation"])?;
    let mut strongest = (0, 1);
    for role in std::iter::once("candidate").chain(CONTROLS) {
        let score = scores.get(role).ok_or("CONTROL_MATRIX")?;
        ratio(&score["calibration"])?;
        let r = ratio(&score["evaluation"])?;
        digest(
            artifacts
                .get(role)
                .and_then(Value::as_str)
                .ok_or("CONTROL_MATRIX")?,
        )?;
        if role != "candidate"
            && (r.0 as u128) * (strongest.1 as u128) > (strongest.0 as u128) * (r.1 as u128)
        {
            strongest = r;
        }
    }
    check(
        (candidate.0 as u128) * (strongest.1 as u128)
            <= (strongest.0 as u128) * (candidate.1 as u128),
        "POSITIVE_GAIN_REQUIRES_SEPARATE_QUALIFICATION",
    )?;
    let phases = value["phases"]
        .as_array()
        .ok_or("ACTUAL_EXECUTION_PHASES")?;
    check(phases.len() == 12, "ACTUAL_EXECUTION_PHASES")?;
    for phase in phases {
        check(
            phase["exit_code"] == 0
                && phase["outcome"] == "success"
                && phase["stop_reason"].is_null(),
            "ACTUAL_EXECUTION_PHASES",
        )?;
    }
    Ok(())
}
fn signed(cfg: &Config, who: u64, sequence: u64, tag: u8, payload: Vec<u8>) -> Result<Vec<u8>> {
    let key = signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&who.to_le_bytes()])))
        .map_err(|_| "KEY")?;
    let mut tx = Envelope {
        network: cfg.network,
        sender: development_public(who)?,
        nonce: sequence,
        expiry: 128,
        fee_limit: 1_000_000,
        tag,
        payload,
        signature: [0; 64],
    };
    tx.signature = hex::decode(sign_hex(
        &key,
        &tx.signing_digest().map_err(|_| "ENCODING")?,
    ))
    .map_err(|_| "ENCODING")?
    .try_into()
    .map_err(|_| "ENCODING")?;
    tx.encode().map_err(|_| "ENCODING".into())
}
fn save(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}
fn run(args: &[String]) -> Result<Value> {
    check(args.len()==5,"usage: llm_zero_gain_round NEW_DIRECTORY ASSESSMENT_JSON CONTROL_PLAN_JSON CANDIDATE_SAFETENSORS CANDIDATE_METADATA_JSON")?;
    let root = Path::new(&args[0]);
    fs::create_dir(root)?;
    let (assessment_bytes, assessment) = json_file(Path::new(&args[1]))?;
    let (roster_bytes, roster) = json_file(Path::new(&args[2]))?;
    assess(&assessment, &roster)?;
    let candidate = read(Path::new(&args[3]), 2_097_152)?;
    check(!candidate.is_empty(), "CANDIDATE_MATERIAL")?;
    let (metadata_bytes, metadata) = json_file(Path::new(&args[4]))?;
    check(
        metadata["role"] == "candidate"
            && metadata["kind"] == "lora"
            && metadata["artifact"] == roster["artifacts"]["candidate"]
            && metadata["contract"] == roster["contract"]
            && metadata["experiment"] == roster["experiment"]
            && metadata["file_sha256"] == hex::encode(Sha256::digest(&candidate)),
        "CANDIDATE_ASSESSMENT_BINDING",
    )?;
    let artifact = hash(b"artifact", &[&candidate]);
    let control_root = hash(b"native-llm-control-plan-v1", &[&roster_bytes]);
    let evidence = hash(b"native-llm-pilot-assessment-v1", &[&assessment_bytes]);
    let cfg = Config::installed_with_model_profiles(
        public_evaluation::PROFILE,
        PROFILE,
        "smollm2-135m-cpu-dev-v1",
    )?;
    let settings = Settings::development_with_model_profiles(
        None,
        public_evaluation::PROFILE,
        PROFILE,
        "smollm2-135m-cpu-dev-v1",
    )?;
    let binding = json!({"schema":"native-llm-external-pilot-binding-v1","network":hex::encode(settings.network()),"parameters":hex::encode(settings.parameters()),"genesis":hex::encode(settings.genesis()),"family":hex::encode(cfg.family),"plan":hex::encode(cfg.plan),"artifact":hex::encode(artifact),"artifact_bytes":candidate.len(),"control_plan":hex::encode(control_root),"assessment":hex::encode(evidence),"original_material_ports_contract":roster["contract"],"scope":"explicit cross-context external CPU observation; original material/ports contract not relabeled as native execution","score":0,"model_value_accepted":false,"independent_accepted":false,"public_network_ready":false});
    save(&root.join("binding.json"), &serde_json::to_vec(&binding)?)?;
    save(&root.join("assessment.json"), &assessment_bytes)?;
    save(&root.join("control-plan.json"), &roster_bytes)?;
    save(&root.join("candidate-metadata.json"), &metadata_bytes)?;
    let cid = hash(
        b"contribution-v3",
        &[
            &development_public(3)?,
            &cfg.family,
            &[0; 32],
            &artifact,
            &control_root,
            &0_u64.to_le_bytes(),
        ],
    );
    let mut p = Vec::new();
    for h in [cid, cfg.family, [0; 32], artifact] {
        p.extend(h);
    }
    p.extend((candidate.len() as u64).to_le_bytes());
    p.extend(control_root);
    p.extend(0_u64.to_le_bytes());
    let contribution = signed(&cfg, 3, 1, 6, p)?;
    let bootstrap = settings.bootstrap_lifecycle_task()?;
    let wire = bootstrap.signed.encode().map_err(|_| "TASK")?;
    let (model, input, a, b) = settings.bootstrap_task_material()?;
    let mut node = Node::open(&root.join("node"), settings.clone(), 4)?;
    let clock = 1_800_010_000;
    let mut round: Hash = [0; 32];
    let mut salt = [0; 32];
    File::open("/dev/urandom")?.read_exact(&mut salt)?;
    let mut attempts = 0_u64;
    for height in 1..=64 {
        let transactions = match height {
            1 => vec![contribution.clone()],
            16 => (0..3)
                .map(|who| {
                    let mut p = Vec::new();
                    p.extend(cid);
                    p.extend(round);
                    p.extend(public_evaluation::reveal_commitment(
                        round,
                        cid,
                        development_public(who)?,
                        cfg.plan,
                        evidence,
                        0,
                        salt,
                    ));
                    signed(&cfg, who, 1, 14, p)
                })
                .collect::<Result<Vec<_>>>()?,
            32 => (0..3)
                .map(|who| {
                    let mut p = Vec::new();
                    for h in [cid, round, cfg.plan, evidence] {
                        p.extend(h);
                    }
                    p.extend(0_u64.to_le_bytes());
                    p.extend(salt);
                    signed(&cfg, who, 2, 15, p)
                })
                .collect::<Result<Vec<_>>>()?,
            _ => vec![],
        };
        let admission = verify_lifecycle_admission(
            &wire,
            TaskMaterial {
                model: &model,
                input: &input,
                a: &a,
                b: &b,
            },
            &bootstrap.lease,
            height,
        )
        .map_err(|_| "TASK")?;
        let packet = node.make_with_task(
            node.active()?.0,
            transactions,
            development_public(0)?,
            1_800_000_000 + height * 10,
            4096,
            &admission,
            TaskMaterial {
                model: &model,
                input: &input,
                a: &a,
                b: &b,
            },
        )?;
        attempts += packet.header.nonce + 1;
        let id = node.admit(&packet, clock)?;
        node.activate_observed(id, clock)?;
        save(
            &root.join(format!("block-{height:04}.bin")),
            &packet.encode()?,
        )?;
        if height == 1 {
            round = public_evaluation::round(
                &node.read_active()?.2[&format!("contribution:{}", hex::encode(cid))]
                    ["public_evaluation"],
            )?;
        }
    }
    let state = node.read_active()?.2;
    let result =
        state[&format!("contribution:{}", hex::encode(cid))]["public_evaluation"]["closed"].clone();
    check(
        result["status"] == "complete-scored"
            && result["score"] == 0
            && state["model:current"] == hex::encode([0; 32])
            && !state.keys().any(|k| k.starts_with("release:")),
        "ZERO_GAIN_SETTLEMENT",
    )?;
    let stats = node.stats()?;
    let mut release = Vec::new();
    for h in [[1; 32], [0; 32], cid] {
        release.extend(h);
    }
    release.extend(10_000_u64.to_le_bytes());
    release.extend(control_root);
    release.extend(1_u64.to_le_bytes());
    release.push(1);
    release.extend(cid);
    release.extend(1_u64.to_le_bytes());
    let mut claim = Vec::new();
    claim.extend([1; 32]);
    claim.extend(cid);
    claim.extend(1_u64.to_le_bytes());
    claim.push(0);
    let mut refusals = Vec::new();
    for (tag, payload, expected) in [(8, release, "PUBLIC_EVAL_ADOPTION"), (9, claim, "STATE")] {
        let admission = verify_lifecycle_admission(
            &wire,
            TaskMaterial {
                model: &model,
                input: &input,
                a: &a,
                b: &b,
            },
            &bootstrap.lease,
            65,
        )
        .map_err(|_| "TASK")?;
        let tx = signed(&cfg, 3, 2, tag, payload)?;
        let error = node
            .make_with_task(
                node.active()?.0,
                vec![tx],
                development_public(0)?,
                1_800_000_650,
                4096,
                &admission,
                TaskMaterial {
                    model: &model,
                    input: &input,
                    a: &a,
                    b: &b,
                },
            )
            .err()
            .ok_or("ZERO_GAIN_MUTATION_ACCEPTED")?
            .to_string();
        check(error == expected, "ZERO_GAIN_REFUSAL")?;
        check(node.stats()? == stats, "ZERO_GAIN_MUTATED_STATE")?;
        refusals.push(json!({"tag":tag,"error":error,"durable_state_unchanged":true}));
    }
    drop(node);
    let reopened = Node::open(&root.join("node"), settings, 1)?;
    check(reopened.stats()? == stats, "REOPEN_STATE")?;
    drop(reopened);
    Ok(
        json!({"schema":"native-llm-zero-gain-round-v1","binding":binding,"candidate":hex::encode(cid),"closed_result":result,"state":stats,"blocks":64,"mining_attempts":attempts,"actual_settlement_refusals":refusals,"clock_scope":"logical-test; actual native proofs/execution/store; no live WAN timing","score":0,"adopted":false,"model_contribution_reward":0,"mining_subsidy_separate":true,"native_ml_execution_claim":false,"public_network_ready":false,"independent_accepted":false,"work_profile_qualified":false}),
    )
}
fn main() {
    match run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        Ok(v) => {
            let bytes = serde_json::to_vec(&v).expect("JSON");
            let path = std::env::args().nth(1).expect("root");
            if let Err(e) = save(&Path::new(&path).join("summary.json"), &bytes) {
                eprintln!("{e}");
                std::process::exit(1);
            }
            println!("{v}");
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ratio_rejects_boolean_zero_denominator_and_out_of_range() {
        for v in [
            json!([true, 2]),
            json!([0, 0]),
            json!([3, 2]),
            json!([0, 1_000_001]),
        ] {
            assert!(ratio(&v).is_err());
        }
        assert_eq!(ratio(&json!([1, 2])).unwrap(), (1, 2));
    }
    #[test]
    fn duplicate_json_and_symlink_fail() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("input");
        fs::write(&p, b"{\"score\":1,\"score\":0}").unwrap();
        assert!(json_file(&p).is_err());
        std::os::unix::fs::symlink(&p, d.path().join("link")).unwrap();
        assert!(json_file(&d.path().join("link")).is_err());
    }
}
