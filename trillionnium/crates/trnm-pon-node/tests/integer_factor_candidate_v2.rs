//! Genuine PNX1/PNW1 admission, durable reopening and branch rollback for tag23.
use serde_json::{json, Value};
use std::{fs, path::Path, process::Command};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::{
    integer_factor_candidate_v2 as factor,
    pon_executor::{Config, State},
    public_evaluation as eval,
};
use trnm_pon_node::{development_public, Node, Settings};
use trnm_protocol::{
    integer_factor_v2::FactorWitnessV2,
    pon_wire::{hash, Envelope, Hash},
};
fn cfg() -> Config {
    Config::installed_with_model_profiles(eval::PROFILE, "legacy-task-v1", factor::PROFILE).unwrap()
}
fn settings() -> Settings {
    Settings::development_with_model_profiles(
        None,
        eval::PROFILE,
        "legacy-task-v1",
        factor::PROFILE,
    )
    .unwrap()
}
fn signed(c: &Config, who: u64, account_sequence: u64, tag: u8, payload: Vec<u8>) -> Vec<u8> {
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&who.to_le_bytes()]))).unwrap();
    let mut t = Envelope {
        network: c.network,
        sender: development_public(who).unwrap(),
        nonce: account_sequence,
        expiry: 2000,
        fee_limit: 1_000_000,
        tag,
        payload,
        signature: [0; 64],
    };
    t.signature = hex::decode(sign_hex(&key, &t.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    t.encode().unwrap()
}
fn factors(rank: u8, amount: i16) -> Vec<i16> {
    let mut f = vec![0; 260 * usize::from(rank)];
    f[0] = 1;
    f[3 * usize::from(rank)] = amount;
    f
}
fn build(
    s: &State,
    c: &Config,
    slot: u8,
    rank: u8,
    f: Vec<i16>,
    round: u64,
    root: Hash,
) -> FactorWitnessV2 {
    factor::build_witness(
        s,
        c,
        development_public(3).unwrap(),
        round,
        factor::FactorInputV2 {
            slot,
            rank,
            coefficients: f,
        },
        root,
    )
    .unwrap()
}
fn retain_context(c: &Config, label: &str) {
    if let Some(dir) = std::env::var_os("INTEGER_FACTOR_V2_EVIDENCE_DIR") {
        let dir = Path::new(&dir).join(label);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("context.json"),serde_json::to_vec(&json!({"network":hex::encode(c.network),"parameters":hex::encode(c.parameters),"family":hex::encode(c.family),"plan":hex::encode(c.plan),"params":c.params,"model_registry":c.model_registry})).unwrap()).unwrap();
    }
}
fn append(n: &mut Node, parent: Hash, height: u64, txs: Vec<Vec<u8>>, label: &str) -> Hash {
    let p = n
        .make(
            parent,
            txs,
            development_public(3).unwrap(),
            1_800_000_000 + height * 10,
            4096,
        )
        .unwrap();
    let id = n.admit(&p, 1_800_100_000).unwrap();
    n.activate(id).unwrap();
    if let Some(dir) = std::env::var_os("INTEGER_FACTOR_V2_EVIDENCE_DIR") {
        let dir = Path::new(&dir).join(label);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join(format!("packet-{height:03}-{}.pnw1", hex::encode(id))),
            p.encode().unwrap(),
        )
        .unwrap();
        fs::write(
            dir.join(format!("state-{height:03}.json")),
            serde_json::to_vec(&n.read_active().unwrap().2).unwrap(),
        )
        .unwrap();
    }
    id
}
fn refusal(n: &Node, parent: Hash, height: u64, tx: Vec<u8>, expected: &str) {
    let before = n.read_active().unwrap();
    let err = n
        .make(
            parent,
            vec![tx],
            development_public(3).unwrap(),
            1_800_000_000 + height * 10,
            4096,
        )
        .unwrap_err();
    assert!(err.to_string().contains(expected), "{err}");
    assert_eq!(n.read_active().unwrap(), before);
}
#[test]
fn exact_variants_refuse_and_real_fork_restores_duplicate_window() {
    let temp = tempfile::tempdir().unwrap();
    let c = cfg();
    retain_context(&c, "variants");
    retain_context(&c, "fork");
    let set = settings();
    let mut n = Node::open(temp.path(), set.clone(), 4).unwrap();
    let genesis = n.settings().genesis();
    let state = n.read_active().unwrap().2;
    assert_ne!(state["model:current"], hex::encode([0; 32]));
    let w = build(&state, &c, 0, 1, factors(1, 2), 0, [8; 32]);
    assert_eq!(159 + w.encode().unwrap().len(), 921);
    let raw = signed(&c, 3, 1, 23, w.encode().unwrap());
    let old = Config::installed_with_evaluation_policy(eval::PROFILE).unwrap();
    assert_eq!(
        trnm_mvcc_fee::pon_executor::validate_main_envelope(&raw, 1, &old),
        Err("FACTOR_PROFILE")
    );
    refusal(
        &n,
        genesis,
        1,
        signed(&c, 3, 1, 6, vec![0; 176]),
        "FACTOR_PROFILE",
    );
    for offset in [95 + 4, 95 + 6, 95 + 7, 95 + 8] {
        let mut broken = raw.clone();
        broken[offset] ^= 128;
        assert!(Envelope::decode(&broken).is_err());
    }
    let mut no_op = w.clone();
    no_op.factors.fill(0);
    refusal(
        &n,
        genesis,
        1,
        signed(&c, 3, 1, 23, no_op.encode().unwrap()),
        "FACTOR_NOOP",
    );
    let a = append(
        &mut n,
        genesis,
        1,
        vec![signed(&c, 3, 1, 23, w.encode().unwrap())],
        "variants",
    );
    let after = n.read_active().unwrap().2;
    for (rank, f) in [
        (1, vec![0; 260]),
        (1, factors(1, i16::MIN)),
        (3, factors(3, 1)),
        (1, {
            let mut f = factors(1, 32767);
            f[0] = 32767;
            f
        }),
    ] {
        assert!(factor::build_witness(
            &after,
            &c,
            development_public(3).unwrap(),
            0,
            factor::FactorInputV2 {
                slot: 0,
                rank,
                coefficients: f
            },
            [8; 32]
        )
        .is_err());
    }
    let mut fake = w.clone();
    fake.candidate_artifact[0] ^= 1;
    fake.contribution_id = factor::contribution_id(&c, development_public(3).unwrap(), &fake);
    refusal(
        &n,
        a,
        2,
        signed(&c, 3, 2, 23, fake.encode().unwrap()),
        "FACTOR_COMPUTED_HASH",
    );
    let round1 = build(&after, &c, 0, 1, factors(1, 3), 1, [8; 32]);
    assert_ne!(w.update_id, round1.update_id);
    refusal(
        &n,
        a,
        2,
        signed(&c, 3, 2, 23, round1.encode().unwrap()),
        "SUBMISSION_ROUND",
    );
    // Loader rejects missing/extra/corrupt chunks and inconsistent metadata.
    let baseprefix = format!("linear-model-v2:{}:", hex::encode(w.parent_artifact));
    for variation in 0..4 {
        let mut broken = after.clone();
        let key = format!("{baseprefix}00");
        match variation {
            0 => {
                broken.remove(&key);
            }
            1 => {
                broken.insert(format!("{baseprefix}99"), json!("00"));
            }
            2 => {
                broken.insert(key, json!("00".repeat(1024)));
            }
            _ => {
                broken.get_mut(&format!("{baseprefix}meta")).unwrap()["chunks"] = json!(63);
            }
        }
        assert!(factor::build_witness(
            &broken,
            &c,
            development_public(3).unwrap(),
            0,
            factor::FactorInputV2 {
                slot: 0,
                rank: 1,
                coefficients: factors(1, 3)
            },
            [8; 32]
        )
        .is_err());
    }

    for f in [
        factors(2, 2),
        {
            let mut f = factors(2, 3);
            f[1] = 1;
            f[6 + 257] = -1;
            f
        },
        {
            let mut f = factors(1, 2);
            f[0] = -1;
            f[3] = -2;
            f
        },
        {
            let mut f = factors(1, 1);
            f[0] = 2;
            f
        },
    ] {
        let rank = if f.len() == 520 { 2 } else { 1 };
        let copy = build(&after, &c, 0, rank, f, 0, [9; 32]);
        assert_eq!(w.update_id, copy.update_id);
        assert_eq!(w.candidate_artifact, copy.candidate_artifact);
        assert_ne!(w.encode().unwrap(), copy.encode().unwrap());
        refusal(
            &n,
            a,
            2,
            signed(&c, 3, 2, 23, copy.encode().unwrap()),
            "DUPLICATE_FUNCTION_UPDATE",
        );
    }
    // Cross-author representation is also a duplicate, despite a different CID.
    let mut copy = w.clone();
    copy.contribution_id = factor::contribution_id(&c, development_public(0).unwrap(), &copy);
    refusal(
        &n,
        a,
        2,
        signed(&c, 0, 1, 23, copy.encode().unwrap()),
        "DUPLICATE_FUNCTION_UPDATE",
    );
    for (slot, amount) in [(1, 2), (0, 3), (0, -2)] {
        let copy = build(&after, &c, slot, 1, factors(1, amount), 0, [9; 32]);
        assert_ne!(w.update_id, copy.update_id);
    }
    drop(n);
    let mut n = Node::open(temp.path(), set.clone(), 2).unwrap();
    assert_eq!(n.read_active().unwrap().2, after);
    let mut bad = w.clone();
    bad.parent_artifact[0] ^= 1;
    bad.contribution_id = factor::contribution_id(&c, development_public(3).unwrap(), &bad);
    refusal(
        &n,
        a,
        2,
        signed(&c, 3, 2, 23, bad.encode().unwrap()),
        "FACTOR_PARENT",
    );
    let b = append(&mut n, genesis, 1, vec![], "fork");
    let b2 = append(&mut n, b, 2, vec![], "fork");
    assert!(!n
        .read_active()
        .unwrap()
        .2
        .contains_key(&format!("linear-update-v2:{}", hex::encode(w.update_id))));
    let b3 = append(
        &mut n,
        b2,
        3,
        vec![signed(&c, 3, 1, 23, w.encode().unwrap())],
        "fork",
    );
    assert!(n
        .state_at(b3)
        .unwrap()
        .contains_key(&format!("linear-update-v2:{}", hex::encode(w.update_id))));
    drop(n);
    assert!(Node::open(temp.path(), Settings::development(None).unwrap(), 2).is_err());
}
fn object(s: &State, cid: Hash) -> &Value {
    &s[&format!("contribution:{}", hex::encode(cid))]
}
#[test]
fn missing_score_abort_keeps_same_round_marker_and_new_round_allows_update() {
    let temp = tempfile::tempdir().unwrap();
    let c = cfg();
    retain_context(&c, "round-retention");
    let mut n = Node::open(temp.path(), settings(), 4).unwrap();
    let initial = n.read_active().unwrap().2;
    let first = build(&initial, &c, 0, 1, factors(1, 2), 0, [8; 32]);
    let mut tip = n.settings().genesis();
    for height in 1..=128 {
        let state = n.read_active().unwrap().2;
        if height == 49 {
            assert_eq!(
                object(&state, first.contribution_id)["status"],
                "evaluation-aborted"
            );
            let copy = build(&state, &c, 0, 2, factors(2, 2), 0, [9; 32]);
            refusal(
                &n,
                tip,
                height,
                signed(&c, 3, 2, 23, copy.encode().unwrap()),
                "DUPLICATE_FUNCTION_UPDATE",
            );
        }
        let txs = match height {
            1 => vec![signed(&c, 3, 1, 23, first.encode().unwrap())],
            128 => {
                let next = build(&state, &c, 0, 2, factors(2, 2), 1, [9; 32]);
                assert_eq!(next.candidate_artifact, first.candidate_artifact);
                assert_ne!(next.update_id, first.update_id);
                vec![signed(&c, 3, 2, 23, next.encode().unwrap())]
            }
            _ => vec![],
        };
        tip = append(&mut n, tip, height, txs, "round-retention");
    }
    let state = n.read_active().unwrap().2;
    assert_eq!(state["model:current"], hex::encode(first.parent_artifact));
    assert!(!state.contains_key(&format!(
        "linear-update-v2:{}",
        hex::encode(first.update_id)
    )));
    assert!(state.contains_key(&format!(
        "evaluation-archive:{}",
        hex::encode(first.contribution_id)
    )));
}
fn commit(c: &Config, s: &State, cid: Hash, who: u64, account_sequence: u64) -> Vec<u8> {
    let round = eval::round(&object(s, cid)["public_evaluation"]).unwrap();
    let mut p = Vec::new();
    p.extend(cid);
    p.extend(round);
    p.extend(eval::reveal_commitment(
        round,
        cid,
        development_public(who).unwrap(),
        c.plan,
        [9; 32],
        10,
        [who as u8 + 1; 32],
    ));
    signed(c, who, account_sequence, 14, p)
}
fn reveal(c: &Config, s: &State, cid: Hash, who: u64, account_sequence: u64) -> Vec<u8> {
    let mut p = Vec::new();
    for h in [
        cid,
        eval::round(&object(s, cid)["public_evaluation"]).unwrap(),
        c.plan,
        [9; 32],
    ] {
        p.extend(h);
    }
    p.extend(10_u64.to_le_bytes());
    p.extend([who as u8 + 1; 32]);
    signed(c, who, account_sequence, 15, p)
}
#[test]
fn loaded_release_parent_full_range_and_new_round_are_native() {
    let temp = tempfile::tempdir().unwrap();
    let c = cfg();
    retain_context(&c, "loaded-parent");
    let mut n = Node::open(temp.path(), settings(), 4).unwrap();
    let genesis = n.settings().genesis();
    let initial = n.read_active().unwrap().2;
    let first = build(&initial, &c, 0, 1, factors(1, 2), 0, [8; 32]);
    let root = hash(
        b"allocation-leaf",
        &[
            &first.contribution_id,
            &development_public(3).unwrap(),
            &10_u64.to_le_bytes(),
        ],
    );
    let bundle = build(&initial, &c, 0, 1, factors(1, 32767), 0, root);
    let ids = [first.contribution_id, bundle.contribution_id];
    let mut tip = genesis;
    let mut release = [0; 32];
    for height in 1..=128 {
        let s = n.read_active().unwrap().2;
        let txs = match height {
            1 => vec![
                signed(&c, 3, 1, 23, first.encode().unwrap()),
                signed(&c, 3, 2, 23, bundle.encode().unwrap()),
            ],
            16 => {
                let mut t = Vec::new();
                for who in 0..3 {
                    for (i, cid) in ids.into_iter().enumerate() {
                        t.push(commit(&c, &s, cid, who, i as u64 + 1));
                    }
                }
                t
            }
            32 => {
                let mut t = Vec::new();
                for who in 0..3 {
                    for (i, cid) in ids.into_iter().enumerate() {
                        t.push(reveal(&c, &s, cid, who, i as u64 + 3));
                    }
                }
                t
            }
            56 => {
                let budget = 10_000_u64;
                release = hash(
                    b"release",
                    &[
                        &bundle.parent_ref,
                        &bundle.contribution_id,
                        &budget.to_le_bytes(),
                        &root,
                        &10_u64.to_le_bytes(),
                    ],
                );
                let mut p = Vec::new();
                p.extend(release);
                p.extend(bundle.parent_ref);
                p.extend(bundle.contribution_id);
                p.extend(budget.to_le_bytes());
                p.extend(root);
                p.extend(10_u64.to_le_bytes());
                p.push(1);
                p.extend(first.contribution_id);
                p.extend(10_u64.to_le_bytes());
                vec![signed(&c, 3, 3, 8, p)]
            }
            128 => {
                let mut forged = first.clone();
                forged.parent_ref = release;
                forged.parent_artifact = bundle.candidate_artifact;
                forged.round = 1;
                forged.factors = factors(1, 1);
                forged.contribution_id =
                    factor::contribution_id(&c, development_public(3).unwrap(), &forged);
                refusal(
                    &n,
                    tip,
                    128,
                    signed(&c, 3, 4, 23, forged.encode().unwrap()),
                    "FACTOR_MODEL_RANGE",
                );
                assert!(factor::build_witness(
                    &s,
                    &c,
                    development_public(3).unwrap(),
                    1,
                    factor::FactorInputV2 {
                        slot: 0,
                        rank: 1,
                        coefficients: factors(1, 1)
                    },
                    [8; 32]
                )
                .is_err());
                let child = build(&s, &c, 0, 1, factors(1, -1), 1, [8; 32]);
                assert_eq!(child.parent_ref, release);
                assert_eq!(child.parent_artifact, bundle.candidate_artifact);
                assert_ne!(child.update_id, first.update_id);
                vec![signed(&c, 3, 4, 23, child.encode().unwrap())]
            }
            _ => vec![],
        };
        tip = append(&mut n, tip, height, txs, "loaded-parent");
        if height == 56 {
            let s = n.read_active().unwrap().2;
            assert_eq!(s["model:current"], hex::encode(release));
            assert!(factor::build_witness(
                &s,
                &c,
                development_public(3).unwrap(),
                0,
                factor::FactorInputV2 {
                    slot: 0,
                    rank: 1,
                    coefficients: factors(1, 1)
                },
                [8; 32]
            )
            .is_err());
        }
    }
    let s = n.read_active().unwrap().2;
    assert_eq!(n.parent_height(tip).unwrap(), 128);
    assert!(!s.contains_key(&format!(
        "linear-update-v2:{}",
        hex::encode(first.update_id)
    )));
    // Same update over the actual new parent, another basis, same round => refuse.
    let copy = build(&s, &c, 0, 2, factors(2, -1), 1, [9; 32]);
    refusal(
        &n,
        tip,
        129,
        signed(&c, 3, 5, 23, copy.encode().unwrap()),
        "DUPLICATE_FUNCTION_UPDATE",
    );
    assert!(s.contains_key(&format!("release:{}", hex::encode(release))));
}
#[test]
fn cli_selects_fresh_profile_and_genesis_before_any_candidate() {
    let temp = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"))
        .args([
            "status",
            "--development",
            "--evaluation-policy",
            eval::PROFILE,
            "--model-profile",
            factor::PROFILE,
            "--store",
        ])
        .arg(temp.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let body: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(body.to_string().contains(&hex::encode(cfg().network)));
    let n = Node::open(temp.path(), settings(), 2).unwrap();
    assert!(n
        .read_active()
        .unwrap()
        .2
        .keys()
        .any(|k| k.starts_with("linear-model-v2:")));
    assert_eq!(
        factor::bootstrap_state(&cfg()).unwrap()["model:current"],
        n.read_active().unwrap().2["model:current"]
    );
    assert_eq!(cfg().params["consensus_revision"], json!(11));
    let initial = n.read_active().unwrap().2;
    drop(n);
    let c = cfg();
    let w = build(&initial, &c, 0, 2, factors(2, 2), 0, [8; 32]);
    let txfile = temp.path().join("candidate-transactions.json");
    fs::write(
        &txfile,
        serde_json::to_vec(&vec![hex::encode(signed(
            &c,
            3,
            1,
            23,
            w.encode().unwrap(),
        ))])
        .unwrap(),
    )
    .unwrap();
    let packet = temp.path().join("candidate.pnw1");
    let mined = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"))
        .args([
            "mine",
            "--development",
            "--evaluation-policy",
            eval::PROFILE,
            "--model-profile",
            factor::PROFILE,
            "--store",
        ])
        .arg(temp.path())
        .args([
            "--logical-now",
            "1800100000",
            "--timestamp",
            "1800000010",
            "--transactions",
        ])
        .arg(&txfile)
        .arg("--output")
        .arg(&packet)
        .output()
        .unwrap();
    assert!(
        mined.status.success(),
        "{}",
        String::from_utf8_lossy(&mined.stderr)
    );
    let n = Node::open(temp.path(), settings(), 2).unwrap();
    assert!(n
        .read_active()
        .unwrap()
        .2
        .contains_key(&format!("contribution:{}", hex::encode(w.contribution_id))));
    if let Some(dir) = std::env::var_os("INTEGER_FACTOR_V2_EVIDENCE_DIR") {
        let dir = Path::new(&dir).join("cli");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("status.stdout"), out.stdout).unwrap();
        fs::write(dir.join("status.stderr"), out.stderr).unwrap();
        fs::write(dir.join("mine.stdout"), mined.stdout).unwrap();
        fs::write(dir.join("mine.stderr"), mined.stderr).unwrap();
        fs::write(dir.join("candidate.pnw1"), fs::read(packet).unwrap()).unwrap();
        fs::write(
            dir.join("state.json"),
            serde_json::to_vec(&n.read_active().unwrap().2).unwrap(),
        )
        .unwrap();
        fs::write(dir.join("receipt.json"),serde_json::to_vec(&json!({"status_returncode":out.status.code(),"mine_returncode":mined.status.code(),"actual_children_waited":true,"public_network_ready":false})).unwrap()).unwrap();
        retain_context(&c, "cli");
    }
}
