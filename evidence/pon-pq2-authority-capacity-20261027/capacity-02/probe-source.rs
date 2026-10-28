//! Actual M06 capacity controls using real ML-DSA proofs. These exercise the
//! source-bound component; the migration checkpoint is an explicit trust fixture,
//! not a claim that source-chain work/finality or prior registry timing was proved.
use serde_json::json;
use trnm_mvcc_fee::pon_executor::{self as exec, pq_accounts_v2 as pq, BlockExecution, Config, ExecutionControl, State};
use trnm_protocol::{pon_wire::{Hash, Header}, pq_native_accounts_v2 as wire};
#[path = "../../trnm-protocol/tests/support/native_pq_accounts_fixture.rs"]
mod fixture;
use fixture::{Key, Witness};

fn common(cfg: &Config, account: Hash, nonce: u64, generation: u64) -> wire::Common {
    wire::Common { context: pq::context(cfg).unwrap(), account, nonce,
        expires_at: 2000, max_fee: 100_000, generation }
}
fn execute(parent: &State, cfg: &Config, miner: Hash, rows: &[Vec<u8>]) -> exec::Result<exec::Output> {
    let progress = |_| Ok::<(), std::convert::Infallible>(());
    match exec::execute_with_control(parent, BlockExecution {
        timestamp: Some(1501), transactions: rows, height: 1, miner, parent_id: [230;32], workers: 1,
    }, cfg, &ExecutionControl::new(&progress, &())) {
        Ok(output) => Ok(output),
        Err(exec::ExecutionError::Relation(error)) => Err(error),
        Err(exec::ExecutionError::Cancelled(impossible)) => match impossible {},
    }
}

#[test]
fn complete_dual_proof_rotation_bytes_allow_56_and_reject_57_without_mutation() {
    let originals: Vec<_> = (1..=57).map(Key::public_test_seed).collect();
    let replacements: Vec<_> = (101..=157).map(Key::public_test_seed).collect();
    let genesis: Vec<_> = originals.iter().map(|key| pq::GenesisAccount { spki: key.spki.clone(), balance: 10_000_000 }).collect();
    let (cfg, state, _) = pq::genesis(&genesis, 1500).unwrap();
    let before = state.clone();
    let rows: Vec<_> = originals.iter().zip(&replacements).map(|(old,new)| {
        let payload = [2_u64.to_be_bytes().as_slice(), &pq::authority_digest(&state, old.id, &cfg).unwrap()].concat();
        fixture::signed(&common(&cfg, old.id, 1, 1), wire::ROTATE, &payload,
            &[Witness { key: old, role: 3, generation: 1, carried: false },
              Witness { key: new, role: 4, generation: 2, carried: true }], None)
    }).collect();
    assert!(rows.iter().all(|row| row.len() == 9_272));
    assert_eq!(rows[..56].iter().map(Vec::len).sum::<usize>(), 519_232);
    assert_eq!(rows.iter().map(Vec::len).sum::<usize>(), 528_504);
    let out = execute(&state, &cfg, originals[0].id, &rows[..56]).unwrap();
    assert_eq!(out.metrics.signature_verifications, 112);
    for (i, old) in originals.iter().enumerate() {
        let auth = &out.state[&format!("pq-auth-v2:{}", hex::encode(old.id))];
        assert_eq!(auth["generation"], if i < 56 { 2 } else { 1 });
        let expected = if i < 56 { replacements[i].id } else { old.id };
        assert_eq!(auth["key_id"], hex::encode(expected));
    }
    let error = execute(&state, &cfg, originals[0].id, &rows).err().expect("over-budget rotations must refuse");
    assert_eq!(error, "PQ2_TRANSACTION_LIMIT");
    assert_eq!(state, before);
    pq::validate_state(&out.state, &cfg).unwrap();
    assert_eq!(out.root, exec::root_for_config(&out.state, &cfg).unwrap());
}

#[test]
fn complete_anchored_claim_bytes_allow_55_and_reject_56_without_reminting() {
    let prior: Vec<_> = (1..=56).map(Key::public_test_seed).collect();
    let next: Vec<_> = (101..=156).map(Key::public_test_seed).collect();
    let source_cfg = Config::installed().unwrap();
    let mut source = State::from([("meta:issued".into(), json!(560_000_000_u64)),
        ("model:current".into(), json!(hex::encode([0;32])))]);
    for index in 1..=56_u8 {
        source.insert(format!("account:{}",hex::encode([index;32])), json!({"balance":10_000_000,"nonce":7}));
    }
    let source_genesis = [231;32];
    let material = pq::CheckpointMaterial { genesis: source_genesis, trace: [232;32], state: source.clone(),
        header: Header { network: source_cfg.network, parameters: source_cfg.parameters,
            parent: [233;32], height: 10, timestamp: 1200, target: [255;32], miner: [1;32],
            transactions: [0;32], state: exec::root_for_config(&source, &source_cfg).unwrap(),
            receipts: [0;32], work_task: [234;32], nonce: 0 } };
    let checkpoint = material.header.block_id(material.trace);
    let entries: Vec<_> = prior.iter().enumerate().map(|(i,key)| pq::PrecommittedAccount {
        source_account: [(i+1) as u8;32], spki: key.spki.clone(), generation: 9 }).collect();
    let anchor = pq::TrustedPqPrecommitments::pin(source_cfg.network, source_genesis, &entries).unwrap()
        .pin_checkpoint(checkpoint, material, &source_cfg).unwrap();
    let (cfg, state, _) = pq::genesis_with_trusted_migration(&[], 1500, anchor).unwrap();
    let before = state.clone();
    let rows: Vec<_> = prior.iter().zip(&next).enumerate().map(|(i,(old,new))| {
        let account = [(i+1) as u8;32];
        fixture::signed(&common(&cfg, account, 8, 0), wire::CLAIM,
            &pq::migration_claim_payload(&cfg, account).unwrap(),
            &[Witness { key: old, role: 5, generation: 9, carried: false },
              Witness { key: new, role: 6, generation: 1, carried: true }], None)
    }).collect();
    assert!(rows.iter().all(|row| row.len() == 9_432));
    assert_eq!(rows[..55].iter().map(Vec::len).sum::<usize>(), 518_760);
    assert_eq!(rows.iter().map(Vec::len).sum::<usize>(), 528_192);
    let out = execute(&state, &cfg, [1;32], &rows[..55]).unwrap();
    assert_eq!(out.metrics.signature_verifications, 110);
    assert_eq!(out.state["meta:issued"], 560_001_000_u64);
    for index in 1..=56_u8 {
        let name = hex::encode([index;32]);
        assert_eq!(out.state[&format!("pq-import-v2:{name}")]["claimed"], index <= 55);
        assert_eq!(out.state[&format!("account:{name}")]["nonce"], if index <= 55 { 8 } else { 7 });
    }
    assert_eq!(execute(&state, &cfg, [1;32], &rows).err().expect("over-budget claims must refuse"), "PQ2_TRANSACTION_LIMIT");
    assert_eq!(state, before);
    pq::validate_state(&out.state, &cfg).unwrap();
    assert_eq!(out.root, exec::root_for_config(&out.state, &cfg).unwrap());
}
