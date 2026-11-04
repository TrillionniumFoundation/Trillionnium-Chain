#![cfg(feature = "pq-native-openssl")]
//! Real Rust ML-DSA/PQG1 import into the existing native M06 transition owner.
use openssl::{
    pkey::{KeyType, PKey, Private},
    sign::Signer,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha384};
use std::{
    collections::BTreeSet,
    io::Write,
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};
use trnm_crypto_primitives::{
    pq_auth::PqNativeSigningKey, public_key_hex, sign_hex, signing_key_from_hex,
};
use trnm_mvcc_fee::pon_executor::{
    self as executor,
    pq_accounts::{self, ImportPins, MigrationEvidence},
    Config, State,
};
use trnm_protocol::{
    pon_wire::{hash, Envelope, Hash},
    pq_frame::ml_dsa_65_key_id_from_spki,
    pq_transaction::Transfer,
};

pub struct Fixture {
    pub raw: Vec<u8>,
    pub pins: ImportPins,
    pub evidence: Vec<MigrationEvidence>,
    pub keys: Vec<PKey<Private>>,
    pub active: Vec<Hash>,
    pub quarantine: Hash,
    pub chain_network: Hash,
}
fn sha384(domain: &[u8], raw: &[u8]) -> [u8; 48] {
    let mut h = Sha384::new();
    h.update(domain);
    h.update((raw.len() as u64).to_be_bytes());
    h.update(raw);
    h.finalize().into()
}
fn account_id(network: Hash, old: Hash, pq: Option<Hash>) -> Hash {
    let mut h = Sha256::new();
    h.update(if pq.is_some() {
        b"TRNM/PQ/Account/v1\0".as_slice()
    } else {
        b"TRNM/PQ/Quarantine/v1\0".as_slice()
    });
    h.update(network);
    h.update(old);
    if let Some(pq) = pq {
        h.update(pq);
    }
    h.finalize().into()
}
pub fn fixture() -> Fixture {
    fixture_at(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 100,
    )
}
pub fn fixture_at(genesis_timestamp: u64) -> Fixture {
    fixture_with_keys(genesis_timestamp, [91, 92])
}
fn fixture_with_keys(genesis_timestamp: u64, seeds: [u8; 2]) -> Fixture {
    let mut old: Vec<_> = (1u8..=3)
        .map(|i| {
            let key = signing_key_from_hex(&format!("{i:02x}").repeat(32)).unwrap();
            let id: Hash = hex::decode(public_key_hex(&key))
                .unwrap()
                .try_into()
                .unwrap();
            (id, key)
        })
        .collect();
    old.sort_by_key(|x| x.0);
    let network = [81; 32];
    let target = [82; 32];
    let head = [83; 32];
    let withdrawal = [84; 32];
    let now = genesis_timestamp + 100;
    let profile = pq_accounts::protocol_id(genesis_timestamp).unwrap();
    let mut raw = b"PQG1\x01".to_vec();
    for value in [network, target, head, withdrawal, profile] {
        raw.extend(value);
    }
    let issued = 60_004_000u64;
    raw.extend(issued.to_be_bytes());
    raw.extend(3u16.to_be_bytes());
    raw.extend(4u16.to_be_bytes());
    let nonces = [23u64, 91, 7];
    let generations = [4u64, 9, 2];
    let mut records = Vec::new();
    for (i, (id, _)) in old.iter().enumerate() {
        let mut r = id.to_vec();
        r.extend(((i as u64 + 1) * 10_000_000).to_be_bytes());
        r.extend(nonces[i].to_be_bytes());
        r.extend(generations[i].to_be_bytes());
        raw.extend(&r);
        records.push(r);
    }
    for i in 1u8..=4 {
        raw.extend([30 + i; 32]);
        raw.extend(old[(i as usize - 1) % 3].0);
        raw.extend(1000u64.to_be_bytes());
        raw.extend(5u64.to_be_bytes());
        raw.push(i);
    }
    let source = sha384(b"TRNM/PQ/GenesisSource/v1\0", &raw);
    let keys: Vec<_> = seeds
        .iter()
        .map(|seed| {
            PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, &[*seed; 32]).unwrap()
        })
        .collect();
    let mut evidence = Vec::new();
    let mut active = Vec::new();
    let mut reference_evidence = Vec::new();
    for i in 0..2 {
        let spki = keys[i].public_key_to_der().unwrap();
        let id = ml_dsa_65_key_id_from_spki(&spki).unwrap();
        let expiry = now + 1000;
        let mut statement = b"TRNM/PQ/GenesisMigration/v1\0".to_vec();
        statement.extend(source);
        for value in [network, target, head, withdrawal, profile] {
            statement.extend(value);
        }
        statement.extend(&records[i]);
        statement.extend(id);
        statement.extend((generations[i] + 1).to_be_bytes());
        statement.extend(expiry.to_be_bytes());
        let old_signature: [u8; 64] = hex::decode(sign_hex(&old[i].1, &statement))
            .unwrap()
            .try_into()
            .unwrap();
        let pq_signature = Signer::new_without_digest(&keys[i])
            .unwrap()
            .sign_oneshot_to_vec(&statement)
            .unwrap();
        reference_evidence.push(json!({"old":hex::encode(old[i].0),"pem":String::from_utf8(keys[i].public_key_to_pem().unwrap()).unwrap(),"expiry":expiry,"ed":hex::encode(old_signature),"pq":hex::encode(&pq_signature)}));
        evidence.push(MigrationEvidence {
            old_public: old[i].0,
            new_spki: spki,
            expires_at: expiry,
            old_signature,
            pq_signature,
        });
        active.push(account_id(target, old[i].0, Some(id)));
    }
    // Independent existing reference implementation computes the exact PQS1
    // projection and verifies both signatures. It is a test oracle only; the
    // production Rust import never invokes a subprocess or trusts this result.
    let reference = r#"import json,sys
from pq_genesis_handoff import MigrationEvidence,verify_handoff
p=json.load(sys.stdin); b=lambda x:bytes.fromhex(x)
e=tuple(MigrationEvidence(b(x['old']),x['pem'].encode(),x['expiry'],b(x['ed']),b(x['pq'])) for x in p['evidence'])
r=verify_handoff(b(p['source']),expected_source_digest=b(p['digest']),expected_legacy_network=b(p['old']),expected_new_network=b(p['new']),expected_legacy_head=b(p['head']),expected_revocation_head=b(p['withdrawal']),expected_new_protocol_hash=b(p['profile']),expected_issued_units=p['issued'],migration_evidence=e,independently_revoked_old_keys=frozenset(),now=p['now'])
print(json.dumps({'root':r.target_state_root.hex(),'genesis':r.target_genesis_id.hex()}))
"#;
    let cwd =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../formal/pon-nakamoto-v1");
    let mut child = Command::new("python3")
        .args(["-c", reference])
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let input = json!({"source":hex::encode(&raw),"digest":hex::encode(source),"old":hex::encode(network),"new":hex::encode(target),"head":hex::encode(head),"withdrawal":hex::encode(withdrawal),"profile":hex::encode(profile),"issued":issued,"evidence":reference_evidence,"now":now});
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&input).unwrap())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "reference oracle: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let observed: Value = serde_json::from_slice(&output.stdout).unwrap();
    let pins = ImportPins {
        source_digest: source,
        old_network: network,
        new_network: target,
        old_head: head,
        withdrawal_head: withdrawal,
        protocol: profile,
        genesis_timestamp,
        issued,
        target_state_root: hex::decode(observed["root"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
        target_genesis: hex::decode(observed["genesis"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
        revoked_old_keys: BTreeSet::new(),
        now,
    };
    let chain_network = pq_accounts::import_genesis(&raw, &pins, &evidence)
        .unwrap()
        .into_execution_parts()
        .0
        .network;
    Fixture {
        raw,
        pins,
        evidence,
        keys,
        active,
        quarantine: account_id(target, old[2].0, None),
        chain_network,
    }
}
pub fn transfer(f: &Fixture, sender: usize, nonce: u64, amount: u64) -> Transfer {
    Transfer {
        network: f.chain_network,
        sender: f.active[sender],
        recipient: f.active[1 - sender],
        generation: if sender == 0 { 5 } else { 10 },
        nonce,
        expires_at: 100,
        amount,
        max_fee: 100_000,
        memo: b"native-owner-test".to_vec(),
    }
}
pub fn signed(f: &Fixture, t: &Transfer, key: usize) -> Vec<u8> {
    let spki = f.keys[key].public_key_to_der().unwrap();
    let id = ml_dsa_65_key_id_from_spki(&spki).unwrap();
    let signer = PqNativeSigningKey::from_owned_key(f.keys[key].clone(), id).unwrap();
    let mut body = t.encode().unwrap();
    let frame = signer
        .sign_statement(
            &t.unsigned_statement(id).unwrap(),
            &t.expectation(id, 1, &body),
        )
        .unwrap();
    body.extend(frame);
    body
}
fn imported(f: &Fixture) -> (Config, State) {
    pq_accounts::import_genesis(&f.raw, &f.pins, &f.evidence)
        .unwrap()
        .into_execution_parts()
}
fn execute(
    state: &State,
    txs: &[Vec<u8>],
    height: u64,
    cfg: &Config,
    miner: Hash,
) -> executor::Result<executor::Output> {
    executor::execute(state, txs, height, miner, [55; 32], 4, cfg)
}

#[test]
fn pqg1_native_import_preserves_nonces_all_four_liabilities_and_original_m06_transfers() {
    let f = fixture();
    let (cfg, state) = imported(&f);
    let before = state.clone();
    let t = transfer(&f, 0, 23, 1000);
    let raw = signed(&f, &t, 0);
    let resign = signed(&f, &t, 0);
    assert_ne!(raw, resign);
    let a = execute(&state, std::slice::from_ref(&raw), 1, &cfg, f.active[0]).unwrap();
    let b = execute(&state, &[resign], 1, &cfg, f.active[0]).unwrap();
    assert_eq!(a.state, b.state);
    assert_eq!(a.receipts, b.receipts);
    assert_eq!(a.root, b.root);
    assert_eq!(state, before);
    assert_eq!(a.metrics.signature_verifications, 1);
    let fee = cfg.fees[1] + raw.len() as u64 * cfg.params["byte_fee_units"].as_u64().unwrap();
    assert_eq!(
        a.state[&format!("account:{}", hex::encode(f.active[0]))],
        json!({"balance":10_000_000-1000-fee,"nonce":23})
    );
    assert_eq!(
        a.state[&format!("account:{}", hex::encode(f.active[1]))],
        json!({"balance":20_001_000,"nonce":90})
    );
    assert_eq!(
        a.state
            .iter()
            .filter(|(k, _)| k.starts_with("pq-import-liability:"))
            .count(),
        4
    );
    for (k, v) in state
        .iter()
        .filter(|(k, _)| k.starts_with("pq-import-liability:"))
    {
        assert_eq!(a.state[k], *v);
    }
    assert_eq!(
        a.state[&format!("account:{}", hex::encode(f.quarantine))]["balance"],
        30_000_000
    );
    let duplicate = execute(&state, &[raw.clone(), raw], 1, &cfg, f.active[0]);
    assert_eq!(duplicate.unwrap_err(), "NONCE");
}

#[test]
fn account_forks_keep_the_original_state_nonce_owner_without_shared_credits() {
    let f = fixture();
    let (cfg, state) = imported(&f);
    let a = execute(
        &state,
        &[signed(&f, &transfer(&f, 0, 23, 1000), 0)],
        1,
        &cfg,
        f.active[0],
    )
    .unwrap();
    let b = execute(
        &state,
        &[signed(&f, &transfer(&f, 0, 23, 2000), 0)],
        1,
        &cfg,
        f.active[0],
    )
    .unwrap();
    assert_ne!(a.root, b.root);
    assert_eq!(
        execute(
            &a.state,
            &[signed(&f, &transfer(&f, 0, 23, 1000), 0)],
            2,
            &cfg,
            f.active[0]
        )
        .unwrap_err(),
        "NONCE"
    );
    let a2 = execute(
        &a.state,
        &[signed(&f, &transfer(&f, 0, 24, 3000), 0)],
        2,
        &cfg,
        f.active[0],
    )
    .unwrap();
    let b2 = execute(
        &b.state,
        &[signed(&f, &transfer(&f, 0, 24, 3000), 0)],
        2,
        &cfg,
        f.active[0],
    )
    .unwrap();
    assert_ne!(a2.root, b2.root);
    assert_eq!(
        state[&format!("account:{}", hex::encode(f.active[0]))]["nonce"],
        22
    );
}

#[test]
fn real_wrong_signatures_context_nonce_quarantine_and_classical_fallback_refuse() {
    let f = fixture();
    let (cfg, state) = imported(&f);
    let t = transfer(&f, 0, 23, 1000);
    let raw = signed(&f, &t, 0);
    let mut bad = raw.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(execute(&state, &[bad], 1, &cfg, f.active[0]).is_err());
    for mutate in 0..4 {
        let mut t = t.clone();
        match mutate {
            0 => t.network = [9; 32],
            1 => t.generation += 1,
            2 => t.nonce = 22,
            _ => t.sender = f.quarantine,
        };
        let raw = signed(&f, &t, 0);
        assert!(execute(&state, &[raw], 1, &cfg, f.active[0]).is_err());
    }
    assert!(execute(&state, &[signed(&f, &t, 1)], 1, &cfg, f.active[0]).is_err());
    let mut payload = f.active[1].to_vec();
    payload.extend(1000u64.to_le_bytes());
    let legacy = Envelope {
        network: cfg.network,
        sender: f.active[0],
        nonce: 23,
        expiry: 100,
        fee_limit: 100_000,
        tag: 1,
        payload,
        signature: [0; 64],
    }
    .encode()
    .unwrap();
    assert_eq!(
        execute(&state, &[legacy], 1, &cfg, f.active[0]).unwrap_err(),
        "PQ_ACCOUNT_ENCODING"
    );
    assert!(executor::validate_main_envelope(&raw, 1, &cfg).is_err());
    assert!(execute(
        &state,
        &[raw],
        1,
        &Config::installed().unwrap(),
        f.active[0]
    )
    .is_err());
}

#[test]
fn dual_migration_native_verification_rejects_either_signature_revocation_or_target_substitution() {
    let mut f = fixture();
    f.evidence[0].old_signature[0] ^= 1;
    assert!(pq_accounts::import_genesis(&f.raw, &f.pins, &f.evidence).is_err());
    f.evidence[0].old_signature[0] ^= 1;
    f.evidence[0].pq_signature[0] ^= 1;
    assert!(pq_accounts::import_genesis(&f.raw, &f.pins, &f.evidence).is_err());
    f.evidence[0].pq_signature[0] ^= 1;
    f.pins.revoked_old_keys.insert(f.evidence[0].old_public);
    assert!(pq_accounts::import_genesis(&f.raw, &f.pins, &f.evidence).is_err());
    f.pins.revoked_old_keys.clear();
    f.pins.target_state_root[0] ^= 1;
    assert!(pq_accounts::import_genesis(&f.raw, &f.pins, &f.evidence).is_err());
    f.pins.target_state_root[0] ^= 1;
    let now = f.pins.now;
    f.pins.now = f.evidence[0].expires_at + 1;
    assert!(pq_accounts::import_genesis(&f.raw, &f.pins, &f.evidence).is_err());
    f.pins.now = now;
    f.pins.genesis_timestamp += 1;
    assert!(pq_accounts::import_genesis(&f.raw, &f.pins, &f.evidence).is_err());
    f.pins.genesis_timestamp -= 1;
    assert!(pq_accounts::import_genesis(&f.raw, &f.pins, &f.evidence[..1]).is_err());
    let mut truncated = f.raw.clone();
    truncated.truncate(truncated.len() - 81);
    assert!(pq_accounts::import_genesis(&truncated, &f.pins, &f.evidence).is_err());
}

#[test]
fn native_parent_rejects_nonce_reset_liability_omission_and_rebound_parameters() {
    let f = fixture();
    let (mut cfg, mut state) = imported(&f);
    let tx = signed(&f, &transfer(&f, 0, 23, 1000), 0);
    let account = format!("account:{}", hex::encode(f.active[0]));
    state.get_mut(&account).unwrap()["nonce"] = json!(0);
    assert_eq!(
        execute(&state, std::slice::from_ref(&tx), 1, &cfg, f.active[0]).unwrap_err(),
        "PQ_ACCOUNT_NONCE_FLOOR"
    );
    state.get_mut(&account).unwrap()["nonce"] = json!(22);
    let liability = state
        .keys()
        .find(|k| k.starts_with("pq-import-liability:"))
        .unwrap()
        .clone();
    state.remove(&liability);
    assert_eq!(
        execute(&state, std::slice::from_ref(&tx), 1, &cfg, f.active[0]).unwrap_err(),
        "PQ_IMPORT_LIABILITY_CHANGED"
    );
    cfg.parameters = hash(b"wrong-parameters", &[]);
    assert!(execute(&state, &[tx], 1, &cfg, f.active[0]).is_err());
}

#[test]
fn rust_qtx1_matches_original_python_wire_signature_identity_and_exact_fee() {
    let f = fixture();
    let (cfg, state) = imported(&f);
    let mut t = transfer(&f, 0, 23, 1000);
    t.memo = vec![0xa5; 512];
    let raw = signed(&f, &t, 0);
    let key_id = ml_dsa_65_key_id_from_spki(&f.keys[0].public_key_to_der().unwrap()).unwrap();
    let input = json!({"raw":hex::encode(&raw),
        "pem":String::from_utf8(f.keys[0].public_key_to_pem().unwrap()).unwrap(),
        "network":hex::encode(t.network),"account":hex::encode(t.sender),
        "key":hex::encode(key_id),"generation":t.generation,"nonce":t.nonce,
        "balance":10_000_000,"base_fee":cfg.fees[1],"byte_fee":cfg.params["byte_fee_units"]});
    let script = r#"import json,sys
from pq_transaction import AccountView,preflight_transfer,parse_signed_transfer
p=json.load(sys.stdin);b=bytes.fromhex
a=AccountView(b(p['network']),b(p['account']),b(p['key']),p['generation'],p['nonce'],p['balance'],True)
r=preflight_transfer(b(p['raw']),public_pem=p['pem'].encode(),account=a,now=1,base_fee=p['base_fee'],byte_fee=p['byte_fee'])
t,body,frame=parse_signed_transfer(b(p['raw']))
print(json.dumps({'id':r.identity.hex(),'bytes':r.encoded_bytes,'fee':r.required_fee,'remaining':r.remaining_units,'body':body.hex(),'statement':frame[:176].hex()}))
"#;
    let mut child = Command::new("python3")
        .args(["-c", script])
        .current_dir(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../../formal/pon-nakamoto-v1"),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&input).unwrap())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "original QTX1 oracle: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let reference: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(reference["body"], hex::encode(t.encode().unwrap()));
    assert_eq!(
        reference["statement"],
        hex::encode(t.unsigned_statement(key_id).unwrap())
    );
    assert_eq!(reference["id"], hex::encode(t.logical_id(key_id).unwrap()));
    assert_eq!(reference["bytes"], raw.len());
    assert_eq!(raw.len(), 4143);
    let applied = execute(&state, &[raw], 1, &cfg, f.active[0]).unwrap();
    assert_eq!(
        applied.state[&format!("account:{}", hex::encode(f.active[0]))]["balance"],
        reference["remaining"]
    );
    let receipt: Value = serde_json::from_slice(&applied.receipts[0]).unwrap();
    assert_eq!(receipt["tx"], reference["id"]);
    assert_eq!(receipt["fee"], reference["fee"]);
}

#[test]
fn qtx1_from_another_import_context_refuses_even_if_declared_network_reused() {
    let f = fixture();
    let other = fixture_at(f.pins.genesis_timestamp - 1);
    let (cfg, state) = imported(&f);
    let (other_cfg, other_state) = imported(&other);
    assert_eq!(f.pins.new_network, other.pins.new_network);
    assert_eq!(f.active, other.active);
    assert_ne!(cfg.parameters, other_cfg.parameters);
    assert_ne!(f.pins.target_genesis, other.pins.target_genesis);
    let raw = signed(&f, &transfer(&f, 0, 23, 1000), 0);
    assert!(execute(&state, std::slice::from_ref(&raw), 1, &cfg, f.active[0]).is_ok());
    let cross = execute(&other_state, &[raw], 1, &other_cfg, other.active[0]);
    println!(
        "{}",
        json!({"case":"cross_import_qtx1_replay","declared_network_reused":true,
        "source_genesis":hex::encode(f.pins.target_genesis),"other_genesis":hex::encode(other.pins.target_genesis),
        "source_parameters":hex::encode(cfg.parameters),"other_parameters":hex::encode(other_cfg.parameters),
        "source_network":hex::encode(cfg.network),"other_network":hex::encode(other_cfg.network),
        "foreign_transaction_applied":cross.is_ok()})
    );
    assert!(
        cross.is_err(),
        "valid QTX1 was replayed into another imported genesis"
    );
}

#[test]
fn dual_possession_does_not_recover_already_compromised_classical_identity() {
    let f = fixture();
    // This controlled adversary is explicitly given the published old test
    // signing keys. It is not a quantum computation or an attack on ML-DSA.
    let attacker = fixture_with_keys(f.pins.genesis_timestamp, [93, 94]);
    assert_eq!(f.raw, attacker.raw);
    assert_ne!(f.pins.target_genesis, attacker.pins.target_genesis);
    let refused = pq_accounts::import_genesis(&f.raw, &f.pins, &attacker.evidence);
    assert!(matches!(refused, Err("PQ_IMPORT_TARGET_PINS")));
    // Dual valid signatures alone allow either new key roster. The independent
    // frozen target commitment supplies the ownership selection, not cryptography
    // that somehow repairs the compromised old signer.
    assert!(pq_accounts::import_genesis(&attacker.raw, &attacker.pins, &attacker.evidence).is_ok());
    println!(
        "{}",
        json!({"case":"compromised_legacy_identity","legacy_signing_capability_given":true,
        "self_selected_pq_keys_have_valid_dual_signatures":true,"original_target_pins_reject":true,
        "actual_quantum_attack":false,"dual_signatures_alone_restore_ownership":false})
    );
}
