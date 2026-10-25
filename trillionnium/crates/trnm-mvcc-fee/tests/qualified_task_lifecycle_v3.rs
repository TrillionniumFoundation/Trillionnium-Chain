use serde_json::Value;
use trnm_mvcc_fee::{
    pon_executor::{Config, State},
    qualified_task_lifecycle::{self, slot_key, LifecycleState},
};
use trnm_protocol::{
    pon_wire::{hash, Envelope},
    qualified_work_task::{
        lifecycle_v2::{DemandLeaseV2, SignedLifecycleTaskV2},
        lifecycle_v3::{AtomicRenewTaskV3, PROFILE},
    },
};
fn sign(who: u64, message: &[u8]) -> [u8; 64] {
    let key = trnm_crypto_primitives::signing_key_from_hex(&hex::encode(hash(
        b"DEV-ONLY-KEY",
        &[&who.to_le_bytes()],
    )))
    .unwrap();
    hex::decode(trnm_crypto_primitives::sign_hex(&key, message))
        .unwrap()
        .try_into()
        .unwrap()
}
struct Spy {
    state: State,
    writes: usize,
}
impl LifecycleState for Spy {
    fn get(&mut self, key: &str) -> Option<Value> {
        self.state.get(key).cloned()
    }
    fn put(&mut self, key: String, value: Value) {
        self.writes += 1;
        self.state.insert(key, value);
    }
    fn scan(&mut self, prefix: &str) -> State {
        self.state
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}
fn request(lease: &DemandLeaseV2, old: &SignedLifecycleTaskV2, sequence: u64) -> AtomicRenewTaskV3 {
    let mut signed = old.clone();
    signed.lease_id = lease.id().unwrap();
    signed.manifest.source_record = lease.bound_source_record().unwrap();
    signed.manifest.withdrawal_head = lease.withdrawal_frontier().unwrap();
    signed.manifest.not_before = lease.not_before;
    signed.manifest.expires = lease.expires;
    signed.manifest.available_until = lease.available_until;
    signed.manifest.demand_nonce = sequence;
    signed.signature = sign(0, &signed.signing_message().unwrap());
    AtomicRenewTaskV3 {
        lease: lease.clone(),
        signed,
    }
}
#[test]
fn lifecycle_owner_writes_exactly_once_after_all_validations_and_never_on_failure() {
    let cfg = Config::installed_with_profiles("native-public-evaluation-dev-v1", PROFILE).unwrap();
    assert_eq!(cfg.params["consensus_revision"], 8);
    assert_eq!(cfg.fees[22], 200);
    let model: Vec<u8> = (0..4096_u32).flat_map(|i| (i % 97).to_le_bytes()).collect();
    let input: Vec<u8> = (0..4096_u32)
        .flat_map(|i| (i % 101).to_le_bytes())
        .collect();
    let boot = qualified_task_lifecycle::bootstrap_state(&cfg, &model, &input).unwrap();
    let mut lease = boot.lease.clone();
    lease.revision += 1;
    lease.not_before = 1;
    lease.expires = 1001;
    lease.available_until = 1101;
    let good = request(&lease, &boot.signed, 2);
    let envelope = |raw: Vec<u8>| {
        let mut tx = Envelope {
            network: cfg.network,
            sender: lease.requester,
            nonce: 1,
            expiry: 100,
            fee_limit: 100000,
            tag: 22,
            payload: raw,
            signature: [0; 64],
        };
        tx.signature = sign(1, &tx.signing_digest().unwrap());
        tx
    };
    let mut bad = good.clone();
    bad.signed.signature[0] ^= 1;
    for request in [bad, request(&lease, &boot.signed, 3)] {
        let mut spy = Spy {
            state: boot.state.clone(),
            writes: 0,
        };
        assert!(qualified_task_lifecycle::apply_verified_command(
            &mut spy,
            &envelope(request.encode().unwrap()),
            1,
            &cfg
        )
        .is_err());
        assert_eq!(spy.writes, 0);
        assert_eq!(spy.state, boot.state);
    }
    let mut spy = Spy {
        state: boot.state.clone(),
        writes: 0,
    };
    qualified_task_lifecycle::apply_verified_command(
        &mut spy,
        &envelope(good.encode().unwrap()),
        1,
        &cfg,
    )
    .unwrap();
    assert_eq!(spy.writes, 1);
    let record = &spy.state[&slot_key(0).unwrap()];
    assert_eq!(record["source_sequence"], 2);
    assert_eq!(record["output_count"], 0);
    assert!(qualified_task_lifecycle::eligible_task(
        &spy.state,
        boot.signed.manifest.matrix_task,
        2,
        &cfg
    )
    .is_ok());
}
