use serde_json::Value;
use trnm_mvcc_fee::{
    pon_executor::{Config, State},
    qualified_task_lifecycle::{self, slot_key, LifecycleState},
};
use trnm_protocol::{
    pon_wire::{hash, Envelope},
    qualified_work_task::{
        lifecycle_v2::{DemandLeaseV2, SignedLifecycleTaskV2},
        lifecycle_v4::{AtomicRenewTaskV4 as AtomicRenewTaskV3, PROFILE},
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
fn overlap_owner_writes_exactly_once_after_all_validations_and_never_on_failure() {
    let cfg = Config::installed_with_profiles("native-public-evaluation-dev-v1", PROFILE).unwrap();
    assert_eq!(cfg.params["consensus_revision"], 9);
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

#[test]
fn signed_overlap_includes_at900_905_999_but_future_expired_regressing_or_invalid_sources_do_not_write(
) {
    let cfg = Config::installed_with_profiles("native-public-evaluation-dev-v1", PROFILE).unwrap();
    let model: Vec<u8> = (0..4096u32).flat_map(|i| (i % 97).to_le_bytes()).collect();
    let input: Vec<u8> = (0..4096u32).flat_map(|i| (i % 101).to_le_bytes()).collect();
    let boot = qualified_task_lifecycle::bootstrap_state(&cfg, &model, &input).unwrap();
    let mut successor = boot.lease.clone();
    successor.revision = 2;
    successor.not_before = 900;
    successor.expires = 1900;
    successor.available_until = 2000;
    let good = request(&successor, &boot.signed, 2);
    let envelope = |r: &AtomicRenewTaskV3| Envelope {
        network: cfg.network,
        sender: successor.requester,
        nonce: 1,
        expiry: 2000,
        fee_limit: 100000,
        tag: 22,
        payload: r.encode().unwrap(),
        signature: [0; 64],
    };
    for height in [900, 905, 999, 1000] {
        let mut spy = Spy {
            state: boot.state.clone(),
            writes: 0,
        };
        qualified_task_lifecycle::apply_verified_command(&mut spy, &envelope(&good), height, &cfg)
            .unwrap();
        assert_eq!(spy.writes, 1);
        assert_eq!(spy.state[&slot_key(0).unwrap()]["source_sequence"], 2);
        assert_eq!(spy.state[&slot_key(0).unwrap()]["output_count"], 0);
        assert_eq!(
            spy.state[&slot_key(0).unwrap()]["statement"],
            hex::encode(good.signed.encode().unwrap())
        );
    }
    let mut bad_signature = good.clone();
    bad_signature.signed.signature[0] ^= 1;
    for (height, r) in [
        (899, good.clone()),
        (1001, good.clone()),
        (905, bad_signature),
        (905, request(&successor, &boot.signed, 3)),
    ] {
        let mut spy = Spy {
            state: boot.state.clone(),
            writes: 0,
        };
        assert!(qualified_task_lifecycle::apply_verified_command(
            &mut spy,
            &envelope(&r),
            height,
            &cfg
        )
        .is_err());
        assert_eq!(spy.writes, 0);
        assert_eq!(spy.state, boot.state);
    }
    // Build a valid shorter successor first, then reject a backward window whose
    // codec is valid. This tests monotonic start, independently of max1000 length.
    let mut first = boot.lease.clone();
    first.revision = 2;
    first.not_before = 500;
    first.expires = 1100;
    first.available_until = 1200;
    let first_request = request(&first, &boot.signed, 2);
    let mut prior = Spy {
        state: boot.state.clone(),
        writes: 0,
    };
    qualified_task_lifecycle::apply_verified_command(
        &mut prior,
        &envelope(&first_request),
        500,
        &cfg,
    )
    .unwrap();
    let before = prior.state.clone();
    prior.writes = 0;
    let mut backwards = first.clone();
    backwards.revision = 3;
    backwards.not_before = 400;
    backwards.expires = 1101;
    backwards.available_until = 1201;
    let second = request(&backwards, &first_request.signed, 3);
    assert!(qualified_task_lifecycle::apply_verified_command(
        &mut prior,
        &envelope(&second),
        501,
        &cfg
    )
    .is_err());
    assert_eq!(prior.writes, 0);
    assert_eq!(prior.state, before);
    let mut oversized = successor.clone();
    oversized.expires = 1901;
    oversized.available_until = 2001;
    assert!(oversized.encode().is_err());
}

#[test]
fn old_v3_keeps_exact_height_and_never_adopts_v4_overlapping_behavior() {
    let cfg = Config::installed_with_profiles(
        "native-public-evaluation-dev-v1",
        "signed-task-lifecycle-dev-v3",
    )
    .unwrap();
    let model: Vec<u8> = (0..4096u32).flat_map(|i| (i % 97).to_le_bytes()).collect();
    let input: Vec<u8> = (0..4096u32).flat_map(|i| (i % 101).to_le_bytes()).collect();
    let boot = qualified_task_lifecycle::bootstrap_state(&cfg, &model, &input).unwrap();
    let mut successor = boot.lease.clone();
    successor.revision = 2;
    successor.not_before = 1;
    successor.expires = 1001;
    successor.available_until = 1101;
    let good = request(&successor, &boot.signed, 2);
    let envelope = Envelope {
        network: cfg.network,
        sender: successor.requester,
        nonce: 1,
        expiry: 100,
        fee_limit: 100000,
        tag: 22,
        payload: good.encode().unwrap(),
        signature: [0; 64],
    };
    for height in [0, 2] {
        let mut spy = Spy {
            state: boot.state.clone(),
            writes: 0,
        };
        assert!(qualified_task_lifecycle::apply_verified_command(
            &mut spy, &envelope, height, &cfg
        )
        .is_err());
        assert_eq!(spy.writes, 0);
        assert_eq!(spy.state, boot.state);
    }
    let mut spy = Spy {
        state: boot.state,
        writes: 0,
    };
    qualified_task_lifecycle::apply_verified_command(&mut spy, &envelope, 1, &cfg).unwrap();
    assert_eq!(spy.writes, 1);
}
