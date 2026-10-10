//! Real main/source signatures and native executor transitions. These are ledger
//! lifecycle tests, not a chain mining/hardness or independent-demand qualification.
use serde_json::json;
use trnm_crypto_primitives::{
    pon_work,
    qualified_work_task::{
        derive_matrices, lifecycle_v2::verify_lifecycle_admission, TaskMaterial,
    },
};
use trnm_mvcc_fee::{
    pon_executor::{self, Config, State},
    qualified_task_lifecycle::{
        self as lifecycle, bootstrap_state, consume_output, eligible_task, slot_key,
        GENERATION_KEY, MAX_RECORD_BYTES, SLOT_PREFIX,
    },
};
use trnm_protocol::{
    pon_wire::{hash, Envelope, Hash},
    qualified_work_task::{
        lifecycle_v2::{
            DemandLeaseV2, DemandRevocationV2, SignedLifecycleTaskV2, OPEN_TAG, PROFILE,
            REGISTER_TAG, RENEW_TAG, REVOKE_TAG,
        },
        QualifiedWorkTask, TaskPurpose, LOGICAL_MULTIPLY_ADD_UNITS, MATRIX_ARTIFACT_BYTES,
    },
};

fn public(index: u64) -> Hash {
    trnm_crypto_primitives::signing_key_from_hex(&hex::encode(hash(
        b"DEV-ONLY-KEY",
        &[&index.to_le_bytes()],
    )))
    .unwrap()
    .verifying_key()
    .to_bytes()
}
fn sign(index: u64, message: &[u8]) -> [u8; 64] {
    let key = trnm_crypto_primitives::signing_key_from_hex(&hex::encode(hash(
        b"DEV-ONLY-KEY",
        &[&index.to_le_bytes()],
    )))
    .unwrap();
    hex::decode(trnm_crypto_primitives::sign_hex(&key, message))
        .unwrap()
        .try_into()
        .unwrap()
}
fn material(offset: u32) -> (Vec<u8>, Vec<u8>) {
    let a: Vec<_> = (0..4096)
        .map(|i| ((i as u32) * 11 + offset) % 1009)
        .collect();
    let b: Vec<_> = (0..4096)
        .map(|i| ((i as u32) * 17 + offset) % 1013)
        .collect();
    (
        a.iter().flat_map(|v| v.to_le_bytes()).collect(),
        b.iter().flat_map(|v| v.to_le_bytes()).collect(),
    )
}
fn initial() -> (Config, State) {
    let cfg = Config::installed_with_profiles("legacy-first-two-v3", PROFILE).unwrap();
    let (model, input) = material(1);
    let bootstrap = bootstrap_state(&cfg, &model, &input).unwrap();
    let mut state = bootstrap.state;
    for account in 0..6 {
        state.insert(
            format!("account:{}", hex::encode(public(account))),
            json!({"balance":10_000_000,"nonce":0}),
        );
    }
    state.insert("meta:issued".into(), json!(60_000_000));
    state.insert("model:current".into(), json!(hex::encode([0; 32])));
    (cfg, state)
}
fn tx(state: &State, cfg: &Config, sender: u64, tag: u8, payload: Vec<u8>) -> Vec<u8> {
    // The ledger sequence comes from the real predecessor account state.
    let sequence = state[&format!("account:{}", hex::encode(public(sender)))]["nonce"]
        .as_u64()
        .unwrap()
        .checked_add(1)
        .unwrap();
    let mut envelope = Envelope {
        network: cfg.network,
        sender: public(sender),
        nonce: sequence,
        expiry: 100_000,
        fee_limit: 10_000_000,
        tag,
        payload,
        signature: [0; 64],
    };
    envelope.signature = sign(sender, &envelope.signing_digest().unwrap());
    envelope.encode().unwrap()
}
fn execute(
    state: &State,
    cfg: &Config,
    transactions: Vec<Vec<u8>>,
    height: u64,
    workers: usize,
) -> pon_executor::Result<pon_executor::Output> {
    pon_executor::execute(
        state,
        &transactions,
        height,
        public(5),
        [42; 32],
        workers,
        cfg,
    )
}
fn request(state: &State, cfg: &Config, slot: u8, height: u64, expiry: u64) -> DemandLeaseV2 {
    let generation = state[GENERATION_KEY]
        .as_u64()
        .unwrap()
        .checked_add(1)
        .unwrap();
    let mut lease = DemandLeaseV2 {
        slot,
        purpose: TaskPurpose::InferenceContraction,
        network: cfg.network,
        parameters: cfg.parameters,
        demand_id: [1; 32],
        requester: public(2),
        source: public(3),
        source_record: [4; 32],
        authorization_scope: [5; 32],
        availability_manifest: [6; 32],
        availability_root: [7; 32],
        generation,
        revision: 1,
        not_before: height,
        expires: expiry,
        available_until: expiry + 100,
        cost_class: 1,
    };
    lease.demand_id = lease.derived_demand_id();
    lease
}
fn statement(lease: &DemandLeaseV2, offset: u32, source_sequence: u64) -> SignedLifecycleTaskV2 {
    let (model, input) = material(offset);
    let (a, b) = derive_matrices(&model, &input).unwrap();
    let model_id = hash(b"artifact", &[&model]);
    let mut manifest = QualifiedWorkTask {
        purpose: lease.purpose,
        cost_class: 1,
        numeric_encoding: 1,
        hardness_status: 0,
        reuse: 1,
        network: lease.network,
        parameters: lease.parameters,
        work_profile: QualifiedWorkTask::profile_id(),
        source: lease.source,
        demand_id: lease.demand_id,
        source_record: lease.bound_source_record().unwrap(),
        model: model_id,
        layer: QualifiedWorkTask::layer_id(model_id),
        input: hash(b"qualified-task-input-v1", &[&input]),
        recipe: QualifiedWorkTask::recipe_id(),
        matrix_task: pon_work::task_id(&a, &b).unwrap(),
        availability_manifest: lease.availability_manifest,
        availability_root: lease.availability_root,
        authorization_scope: lease.authorization_scope,
        withdrawal_head: lease.withdrawal_frontier().unwrap(),
        output_meter: [1; 32],
        rows: 64,
        inner: 64,
        columns: 64,
        demand_nonce: source_sequence,
        not_before: lease.not_before,
        expires: lease.expires,
        available_until: lease.available_until,
        logical_multiply_add_units: LOGICAL_MULTIPLY_ADD_UNITS,
        model_bytes: MATRIX_ARTIFACT_BYTES,
        input_bytes: MATRIX_ARTIFACT_BYTES,
        useful_output_limit: lease.purpose.output_limit(),
    };
    manifest.output_meter = manifest.derived_output_meter();
    let mut signed = SignedLifecycleTaskV2 {
        lease_id: lease.id().unwrap(),
        manifest,
        signature: [0; 64],
    };
    signed.signature = sign(
        if lease.source == public(0) { 0 } else { 3 },
        &signed.signing_message().unwrap(),
    );
    signed
}
fn admitted() -> (Config, State, DemandLeaseV2, SignedLifecycleTaskV2) {
    let (cfg, base) = initial();
    let lease = request(&base, &cfg, 1, 1, 20);
    let signed = statement(&lease, 2, 1);
    let output = execute(
        &base,
        &cfg,
        vec![
            tx(&base, &cfg, 2, OPEN_TAG, lease.encode().unwrap()),
            tx(&base, &cfg, 3, REGISTER_TAG, signed.encode().unwrap()),
        ],
        1,
        4,
    )
    .unwrap();
    (cfg, output.state, lease, signed)
}

#[test]
fn explicit_genesis_has_real_bound_maintenance_and_old_context_isolated() {
    let (cfg, state) = initial();
    let (model, input) = material(1);
    let bootstrap = bootstrap_state(&cfg, &model, &input).unwrap();
    let eligible = eligible_task(&state, bootstrap.signed.manifest.matrix_task, 1, &cfg).unwrap();
    assert_eq!(eligible.lease(), &bootstrap.lease);
    assert_eq!(eligible.statement_id(), bootstrap.signed.id().unwrap());
    assert_eq!(eligible.manifest().useful_output_limit, 0);
    let (a, b) = derive_matrices(&model, &input).unwrap();
    verify_lifecycle_admission(
        &bootstrap.signed.encode().unwrap(),
        TaskMaterial {
            model: &model,
            input: &input,
            a: &a,
            b: &b,
        },
        &bootstrap.lease,
        1,
    )
    .unwrap();
    assert!(bootstrap_state(&Config::installed().unwrap(), &model, &input).is_err());
    assert!(bootstrap_state(&cfg, &model[..100], &input).is_err());
    assert!(eligible_task(&state, bootstrap.signed.manifest.matrix_task, 1001, &cfg).is_err());
}

#[test]
fn renewal_requires_new_source_statement_and_preserves_real_output_meter() {
    let (cfg, mut state, lease, first) = admitted();
    assert!(eligible_task(&state, first.manifest.matrix_task, 1, &cfg).is_err());
    let eligible = eligible_task(&state, first.manifest.matrix_task, 2, &cfg).unwrap();
    let (model, input) = material(2);
    let (a, b) = derive_matrices(&model, &input).unwrap();
    let bytes = pon_work::prove([23; 32], &a, &b).unwrap();
    let work = pon_work::verify([23; 32], first.manifest.matrix_task, [255; 32], &bytes).unwrap();
    let product: Vec<_> = work
        .product()
        .iter()
        .flat_map(|v| v.to_le_bytes())
        .collect();
    let product_hash = hash(b"qualified-task-product-v1", &[&product]);
    assert!(consume_output(&mut state, &eligible, product_hash, 2).unwrap());
    assert!(!consume_output(&mut state, &eligible, product_hash, 3).unwrap());
    let mut renewed = lease.clone();
    renewed.revision += 1;
    renewed.not_before = 15;
    renewed.expires = 35;
    renewed.available_until = 135;
    let out = execute(
        &state,
        &cfg,
        vec![tx(&state, &cfg, 2, RENEW_TAG, renewed.encode().unwrap())],
        15,
        4,
    )
    .unwrap();
    assert!(eligible_task(&out.state, first.manifest.matrix_task, 16, &cfg).is_err());
    assert_eq!(out.state[&slot_key(1).unwrap()]["output_count"], 1);
    let sequence = out.state[&slot_key(1).unwrap()]["source_sequence"]
        .as_u64()
        .unwrap()
        + 1;
    let second = statement(&renewed, 2, sequence);
    assert_eq!(second.manifest.output_meter, first.manifest.output_meter);
    let out = execute(
        &out.state,
        &cfg,
        vec![tx(
            &out.state,
            &cfg,
            3,
            REGISTER_TAG,
            second.encode().unwrap(),
        )],
        16,
        4,
    )
    .unwrap();
    let later = eligible_task(&out.state, first.manifest.matrix_task, 17, &cfg).unwrap();
    let mut state = out.state;
    assert!(!consume_output(&mut state, &later, product_hash, 17).unwrap());
    assert_eq!(
        consume_output(&mut state, &later, [88; 32], 17),
        Err("TASK_OUTPUT_CONFLICT")
    );
}

#[test]
fn source_cannot_reset_material_or_statement_sequence() {
    let (cfg, state, lease, first) = admitted();
    let replay = execute(
        &state,
        &cfg,
        vec![tx(&state, &cfg, 3, REGISTER_TAG, first.encode().unwrap())],
        2,
        1,
    );
    assert_eq!(replay.unwrap_err(), "TASK_SOURCE_NONCE");
    let changed = statement(
        &lease,
        7,
        state[&slot_key(1).unwrap()]["source_sequence"]
            .as_u64()
            .unwrap()
            + 1,
    );
    assert_eq!(
        execute(
            &state,
            &cfg,
            vec![tx(&state, &cfg, 3, REGISTER_TAG, changed.encode().unwrap())],
            2,
            1
        )
        .unwrap_err(),
        "TASK_RENEW_MATERIAL"
    );
}

#[test]
fn authenticated_revocation_is_terminal_and_preserves_retention() {
    let (cfg, state, lease, first) = admitted();
    let revoke = DemandRevocationV2 {
        slot: lease.slot,
        network: cfg.network,
        parameters: cfg.parameters,
        demand_id: lease.demand_id,
        requester: lease.requester,
        expected_revision: lease.revision,
    };
    assert_eq!(
        execute(
            &state,
            &cfg,
            vec![tx(&state, &cfg, 3, REVOKE_TAG, revoke.encode().unwrap())],
            2,
            1
        )
        .unwrap_err(),
        "TASK_REQUESTER"
    );
    let out = execute(
        &state,
        &cfg,
        vec![tx(&state, &cfg, 2, REVOKE_TAG, revoke.encode().unwrap())],
        2,
        1,
    )
    .unwrap();
    assert!(eligible_task(&out.state, first.manifest.matrix_task, 3, &cfg).is_err());
    assert_eq!(
        execute(
            &out.state,
            &cfg,
            vec![tx(
                &out.state,
                &cfg,
                3,
                REGISTER_TAG,
                first.encode().unwrap()
            )],
            3,
            1
        )
        .unwrap_err(),
        "TASK_REVOKED"
    );
    let replacement = request(&out.state, &cfg, 1, 3, 30);
    assert_eq!(
        execute(
            &out.state,
            &cfg,
            vec![tx(
                &out.state,
                &cfg,
                2,
                OPEN_TAG,
                replacement.encode().unwrap()
            )],
            3,
            1
        )
        .unwrap_err(),
        "TASK_RETAINED"
    );
    let mut renewed = lease.clone();
    renewed.revision += 1;
    renewed.not_before = 3;
    renewed.expires = 30;
    renewed.available_until = 130;
    assert_eq!(
        execute(
            &out.state,
            &cfg,
            vec![tx(
                &out.state,
                &cfg,
                2,
                RENEW_TAG,
                renewed.encode().unwrap()
            )],
            3,
            1
        )
        .unwrap_err(),
        "TASK_REVOKED"
    );
}

#[test]
fn more_than_sixteen_demands_recycle_bounded_metadata_and_never_reuse_identity() {
    let (cfg, mut state) = initial();
    let mut seen = std::collections::BTreeSet::new();
    for cycle in 0..40 {
        let height = 1 + cycle * 103;
        let lease = request(&state, &cfg, 1, height, height + 2);
        assert!(seen.insert(lease.demand_id));
        let signed = statement(&lease, 2, 1);
        state = execute(
            &state,
            &cfg,
            vec![
                tx(&state, &cfg, 2, OPEN_TAG, lease.encode().unwrap()),
                tx(&state, &cfg, 3, REGISTER_TAG, signed.encode().unwrap()),
            ],
            height,
            4,
        )
        .unwrap()
        .state;
        eligible_task(&state, signed.manifest.matrix_task, height + 1, &cfg).unwrap();
        assert_eq!(
            state
                .keys()
                .filter(|key| key.starts_with(SLOT_PREFIX))
                .count(),
            2
        );
        assert!(state
            .iter()
            .filter(|(key, _)| key.starts_with(SLOT_PREFIX))
            .all(|(_, value)| serde_json::to_vec(value).unwrap().len() <= MAX_RECORD_BYTES));
    }
    assert_eq!(state[GENERATION_KEY], 41);
    // No PoN packet was mined by this executor-only lifecycle test.
}

#[test]
fn canonical_parallel_execution_tracks_global_generation_and_prefix_conflicts() {
    let (cfg, base) = initial();
    let first = request(&base, &cfg, 1, 1, 20);
    let mut second = request(&base, &cfg, 2, 1, 20);
    second.generation = first.generation + 1;
    second.requester = public(4);
    second.demand_id = second.derived_demand_id();
    let transactions = vec![
        tx(&base, &cfg, 2, OPEN_TAG, first.encode().unwrap()),
        tx(&base, &cfg, 4, OPEN_TAG, second.encode().unwrap()),
    ];
    let serial = execute(&base, &cfg, transactions.clone(), 1, 1).unwrap();
    let parallel = execute(&base, &cfg, transactions, 1, 4).unwrap();
    assert_eq!(serial.state, parallel.state);
    assert_eq!(serial.root, parallel.root);
    assert_eq!(serial.receipts, parallel.receipts);
    assert_eq!(parallel.state[GENERATION_KEY], 3);
}

#[test]
fn failed_fee_signature_nonce_and_wrong_profile_do_not_publish_state() {
    let (cfg, base) = initial();
    let lease = request(&base, &cfg, 1, 1, 20);
    let raw = tx(&base, &cfg, 2, OPEN_TAG, lease.encode().unwrap());
    let snapshot = base.clone();
    assert_eq!(
        execute(&base, &cfg, vec![raw.clone(), raw.clone()], 1, 4).unwrap_err(),
        "NONCE"
    );
    let mut bad = Envelope::decode(&raw).unwrap();
    bad.signature.fill(0);
    assert_eq!(
        execute(&base, &cfg, vec![bad.encode().unwrap()], 1, 1).unwrap_err(),
        "SIGNATURE"
    );
    let mut no_funds = base.clone();
    no_funds
        .get_mut(&format!("account:{}", hex::encode(public(2))))
        .unwrap()["balance"] = json!(0);
    assert_eq!(
        execute(&no_funds, &cfg, vec![raw], 1, 1).unwrap_err(),
        "FUNDS"
    );
    let historical = Config::installed().unwrap();
    assert!(lifecycle::apply_verified_command(&mut base.clone(), &bad, 1, &historical).is_err());
    assert_eq!(base, snapshot);
}

#[test]
fn same_matrix_cannot_authorize_two_active_demands_and_slot_integrity_checked() {
    let (cfg, state, _lease, first) = admitted();
    let second = request(&state, &cfg, 2, 2, 30);
    let signed = statement(&second, 2, 1);
    assert_eq!(
        execute(
            &state,
            &cfg,
            vec![
                tx(&state, &cfg, 2, OPEN_TAG, second.encode().unwrap()),
                tx(&state, &cfg, 3, REGISTER_TAG, signed.encode().unwrap())
            ],
            2,
            4
        )
        .unwrap_err(),
        "TASK_MATRIX_IN_USE"
    );
    let mut corrupted = state.clone();
    let copy = state[&slot_key(1).unwrap()].clone();
    corrupted.insert(format!("{SLOT_PREFIX}99"), copy);
    assert!(eligible_task(&corrupted, first.manifest.matrix_task, 2, &cfg).is_err());
}
