//! Public deterministic research keys, but real NPQ6 signatures, Work, M06,
//! original continuous CPU/Journal, SQL owner and cold-open checks. These local
//! sources do not establish independent Registry2 or deployment qualification.
use super::*;
use crate::{
    operator_continuous_history as history, operator_continuous_policy as policy,
    operator_continuous_recipient as recipient, operator_continuous_test_support as fixtures,
    operator_pq_auth::{Profile, PQ_IDENTITY},
    operator_task_policy::{digest_bytes, MaterialInput},
};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};
use trnm_crypto_primitives::{pon_work, pq_auth::PqNativeSigningKey};
use trnm_protocol::{
    pon_wire::hash,
    pq_frame::{ml_dsa_65_key_id_from_spki, ML_DSA_65_SIGNATURE_BYTES},
    pq_native_accounts_v2 as wire,
    qualified_work_task::{
        QualifiedWorkTask, TaskPurpose, LOGICAL_MULTIPLY_ADD_UNITS, MATRIX_ARTIFACT_BYTES,
    },
};
use zeroize::Zeroizing;

fn key(seed: u8) -> PqNativeSigningKey {
    let seed = Zeroizing::new([seed; 32]);
    let spki = PqNativeSigningKey::public_spki_from_seed(&seed);
    let id = ml_dsa_65_key_id_from_spki(&spki).unwrap();
    PqNativeSigningKey::from_owned_seed(seed, id).unwrap()
}
fn key_id(key: &PqNativeSigningKey) -> Hash {
    ml_dsa_65_key_id_from_spki(key.public_spki()).unwrap()
}
fn sign_command(
    settings: &Settings,
    kind: u8,
    payload: &[u8],
    nonce: u64,
    keys: &[&PqNativeSigningKey],
) -> Vec<u8> {
    let common = wire::Common {
        context: wire::ChainContext {
            network: settings.network(),
            parameters: settings.parameters(),
            genesis: settings.genesis(),
        },
        account: key_id(keys[0]),
        nonce,
        expires_at: 2000,
        max_fee: 100_000,
        generation: 1,
    };
    let descriptors: Vec<_> = keys
        .iter()
        .enumerate()
        .map(|(index, key)| wire::WitnessKey {
            role: index as u8 + 1,
            generation: 1,
            key_id: key_id(key),
            spki: None,
        })
        .collect();
    let frames: Vec<_> = keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            let statement = wire::signing_statement_for_profile(
                AccountProfile::ApplicationV6,
                &common,
                kind,
                payload,
                &descriptors,
                index,
            )
            .unwrap();
            let signature = key.sign_exact_message(&statement).unwrap();
            let mut raw = statement.to_vec();
            raw.extend((ML_DSA_65_SIGNATURE_BYTES as u16).to_be_bytes());
            raw.extend(signature);
            raw
        })
        .collect();
    wire::encode_for_profile(
        AccountProfile::ApplicationV6,
        &common,
        kind,
        payload,
        &descriptors,
        &frames,
    )
    .unwrap()
}
fn sign_owner<T: Serialize>(body: &T, domain: &[u8]) -> (Vec<u8>, String) {
    let message = |role| {
        Profile::PqV3
            .message(b"unused-classic", domain, body, role)
            .unwrap()
    };
    let raw = serde_json::to_vec(&serde_json::json!({"body":body,
        "registry_signature":hex::encode(key(71).sign_exact_message(&message(1)).unwrap()),
        "task_signature":hex::encode(key(72).sign_exact_message(&message(2)).unwrap())}))
    .unwrap();
    (raw, digest_bytes(&message(0)))
}
fn material() -> (Vec<u8>, Vec<u8>) {
    let a: Vec<u8> = (0..4096)
        .flat_map(|i| (((19 * i + 23) % 271) as u32).to_le_bytes())
        .collect();
    let b: Vec<u8> = (0..4096)
        .flat_map(|i| (((31 * i + 37) % 277) as u32).to_le_bytes())
        .collect();
    (a, b)
}
fn registration(
    settings: &Settings,
    requester: Hash,
    source: Hash,
) -> (DemandLeaseV5, TaskRegistrationV5, Vec<u8>, Vec<u8>) {
    let (model, input) = material();
    let (a, b) =
        trnm_crypto_primitives::qualified_work_task::derive_matrices(&model, &input).unwrap();
    let mut lease = DemandLeaseV5 {
        slot: 0,
        purpose: TaskPurpose::Maintenance,
        network: settings.network(),
        parameters: settings.parameters(),
        demand_id: [1; 32],
        requester,
        source,
        source_record: hash(b"public-pq-startup-source", &[&source]),
        authorization_scope: hash(b"public-pq-startup-authority", &[&requester, &source]),
        availability_manifest: [81; 32],
        availability_root: [82; 32],
        generation: 1,
        revision: 1,
        not_before: 1,
        expires: 50,
        available_until: 150,
        cost_class: 1,
    };
    lease.demand_id = lease.derived_demand_id();
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
        source,
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
        demand_nonce: 1,
        not_before: lease.not_before,
        expires: lease.expires,
        available_until: lease.available_until,
        logical_multiply_add_units: LOGICAL_MULTIPLY_ADD_UNITS,
        model_bytes: MATRIX_ARTIFACT_BYTES,
        input_bytes: MATRIX_ARTIFACT_BYTES,
        useful_output_limit: lease.purpose.output_limit(),
    };
    manifest.output_meter = manifest.derived_output_meter();
    (
        lease.clone(),
        TaskRegistrationV5 {
            lease_id: lease.id().unwrap(),
            prior_statement_id: [0; 32],
            manifest,
        },
        model,
        input,
    )
}

struct Fixture {
    root: tempfile::TempDir,
    spec: StartupSpec,
    settings: Settings,
    bundle: StartupBundle,
    lease: DemandLeaseV5,
    registration: TaskRegistrationV5,
    model: Vec<u8>,
    input: Vec<u8>,
    next: Packet,
    next_state: trnm_mvcc_fee::pon_executor::State,
}
fn fixture() -> Fixture {
    fixture_kind(1)
}
fn fixture_kind(next_kind: u8) -> Fixture {
    let root = tempfile::tempdir().unwrap();
    let requester = key(11);
    let source = key(12);
    let evaluator = key(13);
    let mut evaluators = vec![
        hex::encode(key_id(&source)),
        hex::encode(key_id(&evaluator)),
    ];
    evaluators.sort();
    let spec = StartupSpec {
        schema: SPEC_SCHEMA.into(),
        genesis_timestamp: 1000,
        accounts: [&requester, &source, &evaluator]
            .iter()
            .map(|key| StartupAccount {
                spki: hex::encode(key.public_spki()),
                balance: 100_000_000,
            })
            .collect(),
        evaluators,
        evaluation_profile: trnm_mvcc_fee::public_evaluation::PROFILE.into(),
        model_profile: "linear-expert-dev-v1".into(),
        server_spki: hex::encode(key(91).public_spki()),
        network_generation: 1,
        peer_spkis: vec![hex::encode(key(92).public_spki())],
    };
    let settings = spec.settings().unwrap();
    let policy = spec.network_policy(&settings).unwrap();
    let (lease, registration, model, input) =
        registration(&settings, key_id(&requester), key_id(&source));
    let open = sign_command(&settings, 18, &lease.encode().unwrap(), 1, &[&requester]);
    let register = sign_command(
        &settings,
        21,
        &registration.encode().unwrap(),
        2,
        &[&requester, &source],
    );
    let mut producer =
        Node::open_with_pq_network(&root.path().join("producer"), settings.clone(), 1, &policy)
            .unwrap();
    let bundle = StartupBundle::produce(
        &mut producer,
        [open, register],
        key_id(&evaluator),
        1010,
        4096,
    )
    .unwrap();
    let next_command = if next_kind == 20 {
        let revocation = trnm_protocol::qualified_work_task::pq_lifecycle_v5::DemandRevocationV5 {
            lease: lease.clone(),
        };
        sign_command(
            &settings,
            20,
            &revocation.encode().unwrap(),
            3,
            &[&requester],
        )
    } else if next_kind == 22 {
        let state = producer.state_at(producer.active().unwrap().0).unwrap();
        let prior = pq::tasks_v5::eligible_task(
            &state,
            registration.manifest.matrix_task,
            3,
            &settings.app,
        )
        .unwrap()
        .statement_id();
        let mut successor = lease.clone();
        successor.revision = 2;
        successor.not_before = 3;
        successor.expires = 80;
        successor.available_until = 180;
        let mut next = registration.clone();
        next.lease_id = successor.id().unwrap();
        next.prior_statement_id = prior;
        next.manifest.source_record = successor.bound_source_record().unwrap();
        next.manifest.withdrawal_head = successor.withdrawal_frontier().unwrap();
        next.manifest.demand_nonce = 2;
        next.manifest.not_before = successor.not_before;
        next.manifest.expires = successor.expires;
        next.manifest.available_until = successor.available_until;
        next.manifest.output_meter = next.manifest.derived_output_meter();
        let renewal = trnm_protocol::qualified_work_task::pq_lifecycle_v5::AtomicRenewTaskV5 {
            expected_lease_id: lease.id().unwrap(),
            successor,
            registration: next,
        };
        sign_command(
            &settings,
            22,
            &renewal.encode().unwrap(),
            3,
            &[&requester, &source],
        )
    } else {
        let transfer = [
            key_id(&evaluator).as_slice(),
            7_u64.to_le_bytes().as_slice(),
            0_u16.to_be_bytes().as_slice(),
        ]
        .concat();
        sign_command(&settings, 1, &transfer, 3, &[&requester])
    };
    let next = producer
        .make_with_registered_material(
            producer.active().unwrap().0,
            vec![next_command],
            key_id(&evaluator),
            1003,
            4096,
            &model,
            &input,
        )
        .unwrap();
    let next_id = producer.admit(&next, 1010).unwrap();
    producer.activate(next_id).unwrap();
    let next_state = producer.state_at(next_id).unwrap();
    Fixture {
        root,
        spec,
        settings,
        bundle,
        lease,
        registration,
        model,
        input,
        next,
        next_state,
    }
}
fn catalog(f: &Fixture) -> (Vec<MaterialInput>, String) {
    let dir = f.root.path().join("catalog");
    fs::create_dir_all(&dir).unwrap();
    let mut bytes = CATALOG_DOMAIN.to_vec();
    let mut rows = Vec::new();
    for (role, raw) in [
        ("bootstrap", f.bundle.encode().unwrap()),
        ("input", f.input.clone()),
        ("model", f.model.clone()),
        ("spec", f.spec.encode().unwrap()),
    ] {
        let path = dir.join(role);
        if !path.exists() {
            fs::write(&path, &raw).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let sha = digest_bytes(&raw);
        bytes.extend((role.len() as u32).to_le_bytes());
        bytes.extend(role.as_bytes());
        bytes.extend((raw.len() as u64).to_le_bytes());
        bytes.extend((sha.len() as u32).to_le_bytes());
        bytes.extend(sha.as_bytes());
        rows.push(MaterialInput {
            role: role.into(),
            path,
            bytes: raw.len() as u64,
            sha256: sha,
        });
    }
    (rows, digest_bytes(&bytes))
}
fn binding(f: &Fixture, catalog: String) -> recipient::DeclaredBinding {
    let mut binding = fixtures::binding();
    let manifest = &f.registration.manifest;
    binding.task.native_task = hex::encode(manifest.matrix_task);
    binding.task.lease_sha256 = digest_bytes(&f.lease.encode().unwrap());
    binding.task.model_id = "public-pq-startup-research-fixture".into();
    binding.task.model_material = digest_bytes(&f.model);
    binding.task.native_model = hex::encode(manifest.model);
    binding.task.input_material = digest_bytes(&f.input);
    binding.task.native_input = hex::encode(manifest.input);
    binding.task.a_sha256 = digest_bytes(&f.model);
    binding.task.b_sha256 = digest_bytes(&f.input);
    binding.task.layer_selector = hex::encode(manifest.layer);
    binding.task.recipe_sha256 = hex::encode(manifest.recipe);
    binding.task.full_material_catalog = catalog;
    binding
}

struct Outside {
    budget_digest: String,
    view_digest: String,
    search: String,
}
fn inputs(
    f: &Fixture,
    sequence: u64,
    prior: Option<&Outside>,
    head: history::Anchor,
    parent: Hash,
    generation: u64,
) -> (policy::Inputs, Outside) {
    inputs_with_search(f, sequence, prior, head, parent, generation, &[])
}
fn inputs_with_search(
    f: &Fixture,
    sequence: u64,
    prior: Option<&Outside>,
    head: history::Anchor,
    parent: Hash,
    generation: u64,
    search_transactions: &[Vec<u8>],
) -> (policy::Inputs, Outside) {
    let now = crate::operator_task_policy::now_ns().unwrap();
    let until = now + 300_000_000_000;
    let (materials, catalog_hash) = catalog(f);
    let binding = binding(f, catalog_hash);
    let mut identity = fixtures::identity();
    identity.schema = PQ_IDENTITY.into();
    identity.network = hex::encode(f.settings.network());
    identity.parameters = hex::encode(f.settings.parameters());
    identity.registry_key = hex::encode(key(71).public_spki());
    identity.task_key = hex::encode(key(72).public_spki());
    let journal_path = f.root.path().join("journal");
    let uid = rustix::process::geteuid().as_raw();
    if prior.is_none() {
        fs::create_dir(&journal_path).unwrap();
        fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let (raw_budget, budget_authority, budget_digest) = if let Some(prior) = prior {
        (None, None, prior.budget_digest.clone())
    } else {
        let journal = history::Journal::open(&journal_path, uid, &identity, &head).unwrap();
        let mut delegation = fixtures::delegation(1);
        delegation.schema = "restricted-continuous-registry2-budget-delegation-pq-v3".into();
        delegation.declared_binding = binding.clone();
        delegation.not_before_ns = now;
        delegation.expires_ns = until;
        delegation.context.network = identity.network.clone();
        delegation.context.parameters = identity.parameters.clone();
        delegation.context.actual_parent = hex::encode(parent);
        let body = history::BudgetIncrease {
            schema: "restricted-continuous-budget-increase-pq-v3".into(),
            identity: identity.clone(),
            sequence: 1,
            previous_digest: None,
            exact_prior_journal: journal.anchor(),
            exact_usage_digest: journal.usage_digest().unwrap(),
            ceilings: history::Ceilings {
                global: fixtures::usage(),
                tasks: BTreeMap::from([(binding.task.native_task.clone(), fixtures::usage())]),
                classes: BTreeMap::from([(binding.instance_class.clone(), fixtures::usage())]),
            },
            issued_ns: now,
            expires_ns: until,
            revoked: false,
            delegation,
        };
        let (raw, digest) = sign_owner(&body, b"TRNM/PoN/ContinuousBudget/PQ/v3\0");
        let authority = history::BumpAuthority {
            identity: identity.clone(),
            expected: body,
            envelope_sha256: digest_bytes(&raw),
            latest_sequence: 1,
            latest_digest: digest.clone(),
        };
        (Some(raw), Some(authority), digest)
    };
    let intent = crate::operator_mining_policy::SearchIntent {
        miner: hex::encode(key_id(&key(13))),
        timestamp: 1003,
        exact_transactions_sha256: policy::pq_transactions_sha256(search_transactions).unwrap(),
        exact_group_ids: Vec::new(),
        nonce_first: 1,
        nonce_count: 256,
    };
    let packet_hash = digest_bytes(&f.next.encode_for_settings(&f.settings).unwrap());
    let purposes = [
        (
            "startup-catalog",
            binding.task.full_material_catalog.clone(),
        ),
        ("parent-reconcile", hex::encode(parent)),
        (
            "search",
            crate::operator_mining_policy::search_payload_sha256(&intent).unwrap(),
        ),
        ("receiver-validation", packet_hash.clone()),
        ("receiver-activate", packet_hash),
    ];
    let mut allocations = Vec::new();
    let mut search = String::new();
    for (index, (purpose, payload)) in purposes.into_iter().enumerate() {
        let n = (sequence - 1) * 10 + index as u64 + 1;
        let mut body = fixtures::allocation(purpose);
        body.schema = "restricted-continuous-recipient-allocation-pq-v3".into();
        body.identity = identity.clone();
        body.declared_binding = binding.clone();
        body.allocator_sequence = n;
        body.allocator_previous_digest = (n != 1).then(|| "11".repeat(32));
        body.allocator_record_sha256 = if n == 1 {
            "11".repeat(32)
        } else {
            format!("{:064x}", 100 + n)
        };
        body.local_budget_digest = budget_digest.clone();
        body.issued_ns = now;
        body.expires_ns = until;
        let c = &mut body.claim;
        c.operation_nonce = format!("{n:064x}");
        c.parent = hex::encode(parent);
        c.generation = generation;
        c.native_task = binding.task.native_task.clone();
        c.task_binding = recipient::declared_binding_digest(&binding).unwrap();
        c.payload = payload;
        c.global_allocation_id = format!("{:064x}", 10000 + n);
        c.global_allocation_sequence = n;
        c.allocation.cpu_ns = 30_000_000_000;
        c.allocation.material_bytes = 2_000_000;
        c.allocation.da_bytes = 2_000_000;
        c.operation = recipient::operation_id(&identity, c).unwrap();
        if purpose == "search" {
            search = c.operation.clone();
        }
        if purpose.starts_with("receiver-") {
            body.origin = Some(recipient::Origin::ClosedFixture {
                producer_node: "44".repeat(32),
                packet_sha256: c.payload.clone(),
                parent: c.parent.clone(),
                generation,
                task_binding_sha256: c.task_binding.clone(),
                source_commit: identity.source_commit.clone(),
                node_policy_source: identity.node_policy_source.clone(),
                native_receipt_sha256: "55".repeat(32),
                full_reference_receipt_sha256: "66".repeat(32),
            });
        }
        let (raw, _) = sign_owner(&body, b"TRNM/PoN/ContinuousRecipient/PQ/v3\0");
        allocations.push(policy::SignedAllocationInput {
            authority: recipient::Authority {
                identity: identity.clone(),
                expected: body.clone(),
                expected_envelope_sha256: digest_bytes(&raw),
                latest_allocator_sequence: n,
                latest_allocator_digest: body.allocator_record_sha256,
            },
            raw,
        });
    }
    let mut envelopes: Vec<_> = allocations
        .iter()
        .map(|row| digest_bytes(&row.raw))
        .collect();
    envelopes.sort();
    let view = policy::TaskView {
        schema: "restricted-continuous-task-view-pq-v3".into(),
        identity: identity.clone(),
        sequence,
        previous_digest: prior.map(|p| p.view_digest.clone()),
        actual_parent: hex::encode(parent),
        actual_generation: generation,
        declared_binding: binding,
        allocation_envelopes: envelopes,
        searches: vec![policy::SearchBinding {
            operation: search.clone(),
            intent,
            pool_validation_operation: None,
        }],
        allowed_transactions: vec![digest_bytes(&f.next.transactions[0])],
        issued_ns: now,
        expires_ns: until,
        revoked: false,
        pool_selections: Vec::new(),
        lease_edge: None,
        lease_transition_operation: None,
    };
    let (raw_view, view_digest) = sign_owner(&view, b"TRNM/PoN/ContinuousView/PQ/v3\0");
    let input = policy::Inputs {
        view_authority: policy::ViewAuthority {
            identity,
            expected: view,
            envelope_sha256: digest_bytes(&raw_view),
            latest_sequence: sequence,
            latest_digest: view_digest.clone(),
        },
        raw_view,
        raw_budget,
        budget_authority,
        allocations,
        journal_path,
        expected_uid: uid,
        expected_journal: head,
        materials,
        lease_transition: None,
        known_unclean_restart: None,
    };
    (
        input,
        Outside {
            budget_digest,
            view_digest,
            search,
        },
    )
}
fn boot(f: &Fixture) -> Hash {
    PreparedStartup::decode(&f.bundle.encode().unwrap(), &f.settings)
        .unwrap()
        .head()
}
fn open(f: &Fixture, inputs: policy::Inputs) -> Node {
    Node::open_operator_continuous_checkpoint(
        &f.root.path().join("consumer"),
        inputs,
        Instant::now() + Duration::from_secs(60),
    )
    .unwrap()
    .0
}

fn open_controller(
    f: &Fixture,
    input: policy::Inputs,
) -> crate::operator_continuous_controller::Controller {
    use crate::operator_continuous_controller::{Controller, OutsideLaunch};
    use serde_json::json;
    let identity = input.view_authority.identity.clone();
    let allocations: Vec<_> = input.allocations.iter().map(|row| json!({"raw":row.raw,"authority":{
        "identity":row.authority.identity,"expected":row.authority.expected,"expected_envelope_sha256":row.authority.expected_envelope_sha256,
        "latest_allocator_sequence":row.authority.latest_allocator_sequence,"latest_allocator_digest":row.authority.latest_allocator_digest}})).collect();
    let budget = input.budget_authority.as_ref().map(|authority| json!({"identity":authority.identity,"expected":authority.expected,
        "envelope_sha256":authority.envelope_sha256,"latest_sequence":authority.latest_sequence,"latest_digest":authority.latest_digest}));
    let materials: Vec<_> = input
        .materials
        .iter()
        .map(|row| json!({"role":row.role,"path":row.path,"bytes":row.bytes,"sha256":row.sha256}))
        .collect();
    let value = json!({"schema":"restricted-owner-continuous-launch-pq-v3","source_commit":identity.source_commit,
        "node_policy_source":identity.node_policy_source,"registry2_package":identity.registry2_package,
        "store":f.root.path().join("consumer"),"maximum_steps":32,"wall_seconds":180,"receiver_service":null,
        "inputs":{"raw_view":input.raw_view,"view_authority":{"identity":input.view_authority.identity,
            "expected":input.view_authority.expected,"envelope_sha256":input.view_authority.envelope_sha256,
            "latest_sequence":input.view_authority.latest_sequence,"latest_digest":input.view_authority.latest_digest},
            "raw_budget":input.raw_budget,"budget_authority":budget,"allocations":allocations,"journal_path":input.journal_path,
            "expected_uid":input.expected_uid,"expected_journal":input.expected_journal,"materials":materials,
            "lease_transition":null,"known_unclean_restart":null}});
    let raw = serde_json::to_vec(&value).unwrap();
    let path = f.root.path().join(format!(
        "launch-{}.json",
        input.view_authority.latest_sequence
    ));
    fs::write(&path, &raw).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let digest = digest_bytes(&raw);
    Controller::open_pinned(
        OutsideLaunch {
            path: &path,
            sha256: &digest,
            registry_key: &identity.registry_key,
            task_key: &identity.task_key,
            source_commit: &identity.source_commit,
            node_policy_source: &identity.node_policy_source,
            registry2_package: &identity.registry2_package,
        },
        Instant::now(),
    )
    .unwrap()
}

#[test]
fn pq_continuous_real_controller_nonempty_search_receiver_restart_and_wire_limits() {
    use serde_json::json;
    let f = fixture();
    let (input, outside) = inputs_with_search(
        &f,
        1,
        None,
        history::Anchor::empty(),
        boot(&f),
        2,
        &f.next.transactions,
    );
    let mut controller = open_controller(&f, input);
    let mut old_wire = f.next.transactions[0].clone();
    old_wire[3] = b'5';
    old_wire[4] = 5;
    let dual = PreparedStartup::decode(&f.bundle.encode().unwrap(), &f.settings)
        .unwrap()
        .packets[1]
        .transactions[0]
        .clone();
    for transactions in [
        vec!["00".repeat(2048)],
        vec![hex::encode(old_wire)],
        vec!["00".repeat(16385)],
        vec![hex::encode(&f.next.transactions[0]); 65],
        vec![hex::encode(&dual); 33],
    ] {
        let refusal = controller.apply(&serde_json::to_vec(&json!({"purpose":"search","operation_id":outside.search,"transactions":transactions})).unwrap()).unwrap();
        assert!(refusal["native_error"].is_string(), "{refusal}");
        assert_eq!(refusal["control_frame_recorded"], true);
        assert_eq!(refusal["parent"], hex::encode(boot(&f)));
    }
    let search = controller
        .apply(
            &serde_json::to_vec(&json!({"purpose":"search","operation_id":outside.search,
        "transactions":f.next.transactions.iter().map(hex::encode).collect::<Vec<_>>()}))
            .unwrap(),
        )
        .unwrap();
    assert!(search["native_error"].is_null(), "{search}");
    assert!(
        search["result"]["search"]["native_error"].is_null(),
        "{search}"
    );
    let produced = Packet::decode_for_settings(
        &hex::decode(search["result"]["packet"].as_str().unwrap()).unwrap(),
        &f.settings,
    )
    .unwrap();
    assert_eq!(produced.transactions, f.next.transactions);
    assert_eq!(
        produced.header.work_task,
        f.registration.manifest.matrix_task
    );
    let received = controller.apply(&serde_json::to_vec(&json!({"purpose":"receiver-validation","packet":hex::encode(f.next.encode_for_settings(&f.settings).unwrap())})).unwrap()).unwrap();
    assert!(
        received["native_error"].is_null() && received["result"]["native_error"].is_null(),
        "{received}"
    );
    let activated = controller.apply(&serde_json::to_vec(&json!({"purpose":"activate","block":hex::encode(f.next.id().unwrap()),"receiver":true})).unwrap()).unwrap();
    assert!(
        activated["native_error"].is_null() && activated["result"]["native_error"].is_null(),
        "{activated}"
    );
    assert_eq!(activated["parent"], hex::encode(f.next.id().unwrap()));
    let closed = controller.close().unwrap();
    let head = serde_json::from_value(closed["checkpoint"]["journal_head"].clone()).unwrap();
    drop(controller);
    let (input, _) = inputs(&f, 2, Some(&outside), head, f.next.id().unwrap(), 3);
    let mut reopened = open_controller(&f, input);
    let status = reopened.apply(br#"{"purpose":"read-head"}"#).unwrap();
    assert!(status["native_error"].is_null(), "{status}");
    assert_eq!(status["parent"], hex::encode(f.next.id().unwrap()));
    reopened.close().unwrap();
}

#[test]
fn pq_continuous_real_bootstrap_receiver_and_cold_reopen_keep_state_fees_work_and_local_revocation()
{
    let f = fixture();
    let policy = f.spec.network_policy(&f.settings).unwrap();
    let (input, outside) = inputs(&f, 1, None, history::Anchor::empty(), boot(&f), 2);
    let mut consumer = open(&f, input);
    assert_eq!(consumer.active().unwrap(), (boot(&f), 2));
    assert!(Node::open_with_pq_network(
        &f.root.path().join("consumer"),
        f.settings.clone(),
        1,
        &policy
    )
    .is_err());
    let result = consumer
        .receive_owned_continuous_packet(f.next.clone(), 1010)
        .unwrap();
    assert!(result.native_error.is_none(), "{:?}", result.native_error);
    let id = result.native_id.unwrap();
    assert_eq!(id, f.next.id().unwrap());
    let result = consumer
        .activate_owned_continuous_packet(id, true, 1010)
        .unwrap();
    assert!(result.native_error.is_none(), "{:?}", result.native_error);
    assert_eq!(consumer.state_at(id).unwrap(), f.next_state);
    // The maintenance bootstrap authority is gone after startup.
    assert!(consumer
        .admit(
            &PreparedStartup::decode(&f.bundle.encode().unwrap(), &f.settings)
                .unwrap()
                .packets[0],
            1010
        )
        .is_err());
    consumer
        .revoke_pq_network_peer(&policy, key_id(&key(92)))
        .unwrap();
    let before = consumer.pq_network_status(&policy).unwrap();
    assert_eq!(before["revoked_peers"], 1);
    let closed = consumer.close_continuous_checkpoint().unwrap();
    let head: history::Anchor = serde_json::from_value(closed["journal_head"].clone()).unwrap();
    drop(consumer);
    let (next_inputs, _) = inputs(&f, 2, Some(&outside), head, f.next.id().unwrap(), 3);
    let reopened = open(&f, next_inputs);
    assert_eq!(reopened.active().unwrap(), (f.next.id().unwrap(), 3));
    assert_eq!(
        reopened.state_at(f.next.id().unwrap()).unwrap(),
        f.next_state
    );
    assert_eq!(
        reopened.pq_network_status(&policy).unwrap()["revoked_peers"],
        1
    );
    assert_eq!(
        reopened.pq_network_status(&policy).unwrap()["records"],
        before["records"]
    );
    reopened.close_continuous_checkpoint().unwrap();
}

#[test]
fn pq_continuous_original_search_owner_produces_registered_work_and_cannot_replay_allocation() {
    let f = fixture();
    let (input, outside) = inputs(&f, 1, None, history::Anchor::empty(), boot(&f), 2);
    let consumer = open(&f, input);
    let stop = AtomicBool::new(false);
    let request = || crate::ContinuousSearchRequest {
        operation_id: &outside.search,
        transactions: Vec::new(),
        model: &f.model,
        input: &f.input,
        stop: &stop,
        deadline: Instant::now() + Duration::from_secs(60),
    };
    let result = consumer.search_owned_continuous_window(request()).unwrap();
    assert!(result.native_error.is_none(), "{:?}", result.native_error);
    let packet = result.packet.unwrap();
    assert_eq!(packet.header.work_task, f.registration.manifest.matrix_task);
    assert!(result.actual_trials > 0 && result.complete_proofs > 0);
    assert!(consumer.search_owned_continuous_window(request()).is_err());
    consumer.close_continuous_checkpoint().unwrap();
}

#[test]
fn pq_startup_strict_genesis_wire_shape_and_signature_boundaries_refuse_mutations() {
    let f = fixture();
    let raw = f.bundle.encode().unwrap();
    let mut wrong = f.bundle.clone();
    wrong.genesis = "ee".repeat(32);
    assert!(PreparedStartup::decode(&wrong.encode().unwrap(), &f.settings).is_err());
    wrong = f.bundle.clone();
    wrong.packets.reverse();
    assert!(PreparedStartup::decode(&wrong.encode().unwrap(), &f.settings).is_err());
    wrong = f.bundle.clone();
    wrong.packets.push(wrong.packets[0].clone());
    assert!(wrong.encode().is_err());
    let mut noncanonical = raw;
    noncanonical.push(b' ');
    assert!(StartupBundle::decode(&noncanonical).is_err());
    let mut old = f.spec.clone();
    old.schema = "restricted-continuous-checkpoint-v1".into();
    assert!(old.settings().is_err());
    let packet = PreparedStartup::decode(&f.bundle.encode().unwrap(), &f.settings)
        .unwrap()
        .packets[1]
        .clone();
    assert!(
        packet.encode().is_err(),
        "legacy 2,048-byte route cannot carry NPQ6 task signatures"
    );
    assert!(crate::operator_mining_policy::transactions_sha256(&packet.transactions).is_err());
    assert!(policy::pq_transactions_sha256(&packet.transactions).is_ok());
    let many = vec![packet.transactions[0].clone(); 33];
    assert!(
        policy::pq_transactions_sha256(&many).is_err(),
        "66 verification attempts exceed 64 even under the byte cap"
    );
    assert!(policy::pq_transactions_sha256(&[vec![0; 2048]]).is_err());
    let mut profile = packet.transactions[0].clone();
    profile[3] = b'5';
    profile[4] = 5;
    assert!(policy::pq_transactions_sha256(&[profile]).is_err());
    let mut mutated = packet.transactions[0].clone();
    *mutated.last_mut().unwrap() ^= 1;
    let policy = f.spec.network_policy(&f.settings).unwrap();
    let mut producer = Node::open_with_pq_network(
        &f.root.path().join("bad-signature"),
        f.settings.clone(),
        1,
        &policy,
    )
    .unwrap();
    let open = PreparedStartup::decode(&f.bundle.encode().unwrap(), &f.settings)
        .unwrap()
        .packets[0]
        .clone();
    let id = producer.admit(&open, 1010).unwrap();
    producer.activate(id).unwrap();
    let before = producer.state_at(id).unwrap();
    assert!(producer
        .make_consensus_maintenance(id, vec![mutated], key_id(&key(13)), 1002, 4096)
        .is_err());
    assert_eq!(producer.state_at(id).unwrap(), before);
}

#[test]
fn pq_startup_invalid_work_spends_original_journal_and_refuses_automatic_retry() {
    let mut f = fixture();
    let mut packet = PreparedStartup::decode(&f.bundle.encode().unwrap(), &f.settings)
        .unwrap()
        .packets[0]
        .clone();
    packet.proof[0] ^= 1;
    f.bundle.packets[0] = hex::encode(packet.encode_for_settings(&f.settings).unwrap());
    let (input, _) = inputs(&f, 1, None, history::Anchor::empty(), boot(&f), 2);
    let path = f.root.path().join("consumer");
    let result = Node::open_operator_continuous_checkpoint(
        &path,
        input,
        Instant::now() + Duration::from_secs(60),
    );
    assert!(result.is_err());
    let db = rusqlite::Connection::open(path.join("native.sqlite")).unwrap();
    let count: u64 = db
        .query_row("SELECT COUNT(*) FROM blocks", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
    let balance: Vec<u8> = db
        .query_row("SELECT tip FROM active", [], |row| row.get(0))
        .unwrap();
    assert_eq!(balance, f.settings.genesis());
    let entries = fs::read_dir(f.root.path().join("journal"))
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("entry-"))
        .count();
    assert!(
        entries >= 5,
        "budget/view/allocation/actual startup settlement remain durable on refusal"
    );
    assert!(history::Journal::open(
        &f.root.path().join("journal"),
        rustix::process::geteuid().as_raw(),
        &{
            let mut identity = fixtures::identity();
            identity.schema = PQ_IDENTITY.into();
            identity.network = hex::encode(f.settings.network());
            identity.parameters = hex::encode(f.settings.parameters());
            identity.registry_key = hex::encode(key(71).public_spki());
            identity.task_key = hex::encode(key(72).public_spki());
            identity
        },
        &history::Anchor::empty()
    )
    .is_err());
}

#[test]
fn pq_continuous_revoked_actual_task_blocks_cold_restart_without_replaying_bootstrap() {
    let f = fixture_kind(20);
    let (input, outside) = inputs(&f, 1, None, history::Anchor::empty(), boot(&f), 2);
    let mut consumer = open(&f, input);
    let received = consumer
        .receive_owned_continuous_packet(f.next.clone(), 1010)
        .unwrap();
    assert!(
        received.native_error.is_none(),
        "{:?}",
        received.native_error
    );
    let selected = consumer
        .activate_owned_continuous_packet(f.next.id().unwrap(), true, 1010)
        .unwrap();
    assert!(
        selected.native_error.is_none(),
        "{:?}",
        selected.native_error
    );
    let state = consumer.state_at(f.next.id().unwrap()).unwrap();
    assert!(pq::tasks_v5::eligible_task(
        &state,
        f.registration.manifest.matrix_task,
        4,
        &f.settings.app
    )
    .is_err());
    let closed = consumer.close_continuous_checkpoint().unwrap();
    let head = serde_json::from_value(closed["journal_head"].clone()).unwrap();
    drop(consumer);
    let (input, _) = inputs(&f, 2, Some(&outside), head, f.next.id().unwrap(), 3);
    assert!(Node::open_operator_continuous_checkpoint(
        &f.root.path().join("consumer"),
        input,
        Instant::now() + Duration::from_secs(60)
    )
    .is_err());
    let db = rusqlite::Connection::open(f.root.path().join("consumer/native.sqlite")).unwrap();
    let active: Vec<u8> = db
        .query_row("SELECT tip FROM active", [], |row| row.get(0))
        .unwrap();
    assert_eq!(active, f.next.id().unwrap());
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM blocks", [], |row| row
            .get::<_, u64>(0))
            .unwrap(),
        4
    );
}

#[test]
fn pq_continuous_atomic_renewal_reconciles_actual_task_v5_owner_and_strict_lease_edge() {
    let f = fixture_kind(22);
    let (input, outside) = inputs(&f, 1, None, history::Anchor::empty(), boot(&f), 2);
    let identity = input.view_authority.identity.clone();
    let old = input.view_authority.expected.declared_binding.clone();
    let expires_ns = input.view_authority.expected.expires_ns;
    let mut consumer = open(&f, input);
    let received = consumer
        .receive_owned_continuous_packet(f.next.clone(), 1010)
        .unwrap();
    assert!(
        received.native_error.is_none(),
        "{:?}",
        received.native_error
    );
    let selected = consumer
        .activate_owned_continuous_packet(f.next.id().unwrap(), true, 1010)
        .unwrap();
    assert!(
        selected.native_error.is_none(),
        "{:?}",
        selected.native_error
    );
    let command = wire::UnverifiedEnvelope::decode_for_profile(
        &f.next.transactions[0],
        AccountProfile::ApplicationV6,
    )
    .unwrap();
    let successor = trnm_protocol::qualified_work_task::pq_lifecycle_v5::AtomicRenewTaskV5::decode(
        command.payload,
    )
    .unwrap()
    .successor;
    let mut next = old.clone();
    next.task.lease_sha256 = digest_bytes(&successor.encode().unwrap());
    let edge = crate::operator_continuous_lease::LeaseEdge {
        schema: "restricted-continuous-lease-edge-pq-v2".into(),
        actual_parent: hex::encode(f.next.id().unwrap()),
        actual_generation: 3,
        native_task: old.task.native_task.clone(),
        old_task_binding: recipient::declared_binding_digest(&old).unwrap(),
        new_task_binding: recipient::declared_binding_digest(&next).unwrap(),
        old_complete_lease: hex::encode(f.lease.encode().unwrap()),
        new_complete_lease: hex::encode(successor.encode().unwrap()),
        renewal_packet_sha256: digest_bytes(&f.next.encode_for_settings(&f.settings).unwrap()),
        new_registry2_declaration_digest: "77".repeat(32),
    };
    assert!(edge.payload_for(Profile::ClassicalV2).is_err());
    assert!(edge.check_declarations(&old, &next).is_ok());
    let mut bad = edge.clone();
    bad.schema = "restricted-continuous-lease-edge-v1".into();
    assert!(bad.payload_for(Profile::PqV3).is_err());
    let now = crate::operator_task_policy::now_ns().unwrap();
    let mut body = fixtures::allocation("lease-reconcile");
    body.schema = "restricted-continuous-recipient-allocation-pq-v3".into();
    body.identity = identity.clone();
    body.declared_binding = old;
    body.allocator_sequence = 100;
    body.allocator_previous_digest = Some("11".repeat(32));
    body.allocator_record_sha256 = "22".repeat(32);
    body.local_budget_digest = outside.budget_digest;
    body.issued_ns = now;
    body.expires_ns = expires_ns;
    let c = &mut body.claim;
    c.operation_nonce = "64".repeat(32);
    c.global_allocation_id = "65".repeat(32);
    c.global_allocation_sequence = 100;
    c.parent = edge.actual_parent.clone();
    c.generation = 3;
    c.native_task = edge.native_task.clone();
    c.task_binding = edge.old_task_binding.clone();
    c.payload = edge.payload_for(Profile::PqV3).unwrap();
    c.allocation.cpu_ns = 30_000_000_000;
    c.operation = recipient::operation_id(&identity, c).unwrap();
    let (raw, _) = sign_owner(&body, b"TRNM/PoN/ContinuousRecipient/PQ/v3\0");
    let input = policy::LeaseTransitionInput {
        edge,
        permission: policy::SignedAllocationInput {
            authority: recipient::Authority {
                identity,
                expected: body.clone(),
                expected_envelope_sha256: digest_bytes(&raw),
                latest_allocator_sequence: body.allocator_sequence,
                latest_allocator_digest: body.allocator_record_sha256,
            },
            raw,
        },
    };
    let result = consumer.reconcile_owned_continuous_lease(input).unwrap();
    assert!(result.native_error.is_none(), "{:?}", result.native_error);
    assert_eq!(
        result.native_result.unwrap()["lease_witness_recorded"],
        true
    );
    assert!(result.accounting_record_persisted);
    consumer.close_continuous_checkpoint().unwrap();
}
