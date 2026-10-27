//! Controlled native fixture, with disclosed deterministic test actor/authority
//! keys. The original signatures, catalog, startup, W1, scalar reference and M06
//! all execute. Synthetic checkpoint/activation bytes and local authority
//! assertions do NOT establish an actual LLM forward or external Registry2
//! admission, independent governance, useful-work hardness, or production use.
use super::*;
use crate::{
    operator_checkpoint_tile::{
        self as tile, CheckpointTileRuntimePaths, OperatorCheckpointTileSpecV1,
    },
    operator_continuous_recipient as recipient, operator_deployment as actors,
    operator_task_policy::{Allocation, MaterialInput, Task},
};
use serde_json::{json, Value};
use std::{collections::BTreeMap, io::Cursor, os::unix::fs::PermissionsExt, path::PathBuf};
use trnm_crypto_primitives::{public_key_hex, sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::{
    checkpoint_tile_material_v1::{derive_checkpoint_tile_material_v1, PinnedTileContextV1},
    checkpoint_tile_policy_v1::{CheckpointTilePolicySpecV1, PROFILE as TASK_PROFILE},
    pon_executor::Config,
};

pub(super) const CLOCK: u64 = 1_800_010_000;
const BASE: &str = "081c04e893850a42b539d98d6ccfa659496e99ee";
fn sha(raw: &[u8]) -> String {
    crate::operator_task_policy::digest_bytes(raw)
}
fn secret(i: u8) -> String {
    hex::encode([i + 71; 32])
}
fn public(i: u8) -> String {
    public_key_hex(&signing_key_from_hex(&secret(i)).unwrap())
}
fn key(i: u8) -> Hash {
    hex::decode(public(i)).unwrap().try_into().unwrap()
}
fn signature(i: u8, raw: &[u8]) -> [u8; 64] {
    hex::decode(sign_hex(&signing_key_from_hex(&secret(i)).unwrap(), raw))
        .unwrap()
        .try_into()
        .unwrap()
}
fn signed<T: serde::Serialize>(domain: &[u8], body: &T) -> (Vec<u8>, String) {
    crate::operator_continuous_test_support::signed(domain, body)
}
fn write(path: &Path, raw: &[u8]) {
    fs::write(path, raw).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
fn canonical<T: serde::Serialize>(value: &T) -> Vec<u8> {
    actors::canonical(value).unwrap()
}

pub(super) struct Fixture {
    pub dir: tempfile::TempDir,
    pub settings: Settings,
    pub packet: Packet,
    pub page: Vec<u8>,
    pub identity: history::Identity,
    pub binding: recipient::DeclaredBinding,
    material_rows: Vec<(String, PathBuf, u64, String)>,
    pub native_receipt: Value,
    pub reference_receipt: Value,
    pub budget: history::BudgetIncrease,
    pub budget_raw: Vec<u8>,
    pub budget_digest: String,
    issued: u64,
    expires: u64,
}
pub(super) struct ViewInput {
    pub inputs: Option<policy::Inputs>,
    pub view_digest: String,
    pub validation: String,
    pub activation: String,
    pub signed_validation: Vec<u8>,
    pub validation_authority: recipient::Authority,
}

impl Fixture {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        // Same actual synthetic codec relation as checkpoint_tile_operator.rs.
        let header = canonical(&json!({"model.layers.0.self_attn.q_proj.weight":
            {"dtype":"BF16","shape":[576,576],"data_offsets":[0,576*576*2]}}));
        let mut checkpoint = (header.len() as u64).to_le_bytes().to_vec();
        checkpoint.extend(header);
        for _ in 0..576 * 576 {
            checkpoint.extend(0x3f80u16.to_le_bytes());
        }
        let model: Vec<u8> = (0..4096).flat_map(|_| 16384u32.to_le_bytes()).collect();
        let input: Vec<u8> = (0..4096)
            .flat_map(|at| {
                if at % 64 < 2 {
                    16u32.to_le_bytes()
                } else {
                    0u32.to_le_bytes()
                }
            })
            .collect();
        // These exact profile strings are mandatory untrusted codec fields.
        // As in the retained synthetic codec tests, their presence proves no
        // actual model forward. The fixture receipts explicitly say synthetic.
        let activation = canonical(&json!({
            "schema":"checkpoint-qproj-postnorm-activation-v1", "checkpoint_sha256":sha(&checkpoint),
            "dtype":"F32LE","shape":[1,2,576],"token_ids":[1,2],"attention_mask":[1,1],"positions":[0,1],
            "hidden_hex":hex::encode((0..1152).flat_map(|_|1f32.to_bits().to_le_bytes()).collect::<Vec<_>>()),
            "producer_script_sha256":sha(include_bytes!("history_import_fixture.rs")),
            "prompt_utf8_sha256":sha(b"synthetic codec fixture; no model forward"),
            "runtime":{"device":"cpu","python":"synthetic-fixture","torch":"synthetic-fixture",
                "transformers":"synthetic-fixture","safetensors":"synthetic-fixture","numpy":"synthetic-fixture",
                "threads":2,"base_only":true,"training":false,"local_files_only":true,
                "trust_remote_code":false,"forward_calls":1,"hook_calls":1,"parameter_count":134515008,
                "storage_dtype":"float32","material_manifest_sha256":sha(&checkpoint)},
            "activation_origin":"actual-layer0-q_proj-prehook-post-RMSNorm",
            "scope":"observed CPU base-model hook; no independent full-forward proof or source authority"}));
        let mut evaluators: Vec<_> = (2..5).map(public).collect();
        evaluators.sort();
        let mut allocations: Vec<_> = (0..6)
            .map(|i| actors::GenesisAllocation {
                public_key: public(i),
                balance: 50_000_000,
            })
            .collect();
        allocations.sort_by(|a, b| a.public_key.cmp(&b.public_key));
        let actor_spec = actors::OperatorDeploymentSpec {
            schema: "pon-native-operator-actors-spec-v1".into(),
            profile: actors::PROFILE.into(),
            deployment_id: sha(b"history-native-synthetic-actors"),
            genesis_timestamp: 1_800_000_000,
            evaluation_profile: "native-public-evaluation-dev-v1".into(),
            task_profile: "signed-task-lifecycle-dev-v4".into(),
            model_profile: "linear-expert-dev-v1".into(),
            source: public(0),
            requester: public(1),
            evaluators,
            allocations,
            bootstrap: actors::BootstrapMaterialSpec {
                model: hex::encode(hash(b"artifact", &[&model])),
                input: hex::encode(hash(b"qualified-task-input-v1", &[&input])),
                source_record: sha(&checkpoint),
                authorization_scope: sha(b"test-only synthetic material authority"),
                availability_manifest: sha(&activation),
                availability_root: sha(&checkpoint),
            },
            production_activation: false,
            public_network_ready: false,
            independent_governance_accepted: false,
            hardness_accepted: false,
            demand_truth_accepted: false,
            objective_model_quality: false,
        };
        let cfg = Config::installed_with_operator_actors(&actor_spec).unwrap();
        let checked = derive_checkpoint_tile_material_v1(
            &mut Cursor::new(&checkpoint),
            &activation,
            &model,
            &input,
            &PinnedTileContextV1 {
                network: cfg.network,
                parameters: cfg.parameters,
                checkpoint_sha256: hex::decode(sha(&checkpoint)).unwrap().try_into().unwrap(),
                checkpoint_bytes: checkpoint.len() as u64,
                activation_sha256: hex::decode(sha(&activation)).unwrap().try_into().unwrap(),
                model: hash(b"artifact", &[&model]),
                input: hash(b"qualified-task-input-v1", &[&input]),
            },
            |_| Ok(()),
        )
        .unwrap();
        let spec = OperatorCheckpointTileSpecV1 {
            schema: "pon-native-operator-checkpoint-tile-spec-v1".into(),
            profile: tile::PROFILE.into(),
            task_profile: TASK_PROFILE.into(),
            actors: actor_spec,
            material_policy: CheckpointTilePolicySpecV1::from_checked(&checked).unwrap(),
        };
        let cp_path = dir.path().join("checkpoint.safetensors");
        let act_path = dir.path().join("activation.json");
        write(&cp_path, &checkpoint);
        write(&act_path, &activation);
        let paths = CheckpointTileRuntimePaths::new(cp_path.clone(), act_path.clone());
        let template = tile::prepare(&spec, &model, &input, &paths).unwrap();
        let source = tile::approval(
            &template,
            "source",
            hex::encode(signature(
                0,
                &hex::decode(&template.source_message).unwrap(),
            )),
        )
        .unwrap();
        let requester = tile::approval(
            &template,
            "requester",
            hex::encode(signature(
                1,
                &hex::decode(&template.requester_message).unwrap(),
            )),
        )
        .unwrap();
        let bundle = tile::assemble(&template, &source, &requester).unwrap();
        let settings = Settings::development_with_operator_checkpoint_tile(
            &spec, &bundle, &model, &input, paths,
        )
        .unwrap();
        let mut material_rows = Vec::new();
        let mut catalog = b"TRNM-RESTRICTED-NODE-CATALOG1".to_vec();
        for (role, path, raw) in [
            ("activation", act_path, activation),
            (
                "bootstrap",
                dir.path().join("bootstrap.json"),
                canonical(&bundle),
            ),
            ("checkpoint", cp_path, checkpoint),
            ("input", dir.path().join("input.u32le"), input.clone()),
            ("model", dir.path().join("model.u32le"), model.clone()),
            ("spec", dir.path().join("spec.json"), canonical(&spec)),
        ] {
            if !path.exists() {
                write(&path, &raw);
            }
            let digest = sha(&raw);
            catalog.extend_from_slice(&(role.len() as u32).to_le_bytes());
            catalog.extend_from_slice(role.as_bytes());
            catalog.extend_from_slice(&(raw.len() as u64).to_le_bytes());
            catalog.extend_from_slice(&(digest.len() as u32).to_le_bytes());
            catalog.extend_from_slice(digest.as_bytes());
            material_rows.push((role.to_owned(), path, raw.len() as u64, digest));
        }
        let boot = settings.bootstrap_lifecycle_task().unwrap();
        let (a, b) = derive_matrices(&model, &input).unwrap();
        let binding = recipient::DeclaredBinding {
            task: Task {
                purpose: "maintenance-tag1".into(),
                native_task: hex::encode(boot.signed.manifest.matrix_task),
                lease_sha256: sha(&boot.lease.encode().unwrap()),
                model_id: "synthetic-checkpoint-native-history-fixture".into(),
                model_revision: BASE.into(),
                model_material: sha(&model),
                native_model: hex::encode(boot.signed.manifest.model),
                layer_tensor: "model.layers.0.self_attn.q_proj.weight".into(),
                layer_index: 0,
                layer_selector: sha(&canonical(&spec.material_policy)),
                input_material: sha(&input),
                native_input: hex::encode(boot.signed.manifest.input),
                dimension: 64,
                field_modulus: 4_294_967_291,
                encoding: "canonical-u32-le".into(),
                a_sha256: sha(&a.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>()),
                b_sha256: sha(&b.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>()),
                full_material_catalog: sha(&catalog),
                recipe_sha256: sha(&canonical(&spec)),
            },
            instance_class: "structured".into(),
            source_class: "declared-same-operator".into(),
            cost_class: "unmeasured".into(),
            cost_evidence: None,
            preprocessing: "forbidden".into(),
            prepared_artifact: None,
            setup_record: None,
            funding_commitment: sha(b"local test authority budget only"),
            funding_evidence: sha(b"not external Registry2 balance evidence"),
        };
        let assertion = canonical(
            &json!({"schema":"local-history-test-authority-assertion-v1",
            "binding":binding,"registry2_admission_executed":false,"production_authority":false}),
        );
        write(
            &dir.path().join("local-authority-assertion.json"),
            &assertion,
        );
        let identity = history::Identity {
            schema: "restricted-continuous-identity-v2".into(),
            registry: sha(b"local fixture registry role"),
            operator: sha(b"local fixture operator role"),
            network: hex::encode(settings.network()),
            parameters: hex::encode(settings.parameters()),
            source_commit: BASE.into(),
            node_policy_source: sha(include_bytes!("history_import.rs")),
            registry2_package: sha(&assertion),
            registry_key: public_key_hex(&signing_key_from_hex(&"11".repeat(32)).unwrap()),
            task_key: public_key_hex(&signing_key_from_hex(&"22".repeat(32)).unwrap()),
            recipient_node: sha(b"native fixture receiver"),
            global_allocator: sha(b"local fixture allocator"),
        };
        let mut producer = Node::open(&dir.path().join("producer"), settings.clone(), 2).unwrap();
        let transfer = |who: u8| {
            let mut payload = key(5).to_vec();
            payload.extend_from_slice(&7u64.to_le_bytes());
            let mut tx = Envelope {
                network: settings.network(),
                sender: key(who),
                nonce: 1,
                expiry: 2000,
                fee_limit: 1_000_000,
                tag: 1,
                payload,
                signature: [0; 64],
            };
            tx.signature = signature(who, &tx.signing_digest().unwrap());
            tx.encode().unwrap()
        };
        let material = TaskMaterial {
            model: &model,
            input: &input,
            a: &a,
            b: &b,
        };
        let admission =
            trnm_crypto_primitives::qualified_work_task::lifecycle_v2::verify_lifecycle_admission(
                &boot.signed.encode().unwrap(),
                material,
                &boot.lease,
                1,
            )
            .unwrap();
        let prepared = producer
            .prepare_with_task(
                settings.genesis(),
                vec![transfer(0), transfer(1)],
                key(5),
                settings.genesis_time() + 10,
                4096,
                &admission,
                TaskMaterial {
                    model: &model,
                    input: &input,
                    a: &a,
                    b: &b,
                },
            )
            .unwrap();
        let searched = prepared.search_owned_window(1, 4096, &|| Ok(())).unwrap();
        assert!(!searched.stopped && searched.error.is_none());
        let packet = searched.packet.unwrap();
        assert_eq!(
            hex::encode(packet.header.work_task),
            binding.task.native_task
        );
        let id = producer.admit(&packet, CLOCK).unwrap();
        assert_eq!(producer.activate(id).unwrap(), id);
        let native_receipt = json!({"schema":"actual-native-history-fixture-producer-v1", "packet_sha256":sha(&packet.encode().unwrap()),
            "id":hex::encode(id),"active":hex::encode(producer.active().unwrap().0),"generation":producer.active().unwrap().1,
            "state_root":hex::encode(packet.header.state),"source_base":BASE,"synthetic_material":true,
            "actual_neural_trials":searched.trials,"nonce_first":1,
            "external_registry2_admission":false,"independent_authority":false});
        pon_work::verify_reference(
            packet.header.challenge(),
            packet.header.work_task,
            packet.header.target,
            &packet.proof,
        )
        .unwrap();
        let reference_receipt = json!({"schema":"actual-scalar-full-w1-reference-v1",
            "packet_sha256":sha(&packet.encode().unwrap()),"proof_sha256":sha(&packet.proof),"accepted":true,
            "verifier":"pon_work::verify_reference","succinct_proof":false,"independent_implementation":false});
        write(
            &dir.path().join("producer-native-receipt.json"),
            &canonical(&native_receipt),
        );
        write(
            &dir.path().join("scalar-reference-receipt.json"),
            &canonical(&reference_receipt),
        );
        drop(producer);
        let page = canonical(&Page {
            schema: "pon-native-history-v1".into(),
            network: hex::encode(settings.network()),
            parameters: hex::encode(settings.parameters()),
            genesis: hex::encode(settings.genesis()),
            tip: hex::encode(id),
            after: hex::encode(settings.genesis()),
            packets: vec![hex::encode(packet.encode().unwrap())],
            next: hex::encode(id),
            complete: true,
        });
        let journal_path = dir.path().join("journal");
        // The original journal never creates or relaxes its protected parent.
        // This local fixture provisioner supplies the required private directory.
        fs::create_dir(&journal_path).unwrap();
        fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o700)).unwrap();
        let journal = history::Journal::open(
            &journal_path,
            rustix::process::geteuid().as_raw(),
            &identity,
            &history::Anchor::empty(),
        )
        .unwrap();
        let issued = crate::operator_task_policy::now_ns().unwrap();
        let expires = issued + 3_600_000_000_000;
        let usage = history::Usage {
            operations: 64,
            allocation: Allocation {
                cpu_ns: 128_000_000_000,
                material_bytes: 128 << 20,
                da_bytes: 128 << 20,
                funding_units: 64,
                reuse_uses: 0,
            },
            actual_cpu_ns: 128_000_000_000,
        };
        let delegation = history::RegistryDelegation {
            schema: "restricted-continuous-registry2-budget-delegation-v2".into(),
            registry2_admission_package_sha256: identity.registry2_package.clone(),
            registry2_admission_receipt_sha256: sha(&assertion),
            registry2_view_sequence: 1,
            registry2_view_digest: sha(&assertion),
            registry2_declaration_digest: sha(&canonical(&binding)),
            registry2_request_digest: sha(&assertion),
            registry2_claim_sha256: sha(&assertion),
            registry2_operation: sha(b"local test authority budget statement"),
            context: history::RegistryContext {
                registry_id: identity.registry.clone(),
                operator_id: identity.operator.clone(),
                network: identity.network.clone(),
                parameters: identity.parameters.clone(),
                source_commit: BASE.into(),
                consumer_source_package: identity.registry2_package.clone(),
                native_admitter_source: identity.node_policy_source.clone(),
                actual_parent: hex::encode(settings.genesis()),
                scope: "same-operator-declared-task-permission-no-consensus-or-reward-v1".into(),
            },
            declared_binding: binding.clone(),
            allowed_purposes: vec![
                "parent-reconcile".into(),
                "receiver-activate".into(),
                "receiver-validation".into(),
                "startup-catalog".into(),
            ],
            recipient_nodes: vec![identity.recipient_node.clone()],
            global_allocator: identity.global_allocator.clone(),
            allocator_latest: history::Anchor {
                sequence: 1,
                digest: sha(&assertion),
            },
            nonce_first: 1,
            nonce_last: 4096,
            not_before_ns: issued,
            expires_ns: expires,
            budget: history::RegistryBudget {
                max_operations: 64,
                max_cpu_ns: usage.actual_cpu_ns,
                max_material_bytes: 128 << 20,
                max_da_bytes: 128 << 20,
                max_funding_units: 64,
                max_reuse_uses: 0,
            },
            admitted_allocation: usage.allocation.clone(),
        };
        let budget = history::BudgetIncrease {
            schema: "restricted-continuous-budget-increase-v2".into(),
            identity: identity.clone(),
            sequence: 1,
            previous_digest: None,
            exact_prior_journal: journal.anchor(),
            exact_usage_digest: journal.usage_digest().unwrap(),
            ceilings: history::Ceilings {
                global: usage.clone(),
                tasks: BTreeMap::from([(binding.task.native_task.clone(), usage.clone())]),
                classes: BTreeMap::from([("structured".into(), usage)]),
            },
            issued_ns: issued,
            expires_ns: expires,
            revoked: false,
            delegation,
        };
        drop(journal);
        let (budget_raw, budget_digest) = signed(b"TRNM-RESTRICTED-CONTINUOUS-BUDGET2", &budget);
        Self {
            dir,
            settings,
            packet,
            page,
            identity,
            binding,
            material_rows,
            native_receipt,
            reference_receipt,
            budget,
            budget_raw,
            budget_digest,
            issued,
            expires,
        }
    }

    pub fn store(&self) -> PathBuf {
        self.dir.path().join("receiver")
    }
    pub fn view(
        &self,
        sequence: u64,
        previous: Option<String>,
        head: history::Anchor,
        active: (Hash, u64),
        first_nonce: u64,
        with_receiver: bool,
    ) -> ViewInput {
        let (parent, generation) = active;
        let mut allocations = Vec::new();
        let mut hashes = Vec::new();
        let mut validation = String::new();
        let mut activation = String::new();
        let mut saved_validation = None;
        let mut purposes = vec![
            (
                "startup-catalog",
                self.binding.task.full_material_catalog.clone(),
            ),
            ("parent-reconcile", hex::encode(parent)),
        ];
        if with_receiver {
            let h = sha(&self.packet.encode().unwrap());
            purposes.extend([("receiver-validation", h.clone()), ("receiver-activate", h)]);
        }
        for (index, (purpose, payload)) in purposes.into_iter().enumerate() {
            let nonce = first_nonce + index as u64;
            let mut claim = history::Claim {
                operation: String::new(),
                operation_nonce: format!("{nonce:064x}"),
                purpose: purpose.into(),
                payload,
                parent: hex::encode(parent),
                generation,
                native_task: self.binding.task.native_task.clone(),
                instance_class: self.binding.instance_class.clone(),
                task_binding: recipient::declared_binding_digest(&self.binding).unwrap(),
                allocation: Allocation {
                    cpu_ns: 2_000_000_000,
                    material_bytes: 2 << 20,
                    da_bytes: 2 << 20,
                    funding_units: 1,
                    reuse_uses: 0,
                },
                global_allocation_id: sha(format!("local-fixture-allocation:{nonce}").as_bytes()),
                global_allocation_sequence: nonce,
            };
            claim.operation = recipient::operation_id(&self.identity, &claim).unwrap();
            let origin =
                purpose
                    .starts_with("receiver-")
                    .then(|| recipient::Origin::ClosedFixture {
                        producer_node: sha(b"actual native fixture producer"),
                        packet_sha256: claim.payload.clone(),
                        parent: claim.parent.clone(),
                        generation,
                        task_binding_sha256: claim.task_binding.clone(),
                        source_commit: BASE.into(),
                        node_policy_source: self.identity.node_policy_source.clone(),
                        native_receipt_sha256: sha(&canonical(&self.native_receipt)),
                        full_reference_receipt_sha256: sha(&canonical(&self.reference_receipt)),
                    });
            let record = canonical(
                &json!({"schema":"local-test-allocator-statement-v1","sequence":nonce,"claim":claim,
                "external_registry2_admission_executed":false}),
            );
            write(
                &self
                    .dir
                    .path()
                    .join(format!("test-allocation-{nonce}.json")),
                &record,
            );
            let body = recipient::AllocationBody {
                schema: "restricted-continuous-recipient-allocation-v2".into(),
                identity: self.identity.clone(),
                claim,
                allocator_sequence: nonce,
                allocator_previous_digest: (nonce > 1)
                    .then(|| sha(b"local fixture allocator prior assertion")),
                allocator_record_sha256: if nonce == 1 {
                    self.budget.delegation.allocator_latest.digest.clone()
                } else {
                    sha(&record)
                },
                local_budget_sequence: 1,
                local_budget_digest: self.budget_digest.clone(),
                declared_binding: self.binding.clone(),
                origin,
                issued_ns: self.issued,
                expires_ns: self.expires,
            };
            let (raw, _) = signed(b"TRNM-RESTRICTED-CONTINUOUS-RECIPIENT2", &body);
            let authority = || recipient::Authority {
                identity: self.identity.clone(),
                expected: body.clone(),
                expected_envelope_sha256: sha(&raw),
                latest_allocator_sequence: nonce,
                latest_allocator_digest: body.allocator_record_sha256.clone(),
            };
            if purpose == "receiver-validation" {
                validation = body.claim.operation.clone();
                saved_validation = Some((raw.clone(), authority()));
            }
            if purpose == "receiver-activate" {
                activation = body.claim.operation.clone();
            }
            hashes.push(sha(&raw));
            let outside = authority();
            allocations.push(policy::SignedAllocationInput {
                raw,
                authority: outside,
            });
        }
        hashes.sort();
        let mut allowed_transactions: Vec<_> = self
            .packet
            .transactions
            .iter()
            .map(|raw| sha(raw))
            .collect();
        allowed_transactions.sort();
        let body = policy::TaskView {
            schema: "restricted-continuous-task-view-v2".into(),
            identity: self.identity.clone(),
            sequence,
            previous_digest: previous,
            actual_parent: hex::encode(parent),
            actual_generation: generation,
            declared_binding: self.binding.clone(),
            allocation_envelopes: hashes,
            searches: Vec::new(),
            allowed_transactions,
            issued_ns: self.issued,
            expires_ns: self.expires,
            revoked: false,
            pool_selections: Vec::new(),
            lease_edge: None,
            lease_transition_operation: None,
        };
        let (raw_view, view_digest) = signed(b"TRNM-RESTRICTED-CONTINUOUS-TASKVIEW2", &body);
        let (signed_validation, validation_authority) = saved_validation.unwrap_or_else(|| {
            let row = &allocations[0];
            (
                row.raw.clone(),
                recipient::Authority {
                    identity: row.authority.identity.clone(),
                    expected: row.authority.expected.clone(),
                    expected_envelope_sha256: row.authority.expected_envelope_sha256.clone(),
                    latest_allocator_sequence: row.authority.latest_allocator_sequence,
                    latest_allocator_digest: row.authority.latest_allocator_digest.clone(),
                },
            )
        });
        ViewInput {
            inputs: Some(policy::Inputs {
                view_authority: policy::ViewAuthority {
                    identity: self.identity.clone(),
                    expected: body,
                    envelope_sha256: sha(&raw_view),
                    latest_sequence: sequence,
                    latest_digest: view_digest.clone(),
                },
                raw_view,
                raw_budget: (sequence == 1).then(|| self.budget_raw.clone()),
                budget_authority: (sequence == 1).then(|| history::BumpAuthority {
                    identity: self.identity.clone(),
                    expected: self.budget.clone(),
                    envelope_sha256: sha(&self.budget_raw),
                    latest_sequence: 1,
                    latest_digest: self.budget_digest.clone(),
                }),
                allocations,
                journal_path: self.dir.path().join("journal"),
                expected_uid: rustix::process::geteuid().as_raw(),
                expected_journal: head,
                materials: self
                    .material_rows
                    .iter()
                    .map(|(role, path, bytes, h)| MaterialInput {
                        role: role.clone(),
                        path: path.clone(),
                        bytes: *bytes,
                        sha256: h.clone(),
                    })
                    .collect(),
                lease_transition: None,
                known_unclean_restart: None,
            }),
            view_digest,
            validation,
            activation,
            signed_validation,
            validation_authority,
        }
    }
    pub fn request<'a>(&'a self, view: &'a ViewInput) -> OwnedHistoryRequest<'a> {
        OwnedHistoryRequest {
            raw_page: &self.page,
            tip: self.packet.id().unwrap(),
            after: self.settings.genesis(),
            validation_operation_id: &view.validation,
            activation_operation_id: &view.activation,
            observed_now: CLOCK,
        }
    }
}
