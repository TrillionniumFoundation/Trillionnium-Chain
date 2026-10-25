//! Real, isolated development task authority and advancing native parent states.
//! Cached arithmetic never substitutes for the original owner's task admission.
#[path = "w1_cost_game_producers.rs"]
mod producers;

use crate::{Journal, Options, Result, Stamp};
use producers::{Producer, ARMS};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use trnm_crypto_primitives::{
    pon_work::{self, Hash, CELLS, N, Q, R},
    qualified_work_task::{
        derive_matrices, lifecycle_v2::verify_lifecycle_admission, DevelopmentTaskAdmission,
        TaskMaterial,
    },
    sign_hex, signing_key_from_hex,
};
use trnm_mvcc_fee::{continuity_v1, pon_executor::State, qualified_task_lifecycle::slot_key};
use trnm_pon_node::{development_public, sequence_root, Node, Packet, Settings};
use trnm_protocol::{
    pon_wire::{Envelope, Header},
    qualified_work_task::{
        lifecycle_v2::{DemandLeaseV2, DemandRevocationV2, SignedLifecycleTaskV2},
        lifecycle_v4::{AtomicRenewTaskV4, ATOMIC_RENEW_TAG},
        QualifiedWorkTask, TaskPurpose,
    },
};

const MAKE_ATTEMPTS: u64 = 64;
const OBSERVED_NOW: u64 = 100_000;
const LABELS: [&str; 2] = ["continuity-maintenance-v1", "signed-zero-development-v1"];

struct Material {
    model: Vec<u8>,
    input: Vec<u8>,
    a: Vec<u32>,
    b: Vec<u32>,
    task: Hash,
}

impl Material {
    fn view(&self) -> TaskMaterial<'_> {
        TaskMaterial {
            model: &self.model,
            input: &self.input,
            a: &self.a,
            b: &self.b,
        }
    }
}

struct Context {
    node: Node,
    directory: tempfile::TempDir,
    materials: [Material; 2],
    lease: DemandLeaseV2,
    signed: SignedLifecycleTaskV2,
}

struct Acquired {
    id: u64,
    task_index: usize,
    packet: Packet,
}

#[derive(Default)]
struct Counts {
    acquisitions: u64,
    original_make_completed_proofs: u64,
    original_make_failed_target_proofs: u64,
    research_completed_proofs: u64,
    screened_candidates: u64,
    discarded_screen_candidates: u64,
    hot_preparations: u64,
    cold_preparations: u64,
    controls: u64,
    renewals: u64,
    rounds_completed: u64,
    research_complete: BTreeSet<Hash>,
    research_winners: BTreeSet<Hash>,
    all_winners: BTreeSet<Hash>,
    all_admitted: BTreeSet<Hash>,
    all_budget_winners: BTreeSet<Hash>,
    research_budget_winners: BTreeSet<Hash>,
    transaction_fee_total: u64,
    transaction_count: u64,
}

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn relation<T>(value: std::result::Result<T, pon_work::WorkError>) -> Result<T> {
    value.map_err(|error| format!("WORK:{error:?}").into())
}

fn semantic(header: &Header, proof: &[u8]) -> Result<(Hash, Hash, Hash)> {
    if proof.len() != pon_work::PROOF_BYTES {
        return Err("PROOF_LENGTH".into());
    }
    let trace: Hash = proof[proof.len() - 32..].try_into()?;
    let challenge = header.challenge();
    let ticket = pon_work::hash(b"ticket", &[&challenge, &trace]);
    let identity = pon_work::hash(
        b"w1-cost-game-semantic-ticket-v1",
        &[&header.work_task, &challenge, &ticket],
    );
    Ok((trace, ticket, identity))
}

fn fields(header: &Header, proof: &[u8]) -> Result<Value> {
    let (trace, ticket, identity) = semantic(header, proof)?;
    Ok(json!({
        "header_hex":hex::encode(header.encode()),"parent":hex::encode(header.parent),
        "height":header.height,"timestamp":header.timestamp,"nonce":header.nonce,
        "task":hex::encode(header.work_task),"target":hex::encode(header.target),
        "challenge":hex::encode(header.challenge()),"trace":hex::encode(trace),
        "ticket":hex::encode(ticket),"semantic_id":hex::encode(identity),
        "block_id":hex::encode(header.block_id(trace)),
        "target_hit":header.target != [0;32] && ticket <= header.target,
        "proof_sha256":sha(proof),"proof_bytes":proof.len(),"proof_hex":hex::encode(proof)
    }))
}

fn signature(actor: u64, message: &[u8]) -> Result<[u8; 64]> {
    let secret = hex::encode(pon_work::hash(b"DEV-ONLY-KEY", &[&actor.to_le_bytes()]));
    let key = signing_key_from_hex(&secret)?;
    hex::decode(sign_hex(&key, message))?
        .try_into()
        .map_err(|_| "SIGNATURE_LENGTH".into())
}

fn transaction(
    settings: &Settings,
    actor: u64,
    nonce: u64,
    tag: u8,
    payload: Vec<u8>,
) -> Result<Vec<u8>> {
    let mut tx = Envelope {
        network: settings.network(),
        sender: development_public(actor)?,
        nonce,
        expiry: 1000,
        fee_limit: 1_000_000,
        tag,
        payload,
        signature: [0; 64],
    };
    tx.signature = signature(
        actor,
        &tx.signing_digest()
            .map_err(|error| format!("TX:{error:?}"))?,
    )?;
    tx.encode().map_err(|error| format!("TX:{error:?}").into())
}

fn statement(
    settings: &Settings,
    lease: &DemandLeaseV2,
    material: &Material,
    sequence: u64,
) -> Result<SignedLifecycleTaskV2> {
    let mut manifest = settings.bootstrap_lifecycle_task()?.signed.manifest;
    manifest.purpose = lease.purpose;
    manifest.source = lease.source;
    manifest.demand_id = lease.demand_id;
    manifest.source_record = lease
        .bound_source_record()
        .map_err(|error| format!("LEASE:{error:?}"))?;
    manifest.model = pon_work::hash(b"artifact", &[&material.model]);
    manifest.layer = QualifiedWorkTask::layer_id(manifest.model);
    manifest.input = pon_work::hash(b"qualified-task-input-v1", &[&material.input]);
    manifest.matrix_task = material.task;
    manifest.availability_manifest = lease.availability_manifest;
    manifest.availability_root = lease.availability_root;
    manifest.authorization_scope = lease.authorization_scope;
    manifest.withdrawal_head = lease
        .withdrawal_frontier()
        .map_err(|error| format!("LEASE:{error:?}"))?;
    manifest.demand_nonce = sequence;
    manifest.not_before = lease.not_before;
    manifest.expires = lease.expires;
    manifest.available_until = lease.available_until;
    manifest.useful_output_limit = lease.purpose.output_limit();
    manifest.output_meter = manifest.derived_output_meter();
    let mut signed = SignedLifecycleTaskV2 {
        lease_id: lease.id().map_err(|error| format!("LEASE:{error:?}"))?,
        manifest,
        signature: [0; 64],
    };
    signed.signature = signature(
        0,
        &signed
            .signing_message()
            .map_err(|error| format!("STATEMENT:{error:?}"))?,
    )?;
    Ok(signed)
}

impl Context {
    fn new(rounds: u64, journal: &mut Journal) -> Result<Self> {
        let start = journal.stamp()?;
        let settings = Settings::development_with_profiles(
            Some(1),
            "native-public-evaluation-dev-v1",
            continuity_v1::PROFILE,
        )?;
        let directory = tempfile::tempdir()?;
        let node = Node::open(directory.path(), settings.clone(), 1)?;
        let (ma, mb) = continuity_v1::maintenance_matrices();
        let (model, input) = continuity_v1::maintenance_material();
        let maintenance = Material {
            task: relation(pon_work::task_id(&ma, &mb))?,
            model,
            input,
            a: ma,
            b: mb,
        };
        let bytes = vec![0; CELLS * 4];
        let (a, b) =
            derive_matrices(&bytes, &bytes).map_err(|error| format!("MATERIAL:{error:?}"))?;
        let zero = Material {
            task: relation(pon_work::task_id(&a, &b))?,
            model: bytes.clone(),
            input: bytes,
            a,
            b,
        };
        let mut lease = settings.bootstrap_lifecycle_task()?.lease;
        lease.slot = 1;
        lease.generation = 2;
        lease.requester = development_public(2)?;
        lease.purpose = TaskPurpose::Maintenance;
        lease.not_before = 1;
        lease.expires = rounds + 12;
        lease.available_until = lease.expires + 100;
        lease.demand_id = lease.derived_demand_id();
        let signed = statement(&settings, &lease, &zero, 1)?;
        journal.charge(
            "context-open-and-task-source",
            start,
            json!({
                "workers":1,"source":"disclosed-development-signers",
                "real_neural_training":false,"independent_requester":false,
                "source_acquisition_external_cost_claim":null,
                "initial_native_stats":node.stats()?
            }),
        )?;
        for (index, material) in [&maintenance, &zero].iter().enumerate() {
            journal.emit(json!({"kind":"task","task_index":index,"label":LABELS[index],
                "task":hex::encode(material.task),"model_hex":hex::encode(&material.model),
                "input_hex":hex::encode(&material.input),
                "model_sha256":sha(&material.model),"input_sha256":sha(&material.input),
                "source_scope":if index==0 {"immutable-genesis-maintenance"} else {"locally-created-signed-development-zero"},
                "useful_model_qualification":false,"public_network_authority":false}))?;
        }
        journal.emit(json!({"kind":"task-statement","revision":lease.revision,
            "lease_hex":hex::encode(lease.encode().map_err(|e|format!("LEASE:{e:?}"))?),
            "statement_hex":hex::encode(signed.encode().map_err(|e|format!("STATEMENT:{e:?}"))?),
            "registered_in_parent":false}))?;
        Ok(Self {
            node,
            directory,
            materials: [maintenance, zero],
            lease,
            signed,
        })
    }

    fn permit(&self, height: u64) -> Result<DevelopmentTaskAdmission> {
        verify_lifecycle_admission(
            &self
                .signed
                .encode()
                .map_err(|e| format!("STATEMENT:{e:?}"))?,
            self.materials[1].view(),
            &self.lease,
            height,
        )
        .map_err(|error| format!("TASK_ADMISSION:{error:?}").into())
    }

    fn timestamp(&self, parent: Hash) -> Result<u64> {
        Ok(self.node.settings().genesis_time() + (self.node.parent_height(parent)? + 1) * 10)
    }

    fn make(
        &self,
        parent: Hash,
        index: usize,
        transactions: Vec<Vec<u8>>,
    ) -> trnm_pon_node::Result<Packet> {
        let timestamp =
            self.node.settings().genesis_time() + (self.node.parent_height(parent)? + 1) * 10;
        if index == 0 {
            self.node.make_consensus_maintenance(
                parent,
                transactions,
                development_public(3)?,
                timestamp,
                MAKE_ATTEMPTS,
            )
        } else {
            self.node.make_with_registered_material(
                parent,
                transactions,
                development_public(3)?,
                timestamp,
                MAKE_ATTEMPTS,
                &self.materials[index].model,
                &self.materials[index].input,
            )
        }
    }
}

fn economy(state: &State) -> Result<Value> {
    let mut accounts = BTreeMap::new();
    for actor in [0, 2, 3] {
        let key = format!("account:{}", hex::encode(development_public(actor)?));
        accounts.insert(key.clone(), state.get(&key).cloned().unwrap_or(Value::Null));
    }
    let escrow: BTreeMap<_, _> = state
        .iter()
        .filter(|(key, _)| key.contains("escrow"))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    Ok(json!({"accounts":accounts,"escrow_rows":escrow}))
}

fn fees(packet: &Packet, before: &State, after: &State) -> Result<(u64, Value)> {
    let mut records = Vec::new();
    let mut receipts = Vec::new();
    let mut senders = BTreeSet::new();
    let mut sum = 0_u64;
    for bytes in &packet.transactions {
        let tx = Envelope::decode(bytes).map_err(|e| format!("TX:{e:?}"))?;
        if !senders.insert(tx.sender)
            || ![18, 20, 21, ATOMIC_RENEW_TAG].contains(&tx.tag)
            || tx.sender == packet.header.miner
            || packet.header.height >= 20
        {
            return Err("FEE_RECEIPT_FIXTURE_SCOPE".into());
        }
        let key = format!("account:{}", hex::encode(tx.sender));
        let before_balance = before
            .get(&key)
            .and_then(|v| v["balance"].as_u64())
            .ok_or("FEE_ACCOUNT")?;
        let after_balance = after
            .get(&key)
            .and_then(|v| v["balance"].as_u64())
            .ok_or("FEE_ACCOUNT")?;
        let fee = before_balance
            .checked_sub(after_balance)
            .ok_or("FEE_BALANCE")?;
        sum = sum.checked_add(fee).ok_or("FEE_OVERFLOW")?;
        let tx_id = tx.id().map_err(|e| format!("TX:{e:?}"))?;
        receipts.push(serde_json::to_vec(
            &json!({"tx":hex::encode(tx_id),"fee":fee,"status":"applied"}),
        )?);
        records.push(json!({"transaction_id":hex::encode(tx_id),"tag":tx.tag,
            "sender":hex::encode(tx.sender),"nonce":tx.nonce,"fee":fee,
            "fee_limit":tx.fee_limit,"before_balance":before_balance,"after_balance":after_balance}));
    }
    if sequence_root("receipts", &receipts) != packet.header.receipts {
        return Err("FEE_RECEIPT_ROOT".into());
    }
    Ok((
        sum,
        json!({"transactions":records,"fee_total":sum,
        "receipt_root_matches_original_node_header":true,"before":economy(before)?,"after":economy(after)?,
        "fee_units":"native-development-token-integer","cpu_units_separate":true}),
    ))
}

fn admit(
    context: &mut Context,
    packet: &Packet,
    role: &str,
    source_id: u64,
    journal: &mut Journal,
    counts: &mut Counts,
) -> Result<Hash> {
    let start = journal.stamp()?;
    let expected = packet.id()?;
    let id = context.node.admit(packet, OBSERVED_NOW)?;
    let admitted = journal.stamp()?;
    let repeated = context.node.admit(packet, OBSERVED_NOW)?;
    if expected != id || repeated != id {
        return Err("NATIVE_ADMISSION_ID".into());
    }
    let (_, ticket, identity) = semantic(&packet.header, &packet.proof)?;
    if packet.header.target == [0; 32] || ticket > packet.header.target {
        return Err("NATIVE_ADMITTED_TARGET_MISS".into());
    }
    let unique = counts.all_winners.insert(identity);
    counts.all_admitted.insert(id);
    let budget_credit = journal.within(admitted);
    if budget_credit {
        counts.all_budget_winners.insert(identity);
    }
    if role == "research" {
        counts.research_winners.insert(identity);
        if budget_credit {
            counts.research_budget_winners.insert(identity);
        }
    }
    journal.charge(
        "native-admission-and-duplicate-check",
        start,
        json!({"role":role,"source_id":source_id}),
    )?;
    journal.emit(json!({"kind":"admission","role":role,"source_id":source_id,
        "block_id":hex::encode(id),"duplicate_block_id":hex::encode(repeated),
        "semantic_id":hex::encode(identity),"unique_all_work_winner":unique,
        "admitted":true,"native_full_relation_and_parent_qualification":true,
        "admission_completed":admitted,"admission_completed_within_budget":budget_credit,
        "duplicate_creates_new_work":false,"active_chainweight_added_here":false}))?;
    Ok(id)
}

#[allow(clippy::too_many_arguments)]
fn acquire(
    context: &mut Context,
    parent: Hash,
    task_index: usize,
    role: &str,
    transactions: Vec<Vec<u8>>,
    journal: &mut Journal,
    counts: &mut Counts,
    acquisitions: &mut Vec<Acquired>,
) -> Result<Header> {
    let start = journal.stamp()?;
    let before = if transactions.is_empty() {
        None
    } else {
        Some(context.node.state_at(parent)?)
    };
    let original = context.make(parent, task_index, transactions);
    let completed = journal.stamp()?;
    journal.charge(
        "original-node-make",
        start,
        json!({"role":role,"task_index":task_index,"parent":hex::encode(parent),
            "max_attempts":MAKE_ATTEMPTS,"success":original.is_ok()}),
    )?;
    let packet = match original {
        Ok(packet) => packet,
        Err(error) => {
            journal.emit(json!({"kind":"acquisition-failure","role":role,"task_index":task_index,
                "parent":hex::encode(parent),"error":error.to_string(),
                "raw_internal_miss_proofs_available":false,
                "complete_proof_count_inferred_from_original_search":if error.to_string()=="WORK_BUDGET" {Some(MAKE_ATTEMPTS)}else{None},
                "budget_and_failure_retained":true}))?;
            return Err(error.into());
        }
    };
    if packet.header.target != context.node.expected_target(parent)?
        || packet.header.work_task != context.materials[task_index].task
        || packet.header.nonce >= MAKE_ATTEMPTS
    {
        return Err("NATIVE_ACQUISITION_BINDING".into());
    }
    let id = counts.acquisitions;
    counts.acquisitions += 1;
    counts.original_make_completed_proofs += packet.header.nonce + 1;
    counts.original_make_failed_target_proofs += packet.header.nonce;
    journal.emit(
        json!({"kind":"acquisition","acquisition_id":id,"role":role,"task_index":task_index,
        "proof":fields(&packet.header,&packet.proof)?,
        "transactions_hex":packet.transactions.iter().map(hex::encode).collect::<Vec<_>>(),
        "original_search_completed":completed,
        "original_make_complete_attempts":packet.header.nonce+1,
        "original_make_failed_attempts":packet.header.nonce,
        "winning_proof_retention":"original-native-returned-bytes",
        "miss_retention":"not-exposed-by-native-API; reconstructed-after-strategy-only",
        "original_search_cpu_paid":true,"reconstruction_has_no_new_ticket_credit":true}),
    )?;
    let block = admit(context, &packet, "acquisition", id, journal, counts)?;
    if let Some(before) = before {
        let begin = journal.stamp()?;
        let after = context.node.state_at(block)?;
        let (fee, receipt) = fees(&packet, &before, &after)?;
        counts.transaction_fee_total += fee;
        counts.transaction_count += packet.transactions.len() as u64;
        journal.charge(
            "economics-native-state-readback",
            begin,
            json!({"acquisition_id":id}),
        )?;
        journal
            .emit(json!({"kind":"economics","acquisition_id":id,"role":role,"receipt":receipt}))?;
    }
    let header = packet.header.clone();
    acquisitions.push(Acquired {
        id,
        task_index,
        packet,
    });
    Ok(header)
}

fn activate(
    context: &mut Context,
    id: Hash,
    why: &str,
    round: Option<u64>,
    journal: &mut Journal,
) -> Result<()> {
    let start = journal.stamp()?;
    context.node.activate(id)?;
    let stats = context.node.stats()?;
    if stats["tip"] != hex::encode(id) {
        return Err("ACTIVATION_READBACK".into());
    }
    journal.charge(
        "native-activate-and-readback",
        start,
        json!({"reason":why,"round":round}),
    )?;
    journal.emit(
        json!({"kind":"parent","reason":why,"round":round,"stats":stats,
        "actual_native_activation":true,"sibling_chainwork_summed":false}),
    )
}

fn rejection(
    name: &str,
    expected: &str,
    outcome: trnm_pon_node::Result<Packet>,
    start: Stamp,
    journal: &mut Journal,
    counts: &mut Counts,
) -> Result<()> {
    let actual = outcome.err().map(|e| e.to_string());
    journal.charge("native-negative-control", start, json!({"name":name}))?;
    journal.emit(json!({"kind":"control","name":name,"expected":expected,"actual":actual,
        "original_node_called":true,"accepted":actual.is_none(),"expected_rejection":actual.as_deref()==Some(expected)}))?;
    counts.controls += 1;
    if actual.as_deref() != Some(expected) {
        return Err(format!("CONTROL_FAILED:{name}:{actual:?}").into());
    }
    Ok(())
}

fn reject_material(
    context: &Context,
    parent: Hash,
    journal: &mut Journal,
    counts: &mut Counts,
) -> Result<()> {
    let start = journal.stamp()?;
    let height = context.node.parent_height(parent)? + 1;
    let permit = context.permit(height)?;
    let mut wrong = context.materials[1].model.clone();
    wrong[0] ^= 1;
    let material = &context.materials[1];
    rejection(
        "material-mismatch",
        "TASK_MATERIAL",
        context.node.make_with_task(
            parent,
            vec![],
            development_public(3)?,
            context.timestamp(parent)?,
            MAKE_ATTEMPTS,
            &permit,
            TaskMaterial {
                model: &wrong,
                input: &material.input,
                a: &material.a,
                b: &material.b,
            },
        ),
        start,
        journal,
        counts,
    )
}

fn renew(
    context: &mut Context,
    journal: &mut Journal,
    counts: &mut Counts,
    acquisitions: &mut Vec<Acquired>,
) -> Result<bool> {
    let parent = context.node.active()?.0;
    let height = context.node.parent_height(parent)? + 1;
    let old_permit = context.permit(height + 1)?;
    let start = journal.stamp()?;
    let mut successor = context.lease.clone();
    successor.revision = 2;
    successor.not_before = height;
    successor.expires += 8;
    successor.available_until = successor.expires + 100;
    let signed = statement(
        context.node.settings(),
        &successor,
        &context.materials[1],
        2,
    )?;
    let payload = AtomicRenewTaskV4 {
        lease: successor.clone(),
        signed: signed.clone(),
    }
    .encode()
    .map_err(|e| format!("RENEWAL:{e:?}"))?;
    let tx = transaction(context.node.settings(), 2, 2, ATOMIC_RENEW_TAG, payload)?;
    journal.charge(
        "construct-signed-atomic-renewal",
        start,
        json!({"revision":2}),
    )?;
    if !journal.permitted()? {
        return Ok(false);
    }
    let header = acquire(
        context,
        parent,
        0,
        "zero-renewal",
        vec![tx],
        journal,
        counts,
        acquisitions,
    )?;
    let block = acquisitions
        .last()
        .ok_or("ACQUISITION_MISSING")?
        .packet
        .id()?;
    if !journal.permitted()? {
        return Ok(false);
    }
    activate(context, block, "zero-renewal", None, journal)?;
    context.lease = successor;
    context.signed = signed;
    counts.renewals += 1;
    journal.emit(json!({"kind":"task-statement","revision":2,"registered_in_parent":true,
        "parent":hex::encode(block),"height":header.height,
        "lease_hex":hex::encode(context.lease.encode().map_err(|e|format!("LEASE:{e:?}"))?),
        "statement_hex":hex::encode(context.signed.encode().map_err(|e|format!("STATEMENT:{e:?}"))?)}))?;
    if !journal.permitted()? {
        return Ok(false);
    }
    let start = journal.stamp()?;
    rejection(
        "stale-admission-after-renewal",
        "TASK_ADMISSION_CONTEXT",
        context.node.make_with_task(
            block,
            vec![],
            development_public(3)?,
            context.timestamp(block)?,
            MAKE_ATTEMPTS,
            &old_permit,
            context.materials[1].view(),
        ),
        start,
        journal,
        counts,
    )?;
    Ok(true)
}

fn prepare(
    index: usize,
    material: &Material,
    label: &str,
    task_index: usize,
    journal: &mut Journal,
    counts: &mut Counts,
) -> Result<Producer> {
    let start = journal.stamp()?;
    let result =
        relation(Producer::new(index, &material.a, &material.b))?.ok_or("UNSUPPORTED_ARM")?;
    journal.charge(
        "arithmetic-prepare",
        start,
        json!({"cache":label,"task_index":task_index,"arm":ARMS[index]}),
    )?;
    if label == "hot" {
        counts.hot_preparations += 1;
    } else {
        counts.cold_preparations += 1;
    }
    Ok(result)
}

/// Exact public rejection-sampled noise recipe. No transcript, ticket, target or
/// prior native verdict enters this score. These bytes are NOT passed to prove.
fn noise_score(challenge: Hash) -> Result<(u64, u64, String)> {
    let mut bitweight = 0_u64;
    let mut hashes = 0_u64;
    let mut bytes = Vec::with_capacity(4 * N * R * 4);
    for label in 0..4_u8 {
        let mut values = 0;
        let mut counter = 0_u32;
        while values < N * R {
            if counter >= 128 {
                return Err("SCREEN_NOISE_BUDGET".into());
            }
            let digest = pon_work::hash(b"noise", &[&challenge, &[label], &counter.to_le_bytes()]);
            for chunk in digest.chunks_exact(4) {
                let word = u32::from_le_bytes(chunk.try_into()?);
                if u128::from(word) < Q {
                    bitweight += u64::from(word.count_ones());
                    bytes.extend_from_slice(&word.to_le_bytes());
                    values += 1;
                    if values == N * R {
                        break;
                    }
                }
            }
            counter += 1;
            hashes += 1;
        }
    }
    Ok((bitweight, hashes, sha(&bytes)))
}

fn nonce(seed: u64, round: u64, attempt: u64, candidate: u64) -> u64 {
    let digest = pon_work::hash(
        b"w1-parent-reuse-nonce-v1",
        &[
            &seed.to_le_bytes(),
            &round.to_le_bytes(),
            &attempt.to_le_bytes(),
            &candidate.to_le_bytes(),
        ],
    );
    u64::from_le_bytes(digest[..8].try_into().expect("eight bytes"))
}

fn choose(
    options: &Options,
    round: u64,
    attempt: u64,
    templates: &[Header; 2],
    journal: &mut Journal,
    counts: &mut Counts,
) -> Result<(usize, Header)> {
    let start = journal.stamp()?;
    if options.strategy != "paid-task-screen" {
        let index = usize::from(options.strategy == "zero-only");
        let mut header = templates[index].clone();
        header.nonce = nonce(options.seed, round, attempt, 0);
        journal.charge(
            "fixed-task-nonce-selection",
            start,
            json!({"round":round,"attempt":attempt,"task_index":index}),
        )?;
        journal.emit(json!({"kind":"selection","round":round,"attempt":attempt,
            "strategy":options.strategy,"task_index":index,"candidate":0,
            "header_hex":hex::encode(header.encode()),"challenge":hex::encode(header.challenge()),
            "score":null,"score_reads_ticket":false,"screen_candidate_count":0}))?;
        return Ok((index, header));
    }
    let mut candidates = Vec::new();
    for (index, template) in templates.iter().enumerate() {
        for ordinal in 0..options.screen_width {
            let mut header = template.clone();
            header.nonce = nonce(options.seed, round, attempt, ordinal);
            let (score, hashes, digest) = noise_score(header.challenge())?;
            candidates.push((score, index, ordinal, header, hashes, digest));
        }
    }
    let best = candidates
        .iter()
        .enumerate()
        .min_by_key(|(_, v)| (v.0, v.1, v.2))
        .map(|(i, _)| i)
        .ok_or("EMPTY_SCREEN")?;
    let chosen = candidates[best].3.clone();
    let index = candidates[best].1;
    let score = candidates[best].0;
    let ordinal = candidates[best].2;
    journal.charge(
        "paid-noise-screen-and-select",
        start,
        json!({"round":round,"attempt":attempt,"candidates":candidates.len()}),
    )?;
    counts.screened_candidates += candidates.len() as u64;
    counts.discarded_screen_candidates += candidates.len() as u64 - 1;
    for (position, (score, task_index, candidate, header, hashes, digest)) in
        candidates.iter().enumerate()
    {
        journal.emit(json!({"kind":"screen","round":round,"attempt":attempt,"task_index":task_index,
            "candidate":candidate,"header_hex":hex::encode(header.encode()),"challenge":hex::encode(header.challenge()),
            "score":score,"score_definition":"sum-popcount-of-four-canonical-noise-arrays",
            "noise_sha256":digest,"noise_hash_calls":hashes,"noise_words":4*N*R,
            "selected":position==best,"complete_proof":false,"ticket_observed":false,
            "noise_passed_to_producer":false,"credited_ticket":false}))?;
    }
    journal.emit(json!({"kind":"selection","round":round,"attempt":attempt,
        "strategy":options.strategy,"task_index":index,"candidate":ordinal,
        "header_hex":hex::encode(chosen.encode()),"challenge":hex::encode(chosen.challenge()),
        "score":score,"score_reads_ticket":false,"screen_candidate_count":2*options.screen_width}))?;
    Ok((index, chosen))
}

fn reconstruct(
    acquisitions: &[Acquired],
    materials: &[Material; 2],
    journal: &mut Journal,
) -> Result<u64> {
    let mut retained = 0;
    for original in acquisitions {
        let material = &materials[original.task_index];
        let prepared = relation(pon_work::PreparedTask::new(&material.a, &material.b))?;
        for ordinal in 0..=original.packet.header.nonce {
            let mut header = original.packet.header.clone();
            header.nonce = ordinal;
            let proof = relation(prepared.prove(header.challenge()))?;
            let production = relation(pon_work::verify(
                header.challenge(),
                header.work_task,
                [255; 32],
                &proof,
            ))?;
            let reference = relation(pon_work::verify_reference(
                header.challenge(),
                header.work_task,
                [255; 32],
                &proof,
            ))?;
            if production.ticket() != reference.ticket() {
                return Err("RECONSTRUCTION_VERIFIER_DISAGREEMENT".into());
            }
            let last = ordinal == original.packet.header.nonce;
            if last && proof != original.packet.proof {
                return Err("ORIGINAL_WINNER_RECONSTRUCTION_MISMATCH".into());
            }
            let hit = production.ticket() <= header.target;
            if hit != last {
                return Err("ORIGINAL_FIRST_WINNER_RECONSTRUCTION".into());
            }
            journal.emit(json!({"kind":"reconstruction","acquisition_id":original.id,"task_index":original.task_index,
                "ordinal":ordinal,"proof":fields(&header,&proof)?,"original_winner":last,
                "provenance":"reconstructed-after-run","original_bytes_observed":last,
                "original_winner_bytes_equal":last.then_some(true),"native_full_relation_verified":true,
                "native_reference_verified":true,"new_work_credit":false,
                "used_by_selection":false,"included_in_strategy_cpu":false}))?;
            retained += 1;
        }
    }
    Ok(retained)
}

pub fn run(options: &Options, journal: &mut Journal) -> Result<()> {
    if !journal.permitted()? {
        journal.emit(
            json!({"kind":"strategy-end","status":"process-cpu-budget-stopped-before-context",
            "completed":journal.stamp()?,"all_work_unique_winners":0,"research_unique_winners":0,
            "acquisitions":0,"research_completed_proofs":0,"rounds_completed":0,
            "context_drop_included":true,"controls_completed":false}),
        )?;
        return journal.emit(
            json!({"kind":"end","status":"complete","reconstructed_proofs":0,
            "native_admission_scope":"none","useful_learning":false,"hardness_accepted":false}),
        );
    }
    let mut counts = Counts::default();
    let mut acquisitions = Vec::new();
    let mut context = Context::new(options.rounds, journal)?;
    let mut cached: [Option<Producer>; 2] = [None, None];
    let mut stopped = false;
    let mut controls_completed = false;
    'strategy: {
        if !journal.permitted()? {
            stopped = true;
            break 'strategy;
        }
        let genesis = context.node.active()?.0;
        let start = journal.stamp()?;
        rejection(
            "zero-before-registration",
            "TASK",
            context.make(genesis, 1, vec![]),
            start,
            journal,
            &mut counts,
        )?;
        if !journal.permitted()? {
            stopped = true;
            break 'strategy;
        }
        let start = journal.stamp()?;
        let registration = vec![
            transaction(
                context.node.settings(),
                2,
                1,
                18,
                context.lease.encode().map_err(|e| format!("LEASE:{e:?}"))?,
            )?,
            transaction(
                context.node.settings(),
                0,
                1,
                21,
                context
                    .signed
                    .encode()
                    .map_err(|e| format!("STATEMENT:{e:?}"))?,
            )?,
        ];
        journal.charge(
            "construct-signed-registration",
            start,
            json!({"transaction_count":2}),
        )?;
        if !journal.permitted()? {
            stopped = true;
            break 'strategy;
        }
        acquire(
            &mut context,
            genesis,
            0,
            "zero-registration",
            registration,
            journal,
            &mut counts,
            &mut acquisitions,
        )?;
        let registered = acquisitions
            .last()
            .ok_or("ACQUISITION_MISSING")?
            .packet
            .id()?;
        if !journal.permitted()? {
            stopped = true;
            break 'strategy;
        }
        activate(&mut context, registered, "zero-registration", None, journal)?;
        if !journal.permitted()? {
            stopped = true;
            break 'strategy;
        }
        reject_material(&context, registered, journal, &mut counts)?;
        let arm = ARMS
            .iter()
            .position(|name| *name == options.arm)
            .ok_or("ARM")?;
        if options.cache == "hot" && journal.permitted()? {
            for (index, slot) in cached.iter_mut().enumerate() {
                if !journal.permitted()? {
                    stopped = true;
                    break 'strategy;
                }
                *slot = Some(prepare(
                    arm,
                    &context.materials[index],
                    "hot",
                    index,
                    journal,
                    &mut counts,
                )?);
            }
        }
        for round in 0..options.rounds {
            if !journal.permitted()? {
                stopped = true;
                break;
            }
            if round == options.rounds / 2
                && !renew(&mut context, journal, &mut counts, &mut acquisitions)?
            {
                stopped = true;
                break 'strategy;
            }
            if !journal.permitted()? {
                stopped = true;
                break;
            }
            let parent = context.node.active()?.0;
            let maintenance = acquire(
                &mut context,
                parent,
                0,
                "parent-template-maintenance",
                vec![],
                journal,
                &mut counts,
                &mut acquisitions,
            )?;
            if !journal.permitted()? {
                stopped = true;
                break;
            }
            let zero = acquire(
                &mut context,
                parent,
                1,
                "parent-template-zero",
                vec![],
                journal,
                &mut counts,
                &mut acquisitions,
            )?;
            let fallback = acquisitions[acquisitions.len() - 2].packet.id()?;
            let templates = [maintenance, zero];
            journal.emit(json!({"kind":"parent-domain","round":round,"parent":hex::encode(parent),
            "height":context.node.parent_height(parent)?,"tasks":context.materials.iter().map(|m|hex::encode(m.task)).collect::<Vec<_>>(),
            "lease_revision":context.lease.revision,"shared_templates_paid":true,
            "actual_signed_development_eligibility":true}))?;
            let mut first_winner = None;
            for attempt in 0..options.attempts_per_parent {
                if !journal.permitted()? {
                    stopped = true;
                    break;
                }
                let (index, header) =
                    choose(options, round, attempt, &templates, journal, &mut counts)?;
                if !journal.permitted()? {
                    stopped = true;
                    break;
                }
                let cold;
                let producer = if options.cache == "hot" {
                    cached[index].as_ref().ok_or("HOT_CACHE_MISSING")?
                } else {
                    cold = prepare(
                        arm,
                        &context.materials[index],
                        "cold",
                        index,
                        journal,
                        &mut counts,
                    )?;
                    &cold
                };
                if !journal.permitted()? {
                    stopped = true;
                    break;
                }
                let start = journal.stamp()?;
                let proof = relation(producer.prove(header.challenge()))?;
                let completed = journal.charge(
                    "research-complete-proof",
                    start,
                    json!({"round":round,"attempt":attempt,"task_index":index,"arm":options.arm}),
                )?;
                let start = journal.stamp()?;
                let production = relation(pon_work::verify(
                    header.challenge(),
                    header.work_task,
                    [255; 32],
                    &proof,
                ))?;
                let reference = relation(pon_work::verify_reference(
                    header.challenge(),
                    header.work_task,
                    [255; 32],
                    &proof,
                ))?;
                if production.ticket() != reference.ticket() {
                    return Err("RESEARCH_VERIFIER_DISAGREEMENT".into());
                }
                journal.charge(
                    "research-native-full-verifiers",
                    start,
                    json!({"round":round,"attempt":attempt}),
                )?;
                let (_, ticket, identity) = semantic(&header, &proof)?;
                let hit = header.target != [0; 32] && ticket <= header.target;
                let unique = counts.research_complete.insert(identity);
                let attempt_id = counts.research_completed_proofs;
                counts.research_completed_proofs += 1;
                journal.emit(json!({"kind":"attempt","attempt_id":attempt_id,"round":round,"attempt":attempt,
                "task_index":index,"arm":options.arm,"cache":options.cache,"proof":fields(&header,&proof)?,
                "proof_retention":"original-research-producer-returned-bytes","completed":completed,
                "native_full_relation_verified":true,"native_reference_verified":true,
                "unique_research_semantic":unique,"complete_proof_within_budget":journal.within(completed),
                "noise_expanded_again_by_producer":options.strategy=="paid-task-screen"}))?;
                if hit {
                    let packet = Packet {
                        header,
                        transactions: vec![],
                        proof,
                    };
                    let block = admit(
                        &mut context,
                        &packet,
                        "research",
                        attempt_id,
                        journal,
                        &mut counts,
                    )?;
                    if first_winner.is_none() {
                        first_winner = Some(block);
                    }
                }
            }
            if stopped || !journal.permitted()? {
                stopped = true;
                break;
            }
            activate(
                &mut context,
                first_winner.unwrap_or(fallback),
                if first_winner.is_some() {
                    "first-research-winner"
                } else {
                    "paid-original-template-fallback"
                },
                Some(round),
                journal,
            )?;
            counts.rounds_completed += 1;
        }
        if !stopped && journal.permitted()? {
            let parent = context.node.active()?.0;
            let start = journal.stamp()?;
            let revoke = DemandRevocationV2 {
                slot: context.lease.slot,
                network: context.lease.network,
                parameters: context.lease.parameters,
                demand_id: context.lease.demand_id,
                requester: context.lease.requester,
                expected_revision: context.lease.revision,
            };
            let tx = transaction(
                context.node.settings(),
                2,
                3,
                20,
                revoke.encode().map_err(|e| format!("REVOCATION:{e:?}"))?,
            )?;
            journal.charge(
                "construct-signed-revocation",
                start,
                json!({"revision":context.lease.revision}),
            )?;
            if !journal.permitted()? {
                stopped = true;
                break 'strategy;
            }
            acquire(
                &mut context,
                parent,
                0,
                "zero-revocation",
                vec![tx],
                journal,
                &mut counts,
                &mut acquisitions,
            )?;
            let revoked = acquisitions
                .last()
                .ok_or("ACQUISITION_MISSING")?
                .packet
                .id()?;
            if !journal.permitted()? {
                stopped = true;
                break 'strategy;
            }
            activate(&mut context, revoked, "zero-revocation", None, journal)?;
            if !journal.permitted()? {
                stopped = true;
                break 'strategy;
            }
            let start = journal.stamp()?;
            rejection(
                "zero-after-revocation",
                "TASK",
                context.make(revoked, 1, vec![]),
                start,
                journal,
                &mut counts,
            )?;
            // A cached task still exists in memory but cannot authorize a revoked task.
            journal.emit(
                json!({"kind":"revocation-readback","parent":hex::encode(revoked),
            "slot":context.node.state_at(revoked)?.get(&slot_key(1)?),
            "mathematical_cache_still_allocated":options.cache=="hot",
            "cache_is_not_task_authority":true}),
            )?;
            if !journal.permitted()? {
                stopped = true;
                break 'strategy;
            }
            acquire(
                &mut context,
                revoked,
                0,
                "post-revocation-maintenance",
                vec![],
                journal,
                &mut counts,
                &mut acquisitions,
            )?;
            let recovery = acquisitions
                .last()
                .ok_or("ACQUISITION_MISSING")?
                .packet
                .id()?;
            if !journal.permitted()? {
                stopped = true;
                break 'strategy;
            }
            activate(
                &mut context,
                recovery,
                "post-revocation-maintenance",
                None,
                journal,
            )?;
            controls_completed = true;
        } else if !journal.permitted()? {
            stopped = true;
        }
    }
    let final_stats = context.node.stats()?;
    let final_economy = economy(&context.node.state_at(context.node.active()?.0)?)?;
    drop(cached);
    let Context {
        node,
        directory,
        materials,
        ..
    } = context;
    let start = journal.stamp()?;
    drop(node);
    drop(directory);
    journal.charge(
        "native-context-drop",
        start,
        json!({"includes_temporary_state_cleanup":true}),
    )?;
    let strategy_completed = journal.stamp()?;
    journal.emit(json!({"kind":"strategy-end","status":if stopped {"process-cpu-budget-stopped"}else{"planned-rounds-complete"},
        "completed":strategy_completed,"rounds_completed":counts.rounds_completed,
        "context_drop_included":true,"controls_completed":controls_completed,"controls":counts.controls,
        "acquisitions":counts.acquisitions,"original_make_completed_proofs":counts.original_make_completed_proofs,
        "original_make_failed_target_proofs":counts.original_make_failed_target_proofs,
        "original_make_winning_proofs":counts.acquisitions,"research_completed_proofs":counts.research_completed_proofs,
        "research_unique_complete_semantics":counts.research_complete.len(),
        "research_unique_winners":counts.research_winners.len(),"all_work_unique_winners":counts.all_winners.len(),
        "all_work_unique_native_blocks":counts.all_admitted.len(),
        "all_work_unique_admitted_within_budget":counts.all_budget_winners.len(),
        "research_unique_admitted_within_budget":counts.research_budget_winners.len(),
        "screened_candidates":counts.screened_candidates,"discarded_screen_candidates":counts.discarded_screen_candidates,
        "hot_preparations":counts.hot_preparations,"cold_preparations":counts.cold_preparations,
        "renewals":counts.renewals,"transaction_count":counts.transaction_count,
        "transaction_fee_total":counts.transaction_fee_total,"transaction_fee_units":"native-development-token-integer",
        "fees_not_added_to_cpu":true,"final_native_stats":final_stats,"final_economy":final_economy,
        "sibling_work_summed_into_chainweight":false,"minimum_cost_strategy_claim":false,
        "posthoc_original_miss_reconstruction_excluded":true}))?;
    let posthoc_start = journal.stamp()?;
    let reconstructed = reconstruct(&acquisitions, &materials, journal)?;
    drop(acquisitions);
    drop(materials);
    let posthoc_end = journal.stamp()?;
    journal.emit(
        json!({"kind":"end","status":"complete","strategy_completed":strategy_completed,
        "posthoc_start":posthoc_start,"posthoc_end":posthoc_end,
        "posthoc_process_cpu_ns":posthoc_end.process_cpu_ns-posthoc_start.process_cpu_ns,
        "reconstructed_proofs":reconstructed,"reconstructed_proofs_new_credit":0,
        "native_admission_scope":"original-Node-isolated-continuity-development",
        "new_real_training":false,"useful_learning":false,"hardness_accepted":false,
        "cost_lower_bound_proved":false,"production_activation":false}),
    )
}
