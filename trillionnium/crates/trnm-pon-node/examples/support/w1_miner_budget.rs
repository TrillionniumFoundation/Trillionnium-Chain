//! Native research setup and post-miner receiver; the miner itself has no Node.
#[path = "w1_cost_game_producers.rs"]
mod producers;
use crate::{Journal, Options, Result, Stamp};
use producers::{Producer, ARMS};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use trnm_crypto_primitives::{
    pon_work::{self, Hash, CELLS, N, Q, R},
    qualified_work_task::derive_matrices,
    sign_hex, signing_key_from_hex,
};
use trnm_mvcc_fee::{continuity_v1, pon_executor::State};
use trnm_pon_node::{development_public, sequence_root, Node, Packet, Settings};
use trnm_protocol::{
    pon_wire::{Envelope, Header},
    qualified_work_task::{
        lifecycle_v2::{DemandLeaseV2, SignedLifecycleTaskV2},
        lifecycle_v4::ATOMIC_RENEW_TAG,
        QualifiedWorkTask, TaskPurpose,
    },
};
const MAKE_ATTEMPTS: u64 = 64;
const OBSERVED_NOW: u64 = 100_000;
struct Material {
    model: Vec<u8>,
    input: Vec<u8>,
    a: Vec<u32>,
    b: Vec<u32>,
    task: Hash,
}
struct Context {
    node: Node,
    directory: tempfile::TempDir,
    materials: BTreeMap<usize, Material>,
}
struct Acquired {
    id: u64,
    task_index: usize,
    packet: Packet,
}
struct Template {
    bank: usize,
    task_index: usize,
    source: u64,
    header: Header,
}
struct Attempt {
    packet: Packet,
    available: Stamp,
    miner_elapsed_cpu_ns: u64,
    hit: bool,
    identity: Hash,
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

impl Context {
    fn new(
        options: &Options,
        journal: &mut Journal,
    ) -> Result<(Self, Option<(DemandLeaseV2, SignedLifecycleTaskV2)>)> {
        let start = journal.stamp()?;
        let settings = Settings::development_with_profiles(
            Some(1),
            "native-public-evaluation-dev-v1",
            continuity_v1::PROFILE,
        )?;
        let directory = tempfile::tempdir()?;
        let node = Node::open(directory.path(), settings.clone(), 1)?;
        let (a, b) = continuity_v1::maintenance_matrices();
        let (model, input) = continuity_v1::maintenance_material();
        let mut materials = BTreeMap::new();
        materials.insert(
            0,
            Material {
                task: relation(pon_work::task_id(&a, &b))?,
                model,
                input,
                a,
                b,
            },
        );
        let registration = if options.acquired_tasks().contains(&1) {
            let bytes = vec![0; CELLS * 4];
            let (a, b) = derive_matrices(&bytes, &bytes).map_err(|e| format!("MATERIAL:{e:?}"))?;
            materials.insert(
                1,
                Material {
                    task: relation(pon_work::task_id(&a, &b))?,
                    model: bytes.clone(),
                    input: bytes,
                    a,
                    b,
                },
            );
            let mut lease = settings.bootstrap_lifecycle_task()?.lease;
            lease.slot = 1;
            lease.generation = 2;
            lease.requester = development_public(2)?;
            lease.purpose = TaskPurpose::Maintenance;
            lease.not_before = 1;
            lease.expires = options.parents + 12;
            lease.available_until = lease.expires + 100;
            lease.demand_id = lease.derived_demand_id();
            let signed = statement(&settings, &lease, &materials[&1], 1)?;
            Some((lease, signed))
        } else {
            None
        };
        journal.charge("context-and-task-source",start,json!({"initial_stats":node.stats()?,"zero_source_constructed":registration.is_some(),"public_task_authority":false,"real_training":false}))?;
        for (index, material) in &materials {
            journal.emit(json!({"kind":"task","task_index":index,"model_hex":hex::encode(&material.model),"input_hex":hex::encode(&material.input),"task":hex::encode(material.task),"mined":options.miner_tasks().contains(index),"template_acquired":options.acquired_tasks().contains(index)}))?;
        }
        if let Some((lease, signed)) = &registration {
            journal.emit(json!({"kind":"task-statement","lease_hex":hex::encode(lease.encode().map_err(|e|format!("LEASE:{e:?}"))?),"statement_hex":hex::encode(signed.encode().map_err(|e|format!("STATEMENT:{e:?}"))?)}))?;
        }
        Ok((
            Self {
                node,
                directory,
                materials,
            },
            registration,
        ))
    }
    fn make(
        &self,
        parent: Hash,
        task: usize,
        transactions: Vec<Vec<u8>>,
    ) -> trnm_pon_node::Result<Packet> {
        let timestamp =
            self.node.settings().genesis_time() + (self.node.parent_height(parent)? + 1) * 10;
        if task == 0 {
            self.node.make_consensus_maintenance(
                parent,
                transactions,
                development_public(3)?,
                timestamp,
                MAKE_ATTEMPTS,
            )
        } else {
            let material = &self.materials[&task];
            self.node.make_with_registered_material(
                parent,
                transactions,
                development_public(3)?,
                timestamp,
                MAKE_ATTEMPTS,
                &material.model,
                &material.input,
            )
        }
    }
}
fn acquire(
    context: &mut Context,
    task: usize,
    role: &str,
    transactions: Vec<Vec<u8>>,
    acquisitions: &mut Vec<Acquired>,
    journal: &mut Journal,
) -> Result<(Header, Hash, u64, u64)> {
    let start = journal.stamp()?;
    let parent = context.node.active()?.0;
    let before = if transactions.is_empty() {
        None
    } else {
        Some(context.node.state_at(parent)?)
    };
    let packet = context.make(parent, task, transactions)?;
    if packet.header.nonce >= MAKE_ATTEMPTS {
        return Err("NATIVE_ORIGINAL_NONCE".into());
    }
    let made = journal.stamp()?;
    let expected = packet.id()?;
    let id = context.node.admit(&packet, OBSERVED_NOW)?;
    if id != expected {
        return Err("SETUP_ADMISSION_ID".into());
    }
    let admitted = journal.stamp()?;
    let source = acquisitions.len() as u64;
    let (fee, receipt) = if let Some(before) = before {
        let after = context.node.state_at(id)?;
        let (fee, receipt) = fees(&packet, &before, &after)?;
        (fee, Some(receipt))
    } else {
        (0, None)
    };
    journal.charge(
        "native-setup-acquisition",
        start,
        json!({"task_index":task,"role":role,"source_id":source,"max_attempts":MAKE_ATTEMPTS}),
    )?;
    journal.emit(json!({"kind":"setup-acquisition","source_id":source,"task_index":task,"role":role,"proof":fields(&packet.header,&packet.proof)?,"transactions_hex":packet.transactions.iter().map(hex::encode).collect::<Vec<_>>(),"made":made,"admitted":admitted,"native_block_id":hex::encode(id),"original_complete_attempts":packet.header.nonce+1,"original_miss_bytes_retained":false,"fee_receipt":receipt,"fee_units":fee,"posthoc_reconstruction_adds_credit":false}))?;
    let header = packet.header.clone();
    acquisitions.push(Acquired {
        id: source,
        task_index: task,
        packet,
    });
    Ok((header, id, source, fee))
}
fn activate(context: &mut Context, id: Hash, role: &str, journal: &mut Journal) -> Result<()> {
    let start = journal.stamp()?;
    context.node.activate(id)?;
    let stats = context.node.stats()?;
    if stats["tip"] != hex::encode(id) {
        return Err("SETUP_ACTIVE_TIP".into());
    }
    journal.charge(
        "native-setup-activation",
        start,
        json!({"role":role,"block_id":hex::encode(id)}),
    )?;
    journal.emit(json!({"kind":"setup-parent","role":role,"stats":stats}))
}
fn prepare(
    task: usize,
    options: &Options,
    materials: &BTreeMap<usize, Material>,
    journal: &mut Journal,
) -> Result<Producer> {
    let start = journal.stamp()?;
    let name = options.actual_arm(task);
    let arm = ARMS.iter().position(|a| *a == name).ok_or("ARM")?;
    let material = &materials[&task];
    let prepared =
        relation(Producer::new(arm, &material.a, &material.b))?.ok_or("UNSUPPORTED_ARM")?;
    journal.charge(
        "arithmetic-prepare",
        start,
        json!({"task_index":task,"arm":name,"cache":options.cache}),
    )?;
    Ok(prepared)
}
fn nonce(seed: u64, ordinal: u64, bank: usize, task: usize, candidate: u64) -> u64 {
    let hash = pon_work::hash(
        b"w1-miner-budget-nonce-v1",
        &[
            &seed.to_le_bytes(),
            &ordinal.to_le_bytes(),
            &(bank as u64).to_le_bytes(),
            &(task as u64).to_le_bytes(),
            &candidate.to_le_bytes(),
        ],
    );
    u64::from_le_bytes(hash[..8].try_into().expect("eight")) | (1_u64 << 63)
}
fn choose(
    options: &Options,
    ordinal: u64,
    templates: &[Template],
    journal: &mut Journal,
) -> Result<(usize, Header)> {
    let start = journal.stamp()?;
    let tasks = options.miner_tasks();
    if options.policy != "paid-noise-screen" {
        let task = tasks[(ordinal as usize) % tasks.len()];
        let bank = if options.parent_policy == "newest" {
            options.parents as usize - 1
        } else {
            (ordinal as usize / tasks.len()) % options.parents as usize
        };
        let selected = templates
            .iter()
            .position(|t| t.bank == bank && t.task_index == task)
            .ok_or("TEMPLATE_MISSING")?;
        let mut header = templates[selected].header.clone();
        header.nonce = nonce(options.seed, ordinal, bank, task, 0);
        journal.charge("fixed-selection", start, json!({"attempt_id":ordinal}))?;
        journal.emit(json!({"kind":"selection","attempt_id":ordinal,"template_index":selected,"bank":bank,"task_index":task,"candidate":0,"header_hex":hex::encode(header.encode()),"screened":0,"score":null,"ticket_observed":false}))?;
        return Ok((selected, header));
    }
    let mut candidates = Vec::new();
    for (index, template) in templates.iter().enumerate() {
        if !tasks.contains(&template.task_index)
            || options.parent_policy == "newest" && template.bank + 1 != options.parents as usize
        {
            continue;
        }
        for candidate in 0..options.screen_width {
            let mut header = template.header.clone();
            header.nonce = nonce(
                options.seed,
                ordinal,
                template.bank,
                template.task_index,
                candidate,
            );
            let (score, hashes, digest) = noise_score(header.challenge())?;
            candidates.push((score, index, candidate, header, hashes, digest));
        }
    }
    let best = candidates
        .iter()
        .enumerate()
        .min_by_key(|(_, x)| (x.0, x.1, x.2))
        .map(|(i, _)| i)
        .ok_or("EMPTY_SCREEN")?;
    journal.charge(
        "paid-noise-screen",
        start,
        json!({"attempt_id":ordinal,"candidates":candidates.len()}),
    )?;
    for (position, (score, index, candidate, header, hashes, digest)) in
        candidates.iter().enumerate()
    {
        journal.emit(json!({"kind":"screen","attempt_id":ordinal,"template_index":index,"candidate":candidate,"header_hex":hex::encode(header.encode()),"score":score,"noise_hash_calls":hashes,"noise_sha256":digest,"selected":position==best,"ticket_observed":false,"noise_passed_to_producer":false}))?;
    }
    let chosen = &candidates[best];
    let template = &templates[chosen.1];
    journal.emit(json!({"kind":"selection","attempt_id":ordinal,"template_index":chosen.1,"bank":template.bank,"task_index":template.task_index,"candidate":chosen.2,"header_hex":hex::encode(chosen.3.encode()),"screened":candidates.len(),"score":chosen.0,"ticket_observed":false}))?;
    Ok((chosen.1, chosen.3.clone()))
}
/// This function has no Node, Context, receiver, verifier or audit callback.
fn mine(
    options: &Options,
    templates: &[Template],
    materials: &BTreeMap<usize, Material>,
    mut cached: BTreeMap<usize, Producer>,
    ready: bool,
    journal: &mut Journal,
) -> Result<(Vec<Attempt>, Value)> {
    let mut attempts = Vec::new();
    let mut status = "setup-incomplete";
    if ready {
        status = "safety-cap-censored";
        for ordinal in 0..options.max_attempts {
            if !journal.permitted()? {
                status = "miner-cpu-budget-stopped";
                break;
            }
            let (selected, header) = choose(options, ordinal, templates, journal)?;
            let task = templates[selected].task_index;
            if !journal.permitted()? {
                status = "miner-cpu-budget-stopped";
                break;
            }
            let cold;
            let producer = if options.cache == "hot" {
                cached.get(&task).ok_or("HOT_CACHE_MISSING")?
            } else {
                cold = prepare(task, options, materials, journal)?;
                &cold
            };
            if !journal.permitted()? {
                status = "miner-cpu-budget-stopped";
                break;
            }
            let start = journal.stamp()?;
            let proof = relation(producer.prove(header.challenge()))?;
            let generated = journal.stamp()?;
            let (_, ticket, identity) = semantic(&header, &proof)?;
            let hit = header.target != [0; 32] && ticket <= header.target;
            journal.charge(
                "complete-proof-and-ticket",
                start,
                json!({"attempt_id":ordinal,"task_index":task,"arm":options.actual_arm(task)}),
            )?;
            let record = fields(&header, &proof)?;
            let packet = Packet {
                header,
                transactions: vec![],
                proof,
            };
            attempts.push(Attempt {
                packet,
                available: generated,
                miner_elapsed_cpu_ns: 0,
                hit,
                identity,
            });
            journal.emit(json!({"kind":"attempt","attempt_id":ordinal,"template_index":selected,"task_index":task,"arm":options.actual_arm(task),"cache":options.cache,"generated":generated,"proof":record,"native_verifier_called":false,"node_called":false}))?;
            let available = journal.stamp()?;
            let elapsed = journal.elapsed(available)?;
            let retained = attempts.last_mut().ok_or("ATTEMPT_MISSING")?;
            retained.available = available;
            retained.miner_elapsed_cpu_ns = elapsed;
            journal.emit(json!({"kind":"available","attempt_id":ordinal,"available":available,"miner_elapsed_cpu_ns":elapsed,"full_bytes_flushed":true,"within_miner_budget":elapsed<=options.miner_budget_ns}))?;
        }
        if !journal.permitted()? {
            status = "miner-cpu-budget-stopped";
        }
    }
    cached.clear();
    drop(cached);
    let complete: BTreeSet<_> = attempts
        .iter()
        .filter(|a| a.miner_elapsed_cpu_ns <= options.miner_budget_ns)
        .map(|a| a.identity)
        .collect();
    let winners: BTreeSet<_> = attempts
        .iter()
        .filter(|a| a.miner_elapsed_cpu_ns <= options.miner_budget_ns && a.hit)
        .map(|a| a.identity)
        .collect();
    let detail = json!({"status":status,"attempts":attempts.len(),"safety_cap_reached":attempts.len() as u64==options.max_attempts,"miner_unique_complete_by_B":complete.len(),"miner_unique_target_hits_by_B":winners.len(),"native_acceptance_known_during_mining":false,"cache_drop_included":true});
    Ok((attempts, detail))
}
fn audit(
    acquisitions: &[Acquired],
    attempts: &[Attempt],
    materials: &BTreeMap<usize, Material>,
    journal: &mut Journal,
) -> Result<u64> {
    for (index, attempt) in attempts.iter().enumerate() {
        let start = journal.stamp()?;
        let h = &attempt.packet.header;
        let a = relation(pon_work::verify(
            h.challenge(),
            h.work_task,
            [255; 32],
            &attempt.packet.proof,
        ))?;
        let b = relation(pon_work::verify_reference(
            h.challenge(),
            h.work_task,
            [255; 32],
            &attempt.packet.proof,
        ))?;
        if a.ticket() != b.ticket() {
            return Err("AUDIT_DISAGREEMENT".into());
        }
        journal.charge(
            "research-full-native-audit",
            start,
            json!({"attempt_id":index}),
        )?;
        journal.emit(json!({"kind":"audit-proof","attempt_id":index,"full_relation":true,"reference_relation":true,"provides_miner_feedback":false}))?;
    }
    let mut reconstructed = 0;
    for source in acquisitions {
        let m = &materials[&source.task_index];
        let prepared = relation(pon_work::PreparedTask::new(&m.a, &m.b))?;
        for ordinal in 0..=source.packet.header.nonce {
            let mut header = source.packet.header.clone();
            header.nonce = ordinal;
            let proof = relation(prepared.prove(header.challenge()))?;
            let a = relation(pon_work::verify(
                header.challenge(),
                header.work_task,
                [255; 32],
                &proof,
            ))?;
            let b = relation(pon_work::verify_reference(
                header.challenge(),
                header.work_task,
                [255; 32],
                &proof,
            ))?;
            let winner = ordinal == source.packet.header.nonce;
            if a.ticket() != b.ticket()
                || (a.ticket() <= header.target) != winner
                || winner && proof != source.packet.proof
            {
                return Err("ORIGINAL_RECONSTRUCTION".into());
            }
            journal.emit(json!({"kind":"reconstruction","source_id":source.id,"task_index":source.task_index,"ordinal":ordinal,"original_winner":winner,"original_bytes_observed":winner,"proof":fields(&header,&proof)?,"new_work_credit":false,"miner_feedback":false}))?;
            reconstructed += 1;
        }
    }
    Ok(reconstructed)
}
pub fn run(options: &Options, journal: &mut Journal) -> Result<()> {
    let mut context = None;
    let mut acquisitions = Vec::new();
    let mut templates = Vec::new();
    let mut cached = BTreeMap::new();
    let mut setup_complete = false;
    let mut fee_units = 0_u64;
    let mut transaction_count = 0_u64;
    let mut hot_preparations = 0_u64;
    'setup: {
        if !journal.permitted()? {
            break 'setup;
        }
        let (created, registration) = Context::new(options, journal)?;
        context = Some(created);
        let current = context.as_mut().ok_or("CONTEXT")?;
        if let Some((lease, signed)) = registration {
            if !journal.permitted()? {
                break 'setup;
            }
            let start = journal.stamp()?;
            let transactions = vec![
                transaction(
                    current.node.settings(),
                    2,
                    1,
                    18,
                    lease.encode().map_err(|e| format!("LEASE:{e:?}"))?,
                )?,
                transaction(
                    current.node.settings(),
                    0,
                    1,
                    21,
                    signed.encode().map_err(|e| format!("STATEMENT:{e:?}"))?,
                )?,
            ];
            journal.charge(
                "construct-signed-registration",
                start,
                json!({"transactions":2}),
            )?;
            if !journal.permitted()? {
                break 'setup;
            }
            let (_, id, _, fee) = acquire(
                current,
                0,
                "zero-registration",
                transactions,
                &mut acquisitions,
                journal,
            )?;
            fee_units += fee;
            transaction_count += 2;
            if !journal.permitted()? {
                break 'setup;
            }
            activate(current, id, "zero-registration", journal)?;
        }
        for bank in 0..options.parents as usize {
            for task in options.acquired_tasks() {
                if !journal.permitted()? {
                    break 'setup;
                }
                let (header, _, source, _) = acquire(
                    current,
                    task,
                    "bank-template",
                    vec![],
                    &mut acquisitions,
                    journal,
                )?;
                let index = templates.len();
                journal.emit(json!({"kind":"template","template_index":index,"bank":bank,"task_index":task,"source_id":source,"header_hex":hex::encode(header.encode()),"parent":hex::encode(header.parent),"parent_height":header.height-1,"historical_native_parent":true}))?;
                templates.push(Template {
                    bank,
                    task_index: task,
                    source,
                    header,
                });
            }
            if bank + 1 < options.parents as usize {
                if !journal.permitted()? {
                    break 'setup;
                }
                let task = options.miner_tasks()[0];
                let selected = templates
                    .iter()
                    .find(|t| t.bank == bank && t.task_index == task)
                    .ok_or("ADVANCE_TEMPLATE")?;
                let id = acquisitions[selected.source as usize].packet.id()?;
                activate(current, id, "ancestor-bank-advance", journal)?;
            }
        }
        if options.cache == "hot" {
            for task in options.miner_tasks() {
                if !journal.permitted()? {
                    break 'setup;
                }
                cached.insert(task, prepare(task, options, &current.materials, journal)?);
                hot_preparations += 1;
            }
        }
        setup_complete = true;
    }
    let setup_stats = context.as_ref().map(|c| c.node.stats()).transpose()?;
    let setup_economy = context
        .as_ref()
        .map(|c| -> Result<Value> { economy(&c.node.state_at(c.node.active()?.0)?) })
        .transpose()?;
    if !journal.permitted()? {
        setup_complete = false;
    }
    if !setup_complete {
        cached.clear();
    }
    let known: BTreeSet<_> = acquisitions
        .iter()
        .map(|a| semantic(&a.packet.header, &a.packet.proof).map(|x| x.2))
        .collect::<Result<_>>()?;
    let mut setup_detail = json!({"complete":setup_complete,"status":if setup_complete{"complete"}else{"setup-cpu-budget-stopped"},"templates":templates.len(),"requested_parent_bank":options.parents,"acquired_tasks":options.acquired_tasks(),"miner_tasks":options.miner_tasks(),"original_acquisitions":acquisitions.len(),"original_search_complete_attempts":acquisitions.iter().map(|a|a.packet.header.nonce+1).sum::<u64>(),"known_original_winning_semantics":known.len(),"hot_preparations":hot_preparations,"transaction_count":transaction_count,"transaction_fee_units":fee_units,"fee_units_added_to_cpu":false,"native_stats":setup_stats,"economy":setup_economy});
    let setup_end =
        journal.transition("miner", Some(options.miner_budget_ns), setup_detail.clone())?;
    if setup_end.process_cpu_ns > options.setup_budget_ns {
        setup_complete = false;
        setup_detail["complete"] = json!(false);
        setup_detail["status"] = json!("setup-cpu-budget-stopped");
        cached.clear();
    }
    let empty = BTreeMap::new();
    let materials = context.as_ref().map_or(&empty, |c| &c.materials);
    let (mut attempts, miner_detail) = mine(
        options,
        &templates,
        materials,
        cached,
        setup_complete,
        journal,
    )?;
    let miner_total_by_b: BTreeSet<_> = attempts
        .iter()
        .filter(|a| a.miner_elapsed_cpu_ns <= options.miner_budget_ns)
        .map(|a| a.identity)
        .collect();
    let miner_hits_by_b: BTreeSet<_> = attempts
        .iter()
        .filter(|a| a.miner_elapsed_cpu_ns <= options.miner_budget_ns && a.hit)
        .map(|a| a.identity)
        .collect();
    journal.transition("receiver", None, miner_detail.clone())?;
    let mut accepted = BTreeSet::new();
    let mut accepted_from_b = BTreeSet::new();
    let mut final_stats = None;
    if let Some(current) = context.as_mut() {
        let before = current.node.stats()?;
        for (index, attempt) in attempts.iter().enumerate() {
            let start = journal.stamp()?;
            let result = current.node.admit(&attempt.packet, OBSERVED_NOW);
            let completed = journal.stamp()?;
            let (id, error) = match result {
                Ok(id) => (Some(id), None),
                Err(error) => (None, Some(error.to_string())),
            };
            if attempt.hit {
                if id != Some(attempt.packet.id()?) {
                    return Err(format!("RECEIVER_EXPECTED_ACCEPT:{error:?}").into());
                }
                accepted.insert(attempt.identity);
                if attempt.miner_elapsed_cpu_ns <= options.miner_budget_ns {
                    accepted_from_b.insert(attempt.identity);
                }
            } else if error.as_deref() != Some("WORK:Target") {
                return Err(format!("RECEIVER_EXPECTED_TARGET:{error:?}").into());
            }
            journal.charge(
                "original-node-admission",
                start,
                json!({"attempt_id":index}),
            )?;
            journal.emit(json!({"kind":"receiver","attempt_id":index,"accepted":id.is_some(),"block_id":id.map(hex::encode),"error":error,"completed":completed,"from_within_miner_budget":attempt.miner_elapsed_cpu_ns<=options.miner_budget_ns,"semantic_id":hex::encode(attempt.identity),"native_acceptance_after_miner_sealed":true,"miss_is_cheap_target_rejection":!attempt.hit,"claim_of_mature_reward":false}))?;
        }
        let after = current.node.stats()?;
        if before["tip"] != after["tip"]
            || before["height"] != after["height"]
            || before["chainwork_hex"] != after["chainwork_hex"]
        {
            return Err("RECEIVER_CHANGED_ACTIVE_CHAIN".into());
        }
        final_stats = Some(after);
    }
    let mut materials = if let Some(Context {
        node,
        directory,
        materials,
    }) = context.take()
    {
        let start = journal.stamp()?;
        drop(node);
        drop(directory);
        journal.charge(
            "native-owner-and-directory-teardown",
            start,
            json!({"owned_cleanup":true}),
        )?;
        materials
    } else {
        BTreeMap::new()
    };
    let receiver_detail = json!({"attempt_records":attempts.len(),"eventually_native_accepted":accepted.len(),"eventually_native_accepted_from_B":accepted_from_b.len(),"native_stats":final_stats,"active_chain_growth_from_research":0,"node_teardown_included":true,"verification_feedback_to_miner":false});
    journal.transition("audit", None, receiver_detail.clone())?;
    let reconstructed = audit(&acquisitions, &attempts, &materials, journal)?;
    let original_winners = acquisitions.len();
    let research_records = attempts.len();
    attempts.clear();
    acquisitions.clear();
    templates.clear();
    materials.clear();
    drop(attempts);
    drop(acquisitions);
    drop(templates);
    drop(materials);
    let audit_detail = json!({"research_full_native_audits":research_records,"original_reconstruction_records":reconstructed,"original_winner_repetitions":original_winners,"original_target_miss_reconstructions":reconstructed-original_winners as u64,"new_work_credit":0,"all_owned_proof_material_teardown_included":true});
    let total = journal.transition("done", None, audit_detail.clone())?;
    journal.emit(json!({"kind":"end","status":"complete","setup_complete":setup_complete,"miner_status":miner_detail["status"],"phase_cpu_ns":journal.totals,"total_process_cpu_ns":total.process_cpu_ns,"total_wall_ns":total.wall_ns,"native_total_endpoint":"all four phases and owned node/material/proof teardown; final boundary/summary encoding remains in whole-child residual","setup":setup_detail,"miner":miner_detail,"receiver":receiver_detail,"audit":audit_detail,"miner_unique_complete_by_B":miner_total_by_b.len(),"miner_unique_target_hits_by_B":miner_hits_by_b.len(),"eventually_native_accepted_from_B":accepted_from_b.len(),"setup_known_winners_are_separate":true,"native_acceptance_completed_within_miner_B":false,"retained_records_are_distinct_tickets":false,"minimum_attacker_cost_established":false,"hardness_accepted":false,"production_activation":false}))
}
