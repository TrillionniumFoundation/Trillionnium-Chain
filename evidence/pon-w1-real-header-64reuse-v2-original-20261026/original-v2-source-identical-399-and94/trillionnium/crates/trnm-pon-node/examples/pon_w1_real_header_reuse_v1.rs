//! Opt-in, controlled-development PNH1/64-search component. Never a work-hardness receipt.
//! The external owner starts each two-second deadline BEFORE sending its request.
#[path = "support/w1_real_header_reuse_v1.rs"]
mod registry;

use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    io::{self, BufRead, Read, Write},
    path::{Path, PathBuf},
    time::Instant,
};
use trnm_crypto_primitives::{
    pon_work,
    qualified_work_task::{
        derive_matrices, lifecycle_v2::verify_lifecycle_admission, DevelopmentTaskAdmission,
        TaskMaterial,
    },
    sign_hex, signing_key_from_hex,
};
use trnm_pon_node::{development_public, Node, Packet, Settings};
use trnm_protocol::{
    pon_wire::{hash, Envelope, Hash},
    qualified_work_task::{
        lifecycle_v2::{DemandLeaseV2, SignedLifecycleTaskV2},
        lifecycle_v4::PROFILE as TASK_PROFILE,
        QualifiedWorkTask, TaskPurpose,
    },
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
trait Diagnostic<T> {
    fn diag(self) -> Result<T>;
}
impl<T, E: std::fmt::Debug> Diagnostic<T> for std::result::Result<T, E> {
    fn diag(self) -> Result<T> {
        self.map_err(|e| io::Error::other(format!("{e:?}")).into())
    }
}
const PROFILE: &str = "pn1-pnh1-signed-zero-fixed-64-reuse-component-v2";
const POLICY: &str = "pn1-pnh1-frozen-zero-dispatch-v1:canonical-A=B=zero=>blocked-zero-integer-paired;otherwise-refuse";
const STREAM: &[u8] = b"TRNM-PON-W1-PNH1-64REUSE-STREAM-V1\0";
const SEARCHES: u64 = 64;
const ATTEMPTS: u64 = 4096;
const BASE: u64 = 1_000_000;
const CLOCK: u64 = 1_800_010_000;
const MIB: u64 = 1024 * 1024;
const OUT_CAP: u64 = 8 * MIB;
const TERMINAL_RESERVE: u64 = 16 * 1024;

fn require(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message).into())
    }
}
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn cpu() -> Option<u64> {
    use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
    let t = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ProcessCPUTime)).ok()?;
    u64::try_from(t.tv_sec)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(u64::try_from(t.tv_nsec).ok()?)
}
struct Sink {
    bytes: u64,
    sequence: u64,
}
impl Sink {
    fn emit(&mut self, mut value: Value, terminal: bool) -> Result<()> {
        value["schema"] = json!(PROFILE);
        value["sequence"] = json!(self.sequence);
        let mut bytes = serde_json::to_vec(&value)?;
        bytes.push(b'\n');
        let next = self
            .bytes
            .checked_add(bytes.len() as u64)
            .ok_or("OUTPUT_OVERFLOW")?;
        require(
            next <= OUT_CAP - if terminal { 0 } else { TERMINAL_RESERVE },
            "OUTPUT_CAP",
        )?;
        // Count/reserve the complete actual frame before any write. A failed write is fatal.
        self.bytes = next;
        self.sequence = self.sequence.checked_add(1).ok_or("SEQUENCE_OVERFLOW")?;
        let mut stdout = io::stdout().lock();
        stdout.write_all(&bytes)?;
        stdout.flush()?;
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    id: u64,
    op: String,
}
fn request(reader: &mut impl BufRead, id: u64, op: &str) -> Result<()> {
    let mut bytes = Vec::new();
    (&mut *reader).take(4097).read_until(b'\n', &mut bytes)?;
    require(
        !bytes.is_empty() && bytes.len() <= 4096 && bytes.last() == Some(&b'\n'),
        "REQUEST_BOUNDARY",
    )?;
    let got: Request = serde_json::from_slice(&bytes)?;
    require(got.id == id && got.op == op, "REQUEST_ORDER")
}
fn response(
    sink: &mut Sink,
    id: u64,
    op: &str,
    started: Instant,
    before: Option<u64>,
    data: Value,
) -> Result<()> {
    sink.emit(
        json!({"kind":"response","id":id,"op":op,"operation_wall_ns":started.elapsed().as_nanos(),
        "operation_cpu_ns":before.zip(cpu()).and_then(|(a,b)|b.checked_sub(a)),"data":data}),
        false,
    )
}
fn sign(actor: u64, bytes: &[u8]) -> Result<[u8; 64]> {
    let key = signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&actor.to_le_bytes()])))?;
    Ok(hex::decode(sign_hex(&key, bytes))?
        .try_into()
        .map_err(|_| "SIGNATURE_LENGTH")?)
}
fn transaction(settings: &Settings, actor: u64, tag: u8, payload: Vec<u8>) -> Result<Vec<u8>> {
    let mut tx = Envelope {
        network: settings.network(),
        sender: development_public(actor)?,
        nonce: 1,
        expiry: 1000,
        fee_limit: 1_000_000,
        tag,
        payload,
        signature: [0; 64],
    };
    tx.signature = sign(actor, &tx.signing_digest().diag()?)?;
    tx.encode().diag()
}
type Material = (Vec<u8>, Vec<u8>, Vec<u32>, Vec<u32>);
fn material(m: &Material) -> TaskMaterial<'_> {
    TaskMaterial {
        model: &m.0,
        input: &m.1,
        a: &m.2,
        b: &m.3,
    }
}
fn admission(
    signed: &SignedLifecycleTaskV2,
    lease: &DemandLeaseV2,
    m: &Material,
    height: u64,
) -> Result<DevelopmentTaskAdmission> {
    verify_lifecycle_admission(&signed.encode().diag()?, material(m), lease, height).diag()
}
fn statement(
    settings: &Settings,
    lease: &DemandLeaseV2,
    m: &Material,
) -> Result<SignedLifecycleTaskV2> {
    let mut manifest = settings.bootstrap_lifecycle_task()?.signed.manifest;
    manifest.purpose = lease.purpose;
    manifest.source = lease.source;
    manifest.demand_id = lease.demand_id;
    manifest.source_record = lease.bound_source_record().diag()?;
    manifest.model = hash(b"artifact", &[&m.0]);
    manifest.layer = QualifiedWorkTask::layer_id(manifest.model);
    manifest.input = hash(b"qualified-task-input-v1", &[&m.1]);
    manifest.matrix_task = pon_work::task_id(&m.2, &m.3).diag()?;
    manifest.availability_manifest = lease.availability_manifest;
    manifest.availability_root = lease.availability_root;
    manifest.authorization_scope = lease.authorization_scope;
    manifest.withdrawal_head = lease.withdrawal_frontier().diag()?;
    manifest.demand_nonce = 1;
    manifest.not_before = lease.not_before;
    manifest.expires = lease.expires;
    manifest.available_until = lease.available_until;
    manifest.useful_output_limit = lease.purpose.output_limit();
    manifest.output_meter = manifest.derived_output_meter();
    let mut signed = SignedLifecycleTaskV2 {
        lease_id: lease.id().diag()?,
        manifest,
        signature: [0; 64],
    };
    signed.signature = sign(0, &signed.signing_message().diag()?)?;
    Ok(signed)
}
fn make(
    node: &Node,
    parent: Hash,
    tx: Vec<Vec<u8>>,
    permit: &DevelopmentTaskAdmission,
    m: &Material,
) -> Result<Packet> {
    let height = node.parent_height(parent)?.checked_add(1).ok_or("HEIGHT")?;
    Ok(node.make_with_task(
        parent,
        tx,
        development_public(3)?,
        node.settings().genesis_time() + height * 10,
        ATTEMPTS,
        permit,
        material(m),
    )?)
}
fn packet_value(packet: &Packet) -> Result<Value> {
    Ok(
        json!({"header":hex::encode(packet.header.encode()),"transactions":packet.transactions.iter().map(hex::encode).collect::<Vec<_>>(),
        "proof":hex::encode(&packet.proof),"id":hex::encode(packet.id()?),"encoded_sha256":sha(&packet.encode().diag()?)}),
    )
}
fn same_relation(packet: &Packet) -> Result<()> {
    let challenge = packet.header.challenge();
    let p = pon_work::verify(
        challenge,
        packet.header.work_task,
        packet.header.target,
        &packet.proof,
    )
    .diag()?;
    // Different scalar arithmetic, shared verify_with_kernel/parser/flow; not a third independent implementation.
    let r = pon_work::verify_reference(
        challenge,
        packet.header.work_task,
        packet.header.target,
        &packet.proof,
    )
    .diag()?;
    require(p.ticket() == r.ticket(), "SCALAR_REFERENCE_TICKET")
}
fn birth() -> Result<String> {
    let stat = fs::read_to_string("/proc/self/stat")?;
    Ok(stat
        .rsplit_once(')')
        .ok_or("STAT_FORMAT")?
        .1
        .split_whitespace()
        .nth(19)
        .ok_or("STAT_BIRTH")?
        .to_owned())
}
fn owner_limits() -> Result<Value> {
    use rustix::process::{getrlimit, Resource};
    let a = getrlimit(Resource::As);
    let f = getrlimit(Resource::Fsize);
    require(
        a.current == Some(512 * MIB) && a.maximum == Some(512 * MIB),
        "ACTOR_AS_REQUIRED_BEFORE_SETUP",
    )?;
    require(
        f.current == Some(8 * MIB) && f.maximum == Some(8 * MIB),
        "ACTOR_FSIZE_REQUIRED_BEFORE_SETUP",
    )?;
    Ok(
        json!({"as_soft":a.current,"as_hard":a.maximum,"fsize_soft":f.current,"fsize_hard":f.maximum}),
    )
}
struct Context {
    node: Node,
    settings: Settings,
    template: Packet,
    producer: registry::Producer,
    registry: registry::Registry,
    parent: Hash,
    parent_state_sha: String,
    seen: BTreeSet<Hash>,
    admitted: Vec<(Hash, String, String)>,
}
fn initialize(path: &Path, sink: &mut Sink) -> Result<Context> {
    let limits = owner_limits()?;
    let settings = Settings::development_with_profiles(
        Some(1_750_000_000),
        "native-public-evaluation-dev-v1",
        TASK_PROFILE,
    )?;
    let boot = settings.bootstrap_lifecycle_task()?;
    let base = settings.bootstrap_task_material()?;
    let raw = vec![0; pon_work::CELLS * 4];
    let (a, b) = derive_matrices(&raw, &raw).diag()?;
    let zero = (raw.clone(), raw, a, b);
    require(
        zero.2.iter().chain(&zero.3).all(|v| *v == 0),
        "FIXED_POLICY_REFUSED",
    )?;
    let setup_started = Instant::now();
    let setup_cpu = cpu();
    let mut registry = registry::Registry::default();
    // Frozen before any Header/challenge/search result is visible; no outcome-dependent selection.
    let producer = registry
        .prepare(registry::Arm::ZeroPaired, &zero.2, &zero.3)
        .diag()?
        .ok_or("FIXED_ARM_UNSUPPORTED")?;
    let selected_setup = json!({"attempts":registry.setup_attempts,"supported":registry.supported_setups,
        "cpu_ns":setup_cpu.zip(cpu()).and_then(|(a,b)|b.checked_sub(a)),"wall_ns":setup_started.elapsed().as_nanos()});
    let mut lease = boot.lease.clone();
    lease.slot = 1;
    lease.generation = 2;
    lease.requester = development_public(2)?;
    lease.purpose = TaskPurpose::Maintenance;
    lease.not_before = 1;
    lease.expires = 4;
    lease.available_until = 104;
    lease.demand_id = lease.derived_demand_id();
    let signed = statement(&settings, &lease, &zero)?;
    let permit = admission(&signed, &lease, &zero, 2)?;
    fs::create_dir(path)?;
    let mut node = Node::open_with_authenticated_state(path, settings.clone(), 1)?;
    let before = node.read_active()?;
    let denied = make(&node, settings.genesis(), vec![], &permit, &zero)
        .err()
        .ok_or("UNREGISTERED_TASK_ACCEPTED")?
        .to_string();
    require(
        denied == "TASK" && node.read_active()? == before,
        "UNREGISTERED_TASK_NEGATIVE",
    )?;
    let registration = make(
        &node,
        settings.genesis(),
        vec![
            transaction(&settings, 2, 18, lease.encode().diag()?)?,
            transaction(&settings, 0, 21, signed.encode().diag()?)?,
        ],
        &admission(&boot.signed, &boot.lease, &base, 1)?,
        &base,
    )?;
    same_relation(&registration)?;
    let parent = node.admit(&registration, CLOCK)?;
    node.activate(parent)?;
    let template = make(&node, parent, vec![], &permit, &zero)?;
    same_relation(&template)?;
    require(
        template.header.parent == parent
            && template.header.height == 2
            && template.header.target == node.expected_target(parent)?,
        "TEMPLATE_CONTEXT",
    )?;
    require(
        template.header.work_task == pon_work::task_id(&zero.2, &zero.3).diag()?,
        "MATERIAL_TASK",
    )?;
    let mut changed = zero.clone();
    changed.0[0] = 1;
    let changed_error = make(&node, parent, vec![], &permit, &changed)
        .err()
        .ok_or("CHANGED_MATERIAL_ACCEPTED")?
        .to_string();
    require(changed_error == "TASK_MATERIAL", "MATERIAL_NEGATIVE")?;
    let parent_state_sha = sha(&serde_json::to_vec(&node.state_at(parent)?)?);
    sink.emit(json!({"kind":"initialized","owner_pid":std::process::id(),"owner_birth":birth()?,"limits":limits,
        "policy":POLICY,"policy_sha256":sha(POLICY.as_bytes()),"arm":registry::Arm::ZeroPaired.name(),
        "registry":registry::ALL.iter().map(|a|a.name()).collect::<Vec<_>>(),"selected_setup":selected_setup,
        "material":{"model":hex::encode(&zero.0),"input":hex::encode(&zero.1),"task":hex::encode(template.header.work_task)},
        "demand_lease":hex::encode(lease.encode().diag()?),"signed_statement":hex::encode(signed.encode().diag()?),
        "registration":packet_value(&registration)?,"template":packet_value(&template)?,"parent":hex::encode(parent),
        "parent_state_sha256":parent_state_sha,"unregistered_error":denied,"changed_material_error":changed_error,
        "source_authority":"disclosed-controlled-development-keys-not-economic-demand",
        "backend":"public-authenticated-state-component-not-qualified-three-fd",
        "production_template_make_calls":2,"production_generic_setup_count":"not-separately-instrumented-all-cost-in-initialize",
        "independent_parent_state_oracle":false,"whole_work_hardness_qualified":false,"whole_13_kernel_matrix_qualified":false}),false)?;
    Ok(Context {
        node,
        settings,
        template,
        producer,
        registry,
        parent,
        parent_state_sha,
        seen: BTreeSet::new(),
        admitted: Vec::new(),
    })
}
fn search(context: &mut Context, index: u64, sink: &mut Sink) -> Result<Value> {
    let start = Instant::now();
    let before = cpu();
    let first = BASE
        .checked_add(index.checked_mul(ATTEMPTS).ok_or("NONCE_OVERFLOW")?)
        .ok_or("NONCE_OVERFLOW")?;
    let mut stream = Sha256::new();
    stream.update(STREAM);
    let mut attempts = 0_u64;
    let mut found = None;
    for ordinal in 0..ATTEMPTS {
        require(start.elapsed().as_secs_f64() < 2.0, "SEARCH_LOCAL_DEADLINE")?;
        let mut header = context.template.header.clone();
        header.nonce = first.checked_add(ordinal).ok_or("NONCE_OVERFLOW")?;
        let challenge = header.challenge();
        require(context.seen.insert(challenge), "DUPLICATE_CHALLENGE")?;
        // The trial-start record is retained even when proof generation never returns.
        sink.emit(json!({"kind":"trial_started","search":index,"ordinal":ordinal,"header":hex::encode(header.encode()),
            "challenge":hex::encode(challenge)}),false)?;
        let proof = context.producer.prove(challenge).diag()?;
        require(proof.len() == pon_work::PROOF_BYTES, "FULL_PROOF_LENGTH")?;
        let header_bytes = header.encode();
        stream.update((header_bytes.len() as u64).to_le_bytes());
        stream.update(&header_bytes);
        stream.update((proof.len() as u64).to_le_bytes());
        stream.update(&proof);
        let ticket = hash(b"ticket", &[&challenge, &proof[proof.len() - 32..]]);
        let hit = ticket <= header.target;
        sink.emit(
            json!({"kind":"trial_completed","search":index,"ordinal":ordinal,"nonce":header.nonce,
            "ticket":hex::encode(ticket),"proof_sha256":sha(&proof),"target_hit":hit}),
            false,
        )?;
        attempts += 1;
        if hit {
            found = Some(Packet {
                header,
                transactions: context.template.transactions.clone(),
                proof,
            });
            break;
        }
    }
    let acquisition = json!({"cpu_ns":before.zip(cpu()).and_then(|(a,b)|b.checked_sub(a)),"wall_ns":start.elapsed().as_nanos()});
    let packet = found.ok_or("NONCE_BUDGET_EXHAUSTED")?;
    same_relation(&packet)?;
    let id = context.node.admit(&packet, CLOCK)?;
    require(id == packet.id()?, "ADMISSION_ID")?;
    require(
        sha(&serde_json::to_vec(
            &context.node.state_at(context.parent)?,
        )?) == context.parent_state_sha,
        "PARENT_STATE_CHANGED",
    )?;
    let encoded = sha(&packet.encode().diag()?);
    let state = sha(&serde_json::to_vec(&context.node.state_at(id)?)?);
    context.admitted.push((id, encoded.clone(), state.clone()));
    Ok(
        json!({"search":index,"first":first,"count_limit":ATTEMPTS,"attempts":attempts,"stream_sha256":hex::encode(stream.finalize()),
        "packet":packet_value(&packet)?,"admission_id":hex::encode(id),"state_sha256":state,
        "producer_acquisition":acquisition,"setup_attempts":context.registry.setup_attempts,
        "supported_setups":context.registry.supported_setups,"ordinary_node_admission":true,
        "rust_scalar_reference_uses_shared_verifier_flow":true,"independent_python_relation":"not-yet-run"}),
    )
}
fn seal(mut context: Context, path: &Path) -> Result<Value> {
    require(
        context.admitted.len() == SEARCHES as usize
            && context.registry.setup_attempts == 1
            && context.registry.supported_setups == 1,
        "COHORT_INCOMPLETE",
    )?;
    let before = context.node.read_active()?;
    require(
        before.0 == context.parent && before.1 == 1,
        "SIBLING_SCOPE_ACTIVE_PARENT",
    )?;
    drop(context.node);
    context.node = Node::open_with_authenticated_state(path, context.settings.clone(), 1)?;
    require(context.node.read_active()? == before, "COLD_ACTIVE_STATE")?;
    let mut cold = Vec::new();
    for (id, encoded, state) in &context.admitted {
        require(
            sha(&context.node.packet(*id)?.encode().diag()?) == *encoded,
            "COLD_PACKET",
        )?;
        require(
            sha(&serde_json::to_vec(&context.node.state_at(*id)?)?) == *state,
            "COLD_STATE",
        )?;
        cold.push(json!({"id":hex::encode(id),"encoded_sha256":encoded,"state_sha256":state}));
    }
    Ok(
        json!({"native_component_completed":true,"searches":SEARCHES,"same_selected_setup_attempts":context.registry.setup_attempts,
        "scope":"64-same-parent-siblings-not-64-successive-parents","cold":cold,
        "independent_python_relation":"not-yet-run","ordinary_public_service_paid_envelope":false,
        "renewal_revocation_expiry_controls_in_this_profile":false,"whole_13_kernel_matrix_qualified":false,
        "native_three_fd_qualified":false,"hardware_fairness_qualified":false,"lowest_known_cost_audit_complete":false,
        "whole_work_hardness_qualified":false,"full4097_qualified":false,"merge_ready":false}),
    )
}
fn run(sink: &mut Sink) -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    require(
        args.len() == 4 && args[0] == "--profile" && args[1] == PROFILE && args[2] == "--directory",
        "EXPLICIT_PROFILE_REQUIRED",
    )?;
    let path = PathBuf::from(&args[3]);
    let stdin = io::stdin();
    let mut input = stdin.lock();
    request(&mut input, 0, "initialize")?;
    let started = Instant::now();
    let before = cpu();
    let mut context = initialize(&path, sink)?;
    response(
        sink,
        0,
        "initialize",
        started,
        before,
        json!({"initialized":true,"owner_pid":std::process::id(),"owner_birth":birth()?}),
    )?;
    for index in 0..SEARCHES {
        request(&mut input, index + 1, "search")?;
        let started = Instant::now();
        let before = cpu();
        let data = search(&mut context, index, sink)?;
        response(sink, index + 1, "search", started, before, data)?;
    }
    request(&mut input, SEARCHES + 1, "seal")?;
    let started = Instant::now();
    let before = cpu();
    let data = seal(context, &path)?;
    response(sink, SEARCHES + 1, "seal", started, before, data)?;
    Ok(())
}
fn main() {
    let mut sink = Sink {
        bytes: 0,
        sequence: 0,
    };
    if let Err(error) = run(&mut sink) {
        let _ = sink.emit(
            json!({"kind":"fatal","error":error.to_string(),"native_component_completed":false,
            "whole_work_hardness_qualified":false,"merge_ready":false}),
            true,
        );
        std::process::exit(1);
    }
}
