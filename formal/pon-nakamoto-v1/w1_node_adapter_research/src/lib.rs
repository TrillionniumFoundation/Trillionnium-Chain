//! Explicit research adapter: a real complete P3 check precedes the real Node.
//! The native Node still replays W1 and retains its original state authority.
//! This is a PNH1 development adapter, not PGH2 support or production activation.
#![forbid(unsafe_code)]

pub mod proof_start_owner;

use proof_start_owner::{ProofStartRecord, ProofStartReservation};

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use bincode::Options;
use p3_uni_stark::{setup_preprocessed, verify_with_preprocessed};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use trnm_pon_node::{Node, Packet};
use w1_full_public_stark_research::arith_carry_air::Dot8PackedCarryAir;
use w1_full_public_stark_research::proof_config::{
    Dft, PACKED_CARRY_COMPONENT, SCHEDULE_SHA_COMPONENT, W1Proof, config_with_dft,
};
use w1_full_public_stark_research::proof_wire::{Component, limits, scan_proof};
use w1_full_public_stark_research::public::{Expected, PUBLIC_BYTES, PublicStatement};
use w1_full_public_stark_research::sha_plan::HEADER_BYTES;
use w1_full_public_stark_research::sha_schedule_air::ScheduledShaAir;

pub const PROFILE: &str = "w1-pnh1-native-node-scheduled-p3-research-v1";
pub const MAX_PACKET_BYTES: usize = 1_048_576;
pub const MAX_OPERATIONS: usize = 16;
pub type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperatorPlan {
    pub profile: String,
    pub network: String,
    pub parameters: String,
    pub genesis: String,
    /// Chosen by the trusted operation planner, never taken from the certificate.
    pub expected_header: String,
    /// Actual caller-owned artifact commitments, independently provided.
    pub expected_artifacts: String,
}

impl OperatorPlan {
    pub fn expected(&self) -> Result<Expected> {
        require(self.profile == PROFILE, "operator profile")?;
        for word in [&self.network, &self.parameters, &self.genesis] {
            require(canonical_hex(word, 32), "operator context hash")?;
        }
        require(
            canonical_hex(&self.expected_header, HEADER_BYTES),
            "operator header",
        )?;
        require(
            canonical_hex(&self.expected_artifacts, 64),
            "operator artifacts",
        )?;
        Expected::from_bytes(
            &hex::decode(&self.expected_header).map_err(err)?,
            &hex::decode(&self.expected_artifacts).map_err(err)?,
        )
        .map_err(err)
    }
}

fn canonical_hex(value: &str, bytes: usize) -> bool {
    value.len() == 2 * bytes
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn err(value: impl std::fmt::Display) -> String {
    value.to_string()
}
fn require(ok: bool, message: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(message.into()) }
}
pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn read_bounded(path: &Path, maximum: usize, exact: Option<usize>) -> Result<Vec<u8>> {
    require(
        fs::symlink_metadata(path)
            .map_err(err)?
            .file_type()
            .is_file(),
        "regular file required",
    )?;
    let file = File::open(path).map_err(err)?;
    let length = file.metadata().map_err(err)?.len();
    require(
        length <= maximum as u64 && exact.is_none_or(|n| length == n as u64),
        "file byte budget",
    )?;
    let mut bytes = Vec::with_capacity(length as usize);
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(err)?;
    require(
        bytes.len() <= maximum && exact.is_none_or(|n| bytes.len() == n),
        "changed file byte budget",
    )?;
    Ok(bytes)
}

pub fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(err)?;
    file.write_all(bytes).map_err(err)?;
    file.sync_all().map_err(err)
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path).and_then(|f| f.sync_all()).map_err(err)
}

/// Owned immutable bytes; the verifier cannot receive a proof-supplied key.
pub struct PreparedBundle {
    plan: OperatorPlan,
    packet: Packet,
    packet_bytes: Vec<u8>,
    public: Vec<u8>,
    sha: Vec<u8>,
    arithmetic: Vec<u8>,
    operation: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredBinding {
    schema: String,
    profile: String,
    operation: String,
    plan_sha256: String,
    packet_sha256: String,
    public_sha256: String,
    sha_proof_sha256: String,
    arithmetic_proof_sha256: String,
    production_activation: bool,
}

impl PreparedBundle {
    pub fn new(
        plan: OperatorPlan,
        packet_bytes: Vec<u8>,
        public: Vec<u8>,
        sha: Vec<u8>,
        arithmetic: Vec<u8>,
    ) -> Result<Self> {
        require(packet_bytes.len() <= MAX_PACKET_BYTES, "packet byte budget")?;
        require(public.len() == PUBLIC_BYTES, "public byte budget")?;
        // Both frames precede either allocating proof decode or expensive setup.
        scan_proof(&sha, Component::ScheduledSha).map_err(err)?;
        scan_proof(&arithmetic, Component::PackedCarry).map_err(err)?;
        let expected = plan.expected()?;
        let packet = Packet::decode(&packet_bytes).map_err(err)?;
        require(
            packet.encode().map_err(err)? == packet_bytes,
            "noncanonical packet",
        )?;
        require(
            packet.header.encode() == expected.header,
            "packet expected header",
        )?;
        require(
            hex::encode(packet.header.network) == plan.network
                && hex::encode(packet.header.parameters) == plan.parameters,
            "packet context",
        )?;
        let statement = PublicStatement::decode(&public).map_err(err)?;
        let mut raw = packet.header.encode();
        raw.extend_from_slice(&packet.proof);
        require(raw == statement.raw, "packet/statement relation binding")?;
        let mut hasher = Sha256::new();
        hasher.update(b"trnm-w1-node-adapter-operation-v1\0");
        for part in [
            &serde_json::to_vec(&plan).map_err(err)?[..],
            &packet_bytes,
            &public,
            &sha,
            &arithmetic,
        ] {
            hasher.update((part.len() as u64).to_le_bytes());
            hasher.update(part);
        }
        let operation = hex::encode(hasher.finalize());
        Ok(Self {
            plan,
            packet,
            packet_bytes,
            public,
            sha,
            arithmetic,
            operation,
        })
    }

    pub fn operation(&self) -> &str {
        &self.operation
    }
    pub fn packet(&self) -> &Packet {
        &self.packet
    }
    pub fn total_bytes(&self) -> usize {
        self.packet_bytes.len() + self.public.len() + self.sha.len() + self.arithmetic.len()
    }

    fn binding(&self) -> Result<StoredBinding> {
        Ok(StoredBinding {
            schema: "trnm-w1-node-adapter-stored-bundle-v1".into(),
            profile: PROFILE.into(),
            operation: self.operation.clone(),
            plan_sha256: digest(&serde_json::to_vec(&self.plan).map_err(err)?),
            packet_sha256: digest(&self.packet_bytes),
            public_sha256: digest(&self.public),
            sha_proof_sha256: digest(&self.sha),
            arithmetic_proof_sha256: digest(&self.arithmetic),
            production_activation: false,
        })
    }

    /// New isolated archive, never an existing Node database or authoritative receipt.
    /// At most 16 operation directories; caller owns the parent directory exclusively.
    pub fn persist(&self, archive: &Path) -> Result<PathBuf> {
        fs::create_dir_all(archive).map_err(err)?;
        require(
            fs::symlink_metadata(archive)
                .map_err(err)?
                .file_type()
                .is_dir(),
            "archive directory",
        )?;
        let directory = archive.join(&self.operation);
        require(
            !directory.exists(),
            "operation already persisted; use explicit reload",
        )?;
        let mut count = 0;
        for entry in fs::read_dir(archive).map_err(err)?.take(MAX_OPERATIONS + 1) {
            entry.map_err(err)?;
            count += 1;
        }
        require(count < MAX_OPERATIONS, "archive operation budget")?;
        fs::create_dir(&directory).map_err(err)?;
        for (name, bytes) in [
            ("packet.bin", &self.packet_bytes),
            ("statement.bin", &self.public),
            ("sha.proof.bin", &self.sha),
            ("arith.proof.bin", &self.arithmetic),
        ] {
            write_new(&directory.join(name), bytes)?;
        }
        write_new(
            &directory.join("binding.json"),
            &serde_json::to_vec(&self.binding()?).map_err(err)?,
        )?;
        // This marker is last. A crash before it leaves an incomplete archive,
        // which reload refuses without inventing a proof or admission success.
        write_new(&directory.join("complete-v1"), self.operation.as_bytes())?;
        sync_directory(&directory)?;
        sync_directory(archive)?;
        Ok(directory)
    }

    /// The trusted plan is supplied independently again. Stored claims never select it.
    pub fn reload(directory: &Path, plan: OperatorPlan) -> Result<Self> {
        require(
            fs::symlink_metadata(directory)
                .map_err(err)?
                .file_type()
                .is_dir(),
            "bundle directory",
        )?;
        let marker = read_bounded(&directory.join("complete-v1"), 64, Some(64))?;
        let binding: StoredBinding =
            serde_json::from_slice(&read_bounded(&directory.join("binding.json"), 4096, None)?)
                .map_err(err)?;
        let bundle = Self::new(
            plan,
            read_bounded(&directory.join("packet.bin"), MAX_PACKET_BYTES, None)?,
            read_bounded(
                &directory.join("statement.bin"),
                PUBLIC_BYTES,
                Some(PUBLIC_BYTES),
            )?,
            read_bounded(
                &directory.join("sha.proof.bin"),
                limits(Component::ScheduledSha).maximum_bytes,
                None,
            )?,
            read_bounded(
                &directory.join("arith.proof.bin"),
                limits(Component::PackedCarry).maximum_bytes,
                None,
            )?,
        )?;
        require(
            marker == bundle.operation.as_bytes()
                && directory.file_name().and_then(|v| v.to_str()) == Some(&bundle.operation),
            "archive operation identity",
        )?;
        require(
            serde_json::to_vec(&binding).map_err(err)?
                == serde_json::to_vec(&bundle.binding()?).map_err(err)?,
            "archive binding",
        )?;
        Ok(bundle)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    BeforeProof,
    BeforeShaSetup,
    BeforeShaVerify,
    BeforeArithmeticSetup,
    BeforeArithmeticVerify,
    ProofVerified,
    BeforeNodeAdmission,
    NodeCommitted,
    BeforeActivation,
}

#[derive(Serialize)]
pub struct Phase {
    pub stage: String,
    pub wall_seconds: f64,
}

/// Private non-serializable capability. A caller can only obtain it by both PCS checks.
pub struct VerifiedBundle<'a> {
    bundle: &'a PreparedBundle,
    phases: Vec<Phase>,
    proof_start: Option<ProofStartRecord>,
}

fn decode(bytes: &[u8], component: Component) -> Result<W1Proof> {
    let bound = limits(component).maximum_bytes;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit((bound - 8) as u64)
        .reject_trailing_bytes()
        .deserialize(&bytes[8..])
        .map_err(err)
}

/// Unmetered research-library entry point. No lifetime budget is asserted.
/// No Node reference/lock is needed; callers can verify outside the Node owner.
/// The exercise/reopen CLI instead requires verify_reserved_bundle.
pub fn verify_bundle<'a>(
    bundle: &'a PreparedBundle,
    mut progress: impl FnMut(Stage) -> Result<()>,
) -> Result<VerifiedBundle<'a>> {
    progress(Stage::BeforeProof)?;
    let mut phases = Vec::new();
    let start = Instant::now();
    // Own immutability plus repeated fixed scans binds admission to exact decode bytes.
    scan_proof(&bundle.sha, Component::ScheduledSha).map_err(err)?;
    scan_proof(&bundle.arithmetic, Component::PackedCarry).map_err(err)?;
    let sha_proof = decode(&bundle.sha, Component::ScheduledSha)?;
    let arithmetic_proof = decode(&bundle.arithmetic, Component::PackedCarry)?;
    let statement = PublicStatement::decode(&bundle.public).map_err(err)?;
    phases.push(Phase {
        stage: "fixed_shape_scans_and_decode".into(),
        wall_seconds: start.elapsed().as_secs_f64(),
    });
    let start = Instant::now();
    let (sha_plan, original_arithmetic) = statement.plans(&bundle.plan.expected()?)?;
    let arithmetic = Dot8PackedCarryAir::new(original_arithmetic.rows().to_vec()).map_err(err)?;
    drop(original_arithmetic);
    let sha = ScheduledShaAir::public_only(&sha_plan);
    phases.push(Phase {
        stage: "canonical_plans_and_public_only_air".into(),
        wall_seconds: start.elapsed().as_secs_f64(),
    });
    progress(Stage::BeforeShaSetup)?;
    let start = Instant::now();
    // Share only transform-shape twiddle tables within this request. Both
    // component transcripts and complete public preprocessing stay independent.
    let dft = Dft::default();
    let sha_config = config_with_dft(SCHEDULE_SHA_COMPONENT, dft.clone());
    let (pp, vk) = setup_preprocessed(&sha_config, &sha, 13)
        .map_err(|e| format!("{e:?}"))?
        .ok_or("missing SHA preprocessing")?;
    drop(pp);
    phases.push(Phase {
        stage: "sha_independent_preprocessing".into(),
        wall_seconds: start.elapsed().as_secs_f64(),
    });
    progress(Stage::BeforeShaVerify)?;
    let start = Instant::now();
    verify_with_preprocessed(&sha_config, &sha, &sha_proof, &[], Some(&vk))
        .map_err(|e| format!("SHA_PROOF:{e:?}"))?;
    phases.push(Phase {
        stage: "sha_proof_verification".into(),
        wall_seconds: start.elapsed().as_secs_f64(),
    });
    progress(Stage::BeforeArithmeticSetup)?;
    let start = Instant::now();
    let arithmetic_config = config_with_dft(PACKED_CARRY_COMPONENT, dft);
    let (pp, vk) = setup_preprocessed(&arithmetic_config, &arithmetic, 14)
        .map_err(|e| format!("{e:?}"))?
        .ok_or("missing arithmetic preprocessing")?;
    drop(pp);
    phases.push(Phase {
        stage: "arithmetic_independent_preprocessing".into(),
        wall_seconds: start.elapsed().as_secs_f64(),
    });
    progress(Stage::BeforeArithmeticVerify)?;
    let start = Instant::now();
    verify_with_preprocessed(
        &arithmetic_config,
        &arithmetic,
        &arithmetic_proof,
        &[],
        Some(&vk),
    )
    .map_err(|e| format!("ARITHMETIC_PROOF:{e:?}"))?;
    phases.push(Phase {
        stage: "arithmetic_proof_verification".into(),
        wall_seconds: start.elapsed().as_secs_f64(),
    });
    progress(Stage::ProofVerified)?;
    Ok(VerifiedBundle {
        bundle,
        phases,
        proof_start: None,
    })
}

/// Consume one previously synchronized start. The record is diagnostic; the
/// non-deserializable reservation, not a caller-supplied receipt, authorizes this
/// metered call. A mismatch, cancellation, or verifier failure never refunds it.
pub fn verify_reserved_bundle<'a>(
    bundle: &'a PreparedBundle,
    reservation: ProofStartReservation,
    progress: impl FnMut(Stage) -> Result<()>,
) -> Result<VerifiedBundle<'a>> {
    let record = reservation.bind(&bundle.plan)?;
    let mut verified = verify_bundle(bundle, progress)?;
    verified.proof_start = Some(record);
    Ok(verified)
}

pub fn check_current_node(node: &Node, bundle: &PreparedBundle) -> Result<()> {
    check_current_packet(node, &bundle.plan, &bundle.packet)
}

/// Shared live-context checks for the research adapter and native comparator.
/// This check creates no proof capability and does not perform native admission.
pub fn check_current_packet(node: &Node, plan: &OperatorPlan, packet: &Packet) -> Result<()> {
    let settings = node.settings();
    require(
        hex::encode(settings.network()) == plan.network
            && hex::encode(settings.parameters()) == plan.parameters
            && hex::encode(settings.genesis()) == plan.genesis,
        "current Node context",
    )?;
    require(
        node.parent_height(packet.header.parent)
            .map_err(err)?
            .checked_add(1)
            == Some(packet.header.height),
        "current Node parent height",
    )?;
    require(
        node.expected_target(packet.header.parent).map_err(err)? == packet.header.target,
        "current Node target",
    )
}

/// Consumes a real proof capability, then uses the unchanged real Node admission.
/// Fresh admission retains native W1 checks; exact duplicates reuse Node's
/// original admitted state. The adapter never substitutes its proof for either.
pub fn admit(
    node: &mut Node,
    verified: VerifiedBundle<'_>,
    observed_now: u64,
    activate: bool,
    mut progress: impl FnMut(Stage) -> Result<()>,
) -> Result<Value> {
    let mut native_phases = Vec::new();
    let start = Instant::now();
    progress(Stage::BeforeNodeAdmission)?;
    check_current_node(node, verified.bundle)?;
    let before = node.active().map_err(err)?;
    native_phases.push(Phase {
        stage: "current_context_and_before_observation".into(),
        wall_seconds: start.elapsed().as_secs_f64(),
    });
    let start = Instant::now();
    let id = node
        .admit(&verified.bundle.packet, observed_now)
        .map_err(|e| format!("NODE_ADMISSION:{e}"))?;
    let native_admission_seconds = start.elapsed().as_secs_f64();
    native_phases.push(Phase {
        stage: "native_admission".into(),
        wall_seconds: native_admission_seconds,
    });
    // From here on, the durable native fact may not be rewritten as cancellation.
    let start = Instant::now();
    let late_cancellation = progress(Stage::NodeCommitted).err();
    native_phases.push(Phase {
        stage: "postcommit_checkpoint".into(),
        wall_seconds: start.elapsed().as_secs_f64(),
    });
    let mut activation_error = None;
    if activate && late_cancellation.is_none() {
        let start = Instant::now();
        match progress(Stage::BeforeActivation).and_then(|_| node.activate(id).map_err(err)) {
            Ok(_) => (),
            Err(e) => activation_error = Some(e),
        }
        native_phases.push(Phase {
            stage: "activation_checkpoint_and_call".into(),
            wall_seconds: start.elapsed().as_secs_f64(),
        });
    }
    let start = Instant::now();
    let observation = node
        .exact_packet_observation(&verified.bundle.packet)
        .map_err(err);
    native_phases.push(Phase {
        stage: "native_packet_observation".into(),
        wall_seconds: start.elapsed().as_secs_f64(),
    });
    Ok(
        json!({"schema":"trnm-w1-node-adapter-admission-v3","profile":PROFILE,
        "operation":verified.bundle.operation,"block":hex::encode(id),"both_real_proofs_verified":true,
        "native_admission_path_invoked":true,
        "native_work_policy":"fresh packets execute native W1; exact duplicates reuse original admitted state",
        "native_admitted":true,"native_admission_seconds":native_admission_seconds,
        "activation_requested":activate,"late_cancellation":late_cancellation,"activation_error":activation_error,
        "active_before":hex::encode(before.0),"generation_before":before.1,
        "native_observation":observation.as_ref().ok(),"native_observation_error":observation.as_ref().err(),
        "proof_phases":verified.phases,"proof_start":verified.proof_start,
        "native_detail_metrics":{"schema":"trnm-w1-native-admission-metrics-v1",
            "phases_are_disjoint":true,"phases":native_phases,
            "scope":"inside adapter admit; excludes Node open/recovery and enclosing CLI phases; do not add to enclosing phase times"},
        "qualification":"HOLD_NO_GO","production_activation":false}),
    )
}

/// Fresh real proof verification and current durable observation, without admission.
/// Historical receipt/activation labels never select the current active chain.
pub fn observe(
    node: &Node,
    bundle: &PreparedBundle,
    progress: impl FnMut(Stage) -> Result<()>,
) -> Result<Value> {
    observe_verified(node, verify_bundle(bundle, progress)?)
}

/// Observe after a prior proof check. The CLI obtains this capability before
/// opening Node, because the original Node open performs native recovery.
/// Native recovery can activate an already committed packet; no historical
/// adapter label substitutes for the resulting current observation.
pub fn observe_verified(node: &Node, verified: VerifiedBundle<'_>) -> Result<Value> {
    let bundle = verified.bundle;
    check_current_node(node, bundle)?;
    Ok(
        json!({"schema":"trnm-w1-node-adapter-reopen-v2","operation":bundle.operation,
        "both_real_proofs_reverified":true,"admission_performed":false,
        "native_observation":node.exact_packet_observation(&bundle.packet).map_err(err)?,
        "proof_phases":verified.phases,"proof_start":verified.proof_start,"qualification":"HOLD_NO_GO","production_activation":false}),
    )
}

/// Historical in-memory research account, not used by the current CLI.
/// A finite owner-side work-start account. It is not a kernel CPU or wall-time bound.
/// No caller-provided success/estimate can replenish it; failed starts remain spent.
pub struct WorkStartBudget {
    maximum: usize,
    spent: usize,
}
impl WorkStartBudget {
    pub fn new(maximum: usize) -> Result<Self> {
        require(
            (1..=MAX_OPERATIONS).contains(&maximum),
            "work-start budget range",
        )?;
        Ok(Self { maximum, spent: 0 })
    }
    pub fn reserve(&mut self) -> Result<()> {
        require(self.spent < self.maximum, "work-start budget exhausted")?;
        self.spent += 1;
        Ok(())
    }
    pub fn spent(&self) -> usize {
        self.spent
    }
}
