//! Bounded observations of the actual V3 root cryptography APIs.
//!
//! `cargo run --release --locked -p trnm-crypto-primitives --features pq-native-openssl --example pq_root_v3_cost_observation -- --rounds 8`
//!
//! Each ABBA block compares a newly decoded roster plus full quorum verification
//! with a retained roster plus full quorum verification. Every invocation uses
//! the same public fixture, performs all four signature checks and reserves a
//! fresh four-attempt budget. A retained roster is never an authorization cache.
//! Warmups, setup, every raw timing, public fixture bytes and budget counters are
//! emitted as JSON lines. No private key or seed is emitted or persisted.
//!
//! The separate four-approval/six-possession observation shares one ten-attempt
//! budget. It exercises mathematical APIs with a synthetic complete statement;
//! it is not a root owner transition, history replay, Cell read or network cost.
//! No performance threshold, population tail or production qualification follows.

use anyhow::{bail, ensure, Context, Result};
use openssl::{
    asn1::Asn1Object,
    pkey::{Id, PKey, Private},
    pkey_ctx::PkeyCtx,
    sign::{Signer, Verifier},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha512};
use std::{
    env,
    hint::black_box,
    io::{self, Write},
    time::Instant,
};
use trnm_crypto_primitives::pq_root_v3::{
    approval_message_v3, possession_message_v3, DualFamilyRosterV3, KeyIdV3, RootPublicKeyV3,
    RootSignatureV3, RootSuiteV3, VerificationBudgetV3, ENCODED_ROSTER_BYTES_V3,
    MAX_STATEMENT_BYTES_V3,
};

const SCHEMA: &str = "trnm-pq-root-v3-cost-observation-v1";
const DEFAULT_ROUNDS: usize = 8;
const MAX_ROUNDS: usize = 64;
const STATEMENT_DOMAIN: &[u8] = b"TRNM/Observation/RootV3CostStatement/v1\0";

fn emit(value: Value) -> Result<()> {
    let mut output = io::stdout().lock();
    serde_json::to_writer(&mut output, &value)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}

fn elapsed_ns(start: Instant) -> Result<u64> {
    u64::try_from(start.elapsed().as_nanos()).context("monotonic duration overflow")
}

fn rounds_from_args() -> Result<Option<usize>> {
    let mut args = env::args().skip(1);
    let rounds = match args.next().as_deref() {
        None => DEFAULT_ROUNDS,
        Some("--help" | "-h") => {
            println!(
                "pq_root_v3_cost_observation [--rounds N], 1 <= N <= {MAX_ROUNDS}; default {DEFAULT_ROUNDS} ABBA blocks, two samples per arm per block"
            );
            return Ok(None);
        }
        Some("--rounds") => args
            .next()
            .context("--rounds requires an integer")?
            .parse::<usize>()?,
        Some(_) => bail!("expected --rounds N or --help"),
    };
    ensure!(
        args.next().is_none() && (1..=MAX_ROUNDS).contains(&rounds),
        "rounds must be in 1..=64, with no extra arguments"
    );
    Ok(Some(rounds))
}

struct PrivateFixture {
    roster: DualFamilyRosterV3,
    private: Vec<(KeyIdV3, PKey<Private>)>,
}

impl PrivateFixture {
    fn generate() -> Result<Self> {
        let mut public = Vec::with_capacity(6);
        let mut private = Vec::with_capacity(6);
        // Same exact standard OIDs and safe native API as pq_root_v3_native.
        for (suite, oid) in [
            (RootSuiteV3::MlDsa87, "2.16.840.1.101.3.4.3.19"),
            (RootSuiteV3::SlhDsaSha2_256s, "2.16.840.1.101.3.4.3.24"),
        ] {
            for _ in 0..3 {
                let object = Asn1Object::from_str(oid)?;
                let mut context = PkeyCtx::new_id(Id::from_raw(object.nid().as_raw()))?;
                context.keygen_init()?;
                let owned = context.keygen()?;
                let key = RootPublicKeyV3 {
                    suite,
                    spki: owned.public_key_to_der()?,
                };
                private.push((key.id()?, owned));
                public.push(key);
            }
        }
        Ok(Self {
            roster: DualFamilyRosterV3::from_keys(public)?,
            private,
        })
    }

    fn sign_and_check(&self, signer: KeyIdV3, message: &[u8]) -> Result<RootSignatureV3> {
        let key = &self
            .private
            .iter()
            .find(|(id, _)| *id == signer)
            .context("fixture signer is absent")?
            .1;
        let mut signing = Signer::new_without_digest(key)?;
        let signature = signing.sign_oneshot_to_vec(message)?;
        let mut independent = Verifier::new_without_digest(key)?;
        ensure!(
            independent.verify_oneshot(&signature, message)?,
            "fixture signature failed its native self-check"
        );
        Ok(RootSignatureV3 { signer, signature })
    }
}

struct Material {
    current: DualFamilyRosterV3,
    successor: DualFamilyRosterV3,
    current_wire: Vec<u8>,
    successor_wire: Vec<u8>,
    statement: Vec<u8>,
    message: Vec<u8>,
    approvals: Vec<RootSignatureV3>,
    possessions: Vec<RootSignatureV3>,
}

fn signature_bytes(signatures: &[RootSignatureV3]) -> usize {
    signatures.iter().map(|row| row.signature.len()).sum()
}

// This is the owner's reservation formula, not measured transferred bytes,
// allocator use, cryptographic risk or a count of actual hash operations.
fn reserved_bytes(message_bytes: usize, signatures: &[RootSignatureV3], copies: u64) -> u64 {
    (message_bytes as u64) * copies
        + ENCODED_ROSTER_BYTES_V3 as u64
        + signatures.len() as u64 * 64
        + signature_bytes(signatures) as u64
}

fn budget_record(budget: &VerificationBudgetV3) -> Value {
    json!({"reserved_verifications": budget.attempts(), "charged_input_bytes": budget.charged_bytes()})
}

fn public_roster(roster: &DualFamilyRosterV3, wire: &[u8]) -> Value {
    json!({
        "encoded_roster_bytes": wire.len(),
        "encoded_roster_hex": hex::encode(wire),
        "encoded_roster_sha512": hex::encode(Sha512::digest(wire)),
        "roster_commitment_hex": hex::encode(roster.commitment()),
        "spki_bytes_total": roster.keys().iter().map(|key| key.spki.len()).sum::<usize>(),
        "keys": roster.keys().iter().map(|key| json!({
            "suite": key.suite.name(),
            "raw_public_key_bytes": key.suite.public_key_bytes(),
            "spki_bytes": key.spki.len(),
            "raw_signature_bytes": key.suite.signature_bytes(),
        })).collect::<Vec<_>>()
    })
}

fn public_signatures(signatures: &[RootSignatureV3]) -> Value {
    json!(signatures
        .iter()
        .map(|row| json!({
            "signer_id_hex": hex::encode(row.signer),
            "raw_signature_bytes": row.signature.len(),
            "signature_hex": hex::encode(&row.signature),
        }))
        .collect::<Vec<_>>())
}

fn material() -> Result<Material> {
    let setup = Instant::now();
    let start = Instant::now();
    let current = PrivateFixture::generate()?;
    let current_keygen_ns = elapsed_ns(start)?;
    let start = Instant::now();
    let successor = PrivateFixture::generate()?;
    let successor_keygen_ns = elapsed_ns(start)?;
    let current_wire = current.roster.encode();
    let successor_wire = successor.roster.encode();
    ensure!(
        current_wire.len() == ENCODED_ROSTER_BYTES_V3
            && successor_wire.len() == ENCODED_ROSTER_BYTES_V3,
        "fixture roster encoding length"
    );

    // A clearly separate synthetic statement containing both complete public
    // rosters. It is not serialized RootActionV3 or an owner-authorized request.
    let mut statement = STATEMENT_DOMAIN.to_vec();
    for part in [&current_wire, &successor_wire] {
        statement.extend_from_slice(&(part.len() as u64).to_be_bytes());
        statement.extend_from_slice(part);
    }
    ensure!(
        statement.len() <= MAX_STATEMENT_BYTES_V3,
        "fixture statement bound"
    );
    let message = approval_message_v3(&statement)?;
    let ids = current.roster.key_ids();
    let start = Instant::now();
    let approvals = [ids[0], ids[1], ids[3], ids[4]]
        .into_iter()
        .map(|id| current.sign_and_check(id, &message))
        .collect::<Result<Vec<_>>>()?;
    let approval_sign_and_check_ns = elapsed_ns(start)?;
    let start = Instant::now();
    let possessions = successor
        .roster
        .key_ids()
        .into_iter()
        .map(|id| {
            let message = possession_message_v3(&statement, &successor.roster, id)?;
            successor.sign_and_check(id, &message)
        })
        .collect::<Result<Vec<_>>>()?;
    let possession_sign_and_check_ns = elapsed_ns(start)?;
    ensure!(
        signature_bytes(&approvals) == 68_838,
        "approval signature bytes"
    );
    ensure!(
        signature_bytes(&possessions) == 103_257,
        "possession signature bytes"
    );
    ensure!(
        signature_bytes(&approvals) + signature_bytes(&possessions) == 172_095,
        "combined raw signature bytes"
    );
    // Secret keys are discarded before either measured arm runs.
    drop(current.private);
    drop(successor.private);
    let material = Material {
        current: current.roster,
        successor: successor.roster,
        current_wire,
        successor_wire,
        statement,
        message,
        approvals,
        possessions,
    };
    let setup_ns = elapsed_ns(setup)?;
    let possession_messages = material
        .successor
        .key_ids()
        .into_iter()
        .map(|id| {
            let message = possession_message_v3(&material.statement, &material.successor, id)?;
            Ok(
                json!({"signer_id_hex": hex::encode(id), "message_bytes": message.len(),
                "message_sha512": hex::encode(Sha512::digest(&message))}),
            )
        })
        .collect::<Result<Vec<_>>>()?;
    emit(json!({
        "schema": SCHEMA, "kind": "public_fixture",
        "scope": "synthetic statement and ephemeral keys for local mathematical API observations",
        "current": public_roster(&material.current, &material.current_wire),
        "successor": public_roster(&material.successor, &material.successor_wire),
        "statement_bytes": material.statement.len(), "statement_hex": hex::encode(&material.statement),
        "approval_message_bytes": material.message.len(), "approval_message_hex": hex::encode(&material.message),
        "approval_message_sha512": hex::encode(Sha512::digest(&material.message)),
        "approvals": public_signatures(&material.approvals),
        "successor_possessions": public_signatures(&material.possessions),
        "successor_possession_messages": possession_messages,
        "signature_only_bytes": {"four_approvals": signature_bytes(&material.approvals),
            "six_successor_possessions": signature_bytes(&material.possessions),
            "combined": signature_bytes(&material.approvals) + signature_bytes(&material.possessions)},
        "actual_owner_transition_frame_bytes": null,
        "setup_wall_ns": setup_ns,
        "current_key_generation_and_roster_wall_ns": current_keygen_ns,
        "successor_key_generation_and_roster_wall_ns": successor_keygen_ns,
        "approval_sign_and_native_self_check_wall_ns": approval_sign_and_check_ns,
        "successor_sign_and_native_self_check_wall_ns": possession_sign_and_check_ns,
        "setup_native_signatures": 10, "setup_native_self_checks": 10,
        "private_keys_discarded_before_samples": true,
        "private_key_material_emitted": false,
    }))?;
    Ok(material)
}

#[derive(Clone, Copy)]
enum Arm {
    Fresh,
    Retained,
}

impl Arm {
    fn name(self) -> &'static str {
        match self {
            Self::Fresh => "A_fresh_roster_decode_and_full_quorum",
            Self::Retained => "B_retained_roster_full_quorum",
        }
    }
}

struct Timing {
    operation_ns: u64,
    verification_ns: u64,
}

fn quorum_sample(
    material: &Material,
    arm: Arm,
    phase: &str,
    block: usize,
    slot: usize,
) -> Result<Timing> {
    let mut budget = VerificationBudgetV3::new(4)?;
    let operation = Instant::now();
    let prepare = Instant::now();
    let decoded = match arm {
        Arm::Fresh => Some(DualFamilyRosterV3::decode(black_box(
            &material.current_wire,
        ))),
        Arm::Retained => None,
    };
    let decode_ns = match arm {
        Arm::Fresh => Some(elapsed_ns(prepare)?),
        Arm::Retained => None,
    };
    let roster = match decoded.as_ref() {
        Some(Ok(roster)) => Ok(roster),
        Some(Err(error)) => Err(error.to_string()),
        None => Ok(&material.current),
    };
    let started_verification = roster.is_ok();
    let start = Instant::now();
    let result = roster.and_then(|roster| {
        roster
            .verify_quorum(
                black_box(&material.message),
                black_box(&material.approvals),
                &mut budget,
            )
            .map_err(|error| error.to_string())
    });
    let verification_ns = elapsed_ns(start)?;
    let operation_ns = elapsed_ns(operation)?;
    let expected = material
        .approvals
        .iter()
        .map(|row| row.signer)
        .collect::<Vec<_>>();
    let identities_match = result.as_ref().is_ok_and(|ids| ids == &expected);
    let expected_charge = reserved_bytes(material.message.len(), &material.approvals, 1);
    let budget_matches = budget.attempts() == 4 && budget.charged_bytes() == expected_charge;
    emit(json!({
        "schema": SCHEMA, "kind": "quorum_sample", "phase": phase,
        "abba_block": block, "slot_in_block": slot, "arm": arm.name(),
        "roster_decode_wall_ns": decode_ns, "verification_started": started_verification,
        "full_quorum_verification_wall_ns": if started_verification { Some(verification_ns) } else { None },
        "operation_wall_ns": operation_ns,
        "native_api_accepted": result.is_ok(), "exact_signer_ids_match": identities_match,
        "budget": budget_record(&budget), "expected_charged_input_bytes": expected_charge,
        "budget_counters_match": budget_matches, "error": result.as_ref().err(),
        "authorized_external_effect": false,
    }))?;
    ensure!(identities_match, "quorum sample failed: {result:?}");
    ensure!(
        budget_matches,
        "quorum sample changed its reserved budget counters"
    );
    Ok(Timing {
        operation_ns,
        verification_ns,
    })
}

fn combined_observation(material: &Material) -> Result<()> {
    let mut budget = VerificationBudgetV3::new(10)?;
    let start = Instant::now();
    let approved =
        material
            .current
            .verify_quorum(&material.message, &material.approvals, &mut budget);
    let approval_ns = elapsed_ns(start)?;
    let after_approval = budget_record(&budget);
    let expected_approval = reserved_bytes(material.message.len(), &material.approvals, 1);
    let approval_ids = material
        .approvals
        .iter()
        .map(|row| row.signer)
        .collect::<Vec<_>>();
    let approval_ok = approved.as_ref().is_ok_and(|ids| ids == &approval_ids)
        && budget.attempts() == 4
        && budget.charged_bytes() == expected_approval;
    emit(json!({
        "schema": SCHEMA, "kind": "combined_api_stage", "stage": "four_current_approvals",
        "shared_budget_maximum": 10, "wall_ns": approval_ns, "budget": after_approval,
        "exact_result_and_budget_match": approval_ok,
        "native_error": approved.as_ref().err().map(ToString::to_string),
    }))?;
    ensure!(
        approval_ok,
        "combined approval observation failed: {approved:?}"
    );

    let start = Instant::now();
    let possessed = material.successor.verify_possessions(
        &material.statement,
        &material.possessions,
        &mut budget,
    );
    let possession_ns = elapsed_ns(start)?;
    // The API conservatively reserves the complete statement plus 256 bytes
    // per possession, rather than only charging each exact framed message.
    let expected_total = expected_approval
        + reserved_bytes(material.statement.len() + 256, &material.possessions, 6);
    let possession_ok = possessed
        .as_ref()
        .is_ok_and(|ids| ids == &material.successor.key_ids())
        && budget.attempts() == 10
        && budget.charged_bytes() == expected_total;
    emit(json!({
        "schema": SCHEMA, "kind": "combined_api_stage", "stage": "six_successor_possessions",
        "shared_budget_maximum": 10, "wall_ns": possession_ns, "budget": budget_record(&budget),
        "expected_cumulative_charged_input_bytes": expected_total,
        "exact_result_and_budget_match": possession_ok,
        "native_error": possessed.as_ref().err().map(ToString::to_string),
        "current_roster_preverified_during_abba": true,
        "successor_roster_preverified_by_v3_api": false,
        "complete_transition_latency_measured": false,
    }))?;
    ensure!(
        possession_ok,
        "combined possession observation failed: {possessed:?}"
    );
    Ok(())
}

fn distribution(values: impl Iterator<Item = u64>) -> Value {
    let mut values = values.collect::<Vec<_>>();
    values.sort_unstable();
    let middle = values.len() / 2;
    let median = if values.len().is_multiple_of(2) {
        (values[middle - 1] as f64 + values[middle] as f64) / 2.0
    } else {
        values[middle] as f64
    };
    json!({"samples": values.len(), "minimum_ns": values[0], "median_ns": median,
        "maximum_ns": values[values.len() - 1]})
}

fn main() -> Result<()> {
    let Some(rounds) = rounds_from_args()? else {
        return Ok(());
    };
    emit(json!({
        "schema": SCHEMA, "kind": "run", "abba_blocks": rounds,
        "measured_samples_per_arm": 2 * rounds, "warmup_samples_per_arm": 1,
        "clock": "std::time::Instant", "time_unit": "nanoseconds",
        "timing_scope": "local full mathematical quorum APIs; A additionally decodes a fresh roster",
        "budget_setup_and_output_serialization_timed": false,
        "roster_drop_timed": false,
        "sample_scope": "one ephemeral public fixture repeated; no key or message population claim",
        "sampling_order": "one A warmup, one B warmup; then A B B A in every block",
        "pure_signature_context": "empty FIPS context; versioned domain in exact application message",
        "openssl_version": openssl::version::version(),
        "openssl_version_number_hex": format!("{:x}", openssl::version::number()),
        "execution_context": {"arch": env::consts::ARCH, "os": env::consts::OS,
            "debug_assertions": cfg!(debug_assertions), "crate_version": env!("CARGO_PKG_VERSION")},
        "caller_execution_record_required": "retain exact source/diff, locked graph, binary hash, rustc, cargo, target, flags, OpenSSL build/provider, host load, command and terminal exit",
        "provider_identity_attested": false, "fips140_module_qualification_claimed": false,
        "cell_read_measured": false, "owner_history_replay_measured": false,
        "complete_transition_latency_measured": false, "full_pipeline_measured": false,
        "performance_acceptance_threshold": null,
        "whole_chain_pq_qualified": false, "production_activation": false,
    }))?;
    ensure!(
        openssl::version::number() >= 0x3050_0000,
        "actual OpenSSL 3.5+ is required; no skip or successful fallback"
    );
    let material = material()?;
    quorum_sample(&material, Arm::Fresh, "warmup", 0, 0)?;
    quorum_sample(&material, Arm::Retained, "warmup", 0, 1)?;
    let mut fresh = Vec::with_capacity(2 * rounds);
    let mut retained = Vec::with_capacity(2 * rounds);
    for block in 1..=rounds {
        for (slot, arm) in [Arm::Fresh, Arm::Retained, Arm::Retained, Arm::Fresh]
            .into_iter()
            .enumerate()
        {
            let timing = quorum_sample(&material, arm, "measured", block, slot)?;
            match arm {
                Arm::Fresh => fresh.push(timing),
                Arm::Retained => retained.push(timing),
            }
        }
    }
    combined_observation(&material)?;
    for (arm, samples) in [(Arm::Fresh, fresh), (Arm::Retained, retained)] {
        emit(json!({
            "schema": SCHEMA, "kind": "arm_summary", "arm": arm.name(),
            "operation_wall": distribution(samples.iter().map(|sample| sample.operation_ns)),
            "full_quorum_verification_wall": distribution(samples.iter().map(|sample| sample.verification_ns)),
            "median_definition": "arithmetic mean of two central observations for an even count",
            "population_tail_established": false, "performance_acceptance_threshold": null,
        }))?;
    }
    emit(json!({
        "schema": SCHEMA, "kind": "complete", "observation_completed": true,
        "abba_blocks": rounds, "measured_samples_per_arm": 2 * rounds,
        "measured_quorum_calls": 4 * rounds, "measured_reserved_verifications": 16 * rounds,
        "warmup_quorum_calls": 2, "warmup_reserved_verifications": 8,
        "combined_api_reserved_verifications": 10,
        "setup_native_signatures": 10, "setup_native_self_checks": 10,
        "all_emitted_sample_results_and_counters_checked": true,
        "whole_chain_pq_qualified": false, "production_activation": false,
    }))
}
