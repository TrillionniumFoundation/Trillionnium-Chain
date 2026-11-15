//! Bounded NDJSON research fixture. Both real signing keys are PUBLIC TEST keys.
//! Parent/target come from an actual local Node, but no real demand, grouped
//! Node admission, remote service, physical durability or chainwork is claimed.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs::OpenOptions;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;
use trnm_crypto_primitives::{
    pon_grouped_fresh_seal_v0 as seal, public_key_hex, sign_hex, signing_key_from_hex,
};
use trnm_pon_node::{
    digest, grouped_fresh_admission_v0 as admission, sequence_root, Node, Settings,
};
use trnm_protocol::pon_wire::{hash, Hash};

const MAX_COMMAND_BYTES: usize = 8192;
const MAX_COMMANDS: u64 = 16384;
type Result<T> = std::result::Result<T, String>;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Freeze {
    model_commitment: String,
    request_precommitment: String,
    batch_id: String,
    authorization_scope: String,
    demand_id: String,
    source_record: String,
    withdrawal_head: String,
    payee: String,
    model_generation: u64,
    timestamp_ms: u64,
    not_before_ns: u64,
    expires_ns: u64,
    available_until_ns: u64,
    nonce_first: u64,
    nonce_count: u64,
    now_ns: u64,
}
#[derive(Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Freeze(Freeze),
    Prove {
        nonce: u64,
        statement: String,
        now_ns: u64,
        #[serde(default)]
        cancel_after: Option<u16>,
    },
    ReserveOnly {
        nonce: u64,
        now_ns: u64,
    },
    ReserveVerification {
        nonce: u64,
        statement: String,
        proof_sha256: String,
        capsule_sha256: String,
        mode: String,
        now_ns: u64,
    },
    Verify {
        nonce: u64,
        statement: String,
        proof_hex: String,
        verification_permit: String,
        now_ns: u64,
        #[serde(default)]
        capsule_hex: Option<String>,
    },
    VerifyUntrusted {
        nonce: u64,
        statement: String,
        proof_hex: String,
        verification_permit: String,
        now_ns: u64,
        #[serde(default)]
        capsule_hex: Option<String>,
    },
    Reopen {
        now_ns: u64,
    },
    Status,
    Close,
}

#[cfg(target_os = "linux")]
fn cpu_ns() -> Option<u64> {
    use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
    let t = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ThreadCPUTime)).ok()?;
    let sec = u64::try_from(t.tv_sec).ok()?;
    let ns = u64::try_from(t.tv_nsec).ok()?;
    (ns < 1_000_000_000).then_some(())?;
    sec.checked_mul(1_000_000_000)?.checked_add(ns)
}
#[cfg(not(target_os = "linux"))]
fn cpu_ns() -> Option<u64> {
    None
}
struct Stamp {
    wall: Instant,
    cpu: Option<u64>,
}
impl Stamp {
    fn start() -> Self {
        Self {
            wall: Instant::now(),
            cpu: cpu_ns(),
        }
    }
    fn finish(self) -> Value {
        json!({"wall_ns":u64::try_from(self.wall.elapsed().as_nanos()).ok(),
            "thread_cpu_ns":self.cpu.zip(cpu_ns()).and_then(|(a,b)|b.checked_sub(a))})
    }
}
fn checked<T, E: std::fmt::Debug>(value: std::result::Result<T, E>) -> Result<T> {
    value.map_err(|e| format!("{e:?}"))
}
fn hex32(value: &str) -> Result<Hash> {
    checked(digest(value))
}
fn fixed64(value: String) -> Result<[u8; 64]> {
    checked(checked(hex::decode(value))?.try_into())
}
fn write_new(path: &Path, raw: &[u8]) -> Result<()> {
    let mut file = checked(OpenOptions::new().write(true).create_new(true).open(path))?;
    checked(file.write_all(raw))?;
    checked(file.sync_all())
}
fn public_fixture_sign(
    body: &admission::CapsuleBody,
) -> Result<(Vec<u8>, admission::PinnedAuthority)> {
    let r = checked(signing_key_from_hex(&hex::encode(hash(
        b"DEV-ONLY-KEY",
        &[&40_u64.to_le_bytes()],
    ))))?;
    let s = checked(signing_key_from_hex(&hex::encode(hash(
        b"DEV-ONLY-KEY",
        &[&41_u64.to_le_bytes()],
    ))))?;
    let raw = admission::signed_capsule(
        body,
        fixed64(sign_hex(
            &r,
            &admission::signing_message(body, admission::SigningRole::Requester),
        ))?,
        fixed64(sign_hex(
            &s,
            &admission::signing_message(body, admission::SigningRole::Source),
        ))?,
    );
    let authority = admission::PinnedAuthority {
        requester_key: hex32(&public_key_hex(&r))?,
        source_key: hex32(&public_key_hex(&s))?,
        latest_sequence: 1,
        latest_digest: body.intent().registry_digest,
        expected_capsule_sha256: admission::sha256(&raw),
        expected: body.clone(),
    };
    Ok((raw, authority))
}
struct Session {
    node: Node,
    authority: admission::PinnedAuthority,
    raw: Vec<u8>,
    verified: admission::VerifiedAdmission,
    journal: Option<admission::ResearchLedger>,
    directory: PathBuf,
}
impl Session {
    fn freeze(directory: &Path, f: Freeze) -> Result<(Self, Value)> {
        let startup = Stamp::start();
        let node = checked(Node::open(
            &directory.join("native-node.sqlite"),
            checked(Settings::development(Some(1_700_000_000)))?,
            1,
        ))?;
        let startup = startup.finish();
        let prepare = Stamp::start();
        let request = hex32(&f.request_precommitment)?;
        let batch = hex32(&f.batch_id)?;
        let registry = hash(
            b"pon-grouped-fresh-controlled-registry-v0",
            &[&seal::profile_hash()],
        );
        let intent = admission::CapsuleIntent {
            registry_id: registry,
            registry_digest: hash(
                b"pon-grouped-fresh-controlled-registry-entry-v0",
                &[&registry, &request, &batch],
            ),
            previous_registry_digest: [0; 32],
            demand_id: hex32(&f.demand_id)?,
            source_record: hex32(&f.source_record)?,
            authorization_scope: hex32(&f.authorization_scope)?,
            withdrawal_head: hex32(&f.withdrawal_head)?,
            model_commitment: hex32(&f.model_commitment)?,
            request_precommitment: request,
            batch_id: batch,
            transactions_commitment: sequence_root("transactions", &[]),
            payee: hex32(&f.payee)?,
            operation_id: hash(
                b"pon-grouped-fresh-controlled-operation-v0",
                &[
                    &registry,
                    &request,
                    &batch,
                    &f.nonce_first.to_be_bytes(),
                    &f.nonce_count.to_be_bytes(),
                ],
            ),
            registry_sequence: 1,
            model_generation: f.model_generation,
            timestamp_ms: f.timestamp_ms,
            not_before_ns: f.not_before_ns,
            expires_ns: f.expires_ns,
            available_until_ns: f.available_until_ns,
            nonce_first: f.nonce_first,
            nonce_count: f.nonce_count,
        };
        let body = checked(admission::CapsuleBody::from_node(&node, intent))?;
        let (raw, authority) = public_fixture_sign(&body)?;
        let prepare = prepare.finish();
        let verify = Stamp::start();
        let verified = checked(admission::verify_capsule(&raw, &authority, &node, f.now_ns))?;
        let verify = verify.finish();
        let policy = json!({"schema":"pon-grouped-fresh-controlled-external-policy-v0","requester_public_key":hex::encode(authority.requester_key),
            "source_public_key":hex::encode(authority.source_key),"latest_sequence":authority.latest_sequence,
            "latest_digest":hex::encode(authority.latest_digest),"expected_capsule_sha256":hex::encode(authority.expected_capsule_sha256),
            "expected_body_hex":hex::encode(body.encode()),"policy_id":hex::encode(authority.policy_id()),
            "fixture_keys_public":true,"external_demand_authenticated":false,"independent_operators":false});
        let policy_bytes = checked(serde_json::to_vec(&policy))?;
        let persistence = Stamp::start();
        write_new(
            &directory.join("frozen-request.json"),
            &checked(serde_json::to_vec(&f))?,
        )?;
        write_new(&directory.join("expected-policy.json"), &policy_bytes)?;
        write_new(&directory.join("expected-body.bin"), &body.encode())?;
        write_new(&directory.join("capsule.bin"), &raw)?;
        let journal = checked(admission::ResearchLedger::create(
            &directory.join("research-ledger.sqlite"),
            &verified,
        ))?;
        let persistence = persistence.finish();
        let mut candidates = Vec::new();
        for index in 0..f.nonce_count {
            let nonce = f.nonce_first + index;
            candidates.push(json!({"nonce":nonce,"candidate_hex":hex::encode(checked(verified.candidate_bytes(nonce))?),
                "challenge":hex::encode(checked(verified.challenge_for_nonce(nonce))?),"work_id":hex::encode(checked(verified.work_id(nonce))?)}));
        }
        let response = json!({"schema":"pon-grouped-fresh-controlled-freeze-v0","profile":seal::PROFILE,
            "profile_hash":hex::encode(seal::profile_hash()),"steps":seal::STEPS,"numeric":seal::NUMERIC,"batch_size":seal::BATCH_SIZE,
            "branch":body.branch().observation(),"body_hex":hex::encode(body.encode()),"body_bytes":admission::BODY_BYTES,
            "capsule_hex":hex::encode(&raw),"capsule_bytes":raw.len(),"capsule_sha256":hex::encode(admission::sha256(&raw)),
            "external_policy":policy,"expected_policy_file_sha256":hex::encode(admission::sha256(&policy_bytes)),"candidates":candidates,
            "canonical_body_layout":{"magic":"504741420000","profile_hash_bytes":32,"steps_u16_be":64,
                "branch_hashes":["network","parameters","genesis","parent","prior_state","target"],"branch_u64_be":["height","generation"],
                "intent_hashes":["registry_id","registry_digest","previous_registry_digest","demand_id","source_record","authorization_scope","withdrawal_head","model_commitment","request_precommitment","batch_id","transactions_commitment","payee","operation_id"],
                "intent_u64_be":["registry_sequence","model_generation","timestamp_ms","not_before_ns","expires_ns","available_until_ns","nonce_first","nonce_count"]},
            "challenge_formula":"pon_wire.hash(pon-grouped-fresh-challenge-v0, [PGCE\\0\\0 || body || nonce_u64_be])",
            "native_node_startup":startup,"policy_prepare_and_fixture_signatures":prepare,"native_signature_and_parent_verification":verify,"initial_artifact_and_journal_persistence":persistence,
            "controlled_fixture_authority":true,"native_parent_target_checked":true,"fixture_signature_algorithm":"native-strict-Ed25519",
            "external_demand_authenticated":false,"independent_operators":false,"native_w1_admission":false,"chainwork_awarded":0,"production_activation":false});
        Ok((
            Self {
                node,
                authority,
                raw,
                verified,
                journal: Some(journal),
                directory: directory.to_owned(),
            },
            response,
        ))
    }
    fn authenticated(&self, raw: &[u8], now: u64) -> Result<admission::VerifiedAdmission> {
        checked(admission::verify_capsule(
            raw,
            &self.authority,
            &self.node,
            now,
        ))
    }
    fn run(&mut self, command: Command) -> Result<Value> {
        match command {
            Command::Prove {
                nonce,
                statement,
                now_ns,
                cancel_after,
            } => {
                if cancel_after.is_some_and(|step| !(1..=seal::STEPS).contains(&step)) {
                    return Err("CANCELLATION_CHECKPOINT".into());
                }
                let author = Stamp::start();
                let verified = self.authenticated(&self.raw, now_ns)?;
                let author = author.finish();
                let statement = hex32(&statement)?;
                let reservation = Stamp::start();
                checked(
                    self.journal
                        .as_mut()
                        .ok_or("JOURNAL_UNAVAILABLE")?
                        .reserve(&verified, nonce, &self.node, now_ns),
                )?;
                let reservation = reservation.finish();
                let producer = Stamp::start();
                let challenge = checked(verified.challenge_for_nonce(nonce))?;
                let mut steps = 0_u16;
                let proof = seal::prove_with_progress(challenge, statement, |point| {
                    if let seal::Progress::Step(index) = point {
                        steps = index;
                        if cancel_after == Some(index) {
                            return Err("CONTROLLED_PRODUCER_CANCELLATION");
                        }
                    }
                    Ok(())
                });
                let producer = producer.finish();
                let proof = match proof {
                    Ok(proof) => proof,
                    Err(error) => {
                        return Ok(
                            json!({"nonce":nonce,"challenge":hex::encode(challenge),"statement":hex::encode(statement),
                        "work_id":hex::encode(checked(verified.work_id(nonce))?),"status":"cancelled","native_error":error,
                        "proof_hex":null,"target_hit":null,"completed_steps":steps,"final_query_evaluated":steps==seal::STEPS,
                        "native_authorization":author,"durable_reservation":reservation,"native_seal_producer":producer,
                        "reservation_remains_durable":true,"chainwork_awarded":0,"grouped_arithmetic_verified_by_this_api":false}),
                        )
                    }
                };
                let persistence = Stamp::start();
                checked(
                    self.journal
                        .as_mut()
                        .ok_or("JOURNAL_UNAVAILABLE")?
                        .produced(&verified, nonce, statement, &proof),
                )?;
                let persistence = persistence.finish();
                let ticket = &proof[proof.len() - 32..];
                Ok(
                    json!({"nonce":nonce,"status":"produced","challenge":hex::encode(challenge),"statement":hex::encode(statement),"work_id":hex::encode(checked(verified.work_id(nonce))?),
                    "proof_hex":hex::encode(&proof),"proof_bytes":proof.len(),"proof_sha256":hex::encode(admission::sha256(&proof)),"ticket":hex::encode(ticket),
                    "target_hit":ticket<=verified.body().branch().target().as_slice(),"completed_steps":steps,"final_query_evaluated":true,
                    "native_authorization":author,"durable_reservation":reservation,"native_seal_producer":producer,"produced_claim_persistence":persistence,
                    "chainwork_awarded":0,"grouped_arithmetic_verified_by_this_api":false}),
                )
            }
            Command::ReserveOnly { nonce, now_ns } => {
                let author = Stamp::start();
                let verified = self.authenticated(&self.raw, now_ns)?;
                let author = author.finish();
                let reservation = Stamp::start();
                let id = checked(
                    self.journal
                        .as_mut()
                        .ok_or("JOURNAL_UNAVAILABLE")?
                        .reserve(&verified, nonce, &self.node, now_ns),
                )?;
                Ok(
                    json!({"status":"reserved_without_production","nonce":nonce,"work_id":hex::encode(id),
                    "native_authorization":author,"durable_reservation":reservation.finish(),"completed_steps":0,
                    "final_query_evaluated":false,"chainwork_awarded":0}),
                )
            }
            Command::ReserveVerification {
                nonce,
                statement,
                proof_sha256,
                capsule_sha256,
                mode,
                now_ns,
            } => {
                let mode = match mode.as_str() {
                    "record" => admission::VerificationMode::Record,
                    "untrusted" => admission::VerificationMode::Untrusted,
                    _ => return Err("VERIFICATION_MODE".into()),
                };
                let request = admission::VerificationRequest::from_digests(
                    nonce,
                    hex32(&statement)?,
                    hex32(&proof_sha256)?,
                    hex32(&capsule_sha256)?,
                    mode,
                );
                let stamp = Stamp::start();
                let permit = checked(
                    self.journal
                        .as_mut()
                        .ok_or("JOURNAL_UNAVAILABLE")?
                        .reserve_verification(&self.verified, &request, &self.node, now_ns),
                )?;
                Ok(
                    json!({"permit":permit.observation(),"native_verification_budget_reservation":stamp.finish(),
                    "full_grouped_or_seal_replay_started":false,"chainwork_awarded":0}),
                )
            }
            Command::Verify {
                nonce,
                statement,
                proof_hex,
                verification_permit,
                now_ns,
                capsule_hex,
            } => {
                let elapsed = Instant::now();
                let raw = match capsule_hex {
                    Some(s) => checked(hex::decode(s))?,
                    None => self.raw.clone(),
                };
                let proof = checked(hex::decode(proof_hex))?;
                let statement = hex32(&statement)?;
                let request = admission::VerificationRequest::from_digests(
                    nonce,
                    statement,
                    admission::sha256(&proof),
                    admission::sha256(&raw),
                    admission::VerificationMode::Record,
                );
                let permit_claim = Stamp::start();
                let claimed = checked(
                    self.journal
                        .as_mut()
                        .ok_or("JOURNAL_UNAVAILABLE")?
                        .claim_verification(&self.verified, hex32(&verification_permit)?, &request),
                )?;
                let permit_claim = permit_claim.finish();
                let author = Stamp::start();
                let verified = self.authenticated(&raw, now_ns)?;
                let author = author.finish();
                let verify = Stamp::start();
                // The externally supplied fixture clock advances throughout the
                // call. It is not a network peer's self-selected time authority.
                let observation = checked(
                    self.journal
                        .as_mut()
                        .ok_or("JOURNAL_UNAVAILABLE")?
                        .verify_and_record(
                            claimed,
                            &verified,
                            nonce,
                            statement,
                            &proof,
                            &self.node,
                            || {
                                let delta = u64::try_from(elapsed.elapsed().as_nanos())
                                    .map_err(|_| admission::AdmissionError::Window)?;
                                now_ns
                                    .checked_add(delta)
                                    .ok_or(admission::AdmissionError::Window)
                            },
                        ),
                )?;
                let verify = verify.finish();
                Ok(
                    json!({"verification_permit_claim":permit_claim,"native_authorization":author,"full_seal_replay_and_journal_commit":verify,"observation":observation,
                    "clock_scope":"caller-owned controlled-fixture epoch plus actual monotonic elapsed call time"}),
                )
            }
            Command::VerifyUntrusted {
                nonce,
                statement,
                proof_hex,
                verification_permit,
                now_ns,
                capsule_hex,
            } => {
                let elapsed = Instant::now();
                let raw = match capsule_hex {
                    Some(s) => checked(hex::decode(s))?,
                    None => self.raw.clone(),
                };
                let proof = checked(hex::decode(proof_hex))?;
                let statement = hex32(&statement)?;
                let request = admission::VerificationRequest::from_digests(
                    nonce,
                    statement,
                    admission::sha256(&proof),
                    admission::sha256(&raw),
                    admission::VerificationMode::Untrusted,
                );
                let permit_claim = Stamp::start();
                let claimed = checked(
                    self.journal
                        .as_mut()
                        .ok_or("JOURNAL_UNAVAILABLE")?
                        .claim_verification(&self.verified, hex32(&verification_permit)?, &request),
                )?;
                let permit_claim = permit_claim.finish();
                let author = Stamp::start();
                let verified = self.authenticated(&raw, now_ns)?;
                let author = author.finish();
                let verify = Stamp::start();
                let observation = checked(
                    self.journal
                        .as_ref()
                        .ok_or("JOURNAL_UNAVAILABLE")?
                        .verify_untrusted_with_permit(
                            claimed,
                            &verified,
                            nonce,
                            statement,
                            &proof,
                            &self.node,
                            || {
                                let delta = u64::try_from(elapsed.elapsed().as_nanos())
                                    .map_err(|_| admission::AdmissionError::Window)?;
                                now_ns
                                    .checked_add(delta)
                                    .ok_or(admission::AdmissionError::Window)
                            },
                        ),
                )?;
                Ok(
                    json!({"verification_permit_claim":permit_claim,"native_authorization":author,"untrusted_full_seal_replay":verify.finish(),"observation":observation,
                    "independent_of_producer_journal":true,"clock_scope":"caller-owned controlled-fixture epoch plus actual monotonic elapsed call time"}),
                )
            }
            Command::Reopen { now_ns } => {
                checked(self.verified.recheck(&self.node, now_ns))?;
                let stamp = Stamp::start();
                self.journal.take();
                self.journal = Some(checked(admission::ResearchLedger::open(
                    &self.directory.join("research-ledger.sqlite"),
                    &self.verified,
                ))?);
                Ok(
                    json!({"same_process_sqlite_reopen":stamp.finish(),"ledger":checked(self.journal.as_ref().ok_or("JOURNAL_UNAVAILABLE")?.observation())?}),
                )
            }
            Command::Status | Command::Close => Ok(
                json!({"ledger":checked(self.journal.as_ref().ok_or("JOURNAL_UNAVAILABLE")?.observation())?,"native_branch":self.verified.body().branch().observation()}),
            ),
            Command::Freeze(..) => Err("ALREADY_FROZEN".into()),
        }
    }
}

fn bounded_line(reader: &mut impl BufRead) -> io::Result<Option<Vec<u8>>> {
    let mut out = Vec::new();
    loop {
        let bytes = reader.fill_buf()?;
        if bytes.is_empty() {
            return Ok((!out.is_empty()).then_some(out));
        }
        let end = bytes
            .iter()
            .position(|b| *b == b'\n')
            .map_or(bytes.len(), |i| i + 1);
        if out.len() + end > MAX_COMMAND_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "COMMAND_TOO_LARGE",
            ));
        }
        let done = bytes[end - 1] == b'\n';
        out.extend_from_slice(&bytes[..end]);
        reader.consume(end);
        if done {
            return Ok(Some(out));
        }
    }
}
fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 || args[1] != "--directory" {
        return Err(
            "usage: grouped_fresh_admission_v0 --directory FRESH_ABSOLUTE_DIRECTORY".into(),
        );
    }
    let directory = PathBuf::from(&args[2]);
    if !directory.is_absolute() {
        return Err("ABSOLUTE_DIRECTORY_REQUIRED".into());
    }
    checked(std::fs::create_dir(&directory))?;
    let mut transcript = checked(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join("responses.ndjson")),
    )?;
    let mut requests = checked(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join("requests.ndjson")),
    )?;
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    let mut session: Option<Session> = None;
    for ordinal in 0..MAX_COMMANDS {
        let Some(raw) = checked(bounded_line(&mut input))? else {
            break;
        };
        let stamp = Stamp::start();
        checked(requests.write_all(&raw))?;
        checked(requests.sync_all())?;
        let mut close = false;
        let result = (|| -> Result<Value> {
            let command: Command = checked(serde_json::from_slice(&raw))?;
            close = matches!(command, Command::Close);
            if session.is_none() {
                let Command::Freeze(request) = command else {
                    return Err("FREEZE_REQUIRED".into());
                };
                let (value, response) = Session::freeze(&directory, request)?;
                session = Some(value);
                Ok(response)
            } else {
                session.as_mut().ok_or("FREEZE_REQUIRED")?.run(command)
            }
        })();
        let ok = result.is_ok();
        let response = json!({"schema":"pon-grouped-fresh-native-session-response-v0","ordinal":ordinal,"ok":ok,
            "request_bytes":raw.len(),"request_sha256":hex::encode(admission::sha256(&raw)),
            "command_before_response_encoding":stamp.finish(),"response_encoding_persistence_and_stdio_in_command_timing":false,
            "result":result.as_ref().ok(),"error":result.as_ref().err()});
        let mut bytes = checked(serde_json::to_vec(&response))?;
        bytes.push(b'\n');
        checked(transcript.write_all(&bytes))?;
        checked(transcript.sync_all())?;
        checked(output.write_all(&bytes))?;
        checked(output.flush())?;
        if close {
            break;
        }
    }
    checked(transcript.sync_all())?;
    checked(requests.sync_all())?;
    drop(session);
    // The external supervisor owns process-wide startup/exit/CPU and IPC costs.
    // A zero exit cannot convert an earlier refused response into a success.
    Ok(())
}
