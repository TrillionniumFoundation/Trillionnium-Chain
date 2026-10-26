//! A measured miner outputs only actual production packets that meet target.
//! Miss counts and a trace commitment remain paid research instrumentation;
//! they are not consensus requirements or a minimum cost for an adversary.
use crate::producer::DeferredPrepared;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{io::Write, time::Instant};
use trnm_crypto_primitives::pon_work::{self, Hash};
use trnm_mvcc_fee::continuity_v1;
use trnm_pon_node::{development_public, Node, Packet, Settings};
use trnm_protocol::pon_wire::{Header, HEADER_BYTES};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub const SCHEMA: &str = "pon-w1-compact-miner-research-v1";
const MAGIC: &[u8; 8] = b"W1CMR1\0\0";
const COMMIT_DOMAIN: &[u8] = b"TRNM-W1-COMPACT-ATTEMPTS1\0";
const PACKET_BYTES: usize = HEADER_BYTES + 2 + pon_work::PROOF_BYTES;
const FRAME_LIMIT: usize = 65_536;
const NOW: u64 = 100_000;
const MAKE_LIMIT: u64 = 64;
const START: u8 = 1;
const CONTEXT: u8 = 2;
const SETUP_PACKET: u8 = 3;
const SETUP_RECEIPT: u8 = 4;
const PREPARED: u8 = 5;
const BOUNDARY: u8 = 6;
const WINNER: u8 = 7;
const SEAL: u8 = 8;
const RECEIVER: u8 = 9;
const AUDIT: u8 = 10;
const END: u8 = 11;

#[derive(Clone, Debug, Serialize)]
pub struct Options {
    setup_budget_ns: u64,
    miner_budget_ns: u64,
    max_attempts: u64,
    seed: u64,
}
impl Options {
    pub fn read() -> Result<Self> {
        Self::parse(std::env::args().skip(1).collect())
    }
    fn parse(args: Vec<String>) -> Result<Self> {
        let mut result = Self {
            setup_budget_ns: 1_000_000_000,
            miner_budget_ns: 128_000_000,
            max_attempts: 4096,
            seed: 1,
        };
        if !args.len().is_multiple_of(2) {
            return Err("OPTION_PAIRS".into());
        }
        let mut used = std::collections::BTreeSet::new();
        for pair in args.chunks_exact(2) {
            if !used.insert(&pair[0]) {
                return Err("DUPLICATE_OPTION".into());
            }
            if !pair[1].bytes().all(|b| b.is_ascii_digit()) || pair[1].is_empty() {
                return Err("OPTION_INTEGER".into());
            }
            let number = pair[1].parse()?;
            match pair[0].as_str() {
                "--setup-budget-ns" => result.setup_budget_ns = number,
                "--miner-budget-ns" => result.miner_budget_ns = number,
                "--max-attempts" => result.max_attempts = number,
                "--seed" => result.seed = number,
                _ => return Err("UNKNOWN_OPTION".into()),
            }
        }
        if !(1..=4096).contains(&result.max_attempts) || result.seed > u64::from(u32::MAX) {
            return Err("OPTION_BOUNDS".into());
        }
        Ok(result)
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
struct Stamp {
    process_cpu_ns: u64,
    wall_ns: u64,
}
impl Stamp {
    const ZERO: Self = Self {
        process_cpu_ns: 0,
        wall_ns: 0,
    };
}
#[cfg(target_os = "linux")]
fn cpu() -> Result<u64> {
    use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
    let t = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ProcessCPUTime))?;
    let nanos = u64::try_from(t.tv_nsec)?;
    if nanos >= 1_000_000_000 {
        return Err("CPU_NANOS".into());
    }
    u64::try_from(t.tv_sec)?
        .checked_mul(1_000_000_000)
        .and_then(|s| s.checked_add(nanos))
        .ok_or_else(|| "CPU_OVERFLOW".into())
}
#[cfg(not(target_os = "linux"))]
fn cpu() -> Result<u64> {
    Err("LINUX_PROCESS_CLOCK_REQUIRED".into())
}
struct Clock {
    cpu_origin: u64,
    wall_origin: Instant,
}
impl Clock {
    fn new() -> Result<Self> {
        Ok(Self {
            cpu_origin: cpu()?,
            wall_origin: Instant::now(),
        })
    }
    fn stamp(&self) -> Result<Stamp> {
        Ok(Stamp {
            process_cpu_ns: cpu()?.checked_sub(self.cpu_origin).ok_or("CPU_REVERSED")?,
            wall_ns: self.wall_origin.elapsed().as_nanos().try_into()?,
        })
    }
}
struct Wire<W: Write> {
    output: W,
}
impl<W: Write> Wire<W> {
    fn new(mut output: W) -> Result<Self> {
        output.write_all(MAGIC)?;
        output.flush()?;
        Ok(Self { output })
    }
    fn parts(&mut self, tag: u8, parts: &[&[u8]]) -> Result<()> {
        let length = parts
            .iter()
            .try_fold(0_usize, |n, part| n.checked_add(part.len()))
            .ok_or("FRAME_LENGTH_OVERFLOW")?;
        if length == 0 || length > FRAME_LIMIT {
            return Err("FRAME_LENGTH".into());
        }
        self.output.write_all(&[tag])?;
        self.output
            .write_all(&u32::try_from(length)?.to_le_bytes())?;
        for part in parts {
            self.output.write_all(part)?;
        }
        self.output.flush()?;
        Ok(())
    }
    fn json<T: Serialize>(&mut self, tag: u8, value: &T) -> Result<()> {
        let bytes = serde_json::to_vec(value)?;
        self.parts(tag, &[&bytes])
    }
}
fn transition<W: Write>(
    clock: &Clock,
    wire: &mut Wire<W>,
    origin: &mut Stamp,
    from: &str,
    to: &str,
) -> Result<Stamp> {
    let end = clock.stamp()?;
    wire.json(
        BOUNDARY,
        &json!({"from":from,"to":to,"begin":origin,"end":end,
        "elapsed_cpu_ns":end.process_cpu_ns-origin.process_cpu_ns,
        "boundary_output_charged_to_next_phase":true}),
    )?;
    *origin = end;
    Ok(end)
}
fn relation<T>(value: std::result::Result<T, pon_work::WorkError>) -> Result<T> {
    value.map_err(|error| format!("WORK:{error:?}").into())
}
fn ticket(header: &Header, trace: Hash) -> Hash {
    pon_work::hash(b"ticket", &[&header.challenge(), &trace])
}
fn hit(header: &Header, value: Hash) -> bool {
    header.target != [0; 32] && value <= header.target
}
fn initial_commitment(template: &Header, seed: u64) -> Sha256 {
    let mut result = Sha256::new();
    result.update(COMMIT_DOMAIN);
    result.update(template.encode());
    result.update(seed.to_le_bytes());
    result
}
fn append_commitment(value: &mut Sha256, ordinal: u64, trace: Hash) {
    value.update(ordinal.to_le_bytes());
    value.update(trace);
}
struct NativeContext {
    node: Node,
    directory: tempfile::TempDir,
    a: Vec<u32>,
    b: Vec<u32>,
    genesis: Hash,
}
struct Prepared {
    producer: DeferredPrepared,
    initial_commitment: Sha256,
}
struct Winner {
    ordinal: u64,
    bytes: Vec<u8>,
    available: Stamp,
    accounted: Stamp,
}
#[derive(Serialize)]
struct MinerSeal {
    setup_complete: bool,
    stop_reason: &'static str,
    attempts: u64,
    target_hits: u64,
    target_misses: u64,
    attempts_available_by_b: u64,
    full_winners_available_by_b: u64,
    trace_commitment: Option<String>,
    committed_attempt_payload_bytes: u64,
    winner_packet_bytes: u64,
    original_miss_records: u64,
    first_attempt_begin: Option<Stamp>,
    last_attempt_begin: Option<Stamp>,
    last_attempt_available: Option<Stamp>,
    last_attempt_accounted: Option<Stamp>,
    stop_poll: Stamp,
    availability_to_accounting_observation_cpu_ns: u64,
    availability_to_accounting_observation_wall_ns: u64,
}
impl MinerSeal {
    fn empty(setup_complete: bool, stop_poll: Stamp) -> Self {
        Self {
            setup_complete,
            stop_reason: "setup-incomplete",
            attempts: 0,
            target_hits: 0,
            target_misses: 0,
            attempts_available_by_b: 0,
            full_winners_available_by_b: 0,
            trace_commitment: None,
            committed_attempt_payload_bytes: 0,
            winner_packet_bytes: 0,
            original_miss_records: 0,
            first_attempt_begin: None,
            last_attempt_begin: None,
            last_attempt_available: None,
            last_attempt_accounted: None,
            stop_poll,
            availability_to_accounting_observation_cpu_ns: 0,
            availability_to_accounting_observation_wall_ns: 0,
        }
    }
}
// This function has no Node or verifier argument and receives no admission feedback.
fn mine<W: Write>(
    clock: &Clock,
    wire: &mut Wire<W>,
    o: &Options,
    origin: Stamp,
    prepared: &Prepared,
    template: &Header,
) -> Result<(MinerSeal, Vec<Winner>)> {
    let mut seal = MinerSeal::empty(true, clock.stamp()?);
    let mut commitment = prepared.initial_commitment.clone();
    let mut winners: Vec<Winner> = Vec::new();
    loop {
        let begin = clock.stamp()?;
        seal.stop_poll = begin;
        if seal.attempts == o.max_attempts {
            seal.stop_reason = "safety-cap-censored";
            break;
        }
        if begin.process_cpu_ns - origin.process_cpu_ns >= o.miner_budget_ns {
            seal.stop_reason = "miner-cpu-budget-stopped";
            break;
        }
        let ordinal = seal.attempts;
        let mut header = template.clone();
        // Exactly the existing late-assembly schedule; no new challenge domain.
        header.nonce = (1_u64 << 63) + o.seed * 4096 + ordinal;
        let challenge = header.challenge();
        let trace = prepared.producer.trace(challenge).map_err(|error| {
            format!(
                "PRODUCER_FAILURE ordinal={ordinal} completed={} misses={} error={error:?}",
                seal.attempts, seal.target_misses
            )
        })?;
        let value = pon_work::hash(b"ticket", &[&challenge, &trace]);
        let is_hit = hit(&header, value);
        append_commitment(&mut commitment, ordinal, trace);
        seal.attempts += 1;
        seal.target_hits += u64::from(is_hit);
        seal.target_misses += u64::from(!is_hit);
        let bytes = if is_hit {
            let packet = Packet {
                header,
                transactions: Vec::new(),
                proof: prepared.producer.assemble(trace),
            };
            let bytes = packet.encode()?;
            if bytes.len() != PACKET_BYTES {
                return Err("PRODUCTION_PACKET_LENGTH".into());
            }
            // No proof hex, proof SHA, statement JSON or additional semantic hashes.
            wire.parts(WINNER, &[&ordinal.to_le_bytes(), &bytes])
                .map_err(|error| {
                    format!(
                "WINNER_OUTPUT_FAILURE ordinal={ordinal} completed={} misses={} error={error}",
                seal.attempts, seal.target_misses)
                })?;
            Some(bytes)
        } else {
            None
        };
        // A winning packet is credited only after original bytes were fully flushed.
        let available = clock.stamp()?;
        let within = available.process_cpu_ns - origin.process_cpu_ns <= o.miner_budget_ns;
        seal.attempts_available_by_b += u64::from(within);
        seal.full_winners_available_by_b += u64::from(within && is_hit);
        if let Some(bytes) = bytes {
            seal.winner_packet_bytes += bytes.len() as u64;
            winners.push(Winner {
                ordinal,
                bytes,
                available,
                accounted: available,
            });
        }
        let accounted = clock.stamp()?;
        if is_hit {
            winners.last_mut().ok_or("WINNER_LEDGER")?.accounted = accounted;
        }
        seal.availability_to_accounting_observation_cpu_ns +=
            accounted.process_cpu_ns - available.process_cpu_ns;
        seal.availability_to_accounting_observation_wall_ns +=
            accounted.wall_ns - available.wall_ns;
        seal.first_attempt_begin.get_or_insert(begin);
        seal.last_attempt_begin = Some(begin);
        seal.last_attempt_available = Some(available);
        seal.last_attempt_accounted = Some(accounted);
    }
    seal.trace_commitment = Some(hex::encode(commitment.finalize()));
    seal.committed_attempt_payload_bytes = seal.attempts * 40;
    Ok((seal, winners))
}

pub fn run(o: Options) -> Result<()> {
    let clock = Clock::new()?;
    let stdout = std::io::stdout();
    let mut wire = Wire::new(std::io::BufWriter::with_capacity(
        FRAME_LIMIT,
        stdout.lock(),
    ))?;
    wire.json(START, &json!({"schema":SCHEMA,"options":o,"origin":Stamp::ZERO,
        "phase_order":["setup","miner","receiver","audit","done"],
        "cpu_scope":"actual-process-CPU-no-observer-subtraction",
        "winner_payload":"unchanged-Packet-encode","packet_bytes":PACKET_BYTES,
        "miss_originals_retained":false,"trace_commitment_is_paid_observation":true,
        "commitment_required_by_consensus":false,"trace_kernel":"DeferredPrepared-integer-paired-general",
        "production_activation":false,"minimum_attacker_cost_established":false}))?;
    let mut context: Option<NativeContext> = None;
    let mut setup_packet: Option<Packet> = None;
    let mut prepared: Option<Prepared> = None;
    let begin = clock.stamp()?;
    if begin.process_cpu_ns < o.setup_budget_ns {
        let directory = tempfile::tempdir()?;
        let settings = Settings::development_with_profiles(
            Some(1),
            "native-public-evaluation-dev-v1",
            continuity_v1::PROFILE,
        )?;
        let (_, _, a, b) = settings.consensus_maintenance_material()?;
        let node = Node::open(directory.path(), settings, 2)?;
        let genesis = node.active()?.0;
        wire.json(
            CONTEXT,
            &json!({"begin":begin,"observed":clock.stamp()?,
            "genesis":hex::encode(genesis),"task":hex::encode(relation(pon_work::task_id(&a,&b))?),
            "observed_now":NOW,"maintenance_is_real_training":false}),
        )?;
        context = Some(NativeContext {
            node,
            directory,
            a,
            b,
            genesis,
        });
    }
    let begin = clock.stamp()?;
    if begin.process_cpu_ns < o.setup_budget_ns {
        if let Some(c) = context.as_mut() {
            let packet = c.node.make_consensus_maintenance(
                c.genesis,
                Vec::new(),
                development_public(0)?,
                11,
                MAKE_LIMIT,
            )?;
            let id = c.node.admit(&packet, NOW)?;
            if c.node.active()?.0 != c.genesis
                || packet.header.target != c.node.expected_target(c.genesis)?
            {
                return Err("SETUP_NATIVE_CONTEXT".into());
            }
            let bytes = packet.encode()?;
            wire.parts(SETUP_PACKET, &[&bytes])?;
            wire.json(SETUP_RECEIPT, &json!({"begin":begin,"packet_flushed":clock.stamp()?,
                "native_block_id":hex::encode(id),"original_completed_attempts":packet.header.nonce+1,
                "original_target_misses":packet.header.nonce,"original_miss_records":0,
                "setup_credit_separate":true,"active_unchanged":true}))?;
            setup_packet = Some(packet);
        }
    }
    let begin = clock.stamp()?;
    if begin.process_cpu_ns < o.setup_budget_ns {
        if let (Some(c), Some(packet)) = (&context, &setup_packet) {
            prepared = Some(Prepared {
                producer: relation(DeferredPrepared::new(&c.a, &c.b))?,
                initial_commitment: initial_commitment(&packet.header, o.seed),
            });
            wire.json(
                PREPARED,
                &json!({"begin":begin,"observed":clock.stamp()?,
                "arm":"integer-paired-general","original_AB_and_prefix_paid_in_setup":true,
                "commitment_initialization_paid_in_setup":true}),
            )?;
        }
    }
    let mut phase_origin = Stamp::ZERO;
    let setup_end = transition(&clock, &mut wire, &mut phase_origin, "setup", "miner")?;
    let setup_complete = prepared.is_some() && setup_end.process_cpu_ns <= o.setup_budget_ns;
    let (seal, winners) = if setup_complete {
        mine(
            &clock,
            &mut wire,
            &o,
            phase_origin,
            prepared.as_ref().ok_or("PREPARED")?,
            &setup_packet.as_ref().ok_or("TEMPLATE")?.header,
        )?
    } else {
        (MinerSeal::empty(false, clock.stamp()?), Vec::new())
    };
    // Seal formatting, final commitment and flush remain charged to actual miner CPU.
    // They do not backdate the earlier completion of any winning packet.
    wire.json(SEAL, &seal)?;
    let miner_end = transition(&clock, &mut wire, &mut phase_origin, "miner", "receiver")?;
    let mut accepted = 0_u64;
    let mut accepted_by_b = 0_u64;
    if let Some(c) = context.as_mut() {
        for w in &winners {
            // Admission uses exactly the original production-format bytes.
            let packet = Packet::decode(&w.bytes)?;
            let id = c.node.admit(&packet, NOW)?;
            if id != packet.id()? || c.node.active()?.0 != c.genesis {
                return Err("RECEIVER_NATIVE_CONTEXT".into());
            }
            let within = w.available.process_cpu_ns - setup_end.process_cpu_ns <= o.miner_budget_ns;
            accepted += 1;
            accepted_by_b += u64::from(within);
            wire.json(
                RECEIVER,
                &json!({"ordinal":w.ordinal,"available":w.available,"accounted":w.accounted,
                "within_miner_budget":within,"native_block_id":hex::encode(id),
                "active_tip":hex::encode(c.node.active()?.0),"admission_completed":clock.stamp()?,
                "original_packet_bytes":w.bytes.len(),"mature_reward_claim":false}),
            )?;
        }
    }
    let materials = context.take().map(|c| {
        let NativeContext {
            node,
            directory,
            a,
            b,
            genesis: _,
        } = c;
        drop(node);
        drop(directory);
        (a, b)
    });
    let receiver_end = transition(&clock, &mut wire, &mut phase_origin, "receiver", "audit")?;
    let mut research_replayed = 0_u64;
    let mut setup_replayed = 0_u64;
    let mut reconstructed_hits = 0_u64;
    let mut reconstructed_misses = 0_u64;
    let mut audit_commitment = None;
    if setup_complete {
        let packet = setup_packet.as_ref().ok_or("AUDIT_TEMPLATE")?;
        let (a, b) = materials.as_ref().ok_or("AUDIT_MATERIAL")?;
        let mut commitment = initial_commitment(&packet.header, o.seed);
        let mut winner_index = 0_usize;
        for ordinal in 0..seal.attempts {
            let mut header = packet.header.clone();
            header.nonce = (1_u64 << 63) + o.seed * 4096 + ordinal;
            let challenge = header.challenge();
            let proof = relation(pon_work::prove(challenge, a, b))?;
            relation(pon_work::verify_reference(
                challenge,
                header.work_task,
                [255; 32],
                &proof,
            ))?;
            let trace: Hash = proof[pon_work::PROOF_BYTES - 32..].try_into()?;
            append_commitment(&mut commitment, ordinal, trace);
            let is_hit = hit(&header, ticket(&header, trace));
            reconstructed_hits += u64::from(is_hit);
            reconstructed_misses += u64::from(!is_hit);
            if is_hit {
                let w = winners.get(winner_index).ok_or("AUDIT_WINNER_MISSING")?;
                let reconstructed = Packet {
                    header,
                    transactions: Vec::new(),
                    proof,
                }
                .encode()?;
                if w.ordinal != ordinal || w.bytes != reconstructed {
                    return Err("AUDIT_ORIGINAL_PACKET".into());
                }
                winner_index += 1;
            }
            research_replayed += 1;
        }
        audit_commitment = Some(hex::encode(commitment.finalize()));
        if audit_commitment != seal.trace_commitment
            || reconstructed_hits != seal.target_hits
            || reconstructed_misses != seal.target_misses
            || winner_index != winners.len()
        {
            return Err("AUDIT_MINER_LEDGER".into());
        }
    }
    if let Some(packet) = &setup_packet {
        let (a, b) = materials.as_ref().ok_or("SETUP_AUDIT_MATERIAL")?;
        for nonce in 0..=packet.header.nonce {
            let mut header = packet.header.clone();
            header.nonce = nonce;
            let challenge = header.challenge();
            let proof = relation(pon_work::prove(challenge, a, b))?;
            relation(pon_work::verify_reference(
                challenge,
                header.work_task,
                [255; 32],
                &proof,
            ))?;
            let trace: Hash = proof[pon_work::PROOF_BYTES - 32..].try_into()?;
            let winner = nonce == packet.header.nonce;
            if hit(&header, ticket(&header, trace)) != winner || (winner && proof != packet.proof) {
                return Err("AUDIT_SETUP_SEARCH".into());
            }
            setup_replayed += 1;
        }
    }
    wire.json(AUDIT,&json!({"research_recomputed":research_replayed,"setup_recomputed":setup_replayed,
        "research_hits":reconstructed_hits,"research_misses":reconstructed_misses,
        "trace_commitment":audit_commitment,"reference_relation_checks":research_replayed+setup_replayed,
        "posthoc_miss_bytes_are_original":false,"posthoc_new_credit":0,
        "feedback_to_miner":false,"observed":clock.stamp()?}))?;
    drop(materials);
    drop(prepared);
    drop(setup_packet);
    drop(winners);
    let audit_end = transition(&clock, &mut wire, &mut phase_origin, "audit", "done")?;
    let endpoint = clock.stamp()?;
    wire.json(
        END,
        &json!({"schema":SCHEMA,"status":"PASS","setup_complete":setup_complete,
        "attempts":seal.attempts,"target_misses":seal.target_misses,"target_hits":seal.target_hits,
        "attempts_available_by_B":seal.attempts_available_by_b,
        "full_winners_available_by_B":seal.full_winners_available_by_b,
        "native_accepted":accepted,"native_accepted_from_B":accepted_by_b,
        "late_attempts":seal.attempts-seal.attempts_available_by_b,
        "late_winners":seal.target_hits-seal.full_winners_available_by_b,
        "censored_by_attempt_cap":seal.stop_reason=="safety-cap-censored",
        "phase_cpu_ns":{"setup":setup_end.process_cpu_ns,
            "miner":miner_end.process_cpu_ns-setup_end.process_cpu_ns,
            "receiver":receiver_end.process_cpu_ns-miner_end.process_cpu_ns,
            "audit":audit_end.process_cpu_ns-receiver_end.process_cpu_ns},
        "post_stop_seal_cpu_ns":miner_end.process_cpu_ns-seal.stop_poll.process_cpu_ns,
        "native_total_endpoint":endpoint,"candidate_chain_activation":false,
        "minimum_attacker_cost_established":false,"production_activation":false,
        "final_serialization_and_remaining_drops_in_whole_child_residual":true}),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn option_bounds_and_duplicate_errors_are_explicit() {
        for argv in [
            vec!["--max-attempts", "0"],
            vec!["--max-attempts", "4097"],
            vec!["--seed", "4294967296"],
            vec!["--seed", "+1"],
            vec!["--seed", "1", "--seed", "2"],
        ] {
            assert!(Options::parse(argv.into_iter().map(str::to_owned).collect()).is_err());
        }
        assert_eq!(
            Options::parse(vec!["--miner-budget-ns".into(), "0".into()])
                .unwrap()
                .miner_budget_ns,
            0
        );
    }
    struct ShortWriter {
        bytes: Vec<u8>,
        fail_after: Option<usize>,
        chunk: usize,
    }
    impl Write for ShortWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.fail_after.is_some_and(|n| self.bytes.len() >= n) {
                return Err(std::io::Error::other("injected"));
            }
            let capacity = self.fail_after.map_or(usize::MAX, |n| n - self.bytes.len());
            let n = bytes.len().min(self.chunk).min(capacity);
            self.bytes.extend_from_slice(&bytes[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn ordinary_short_writes_are_completed_exactly() {
        let mut wire = Wire::new(ShortWriter {
            bytes: Vec::new(),
            fail_after: None,
            chunk: 2,
        })
        .unwrap();
        wire.parts(WINNER, &[b"123", b"4567"]).unwrap();
        let mut expected = MAGIC.to_vec();
        expected.push(WINNER);
        expected.extend(7_u32.to_le_bytes());
        expected.extend(b"1234567");
        assert_eq!(wire.output.bytes, expected);
    }
    #[test]
    fn interrupted_frame_retains_prefix_and_fails() {
        let mut wire = Wire::new(ShortWriter {
            bytes: Vec::new(),
            fail_after: Some(16),
            chunk: 3,
        })
        .unwrap();
        assert!(wire.parts(WINNER, &[b"1234567890"]).is_err());
        assert_eq!(wire.output.bytes.len(), 16);
        assert!(wire.parts(SEAL, &[b"{}"]).is_err());
    }
    #[test]
    fn oversized_frame_does_not_write_a_false_prefix() {
        let mut wire = Wire::new(Vec::new()).unwrap();
        assert!(wire.parts(WINNER, &[&vec![0; FRAME_LIMIT + 1]]).is_err());
        assert_eq!(wire.output, MAGIC);
    }
}
