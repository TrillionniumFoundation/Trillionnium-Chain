//! Adapter for the unchanged original LocalPlanGuardV0 and strict crypto crate.
//! This new local provider profile is explicit; it is not an old production
//! signature contract. All guard policy and receipts call the original API.

use std::error::Error;
use std::fmt;
use std::io::{self, BufRead, Write};
use trnm_control_plane::*;
use trnm_crypto_primitives as crypto;

// Only this comparison process has a 1 MiB transport budget.
const MAX_FRAME_BYTES: usize = 1024 * 1024;
const MALFORMED: u32 = 100;
type Parsed<T> = Result<T, u32>;
const SIGNER_DOMAIN: &[u8] = b"trnm.control.local-ed25519-provider.signer.v1";
const SIGNATURE_DOMAIN: &[u8] = b"trnm.control.local-ed25519-provider.signature.v1";
const MESSAGE_DOMAIN: &[u8] = b"trnm.control.local-ed25519-provider.plan.v1";

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, count: usize) -> Parsed<&'a [u8]> {
        let end = self.position.checked_add(count).ok_or(MALFORMED)?;
        let result = self.bytes.get(self.position..end).ok_or(MALFORMED)?;
        self.position = end;
        Ok(result)
    }

    fn u64(&mut self) -> Parsed<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().map_err(|_| MALFORMED)?))
    }

    fn count(&mut self) -> Parsed<usize> {
        usize::try_from(self.u64()?).map_err(|_| MALFORMED)
    }

    fn module(&mut self) -> Parsed<u16> {
        u16::try_from(self.u64()?).map_err(|_| MALFORMED)
    }

    fn i128(&mut self) -> Parsed<i128> {
        Ok(i128::from_le_bytes(self.take(16)?.try_into().map_err(|_| MALFORMED)?))
    }

    fn digest(&mut self) -> Parsed<Digest32V0> {
        Ok(Digest32V0(self.take(32)?.try_into().map_err(|_| MALFORMED)?))
    }

    fn vector(&mut self) -> Parsed<Vec<u8>> {
        let count = self.count()?;
        Ok(self.take(count)?.to_vec())
    }

    fn boolean(&mut self) -> Parsed<bool> {
        match self.u64()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(MALFORMED),
        }
    }

    fn finish(&self) -> Parsed<()> {
        if self.position == self.bytes.len() { Ok(()) } else { Err(MALFORMED) }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }
}

fn parameter_class(value: u64) -> Parsed<ParameterClassV0> {
    match value {
        0 => Ok(ParameterClassV0::OperationalLocal),
        1 => Ok(ParameterClassV0::DeterminismCritical),
        2 => Ok(ParameterClassV0::ConsensusCritical),
        _ => Err(MALFORMED),
    }
}

fn action(r: &mut Reader<'_>) -> Parsed<PlanActionV0> {
    match r.u64()? {
        0 => Ok(PlanActionV0::SetBoundedInteger {
            module_id: r.module()?, class: parameter_class(r.u64()?)?,
            value: r.i128()?, parameter: r.vector()?,
        }),
        1 => Ok(PlanActionV0::PlaceIsolatedWorker {
            module_id: r.module()?, worker_profile_digest: r.digest()?,
            placement_digest: r.digest()?,
        }),
        2 => {
            use ForbiddenAuthorityActionV0::*;
            Ok(PlanActionV0::Forbidden(match r.u64()? {
                0 => Sign, 1 => Vote, 2 => Finalize, 3 => ModifySafetyRules,
                4 => CreateStateRoot, 5 => BypassAdmission, 6 => EraseEvidence,
                7 => RewriteHistory, 8 => ForceIncompatibleStartup,
                9 => ActivateProduction, _ => return Err(MALFORMED),
            }))
        }
        _ => Err(MALFORMED),
    }
}

fn plan(r: &mut Reader<'_>) -> Parsed<OptimizationPlanV1> {
    let plan_id = r.digest()?;
    let source_graph_digest = r.digest()?;
    let contract_set_digest = r.digest()?;
    let workload_assumption_digest = r.digest()?;
    let expected_effect_digest = r.digest()?;
    let rollback_plan_digest = r.digest()?;
    let issued_generation = r.u64()?;
    let not_before_height = r.u64()?;
    let expires_after_height = r.u64()?;
    let signer_id = r.digest()?;
    let signature_digest = r.digest()?;
    let canonical_plan_digest = r.digest()?;
    let count = r.count()?;
    if count > r.remaining() / 24 { return Err(MALFORMED); }
    let mut actions = Vec::with_capacity(count);
    for _ in 0..count {
        let size = r.count()?;
        let mut nested = Reader::new(r.take(size)?);
        let value = action(&mut nested)?;
        nested.finish()?;
        actions.push(value);
    }
    Ok(OptimizationPlanV1 { plan_id, source_graph_digest, contract_set_digest,
        workload_assumption_digest, expected_effect_digest, rollback_plan_digest,
        issued_generation, not_before_height, expires_after_height, actions,
        signer_id, signature_digest, canonical_plan_digest })
}

fn bound(r: &mut Reader<'_>) -> Parsed<ParameterBoundV0> {
    Ok(ParameterBoundV0 {
        module_id: r.module()?, class: parameter_class(r.u64()?)?,
        minimum: r.i128()?, maximum: r.i128()?, parameter: r.vector()?,
    })
}


#[derive(Debug)]
struct ProviderError(u64);
impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "local Ed25519 provider error {}", self.0)
    }
}
impl Error for ProviderError {}

struct LocalEd25519Provider {
    public_key: [u8; 32],
    signatures: Vec<[u8; 64]>,
}

fn hex(raw: &[u8]) -> String {
    raw.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl PlanSignatureVerifierV0 for LocalEd25519Provider {
    type Error = ProviderError;
    fn verify_plan_signature(&self, plan: &OptimizationPlanV1) -> Result<(), Self::Error> {
        let signer = Digest32V0::hash(SIGNER_DOMAIN, &[&self.public_key]);
        if plan.signer_id != signer { return Err(ProviderError(1)); }
        let signature = self.signatures.iter().find(|bytes|
            Digest32V0::hash(SIGNATURE_DOMAIN, &[&bytes[..]]) == plan.signature_digest)
            .ok_or(ProviderError(2))?;
        let mut message = MESSAGE_DOMAIN.to_vec();
        message.extend_from_slice(&plan.canonical_plan_digest.0);
        crypto::verify_hex_strict(&hex(&self.public_key), &message, &hex(signature))
            .map_err(|_| ProviderError(3))
    }
}

struct Evaluation {
    height: u64,
    configuration: Digest32V0,
    invariant: Digest32V0,
    governance: Option<GovernanceAuthorizationV0>,
    determinism: Option<DeterminismEvidenceV0>,
    plan: OptimizationPlanV1,
}

fn evaluation(r: &mut Reader<'_>) -> Parsed<Evaluation> {
    let height = r.u64()?;
    let configuration = r.digest()?;
    let invariant = r.digest()?;
    let governance = if r.boolean()? {
        Some(GovernanceAuthorizationV0 {
            plan_digest: r.digest()?, activation_height: r.u64()?,
            validator_set_digest: r.digest()?, authorization_digest: r.digest()?,
        })
    } else { None };
    let determinism = if r.boolean()? {
        Some(DeterminismEvidenceV0 {
            plan_digest: r.digest()?, shadow_replay_digest: r.digest()?,
            worker_invariance_digest: r.digest()?, pre_root: r.digest()?,
            post_root: r.digest()?,
        })
    } else { None };
    let plan = plan(r)?;
    Ok(Evaluation { height, configuration, invariant, governance, determinism, plan })
}

fn word(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn receipt_bytes(receipt: &ActionReceiptV1) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&receipt.plan_digest.0);
    word(&mut bytes, receipt.accepted_generation);
    for value in [receipt.source_graph_digest, receipt.resulting_configuration_digest,
                  receipt.invariant_result_digest] {
        bytes.extend_from_slice(&value.0);
    }
    word(&mut bytes, u64::from(receipt.accepted));
    word(&mut bytes, receipt.action_results.len() as u64);
    bytes.extend_from_slice(&receipt.receipt_digest.0);
    for result in &receipt.action_results {
        bytes.extend_from_slice(&result.action_digest.0);
        let (decision, error) = match result.decision {
            ActionDecisionV0::Accepted => (0, 0),
            ActionDecisionV0::Rejected(error) => (1, u64::from(error as u16)),
        };
        word(&mut bytes, decision);
        word(&mut bytes, error);
    }
    bytes
}

fn execute(frame: &[u8]) -> Parsed<Vec<u8>> {
    let mut r = Reader::new(frame);
    if r.take(8)? != b"NCPG0001" { return Err(MALFORMED); }
    let graph = r.digest()?;
    let contracts = r.digest()?;
    let generation = r.u64()?;
    let public_key = r.take(32)?.try_into().map_err(|_| MALFORMED)?;
    let bound_count = r.count()?;
    let signature_count = r.count()?;
    let evaluation_count = r.count()?;
    if bound_count > r.remaining() / 64 { return Err(MALFORMED); }
    let mut bounds = Vec::with_capacity(bound_count);
    for _ in 0..bound_count {
        let size = r.count()?;
        let mut value = Reader::new(r.take(size)?);
        bounds.push(bound(&mut value)?);
        value.finish()?;
    }
    if signature_count > r.remaining() / 64 { return Err(MALFORMED); }
    let mut signatures = Vec::with_capacity(signature_count);
    for _ in 0..signature_count {
        signatures.push(r.take(64)?.try_into().map_err(|_| MALFORMED)?);
    }
    if evaluation_count > r.remaining() / 8 { return Err(MALFORMED); }
    let mut evaluations = Vec::with_capacity(evaluation_count);
    for _ in 0..evaluation_count {
        let size = r.count()?;
        let mut value = Reader::new(r.take(size)?);
        evaluations.push(evaluation(&mut value)?);
        value.finish()?;
    }
    r.finish()?;
    // Typed transport is now complete. Constructor and every evaluation below
    // invoke the unchanged production types and functions; no copied guard.
    let provider = LocalEd25519Provider { public_key, signatures };
    let guard = LocalPlanGuardV0::new(provider, graph, contracts, generation, bounds)
        .map_err(|error| error as u32)?;
    let mut output = vec![0; 8];
    word(&mut output, evaluation_count as u64);
    for value in evaluations {
        let (category, error, receipt) = match guard.evaluate(&value.plan, value.height,
            value.governance, value.determinism, value.configuration, value.invariant) {
            Ok(receipt) => (0, 0, receipt_bytes(&receipt)),
            Err(ControlPlaneHostErrorV0::Protocol(error)) => (1, error as u64, Vec::new()),
            Err(ControlPlaneHostErrorV0::Signature(error)) => (2, error.0, Vec::new()),
        };
        word(&mut output, category);
        word(&mut output, error);
        word(&mut output, receipt.len() as u64);
        output.extend_from_slice(&receipt);
    }
    let size = output.len() as u64;
    output[..8].copy_from_slice(&size.to_le_bytes());
    Ok(output)
}

fn decode_hex(line: &[u8]) -> Parsed<Vec<u8>> {
    if line.len() % 2 != 0 || line.len() > 2 * MAX_FRAME_BYTES { return Err(MALFORMED); }
    fn digit(c: u8) -> Parsed<u8> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'), b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10), _ => Err(MALFORMED),
        }
    }
    line.chunks_exact(2).map(|p| Ok((digit(p[0])? << 4) | digit(p[1])?)).collect()
}

fn bounded_line(reader: &mut impl BufRead) -> io::Result<Option<Parsed<Vec<u8>>>> {
    let mut line = Vec::new();
    let mut oversized = false;
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return Ok(if line.is_empty() && !oversized { None }
                else if oversized { Some(Err(MALFORMED)) } else { Some(Ok(line)) });
        }
        let newline = buffer.iter().position(|byte| *byte == b'\n');
        let used = newline.map_or(buffer.len(), |index| index + 1);
        let data_len = if newline.is_some() { used - 1 } else { used };
        if !oversized {
            if data_len > 2 * MAX_FRAME_BYTES + 1 - line.len() {
                line.clear();
                oversized = true;
            } else { line.extend_from_slice(&buffer[..data_len]); }
        }
        reader.consume(used);
        if newline.is_some() {
            if line.last() == Some(&b'\r') { line.pop(); }
            return Ok(Some(if oversized { Err(MALFORMED) } else { Ok(line) }));
        }
    }
}

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let stdout = io::stdout();
    let mut writer = io::BufWriter::new(stdout.lock());
    while let Some(line) = bounded_line(&mut reader)? {
        match line.and_then(|value| decode_hex(&value)).and_then(|frame| execute(&frame)) {
            Ok(output) => {
                write!(writer, "0 ")?;
                if output.is_empty() { write!(writer, "-")?; }
                for byte in output { write!(writer, "{byte:02x}")?; }
                writeln!(writer)?;
            }
            Err(status) => writeln!(writer, "{status} -")?,
        }
        writer.flush()?;
    }
    Ok(())
}
