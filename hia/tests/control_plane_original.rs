//! Transport adapter for the complete, unchanged original control-plane crate.
//! All business validation and canonical hashing below call its public API.

use std::io::{self, BufRead, Write};
use trnm_control_plane::*;

// This is the comparison driver's transport budget, not an original API limit.
const MAX_FRAME_BYTES: usize = 1024 * 1024;
const MALFORMED: u32 = 100;
type Parsed<T> = Result<T, u32>;

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

fn protocol_error(value: u64) -> Parsed<ControlPlaneErrorV0> {
    use ControlPlaneErrorV0::*;
    Ok(match value {
        1 => InvalidDescriptor,
        2 => DuplicateCapability,
        3 => GenerationRollback,
        4 => DescriptorSubstitution,
        5 => InvalidMeasurement,
        6 => UnknownModule,
        7 => MeasurementSubstitution,
        8 => InvalidPlan,
        9 => InvalidParameter,
        10 => InvalidParameterBound,
        11 => DuplicateParameterBound,
        12 => InvalidGuardConfiguration,
        13 => SourceGraphMismatch,
        14 => GenerationMismatch,
        15 => PlanOutsideActivationWindow,
        16 => InvalidReceiptFacts,
        17 => ForbiddenAuthorityAction,
        18 => InvalidPlacement,
        19 => UnknownParameter,
        20 => ParameterOutOfBounds,
        21 => MissingDeterminismEvidence,
        22 => MissingGovernanceAuthorization,
        23 => ReceiptOutOfBounds,
        24 => DuplicatePlanAction,
        25 => UnsupportedPlanAction,
        26 => GenerationOverflow,
        _ => return Err(MALFORMED),
    })
}

fn descriptor(r: &mut Reader<'_>) -> Parsed<ModuleDescriptorV0> {
    let module_id = r.module()?;
    let generation = r.u64()?;
    let count = r.count()?;
    let contract_digest = r.digest()?;
    let implementation_digest = r.digest()?;
    let dependency_graph_digest = r.digest()?;
    let configuration_digest = r.digest()?;
    let invariant_digest = r.digest()?;
    let descriptor_digest = r.digest()?;
    if count > r.remaining() / 32 { return Err(MALFORMED); }
    let mut capability_digests = Vec::with_capacity(count);
    for _ in 0..count { capability_digests.push(r.digest()?); }
    Ok(ModuleDescriptorV0 { module_id, generation, contract_digest,
        implementation_digest, dependency_graph_digest, configuration_digest,
        capability_digests, invariant_digest, descriptor_digest })
}

fn measurement(r: &mut Reader<'_>) -> Parsed<WorkloadMeasurementV0> {
    Ok(WorkloadMeasurementV0 {
        workload_digest: r.digest()?, validity_region_digest: r.digest()?,
        evidence_digest: r.digest()?, committed_goodput_milli: r.u64()?,
        finality_p50_micros: r.u64()?, finality_p95_micros: r.u64()?,
        finality_p99_micros: r.u64()?, cpu_milli: r.u64()?,
        memory_bytes: r.u64()?, disk_bytes: r.u64()?, network_bytes: r.u64()?,
        queue_pressure_milli: u32::try_from(r.u64()?).map_err(|_| MALFORMED)?,
        error_count: r.u64()?, drop_count: r.u64()?, recovery_cost_milli: r.u64()?,
    })
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

fn receipt(r: &mut Reader<'_>) -> Parsed<ActionReceiptV1> {
    let plan_digest = r.digest()?;
    let accepted_generation = r.u64()?;
    let source_graph_digest = r.digest()?;
    let resulting_configuration_digest = r.digest()?;
    let invariant_result_digest = r.digest()?;
    let accepted = r.boolean()?;
    let count = r.count()?;
    let receipt_digest = r.digest()?;
    if count > r.remaining() / 48 { return Err(MALFORMED); }
    let mut action_results = Vec::with_capacity(count);
    for _ in 0..count {
        let action_digest = r.digest()?;
        let decision = r.u64()?;
        let error = r.u64()?;
        let decision = match decision {
            0 if error == 0 => ActionDecisionV0::Accepted,
            1 => ActionDecisionV0::Rejected(protocol_error(error)?),
            _ => return Err(MALFORMED),
        };
        action_results.push(ActionResultV0 { action_digest, decision });
    }
    Ok(ActionReceiptV1 { plan_digest, accepted_generation, source_graph_digest,
        resulting_configuration_digest, invariant_result_digest, action_results,
        accepted, receipt_digest })
}

enum RegistryCommand {
    Register(ModuleDescriptorV0),
    Observe(u16, WorkloadMeasurementV0),
    Descriptor(u16),
}

fn encode_descriptor(value: &ModuleDescriptorV0) -> Vec<u8> {
    let mut bytes = Vec::new();
    for scalar in [u64::from(value.module_id), value.generation,
                   value.capability_digests.len() as u64] {
        bytes.extend_from_slice(&scalar.to_le_bytes());
    }
    for digest in [value.contract_digest, value.implementation_digest,
                   value.dependency_graph_digest, value.configuration_digest,
                   value.invariant_digest, value.descriptor_digest] {
        bytes.extend_from_slice(&digest.0);
    }
    for digest in &value.capability_digests {
        bytes.extend_from_slice(&digest.0);
    }
    bytes
}

fn registry(r: &mut Reader<'_>) -> Parsed<Vec<u8>> {
    let count = r.count()?;
    if count > r.remaining() / 16 { return Err(MALFORMED); }
    let mut commands = Vec::with_capacity(count);
    // Parse the entire typed transport before constructing or changing a registry.
    for _ in 0..count {
        let op = r.u64()?;
        let size = r.count()?;
        let mut payload = Reader::new(r.take(size)?);
        let command = match op {
            0 => RegistryCommand::Register(descriptor(&mut payload)?),
            1 => RegistryCommand::Observe(payload.module()?, measurement(&mut payload)?),
            2 => RegistryCommand::Descriptor(payload.module()?),
            _ => return Err(MALFORMED),
        };
        payload.finish()?;
        commands.push(command);
    }
    r.finish()?;
    let mut owner = ObserverRegistryV0::default();
    let mut output = vec![0; 8];
    output.extend_from_slice(&(count as u64).to_le_bytes());
    for command in commands {
        let (status, value) = match command {
            RegistryCommand::Register(value) => (
                owner.register(value).err().map_or(0, |error| error as u64), Vec::new()),
            RegistryCommand::Observe(module, value) => (
                owner.observe(module, value).err().map_or(0, |error| error as u64), Vec::new()),
            RegistryCommand::Descriptor(module) => (
                0, owner.descriptor(module).map_or_else(Vec::new, encode_descriptor)),
        };
        output.extend_from_slice(&status.to_le_bytes());
        output.extend_from_slice(&(value.len() as u64).to_le_bytes());
        output.extend_from_slice(&value);
    }
    let size = output.len() as u64;
    output[..8].copy_from_slice(&size.to_le_bytes());
    Ok(output)
}

fn execute(bytes: &[u8]) -> Parsed<Vec<u8>> {
    if bytes.len() > MAX_FRAME_BYTES { return Err(MALFORMED); }
    let mut r = Reader::new(bytes);
    let magic = r.take(8)?;
    if magic == b"NCPR0001" { return registry(&mut r); }
    if magic != b"NCPL0001" { return Err(MALFORMED); }
    let op = r.u64()?;
    let digest = match op {
        0 | 1 => {
            let value = descriptor(&mut r)?;
            r.finish()?;
            if op == 1 { value.validate().map_err(|e| e as u32)?; }
            Some(value.canonical_digest())
        }
        2 => {
            let value = measurement(&mut r)?;
            r.finish()?;
            value.validate().map_err(|e| e as u32)?;
            None
        }
        3 => {
            let value = action(&mut r)?;
            r.finish()?;
            Some(value.canonical_digest())
        }
        4 | 5 => {
            let value = plan(&mut r)?;
            r.finish()?;
            if op == 5 { value.validate_shape().map_err(|e| e as u32)?; }
            Some(value.canonical_digest())
        }
        6 => {
            let value = bound(&mut r)?;
            r.finish()?;
            value.validate().map_err(|e| e as u32)?;
            None
        }
        7 => {
            let value = receipt(&mut r)?;
            r.finish()?;
            Some(value.canonical_digest())
        }
        8 => {
            let domain_size = r.count()?;
            let count = r.count()?;
            let domain = r.take(domain_size)?;
            if count > r.remaining() / 8 { return Err(MALFORMED); }
            let mut parts = Vec::with_capacity(count);
            for _ in 0..count {
                let size = r.count()?;
                parts.push(r.take(size)?);
            }
            r.finish()?;
            Some(Digest32V0::hash(domain, &parts))
        }
        _ => return Err(MALFORMED),
    };
    Ok(digest.map_or_else(Vec::new, |value| value.0.to_vec()))
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
