//! Fixed-size offline native work bridge. No process network, key or chain authority.
use std::io::{self, Read, Write};
use std::time::Instant;
use trnm_crypto_primitives::pon_work::*;
fn h(bytes: &[u8]) -> Result<Hash, &'static str> {
    bytes.try_into().map_err(|_| "LENGTH")
}
fn input_length(mode: &str) -> Result<usize, &'static str> {
    match mode {
        "prove" => Ok(32 + 2 * CELLS * 4),
        "verify" | "diagnose-production" | "diagnose-reference" | "diagnose-limb" => {
            Ok(96 + PROOF_BYTES)
        }
        "forge-transcript" => Ok(104 + 2 * CELLS * 4),
        _ => Err("OPERATION"),
    }
}
fn result_name(result: &Result<VerifiedWork, WorkError>) -> &'static str {
    match result {
        Ok(_) => "Accepted",
        Err(WorkError::Length) => "Length",
        Err(WorkError::Version) => "Version",
        Err(WorkError::Field) => "Field",
        Err(WorkError::Task) => "Task",
        Err(WorkError::Transcript) => "Transcript",
        Err(WorkError::Product) => "Product",
        Err(WorkError::Target) => "Target",
        Err(WorkError::NoiseBudget) => "NoiseBudget",
    }
}
fn diagnose(mode: &str, input: &[u8]) -> Result<Vec<u8>, &'static str> {
    let challenge = h(&input[..32])?;
    let task = h(&input[32..64])?;
    let target = h(&input[64..96])?;
    let started = Instant::now();
    let result = match mode {
        "diagnose-production" => verify(challenge, task, target, &input[96..]),
        "diagnose-reference" => verify_reference(challenge, task, target, &input[96..]),
        "diagnose-limb" => verify_limb(challenge, task, target, &input[96..]),
        _ => return Err("OPERATION"),
    };
    let elapsed = started.elapsed().as_nanos();
    Ok(format!(
        "{{\"schema\":\"pon-work-verifier-diagnostic-v1\",\"mode\":\"{mode}\",\"result\":\"{}\",\"elapsed_ns\":{elapsed}}}\n",
        result_name(&result)
    )
    .into_bytes())
}

// This negative-input constructor never calls prove, PreparedTask or evaluate.
// Canonical A/B and an invented zero C suffice for the prefilter. Passing the
// ticket threshold is not a claim that the transcript or product is valid.
fn forge_transcript(input: &[u8]) -> Result<Vec<u8>, &'static str> {
    let started = Instant::now();
    let challenge = h(&input[..32])?;
    let expected_task = h(&input[32..64])?;
    let target = h(&input[64..96])?;
    let limit_bytes = input[input.len() - 8..].try_into().map_err(|_| "LENGTH")?;
    let limit = u64::from_le_bytes(limit_bytes);
    if !(1..=4096).contains(&limit) {
        return Err("BUDGET");
    }
    let material = &input[96..input.len() - 8];
    let values: Vec<u32> = material
        .chunks_exact(4)
        .map(|word| u32::from_le_bytes(word.try_into().expect("four-byte word")))
        .collect();
    let task = task_id(&values[..CELLS], &values[CELLS..]).map_err(|_| "WORK")?;
    if task != expected_task {
        return Err("TASK");
    }
    let mut proof = Vec::with_capacity(PROOF_BYTES);
    proof.extend_from_slice(b"PNW1");
    proof.extend_from_slice(material);
    proof.resize(PROOF_BYTES, 0); // Claimed C and the as-yet unselected trace.
    let setup_ns = started.elapsed().as_nanos();
    let search_started = Instant::now();
    let mut attempts = Vec::new();
    let mut chosen = None;
    for nonce in 0..limit {
        let trace = hash(b"from-zero-fake-trace-v1", &[&challenge, &nonce.to_le_bytes()]);
        let ticket = hash(b"ticket", &[&challenge, &trace]);
        let selected = target != [0; 32] && ticket <= target;
        attempts.push((nonce, trace, ticket, selected));
        if selected {
            chosen = Some(trace);
            break;
        }
    }
    let search_ns = search_started.elapsed().as_nanos();
    if let Some(trace) = chosen {
        proof[PROOF_BYTES - 32..].copy_from_slice(&trace);
    }
    let total_ns = started.elapsed().as_nanos();
    // JSON encoding and process IO are outside these timers; the collector also
    // retains enclosing process wall time rather than labelling it kernel time.
    let attempts = attempts
        .iter()
        .map(|(nonce, trace, ticket, selected)| {
            format!(
                "{{\"nonce\":{nonce},\"trace\":\"{}\",\"ticket\":\"{}\",\"selected\":{selected}}}",
                hex::encode(trace),
                hex::encode(ticket)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let proof = if chosen.is_some() {
        format!("\"{}\"", hex::encode(proof))
    } else {
        "null".to_owned()
    };
    Ok(format!(
        "{{\"schema\":\"pon-work-from-zero-construction-v1\",\"challenge\":\"{}\",\"task\":\"{}\",\"target\":\"{}\",\"attempt_limit\":{limit},\"setup_ns\":{setup_ns},\"search_ns\":{search_ns},\"total_ns\":{total_ns},\"outcome\":\"{}\",\"attempts\":[{attempts}],\"proof_hex\":{proof},\"honest_proof_acquired\":false,\"acceptance_granted\":false}}\n",
        hex::encode(challenge),
        hex::encode(task),
        hex::encode(target),
        if chosen.is_some() { "prefilter-candidate" } else { "exhausted" }
    )
    .into_bytes())
}
fn run() -> Result<(), &'static str> {
    let mode = std::env::args().nth(1).ok_or("OPERATION")?;
    let expected = input_length(&mode)?;
    let mut input = Vec::new();
    io::stdin()
        .take(expected as u64 + 1)
        .read_to_end(&mut input)
        .map_err(|_| "IO")?;
    if input.len() != expected {
        return Err("LENGTH");
    }
    let challenge = h(&input[..32])?;
    let output = if mode == "prove" {
        let elements: Vec<u32> = input[32..]
            .chunks_exact(4)
            .map(|b| u32::from_le_bytes(b.try_into().expect("four-byte chunk")))
            .collect();
        prove(challenge, &elements[..CELLS], &elements[CELLS..]).map_err(|_| "WORK")?
    } else if mode == "verify" {
        let task = h(&input[32..64])?;
        let target = h(&input[64..96])?;
        verify(challenge, task, target, &input[96..]).map_err(|_| "WORK")?;
        hash(b"native-work-verification", &[&input]).to_vec()
    } else if mode == "forge-transcript" {
        forge_transcript(&input)?
    } else {
        diagnose(&mode, &input)?
    };
    io::stdout().write_all(&output).map_err(|_| "IO")?;
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_diagnostic_modes_do_not_change_legacy_frame_lengths() {
        assert_eq!(input_length("prove"), Ok(32 + 8 * CELLS));
        assert_eq!(input_length("verify"), Ok(96 + PROOF_BYTES));
        assert_eq!(input_length("forge-transcript"), Ok(104 + 8 * CELLS));
        assert_eq!(input_length("verify-unknown"), Err("OPERATION"));
    }

    #[test]
    fn diagnostic_kernels_reject_fabricated_transcripts_without_verified_work() {
        let material = vec![0; CELLS];
        let task = task_id(&material, &material).unwrap();
        let challenge = [23; 32];
        let mut proof = b"PNW1".to_vec();
        proof.resize(PROOF_BYTES, 0);
        let trace = hash(b"from-zero-fake-trace-v1", &[&challenge, &0u64.to_le_bytes()]);
        proof[PROOF_BYTES - 32..].copy_from_slice(&trace);
        let mut input = challenge.to_vec();
        input.extend(task);
        input.extend([255; 32]);
        input.extend(&proof);
        for mode in ["diagnose-production", "diagnose-reference", "diagnose-limb"] {
            let output = String::from_utf8(diagnose(mode, &input).unwrap()).unwrap();
            assert!(output.contains("\"result\":\"Transcript\""));
            input[64..96].fill(0);
            let output = String::from_utf8(diagnose(mode, &input).unwrap()).unwrap();
            assert!(output.contains("\"result\":\"Target\""));
            input[64..96].fill(255);
        }
        let mut construction = input[..96].to_vec();
        construction.extend(vec![0; 8 * CELLS]);
        construction.extend(1u64.to_le_bytes());
        let output = String::from_utf8(forge_transcript(&construction).unwrap()).unwrap();
        assert!(output.contains("\"proof_hex\":\""));
        construction[64..96].fill(0);
        let output = String::from_utf8(forge_transcript(&construction).unwrap()).unwrap();
        assert!(output.contains("\"outcome\":\"exhausted\""));
        assert!(output.contains("\"proof_hex\":null"));
        let end = construction.len();
        construction[end - 8..].copy_from_slice(&4097u64.to_le_bytes());
        assert_eq!(forge_transcript(&construction).unwrap_err(), "BUDGET");
    }
}
