pub fn precheck_proof_statement(
    challenge: Hash,
    expected_task: Hash,
    target: Hash,
    bytes: &[u8],
) -> Result<(), WorkError> {
    precheck_proof_encoding(bytes)?;
    if target == [0; 32] {
        return Err(WorkError::Target);
    }
    let actual_task = hash(
        b"task",
        &[
            &bytes[4..4 + CELLS * 4],
            &bytes[4 + CELLS * 4..4 + CELLS * 8],
        ],
    );
    if actual_task != expected_task {
        return Err(WorkError::Task);
    }
    let trace_claim = &bytes[4 + 3 * CELLS * 4..];
    if hash(b"ticket", &[&challenge, trace_claim]) > target {
        return Err(WorkError::Target);
    }
    Ok(())
}
