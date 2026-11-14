pub fn verify(
    challenge: Hash,
    expected_task: Hash,
    target: Hash,
    bytes: &[u8],
) -> Result<VerifiedWork, WorkError> {
    relation_only(verify_with_progress(
        challenge,
        expected_task,
        target,
        bytes,
        &mut no_cancellation,
    ))
}
