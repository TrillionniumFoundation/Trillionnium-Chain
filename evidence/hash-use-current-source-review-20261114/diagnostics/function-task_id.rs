pub fn task_id(a: &[u32], b: &[u32]) -> Result<Hash, WorkError> {
    validate(a)?;
    validate(b)?;
    Ok(hash(b"task", &[&field_bytes(a), &field_bytes(b)]))
}
