// Compiled beside the unchanged original binding types and methods.
// Wrapper transport/type parsing and observation are the only adapter operations.
pub(super) fn observe(wire: &[u8]) -> CellResultV1<[u8; 72]> {
    assert!(&wire[..4] == b"TCB1");
    let index = u32::from_le_bytes(wire[4..8].try_into().unwrap());
    let id = wire[8..40].try_into().unwrap();
    let family_end = 41 + usize::from(wire[40]);
    let mut digests = wire[family_end..family_end + 160].chunks_exact(32);
    let mut next = || digests.next().unwrap().try_into().unwrap();
    let context = CellContextV1 {
        family: String::from_utf8(wire[41..family_end].to_vec()).unwrap(),
        base: next(),
        parent: next(),
        tokenizer: next(),
        layout: next(),
        runtime: next(),
    };
    let manifest = CellManifestV1::decode(&wire[family_end + 160..])?;
    let binding = CellRs46ManifestBindingV1::new(&manifest, id, &context)?.chunk(index)?;
    let mut row = [0; 72];
    row[..32].copy_from_slice(&binding.manifest);
    row[32..36].copy_from_slice(&binding.index.to_le_bytes());
    row[36..40].copy_from_slice(&binding.chunk.size.to_le_bytes());
    row[40..].copy_from_slice(&binding.chunk.sha256);
    Ok(row)
}
