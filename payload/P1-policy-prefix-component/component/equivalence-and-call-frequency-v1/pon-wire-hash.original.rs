pub fn hash(tag: &[u8], parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    h.update(b"TRNM-PON1\0");
    h.update((tag.len() as u16).to_le_bytes());
    h.update(tag);
    for p in parts {
        h.update((p.len() as u32).to_le_bytes());
        h.update(p);
    }
    h.finalize().into()
}