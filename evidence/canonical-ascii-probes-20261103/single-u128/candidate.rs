pub fn unescaped_ascii_json(bytes: &[u8]) -> bool {
    const HIGH: u128 = u128::from_le_bytes([0x80; 16]);
    const ONE: u128 = u128::from_le_bytes([1; 16]);
    let mut chunks = bytes.chunks_exact(16);
    for chunk in &mut chunks {
        let mut word_bytes = [0; 16];
        word_bytes.copy_from_slice(chunk);
        let word = u128::from_le_bytes(word_bytes);
        if word & HIGH != 0 { return false; }
        let control = word.wrapping_sub(u128::from_le_bytes([0x20; 16]));
        let quote = (word ^ u128::from_le_bytes([0x22; 16])).wrapping_sub(ONE);
        let backslash = (word ^ u128::from_le_bytes([0x5c; 16])).wrapping_sub(ONE);
        if (control | quote | backslash) & HIGH != 0 { return false; }
    }
    {

    const HIGH: u64 = 0x8080_8080_8080_8080;
    const ONE: u64 = 0x0101_0101_0101_0101;
    let mut chunks = chunks.remainder().chunks_exact(8);
    for chunk in &mut chunks {
        let mut word_bytes = [0; 8];
        word_bytes.copy_from_slice(chunk);
        let word = u64::from_le_bytes(word_bytes);
        if word & HIGH != 0 {
            return false;
        }
        let control = word.wrapping_sub(0x2020_2020_2020_2020);
        let quote = (word ^ 0x2222_2222_2222_2222).wrapping_sub(ONE);
        let backslash = (word ^ 0x5c5c_5c5c_5c5c_5c5c).wrapping_sub(ONE);
        if (control | quote | backslash) & HIGH != 0 {
            return false;
        }
    }
    chunks
        .remainder()
        .iter()
        .all(|&byte| (0x20..=0x7f).contains(&byte) && byte != b'"' && byte != b'\\')

    }
}
