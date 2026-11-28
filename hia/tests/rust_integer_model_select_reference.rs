// Appended to the isolated original ReadState/prefix_rows/load_model source.
// The row decoder above is the original Execution State qualification adapter.
fn main() -> io::Result<()> {
    let mut requests = Vec::new();
    io::stdin().read_to_end(&mut requests)?;
    let mut stream = 0;
    let mut out = io::stdout().lock();
    while stream < requests.len() {
        let id: Hash = take(&requests, &mut stream, 32).try_into().unwrap();
        let family: Hash = take(&requests, &mut stream, 32).try_into().unwrap();
        let extent = u32_at(&requests, &mut stream);
        let raw = take(&requests, &mut stream, extent);
        let mut cursor = 0;
        let count = selector_u64(raw, &mut cursor);
        let mut state = State::new();
        let mut positions = BTreeMap::new();
        for _ in 0..count {
            let key_len = selector_u64(raw, &mut cursor);
            let data_len = selector_u64(raw, &mut cursor);
            let key = String::from_utf8(take(raw, &mut cursor, key_len).to_vec()).unwrap();
            positions.insert(key.clone(), [cursor, data_len]);
            let value = decode_value(take(raw, &mut cursor, data_len));
            assert!(state.insert(key, value).is_none());
        }
        assert_eq!(cursor, raw.len());
        let old_prefix = prefix(id, false);
        let new_prefix = prefix(id, true);
        let mut read = ReadState(&state);
        let old = read.scan(&old_prefix);
        let new = read.scan(&new_prefix);
        let loaded = load_model(&mut read, id, family);
        let full = match &loaded {
            Ok(_) => "OK",
            Err(reason) => reason,
        };
        let (status, metadata) = match full {
            "FACTOR_MODEL_COLLISION" => (1, None),
            "FACTOR_MODEL_MISSING" => (2, None),
            _ => {
                let selected = if new.is_empty() { old_prefix } else { new_prefix };
                let [at, len] = positions[&format!("{selected}meta")];
                (0, Some([old.len(), new.len(), at, len]))
            }
        };
        assert_eq!(state.len(), count);
        writeln!(out, "{}", json!({
            "status": status, "metadata": metadata, "original_load": full,
            "old_count": old.len(), "new_count": new.len(),
        }))?;
    }
    Ok(())
}

fn selector_u64(data: &[u8], at: &mut usize) -> usize {
    let n = u64::from_le_bytes(take(data, at, 8).try_into().unwrap());
    usize::try_from(n).unwrap()
}
