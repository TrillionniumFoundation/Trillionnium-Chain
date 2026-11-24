// Test-only independent caller: original State, ReadState::scan and load_model.
use std::os::raw::c_uchar;

unsafe extern "C" {
    fn trnm_integer_model_snapshot_load_v1(
        request: *const c_uchar,
        request_len: usize,
        response: *mut c_uchar,
        response_len: usize,
        scratch: *mut c_uchar,
        scratch_len: usize,
    ) -> u64;
}

const ROW: usize = 2064;
const ROW_PAYLOAD: usize = 2048;
const MAX_ROWS: usize = 10;
const RESPONSE: usize = 32 + EVOLUTION_MODEL_BYTES + 19;
const SCRATCH: usize = 9014;

fn encode_cell(dst: &mut [u8], key: &str, tag: u8, data: &[u8]) -> Option<()> {
    let key = key.as_bytes();
    if key.len() > 8 || !key.is_ascii() || key.contains(&0) || data.len() > dst.len() - 16 {
        return None;
    }
    dst[..key.len()].copy_from_slice(key);
    dst[8] = tag;
    dst[9..11].copy_from_slice(&(data.len() as u16).to_le_bytes());
    dst[16..16 + data.len()].copy_from_slice(data);
    Some(())
}

fn encode_value(dst: &mut [u8], key: &str, value: &Value, nested: bool) -> Option<()> {
    if let Some(text) = value.as_str() {
        return encode_cell(dst, key, 1, text.as_bytes());
    }
    if nested {
        return if let Some(integer) = value.as_u64() {
            encode_cell(dst, key, 3, &integer.to_le_bytes())
        } else {
            encode_cell(dst, key, 0, &[])
        };
    }
    if let Some(fields) = value.as_object() {
        let size = 1 + 80 * fields.len();
        if size > ROW_PAYLOAD {
            return None;
        }
        let mut encoded = vec![0; size];
        encoded[0] = fields.len() as u8;
        for ((name, value), field) in fields.iter().zip(encoded[1..].chunks_exact_mut(80)) {
            encode_value(field, name, value, true)?;
        }
        return encode_cell(dst, key, 2, &encoded);
    }
    encode_cell(dst, key, 0, &[])
}

fn project(state: &State, id: Hash, family: Hash) -> Option<Vec<u8>> {
    fn append(bytes: &mut Vec<u8>, scoped: State, prefix: &str) -> Option<()> {
        for (key, value) in scoped {
            let at = bytes.len();
            bytes.resize(at + ROW, 0);
            encode_value(&mut bytes[at..], key.strip_prefix(prefix)?, &value, false)?;
        }
        Some(())
    }
    let mut source = ReadState(state);
    let old_prefix = prefix(id, false);
    let new_prefix = prefix(id, true);
    let old = source.scan(&old_prefix);
    let new = source.scan(&new_prefix);
    if old.len() > MAX_ROWS || new.len() > MAX_ROWS {
        return None;
    }
    let mut bytes = Vec::with_capacity(72 + ROW * (old.len() + new.len()));
    bytes.extend_from_slice(b"IMD2");
    bytes.extend([old.len() as u8, new.len() as u8, 0, 0]);
    bytes.extend_from_slice(&family);
    append(&mut bytes, old, &old_prefix)?;
    append(&mut bytes, new, &new_prefix)?;
    bytes.extend_from_slice(&id);
    Some(bytes)
}

fn hash_arg(value: &Value) -> Hash {
    hex::decode(value.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

fn original_status(err: &str) -> u32 {
    match err {
        "FACTOR_MODEL_COLLISION" => 1,
        "FACTOR_MODEL_MISSING" => 2,
        "FACTOR_MODEL_METADATA" => 3,
        "FACTOR_MODEL_CHUNK" => 4,
        "FACTOR_MODEL_LENGTH" => 5,
        "FACTOR_MODEL_VERSION" => 6,
        "FACTOR_MODEL_CONTEXT" => 7,
        "EVOLUTION_GRAPH" => 8,
        "FACTOR_MODEL_RANGE" => 9,
        "FACTOR_MODEL_HASH" => 10,
        _ => panic!("unexpected original state result: {err}"),
    }
}

fn observation(query: &Value) -> Value {
    let state: State = serde_json::from_value(query["state"].clone()).unwrap();
    let before = state.clone();
    let id = hash_arg(&query["id"]);
    let family = hash_arg(&query["family"]);
    let old = load_model(&mut ReadState(&state), id, family);
    let (old_code, expected) = match old {
        Ok(value) => (
            0,
            [value.id().as_slice(), value.encode().as_slice()].concat(),
        ),
        Err(err) => (original_status(err), Vec::new()),
    };
    let Some(request) = project(&state, id, family) else {
        assert_eq!(before, state);
        return json!({"projection":"outside-private-abi", "original_status":old_code,
                      "state_unchanged":true, "native_calls":0, "state_rows":state.len()});
    };
    let snapshot = request.clone();
    let mut output = [0xa5; RESPONSE];
    let mut scratch = [0x49; SCRATCH + 13];
    let raw_status = unsafe {
        trnm_integer_model_snapshot_load_v1(
            request.as_ptr(),
            request.len(),
            output.as_mut_ptr(),
            output.len(),
            scratch.as_mut_ptr(),
            scratch.len(),
        )
    };
    assert_eq!(raw_status >> 32, 0, "named foreign ABI returned a failure");
    let native_code = raw_status as u32;
    assert_eq!(
        native_code, old_code,
        "same typed State disagrees with original load"
    );
    assert_eq!(&output[..expected.len()], expected.as_slice());
    assert!(output[expected.len()..].iter().all(|b| *b == 0xa5));
    assert_eq!(&scratch[SCRATCH..], &[0x49; 13]);
    assert_eq!(request, snapshot);
    assert_eq!(state, before);
    json!({"projection":"named-native", "original_status":old_code,
           "abi_status":raw_status >> 32, "native_status":native_code,
           "body_hex":hex::encode(&output[..expected.len()]), "state_unchanged":true,
           "state_rows":state.len(), "namespace_rows":[request[4],request[5]], "native_calls":1})
}

fn main() -> io::Result<()> {
    use std::io::BufRead;
    let mut output = io::stdout().lock();
    for row in io::stdin().lock().lines() {
        let query: Value = serde_json::from_str(&row?).unwrap();
        serde_json::to_writer(&mut output, &observation(&query))?;
        output.write_all(b"\n")?;
    }
    Ok(())
}
