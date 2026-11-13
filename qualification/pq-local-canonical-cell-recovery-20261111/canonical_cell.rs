//! Exact canonical decoding of an already bounded, currently borrowed SQL cell.
//!
//! The caller still reads every typed row and checks its original dimensions.
//! A strict unescaped ASCII string has exactly one serde_json representation;
//! construct that owned value directly. Every other input runs the unchanged
//! decoder and canonical-byte comparison. No retained row, root or validity
//! result is consulted, and no SQLite borrow leaves this call.
use super::{ensure, Error, Result};
use serde_json::Value;

fn plain_ascii_body(bytes: &[u8]) -> Option<&str> {
    let [b'"', body @ .., b'"'] = bytes else {
        return None;
    };
    const HIGH: u64 = u64::from_le_bytes([0x80; 8]);
    const ONE: u64 = u64::from_le_bytes([1; 8]);
    let mut chunks = body.chunks_exact(8);
    for chunk in &mut chunks {
        let mut word_bytes = [0; 8];
        word_bytes.copy_from_slice(chunk);
        let word = u64::from_le_bytes(word_bytes);
        if word & HIGH != 0 {
            return None;
        }
        // With high bits excluded, the first byte below each threshold
        // underflows. Borrow propagation cannot hide that first high bit.
        let control = word.wrapping_sub(u64::from_le_bytes([0x20; 8]));
        let quote = (word ^ u64::from_le_bytes([b'"'; 8])).wrapping_sub(ONE);
        let backslash = (word ^ u64::from_le_bytes([b'\\'; 8])).wrapping_sub(ONE);
        if (control | quote | backslash) & HIGH != 0 {
            return None;
        }
    }
    if !chunks
        .remainder()
        .iter()
        .all(|&byte| (0x20..=0x7f).contains(&byte) && byte != b'"' && byte != b'\\')
    {
        return None;
    }
    // The ASCII test implies UTF-8, but keep the safe checked conversion.
    std::str::from_utf8(body).ok()
}

pub(super) fn decode(bytes: &[u8], canonical_bytes: &mut Vec<u8>) -> Result<Value> {
    if let Some(body) = plain_ascii_body(bytes) {
        canonical_bytes.clear();
        return Ok(Value::String(body.to_owned()));
    }
    let value: Value =
        serde_json::from_slice(bytes).map_err(|error| Error::from(error).local_integrity())?;
    canonical_bytes.clear();
    serde_json::to_writer(&mut *canonical_bytes, &value)
        .map_err(|error| Error::from(error).local_integrity())?;
    ensure(canonical_bytes.as_slice() == bytes, "STATE_BYTES").map_err(Error::local_integrity)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The original SQL-cell implementation remains the independent reference.
    fn original(bytes: &[u8]) -> Result<Value> {
        let value: Value =
            serde_json::from_slice(bytes).map_err(|error| Error::from(error).local_integrity())?;
        let canonical =
            serde_json::to_vec(&value).map_err(|error| Error::from(error).local_integrity())?;
        ensure(canonical == bytes, "STATE_BYTES").map_err(Error::local_integrity)?;
        Ok(value)
    }

    fn observed(result: Result<Value>) -> std::result::Result<Vec<u8>, (String, bool)> {
        result
            .map(|value| serde_json::to_vec(&value).unwrap())
            .map_err(|error| (error.to_string(), error.requires_owner_stop()))
    }

    fn same(bytes: &[u8], scratch: &mut Vec<u8>) {
        assert_eq!(observed(decode(bytes, scratch)), observed(original(bytes)));
    }

    #[test]
    fn current_cell_ascii_substitutions_preserve_original_decode_and_owner_errors() {
        let mut scratch = Vec::new();
        for length in [1, 7, 8, 9, 15, 16, 17, 31, 32, 33] {
            let mut bytes = vec![b'x'; length + 2];
            bytes[0] = b'"';
            bytes[length + 1] = b'"';
            for position in 1..=length {
                for byte in 0..=u8::MAX {
                    bytes[position] = byte;
                    same(&bytes, &mut scratch);
                }
                bytes[position] = b'x';
            }
        }
        // Adjacent bytes cross the word boundary and exercise borrow chains.
        let mut bytes = *b"\"xxxxxxxxxxxxxxxx\"";
        for left in 0..=u8::MAX {
            bytes[8] = left;
            for right in 0..=u8::MAX {
                bytes[9] = right;
                same(&bytes, &mut scratch);
            }
        }
    }

    #[test]
    fn current_cell_fast_path_keeps_full_lengths_and_fallback_semantics() {
        let mut scratch = vec![0x5a; 4096];
        for length in [0, 1, 7, 8, 9, 31, 32, 33, 127, 128, 4080, 4094] {
            let body = "x".repeat(length);
            let bytes = serde_json::to_vec(&body).unwrap();
            assert_eq!(plain_ascii_body(&bytes), Some(body.as_str()));
            same(&bytes, &mut scratch);
        }
        for bytes in [
            &b"\"\x7f\""[..],
            &b"\"a\\nb\""[..],
            &b"\"a\\\\b\""[..],
            &b"\"a\\\"b\""[..],
            &b"\"\\u0078\""[..],
            &b"\"\\u0000\""[..],
            "é".as_bytes(),
            "\"é\"".as_bytes(),
            &b"null"[..],
            &b"true"[..],
            &b"-0.0"[..],
            &b"18446744073709551615"[..],
            &b"[\"x\",0,true]"[..],
            &b"{\"a\":1,\"b\":2}"[..],
            &b"{\"b\":2,\"a\":1}"[..],
            &b" \"x\""[..],
            &b"\"x\" "[..],
            &b"\"x\" \"y\""[..],
            &b"\""[..],
            &b"\\\""[..],
            &b"\"\xff\""[..],
            &b"["[..],
            &b""[..],
        ] {
            same(bytes, &mut scratch);
        }
    }
}
