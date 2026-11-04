//! Recognize one exact, complete JSON string from freshly read SQLite bytes.
//! This grants no State/root authority and retains no result between calls.
//! Every other input is decoded and compared by the original serde path.
use serde_json::Value;

// Same eight-byte ASCII test as M06's existing encoder. A high bit, control,
// quote or backslash requires the original decoder. DEL stays literal JSON.
fn unescaped_ascii(bytes: &[u8]) -> bool {
    const HIGH: u64 = 0x8080_8080_8080_8080;
    const ONE: u64 = 0x0101_0101_0101_0101;
    let (chunks, tail) = bytes.as_chunks::<8>();
    for word_bytes in chunks {
        let word = u64::from_le_bytes(*word_bytes);
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
    tail.iter()
        .all(|&byte| (0x20..=0x7f).contains(&byte) && byte != b'"' && byte != b'\\')
}

pub(super) fn unescaped_string_value(bytes: &[u8]) -> Option<Value> {
    let raw = bytes.strip_prefix(b"\"")?.strip_suffix(b"\"")?;
    if !unescaped_ascii(raw) {
        return None;
    }
    // Keep checked UTF-8 and an owned copy; no SQLite row borrow escapes.
    std::str::from_utf8(raw)
        .ok()
        .map(|value| Value::String(value.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn native_string_decoder_matches_serde_at_every_ascii_position_and_boundary() {
        for width in [
            0, 1, 7, 8, 9, 15, 16, 17, 126, 127, 128, 129, 4094, 4095, 4096, 65_536, 262_144,
        ] {
            let expected = json!("x".repeat(width));
            let raw = serde_json::to_vec(&expected).unwrap();
            let decoded = unescaped_string_value(&raw).unwrap();
            assert_eq!(decoded, expected);
            assert_eq!(serde_json::to_vec(&decoded).unwrap(), raw);
        }
        for width in [1, 7, 8, 9, 15, 16, 17] {
            for position in 0..width {
                for byte in 0..=127u8 {
                    let mut bytes = vec![b'x'; width];
                    bytes[position] = byte;
                    let expected = json!(String::from_utf8(bytes).unwrap());
                    let raw = serde_json::to_vec(&expected).unwrap();
                    if let Some(decoded) = unescaped_string_value(&raw) {
                        assert_eq!(decoded, serde_json::from_slice::<Value>(&raw).unwrap());
                        assert_eq!(decoded, expected);
                        assert_eq!(serde_json::to_vec(&decoded).unwrap(), raw);
                    }
                }
            }
        }
    }

    #[test]
    fn native_string_decoder_preserves_every_nonfast_input_for_original_serde() {
        for raw in [
            &b""[..],
            b"x",
            b"\"",
            b"\"x",
            b"x\"",
            b"\"x\" ",
            b" \"x\"",
            b"\"x\"\"y\"",
            b"\"x\\n\"",
            b"\"\\u0078\"",
            b"\"\\u007f\"",
            b"\"x\ny\"",
            b"\"x\x1fy\"",
            b"\"\xff\"",
            b"\"\xc3\xa9\"",
            b"null",
            b"-0.0",
            b"{}",
            b"[]",
        ] {
            assert!(unescaped_string_value(raw).is_none(), "{raw:?}");
        }
        for text in [
            "é",
            "中文",
            "😀",
            "\u{2028}\u{2029}",
            "quote\"slash\\line\n",
            "\0\u{001f}",
        ] {
            assert!(unescaped_string_value(&serde_json::to_vec(text).unwrap()).is_none());
        }
        for raw in [
            &b"\"\""[..],
            b"\"x\"",
            b"\"\x7f\"",
            b"\"ascii !#$%&'()*+,-./:;<=>?@[]^_\x60{|}~\"",
        ] {
            let value = unescaped_string_value(raw).unwrap();
            assert_eq!(value, serde_json::from_slice::<Value>(raw).unwrap());
            assert_eq!(serde_json::to_vec(&value).unwrap(), raw);
        }
    }
}
