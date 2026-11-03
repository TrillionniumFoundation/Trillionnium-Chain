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

/// Encode exactly the State's serde JSON representation. State is a
/// BTreeMap<String, Value>, so iteration preserves the original map order.
/// Keys and every nonfast value retain serde's original serializer. The sole
/// fast value case uses the same complete ASCII guard as the SQL string reader;
/// it cannot change escaping, Unicode, number, object or array representations.
pub(super) fn state_bytes(
    state: &trnm_mvcc_fee::pon_executor::State,
) -> serde_json::Result<Vec<u8>> {
    use std::io::Write;

    fn append(bytes: &mut Vec<u8>, part: &[u8]) -> serde_json::Result<()> {
        bytes.write_all(part).map_err(serde_json::Error::io)
    }

    // Mirror serde_json::to_vec's initial capacity and the CompactFormatter
    // write sequence, including the original three unescaped-string writes.
    let mut bytes = Vec::with_capacity(128);
    append(&mut bytes, b"{")?;
    for (index, (key, value)) in state.iter().enumerate() {
        if index != 0 {
            append(&mut bytes, b",")?;
        }
        serde_json::to_writer(&mut bytes, key)?;
        append(&mut bytes, b":")?;
        match value {
            Value::String(value) if unescaped_ascii(value.as_bytes()) => {
                append(&mut bytes, b"\"")?;
                if !value.is_empty() {
                    append(&mut bytes, value.as_bytes())?;
                }
                append(&mut bytes, b"\"")?;
            }
            _ => serde_json::to_writer(&mut bytes, value)?,
        }
    }
    append(&mut bytes, b"}")?;
    Ok(bytes)
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

    fn assert_state_encoding(state: &trnm_mvcc_fee::pon_executor::State) {
        match (serde_json::to_vec(state), state_bytes(state)) {
            (Ok(expected), Ok(actual)) => {
                assert_eq!(actual, expected);
                assert_eq!(actual.capacity(), expected.capacity());
            }
            (Err(expected), Err(actual)) => {
                assert_eq!(actual.to_string(), expected.to_string());
                assert_eq!(actual.classify(), expected.classify());
                assert_eq!(
                    (actual.line(), actual.column()),
                    (expected.line(), expected.column())
                );
            }
            (expected, actual) => panic!("State encoding mismatch: {expected:?} versus {actual:?}"),
        }
    }

    #[test]
    fn native_state_encoder_matches_serde_for_map_order_and_mixed_values() {
        use trnm_mvcc_fee::pon_executor::State;

        assert_state_encoding(&State::new());
        let state = State::from([
            ("z".into(), json!(false)),
            ("é".into(), json!("unicode key")),
            ("a".into(), json!(1.0)),
            (String::new(), json!("")),
            ("\"\\\n".into(), json!({"b": [null, true, -0.0], "a": "x"})),
            ("m".into(), json!("unescaped \u{007f} ASCII")),
        ]);
        assert_state_encoding(&state);
        let ordered = State::from([("z".into(), json!("last")), ("a".into(), json!("first"))]);
        assert_eq!(
            state_bytes(&ordered).unwrap(),
            br#"{"a":"first","z":"last"}"#
        );
    }

    #[test]
    fn native_state_encoder_matches_serde_for_ascii_positions_and_capacity_boundaries() {
        use trnm_mvcc_fee::pon_executor::State;

        for width in [
            0, 1, 7, 8, 9, 15, 16, 17, 125, 126, 127, 128, 129, 4080, 4094, 4095, 4096, 65_536,
            262_144,
        ] {
            let state = State::from([
                ("a".into(), json!("prefix")),
                ("m".into(), json!("x".repeat(width))),
                ("z".into(), json!("suffix")),
            ]);
            assert_state_encoding(&state);
        }
        for width in [1, 7, 8, 9, 15, 16, 17] {
            for position in 0..width {
                for byte in 0..=127u8 {
                    let mut value = vec![b'x'; width];
                    value[position] = byte;
                    let state = State::from([
                        ("a".into(), json!("prefix")),
                        ("m".into(), json!(String::from_utf8(value).unwrap())),
                        ("z".into(), json!("suffix")),
                    ]);
                    assert_state_encoding(&state);
                }
            }
        }
    }

    #[test]
    fn native_state_encoder_keeps_nonfast_values_and_nested_representations() {
        use trnm_mvcc_fee::pon_executor::State;

        for text in [
            "é",
            "中文",
            "😀",
            "\u{2028}\u{2029}",
            "quote\"slash\\line\n",
            "\0\u{001f}",
        ] {
            for prefix in [0, 1, 7, 8, 9, 15, 16, 17, 4096] {
                let state = State::from([
                    ("a".into(), json!("fast first")),
                    (
                        "\"\\\n中文".into(),
                        json!(format!("{}{text}", "x".repeat(prefix))),
                    ),
                    (
                        "z".into(),
                        json!({"nested": [text, {"control": "\n", "zero": -0.0}]}),
                    ),
                ]);
                assert_state_encoding(&state);
            }
        }
        let state = State::from([
            (
                "numbers".into(),
                json!([i64::MIN, u64::MAX, -0.0, 0.0, 1.0, f64::MIN, f64::MAX]),
            ),
            (
                "nested".into(),
                json!({"z": [true, null, {"a": "quoted\""}], "a": []}),
            ),
            ("fast".into(), json!("a".repeat(4096))),
        ]);
        assert_state_encoding(&state);
    }

    #[test]
    fn native_snapshot_comparisons_keep_original_decode_and_refusal_errors() {
        use trnm_mvcc_fee::pon_executor::State;

        fn checked(
            raw: &[u8],
            initial: Option<&State>,
            encode: fn(&State) -> serde_json::Result<Vec<u8>>,
        ) -> crate::Result<State> {
            let state: State = serde_json::from_slice(raw)
                .map_err(|error| crate::Error::from(error).local_integrity())?;
            let bytes = encode(&state)?;
            let (equal, refusal) = match initial {
                Some(initial) => (bytes == raw && &state == initial, "NATIVE_STATE_GENESIS"),
                None => (bytes == raw, "STATE_BYTES"),
            };
            super::super::ensure(equal, refusal).map_err(crate::Error::local_integrity)?;
            Ok(state)
        }

        let initial = State::from([("a".into(), json!("x"))]);
        let mut inputs: Vec<Vec<u8>> = [
            &b""[..],
            b"null",
            b"[]",
            b"{",
            b"{}",
            br#"{"a":"x"}"#,
            br#"{"a": "x"}"#,
            br#"{"a":"\u0078"}"#,
            br#"{"a":"x","a":"x"}"#,
            br#"{"z":0,"a":"x"}"#,
            br#"{"a":-0}"#,
            br#"{"a":-0.0}"#,
            br#"{"a":1.0}"#,
            br#"{"a":null}"#,
            br#"{"a":NaN}"#,
            br#"{"a":"x"} "#,
            br#"{"a":"x"}{}"#,
            b"{\"a\":\"\xff\"}",
        ]
        .into_iter()
        .map(<[u8]>::to_vec)
        .collect();
        inputs.push("{\"a\":\"中文😀\"}".as_bytes().to_vec());
        inputs.push(format!("{{\"a\":{}0{}}}", "[".repeat(140), "]".repeat(140)).into_bytes());
        assert!(checked(br#"{"a":"x"}"#, Some(&initial), serde_json::to_vec::<State>).is_ok());
        for raw in inputs {
            for genesis in [None, Some(&initial)] {
                let expected = checked(&raw, genesis, serde_json::to_vec::<State>);
                let actual = checked(&raw, genesis, state_bytes);
                assert_eq!(format!("{actual:?}"), format!("{expected:?}"), "{raw:?}");
            }
        }
    }
}
