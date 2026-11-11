use super::*;

fn byte_oracle(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|&byte| (0x20..0x80).contains(&byte) && byte != b'"' && byte != b'\\')
}

#[test]
fn canonical_string_array_scan_checks_every_byte_and_word_boundary() {
    for length in 0..=80 {
        let mut bytes = vec![b'x'; length];
        assert_eq!(unescaped_ascii_json(&bytes), byte_oracle(&bytes));
        for position in 0..length {
            for byte in 0..=255 {
                bytes[position] = byte;
                assert_eq!(
                    unescaped_ascii_json(&bytes),
                    byte_oracle(&bytes),
                    "length={length} position={position} byte={byte}"
                );
            }
            bytes[position] = b'x';
        }
    }
    // Adjacent values on both sides of the word boundary catch subtraction
    // borrow interactions independently of individual delimiter substitutions.
    for position in [6, 7, 8, 14, 15, 16, 30, 31, 32, 62, 63, 64, 78] {
        let mut bytes = [b'x'; 80];
        for pair in 0..=u16::MAX {
            bytes[position..position + 2].copy_from_slice(&pair.to_le_bytes());
            assert_eq!(
                unescaped_ascii_json(&bytes),
                byte_oracle(&bytes),
                "position={position} pair={pair}"
            );
        }
    }
    for length in [4080, 4094, 4096] {
        let mut bytes = vec![b'x'; length];
        for position in [0, 7, 8, 63, 64, length - 9, length - 8, length - 1] {
            for byte in 0..=255 {
                bytes[position] = byte;
                assert_eq!(unescaped_ascii_json(&bytes), byte_oracle(&bytes));
            }
            bytes[position] = b'x';
        }
    }
}

#[test]
fn canonical_string_array_scan_keeps_serde_bytes_capacities_and_errors() {
    let mut reused = Vec::new();
    for length in [
        0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 63, 64, 65, 126, 127, 128, 129, 4080, 4094,
    ] {
        let plain = Value::String("x".repeat(length));
        let reference = serde_json::to_vec(&plain).unwrap();
        let actual = canonical(&plain).unwrap();
        assert_eq!(
            (&actual, actual.capacity()),
            (&reference, reference.capacity())
        );
        if length == 0 {
            continue;
        }
        for position in [0, length / 2, length - 1] {
            let mut bytes = vec![b'x'; length];
            for byte in 0..=127 {
                bytes[position] = byte;
                let value = Value::String(String::from_utf8(bytes.clone()).unwrap());
                let reference = serde_json::to_vec(&value).unwrap();
                let actual = canonical(&value).unwrap();
                assert_eq!(
                    (&actual, actual.capacity()),
                    (&reference, reference.capacity()),
                    "length={length} position={position} byte={byte}"
                );
                canonical_into(&value, &mut reused).unwrap();
                assert_eq!(reused, reference);
            }
        }
    }
    for (value, expected) in [
        (json!("λ"), "NONCANONICAL"),
        (json!("é"), "NONCANONICAL"),
        (json!(["ASCII", "λ"]), "NONCANONICAL"),
        (json!({"λ":0}), "NONCANONICAL"),
        (json!(0.0), "RANGE"),
        (json!(-0.0), "RANGE"),
    ] {
        assert_eq!(canonical(&value), Err(expected));
        assert_eq!(canonical_into(&value, &mut reused), Err(expected));
    }
}
