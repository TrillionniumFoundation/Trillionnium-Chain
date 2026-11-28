//! Test-only transport for the actual complete original AuditEvent crate.
use std::io::{self, BufRead, Write};
use trnm_audit_events::AuditEvent;

fn word(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

fn text(bytes: &[u8]) -> String {
    std::str::from_utf8(bytes).unwrap().to_owned()
}

fn constant(bytes: &[u8]) -> &'static str {
    // The original constructor requires static strings. The finite test
    // process deliberately owns these leaked constants for its whole lifetime.
    Box::leak(text(bytes).into_boxed_str())
}

fn decode(bytes: &[u8]) -> AuditEvent {
    assert_eq!(&bytes[..8], b"NAER0001");
    assert_eq!(word(bytes, 8) as usize, bytes.len());
    let mask = word(bytes, 16);
    assert!(mask <= 63);
    let mut position = 96;
    let mut strings = Vec::new();
    for i in 0..7 {
        let size = usize::try_from(word(bytes, 40 + 8 * i)).unwrap();
        strings.push(&bytes[position..position + size]);
        position += size;
    }
    assert_eq!(position, bytes.len());
    let mut event = AuditEvent::new(constant(strings[0]), constant(strings[1]));
    let optional = |index: usize, bit: u32| (mask & (1u64 << bit) != 0).then(|| text(strings[index]));
    event.actor = optional(2, 0);
    event.object_id = optional(3, 1);
    event.related_id = optional(4, 2);
    event.reason = optional(5, 4);
    event.note = optional(6, 5);
    event.amount = (mask & 8 != 0).then(|| u128::from_le_bytes(bytes[24..40].try_into().unwrap()));
    event
}

fn encode(event: &AuditEvent) -> Vec<u8> {
    let strings = [event.source, event.event_type, event.actor.as_deref().unwrap_or(""),
        event.object_id.as_deref().unwrap_or(""), event.related_id.as_deref().unwrap_or(""),
        event.reason.as_deref().unwrap_or(""), event.note.as_deref().unwrap_or("")];
    let presence = [event.actor.is_some(), event.object_id.is_some(), event.related_id.is_some(),
        event.amount.is_some(), event.reason.is_some(), event.note.is_some()];
    let mask = presence.iter().enumerate().fold(0u64, |bits, (i, present)| bits | (u64::from(*present) << i));
    let total: usize = 96 + strings.iter().map(|s| s.len()).sum::<usize>();
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(b"NAER0001");
    out.extend_from_slice(&(total as u64).to_le_bytes());
    out.extend_from_slice(&mask.to_le_bytes());
    out.extend_from_slice(&event.amount.unwrap_or(0).to_le_bytes());
    for value in strings { out.extend_from_slice(&(value.len() as u64).to_le_bytes()); }
    for value in strings { out.extend_from_slice(value.as_bytes()); }
    assert_eq!(out.len(), total);
    out
}

fn main() {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        assert_eq!(line.len() % 2, 0);
        let input: Vec<u8> = (0..line.len()).step_by(2)
            .map(|i| u8::from_str_radix(&line[i..i + 2], 16).unwrap()).collect();
        assert_eq!(&input[..8], b"NAEB0001");
        let op = word(&input, 8);
        let a = usize::try_from(word(&input, 16)).unwrap();
        let b = usize::try_from(word(&input, 24)).unwrap();
        assert_eq!(input.len(), 32 + a + b);
        let left = &input[32..32 + a];
        let right = &input[32 + a..];
        let answer = if op == 0 {
            encode(&AuditEvent::new(constant(left), constant(right)))
        } else if op == 8 {
            vec![u8::from(decode(left) == decode(right))]
        } else {
            let event = decode(left);
            let changed = match op {
                1 => event.with_actor(text(right)),
                2 => event.with_object_id(text(right)),
                3 => event.with_related_id(text(right)),
                4 => event.with_amount(u128::from_le_bytes(right.try_into().unwrap())),
                5 => event.with_reason(text(right)),
                6 => event.with_note(text(right)),
                7 => { assert!(right.is_empty()); event.clone() },
                _ => panic!("unsupported test operation"),
            };
            encode(&changed)
        };
        for byte in answer { write!(out, "{byte:02x}").unwrap(); }
        writeln!(out).unwrap();
    }
}
