use std::io::{self, Read, Write};
use trnm_state_import::{MigrationErrorV0, TargetDeltaRowV0};

fn le_word(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().expect("fixture word"))
}

fn main() {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input).expect("fixture input");
    let mut cases = input.as_slice();
    let mut output = io::stdout().lock();
    while !cases.is_empty() {
        let size = le_word(&cases[..4]) as usize;
        let (recipe, rest) = cases[4..].split_at(size);
        cases = rest;

        let namespace_end = le_word(&recipe[..4]) as usize;
        let key_end = namespace_end + le_word(&recipe[4..8]) as usize;
        let value_end = key_end + le_word(&recipe[8..12]) as usize;
        let kind = le_word(&recipe[12..16]);
        let change = recipe[16];
        let fields = &recipe[17..];
        assert_eq!(value_end, fields.len());
        assert!(matches!(kind, 0 | 1));
        assert!(kind == 1 || value_end == key_end);
        let namespace = fields[..namespace_end].to_vec();
        let key = fields[namespace_end..key_end].to_vec();
        let value = (kind == 1).then(|| fields[key_end..].to_vec());

        let mut stored = TargetDeltaRowV0::canonical_digest(&namespace, &key, value.as_deref());
        if change != 0 {
            stored.0[usize::from(change - 1)] ^= 0x80;
        }
        let row = TargetDeltaRowV0 {
            namespace,
            key,
            value,
            operation_digest: stored,
        };
        let status = match row.validate() {
            Ok(()) => 0_u32,
            Err(MigrationErrorV0::InvalidDeltaRow) => 101,
            other => panic!("Unexpected original row observation: {other:?}"),
        };
        output.write_all(&status.to_le_bytes()).expect("status");
        output.write_all(&stored.0).expect("stored digest");
    }
}
