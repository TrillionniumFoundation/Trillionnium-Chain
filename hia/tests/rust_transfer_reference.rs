//! Test-only framing for the unchanged complete trnm-types TransferTx methods.
use std::io::{self, BufRead, Write};
use trnm_types::{TransferTx, TransferTxValidationError};

fn word(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
fn code(error: TransferTxValidationError) -> u32 {
    match error {
        TransferTxValidationError::EmptyFrom => 1,
        TransferTxValidationError::EmptyTo => 2,
        TransferTxValidationError::SameSenderAndRecipient => 3,
        TransferTxValidationError::ZeroAmount => 4,
        TransferTxValidationError::MissingSignature => 5,
        TransferTxValidationError::InvalidSignature => 6,
    }
}
fn run(input: &[u8]) -> (u32, Vec<u8>) {
    assert!(input.len() >= 88);
    assert_eq!(&input[..8], b"TRNMTX1\0");
    let op = word(input, 8);
    let mut at = 88usize;
    let mut fields = Vec::new();
    for offset in [16, 24, 32, 40] {
        let len = usize::try_from(word(input, offset)).unwrap();
        fields.push(&input[at..at + len]);
        at += len;
    }
    assert_eq!(at, input.len());
    if op == 1 {
        return (
            0,
            TransferTx::derive_address_from_ed25519_pubkey(fields[0]).into_bytes(),
        );
    }
    let tx = TransferTx {
        from: String::from_utf8(fields[0].to_vec()).unwrap(),
        to: String::from_utf8(fields[1].to_vec()).unwrap(),
        amount: u128::from_le_bytes(input[48..64].try_into().unwrap()),
        fee: u128::from_le_bytes(input[64..80].try_into().unwrap()),
        nonce: word(input, 80),
        signature: String::from_utf8(fields[2].to_vec()).unwrap(),
    };
    match op {
        0 => (0, tx.signing_message()),
        2 => match tx.sign_with_private_key_hex(std::str::from_utf8(fields[3]).unwrap()) {
            Ok(value) => (0, value.into_bytes()),
            Err(error) => (code(error), Vec::new()),
        },
        3 => (tx.validate_basic().err().map_or(0, code), Vec::new()),
        _ => panic!("unsupported test operation"),
    }
}
fn main() {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        assert_eq!(line.len() % 2, 0);
        let bytes: Vec<u8> = (0..line.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&line[i..i + 2], 16).unwrap())
            .collect();
        let (status, bytes) = run(&bytes);
        write!(out, "{status}:").unwrap();
        for byte in bytes {
            write!(out, "{byte:02x}").unwrap();
        }
        writeln!(out).unwrap();
    }
}
