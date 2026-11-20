//! Test adapter to the complete unchanged original Node consensus module.
//!
//! test_consensus_work.py replaces exactly one marker with the original source
//! bytes in a fresh temporary Rust file. No production function is rewritten.
//! These two wrappers only expose existing private division/window entry points.
#![allow(dead_code)]
use std::io::{self, BufRead};
type Result<T> = std::result::Result<T, String>;
fn ensure(ok: bool, message: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(message.to_owned()) }
}
mod original {
// TRNM_ORIGINAL_CONSENSUS_SOURCE
    pub fn adapter_divide(left: Work, right: Work) -> crate::Result<Work> {
        left.divided(right)
    }
    pub fn adapter_window(height: u64, recent: &[(u64, [u8; 32])], interval: u64)
        -> crate::Result<(u64, [u8; 32], u64, u64)>
    {
        match BranchTargetHeight::after(height)?.window(recent, interval)? {
            TargetWindow::Parent(target) => Ok((0, target, 0, 0)),
            TargetWindow::Retarget { target, first, last } => Ok((1, target, first, last)),
        }
    }
}
fn word(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
fn fixed<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    bytes[offset..offset + N].try_into().unwrap()
}
fn decode(text: &str) -> Vec<u8> {
    assert!(text.len() % 2 == 0);
    text.as_bytes().chunks_exact(2).map(|pair| {
        let s = std::str::from_utf8(pair).unwrap();
        u8::from_str_radix(s, 16).unwrap()
    }).collect()
}
fn encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut result = String::new();
    for byte in bytes { write!(&mut result, "{byte:02x}").unwrap(); }
    result
}
fn evaluate(bytes: &[u8]) -> Result<Vec<u8>> {
    assert!(bytes.len() >= 16 && &bytes[..8] == b"NCWV0001");
    let op = word(bytes, 8);
    let x = || original::Work::from_bytes(fixed(bytes, 16));
    let y = || original::Work::from_bytes(fixed(bytes, 80));
    match op {
        0 => { assert_eq!(bytes.len(), 144); Ok(x().checked_add(y())?.bytes().to_vec()) }
        1 => { assert_eq!(bytes.len(), 144); Ok(x().checked_sub(y())?.bytes().to_vec()) }
        2 => { assert_eq!(bytes.len(), 88); Ok(x().mul_small(word(bytes, 80))?.bytes().to_vec()) }
        3 => { assert_eq!(bytes.len(), 144); Ok(original::adapter_divide(x(), y())?.bytes().to_vec()) }
        4 => { assert_eq!(bytes.len(), 48); Ok(original::required_work(fixed(bytes, 16))?.bytes().to_vec()) }
        5 => {
            assert_eq!(bytes.len(), 112);
            Ok(original::retarget(fixed(bytes, 16), word(bytes, 80), word(bytes, 88),
                word(bytes, 96), word(bytes, 104), fixed(bytes, 48))?.to_vec())
        }
        6 => { assert_eq!(bytes.len(), 80); Ok(x().target()?.to_vec()) }
        7 => {
            assert_eq!(bytes.len(), 144);
            let value: u64 = match x().cmp(&y()) {
                std::cmp::Ordering::Less => 0, std::cmp::Ordering::Equal => 1,
                std::cmp::Ordering::Greater => 2,
            };
            Ok(value.to_le_bytes().to_vec())
        }
        8 => { assert_eq!(bytes.len(), 48); Ok(original::Work::from_target(fixed(bytes, 16)).bytes().to_vec()) }
        9 => {
            let count = usize::try_from(word(bytes, 32)).unwrap();
            assert_eq!(bytes.len(), 40 + 40 * count);
            let recent: Vec<_> = (0..count).map(|i|
                (word(bytes, 40 + 40 * i), fixed(bytes, 48 + 40 * i))).collect();
            let (kind, target, first, last) = original::adapter_window(
                word(bytes, 16), &recent, word(bytes, 24))?;
            let mut result = kind.to_le_bytes().to_vec();
            result.extend_from_slice(&target);
            result.extend_from_slice(&first.to_le_bytes());
            result.extend_from_slice(&last.to_le_bytes());
            Ok(result)
        }
        10 => {
            let count = usize::try_from(word(bytes, 40)).unwrap();
            assert_eq!(bytes.len(), 48 + 8 * count);
            let ancestors: Vec<_> = (0..count).map(|i| word(bytes, 48 + 8 * i)).collect();
            original::check_time(word(bytes, 16), &ancestors, word(bytes, 24), word(bytes, 32))?;
            Ok(Vec::new())
        }
        _ => panic!("unknown consensus adapter operation"),
    }
}
fn main() {
    println!("SOURCE_SHA256 {}", env!("TRNM_CONSENSUS_SOURCE_SHA256"));
    for line in io::stdin().lock().lines() {
        let bytes = decode(&line.expect("original consensus input"));
        match evaluate(&bytes) {
            Ok(bytes) => println!("OK {}", encode(&bytes)),
            Err(error) => println!("ERR {error}"),
        }
    }
}
