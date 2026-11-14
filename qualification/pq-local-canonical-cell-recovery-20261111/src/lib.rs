#![allow(dead_code)]
use serde_json::Value;

#[derive(Debug)]
pub struct Error {
    text: String,
    stop: bool,
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Self { text: err.to_string(), stop: true }
    }
}
impl Error {
    fn local_integrity(mut self) -> Self {
        self.stop = true;
        self
    }
    fn requires_owner_stop(&self) -> bool {
        self.stop
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.text)
    }
}
type Result<T> = std::result::Result<T, Error>;
fn ensure(ok: bool, msg: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(Error { text: msg.to_owned(), stop: true }) }
}

#[path = "../canonical_cell.rs"]
mod canonical_cell;

#[test]
fn additional_positive_negative_control() {
    let mut scratch = vec![0x55; 4096];
    assert_eq!(canonical_cell::decode(b"\"valid\"", &mut scratch).unwrap(),
               Value::String("valid".into()));
    assert_eq!(scratch.len(), 0);
    assert!(canonical_cell::decode(br#"\"va\\u006cid\""#, &mut scratch).is_err());
    assert!(canonical_cell::decode(b"\"bad\\x00\"", &mut scratch).is_err());
}
