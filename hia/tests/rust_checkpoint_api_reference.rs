//! Pipe adapter around the unchanged original Rust public API and private CLI
//! ledger source. This executable is an independent qualification oracle.
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    io::{self, Read, Write},
    os::unix::ffi::OsStrExt,
    process,
    time::Duration,
};
use trnm_checkpoint_store::{
    read_external_journal_checkpoint_v1, write_new_external_journal_checkpoint_v1,
    ExternalCheckpointAuthorityErrorV2 as AuthorityError, ExternalCheckpointAuthorityV2,
    ExternalJournalCheckpointV1, UnixExternalCheckpointStoreV2,
};
use trnm_checkpoint_types::{
    ExternalCheckpointStoreErrorV2, ExternalCheckpointStoreV2, ExternalCheckpointV2,
};
#[path = "../../trillionnium/crates/trnm-checkpoint-store/src/node_commit_ledger_v1.rs"]
mod ledger_original;
use ledger_original::{
    NodeCommitConvergenceV1, NodeCommitLedgerErrorV1 as LedgerError, NodeCommitLedgerHeadV1,
    NodeCommitLedgerV1,
};

#[derive(Debug)]
struct Failure {
    status: u64,
    code: u64,
    errno: u64,
    text: String,
}
fn code(kind: &str, text: &str) -> u64 {
    let prefix = match kind {
        "config" => 1,
        "log" => 2,
        "io" => 3,
        "protocol" => 4,
        "compare" => 5,
        "unavailable" => 6,
        "ledger_path" => 7,
        "ledger_state" => 8,
        "ledger_source" => 9,
        "ledger_target" => 10,
        "ledger_third" => 11,
        "ledger_io" => 12,
        "store" => 13,
        _ => panic!("unknown oracle error kind"),
    };
    let digest = Sha256::digest(format!("{kind}:{text}").as_bytes());
    (prefix << 32) | u64::from(u32::from_be_bytes(digest[..4].try_into().unwrap()))
}
fn io_number(error: &io::Error) -> u64 {
    if let Some(number) = error.raw_os_error() {
        return number as u64;
    }
    let detail = match error.to_string().as_str() {
        "paths must not contain interior null bytes" => 0x104,
        "path must be shorter than SUN_LEN" => 0x204,
        "checkpoint socket listener is still live" => 0x305,
        "cannot set a 0 duration timeout" => 0x404,
        _ => match error.kind() {
            io::ErrorKind::UnexpectedEof => 1,
            io::ErrorKind::WriteZero => 2,
            io::ErrorKind::TimedOut => 3,
            io::ErrorKind::InvalidInput => 4,
            io::ErrorKind::AddrInUse => 5,
            _ => 255,
        },
    };
    (1u64 << 32) + detail
}
impl From<AuthorityError> for Failure {
    fn from(error: AuthorityError) -> Self {
        let (kind, detail, errno) = match &error {
            AuthorityError::InvalidConfig(value) => ("config", *value, 0),
            AuthorityError::InvalidLog(value) => ("log", *value, 0),
            AuthorityError::Protocol(value) => ("protocol", *value, 0),
            AuthorityError::Io { stage, source } => ("io", *stage, io_number(source)),
            AuthorityError::CompareFailed => {
                ("compare", "node-checkpoint compare-and-advance failed", 0)
            }
            AuthorityError::Unavailable => {
                ("unavailable", "node-checkpoint authority unavailable", 0)
            }
        };
        Self {
            status: 1,
            code: code(kind, detail),
            errno,
            text: error.to_string(),
        }
    }
}
impl From<LedgerError> for Failure {
    fn from(error: LedgerError) -> Self {
        let (kind, detail, errno) = match &error {
            LedgerError::InvalidPath(value) => ("ledger_path", *value, 0),
            LedgerError::InvalidState(value) => ("ledger_state", *value, 0),
            LedgerError::Io { stage, source } => ("ledger_io", *stage, io_number(source)),
            LedgerError::SourceMismatch => (
                "ledger_source",
                "node commit ledger source differs from durable head",
                0,
            ),
            LedgerError::TargetNotSuccessor => (
                "ledger_target",
                "node commit ledger target is not the exact successor",
                0,
            ),
            LedgerError::ThirdState => (
                "ledger_third",
                "node commit ledger observed neither exact source nor exact target",
                0,
            ),
        };
        Self {
            status: 1,
            code: code(kind, detail),
            errno,
            text: error.to_string(),
        }
    }
}
impl From<ExternalCheckpointStoreErrorV2> for Failure {
    fn from(error: ExternalCheckpointStoreErrorV2) -> Self {
        let text = error.to_string();
        Self {
            status: 1,
            code: code("store", &text),
            errno: 0,
            text,
        }
    }
}
fn abi(detail: &'static str) -> Failure {
    Failure {
        status: 2,
        code: code("config", detail),
        errno: 0,
        text: format!("invalid node-checkpoint config: {detail}"),
    }
}
fn exact(bytes: &[u8], size: usize) -> Result<(), Failure> {
    if bytes.len() == size {
        Ok(())
    } else {
        Err(abi("native API request body"))
    }
}
fn minimum(bytes: &[u8], size: usize) -> Result<(), Failure> {
    if bytes.len() >= size {
        Ok(())
    } else {
        Err(abi("native API request body"))
    }
}
fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
fn checkpoint(bytes: &[u8]) -> Result<ExternalCheckpointV2, Failure> {
    ExternalCheckpointV2::decode_canonical_exact(bytes)
        .map_err(|_| abi("native API checkpoint value"))
}
fn compare_input(
    bytes: &[u8],
) -> Result<(Option<ExternalCheckpointV2>, ExternalCheckpointV2), Failure> {
    exact(bytes, 1352)?;
    let present = u64_at(bytes, 0);
    if present > 1 {
        return Err(abi("native API request body"));
    }
    let target = checkpoint(&bytes[680..])?;
    let source = if present == 1 {
        Some(checkpoint(&bytes[8..680])?)
    } else {
        None
    };
    Ok((source, target))
}
fn value_bytes(value: Option<ExternalCheckpointV2>) -> Vec<u8> {
    let mut result = u64::from(value.is_some()).to_le_bytes().to_vec();
    if let Some(value) = value {
        result.extend(value.encode_canonical());
    }
    result
}
fn head_bytes(value: NodeCommitLedgerHeadV1) -> Vec<u8> {
    let mut result = value.sequence.to_le_bytes().to_vec();
    result.extend(value.checkpoint.encode_canonical());
    result.extend(value.record_digest);
    result
}
enum Owner {
    Authority(Box<ExternalCheckpointAuthorityV2>),
    Client(UnixExternalCheckpointStoreV2),
    Ledger(Box<NodeCommitLedgerV1>),
}
#[derive(Default)]
struct Session {
    owner: Option<Owner>,
}
impl Session {
    fn vacant(&self) -> Result<(), Failure> {
        if self.owner.is_none() {
            Ok(())
        } else {
            Err(abi("native API owner kind"))
        }
    }
    fn authority(&mut self) -> Result<&mut ExternalCheckpointAuthorityV2, Failure> {
        match self.owner.as_mut() {
            Some(Owner::Authority(value)) => Ok(value),
            _ => Err(abi("native API owner kind")),
        }
    }
    fn client(&mut self) -> Result<&mut UnixExternalCheckpointStoreV2, Failure> {
        match self.owner.as_mut() {
            Some(Owner::Client(value)) => Ok(value),
            _ => Err(abi("native API owner kind")),
        }
    }
    fn ledger(&mut self) -> Result<&mut NodeCommitLedgerV1, Failure> {
        match self.owner.as_mut() {
            Some(Owner::Ledger(value)) => Ok(value),
            _ => Err(abi("native API owner kind")),
        }
    }
    fn execute(&mut self, op: u64, bytes: &[u8]) -> Result<Vec<u8>, Failure> {
        match op {
            1..=3 => {
                if op != 1 {
                    exact(bytes, 84)?;
                }
                let value = ExternalJournalCheckpointV1::decode_canonical_exact(bytes)?;
                if op == 3 {
                    let mut out = value.record_count().to_le_bytes().to_vec();
                    out.extend(value.root());
                    Ok(out)
                } else {
                    Ok(value.encode_canonical().to_vec())
                }
            }
            4 => Ok(
                read_external_journal_checkpoint_v1(OsStr::from_bytes(bytes))?
                    .encode_canonical()
                    .to_vec(),
            ),
            5 => {
                minimum(bytes, 84)?;
                let value = ExternalJournalCheckpointV1::decode_canonical_exact(&bytes[..84])?;
                write_new_external_journal_checkpoint_v1(OsStr::from_bytes(&bytes[84..]), value)?;
                Ok(vec![])
            }
            10..=12 => {
                self.vacant()?;
                let value = if op == 12 {
                    minimum(bytes, 84)?;
                    let pin = ExternalJournalCheckpointV1::decode_canonical_exact(&bytes[..84])?;
                    ExternalCheckpointAuthorityV2::reopen_with_external_checkpoint(
                        OsStr::from_bytes(&bytes[84..]),
                        pin,
                    )?
                } else if op == 11 {
                    ExternalCheckpointAuthorityV2::register_new(OsStr::from_bytes(bytes))?
                } else {
                    ExternalCheckpointAuthorityV2::open(OsStr::from_bytes(bytes))?
                };
                self.owner = Some(Owner::Authority(Box::new(value)));
                Ok(vec![])
            }
            13 => {
                let value = self.authority()?;
                exact(bytes, 0)?;
                Ok(value.log_path().as_os_str().as_bytes().to_vec())
            }
            14 => {
                let value = self.authority()?;
                exact(bytes, 0)?;
                Ok(value.journal_checkpoint_v1()?.encode_canonical().to_vec())
            }
            15 => {
                let value = self.authority()?;
                exact(bytes, 0)?;
                value.revalidate_bound_endpoints_v2()?;
                Ok(vec![])
            }
            16 => {
                let value = self.authority()?;
                exact(bytes, 32)?;
                Ok(value_bytes(value.load_checked(bytes.try_into().unwrap())?))
            }
            17 => {
                let value = self.authority()?;
                let (source, target) = compare_input(bytes)?;
                value.compare_and_advance_checked(source, target)?;
                Ok(vec![])
            }
            18 => {
                self.authority()?;
                let Some(Owner::Authority(value)) = self.owner.take() else {
                    unreachable!()
                };
                value.serve_unix(OsStr::from_bytes(bytes))?;
                Ok(vec![])
            }
            19 => {
                self.authority()?;
                exact(bytes, 0)?;
                self.owner = None;
                Ok(vec![])
            }
            30 => {
                self.vacant()?;
                self.owner = Some(Owner::Client(UnixExternalCheckpointStoreV2::new(
                    OsStr::from_bytes(bytes),
                )?));
                Ok(vec![])
            }
            31 => {
                let value = self.client()?;
                exact(bytes, 16)?;
                let nanos = u64_at(bytes, 8);
                if nanos >= 1_000_000_000 {
                    return Err(abi("native API request body"));
                }
                *value = value
                    .clone()
                    .with_timeout(Duration::new(u64_at(bytes, 0), nanos as u32));
                Ok(vec![])
            }
            32 => {
                let value = self.client()?;
                exact(bytes, 0)?;
                Ok(value.socket_path().as_os_str().as_bytes().to_vec())
            }
            33 => {
                let value = self.client()?;
                exact(bytes, 0)?;
                Ok(value.journal_checkpoint_v1()?.encode_canonical().to_vec())
            }
            34 | 36 => {
                let value = self.client()?;
                exact(bytes, 32)?;
                let scope = bytes.try_into().unwrap();
                let loaded = if op == 36 {
                    ExternalCheckpointStoreV2::load(value, scope)?
                } else {
                    value.load_checked(scope)?
                };
                Ok(value_bytes(loaded))
            }
            35 | 37 => {
                let value = self.client()?;
                let (source, target) = compare_input(bytes)?;
                if op == 37 {
                    ExternalCheckpointStoreV2::compare_and_advance(value, source, target)?;
                } else {
                    value.compare_and_advance_checked(source, target)?;
                }
                Ok(vec![])
            }
            38 => {
                self.client()?;
                exact(bytes, 0)?;
                self.owner = None;
                Ok(vec![])
            }
            40 => {
                self.vacant()?;
                minimum(bytes, 672)?;
                let value = checkpoint(&bytes[..672])?;
                self.owner = Some(Owner::Ledger(Box::new(NodeCommitLedgerV1::initialize_new(
                    OsStr::from_bytes(&bytes[672..]),
                    value,
                )?)));
                Ok(vec![])
            }
            41 => {
                self.vacant()?;
                minimum(bytes, 1344)?;
                let source = checkpoint(&bytes[..672])?;
                let target = checkpoint(&bytes[672..1344])?;
                self.owner = Some(Owner::Ledger(Box::new(
                    NodeCommitLedgerV1::open_existing_expected(
                        OsStr::from_bytes(&bytes[1344..]),
                        source,
                        target,
                    )?,
                )));
                Ok(vec![])
            }
            42 => {
                let value = self.ledger()?;
                exact(bytes, 0)?;
                Ok(head_bytes(value.head()))
            }
            43 | 44 => {
                let value = self.ledger()?;
                exact(bytes, 1344)?;
                let source = checkpoint(&bytes[..672])?;
                let target = checkpoint(&bytes[672..])?;
                if op == 43 {
                    Ok(head_bytes(value.append_exact_successor(source, target)?))
                } else {
                    Ok(
                        match value.resolve_exact_source_or_target(source, target)? {
                            NodeCommitConvergenceV1::Source => 0u64,
                            NodeCommitConvergenceV1::Target => 1u64,
                        }
                        .to_le_bytes()
                        .to_vec(),
                    )
                }
            }
            45 => {
                self.ledger()?;
                exact(bytes, 0)?;
                self.owner = None;
                Ok(vec![])
            }
            50 => Ok(
                ledger_original::read_checkpoint_file_v1(std::path::Path::new(OsStr::from_bytes(
                    bytes,
                )))?
                .encode_canonical()
                .to_vec(),
            ),
            60 => {
                exact(bytes, 16)?;
                let number = u64_at(bytes, 8);
                let source = if number < (1 << 32) {
                    io::Error::from_raw_os_error(number as i32)
                } else {
                    match number - (1 << 32) {
                        1 => io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "failed to fill whole buffer",
                        ),
                        2 => {
                            io::Error::new(io::ErrorKind::WriteZero, "failed to write whole buffer")
                        }
                        3 => io::Error::new(
                            io::ErrorKind::TimedOut,
                            "checkpoint frame deadline expired",
                        ),
                        4 => io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "file name contained an unexpected NUL byte",
                        ),
                        0x104 => io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "paths must not contain interior null bytes",
                        ),
                        0x204 => io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "path must be shorter than SUN_LEN",
                        ),
                        0x305 => io::Error::new(
                            io::ErrorKind::AddrInUse,
                            "checkpoint socket listener is still live",
                        ),
                        0x404 => io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "cannot set a 0 duration timeout",
                        ),
                        _ => return Err(abi("native API request body")),
                    }
                };
                if u64_at(bytes, 0) != code("io", "Unix transport") {
                    return Err(abi("native API request body"));
                }
                Ok(AuthorityError::Io {
                    stage: "Unix transport",
                    source,
                }
                .to_string()
                .into_bytes())
            }
            62 => {
                exact(bytes, 0)?;
                Ok((1u64 | (1 << 8) | (1 << 9)).to_le_bytes().to_vec())
            }
            _ => Err(abi("native API method")),
        }
    }
}
fn main() {
    let mut session = Session::default();
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    loop {
        let mut header = [0u8; 32];
        let mut first = [0u8; 1];
        match input.read(&mut first) {
            Ok(0) => break,
            Ok(1) => header[0] = first[0],
            _ => process::exit(101),
        }
        if input.read_exact(&mut header[1..]).is_err() {
            process::exit(64)
        }
        if &header[..8] != b"HCSAPI01" || u64_at(&header, 24) != 0 {
            process::exit(64)
        }
        let op = u64_at(&header, 8);
        let length = u64_at(&header, 16);
        if length >= (1u64 << 63) - 4096 {
            process::exit(64)
        }
        let mut body = vec![0; usize::try_from(length).unwrap()];
        if input.read_exact(&mut body).is_err() {
            process::exit(64)
        }
        let (status, error, errno, payload) = match session.execute(op, &body) {
            Ok(value) => (0, 0, 0, value),
            Err(error) => (
                error.status,
                error.code,
                error.errno,
                error.text.into_bytes(),
            ),
        };
        output.write_all(b"HCSAPO01").unwrap();
        for value in [status, error, errno, payload.len() as u64, op] {
            output.write_all(&value.to_le_bytes()).unwrap();
        }
        output.write_all(&payload).unwrap();
        output.flush().unwrap();
    }
}
