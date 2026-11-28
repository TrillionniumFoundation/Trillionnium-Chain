//! Test-only framed observer of the unchanged original public payload API.
//! All acceptance, replay, filesystem and commit decisions belong to the
//! original trnm_peer_lease crate. This file only translates method arguments
//! and public return values. The poison field is not publicly observable and
//! is marked zero; tests verify poisoning by subsequent public method calls.
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;
use trnm_peer_lease::{
    PayloadReplayDirectionV1 as Direction, PayloadReplayErrorV1 as Error,
    PayloadReplayFrameV1 as Frame, PayloadReplayNamespaceV1 as Namespace,
    PayloadReplayStoreV1 as Store, PeerLeaseScopeV1 as Scope,
};

type Failure = (u64, u64, u64, u64);
type Result<T> = std::result::Result<T, Failure>;
const WIRE: Failure = (100, 0, 0, 0);
fn word(b: &[u8], p: usize) -> u64 {
    u64::from_le_bytes(b[p..p + 8].try_into().unwrap())
}
fn array(b: &[u8], p: usize) -> [u8; 32] {
    b[p..p + 32].try_into().unwrap()
}
fn put(b: &mut Vec<u8>, n: u64) {
    b.extend_from_slice(&n.to_le_bytes());
}
fn direction(n: u64) -> Result<Direction> {
    match n {
        1 => Ok(Direction::Outbound),
        2 => Ok(Direction::Inbound),
        _ => Err(WIRE),
    }
}
fn reason(s: &str) -> u64 {
    match s {
        "payload replay authority file identity changed" => 1,
        "payload replay parent directory is a symlink alias" => 2,
        "payload replay file is not a private single-link regular file" => 3,
        "payload replay authority path identity changed" => 4,
        "payload replay parent directory identity changed" => 5,
        "payload replay head path is not a private regular file" => 6,
        "payload replay head descriptor/path identity changed" => 7,
        "payload replay head is not private" => 8,
        "payload replay path filename" => 9,
        "payload replay path has no parent" => 10,
        "payload replay parent directory is not private" => 11,
        "payload replay head exists for a virgin journal" => 12,
        "payload replay journal path is not a private regular file" => 13,
        "payload replay authority path is a symlink" => 14,
        "payload replay head appeared during virgin open" => 15,
        "payload replay head is not a private regular file" => 16,
        "journal path must be absolute" => 1001,
        "journal parent" => 1002,
        "journal anchor filename" => 1003,
        "journal parent must be a directory" => 1004,
        "journal parent must have private mode 0700" => 1005,
        "journal parent must be owned by the effective user" => 1006,
        "journal parent must not be a symlink alias" => 1007,
        "journal parent ancestry must not be group/world writable" => 1008,
        "journal parent ancestry must be root- or owner-controlled" => 1009,
        "journal parent must be a real directory" => 1014,
        "journal parent has no existing ancestor" => 1015,
        _ => 0,
    }
}
fn error(e: Error) -> Failure {
    eprintln!("ORIGINAL_PAYLOAD_ERROR Debug={e:?}; Display={e}");
    match e {
        Error::Truncated => (2, 0, 0, 0),
        Error::Corrupt => (3, 0, 0, 0),
        Error::ContextMismatch => (4, 0, 0, 0),
        Error::Replay => (5, 0, 0, 0),
        Error::StaleGeneration => (6, 0, 0, 0),
        Error::SequenceGap => (7, 0, 0, 0),
        Error::TooLarge => (8, 0, 0, 0),
        Error::Poisoned => (9, 0, 0, 0),
        Error::InvalidRequest(s) => (10, 0, reason(s), 0),
        Error::Protocol(_) => (12, 0, 0, 0),
        Error::CommitAmbiguous(inner) => {
            let (code, errno, reason, _) = error(*inner);
            (13, errno, reason, code)
        }
        Error::Io(e) => {
            if let Some(errno) = e.raw_os_error() {
                return (11, errno as u64, 0, 0);
            }
            let message = e.to_string();
            let why = match message.as_str() {
                "failed to write whole buffer" => 20,
                "file name contained an unexpected NUL byte" => 21,
                "payload replay head descriptor/path identity changed" => 23,
                _ => panic!("unmapped original non-errno I/O error: {message}"),
            };
            (11, 0, why, 0)
        }
    }
}
fn namespace(b: &[u8]) -> Result<Namespace> {
    Namespace::new(
        array(b, 0),
        word(b, 128),
        array(b, 32),
        array(b, 64),
        array(b, 96),
    )
    .map_err(error)
}
fn frame(b: &[u8]) -> Result<Frame> {
    // The same typed transport representation rejects invalid enum values
    // and numbers which cannot be represented by the original public API.
    let d = direction(word(b, 96))?;
    let scope =
        Scope::new(array(b, 0), array(b, 32), d, word(b, 104), array(b, 64)).map_err(|e| {
            eprintln!("ORIGINAL_SCOPE_ERROR {e:?}");
            (10, 0, 0, 0)
        })?;
    let kind = u8::try_from(word(b, 224)).map_err(|_| WIRE)?;
    let size = usize::try_from(word(b, 232)).map_err(|_| WIRE)?;
    Frame::new(
        scope,
        array(b, 112),
        array(b, 144),
        array(b, 176),
        word(b, 208),
        word(b, 216),
        kind,
        size,
        array(b, 240),
    )
    .map_err(error)
}
fn ns_bytes(n: Namespace, out: &mut Vec<u8>) {
    out.extend_from_slice(&n.local_id());
    out.extend_from_slice(&n.peer_scope_id());
    out.extend_from_slice(&n.run_id_hash());
    out.extend_from_slice(&n.network_context_hash());
    put(out, n.epoch());
}
fn execute(b: &[u8], owner: &mut Option<Store>) -> Result<Vec<u8>> {
    let op = word(b, 0);
    let mut out = Vec::new();
    match op {
        1 => {
            if owner.is_some() || b.len() < 152 || word(b, 144) != (b.len() - 152) as u64 {
                return Err(WIRE);
            }
            let ns = namespace(&b[8..144])?;
            let path = PathBuf::from(OsString::from_vec(b[152..].to_vec()));
            *owner = Some(Store::open(path, ns).map_err(error)?);
        }
        2 | 3 => {
            if b.len() != 280 {
                return Err(WIRE);
            }
            let store = owner.as_mut().ok_or(WIRE)?;
            let value = frame(&b[8..])?;
            if op == 2 {
                let receipt = store.admit(&value).map_err(error)?;
                put(&mut out, receipt.record_index());
                out.extend_from_slice(&receipt.record_hash());
            } else {
                match store.lookup_exact_v1(&value).map_err(error)? {
                    Some(receipt) => {
                        put(&mut out, 1);
                        put(&mut out, receipt.record_index());
                        out.extend_from_slice(&receipt.record_hash());
                    }
                    None => out.resize(48, 0),
                }
            }
        }
        4 => {
            if b.len() != 8 {
                return Err(WIRE);
            }
            owner
                .as_ref()
                .ok_or(WIRE)?
                .verify_bound_endpoint_identity()
                .map_err(error)?;
        }
        5 => {
            if b.len() != 8 {
                return Err(WIRE);
            }
            let store = owner.as_ref().ok_or(WIRE)?;
            let p = store.path().as_os_str().as_bytes();
            put(&mut out, p.len() as u64);
            out.extend_from_slice(p);
            let h = store.head_path().as_os_str().as_bytes();
            put(&mut out, h.len() as u64);
            out.extend_from_slice(h);
            ns_bytes(store.namespace(), &mut out);
            put(&mut out, store.accepted_frame_count());
        }
        6 => {
            if b.len() != 80 {
                return Err(WIRE);
            }
            let store = owner.as_ref().ok_or(WIRE)?;
            put(
                &mut out,
                u64::from(store.contains_session(
                    array(b, 8),
                    direction(word(b, 40))?,
                    array(b, 48),
                )),
            );
        }
        7 => {
            if b.len() != 48 {
                return Err(WIRE);
            }
            let store = owner.as_ref().ok_or(WIRE)?;
            match store.latest_generation(array(b, 8), direction(word(b, 40))?) {
                Some(n) => {
                    put(&mut out, 1);
                    put(&mut out, n);
                }
                None => out.resize(16, 0),
            }
        }
        8 | 9 => {
            if b.len() != 8 {
                return Err(WIRE);
            }
            drop(owner.take());
        }
        _ => return Err(WIRE),
    }
    Ok(out)
}
fn response(
    output: &mut impl Write,
    failure: Failure,
    body: &[u8],
    owner: &Option<Store>,
) -> io::Result<()> {
    let mut b = Vec::with_capacity(96 + body.len());
    put(&mut b, 88 + body.len() as u64);
    for n in [
        failure.0,
        failure.1,
        failure.2,
        failure.3,
        0,
        owner.as_ref().map_or(0, Store::record_count),
    ] {
        put(&mut b, n);
    }
    b.extend_from_slice(&owner.as_ref().map_or([0; 32], Store::last_hash));
    put(&mut b, body.len() as u64);
    b.extend_from_slice(body);
    output.write_all(&b)?;
    output.flush()
}
fn main() -> io::Result<()> {
    let input = io::stdin();
    let output = io::stdout();
    let mut i = input.lock();
    let mut o = output.lock();
    let mut owner = None;
    loop {
        let mut head = [0_u8; 8];
        let n = i.read(&mut head[..1])?;
        if n == 0 {
            break;
        }
        if i.read_exact(&mut head[1..]).is_err() {
            response(&mut o, WIRE, &[], &owner)?;
            break;
        }
        let length = u64::from_le_bytes(head);
        if !(8..=65536).contains(&length) {
            response(&mut o, WIRE, &[], &owner)?;
            break;
        }
        let mut body = vec![0; length as usize];
        if i.read_exact(&mut body).is_err() {
            response(&mut o, WIRE, &[], &owner)?;
            break;
        }
        let op = word(&body, 0);
        match execute(&body, &mut owner) {
            Ok(value) => response(&mut o, (0, 0, 0, 0), &value, &owner)?,
            Err(failure) => response(&mut o, failure, &[], &owner)?,
        }
        if op == 9 && body.len() == 8 {
            break;
        }
    }
    Ok(())
}
