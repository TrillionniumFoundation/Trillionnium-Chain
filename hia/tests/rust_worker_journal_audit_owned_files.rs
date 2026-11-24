// Private qualification driver; filenames are fixed, not caller-controlled.
// Do not use it as a journal owner or production export CLI.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

const INPUT: &str = "ingress.jsonl";
const OUT: [&str; 3] = ["audit.jsonl", "audit.md", "audit.jsonl.index.json"];
const IN_LIMIT: usize = 65_536;
const OUT_LIMIT: usize = 1 << 20;
const SCRATCH: usize = 102_400;
const FILL: u8 = 0xa5;
// The driver's fixed Linux x86-64 admission does not implement the original
// journal owner. These local open flags merely protect its fixture boundary.
const READ_FLAGS: i32 = 0o400000 | 0o4000; // O_NOFOLLOW | O_NONBLOCK
const WRITE_FLAGS: i32 = 0o400000; // O_NOFOLLOW

unsafe extern "C" {
    fn trnm_worker_journal_audit_export_v3(
        bytes: *const u8,
        length: usize,
        output: *mut u8,
        capacity: usize,
        scratch: *mut u8,
        scratch_capacity: usize,
    ) -> u64;
}

fn error(message: &'static str) -> io::Error {
    io::Error::other(message)
}

fn read_fixture() -> io::Result<Vec<u8>> {
    let cwd = fs::metadata(".")?;
    if !cwd.is_dir() || cwd.mode() & 0o077 != 0 {
        return Err(error("fixture directory is not private"));
    }
    let mut file = OpenOptions::new().read(true).custom_flags(READ_FLAGS).open(INPUT)?;
    let before = file.metadata()?;
    if !before.is_file() || before.nlink() != 1 || before.uid() != cwd.uid()
        || before.mode() & 0o077 != 0 || before.len() > IN_LIMIT as u64
    {
        return Err(error("fixture input metadata or limit"));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file).take(IN_LIMIT as u64 + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() > IN_LIMIT || bytes.len() as u64 != before.len()
        || after.len() != before.len() || after.modified()? != before.modified()?
    {
        return Err(error("fixture input length or readback changed"));
    }
    Ok(bytes)
}

fn split_wao(raw: &[u8]) -> io::Result<[&[u8]; 3]> {
    let header = raw.get(..16).ok_or_else(|| error("short WQX packet"))?;
    if &header[..4] != b"WAO1" {
        return Err(error("unexpected WQX packet tag"));
    }
    let mut lengths = [0usize; 3];
    for (slot, word) in lengths.iter_mut().zip(header[4..].chunks_exact(4)) {
        *slot = u32::from_le_bytes(word.try_into().unwrap()) as usize;
    }
    let mut pieces = [&[][..]; 3];
    let mut offset = 16usize;
    for (dst, count) in pieces.iter_mut().zip(lengths) {
        let end = offset.checked_add(count).ok_or_else(|| error("invalid WQX length"))?;
        *dst = raw.get(offset..end).ok_or_else(|| error("out of extent WQX section"))?;
        offset = end;
    }
    if offset != raw.len() {
        return Err(error("extra WQX packet bytes"));
    }
    Ok(pieces)
}

fn write_new(path: &str, body: &[u8]) -> io::Result<()> {
    let mut file: File = OpenOptions::new()
        .write(true).create_new(true).mode(0o600).custom_flags(WRITE_FLAGS).open(path)?;
    file.write_all(body)?;
    file.flush()
}

fn run() -> io::Result<()> {
    if std::env::args_os().len() != 1 {
        return Err(error("fixture does not take paths or options"));
    }
    let bytes = read_fixture()?;
    // Detect a previously occupied name before creating any of the outputs.
    // The actual writes still use create_new; a later failure is not a
    // multi-file atomic transaction and no names are removed or overwritten.
    for path in OUT {
        match fs::symlink_metadata(path) {
            Ok(_) => return Err(error("fixture output already exists")),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e),
        }
    }
    let mut output = vec![FILL; OUT_LIMIT];
    let mut scratch = vec![0xd6; SCRATCH + 13];
    // SAFETY: the owned whole-file buffer is live and read-only, and both
    // writable slices are distinct initialized allocations kept for the call.
    let result = unsafe {
        trnm_worker_journal_audit_export_v3(
            bytes.as_ptr(), bytes.len(), output.as_mut_ptr(), output.len(),
            scratch.as_mut_ptr(), scratch.len(),
        )
    };
    if result >> 32 != 0 {
        return Err(error("WQX outer ABI refusal"));
    }
    let n = result as u32;
    if n == u32::MAX || n == u32::MAX - 1 {
        if output.iter().any(|&v| v != FILL) {
            return Err(error("WQX refusal modified output"));
        }
        return Err(error("WQX profile or capacity refusal"));
    }
    let n = n as usize;
    if n > output.len() || output[n..].iter().any(|&v| v != FILL)
        || scratch[SCRATCH..].iter().any(|&v| v != 0xd6)
    {
        return Err(error("WQX result or tail changed"));
    }
    let parts = split_wao(&output[..n])?;
    for (path, body) in OUT.into_iter().zip(parts) {
        write_new(path, body)?;
    }
    writeln!(io::stdout().lock(), "WQX3 fixture emitted {n} bytes")
}

fn main() {
    if let Err(err) = run() {
        eprintln!("offline Worker fixture: {err}");
        std::process::exit(1);
    }
}
