//! Fixed private Rust transport for exact stock HIA window calls.
//! This fixture is not a native syscall, SQL, filesystem or custody owner.
use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::mem::ManuallyDrop;
use std::os::fd::{FromRawFd, IntoRawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt};

const WINDOW: usize = 65_536;
const CHUNK: usize = 4_194_304;
const ALL_SEALS: i32 = 15;
const GET_SEALS: i32 = 1034;

unsafe extern "C" {
    fn fcntl(fd: i32, command: i32, ...) -> i32;
    fn close(fd: i32) -> i32;
    #[link_name = "f0"]
    fn stock_hia(
        data: *const u8, n: usize, out: *mut u8, cap: usize, scratch: *mut u8, m: usize,
    ) -> u64;
}

fn seals() -> i32 {
    // Fixed inherited private input only; no descriptor value from a caller.
    unsafe { fcntl(0, GET_SEALS) }
}

fn filling(f: &mut File, mut out: &mut [u8], retry: &mut usize) -> Result<(), u8> {
    while !out.is_empty() {
        match f.read(out) {
            Ok(0) => return Err(73),
            Ok(n) => out = &mut out[n..],
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted && *retry > 0 => *retry -= 1,
            Err(_) => return Err(73),
        }
    }
    Ok(())
}

fn probe(f: &mut File, retry: &mut usize) -> Result<(), u8> {
    let mut sentinel = [0; 1];
    loop {
        match f.read(&mut sentinel) {
            Ok(0) => return Ok(()),
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted && *retry > 0 => *retry -= 1,
            _ => return Err(73),
        }
    }
}

fn call(raw: &[u8], out: &mut [u8], scratch: &mut [u8]) -> u64 {
    // Three owned disjoint loans; all lengths are checked by the stock entry.
    unsafe { stock_hia(raw.as_ptr(), raw.len(), out.as_mut_ptr(), out.len(),
                       scratch.as_mut_ptr(), scratch.len()) }
}

fn run() -> Result<(), u8> {
    let mut source = unsafe { File::from_raw_fd(0) };
    let mut sink = ManuallyDrop::new(unsafe { File::from_raw_fd(1) });
    let before = source.metadata().map_err(|_| 70u8)?;
    if !before.is_file() || seals() != ALL_SEALS {
        return Err(70);
    }
    if before.size() > (CHUNK + WINDOW) as u64 {
        return Err(71);
    }
    if source.stream_position().map_err(|_| 72u8)? != 0 {
        return Err(72);
    }
    if !sink.metadata().map_err(|_| 75u8)?.file_type().is_fifo() {
        return Err(75);
    }
    let physical_size = before.size() as usize;
    if physical_size < 20 {
        return Err(73);
    }
    let mut retry = 8;
    let mut input = vec![0; WINDOW + 8];
    let mut output = vec![0xa5; WINDOW + 16];
    let mut scratch = vec![0; 69_632];
    filling(&mut source, &mut input[8..28], &mut retry)?;
    let m = u32::from_le_bytes(input[24..28].try_into().unwrap()) as usize;
    if m > WINDOW-20 || m > physical_size-20 {
        return Err(73);
    }
    let mut remaining = physical_size-20-m;
    if remaining > CHUNK {
        return Err(71);
    }
    filling(&mut source,&mut input[28..28+m],&mut retry)?;
    if call(&input[..28+m],&mut output,&mut scratch)!=0 {
        return Err(74);
    }
    input[..8].copy_from_slice(&1u64.to_le_bytes());
    while remaining != 0 {
        let n = remaining.min(WINDOW);
        filling(&mut source,&mut input[8..8+n],&mut retry)?;
        if call(&input[..8+n],&mut output,&mut scratch)!=0 {
            return Err(74);
        }
        remaining -= n;
    }
    // A real EOF and the measured private FD must survive all native calls.
    probe(&mut source, &mut retry)?;
    let after = source.metadata().map_err(|_| 73u8)?;
    let cursor = source.stream_position().map_err(|_| 73u8)?;
    if (before.dev(),before.ino(),before.size()) != (after.dev(),after.ino(),after.size())
        || seals() != ALL_SEALS || cursor != before.size()
        || output.iter().any(|&b| b!=0xa5) {
        return Err(73);
    }
    if source.into_raw_fd() != 0 || unsafe { close(0) } != 0 {
        return Err(73);
    }
    if call(&2u64.to_le_bytes(),&mut output,&mut scratch)!=0 {
        return Err(74);
    }
    let count = u64::from_le_bytes(output[8..16].try_into().unwrap());
    if count > WINDOW as u64 || output[16+count as usize..].iter().any(|&b| b!=0xa5) {
        return Err(74);
    }
    sink.write_all(&output[..16+count as usize]).map_err(|_| 76u8)?;
    Ok(())
}

fn main() {
    if !cfg!(target_os="linux") || !cfg!(target_arch="x86_64") {
        std::process::exit(77);
    }
    if let Err(status) = run() {
        std::process::exit(i32::from(status));
    }
}
