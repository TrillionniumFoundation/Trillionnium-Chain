// Private qualification consumer; never built or used by production Worker.
use std::io::{self, Read, Write};

const MAX_OUTPUT: usize = 1 << 20;
const SCRATCH: usize = 102_400;
const FILL: u8 = 0xa5;
const SCRATCH_FILL: u8 = 0xd6;
const INVALID: u32 = u32::MAX;
const CAPACITY: u32 = u32::MAX - 1;

unsafe extern "C" {
    fn trnm_worker_journal_audit_export_v1(
        snapshot: *const u8,
        snapshot_bytes: usize,
        output: *mut u8,
        output_bytes: usize,
        scratch: *mut u8,
        scratch_bytes: usize,
    ) -> u64;
}

fn call(snapshot: &[u8], output: &mut [u8], scratch: &mut [u8]) -> (u32, u32) {
    // SAFETY: an immutable live slice and two independent unique mutable
    // slices. Their capacities are unchanged and never retained by HIA.
    let value = unsafe {
        trnm_worker_journal_audit_export_v1(
            snapshot.as_ptr(), snapshot.len(), output.as_mut_ptr(), output.len(),
            scratch.as_mut_ptr(), scratch.len(),
        )
    };
    ((value >> 32) as u32, value as u32)
}

fn main() -> io::Result<()> {
    let mut args = std::env::args().skip(1);
    let cap: usize = args.next().unwrap().parse().unwrap();
    let scratch_cap: usize = args.next().unwrap().parse().unwrap();
    assert!(args.next().is_none() && cap <= MAX_OUTPUT && scratch_cap <= MAX_OUTPUT);
    let mut snapshot = Vec::new();
    io::stdin().take(65_538).read_to_end(&mut snapshot)?;
    assert!(snapshot.len() <= 65_537);
    let original = snapshot.clone();
    let mut output = vec![FILL; cap];
    let mut scratch = vec![SCRATCH_FILL; scratch_cap];
    let (abi, result) = call(&snapshot, &mut output, &mut scratch);
    assert_eq!(snapshot, original);
    assert!(scratch.get(SCRATCH..).unwrap_or(&[]).iter().all(|&b| b == SCRATCH_FILL));
    let written = if abi != 0 || matches!(result, INVALID | CAPACITY) { 0 } else { result as usize };
    assert!(written <= cap && output[written..].iter().all(|&b| b == FILL));
    let mut out = io::stdout().lock();
    out.write_all(&abi.to_le_bytes())?;
    out.write_all(&result.to_le_bytes())?;
    out.write_all(&output[..written])
}
