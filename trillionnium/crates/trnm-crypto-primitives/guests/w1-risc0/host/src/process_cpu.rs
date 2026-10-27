//! Linux process CPU observations; no clock or measurement enters the guest.
use anyhow::{ensure, Result};

#[cfg(target_os = "linux")]
pub fn nanoseconds() -> Result<u128> {
    #[repr(C)]
    struct Timespec {
        seconds: std::ffi::c_long,
        nanos: std::ffi::c_long,
    }
    unsafe extern "C" {
        fn clock_gettime(clock: std::ffi::c_int, value: *mut Timespec) -> std::ffi::c_int;
    }
    let mut value = Timespec {
        seconds: 0,
        nanos: 0,
    };
    // CLOCK_PROCESS_CPUTIME_ID includes every thread in this verifier process.
    // The fixed Linux x86_64 tool profile does not use this for child r0vm CPU:
    // measure_step.py separately records the waited child family's resource use.
    // SAFETY: value is a valid, aligned, writable platform timespec for the call.
    let status = unsafe { clock_gettime(2, &mut value) };
    ensure!(
        status == 0 && value.seconds >= 0 && (0..1_000_000_000).contains(&value.nanos),
        "Linux process CPU clock unavailable"
    );
    Ok(value.seconds as u128 * 1_000_000_000 + value.nanos as u128)
}

#[cfg(not(target_os = "linux"))]
pub fn nanoseconds() -> Result<u128> {
    anyhow::bail!("this pinned research observation requires the Linux process CPU clock")
}
