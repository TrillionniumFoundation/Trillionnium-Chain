//! Explicit independently provisioned bounds, not a SystemTime fallback.
//! The pinned clock must sample floor(unix seconds) after the fresh challenge,
//! never decrease or step forward, and advance by at most maximum_rate_ppm per BOOTTIME.
//! Those deployment properties need independent qualification evidence.
use super::frontier::{invalid, Digest32, Result, Validity};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

const NS: u128 = 1_000_000_000;
const PPM: u128 = 1_000_000;
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Contract {
    pub profile: String,
    pub integer_seconds_are_floor: bool,
    pub forward_steps_forbidden: bool,
    pub monotonic_nondecreasing: bool,
    // Total maximum rate, not drift: 1_000_000 means 1 trusted second per
    // BOOTTIME second, 2_000_000 means at most 2. No implicit/default contract.
    pub maximum_rate_ppm: u32,
}
impl Contract {
    pub fn validate(&self) -> Result<()> {
        if self.profile != "trnm-m15-boottime-bounded-clock-v1"
            || !self.integer_seconds_are_floor
            || !self.forward_steps_forbidden
            || !self.monotonic_nondecreasing
            || !(1_000_000..=2_000_000).contains(&self.maximum_rate_ppm)
        {
            return Err(invalid("M15 explicit bounded clock contract required"));
        }
        Ok(())
    }
    pub fn begin(&self) -> Result<Ticket> {
        self.validate()?;
        Ok(Ticket {
            contract: self.clone(),
            start: stamp()?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Stamp {
    boot: Digest32,
    namespace: (u64, u64),
    nanos: u128,
}
fn stamp() -> Result<Stamp> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open("/proc/sys/kernel/random/boot_id")?;
    if !file.metadata()?.is_file() {
        return Err(invalid("M15 boot identity type"));
    }
    let mut boot = Vec::new();
    Read::by_ref(&mut file).take(129).read_to_end(&mut boot)?;
    if boot.len() != 37
        || boot[36] != b'\n'
        || boot[..36].iter().enumerate().any(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                *b != b'-'
            } else {
                !b.is_ascii_hexdigit() || b.is_ascii_uppercase()
            }
        })
    {
        return Err(invalid("M15 boot identity encoding"));
    }
    let namespace = fs::metadata("/proc/self/ns/time")?;
    if namespace.ino() == 0 {
        return Err(invalid("M15 time namespace identity"));
    }
    // BOOTTIME includes suspend. Read last, after all identity I/O.
    let time = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds = u128::try_from(time.tv_sec).map_err(std::io::Error::other)?;
    let nanos = u128::try_from(time.tv_nsec).map_err(std::io::Error::other)?;
    if nanos >= NS {
        return Err(invalid("M15 invalid BOOTTIME nanoseconds"));
    }
    let nanos = seconds
        .checked_mul(NS)
        .and_then(|v| v.checked_add(nanos))
        .ok_or_else(|| invalid("M15 BOOTTIME overflow"))?;
    Ok(Stamp {
        boot: super::frontier::hash(b"TRNM/M15/LinuxBootIdentity/v1\0", &boot),
        namespace: (namespace.dev(), namespace.ino()),
        nanos,
    })
}

pub(super) struct Ticket {
    contract: Contract,
    start: Stamp,
}
pub(super) struct Sample {
    ticket: Ticket,
    floor_seconds: u64,
}
impl Ticket {
    /// Called only after verifying the signed response's nonce, exact request,
    /// namespace, domain and floor. Request creation occurs after begin().
    pub fn authenticated(self, floor_seconds: u64) -> Sample {
        Sample {
            ticket: self,
            floor_seconds,
        }
    }
}
impl Sample {
    // Only this observed lower bound is persisted as the time floor. The
    // conservative upper bound is never persisted/returned as a future sample.
    pub fn floor_seconds(&self) -> u64 {
        self.floor_seconds
    }
    fn upper_at(&self, current: &Stamp) -> Result<u128> {
        if current.boot != self.ticket.start.boot
            || current.namespace != self.ticket.start.namespace
        {
            return Err(invalid("M15 boot/time namespace changed"));
        }
        let elapsed = current
            .nanos
            .checked_sub(self.ticket.start.nanos)
            .ok_or_else(|| invalid("M15 BOOTTIME moved backwards"))?;
        let scaled = elapsed
            .checked_mul(u128::from(self.ticket.contract.maximum_rate_ppm))
            .and_then(|v| v.checked_add(PPM - 1))
            .map(|v| v / PPM)
            .ok_or_else(|| invalid("M15 clock interval scaling overflow"))?;
        // floor sample n means its true time is in [n,n+1). The sample was
        // taken after request start, so elapsed since start is conservative.
        (u128::from(self.floor_seconds) + 1)
            .checked_mul(NS)
            .and_then(|v| v.checked_add(scaled))
            .ok_or_else(|| invalid("M15 trusted time upper bound overflow"))
    }
    fn checked_upper(&self, current: &Stamp) -> Result<u128> {
        let upper = self.upper_at(current)?;
        if current
            .nanos
            .checked_sub(self.ticket.start.nanos)
            .ok_or_else(|| invalid("M15 BOOTTIME moved backwards"))?
            > 2 * NS
        {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        Ok(upper)
    }
    pub fn check_fresh(&self) -> Result<()> {
        self.checked_upper(&stamp()?).map(|_| ())
    }
    pub fn check(&self, validity: Validity) -> Result<()> {
        self.check_at(validity, &stamp()?)
    }
    fn check_at(&self, validity: Validity, current: &Stamp) -> Result<()> {
        validity.check(self.floor_seconds)?;
        let upper = self.checked_upper(current)?;
        let expires = u128::from(validity.expires_at)
            .checked_mul(NS)
            .ok_or_else(|| invalid("M15 expiry conversion overflow"))?;
        if upper > expires {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "M15 conservative trusted time interval is outside the exact window",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "clock_contract_tests.rs"]
mod tests;
