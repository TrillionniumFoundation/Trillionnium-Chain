use std::{
    io::{self, Read, Write},
    net::TcpStream,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use super::{
    require, CellBep52StorageBindingV2, CellDigestV1, CellErrorV1, CellResultV1,
    MAX_CELL_BEP52_STORAGE_FRAME_BYTES_V2,
};
use crate::cell::MAX_CELL_BYTES;

const IO_POLL: Duration = Duration::from_millis(25);
const MAX_SESSION_BYTES: u64 = 2 * MAX_CELL_BYTES;
const MAX_SESSION_MESSAGES: u64 = 10_000_000;

/// An explicit original reservation. Bounds are for this new profile only;
/// existing BEP52 V1 framing and limits retain their prior meanings.
#[derive(Clone, Copy, Debug)]
pub struct CellBep52StoragePeerLimitsV2 {
    pub deadline: Instant,
    pub request_timeout: Duration,
    pub max_connections: u64,
    pub max_received_bytes: u64,
    pub max_sent_bytes: u64,
    /// Combined incoming/outgoing frame admissions, including EOF read attempts.
    pub max_messages: u64,
}

impl CellBep52StoragePeerLimitsV2 {
    fn validate(self) -> CellResultV1<()> {
        require(
            (Duration::from_millis(10)..=Duration::from_secs(30)).contains(&self.request_timeout),
            "CBL2 request timeout",
        )?;
        require(
            (1..=8).contains(&self.max_connections),
            "CBL2 connection bound",
        )?;
        require(
            self.max_received_bytes <= MAX_SESSION_BYTES
                && self.max_sent_bytes <= MAX_SESSION_BYTES,
            "CBL2 session byte bounds",
        )?;
        require(
            (1..=MAX_SESSION_MESSAGES).contains(&self.max_messages),
            "CBL2 frame bound",
        )?;
        let now = Instant::now();
        require(
            self.deadline > now && self.deadline.duration_since(now) <= Duration::from_secs(86_400),
            "CBL2 original deadline",
        )
    }
}

/// Actual application socket bytes, including partial/rejected frames. TCP/IP
/// overhead and bytes not read from a socket are outside these counters.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CellBep52StoragePeerUsageV2 {
    pub connection_attempts: u64,
    pub received_bytes: u64,
    pub sent_bytes: u64,
    pub received_messages: u64,
    pub sent_messages: u64,
    pub failed_connections: u64,
    pub completed_fetches: u64,
}

/// Reuse this non-cloneable owner after failure. Its identity, pinned mapping,
/// absolute deadline and cumulative counters cannot be reset by a new peer.
pub struct CellBep52StoragePeerSessionV2 {
    operation_id: CellDigestV1,
    scope: Option<(CellDigestV1, CellDigestV1)>,
    limits: CellBep52StoragePeerLimitsV2,
    usage: CellBep52StoragePeerUsageV2,
    cancelled: Arc<AtomicBool>,
    cancellation_latched: bool,
}

impl CellBep52StoragePeerSessionV2 {
    pub fn new(
        operation_id: CellDigestV1,
        limits: CellBep52StoragePeerLimitsV2,
    ) -> CellResultV1<Self> {
        require(operation_id != [0; 32], "CBL2 operation identity")?;
        limits.validate()?;
        Ok(Self {
            operation_id,
            scope: None,
            limits,
            usage: CellBep52StoragePeerUsageV2::default(),
            cancelled: Arc::new(AtomicBool::new(false)),
            cancellation_latched: false,
        })
    }

    pub fn operation_id(&self) -> CellDigestV1 {
        self.operation_id
    }
    pub fn deadline(&self) -> Instant {
        self.limits.deadline
    }
    pub fn usage(&self) -> &CellBep52StoragePeerUsageV2 {
        &self.usage
    }
    pub fn cancellation_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancelled)
    }

    pub(super) fn bind(&mut self, binding: &CellBep52StorageBindingV2) -> CellResultV1<()> {
        self.check(self.deadline())?;
        let scope = (binding.manifest_id(), binding.mapping_id());
        if let Some(original) = self.scope {
            require(original == scope, "CBL2 original operation scope")?;
        } else {
            self.scope = Some(scope);
        }
        Ok(())
    }

    pub(super) fn check(&mut self, deadline: Instant) -> CellResultV1<()> {
        self.cancellation_latched |= self.cancelled.load(Ordering::Acquire);
        require(!self.cancellation_latched, "CBL2 operation cancelled")?;
        require(
            Instant::now() < deadline.min(self.limits.deadline),
            "CBL2 original deadline",
        )
    }

    pub(super) fn request_deadline(&mut self) -> CellResultV1<Instant> {
        self.check(self.deadline())?;
        Ok((Instant::now() + self.limits.request_timeout).min(self.limits.deadline))
    }

    pub(super) fn remaining(&mut self, deadline: Instant) -> CellResultV1<Duration> {
        self.check(deadline)?;
        Ok(deadline
            .min(self.deadline())
            .saturating_duration_since(Instant::now())
            .max(Duration::from_micros(1)))
    }

    pub(super) fn connection(&mut self) -> CellResultV1<()> {
        self.check(self.deadline())?;
        require(
            self.usage.connection_attempts < self.limits.max_connections,
            "CBL2 connection budget",
        )?;
        require(
            self.usage.received_bytes < self.limits.max_received_bytes
                && self.usage.sent_bytes < self.limits.max_sent_bytes,
            "CBL2 connection byte reservation",
        )?;
        self.usage.connection_attempts += 1;
        Ok(())
    }

    pub(super) fn failed_connection(&mut self) {
        self.usage.failed_connections += 1;
    }
    pub(super) fn completed_fetch(&mut self) {
        self.usage.completed_fetches += 1;
    }

    fn frame(&mut self, outgoing: bool, deadline: Instant) -> CellResultV1<()> {
        self.check(deadline)?;
        require(
            self.usage.received_messages + self.usage.sent_messages < self.limits.max_messages,
            "CBL2 frame budget",
        )?;
        if outgoing {
            self.usage.sent_messages += 1;
        } else {
            self.usage.received_messages += 1;
        }
        Ok(())
    }

    fn read_exact(
        &mut self,
        stream: &mut TcpStream,
        bytes: &mut [u8],
        deadline: Instant,
        eof: bool,
    ) -> CellResultV1<bool> {
        let mut filled = 0;
        while filled < bytes.len() {
            self.check(deadline)?;
            let allowance = (self.limits.max_received_bytes - self.usage.received_bytes)
                .min((bytes.len() - filled) as u64) as usize;
            require(allowance > 0, "CBL2 receive byte budget")?;
            stream.set_read_timeout(Some(IO_POLL.min(self.remaining(deadline)?)))?;
            match stream.read(&mut bytes[filled..filled + allowance]) {
                Ok(0) if filled == 0 && eof => return Ok(false),
                Ok(0) => {
                    return Err(
                        io::Error::new(io::ErrorKind::UnexpectedEof, "CBL2 partial frame").into(),
                    )
                }
                Ok(count) => {
                    self.usage.received_bytes += count as u64;
                    filled += count;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    continue
                }
                Err(error) => return Err(error.into()),
            }
        }
        self.check(deadline)?;
        Ok(true)
    }

    fn write_all(
        &mut self,
        stream: &mut TcpStream,
        bytes: &[u8],
        deadline: Instant,
    ) -> CellResultV1<()> {
        let mut written = 0;
        while written < bytes.len() {
            self.check(deadline)?;
            let allowance = (self.limits.max_sent_bytes - self.usage.sent_bytes)
                .min((bytes.len() - written) as u64) as usize;
            require(allowance > 0, "CBL2 send byte budget")?;
            stream.set_write_timeout(Some(IO_POLL.min(self.remaining(deadline)?)))?;
            match stream.write(&bytes[written..written + allowance]) {
                Ok(0) => {
                    return Err(
                        io::Error::new(io::ErrorKind::WriteZero, "CBL2 stopped write").into(),
                    )
                }
                Ok(count) => {
                    self.usage.sent_bytes += count as u64;
                    written += count;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    continue
                }
                Err(error) => return Err(error.into()),
            }
        }
        self.check(deadline)
    }

    pub(super) fn read_frame(
        &mut self,
        stream: &mut TcpStream,
        deadline: Instant,
        eof: bool,
    ) -> CellResultV1<Option<Vec<u8>>> {
        self.frame(false, deadline)?;
        let mut header = [0; 4];
        if !self.read_exact(stream, &mut header, deadline, eof)? {
            return Ok(None);
        }
        let length = u32::from_be_bytes(header) as usize;
        require(
            length <= MAX_CELL_BEP52_STORAGE_FRAME_BYTES_V2,
            "CBL2 frame length",
        )?;
        require(
            length as u64 <= self.limits.max_received_bytes - self.usage.received_bytes,
            "CBL2 receive byte budget",
        )?;
        let mut body = vec![0; length];
        self.read_exact(stream, &mut body, deadline, false)?;
        Ok(Some(body))
    }

    pub(super) fn required_frame(
        &mut self,
        stream: &mut TcpStream,
        deadline: Instant,
    ) -> CellResultV1<Vec<u8>> {
        self.read_frame(stream, deadline, false)?
            .ok_or(CellErrorV1::Unavailable)
    }

    pub(super) fn send_frame(
        &mut self,
        stream: &mut TcpStream,
        body: &[u8],
        deadline: Instant,
    ) -> CellResultV1<()> {
        require(
            body.len() <= MAX_CELL_BEP52_STORAGE_FRAME_BYTES_V2,
            "CBL2 frame length",
        )?;
        self.frame(true, deadline)?;
        self.write_all(stream, &(body.len() as u32).to_be_bytes(), deadline)?;
        self.write_all(stream, body, deadline)
    }
}
