use super::*;
use openssl::ssl::SslStream;
use std::io::{self, Read, Write};

// These are extra ciphertext bounds, not larger application frame allowances.
// TLS records/certificate input also spend the original durable 32 MiB ingress
// budget. The existing 2 MiB signed PNQ frame/body checks remain unchanged.
// Each limit applies independently to received and written ciphertext. Their
// combined ceilings are 128 KiB per handshake and 8 MiB per connection; only
// received bytes are debited from the original durable ingress owner.
const HANDSHAKE_BYTES: usize = 65_536;
const CONNECTION_BYTES: usize = MAX_WIRE * 2;

pub(super) struct DeadlineStream<'a> {
    stream: TcpStream,
    deadline: Instant,
    read_bytes: usize,
    written_bytes: usize,
    limit: usize,
    owner: Option<(&'a Mutex<Node>, &'a PqNetworkPolicy)>,
}
impl<'a> DeadlineStream<'a> {
    pub(super) fn new(
        stream: TcpStream,
        deadline: Instant,
        owner: Option<(&'a Mutex<Node>, &'a PqNetworkPolicy)>,
    ) -> Result<Self> {
        check_live_request(deadline, None)?;
        // Darwin may inherit O_NONBLOCK from the listener. Read/write timeouts
        // need a blocking descriptor; each BIO call still uses the SAME end.
        stream.set_nonblocking(false)?;
        // Disable Nagle without changing TLS bytes, deadlines or read accounting.
        stream.set_nodelay(true)?;
        Ok(Self {
            stream,
            deadline,
            read_bytes: 0,
            written_bytes: 0,
            limit: HANDSHAKE_BYTES,
            owner,
        })
    }
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "PQ_NETWORK_DEADLINE"))
    }
    fn charge(&self, bytes: usize) -> io::Result<()> {
        if let Some((node, policy)) = self.owner {
            let result = lock_live_owner(node, self.deadline, None).and_then(|mut owner| {
                owner.charge_pq_ingress_with_check(
                    policy,
                    false,
                    bytes as u64,
                    false,
                    self.deadline,
                    &mut || check_live_request(self.deadline, None),
                )
            });
            result.map_err(|error| io::Error::other(error.to_string()))?;
        }
        self.remaining().map(|_| ())
    }
}
impl Read for DeadlineStream<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        let remaining = self.remaining()?;
        let count = output.len().min(self.limit.saturating_sub(self.read_bytes));
        if count == 0 {
            return Err(io::Error::other("PQ_TLS_CIPHERTEXT_LIMIT"));
        }
        self.stream.set_read_timeout(Some(remaining))?;
        let read = self.stream.read(&mut output[..count])?;
        self.read_bytes += read;
        // The bytes are charged before OpenSSL receives them for parsing or
        // signature verification. Failure closes the channel, with no refund.
        self.charge(read)?;
        Ok(read)
    }
}
impl Write for DeadlineStream<'_> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        let remaining = self.remaining()?;
        let count = input
            .len()
            .min(self.limit.saturating_sub(self.written_bytes));
        if count == 0 {
            return Err(io::Error::other("PQ_TLS_CIPHERTEXT_LIMIT"));
        }
        self.stream.set_write_timeout(Some(remaining))?;
        let written = self.stream.write(&input[..count])?;
        self.written_bytes += written;
        self.remaining()?;
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.remaining().map(|_| ())
    }
}

pub(super) struct Channel<'a> {
    stream: SslStream<DeadlineStream<'a>>,
    admission: TransportAdmission,
    deadline: Instant,
}
impl<'a> Channel<'a> {
    pub(super) fn connect(
        stream: TcpStream,
        deadline: Instant,
        context: &context::TlsContext,
    ) -> Result<Self> {
        Self::handshake(stream, deadline, context, None, false)
    }
    pub(super) fn accept(
        stream: TcpStream,
        deadline: Instant,
        context: &context::TlsContext,
        node: &'a Mutex<Node>,
        policy: &'a PqNetworkPolicy,
    ) -> Result<Self> {
        // connection() has already spent this owner's durable TLS handshake
        // attempt. Certificate-path construction may perform multiple signature
        // operations: it is NOT charged as one/two native TPQ verifications.
        Self::handshake(stream, deadline, context, Some((node, policy)), true)
    }
    fn handshake(
        stream: TcpStream,
        deadline: Instant,
        context: &context::TlsContext,
        owner: Option<(&'a Mutex<Node>, &'a PqNetworkPolicy)>,
        server: bool,
    ) -> Result<Self> {
        let io = DeadlineStream::new(stream, deadline, owner)?;
        let mut stream = SslStream::new(context.session()?, io).map_err(crypto)?;
        check_live_request(deadline, None)?;
        if server {
            stream.accept()
        } else {
            stream.connect()
        }
        .map_err(crypto)?;
        // Handshake crypto itself is synchronous. Late completion never grants
        // request dispatch, even when the final BIO read completed in time.
        check_live_request(deadline, None)?;
        let admission = context.admit(stream.ssl())?;
        check_live_request(deadline, None)?;
        stream.get_mut().limit = CONNECTION_BYTES;
        Ok(Self {
            stream,
            admission,
            deadline,
        })
    }
    pub(super) fn admission(&self) -> &TransportAdmission {
        &self.admission
    }
    pub(super) fn read_exact(&mut self, bytes: &mut [u8]) -> Result<()> {
        check_live_request(self.deadline, None)?;
        self.stream.read_exact(bytes)?;
        check_live_request(self.deadline, None)
    }
    pub(super) fn read_frame(&mut self) -> Result<Vec<u8>> {
        let mut prefix = [0; 4];
        self.read_exact(&mut prefix)?;
        let length = u32::from_be_bytes(prefix) as usize;
        ensure((1..=MAX_WIRE).contains(&length), "PQ_NETWORK_WIRE_LIMIT")?;
        let mut bytes = vec![0; length];
        self.read_exact(&mut bytes)?;
        Ok(bytes)
    }
    pub(super) fn write_frame(&mut self, bytes: &[u8]) -> Result<()> {
        ensure(
            (1..=MAX_WIRE).contains(&bytes.len()),
            "PQ_NETWORK_WIRE_LIMIT",
        )?;
        check_live_request(self.deadline, None)?;
        // Coalesce the unchanged length prefix and first payload bytes into
        // one bounded SSL write. Receive charging and live checks are unchanged.
        let mut first = [0_u8; 16_384];
        let prefix = (bytes.len() as u32).to_be_bytes();
        let copied = bytes.len().min(first.len() - prefix.len());
        first[..prefix.len()].copy_from_slice(&prefix);
        first[prefix.len()..prefix.len() + copied].copy_from_slice(&bytes[..copied]);
        self.stream.write_all(&first[..prefix.len() + copied])?;
        self.stream.write_all(&bytes[copied..])?;
        check_live_request(self.deadline, None)
    }
}
