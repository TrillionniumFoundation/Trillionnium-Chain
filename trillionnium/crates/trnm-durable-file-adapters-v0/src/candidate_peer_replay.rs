use fs2::FileExt;
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};
use trnm_node_boundary_v0::{
    AuthorityReceiptV0, AuthorityStageV0, BoundIngressV0, BoundaryErrorV0,
    Digest32V0 as NodeDigestV0, NodeIdentityV0, OperationBindingV0,
};
use trnm_poco_node_io::{
    AuthenticatedPeerFrameV0, CandidateP2pAdmissionV0, IoDigest32V0, PeerAdmissionErrorV0,
    PeerFrameSourceV0, PeerFrameVerificationErrorV0, PeerRecoveryErrorV0,
    PeerReplayRecoverySourceV0, PeerReplayStateV0, PeerSessionIdentityV0, VerifiedPeerFrameV0,
    MAX_CANDIDATE_PEER_FRAME_BYTES_V0,
};

pub const CANDIDATE_PEER_REPLAY_VERSION_V0: u16 = 0;
const MAGIC_V0: &str = "trnm-candidate-peer-replay-v0";

#[derive(Debug)]
pub enum CandidatePeerReplayErrorV0 {
    Io(io::Error),
    LockBusy(PathBuf),
    Boundary(PeerAdmissionErrorV0),
    NodeBoundary(BoundaryErrorV0),
    Corrupt(&'static str),
    WrongNodeIdentity,
    WrongPeerSession,
    PendingBindingConflict,
    MissingPendingFrame,
    InvalidPreparedReceipt(&'static str),
    ConflictingRecovery,
    Poisoned,
    RevisionOverflow,
    InMemoryStateMismatch,
}

impl fmt::Display for CandidatePeerReplayErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "candidate peer replay I/O failed: {error}"),
            Self::LockBusy(path) => {
                write!(
                    formatter,
                    "candidate peer replay lock is busy: {}",
                    path.display()
                )
            }
            Self::Boundary(error) => {
                write!(formatter, "candidate peer replay boundary failed: {error}")
            }
            Self::NodeBoundary(error) => {
                write!(
                    formatter,
                    "candidate peer replay node binding failed: {error}"
                )
            }
            Self::Corrupt(reason) => {
                write!(
                    formatter,
                    "candidate peer replay snapshot is corrupt: {reason}"
                )
            }
            Self::WrongNodeIdentity => {
                formatter.write_str("candidate peer replay node identity changed")
            }
            Self::WrongPeerSession => {
                formatter.write_str("candidate peer replay session identity changed")
            }
            Self::PendingBindingConflict => {
                formatter.write_str("pending peer frame changed its bound ingress")
            }
            Self::MissingPendingFrame => {
                formatter.write_str("no matching pending peer frame exists")
            }
            Self::InvalidPreparedReceipt(reason) => {
                write!(
                    formatter,
                    "Core Prepared acknowledgement rejected: {reason}"
                )
            }
            Self::ConflictingRecovery => formatter
                .write_str("candidate peer replay temporary snapshot conflicts with current"),
            Self::Poisoned => {
                formatter.write_str("candidate peer replay is poisoned after an uncertain write")
            }
            Self::RevisionOverflow => {
                formatter.write_str("candidate peer replay revision overflowed")
            }
            Self::InMemoryStateMismatch => {
                formatter.write_str("durable and in-memory peer replay states diverged")
            }
        }
    }
}

impl Error for CandidatePeerReplayErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Boundary(error) => Some(error),
            Self::NodeBoundary(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for CandidatePeerReplayErrorV0 {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingPeerIngressV0 {
    frame: AuthenticatedPeerFrameV0,
    binding: OperationBindingV0,
    ingress_digest: NodeDigestV0,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedPeerAcknowledgementV0 {
    frame: AuthenticatedPeerFrameV0,
    ingress_digest: NodeDigestV0,
    receipt: AuthorityReceiptV0,
}

impl PreparedPeerAcknowledgementV0 {
    #[must_use]
    pub const fn frame(self) -> AuthenticatedPeerFrameV0 {
        self.frame
    }

    #[must_use]
    pub const fn ingress_digest(self) -> NodeDigestV0 {
        self.ingress_digest
    }

    #[must_use]
    pub const fn receipt(self) -> AuthorityReceiptV0 {
        self.receipt
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SnapshotV0 {
    node_identity: NodeIdentityV0,
    session: PeerSessionIdentityV0,
    revision: u64,
    replay: PeerReplayStateV0,
    pending: Option<PendingPeerIngressV0>,
    last_acknowledgement: Option<PreparedPeerAcknowledgementV0>,
    previous_checksum: [u8; 32],
    checksum: [u8; 32],
}

impl SnapshotV0 {
    fn initial(
        node_identity: NodeIdentityV0,
        session: PeerSessionIdentityV0,
    ) -> Result<Self, CandidatePeerReplayErrorV0> {
        let replay = PeerReplayStateV0::new(session, 0, None)
            .map_err(CandidatePeerReplayErrorV0::Boundary)?;
        let mut snapshot = Self {
            node_identity,
            session,
            revision: 1,
            replay,
            pending: None,
            last_acknowledgement: None,
            previous_checksum: [0; 32],
            checksum: [0; 32],
        };
        snapshot.validate()?;
        snapshot.checksum = snapshot.compute_checksum()?;
        Ok(snapshot)
    }

    fn validate(self) -> Result<(), CandidatePeerReplayErrorV0> {
        self.node_identity
            .validate()
            .map_err(CandidatePeerReplayErrorV0::NodeBoundary)?;
        if self.revision == 0 {
            return Err(CandidatePeerReplayErrorV0::Corrupt("zero revision"));
        }
        if self.session.chain_id().bytes() != self.node_identity.chain_id.0 {
            return Err(CandidatePeerReplayErrorV0::WrongPeerSession);
        }
        if self.replay.session() != self.session {
            return Err(CandidatePeerReplayErrorV0::Corrupt(
                "replay session mismatch",
            ));
        }
        match self.pending {
            Some(pending) => {
                pending
                    .binding
                    .validate(self.node_identity)
                    .map_err(CandidatePeerReplayErrorV0::NodeBoundary)?;
                if pending.frame.session() != self.session
                    || pending.binding.proposal_digest != pending.ingress_digest
                    || pending.ingress_digest == NodeDigestV0([0; 32])
                    || self.replay.pending() != Some(pending.frame)
                {
                    return Err(CandidatePeerReplayErrorV0::Corrupt(
                        "pending ingress mismatch",
                    ));
                }
            }
            None if self.replay.pending().is_some() => {
                return Err(CandidatePeerReplayErrorV0::Corrupt(
                    "unbound pending replay frame",
                ));
            }
            None => {}
        }

        let floor = self.replay.highest_acknowledged_nonce();
        match (floor, self.last_acknowledgement) {
            (0, None) => {}
            (0, Some(_)) => {
                return Err(CandidatePeerReplayErrorV0::Corrupt(
                    "zero replay floor has an acknowledgement",
                ));
            }
            (_, None) => {
                return Err(CandidatePeerReplayErrorV0::Corrupt(
                    "nonzero replay floor lacks an acknowledgement",
                ));
            }
            (_, Some(acknowledgement)) => {
                acknowledgement
                    .receipt
                    .binding
                    .validate(self.node_identity)
                    .map_err(CandidatePeerReplayErrorV0::NodeBoundary)?;
                if acknowledgement.frame.session() != self.session
                    || acknowledgement.frame.replay_nonce() != floor
                    || acknowledgement.receipt.durable_stage != AuthorityStageV0::Prepared
                    || acknowledgement.receipt.binding.proposal_digest
                        != acknowledgement.ingress_digest
                    || acknowledgement.receipt.facts_digest != acknowledgement.ingress_digest
                    || acknowledgement.receipt.record_digest == NodeDigestV0([0; 32])
                {
                    return Err(CandidatePeerReplayErrorV0::Corrupt(
                        "Prepared acknowledgement mismatch",
                    ));
                }
            }
        }
        Ok(())
    }

    fn body(self) -> Result<String, CandidatePeerReplayErrorV0> {
        self.validate()?;
        Ok(format!(
            "magic={MAGIC_V0}\nversion={}\nrevision={}\nnode={}\nsession={}\nfloor={}\npending={}\nack={}\nprevious={}\n",
            CANDIDATE_PEER_REPLAY_VERSION_V0,
            self.revision,
            encode_node_identity(self.node_identity),
            encode_session(self.session),
            self.replay.highest_acknowledged_nonce(),
            encode_pending(self.pending)?,
            encode_acknowledgement(self.last_acknowledgement)?,
            encode_hex(&self.previous_checksum),
        ))
    }

    fn compute_checksum(self) -> Result<[u8; 32], CandidatePeerReplayErrorV0> {
        let body = self.body()?;
        let mut hasher = Sha256::new();
        let domain = b"trnm.candidate.peer-replay-snapshot.v0";
        hasher.update((domain.len() as u64).to_be_bytes());
        hasher.update(domain);
        hasher.update((body.len() as u64).to_be_bytes());
        hasher.update(body.as_bytes());
        Ok(hasher.finalize().into())
    }

    fn encode(self) -> Result<Vec<u8>, CandidatePeerReplayErrorV0> {
        let body = self.body()?;
        let checksum = self.compute_checksum()?;
        if self.checksum != [0; 32] && self.checksum != checksum {
            return Err(CandidatePeerReplayErrorV0::Corrupt(
                "in-memory checksum mismatch",
            ));
        }
        Ok(format!("{body}checksum={}\n", encode_hex(&checksum)).into_bytes())
    }

    fn decode(bytes: &[u8]) -> Result<Self, CandidatePeerReplayErrorV0> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| CandidatePeerReplayErrorV0::Corrupt("snapshot is not UTF-8"))?;
        let lines = text.lines().collect::<Vec<_>>();
        if lines.len() != 10 {
            return Err(CandidatePeerReplayErrorV0::Corrupt(
                "unexpected snapshot line count",
            ));
        }
        let value = |index: usize, key: &'static str| {
            lines[index]
                .strip_prefix(key)
                .ok_or(CandidatePeerReplayErrorV0::Corrupt("snapshot key mismatch"))
        };
        if value(0, "magic=")? != MAGIC_V0 {
            return Err(CandidatePeerReplayErrorV0::Corrupt("magic mismatch"));
        }
        if parse_u16(value(1, "version=")?, "version")? != CANDIDATE_PEER_REPLAY_VERSION_V0 {
            return Err(CandidatePeerReplayErrorV0::Corrupt(
                "unsupported snapshot version",
            ));
        }
        let revision = parse_u64(value(2, "revision=")?, "revision")?;
        let node_identity = decode_node_identity(value(3, "node=")?)?;
        let session = decode_session(value(4, "session=")?)?;
        let floor = parse_u64(value(5, "floor=")?, "replay floor")?;
        let pending = decode_pending(value(6, "pending=")?, session)?;
        let last_acknowledgement = decode_acknowledgement(value(7, "ack=")?, session)?;
        let previous_checksum = decode_hex32(value(8, "previous=")?)?;
        let checksum = decode_hex32(value(9, "checksum=")?)?;
        let replay = PeerReplayStateV0::new(session, floor, pending.map(|entry| entry.frame))
            .map_err(CandidatePeerReplayErrorV0::Boundary)?;
        let snapshot = Self {
            node_identity,
            session,
            revision,
            replay,
            pending,
            last_acknowledgement,
            previous_checksum,
            checksum,
        };
        snapshot.validate()?;
        if snapshot.compute_checksum()? != checksum {
            return Err(CandidatePeerReplayErrorV0::Corrupt(
                "snapshot checksum mismatch",
            ));
        }
        Ok(snapshot)
    }
}

fn parse_u64(value: &str, reason: &'static str) -> Result<u64, CandidatePeerReplayErrorV0> {
    value
        .parse()
        .map_err(|_| CandidatePeerReplayErrorV0::Corrupt(reason))
}

fn parse_u16(value: &str, reason: &'static str) -> Result<u16, CandidatePeerReplayErrorV0> {
    value
        .parse()
        .map_err(|_| CandidatePeerReplayErrorV0::Corrupt(reason))
}

fn encode_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

fn decode_hex32(value: &str) -> Result<[u8; 32], CandidatePeerReplayErrorV0> {
    if value.len() != 64 {
        return Err(CandidatePeerReplayErrorV0::Corrupt(
            "digest length mismatch",
        ));
    }
    let mut bytes = [0_u8; 32];
    for (index, target) in bytes.iter_mut().enumerate() {
        let offset = index * 2;
        *target = (decode_nibble(value.as_bytes()[offset])? << 4)
            | decode_nibble(value.as_bytes()[offset + 1])?;
    }
    Ok(bytes)
}

fn decode_nibble(value: u8) -> Result<u8, CandidatePeerReplayErrorV0> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(CandidatePeerReplayErrorV0::Corrupt(
            "digest contains non-hex byte",
        )),
    }
}

fn split_exact<'a>(
    value: &'a str,
    count: usize,
    reason: &'static str,
) -> Result<Vec<&'a str>, CandidatePeerReplayErrorV0> {
    let parts = value.split(':').collect::<Vec<_>>();
    if parts.len() != count {
        return Err(CandidatePeerReplayErrorV0::Corrupt(reason));
    }
    Ok(parts)
}

fn io_digest(value: &str) -> Result<IoDigest32V0, CandidatePeerReplayErrorV0> {
    IoDigest32V0::new(decode_hex32(value)?).map_err(CandidatePeerReplayErrorV0::Boundary)
}

fn encode_node_identity(identity: NodeIdentityV0) -> String {
    format!(
        "{}:{}:{}:{}",
        encode_hex(&identity.chain_id.0),
        encode_hex(&identity.validator_id.0),
        encode_hex(&identity.application_id.0),
        identity.generation,
    )
}

fn decode_node_identity(value: &str) -> Result<NodeIdentityV0, CandidatePeerReplayErrorV0> {
    let parts = split_exact(value, 4, "node identity field count")?;
    NodeIdentityV0 {
        chain_id: NodeDigestV0(decode_hex32(parts[0])?),
        validator_id: NodeDigestV0(decode_hex32(parts[1])?),
        application_id: NodeDigestV0(decode_hex32(parts[2])?),
        generation: parse_u64(parts[3], "node generation")?,
    }
    .validate()
    .map_err(CandidatePeerReplayErrorV0::NodeBoundary)
}

fn encode_session(session: PeerSessionIdentityV0) -> String {
    format!(
        "{}:{}:{}:{}:{}:{}",
        encode_hex(&session.chain_id().bytes()),
        encode_hex(&session.protocol_digest().bytes()),
        encode_hex(&session.peer_id().bytes()),
        encode_hex(&session.session_id().bytes()),
        encode_hex(&session.profile_digest().bytes()),
        session.generation(),
    )
}

fn decode_session(value: &str) -> Result<PeerSessionIdentityV0, CandidatePeerReplayErrorV0> {
    let parts = split_exact(value, 6, "session identity field count")?;
    PeerSessionIdentityV0::new(
        io_digest(parts[0])?,
        io_digest(parts[1])?,
        io_digest(parts[2])?,
        io_digest(parts[3])?,
        io_digest(parts[4])?,
        parse_u64(parts[5], "peer generation")?,
    )
    .map_err(CandidatePeerReplayErrorV0::Boundary)
}

fn encode_frame(frame: AuthenticatedPeerFrameV0) -> String {
    format!(
        "{}:{}:{}",
        frame.replay_nonce(),
        encode_hex(&frame.payload_digest().bytes()),
        frame.payload_bytes(),
    )
}

fn decode_frame(
    parts: &[&str],
    session: PeerSessionIdentityV0,
) -> Result<AuthenticatedPeerFrameV0, CandidatePeerReplayErrorV0> {
    AuthenticatedPeerFrameV0::new(
        session,
        parse_u64(parts[0], "frame nonce")?,
        io_digest(parts[1])?,
        parts[2]
            .parse()
            .map_err(|_| CandidatePeerReplayErrorV0::Corrupt("frame byte count"))?,
    )
    .map_err(CandidatePeerReplayErrorV0::Boundary)
}

fn encode_binding(binding: OperationBindingV0) -> String {
    format!(
        "{}:{}:{}:{}:{}:{}",
        encode_hex(&binding.operation_id.0),
        binding.height,
        binding.view,
        encode_hex(&binding.block_id.0),
        encode_hex(&binding.parent_id.0),
        encode_hex(&binding.proposal_digest.0),
    )
}

fn decode_binding(parts: &[&str]) -> Result<OperationBindingV0, CandidatePeerReplayErrorV0> {
    Ok(OperationBindingV0 {
        operation_id: NodeDigestV0(decode_hex32(parts[0])?),
        height: parse_u64(parts[1], "operation height")?,
        view: parse_u64(parts[2], "operation view")?,
        block_id: NodeDigestV0(decode_hex32(parts[3])?),
        parent_id: NodeDigestV0(decode_hex32(parts[4])?),
        proposal_digest: NodeDigestV0(decode_hex32(parts[5])?),
    })
}

fn encode_pending(
    pending: Option<PendingPeerIngressV0>,
) -> Result<String, CandidatePeerReplayErrorV0> {
    Ok(match pending {
        None => "none".to_owned(),
        Some(pending) => format!(
            "{}:{}:{}",
            encode_frame(pending.frame),
            encode_binding(pending.binding),
            encode_hex(&pending.ingress_digest.0),
        ),
    })
}

fn decode_pending(
    value: &str,
    session: PeerSessionIdentityV0,
) -> Result<Option<PendingPeerIngressV0>, CandidatePeerReplayErrorV0> {
    if value == "none" {
        return Ok(None);
    }
    let parts = split_exact(value, 10, "pending field count")?;
    Ok(Some(PendingPeerIngressV0 {
        frame: decode_frame(&parts[0..3], session)?,
        binding: decode_binding(&parts[3..9])?,
        ingress_digest: NodeDigestV0(decode_hex32(parts[9])?),
    }))
}

fn encode_acknowledgement(
    acknowledgement: Option<PreparedPeerAcknowledgementV0>,
) -> Result<String, CandidatePeerReplayErrorV0> {
    Ok(match acknowledgement {
        None => "none".to_owned(),
        Some(acknowledgement) => format!(
            "{}:{}:{}:{}:{}:{}:{}:{}",
            encode_frame(acknowledgement.frame),
            encode_hex(&acknowledgement.ingress_digest.0),
            encode_binding(acknowledgement.receipt.binding),
            acknowledgement.receipt.durable_stage as u8,
            acknowledgement.receipt.durable_sequence,
            encode_hex(&acknowledgement.receipt.facts_digest.0),
            encode_hex(&acknowledgement.receipt.record_digest.0),
            "prepared",
        ),
    })
}

fn decode_acknowledgement(
    value: &str,
    session: PeerSessionIdentityV0,
) -> Result<Option<PreparedPeerAcknowledgementV0>, CandidatePeerReplayErrorV0> {
    if value == "none" {
        return Ok(None);
    }
    let parts = split_exact(value, 15, "acknowledgement field count")?;
    if parts[14] != "prepared" {
        return Err(CandidatePeerReplayErrorV0::Corrupt(
            "acknowledgement marker mismatch",
        ));
    }
    let stage = match parse_u64(parts[10], "acknowledgement stage")? {
        0 => AuthorityStageV0::Prepared,
        1 => AuthorityStageV0::ApplicationSealed,
        2 => AuthorityStageV0::SafetyPersisted,
        3 => AuthorityStageV0::SignIntentPersisted,
        4 => AuthorityStageV0::SignatureConfirmed,
        5 => AuthorityStageV0::FinalityApplied,
        6 => AuthorityStageV0::CheckpointConfirmed,
        7 => AuthorityStageV0::OutboundPublished,
        _ => {
            return Err(CandidatePeerReplayErrorV0::Corrupt(
                "unknown acknowledgement stage",
            ));
        }
    };
    Ok(Some(PreparedPeerAcknowledgementV0 {
        frame: decode_frame(&parts[0..3], session)?,
        ingress_digest: NodeDigestV0(decode_hex32(parts[3])?),
        receipt: AuthorityReceiptV0 {
            binding: decode_binding(&parts[4..10])?,
            durable_stage: stage,
            durable_sequence: parse_u64(parts[11], "authority sequence")?,
            facts_digest: NodeDigestV0(decode_hex32(parts[12])?),
            record_digest: NodeDigestV0(decode_hex32(parts[13])?),
        },
    }))
}

fn acquire_lock(path: &Path) -> Result<File, CandidatePeerReplayErrorV0> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)?;
    match file.try_lock_exclusive() {
        Ok(()) => Ok(file),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            Err(CandidatePeerReplayErrorV0::LockBusy(path.to_path_buf()))
        }
        Err(error) => Err(CandidatePeerReplayErrorV0::Io(error)),
    }
}

fn sync_directory(path: &Path) -> Result<(), CandidatePeerReplayErrorV0> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn read_snapshot(path: &Path) -> Result<(Vec<u8>, SnapshotV0), CandidatePeerReplayErrorV0> {
    let bytes = fs::read(path)?;
    let snapshot = SnapshotV0::decode(&bytes)?;
    Ok((bytes, snapshot))
}

fn write_atomic(
    root: &Path,
    current_path: &Path,
    temporary_path: &Path,
    snapshot: SnapshotV0,
) -> Result<[u8; 32], CandidatePeerReplayErrorV0> {
    let encoded = snapshot.encode()?;
    let mut temporary = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(temporary_path)?;
    temporary.write_all(&encoded)?;
    temporary.sync_all()?;
    fs::rename(temporary_path, current_path)?;
    sync_directory(root)?;
    Ok(SnapshotV0::decode(&encoded)?.checksum)
}

fn payload_digest(payload: &[u8]) -> Result<IoDigest32V0, CandidatePeerReplayErrorV0> {
    if payload.is_empty() || payload.len() > MAX_CANDIDATE_PEER_FRAME_BYTES_V0 {
        return Err(CandidatePeerReplayErrorV0::Boundary(
            PeerAdmissionErrorV0::InvalidFrame,
        ));
    }
    let mut hasher = Sha256::new();
    let domain = b"trnm.candidate.peer-payload.v0";
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    IoDigest32V0::new(hasher.finalize().into()).map_err(CandidatePeerReplayErrorV0::Boundary)
}

pub fn candidate_frame_for_bound_ingress_v0(
    node_identity: NodeIdentityV0,
    session: PeerSessionIdentityV0,
    ingress: &BoundIngressV0,
) -> Result<AuthenticatedPeerFrameV0, CandidatePeerReplayErrorV0> {
    node_identity
        .validate()
        .map_err(CandidatePeerReplayErrorV0::NodeBoundary)?;
    ingress
        .validate(node_identity)
        .map_err(CandidatePeerReplayErrorV0::NodeBoundary)?;
    if session.chain_id().bytes() != node_identity.chain_id.0
        || session.peer_id().bytes() != ingress.frame.peer_id.0
        || session.profile_digest().bytes() != ingress.frame.profile_digest.0
    {
        return Err(CandidatePeerReplayErrorV0::WrongPeerSession);
    }
    AuthenticatedPeerFrameV0::new(
        session,
        ingress.frame.replay_nonce,
        payload_digest(&ingress.frame.payload)?,
        ingress.frame.payload.len(),
    )
    .map_err(CandidatePeerReplayErrorV0::Boundary)
}

pub struct CandidatePeerReplayJournalV0 {
    root: PathBuf,
    current_path: PathBuf,
    temporary_path: PathBuf,
    _lock: File,
    snapshot: SnapshotV0,
    recovered_temporary: bool,
    poisoned: bool,
}

impl CandidatePeerReplayJournalV0 {
    pub fn open(
        root: impl AsRef<Path>,
        node_identity: NodeIdentityV0,
        session: PeerSessionIdentityV0,
    ) -> Result<Self, CandidatePeerReplayErrorV0> {
        node_identity
            .validate()
            .map_err(CandidatePeerReplayErrorV0::NodeBoundary)?;
        if session.chain_id().bytes() != node_identity.chain_id.0 {
            return Err(CandidatePeerReplayErrorV0::WrongPeerSession);
        }

        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        let current_path = root.join("peer-replay-v0.current");
        let temporary_path = root.join("peer-replay-v0.tmp");
        let lock = acquire_lock(&root.join("peer-replay-v0.lock"))?;
        let mut recovered_temporary = false;

        if temporary_path.exists() {
            if current_path.exists() {
                let (current_bytes, current) = read_snapshot(&current_path)?;
                match read_snapshot(&temporary_path) {
                    Ok((temporary_bytes, temporary))
                        if temporary.node_identity == current.node_identity
                            && temporary.session == current.session
                            && temporary_bytes == current_bytes
                            && temporary == current =>
                    {
                        fs::remove_file(&temporary_path)?;
                        sync_directory(&root)?;
                        recovered_temporary = true;
                    }
                    Ok((_, temporary))
                        if temporary.node_identity == current.node_identity
                            && temporary.session == current.session
                            && temporary.revision
                                == current
                                    .revision
                                    .checked_add(1)
                                    .ok_or(CandidatePeerReplayErrorV0::RevisionOverflow)?
                            && temporary.previous_checksum == current.checksum =>
                    {
                        fs::rename(&temporary_path, &current_path)?;
                        sync_directory(&root)?;
                        recovered_temporary = true;
                    }
                    Ok(_) => return Err(CandidatePeerReplayErrorV0::ConflictingRecovery),
                    Err(_) => {
                        fs::remove_file(&temporary_path)?;
                        sync_directory(&root)?;
                        recovered_temporary = true;
                    }
                }
            } else {
                let (_, temporary) = read_snapshot(&temporary_path)?;
                if temporary.node_identity != node_identity
                    || temporary.session != session
                    || temporary.revision != 1
                    || temporary.previous_checksum != [0; 32]
                {
                    return Err(CandidatePeerReplayErrorV0::ConflictingRecovery);
                }
                fs::rename(&temporary_path, &current_path)?;
                sync_directory(&root)?;
                recovered_temporary = true;
            }
        }

        let snapshot = if current_path.exists() {
            read_snapshot(&current_path)?.1
        } else {
            let initial = SnapshotV0::initial(node_identity, session)?;
            write_atomic(&root, &current_path, &temporary_path, initial)?;
            initial
        };
        if snapshot.node_identity != node_identity {
            return Err(CandidatePeerReplayErrorV0::WrongNodeIdentity);
        }
        if snapshot.session != session {
            return Err(CandidatePeerReplayErrorV0::WrongPeerSession);
        }

        Ok(Self {
            root,
            current_path,
            temporary_path,
            _lock: lock,
            snapshot,
            recovered_temporary,
            poisoned: false,
        })
    }

    #[must_use]
    pub const fn recovery_state(&self) -> PeerReplayStateV0 {
        self.snapshot.replay
    }

    #[must_use]
    pub const fn last_prepared_acknowledgement(&self) -> Option<PreparedPeerAcknowledgementV0> {
        self.snapshot.last_acknowledgement
    }

    #[must_use]
    pub const fn recovered_temporary(&self) -> bool {
        self.recovered_temporary
    }

    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    #[must_use]
    pub fn current_path(&self) -> &Path {
        &self.current_path
    }

    fn persist(
        &mut self,
        mut next: SnapshotV0,
    ) -> Result<PeerReplayStateV0, CandidatePeerReplayErrorV0> {
        if self.poisoned {
            return Err(CandidatePeerReplayErrorV0::Poisoned);
        }
        next.revision = self
            .snapshot
            .revision
            .checked_add(1)
            .ok_or(CandidatePeerReplayErrorV0::RevisionOverflow)?;
        next.previous_checksum = self.snapshot.checksum;
        next.checksum = [0; 32];
        next.validate()?;
        next.checksum = next.compute_checksum()?;
        match write_atomic(&self.root, &self.current_path, &self.temporary_path, next) {
            Ok(checksum) => {
                next.checksum = checksum;
                self.snapshot = next;
                Ok(next.replay)
            }
            Err(error) => {
                self.poisoned = true;
                Err(error)
            }
        }
    }

    pub fn stage_verified(
        &mut self,
        verified: &VerifiedPeerFrameV0,
        ingress: &BoundIngressV0,
    ) -> Result<PeerReplayStateV0, CandidatePeerReplayErrorV0> {
        if self.poisoned {
            return Err(CandidatePeerReplayErrorV0::Poisoned);
        }
        if verified.prior() != self.snapshot.replay {
            return Err(CandidatePeerReplayErrorV0::Boundary(
                PeerAdmissionErrorV0::StaleToken,
            ));
        }
        let canonical = candidate_frame_for_bound_ingress_v0(
            self.snapshot.node_identity,
            self.snapshot.session,
            ingress,
        )?;
        if verified.frame() != canonical {
            return Err(CandidatePeerReplayErrorV0::PendingBindingConflict);
        }
        let pending = PendingPeerIngressV0 {
            frame: canonical,
            binding: ingress.binding,
            ingress_digest: ingress.ingress_digest(),
        };
        if let Some(current) = self.snapshot.pending {
            return if current == pending {
                Ok(self.snapshot.replay)
            } else {
                Err(CandidatePeerReplayErrorV0::PendingBindingConflict)
            };
        }
        let replay = PeerReplayStateV0::new(
            self.snapshot.session,
            self.snapshot.replay.highest_acknowledged_nonce(),
            Some(canonical),
        )
        .map_err(CandidatePeerReplayErrorV0::Boundary)?;
        self.persist(SnapshotV0 {
            replay,
            pending: Some(pending),
            ..self.snapshot
        })
    }

    pub fn acknowledge_prepared(
        &mut self,
        frame: AuthenticatedPeerFrameV0,
        receipt: AuthorityReceiptV0,
    ) -> Result<PeerReplayStateV0, CandidatePeerReplayErrorV0> {
        if self.poisoned {
            return Err(CandidatePeerReplayErrorV0::Poisoned);
        }
        let pending = match self.snapshot.pending {
            Some(pending) if pending.frame == frame => pending,
            Some(_) => return Err(CandidatePeerReplayErrorV0::MissingPendingFrame),
            None => {
                if self
                    .snapshot
                    .last_acknowledgement
                    .is_some_and(|last| last.frame == frame && last.receipt == receipt)
                {
                    return Ok(self.snapshot.replay);
                }
                return Err(CandidatePeerReplayErrorV0::MissingPendingFrame);
            }
        };
        receipt
            .binding
            .validate(self.snapshot.node_identity)
            .map_err(CandidatePeerReplayErrorV0::NodeBoundary)?;
        if receipt.durable_stage != AuthorityStageV0::Prepared {
            return Err(CandidatePeerReplayErrorV0::InvalidPreparedReceipt(
                "receipt is not Prepared",
            ));
        }
        if receipt.binding != pending.binding {
            return Err(CandidatePeerReplayErrorV0::InvalidPreparedReceipt(
                "operation binding mismatch",
            ));
        }
        if receipt.facts_digest != pending.ingress_digest {
            return Err(CandidatePeerReplayErrorV0::InvalidPreparedReceipt(
                "ingress digest mismatch",
            ));
        }
        if receipt.record_digest == NodeDigestV0([0; 32]) {
            return Err(CandidatePeerReplayErrorV0::InvalidPreparedReceipt(
                "record digest is zero",
            ));
        }

        let replay = PeerReplayStateV0::new(self.snapshot.session, frame.replay_nonce(), None)
            .map_err(CandidatePeerReplayErrorV0::Boundary)?;
        self.persist(SnapshotV0 {
            replay,
            pending: None,
            last_acknowledgement: Some(PreparedPeerAcknowledgementV0 {
                frame,
                ingress_digest: pending.ingress_digest,
                receipt,
            }),
            ..self.snapshot
        })
    }
}

impl PeerReplayRecoverySourceV0 for CandidatePeerReplayJournalV0 {
    type Error = CandidatePeerReplayErrorV0;

    fn verify_recovery(&mut self, state: &PeerReplayStateV0) -> Result<(), Self::Error> {
        if *state != self.snapshot.replay {
            return Err(CandidatePeerReplayErrorV0::InMemoryStateMismatch);
        }
        self.snapshot.validate()
    }
}

pub struct CandidatePersistentPeerAdmissionV0 {
    admission: CandidateP2pAdmissionV0,
    journal: CandidatePeerReplayJournalV0,
}

impl CandidatePersistentPeerAdmissionV0 {
    pub fn open(
        root: impl AsRef<Path>,
        node_identity: NodeIdentityV0,
        session: PeerSessionIdentityV0,
    ) -> Result<Self, CandidatePeerReplayErrorV0> {
        let mut journal = CandidatePeerReplayJournalV0::open(root, node_identity, session)?;
        let state = journal.recovery_state();
        let admission =
            CandidateP2pAdmissionV0::recover_verified(state, &mut journal).map_err(|error| {
                match error {
                    PeerRecoveryErrorV0::Boundary(error) => {
                        CandidatePeerReplayErrorV0::Boundary(error)
                    }
                    PeerRecoveryErrorV0::Source(error) => error,
                }
            })?;
        Ok(Self { admission, journal })
    }

    #[must_use]
    pub const fn recovery_state(&self) -> PeerReplayStateV0 {
        self.admission.recovery_state()
    }

    #[must_use]
    pub const fn last_prepared_acknowledgement(&self) -> Option<PreparedPeerAcknowledgementV0> {
        self.journal.last_prepared_acknowledgement()
    }

    #[must_use]
    pub const fn journal(&self) -> &CandidatePeerReplayJournalV0 {
        &self.journal
    }

    pub fn verify_frame<S>(
        &self,
        frame: AuthenticatedPeerFrameV0,
        source: &mut S,
    ) -> Result<VerifiedPeerFrameV0, PeerFrameVerificationErrorV0<S::Error>>
    where
        S: PeerFrameSourceV0,
    {
        self.admission.verify_frame(frame, source)
    }

    pub fn admit_verified(
        &mut self,
        verified: VerifiedPeerFrameV0,
        ingress: &BoundIngressV0,
    ) -> Result<AuthenticatedPeerFrameV0, CandidatePeerReplayErrorV0> {
        self.journal.stage_verified(&verified, ingress)?;
        let admitted = self
            .admission
            .admit_verified(verified)
            .map_err(CandidatePeerReplayErrorV0::Boundary)?;
        if self.admission.recovery_state() != self.journal.recovery_state() {
            return Err(CandidatePeerReplayErrorV0::InMemoryStateMismatch);
        }
        Ok(admitted)
    }

    pub fn acknowledge_prepared(
        &mut self,
        frame: AuthenticatedPeerFrameV0,
        receipt: AuthorityReceiptV0,
    ) -> Result<PeerReplayStateV0, CandidatePeerReplayErrorV0> {
        let durable = self.journal.acknowledge_prepared(frame, receipt)?;
        match self.admission.acknowledge(frame) {
            Ok(memory) if memory == durable => Ok(durable),
            Ok(_) => Err(CandidatePeerReplayErrorV0::InMemoryStateMismatch),
            Err(_) if self.admission.recovery_state() == durable => Ok(durable),
            Err(error) => Err(CandidatePeerReplayErrorV0::Boundary(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        convert::Infallible,
        sync::atomic::{AtomicU64, Ordering},
    };
    use trnm_node_boundary_v0::{Digest32V0, IngressFrameV0};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "trnm-candidate-peer-replay-{label}-{}-{sequence}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn node_digest(byte: u8) -> Digest32V0 {
        Digest32V0([byte; 32])
    }

    fn io_digest(byte: u8) -> IoDigest32V0 {
        IoDigest32V0::new([byte; 32]).unwrap()
    }

    fn node_identity() -> NodeIdentityV0 {
        NodeIdentityV0 {
            chain_id: node_digest(1),
            validator_id: node_digest(2),
            application_id: node_digest(3),
            generation: 1,
        }
    }

    fn session(session_byte: u8) -> PeerSessionIdentityV0 {
        PeerSessionIdentityV0::new(
            io_digest(1),
            io_digest(6),
            io_digest(4),
            io_digest(session_byte),
            io_digest(5),
            1,
        )
        .unwrap()
    }

    fn ingress(nonce: u64, payload: &[u8]) -> BoundIngressV0 {
        let frame =
            IngressFrameV0::new(node_digest(4), node_digest(5), nonce, payload.to_vec()).unwrap();
        BoundIngressV0::derive(
            node_identity(),
            nonce,
            0,
            node_digest(20),
            node_digest(19),
            frame,
        )
        .unwrap()
    }

    fn receipt(ingress: &BoundIngressV0) -> AuthorityReceiptV0 {
        AuthorityReceiptV0 {
            binding: ingress.binding,
            durable_stage: AuthorityStageV0::Prepared,
            durable_sequence: 0,
            facts_digest: ingress.ingress_digest(),
            record_digest: node_digest(90),
        }
    }

    struct AcceptFrame;

    impl PeerFrameSourceV0 for AcceptFrame {
        type Error = Infallible;

        fn verify_frame(
            &mut self,
            _state: PeerReplayStateV0,
            _frame: &AuthenticatedPeerFrameV0,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[test]
    fn pending_is_durable_before_core_and_lost_ack_replays() {
        let directory = TestDirectory::new("lost-ack");
        let ingress = ingress(1, b"proposal-one");
        let frame =
            candidate_frame_for_bound_ingress_v0(node_identity(), session(7), &ingress).unwrap();

        {
            let mut persistent =
                CandidatePersistentPeerAdmissionV0::open(&directory.0, node_identity(), session(7))
                    .unwrap();
            let verified = persistent.verify_frame(frame, &mut AcceptFrame).unwrap();
            persistent.admit_verified(verified, &ingress).unwrap();
            assert_eq!(persistent.recovery_state().pending(), Some(frame));
        }

        {
            let mut recovered =
                CandidatePersistentPeerAdmissionV0::open(&directory.0, node_identity(), session(7))
                    .unwrap();
            let replay = recovered.verify_frame(frame, &mut AcceptFrame).unwrap();
            recovered.admit_verified(replay, &ingress).unwrap();
            let prepared = receipt(&ingress);
            let state = recovered.acknowledge_prepared(frame, prepared).unwrap();
            assert_eq!(state.highest_acknowledged_nonce(), 1);
            assert_eq!(state.pending(), None);
            assert_eq!(
                recovered.last_prepared_acknowledgement().unwrap().receipt(),
                prepared
            );
        }

        let reopened =
            CandidatePersistentPeerAdmissionV0::open(&directory.0, node_identity(), session(7))
                .unwrap();
        assert_eq!(reopened.recovery_state().highest_acknowledged_nonce(), 1);
        assert_eq!(reopened.recovery_state().pending(), None);
    }

    #[test]
    fn conflicting_replay_and_wrong_receipts_are_non_mutating() {
        let directory = TestDirectory::new("conflict");
        let first_ingress = ingress(1, b"first");
        let first =
            candidate_frame_for_bound_ingress_v0(node_identity(), session(7), &first_ingress)
                .unwrap();
        let mut persistent =
            CandidatePersistentPeerAdmissionV0::open(&directory.0, node_identity(), session(7))
                .unwrap();
        let verified = persistent.verify_frame(first, &mut AcceptFrame).unwrap();
        persistent.admit_verified(verified, &first_ingress).unwrap();

        let conflicting_ingress = ingress(1, b"different");
        let conflicting =
            candidate_frame_for_bound_ingress_v0(node_identity(), session(7), &conflicting_ingress)
                .unwrap();
        assert!(matches!(
            persistent.verify_frame(conflicting, &mut AcceptFrame),
            Err(PeerFrameVerificationErrorV0::Boundary(
                PeerAdmissionErrorV0::ConflictingReplay
            ))
        ));

        let mut wrong = receipt(&first_ingress);
        wrong.durable_stage = AuthorityStageV0::ApplicationSealed;
        assert!(matches!(
            persistent.acknowledge_prepared(first, wrong),
            Err(CandidatePeerReplayErrorV0::InvalidPreparedReceipt(_))
        ));
        assert_eq!(persistent.recovery_state().pending(), Some(first));
        persistent
            .acknowledge_prepared(first, receipt(&first_ingress))
            .unwrap();
    }

    #[test]
    fn complete_temporary_snapshot_is_promoted_after_response_loss() {
        let directory = TestDirectory::new("temporary");
        let ingress = ingress(1, b"proposal");
        let frame =
            candidate_frame_for_bound_ingress_v0(node_identity(), session(7), &ingress).unwrap();
        let current_path;
        {
            let mut journal =
                CandidatePeerReplayJournalV0::open(&directory.0, node_identity(), session(7))
                    .unwrap();
            let mut admission =
                CandidateP2pAdmissionV0::recover_verified(journal.recovery_state(), &mut journal)
                    .unwrap();
            let verified = admission.verify_frame(frame, &mut AcceptFrame).unwrap();
            journal.stage_verified(&verified, &ingress).unwrap();
            admission.admit_verified(verified).unwrap();
            current_path = journal.current_path().to_path_buf();
        }

        let current = SnapshotV0::decode(&fs::read(&current_path).unwrap()).unwrap();
        let next = SnapshotV0 {
            revision: current.revision + 1,
            previous_checksum: current.checksum,
            checksum: [0; 32],
            replay: PeerReplayStateV0::new(session(7), 1, None).unwrap(),
            pending: None,
            last_acknowledgement: Some(PreparedPeerAcknowledgementV0 {
                frame,
                ingress_digest: ingress.ingress_digest(),
                receipt: receipt(&ingress),
            }),
            ..current
        };
        let temporary_path = directory.0.join("peer-replay-v0.tmp");
        let mut temporary = File::create(&temporary_path).unwrap();
        temporary.write_all(&next.encode().unwrap()).unwrap();
        temporary.sync_all().unwrap();

        let recovered =
            CandidatePeerReplayJournalV0::open(&directory.0, node_identity(), session(7)).unwrap();
        assert!(recovered.recovered_temporary());
        assert_eq!(recovered.recovery_state().highest_acknowledged_nonce(), 1);
        assert!(!temporary_path.exists());
    }

    #[test]
    fn tamper_session_substitution_and_concurrent_open_fail_closed() {
        let directory = TestDirectory::new("fail-closed");
        let journal =
            CandidatePeerReplayJournalV0::open(&directory.0, node_identity(), session(7)).unwrap();
        assert!(matches!(
            CandidatePeerReplayJournalV0::open(&directory.0, node_identity(), session(7)),
            Err(CandidatePeerReplayErrorV0::LockBusy(_))
        ));
        let current_path = journal.current_path().to_path_buf();
        drop(journal);

        assert!(matches!(
            CandidatePeerReplayJournalV0::open(&directory.0, node_identity(), session(8)),
            Err(CandidatePeerReplayErrorV0::WrongPeerSession)
        ));

        let mut bytes = fs::read(&current_path).unwrap();
        bytes[32] ^= 0x01;
        fs::write(&current_path, bytes).unwrap();
        assert!(matches!(
            CandidatePeerReplayJournalV0::open(&directory.0, node_identity(), session(7)),
            Err(CandidatePeerReplayErrorV0::Corrupt(_))
        ));
    }
}
