#![forbid(unsafe_code)]
//! Candidate-only process that orders durable peer replay and Core `Prepared`.
//!
//! This binary is not a production network, authenticator, validator, signer,
//! finality owner, or activation path. It composes two candidate journals in a
//! fixed order and makes a lost Core acknowledgement recoverable by exact frame
//! replay across process restart.

#[cfg(not(feature = "candidate-peer-replay"))]
fn main() {
    eprintln!("trnm-candidate-peer-authority requires --features candidate-peer-replay");
    std::process::exit(2);
}

#[cfg(feature = "candidate-peer-replay")]
mod enabled {
    use std::{env, error::Error, fmt, path::Path, process};

    use trnm_durable_file_adapters_v0::{
        candidate_frame_for_bound_ingress_v0, CandidateAuthorityErrorV0,
        CandidateAuthorityJournalV0, CandidatePeerReplayErrorV0,
        CandidatePersistentPeerAdmissionV0,
    };
    use trnm_node_boundary_v0::{
        AuthorityReceiptV0, AuthorityStageV0, BoundIngressV0, Digest32V0, IngressFrameV0,
        NodeIdentityV0, RecoveryDispositionV0,
    };
    use trnm_poco_node_io::{
        AuthenticatedPeerFrameV0, IoDigest32V0, PeerFrameSourceV0,
        PeerFrameVerificationErrorV0, PeerReplayStateV0, PeerSessionIdentityV0,
        VerifiedPeerFrameV0,
    };

    const ACK: &str = "--acknowledge-candidate-only";
    const SCHEMA: &str = "trnm_candidate_peer_authority_v0";

    #[derive(Debug)]
    enum TransactionErrorV0 {
        Authority(CandidateAuthorityErrorV0),
        Peer(CandidatePeerReplayErrorV0),
        AuthorityQuarantined,
        AuthorityIdentityUnavailable,
        FrameIngressMismatch,
        PreparedReceiptMismatch,
        ReplayStateMismatch,
        FrameRejected,
    }

    impl fmt::Display for TransactionErrorV0 {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Authority(error) => write!(formatter, "authority transaction failed: {error}"),
                Self::Peer(error) => write!(formatter, "peer transaction failed: {error}"),
                Self::AuthorityQuarantined => formatter.write_str("authority is quarantined"),
                Self::AuthorityIdentityUnavailable => {
                    formatter.write_str("authority identity is unavailable")
                }
                Self::FrameIngressMismatch => {
                    formatter.write_str("peer frame differs from bound ingress")
                }
                Self::PreparedReceiptMismatch => {
                    formatter.write_str("Core Prepared receipt differs from bound ingress")
                }
                Self::ReplayStateMismatch => {
                    formatter.write_str("peer replay state differs from transaction result")
                }
                Self::FrameRejected => formatter.write_str("exact peer frame verification failed"),
            }
        }
    }

    impl Error for TransactionErrorV0 {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            match self {
                Self::Authority(error) => Some(error),
                Self::Peer(error) => Some(error),
                _ => None,
            }
        }
    }

    impl From<CandidateAuthorityErrorV0> for TransactionErrorV0 {
        fn from(error: CandidateAuthorityErrorV0) -> Self {
            Self::Authority(error)
        }
    }

    impl From<CandidatePeerReplayErrorV0> for TransactionErrorV0 {
        fn from(error: CandidatePeerReplayErrorV0) -> Self {
            Self::Peer(error)
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct PreparedTransactionV0 {
        receipt: AuthorityReceiptV0,
        replay: PeerReplayStateV0,
        recovered_lost_acknowledgement: bool,
    }

    struct ExactFrameSourceV0 {
        expected: AuthenticatedPeerFrameV0,
    }

    impl PeerFrameSourceV0 for ExactFrameSourceV0 {
        type Error = TransactionErrorV0;

        fn verify_frame(
            &mut self,
            _state: PeerReplayStateV0,
            frame: &AuthenticatedPeerFrameV0,
        ) -> Result<(), Self::Error> {
            if *frame == self.expected {
                Ok(())
            } else {
                Err(TransactionErrorV0::FrameRejected)
            }
        }
    }

    struct CandidatePeerAuthorityCoordinatorV0 {
        authority: CandidateAuthorityJournalV0,
        peer: CandidatePersistentPeerAdmissionV0,
    }

    impl CandidatePeerAuthorityCoordinatorV0 {
        fn open(
            authority_root: impl AsRef<Path>,
            peer_root: impl AsRef<Path>,
            identity: NodeIdentityV0,
            session: PeerSessionIdentityV0,
        ) -> Result<Self, TransactionErrorV0> {
            let mut authority =
                CandidateAuthorityJournalV0::open_candidate(authority_root, identity)?;
            match authority.recover()? {
                RecoveryDispositionV0::Clean | RecoveryDispositionV0::Resume { .. } => {}
                RecoveryDispositionV0::Quarantine { .. } => {
                    return Err(TransactionErrorV0::AuthorityQuarantined);
                }
            }
            let peer = CandidatePersistentPeerAdmissionV0::open(peer_root, identity, session)?;
            Ok(Self { authority, peer })
        }

        fn current_receipt(&self) -> Option<AuthorityReceiptV0> {
            self.authority.current_receipt()
        }

        const fn replay_state(&self) -> PeerReplayStateV0 {
            self.peer.recovery_state()
        }

        fn verify_frame(
            &self,
            frame: AuthenticatedPeerFrameV0,
        ) -> Result<VerifiedPeerFrameV0, TransactionErrorV0> {
            self.peer
                .verify_frame(frame, &mut ExactFrameSourceV0 { expected: frame })
                .map_err(|error| match error {
                    PeerFrameVerificationErrorV0::Boundary(error) => {
                        TransactionErrorV0::Peer(CandidatePeerReplayErrorV0::Boundary(error))
                    }
                    PeerFrameVerificationErrorV0::Source(error) => error,
                })
        }

        fn prepare_verified(
            &mut self,
            verified: VerifiedPeerFrameV0,
            ingress: &BoundIngressV0,
        ) -> Result<PreparedTransactionV0, TransactionErrorV0> {
            let identity = self
                .authority
                .identity()
                .ok_or(TransactionErrorV0::AuthorityIdentityUnavailable)?;
            let frame = verified.frame();
            let expected = candidate_frame_for_bound_ingress_v0(
                identity,
                self.peer.recovery_state().session(),
                ingress,
            )?;
            if frame != expected {
                return Err(TransactionErrorV0::FrameIngressMismatch);
            }

            let was_pending = self.peer.recovery_state().pending() == Some(frame);
            let authority_before = self.authority.current_receipt();
            let admitted = self.peer.admit_verified(verified, ingress)?;
            if admitted != frame || self.peer.recovery_state().pending() != Some(frame) {
                return Err(TransactionErrorV0::ReplayStateMismatch);
            }

            let receipt = self.authority.prepare_bound_ingress(ingress)?;
            if receipt.binding != ingress.binding
                || receipt.durable_stage != AuthorityStageV0::Prepared
                || receipt.facts_digest != ingress.ingress_digest()
                || receipt.record_digest == Digest32V0([0; 32])
            {
                return Err(TransactionErrorV0::PreparedReceiptMismatch);
            }

            let replay = self.peer.acknowledge_prepared(frame, receipt)?;
            if replay.pending().is_some()
                || replay.highest_acknowledged_nonce() != frame.replay_nonce()
                || self.peer.recovery_state() != replay
                || self
                    .peer
                    .last_prepared_acknowledgement()
                    .is_none_or(|acknowledgement| {
                        acknowledgement.frame() != frame || acknowledgement.receipt() != receipt
                    })
            {
                return Err(TransactionErrorV0::ReplayStateMismatch);
            }

            Ok(PreparedTransactionV0 {
                receipt,
                replay,
                recovered_lost_acknowledgement: was_pending && authority_before == Some(receipt),
            })
        }
    }

    fn usage() -> &'static str {
        "usage:\n  trnm-candidate-peer-authority --acknowledge-candidate-only status \
<authority-root> <peer-root> <chain-id> <validator-id> <application-id> \
<node-generation> <protocol-digest> <peer-id> <session-id> <profile-digest> \
<peer-generation>\n  trnm-candidate-peer-authority --acknowledge-candidate-only prepare \
<authority-root> <peer-root> <chain-id> <validator-id> <application-id> \
<node-generation> <protocol-digest> <peer-id> <session-id> <profile-digest> \
<peer-generation> <height> <view> <block-id> <parent-id> <replay-nonce> <payload-utf8>"
    }

    fn parse_hex32(label: &str, value: &str) -> Result<[u8; 32], String> {
        if value.len() != 64
            || value
                .bytes()
                .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
        {
            return Err(format!("{label} must be 64 lowercase hexadecimal characters"));
        }
        let mut bytes = [0_u8; 32];
        for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
            let pair = std::str::from_utf8(chunk).map_err(|_| format!("{label} is not UTF-8"))?;
            bytes[index] =
                u8::from_str_radix(pair, 16).map_err(|_| format!("{label} is invalid"))?;
        }
        if bytes == [0; 32] {
            return Err(format!("{label} may not be zero"));
        }
        Ok(bytes)
    }

    fn parse_u64(label: &str, value: &str) -> Result<u64, String> {
        value
            .parse()
            .map_err(|_| format!("{label} must be an unsigned 64-bit integer"))
    }

    fn parse_nonzero_u64(label: &str, value: &str) -> Result<u64, String> {
        let value = parse_u64(label, value)?;
        if value == 0 {
            return Err(format!("{label} must be non-zero"));
        }
        Ok(value)
    }

    fn node_digest(label: &str, value: &str) -> Result<Digest32V0, String> {
        Ok(Digest32V0(parse_hex32(label, value)?))
    }

    fn io_digest(label: &str, value: &str) -> Result<IoDigest32V0, String> {
        IoDigest32V0::new(parse_hex32(label, value)?).map_err(|error| error.to_string())
    }

    fn parse_identity(arguments: &[String]) -> Result<NodeIdentityV0, String> {
        NodeIdentityV0 {
            chain_id: node_digest("chain-id", &arguments[0])?,
            validator_id: node_digest("validator-id", &arguments[1])?,
            application_id: node_digest("application-id", &arguments[2])?,
            generation: parse_nonzero_u64("node-generation", &arguments[3])?,
        }
        .validate()
        .map_err(|error| error.to_string())
    }

    fn parse_session(arguments: &[String]) -> Result<PeerSessionIdentityV0, String> {
        PeerSessionIdentityV0::new(
            io_digest("chain-id", &arguments[0])?,
            io_digest("protocol-digest", &arguments[4])?,
            io_digest("peer-id", &arguments[5])?,
            io_digest("session-id", &arguments[6])?,
            io_digest("profile-digest", &arguments[7])?,
            parse_nonzero_u64("peer-generation", &arguments[8])?,
        )
        .map_err(|error| error.to_string())
    }

    fn hex(digest: Digest32V0) -> String {
        let mut output = String::with_capacity(64);
        for byte in digest.0 {
            use std::fmt::Write as _;
            write!(&mut output, "{byte:02x}").expect("String write cannot fail");
        }
        output
    }

    fn run_status(arguments: &[String]) -> Result<(), Box<dyn Error>> {
        if arguments.len() != 11 {
            return Err(usage().into());
        }
        let identity = parse_identity(&arguments[2..6])?;
        let session = parse_session(&arguments[2..11])?;
        let coordinator = CandidatePeerAuthorityCoordinatorV0::open(
            &arguments[0],
            &arguments[1],
            identity,
            session,
        )?;
        let current = coordinator.current_receipt();
        let stage = current.map_or_else(
            || "null".to_owned(),
            |receipt| format!("\"{:?}\"", receipt.durable_stage),
        );
        let sequence = current.map_or_else(
            || "null".to_owned(),
            |receipt| receipt.durable_sequence.to_string(),
        );
        println!(
            "{{\"schema\":\"{SCHEMA}\",\"command\":\"status\",\"authority_stage\":{stage},\"authority_sequence\":{sequence},\"replay_floor\":{},\"pending\":{},\"persistent_peer_replay\":true,\"durable_core_prepared\":true,\"crash_reconciliation\":true,\"hardware_atomicity\":false,\"authenticated_network\":false,\"production_candidate\":false,\"production_activation\":false}}",
            coordinator.replay_state().highest_acknowledged_nonce(),
            coordinator.replay_state().pending().is_some(),
        );
        Ok(())
    }

    fn run_prepare(arguments: &[String]) -> Result<(), Box<dyn Error>> {
        if arguments.len() != 17 {
            return Err(usage().into());
        }
        let identity = parse_identity(&arguments[2..6])?;
        let session = parse_session(&arguments[2..11])?;
        let height = parse_nonzero_u64("height", &arguments[11])?;
        let view = parse_u64("view", &arguments[12])?;
        let block_id = node_digest("block-id", &arguments[13])?;
        let parent_id = node_digest("parent-id", &arguments[14])?;
        let replay_nonce = parse_nonzero_u64("replay-nonce", &arguments[15])?;
        let frame = IngressFrameV0::new(
            Digest32V0(session.peer_id().bytes()),
            Digest32V0(session.profile_digest().bytes()),
            replay_nonce,
            arguments[16].as_bytes().to_vec(),
        )?;
        let ingress =
            BoundIngressV0::derive(identity, height, view, block_id, parent_id, frame)?;
        let peer_frame = candidate_frame_for_bound_ingress_v0(identity, session, &ingress)?;
        let mut coordinator = CandidatePeerAuthorityCoordinatorV0::open(
            &arguments[0],
            &arguments[1],
            identity,
            session,
        )?;
        let verified = coordinator.verify_frame(peer_frame)?;
        let result = coordinator.prepare_verified(verified, &ingress)?;
        println!(
            "{{\"schema\":\"{SCHEMA}\",\"command\":\"prepare\",\"operation_id\":\"{}\",\"height\":{},\"view\":{},\"authority_stage\":\"Prepared\",\"authority_sequence\":{},\"facts_digest\":\"{}\",\"record_digest\":\"{}\",\"replay_floor\":{},\"recovered_lost_acknowledgement\":{},\"persistent_peer_replay\":true,\"durable_core_prepared\":true,\"crash_reconciliation\":true,\"hardware_atomicity\":false,\"authenticated_network\":false,\"production_candidate\":false,\"production_activation\":false}}",
            hex(result.receipt.binding.operation_id),
            result.receipt.binding.height,
            result.receipt.binding.view,
            result.receipt.durable_sequence,
            hex(result.receipt.facts_digest),
            hex(result.receipt.record_digest),
            result.replay.highest_acknowledged_nonce(),
            result.recovered_lost_acknowledgement,
        );
        Ok(())
    }

    pub fn main() {
        let arguments = env::args().skip(1).collect::<Vec<_>>();
        let result = match arguments.as_slice() {
            [ack, command, rest @ ..] if ack == ACK && command == "status" => run_status(rest),
            [ack, command, rest @ ..] if ack == ACK && command == "prepare" => run_prepare(rest),
            _ => Err(usage().into()),
        };
        if let Err(error) = result {
            eprintln!("{error}");
            process::exit(2);
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{
            fs,
            path::PathBuf,
            sync::atomic::{AtomicU64, Ordering},
            time::{SystemTime, UNIX_EPOCH},
        };

        static NEXT: AtomicU64 = AtomicU64::new(0);

        struct TestDirectory(PathBuf);

        impl TestDirectory {
            fn new(label: &str) -> Self {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos();
                let next = NEXT.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "trnm-peer-authority-{label}-{}-{now}-{next}",
                    process::id()
                ));
                fs::create_dir_all(&path).expect("create directory");
                Self(path)
            }

            fn path(&self) -> &Path {
                &self.0
            }
        }

        impl Drop for TestDirectory {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }

        fn d(byte: u8) -> Digest32V0 {
            Digest32V0([byte; 32])
        }

        fn io(byte: u8) -> IoDigest32V0 {
            IoDigest32V0::new([byte; 32]).expect("digest")
        }

        fn identity() -> NodeIdentityV0 {
            NodeIdentityV0 {
                chain_id: d(1),
                validator_id: d(2),
                application_id: d(3),
                generation: 1,
            }
        }

        fn session() -> PeerSessionIdentityV0 {
            PeerSessionIdentityV0::new(io(1), io(6), io(4), io(7), io(5), 1)
                .expect("session")
        }

        fn ingress(payload: &[u8]) -> BoundIngressV0 {
            let frame = IngressFrameV0::new(d(4), d(5), 1, payload.to_vec()).expect("frame");
            BoundIngressV0::derive(identity(), 1, 0, d(20), d(19), frame).expect("ingress")
        }

        #[test]
        fn normal_transaction_reopens_with_exact_receipt_and_floor() {
            let authority = TestDirectory::new("normal-core");
            let peer = TestDirectory::new("normal-peer");
            let ingress = ingress(b"proposal");
            let frame = candidate_frame_for_bound_ingress_v0(identity(), session(), &ingress)
                .expect("peer frame");
            let result = {
                let mut coordinator = CandidatePeerAuthorityCoordinatorV0::open(
                    authority.path(),
                    peer.path(),
                    identity(),
                    session(),
                )
                .expect("open");
                let verified = coordinator.verify_frame(frame).expect("verify");
                coordinator
                    .prepare_verified(verified, &ingress)
                    .expect("prepare")
            };
            assert_eq!(result.receipt.durable_stage, AuthorityStageV0::Prepared);
            assert_eq!(result.replay.highest_acknowledged_nonce(), 1);
            assert_eq!(result.replay.pending(), None);
            assert!(!result.recovered_lost_acknowledgement);

            let reopened = CandidatePeerAuthorityCoordinatorV0::open(
                authority.path(),
                peer.path(),
                identity(),
                session(),
            )
            .expect("reopen");
            assert_eq!(reopened.current_receipt(), Some(result.receipt));
            assert_eq!(reopened.replay_state(), result.replay);
        }

        #[test]
        fn peer_staged_cut_retries_without_losing_pending_frame() {
            let authority = TestDirectory::new("peer-cut-core");
            let peer = TestDirectory::new("peer-cut-peer");
            let ingress = ingress(b"proposal");
            let frame = candidate_frame_for_bound_ingress_v0(identity(), session(), &ingress)
                .expect("peer frame");
            {
                let mut pending = CandidatePersistentPeerAdmissionV0::open(
                    peer.path(),
                    identity(),
                    session(),
                )
                .expect("open peer");
                let verified = pending
                    .verify_frame(frame, &mut ExactFrameSourceV0 { expected: frame })
                    .expect("verify");
                pending
                    .admit_verified(verified, &ingress)
                    .expect("persist pending");
            }

            let mut coordinator = CandidatePeerAuthorityCoordinatorV0::open(
                authority.path(),
                peer.path(),
                identity(),
                session(),
            )
            .expect("open coordinator");
            assert_eq!(coordinator.current_receipt(), None);
            assert_eq!(coordinator.replay_state().pending(), Some(frame));
            let verified = coordinator.verify_frame(frame).expect("verify replay");
            let result = coordinator
                .prepare_verified(verified, &ingress)
                .expect("complete");
            assert_eq!(result.replay.pending(), None);
            assert!(!result.recovered_lost_acknowledgement);
        }

        #[test]
        fn core_prepared_cut_is_reconciled_by_exact_frame_replay() {
            let authority = TestDirectory::new("core-cut-core");
            let peer = TestDirectory::new("core-cut-peer");
            let ingress = ingress(b"proposal");
            let frame = candidate_frame_for_bound_ingress_v0(identity(), session(), &ingress)
                .expect("peer frame");
            {
                let mut pending = CandidatePersistentPeerAdmissionV0::open(
                    peer.path(),
                    identity(),
                    session(),
                )
                .expect("open peer");
                let verified = pending
                    .verify_frame(frame, &mut ExactFrameSourceV0 { expected: frame })
                    .expect("verify");
                pending
                    .admit_verified(verified, &ingress)
                    .expect("persist pending");
            }
            let prepared = {
                let mut core =
                    CandidateAuthorityJournalV0::open_candidate(authority.path(), identity())
                        .expect("open Core");
                assert_eq!(
                    core.recover().expect("recover Core"),
                    RecoveryDispositionV0::Clean
                );
                core.prepare_bound_ingress(&ingress).expect("Prepared")
            };

            let mut coordinator = CandidatePeerAuthorityCoordinatorV0::open(
                authority.path(),
                peer.path(),
                identity(),
                session(),
            )
            .expect("open coordinator");
            assert_eq!(coordinator.current_receipt(), Some(prepared));
            assert_eq!(coordinator.replay_state().pending(), Some(frame));
            let verified = coordinator.verify_frame(frame).expect("verify replay");
            let result = coordinator
                .prepare_verified(verified, &ingress)
                .expect("reconcile");
            assert_eq!(result.receipt, prepared);
            assert!(result.recovered_lost_acknowledgement);
            assert_eq!(result.replay.pending(), None);
            assert_eq!(result.replay.highest_acknowledged_nonce(), 1);
        }

        #[test]
        fn frame_cannot_be_rebound_to_substituted_ingress() {
            let authority = TestDirectory::new("substitute-core");
            let peer = TestDirectory::new("substitute-peer");
            let original = ingress(b"original");
            let substituted = ingress(b"substituted");
            let frame = candidate_frame_for_bound_ingress_v0(identity(), session(), &original)
                .expect("peer frame");
            let mut coordinator = CandidatePeerAuthorityCoordinatorV0::open(
                authority.path(),
                peer.path(),
                identity(),
                session(),
            )
            .expect("open coordinator");
            let verified = coordinator.verify_frame(frame).expect("verify");
            assert!(matches!(
                coordinator.prepare_verified(verified, &substituted),
                Err(TransactionErrorV0::FrameIngressMismatch)
            ));
            assert_eq!(coordinator.current_receipt(), None);
            assert_eq!(coordinator.replay_state().pending(), None);
        }
    }
}

#[cfg(feature = "candidate-peer-replay")]
fn main() {
    enabled::main();
}
