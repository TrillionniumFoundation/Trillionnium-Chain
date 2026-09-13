//! Secret-free observer verification for the durable N/N fleet-start proof.

use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

use anyhow::{ensure, Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    config::PublicReportVerifierContext,
    consensus_runtime::{
        CONSENSUS_RUNTIME_FLEET_BARRIER_ROUND_V1,
        CONSENSUS_RUNTIME_PACEMAKER_BASE_TIMEOUT_SECONDS_V1,
        CONSENSUS_RUNTIME_TERMINAL_DRAIN_ALLOWANCE_SECONDS_V1,
        CONSENSUS_RUNTIME_TIMEOUT_VIEW_BUDGET_ALLOWANCE_SECONDS_V1,
    },
    continuous_runtime::CONTINUOUS_RUNTIME_RETAINED_VIEW_TAIL_V0,
    fleet_barrier::{
        FleetBarrierTransportV1, FleetStartCertificateV1, MAX_FLEET_BARRIER_ARCHIVE_ENTRIES_V1,
        MAX_FLEET_BARRIER_SIGNER_INTENTS_V1, MAX_FLEET_START_CERTIFICATE_BYTES_V1,
    },
};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FleetStartCertificateVerificationV1 {
    pub schema_version: u32,
    pub status: &'static str,
    pub run_id: String,
    pub selected_validator_id: String,
    pub validator_count: usize,
    pub validator_set_id: String,
    pub validator_set_sha256: String,
    pub topology_sha256: String,
    pub coordinator_manifest_sha256: String,
    pub candidate_source_sha256: String,
    pub binary_sha256: String,
    pub workload_corpus_sha256: String,
    pub workload_policy_sha256: String,
    pub ordinary_start_height: u64,
    pub duration_seconds: u64,
    pub max_blocks: u64,
    pub target_height: u64,
    pub barrier_round: u64,
    pub transport: &'static str,
    pub relay_hop_budget: u8,
    pub context_sha256: String,
    pub ready_set_sha256: String,
    pub fleet_start_certificate_digest: String,
    pub fleet_start_certificate_sha256: String,
    pub ready_statement_count: usize,
    pub start_statement_count: usize,
    pub mesh_session_count: usize,
    pub selected_pre_ready_journal_sequence: u64,
    pub selected_pre_ready_journal_sha256: String,
    pub selected_fleet_ready_event_sequence: u64,
    pub selected_fleet_ready_event_sha256: String,
    pub initial_current_view: u64,
    pub initial_high_qc_height: u64,
    pub initial_finalized_height: u64,
    pub initial_application_height: u64,
    pub initial_proposal_parent_height: u64,
    pub maximum_timeout_view_advances: u64,
    pub maximum_local_vote_intents: u64,
    pub maximum_local_timeout_intents: u64,
    pub maximum_total_signer_intents: u64,
    pub maximum_signed_replay_archive_entries: u64,
    pub relay_admission_capacity: u64,
    pub signature_verified: bool,
    pub semantics_verified: bool,
    pub exact_session_topology_verified: bool,
    pub g3_evidence_complete: bool,
    pub geo_wan_evidence: bool,
    pub production_activation: bool,
}

/// Opens one immutable copied certificate without following a final symlink,
/// verifies its complete canonical wire form, and joins it to the closed
/// observer-public deployment and the operator's exact bounded-run request.
pub fn load_and_verify_fleet_start_certificate_v1(
    path: &Path,
    public: &PublicReportVerifierContext,
    expected_duration_seconds: u64,
    expected_max_blocks: u64,
) -> Result<FleetStartCertificateVerificationV1> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open pinned fleet StartCertificate {}", path.display()))?;
    let initial = file
        .metadata()
        .context("inspect pinned fleet StartCertificate")?;
    ensure!(
        initial.is_file()
            && initial.nlink() == 1
            && initial.permissions().mode() & 0o777 == 0o600
            && initial.len() > 0
            && initial.len()
                <= u64::try_from(MAX_FLEET_START_CERTIFICATE_BYTES_V1).unwrap_or(u64::MAX),
        "fleet StartCertificate file crosses its bounded profile"
    );
    let expected_len = usize::try_from(initial.len()).context("certificate size overflow")?;
    let mut bytes = Vec::with_capacity(expected_len);
    file.read_to_end(&mut bytes)
        .context("read pinned fleet StartCertificate")?;
    let final_metadata = file
        .metadata()
        .context("reinspect pinned fleet StartCertificate")?;
    ensure!(
        bytes.len() == expected_len
            && initial.dev() == final_metadata.dev()
            && initial.ino() == final_metadata.ino()
            && initial.len() == final_metadata.len()
            && initial.uid() == final_metadata.uid()
            && initial.mode() == final_metadata.mode()
            && initial.mtime() == final_metadata.mtime()
            && initial.mtime_nsec() == final_metadata.mtime_nsec()
            && initial.ctime() == final_metadata.ctime()
            && initial.ctime_nsec() == final_metadata.ctime_nsec()
            && final_metadata.nlink() == 1
            && final_metadata.permissions().mode() & 0o777 == 0o600,
        "fleet StartCertificate changed while verified"
    );

    let certificate = FleetStartCertificateV1::decode(&bytes, public.validator_set())
        .map_err(|error| anyhow::anyhow!("decode fleet StartCertificate: {error}"))?;
    certificate
        .verify(public.validator_set())
        .map_err(|error| anyhow::anyhow!("verify fleet StartCertificate: {error}"))?;
    certificate
        .verify_exact_mesh_topology(public.expected_outgoing_peers())
        .map_err(|error| anyhow::anyhow!("verify fleet session topology: {error}"))?;
    ensure!(
        certificate.encode() == bytes,
        "fleet StartCertificate canonical re-encoding differs"
    );

    let ready_set = certificate.ready_set();
    let context = ready_set.context();
    let identity = context.identity();
    let request = context.request();
    let capacities = context.capacities();
    let cut = context.initial_chain_cut();
    let bootstrap_cut = public.bootstrap_initial_cut();
    let validator_count = public.validator_set().validators().len();
    ensure!(
        identity.run_id() == public.run_id()
            && identity.validator_set_sha256() == public.validator_set_sha256()
            && identity.topology_sha256() == public.topology_sha256()
            && identity.coordinator_manifest_sha256() == public.coordinator_manifest_sha256()
            && identity.candidate_source_sha256() == public.candidate_source_sha256()
            && identity.binary_sha256() == public.binary_sha256()
            && identity.workload_corpus_sha256() == public.workload_corpus_sha256()
            && identity.workload_policy_sha256() == public.workload_policy_sha256()
            && usize::try_from(identity.validator_count()).ok() == Some(validator_count),
        "fleet StartCertificate deployment identity differs from observer-public"
    );
    let expected_target_height = public
        .ordinary_start_height()
        .checked_add(
            expected_max_blocks
                .checked_sub(1)
                .context("max-blocks is zero")?,
        )
        .context("expected target height overflows")?;
    ensure!(
        expected_duration_seconds > 0
            && request.barrier_round() == CONSENSUS_RUNTIME_FLEET_BARRIER_ROUND_V1
            && request.ordinary_start_height() == public.ordinary_start_height()
            && request.duration_seconds() == expected_duration_seconds
            && request.pacemaker_base_timeout_seconds()
                == CONSENSUS_RUNTIME_PACEMAKER_BASE_TIMEOUT_SECONDS_V1
            && request.terminal_drain_allowance_seconds()
                == CONSENSUS_RUNTIME_TERMINAL_DRAIN_ALLOWANCE_SECONDS_V1
            && request.timeout_view_budget_allowance_seconds()
                == CONSENSUS_RUNTIME_TIMEOUT_VIEW_BUDGET_ALLOWANCE_SECONDS_V1
            && request.maximum_blocks() == expected_max_blocks
            && request.target_height() == expected_target_height
            && cut.proposal_parent_height().checked_add(1) == Some(public.ordinary_start_height())
            && cut.high_qc_height() == cut.proposal_parent_height()
            && cut.high_qc_block_id() == cut.proposal_parent_block_id()
            && capacities.signer_journal_capacity() == MAX_FLEET_BARRIER_SIGNER_INTENTS_V1
            && capacities.signed_replay_archive_capacity() == MAX_FLEET_BARRIER_ARCHIVE_ENTRIES_V1,
        "fleet StartCertificate request/cut/capacity differs from bounded runtime"
    );
    let expected_current_view = bootstrap_cut
        .high_qc_view
        .checked_add(1)
        .context("bootstrap high-QC view overflows")?;
    let retained_predecessors = u64::try_from(
        CONTINUOUS_RUNTIME_RETAINED_VIEW_TAIL_V0
            .checked_sub(1)
            .context("continuous retained-view tail is zero")?,
    )
    .context("continuous retained-view tail does not fit u64")?;
    ensure!(
        cut.minimum_retained_view() == expected_current_view.saturating_sub(retained_predecessors)
            && cut.current_view() == expected_current_view
            && cut.epoch() == public.validator_set().epoch().get()
            && cut.high_qc_certificate_id() == bootstrap_cut.high_qc_certificate_id
            && cut.high_qc_view() == bootstrap_cut.high_qc_view
            && cut.high_qc_height() == bootstrap_cut.high_qc_height
            && cut.high_qc_block_id() == bootstrap_cut.high_qc_block_id
            && cut.finalized_height() == bootstrap_cut.finalized_height
            && cut.finalized_block_id() == bootstrap_cut.finalized_block_id
            && cut.application_height() == bootstrap_cut.application_height
            && cut.application_block_id() == bootstrap_cut.application_block_id
            && cut.proposal_parent_height() == bootstrap_cut.proposal_parent_height
            && cut.proposal_parent_block_id() == bootstrap_cut.proposal_parent_block_id
            && cut.application_state_root() == bootstrap_cut.application_state_root
            && cut.safety_revision() == 5
            && cut.signer_watermark_sequence() == 0
            && cut.checkpoint_generation() == 3,
        "fleet StartCertificate initial cut differs from verified h1-h3 commissioning"
    );
    ensure!(
        public.validator_config_sha256().len() == validator_count
            && ready_set.statements().len() == validator_count
            && certificate.statements().len() == validator_count
            && ready_set.statements().iter().all(|statement| {
                public
                    .validator_config_sha256()
                    .get(&statement.origin())
                    .is_some_and(|expected| *expected == statement.local_cut().config_sha256())
                    && statement.local_cut().process_instance() == 1
            }),
        "fleet Ready config/process inventory differs from observer-public"
    );
    let mesh_session_count = ready_set
        .statements()
        .iter()
        .try_fold(0usize, |count, statement| {
            count.checked_add(statement.mesh_session_set().sessions().len())
        })
        .context("fleet mesh session count overflows")?;
    let selected_ready = ready_set
        .statement(public.local_validator())
        .context("fleet ReadySet lacks selected validator")?;
    let selected_start = certificate
        .statement(public.local_validator())
        .context("fleet StartCertificate lacks selected validator")?;
    ensure!(
        selected_start.fleet_ready_event_sequence()
            == selected_ready
                .local_cut()
                .pre_ready_journal_sequence()
                .checked_add(1)
                .context("selected pre-Ready sequence overflows")?,
        "selected fleet Start does not immediately bind its pre-Ready journal cut"
    );
    let (transport, relay_hop_budget) = match request.transport() {
        FleetBarrierTransportV1::Direct => ("direct", 0),
        FleetBarrierTransportV1::SparseRelay { hop_budget } => {
            ("origin-signed-sparse-relay", hop_budget)
        }
    };
    let file_sha256 = Sha256::digest(&bytes);
    Ok(FleetStartCertificateVerificationV1 {
        schema_version: 1,
        status: "fleet-start-certificate-signature-and-semantics-verified",
        run_id: public.run_id().to_owned(),
        selected_validator_id: hex::encode(public.local_validator().as_bytes()),
        validator_count,
        validator_set_id: hex::encode(public.validator_set().id().as_bytes()),
        validator_set_sha256: hex::encode(public.validator_set_sha256()),
        topology_sha256: hex::encode(public.topology_sha256()),
        coordinator_manifest_sha256: hex::encode(public.coordinator_manifest_sha256()),
        candidate_source_sha256: hex::encode(public.candidate_source_sha256()),
        binary_sha256: hex::encode(public.binary_sha256()),
        workload_corpus_sha256: hex::encode(public.workload_corpus_sha256()),
        workload_policy_sha256: hex::encode(public.workload_policy_sha256()),
        ordinary_start_height: public.ordinary_start_height(),
        duration_seconds: request.duration_seconds(),
        max_blocks: request.maximum_blocks(),
        target_height: request.target_height(),
        barrier_round: request.barrier_round(),
        transport,
        relay_hop_budget,
        context_sha256: hex::encode(context.digest()),
        ready_set_sha256: hex::encode(ready_set.digest()),
        fleet_start_certificate_digest: hex::encode(certificate.digest()),
        fleet_start_certificate_sha256: hex::encode(file_sha256),
        ready_statement_count: ready_set.statements().len(),
        start_statement_count: certificate.statements().len(),
        mesh_session_count,
        selected_pre_ready_journal_sequence: selected_ready
            .local_cut()
            .pre_ready_journal_sequence(),
        selected_pre_ready_journal_sha256: hex::encode(
            selected_ready.local_cut().pre_ready_journal_sha256(),
        ),
        selected_fleet_ready_event_sequence: selected_start.fleet_ready_event_sequence(),
        selected_fleet_ready_event_sha256: hex::encode(selected_start.fleet_ready_event_sha256()),
        initial_current_view: cut.current_view(),
        initial_high_qc_height: cut.high_qc_height(),
        initial_finalized_height: cut.finalized_height(),
        initial_application_height: cut.application_height(),
        initial_proposal_parent_height: cut.proposal_parent_height(),
        maximum_timeout_view_advances: capacities.maximum_timeout_view_advances(),
        maximum_local_vote_intents: capacities.maximum_local_vote_intents(),
        maximum_local_timeout_intents: capacities.maximum_local_timeout_intents(),
        maximum_total_signer_intents: capacities.maximum_total_signer_intents(),
        maximum_signed_replay_archive_entries: capacities.maximum_signed_replay_archive_entries(),
        relay_admission_capacity: capacities.relay_admission_capacity(),
        signature_verified: true,
        semantics_verified: true,
        exact_session_topology_verified: true,
        g3_evidence_complete: false,
        geo_wan_evidence: false,
        production_activation: false,
    })
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
    };

    use ed25519_dalek::SigningKey;
    use tempfile::TempDir;
    use trnm_consensus_types::{
        ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch, GenesisHash, ProtocolVersion,
        Validator, ValidatorId, ValidatorSet, VotingPower,
    };

    use super::*;
    use crate::{
        bootstrap_material::VerifiedPublicBootstrapInitialCutV1,
        fleet_barrier::{
            CommonCampaignContextV1, CommonChainCutV1, FleetCampaignCapacitiesV1,
            FleetCampaignIdentityV1, FleetCampaignRequestV1, FleetMeshSessionDirectionV1,
            FleetMeshSessionSetV1, FleetMeshSessionV1, FleetReadySetV1, LocalReadyCutV1,
            SignedFleetReadyV1, SignedFleetStartV1,
        },
    };

    struct CertificateFixture {
        _temporary: TempDir,
        path: PathBuf,
        public: PublicReportVerifierContext,
        certificate: FleetStartCertificateV1,
        context: CommonCampaignContextV1,
        keys: Vec<SigningKey>,
        config_sha256: BTreeMap<ValidatorId, [u8; 32]>,
        expected_outgoing: BTreeMap<ValidatorId, BTreeSet<ValidatorId>>,
        bootstrap_cut: VerifiedPublicBootstrapInitialCutV1,
    }

    fn validator_fixture() -> (ValidatorSet, Vec<SigningKey>) {
        let keys = (0..7)
            .map(|index| SigningKey::from_bytes(&[0x31 + index; 32]))
            .collect::<Vec<_>>();
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let validators = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                Validator::new(
                    ValidatorId::new([0x11 + u8::try_from(index).unwrap(); 32]),
                    ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap()
            })
            .collect();
        let set = ValidatorSet::new(
            GenesisHash::new([0x21; 32]),
            ChainId::new("trnm-poco-g3-observer-barrier-test").unwrap(),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .unwrap();
        (set, keys)
    }

    fn bootstrap_cut() -> VerifiedPublicBootstrapInitialCutV1 {
        VerifiedPublicBootstrapInitialCutV1 {
            high_qc_certificate_id: [0x50; 32],
            high_qc_view: 3,
            high_qc_height: 3,
            high_qc_block_id: [0x51; 32],
            finalized_height: 1,
            finalized_block_id: [0x52; 32],
            application_height: 1,
            application_block_id: [0x52; 32],
            proposal_parent_height: 3,
            proposal_parent_block_id: [0x51; 32],
            application_state_root: [0x54; 32],
        }
    }

    fn campaign(set: &ValidatorSet) -> CommonCampaignContextV1 {
        CommonCampaignContextV1::new(
            FleetCampaignIdentityV1::new(
                "poco-g3-7-20260814T000000Z-1234abcd".to_owned(),
                set.chain_id(),
                *set.genesis_hash().as_bytes(),
                *set.id().as_bytes(),
                [0x41; 32],
                [0x42; 32],
                [0x43; 32],
                [0x44; 32],
                [0x45; 32],
                [0x46; 32],
                [0x47; 32],
                u32::try_from(set.validators().len()).unwrap(),
            )
            .unwrap(),
            FleetCampaignRequestV1::new(
                CONSENSUS_RUNTIME_FLEET_BARRIER_ROUND_V1,
                4,
                60,
                CONSENSUS_RUNTIME_PACEMAKER_BASE_TIMEOUT_SECONDS_V1,
                CONSENSUS_RUNTIME_TERMINAL_DRAIN_ALLOWANCE_SECONDS_V1,
                CONSENSUS_RUNTIME_TIMEOUT_VIEW_BUDGET_ALLOWANCE_SECONDS_V1,
                100,
                103,
                FleetBarrierTransportV1::Direct,
            )
            .unwrap(),
            FleetCampaignCapacitiesV1::new(4_096, 60, 163, 160, 60, 220, 8_192, 160, 161, 321, 108)
                .unwrap(),
            CommonChainCutV1::new(
                0, 4, 0, [0x50; 32], 3, 3, [0x51; 32], 1, [0x52; 32], 1, [0x52; 32], 3, [0x51; 32],
                [0x54; 32], 5, 0, 3,
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn session_id(source: usize, target: usize, validator_count: usize) -> [u8; 32] {
        [0x20 + u8::try_from(source * validator_count + target).unwrap(); 32]
    }

    fn local_ready(
        set: &ValidatorSet,
        index: usize,
        mismatch_endpoint: bool,
    ) -> (LocalReadyCutV1, FleetMeshSessionSetV1) {
        let local = set.validators()[index].id();
        let count = set.validators().len();
        let mut sessions = Vec::new();
        for (remote_index, remote) in set.validators().iter().enumerate() {
            if remote.id() == local {
                continue;
            }
            let incoming_id = if mismatch_endpoint && index == 1 && remote_index == 0 {
                [0xee; 32]
            } else {
                session_id(remote_index, index, count)
            };
            sessions.push(
                FleetMeshSessionV1::new(
                    FleetMeshSessionDirectionV1::Incoming,
                    remote.id(),
                    incoming_id,
                )
                .unwrap(),
            );
            sessions.push(
                FleetMeshSessionV1::new(
                    FleetMeshSessionDirectionV1::Outgoing,
                    remote.id(),
                    session_id(index, remote_index, count),
                )
                .unwrap(),
            );
        }
        let mesh = FleetMeshSessionSetV1::new(local, sessions, set).unwrap();
        let local_cut = LocalReadyCutV1::new(
            local,
            [0x61 + u8::try_from(index).unwrap(); 32],
            1,
            10 + u64::try_from(index).unwrap(),
            [0x71 + u8::try_from(index).unwrap(); 32],
            &mesh,
            [0x91 + u8::try_from(index).unwrap(); 32],
            [0xa1 + u8::try_from(index).unwrap(); 32],
            [0xb1 + u8::try_from(index).unwrap(); 32],
            [0xc1 + u8::try_from(index).unwrap(); 32],
        )
        .unwrap();
        (local_cut, mesh)
    }

    fn ready_statements(
        set: &ValidatorSet,
        keys: &[SigningKey],
        context: &CommonCampaignContextV1,
        mismatch_endpoint: bool,
    ) -> Vec<SignedFleetReadyV1> {
        keys.iter()
            .enumerate()
            .map(|(index, key)| {
                let (local_cut, mesh) = local_ready(set, index, mismatch_endpoint);
                SignedFleetReadyV1::new(context.clone(), local_cut, mesh, set, key).unwrap()
            })
            .collect()
    }

    fn write_mode_0600(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn raw_certificate(ready: &[SignedFleetReadyV1], starts: &[SignedFleetStartV1]) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(b"TRNMFBC1");
        output.extend_from_slice(&1u16.to_be_bytes());
        output.extend_from_slice(&u32::try_from(ready.len()).unwrap().to_be_bytes());
        for statement in ready {
            let encoded = statement.encode();
            output.extend_from_slice(&u32::try_from(encoded.len()).unwrap().to_be_bytes());
            output.extend_from_slice(&encoded);
        }
        output.extend_from_slice(&u32::try_from(starts.len()).unwrap().to_be_bytes());
        for statement in starts {
            let encoded = statement.encode();
            output.extend_from_slice(&u32::try_from(encoded.len()).unwrap().to_be_bytes());
            output.extend_from_slice(&encoded);
        }
        output
    }

    fn fixture() -> CertificateFixture {
        let (set, keys) = validator_fixture();
        let context = campaign(&set);
        let ready = ready_statements(&set, &keys, &context, false);
        let ready_set = FleetReadySetV1::new(context.clone(), ready.clone(), &set).unwrap();
        let starts = ready
            .iter()
            .zip(&keys)
            .enumerate()
            .map(|(index, (ready, key))| {
                SignedFleetStartV1::new(
                    ready,
                    &ready_set,
                    ready.local_cut().pre_ready_journal_sequence() + 1,
                    [0xd1 + u8::try_from(index).unwrap(); 32],
                    &set,
                    key,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let certificate = FleetStartCertificateV1::new(ready_set, starts, &set).unwrap();
        let config_sha256 = set
            .validators()
            .iter()
            .enumerate()
            .map(|(index, validator)| (validator.id(), [0x61 + u8::try_from(index).unwrap(); 32]))
            .collect::<BTreeMap<_, _>>();
        let expected_outgoing = set
            .validators()
            .iter()
            .map(|validator| {
                (
                    validator.id(),
                    set.validators()
                        .iter()
                        .map(|peer| peer.id())
                        .filter(|peer| *peer != validator.id())
                        .collect::<BTreeSet<_>>(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let bootstrap_cut = bootstrap_cut();
        let public = PublicReportVerifierContext::from_fleet_barrier_test_parts_v1(
            set.clone(),
            set.validators()[0].id(),
            &context,
            config_sha256.clone(),
            expected_outgoing.clone(),
            bootstrap_cut,
        );
        let temporary = TempDir::new().unwrap();
        let path = temporary.path().join("fleet-start-certificate.cev1");
        write_mode_0600(&path, &certificate.encode());
        CertificateFixture {
            _temporary: temporary,
            path,
            public,
            certificate,
            context,
            keys,
            config_sha256,
            expected_outgoing,
            bootstrap_cut,
        }
    }

    #[test]
    fn full_seven_validator_certificate_is_verified_against_public_cut_and_topology() {
        let fixture = fixture();
        let observed =
            load_and_verify_fleet_start_certificate_v1(&fixture.path, &fixture.public, 60, 100)
                .unwrap();
        assert_eq!(observed.validator_count, 7);
        assert_eq!(observed.ready_statement_count, 7);
        assert_eq!(observed.start_statement_count, 7);
        assert_eq!(observed.mesh_session_count, 84);
        assert_eq!(observed.selected_pre_ready_journal_sequence, 10);
        assert_eq!(observed.selected_fleet_ready_event_sequence, 11);
        assert_eq!(observed.initial_current_view, 4);
        assert_eq!(observed.initial_finalized_height, 1);
        assert_eq!(observed.initial_proposal_parent_height, 3);
        assert_eq!(
            observed.fleet_start_certificate_sha256,
            hex::encode(Sha256::digest(fixture.certificate.encode()))
        );
        assert_ne!(
            observed.fleet_start_certificate_sha256,
            observed.fleet_start_certificate_digest
        );
        assert!(observed.signature_verified);
        assert!(observed.semantics_verified);
        assert!(observed.exact_session_topology_verified);
        assert!(!observed.g3_evidence_complete);
    }

    #[test]
    fn operator_duration_and_max_blocks_must_match_exactly() {
        let fixture = fixture();
        assert!(load_and_verify_fleet_start_certificate_v1(
            &fixture.path,
            &fixture.public,
            61,
            100,
        )
        .is_err());
        assert!(
            load_and_verify_fleet_start_certificate_v1(&fixture.path, &fixture.public, 60, 99,)
                .is_err()
        );
    }

    #[test]
    fn independently_signed_session_endpoint_disagreement_is_rejected() {
        let fixture = fixture();
        let mismatched_ready = ready_statements(
            fixture.public.validator_set(),
            &fixture.keys,
            &fixture.context,
            true,
        );
        let bytes = raw_certificate(&mismatched_ready, fixture.certificate.statements());
        let path = fixture._temporary.path().join("endpoint-mismatch.cev1");
        write_mode_0600(&path, &bytes);
        let error = load_and_verify_fleet_start_certificate_v1(&path, &fixture.public, 60, 100)
            .unwrap_err();
        assert!(format!("{error:#}").contains("endpoint identity disagreement"));
    }

    #[test]
    fn observer_public_config_substitution_is_rejected() {
        let fixture = fixture();
        let mut substituted = fixture.config_sha256.clone();
        substituted.insert(
            fixture.public.validator_set().validators()[1].id(),
            [0xef; 32],
        );
        let public = PublicReportVerifierContext::from_fleet_barrier_test_parts_v1(
            fixture.public.validator_set().clone(),
            fixture.public.local_validator(),
            &fixture.context,
            substituted,
            fixture.expected_outgoing.clone(),
            fixture.bootstrap_cut,
        );
        assert!(
            load_and_verify_fleet_start_certificate_v1(&fixture.path, &public, 60, 100,).is_err()
        );
    }

    #[test]
    fn same_length_session_preimage_mutation_and_public_mode_are_rejected() {
        let fixture = fixture();
        let original = fixture.certificate.encode();
        let needle = session_id(0, 1, 7);
        let offset = original
            .windows(needle.len())
            .position(|window| window == needle)
            .expect("encoded certificate contains full session preimage");
        let mut mutated = original.clone();
        mutated[offset] ^= 1;
        assert_eq!(mutated.len(), original.len());
        let mutation_path = fixture._temporary.path().join("same-length-mutation.cev1");
        write_mode_0600(&mutation_path, &mutated);
        assert!(load_and_verify_fleet_start_certificate_v1(
            &mutation_path,
            &fixture.public,
            60,
            100,
        )
        .is_err());

        fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_and_verify_fleet_start_certificate_v1(
            &fixture.path,
            &fixture.public,
            60,
            100,
        )
        .is_err());
    }
}
