//! M13's independently pinned consumer of M01 historical header verification.
//! Covered-header links describe ancestry authenticated by the terminal proof;
//! they do not claim a separately retained finality proof for each ancestor.
use super::*;
use trnm_consensus_crypto::verify_historical_header_ancestry_v1;
use trnm_consensus_types::BlockKind;

fn framed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn transcript_digest(
    anchor_pin: Digest32V0,
    headers: &[&[u8]],
    activations: &[EpochActivationEvidencePreimagesV0<'_>],
    terminal_proof: &[u8],
) -> Digest32V0 {
    let mut hasher = Sha256::new();
    framed(
        &mut hasher,
        b"trnm.state-sync.native-historical-transcript.v1",
    );
    framed(&mut hasher, &anchor_pin.0);
    hasher.update((headers.len() as u64).to_be_bytes());
    for header in headers {
        framed(&mut hasher, header);
    }
    hasher.update((activations.len() as u64).to_be_bytes());
    for activation in activations {
        hasher.update(8u64.to_be_bytes());
        for root in evidence_parts(*activation) {
            framed(&mut hasher, root);
        }
    }
    framed(&mut hasher, terminal_proof);
    Digest32V0(hasher.finalize().into())
}

/// Verify complete historical header ancestry from an independently pinned
/// native anchor. No individual ancestor finality proofs are required.
///
/// The shared strict verifier meters every transition and the terminal proof
/// against the caller's remaining budget. Only its successful sealed result
/// permits this module to construct the private snapshot projection. All raw
/// header, activation and proof bytes enter a separately framed transcript.
/// Seals remain consensus ancestors but create no application checkpoint link.
///
/// This result authenticates the target header/configuration, not application
/// bodies, replay identities, installed state, Core readiness or signing.
#[inline(never)]
pub fn verify_native_historical_trust_path_v1(
    anchor: &NativeTrustAnchorV1,
    headers: &[&[u8]],
    activations: &[EpochActivationEvidencePreimagesV0<'_>],
    terminal_proof: &[u8],
    limits: HistoricalAncestryLimitsV1,
    budget: &mut Cev0AdmissionBudgetV0,
) -> Result<VerifiedNativeTrustPathV1, NativeTrustErrorV1> {
    let verified = verify_historical_header_ancestry_v1(
        anchor.header(),
        anchor.validator_set(),
        anchor.parameters(),
        headers,
        activations,
        terminal_proof,
        limits,
        budget,
    )
    .map_err(NativeTrustErrorV1::Historical)?;
    if verified.headers().len() != headers.len() {
        return Err(NativeTrustErrorV1::DisconnectedStep);
    }
    let transcript = transcript_digest(anchor.pin(), headers, activations, terminal_proof);
    let chain = Digest32V0::hash(
        b"trnm.state-sync.native-chain.v1",
        &[
            anchor.header.genesis_hash().as_bytes(),
            anchor.header.chain_id().as_bytes(),
        ],
    );
    let protocol = Digest32V0::hash(
        b"trnm.state-sync.native-protocol.v1",
        &[&anchor.header.protocol_version().get().to_be_bytes()],
    );
    let projected_anchor = WeakSubjectivityAnchorV0 {
        chain_id: chain,
        protocol_digest: protocol,
        epoch: anchor.header.epoch().get(),
        height: anchor.header.height().get(),
        checkpoint_digest: anchor.pin(),
        validator_set_digest: Digest32V0(*anchor.set.id().as_bytes()),
    };
    let application_count = verified
        .headers()
        .iter()
        .filter(|header| {
            !matches!(
                header.block_kind(),
                BlockKind::EpochSeal1 | BlockKind::EpochSeal2
            )
        })
        .count();
    let mut path_hasher = Sha256::new();
    framed(
        &mut path_hasher,
        b"trnm.state-sync.native-historical-trust-path.v1",
    );
    framed(&mut path_hasher, &anchor.pin().0);
    framed(&mut path_hasher, &transcript.0);
    path_hasher.update((application_count as u64).to_be_bytes());
    let mut previous = anchor.header();
    let mut set_id = anchor.validator_set().id();
    let mut previous_digest = anchor.pin();
    let mut activation_index = 0usize;
    let mut application_index = 0u32;
    let mut terminal = None;
    for (index, header) in verified.headers().iter().enumerate() {
        if matches!(
            header.block_kind(),
            BlockKind::EpochSeal1 | BlockKind::EpochSeal2
        ) {
            continue;
        }
        let old_set_id = set_id;
        if header.block_kind() == BlockKind::EpochHandoff {
            let activation = verified
                .activations()
                .get(activation_index)
                .ok_or(NativeTrustErrorV1::DisconnectedStep)?;
            if activation
                .old_checkpoint_finality()
                .finalized_block()
                .header()
                != previous
                || activation.old_validator_set().id() != set_id
                || previous.height().get().checked_add(3) != Some(header.height().get())
                || previous.epoch().get().checked_add(1) != Some(header.epoch().get())
            {
                return Err(NativeTrustErrorV1::DisconnectedStep);
            }
            set_id = activation.new_validator_set().id();
            activation_index += 1;
        } else if !matches!(
            header.block_kind(),
            BlockKind::Regular | BlockKind::EpochCheckpoint
        ) || previous.height().get().checked_add(1) != Some(header.height().get())
            || header.parent_id() != previous.id()
            || header.epoch() != previous.epoch()
        {
            return Err(NativeTrustErrorV1::DisconnectedStep);
        }
        if header.validator_set_id() != set_id {
            return Err(NativeTrustErrorV1::DisconnectedStep);
        }
        let coverage_digest = Digest32V0::hash(
            b"trnm.state-sync.native-historical-covered-header.v1",
            &[
                &transcript.0,
                &(index as u64).to_be_bytes(),
                &application_index.to_be_bytes(),
                headers[index],
            ],
        );
        let mut link = CheckpointLinkV0 {
            chain_id: chain,
            protocol_digest: protocol,
            epoch: header.epoch().get(),
            height: header.height().get(),
            state_root: Digest32V0(*header.state_root().as_bytes()),
            validator_set_digest: Digest32V0(*old_set_id.as_bytes()),
            next_validator_set_digest: Digest32V0(*set_id.as_bytes()),
            parent_checkpoint_digest: previous_digest,
            finality_proof_digest: coverage_digest,
            checkpoint_digest: Digest32V0([0; 32]),
        };
        link.checkpoint_digest = link.canonical_digest();
        framed(&mut path_hasher, &link.checkpoint_digest.0);
        previous_digest = link.checkpoint_digest;
        previous = header;
        application_index += 1;
        terminal = Some(link);
    }
    if activation_index != verified.activations().len()
        || previous != verified.terminal_header()
        || set_id != verified.terminal_validator_set().id()
    {
        return Err(NativeTrustErrorV1::DisconnectedStep);
    }
    Ok(VerifiedNativeTrustPathV1 {
        header: verified.terminal_header().clone(),
        set: verified.terminal_validator_set().clone(),
        parameters: *verified.terminal_parameters(),
        projection: VerifiedTrustPathV0 {
            anchor: projected_anchor,
            terminal: terminal.ok_or(NativeTrustErrorV1::Bounds)?,
            link_count: application_index,
            path_digest: Digest32V0(path_hasher.finalize().into()),
        },
    })
}
