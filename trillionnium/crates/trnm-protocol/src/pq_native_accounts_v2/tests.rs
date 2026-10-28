use super::*;
use crate::pq_frame::ML_DSA_65_SIGNATURE_BYTES;

const SPKI: &[u8] = include_bytes!("../../tests/fixtures/pq_transfer/public.der");

fn case(kind: u8) -> (Common, Vec<u8>, Vec<WitnessKey>) {
    let old_id = ml_dsa_65_key_id_from_spki(SPKI).unwrap();
    let mut new_spki = SPKI.to_vec();
    new_spki[100] ^= 1; // Syntax-only public material; no valid private key is claimed.
    let new_id = ml_dsa_65_key_id_from_spki(&new_spki).unwrap();
    let common = Common {
        context: ChainContext {
            network: [1; 32],
            parameters: [2; 32],
            genesis: [3; 32],
        },
        account: old_id,
        nonce: 7,
        expires_at: 1000,
        max_fee: 100_000,
        generation: if matches!(kind, REGISTER | CLAIM) {
            0
        } else {
            1
        },
    };
    let payload = match kind {
        1 => [
            [9; 32].as_slice(),
            &5_u64.to_le_bytes(),
            &0_u16.to_be_bytes(),
        ]
        .concat(),
        2 => vec![9; 80],
        3 => vec![9; 32],
        4 | 5 => vec![9; 64],
        REGISTER => 1_u64.to_be_bytes().to_vec(),
        ROTATE => [2_u64.to_be_bytes().as_slice(), &[9; 48]].concat(),
        CLAIM => [
            [9; 48].as_slice(),
            &[8; 32],
            &[7; 32],
            &old_id,
            &50_u64.to_be_bytes(),
            &6_u64.to_be_bytes(),
            &[6; 48],
            &1_u64.to_be_bytes(),
        ]
        .concat(),
        _ => unreachable!(),
    };
    let keys = roles(AccountProfile::AccountsV2, kind)
        .unwrap()
        .iter()
        .map(|&(role, carried)| {
            let new = matches!(role, 4 | 6);
            WitnessKey {
                role,
                generation: if role == 4 { 2 } else { 1 },
                key_id: if new { new_id } else { old_id },
                spki: carried.then(|| if new { new_spki.clone() } else { SPKI.to_vec() }),
            }
        })
        .collect();
    (common, payload, keys)
}

fn frames(common: &Common, kind: u8, payload: &[u8], keys: &[WitnessKey]) -> Vec<Vec<u8>> {
    (0..keys.len())
        .map(|index| {
            let mut frame = signing_statement(common, kind, payload, keys, index)
                .unwrap()
                .to_vec();
            frame.extend((ML_DSA_65_SIGNATURE_BYTES as u16).to_be_bytes());
            frame.extend(vec![0x73; ML_DSA_65_SIGNATURE_BYTES]); // Deliberately unverified.
            frame
        })
        .collect()
}

#[test]
fn exact_fresh_frame_sizes_include_every_key_and_both_proofs() {
    for (kind, expected) in [
        (1, 3751),
        (2, 3789),
        (3, 3741),
        (4, 3773),
        (5, 3773),
        (REGISTER, 5691),
        (ROTATE, 9272),
        (CLAIM, 9432),
    ] {
        let (common, payload, keys) = case(kind);
        let raw = encode(
            &common,
            kind,
            &payload,
            &keys,
            &frames(&common, kind, &payload, &keys),
        )
        .unwrap();
        assert_eq!(raw.len(), expected);
        let parsed = UnverifiedEnvelope::decode(&raw).unwrap();
        assert_eq!(parsed.common, common);
        assert_eq!(parsed.payload, payload);
        assert_eq!(parsed.witnesses().len(), keys.len());
        assert!(crate::pon_wire::Envelope::decode(&raw).is_err());
        assert!(crate::pq_native_transfer_v1::UnverifiedEnvelope::decode(&raw).is_err());
    }
    let (common, mut payload, keys) = case(1);
    payload[40..42].copy_from_slice(&512_u16.to_be_bytes());
    payload.extend([7; 512]);
    let raw = encode(
        &common,
        1,
        &payload,
        &keys,
        &frames(&common, 1, &payload, &keys),
    )
    .unwrap();
    assert_eq!(raw.len(), 4263);
    assert_eq!(MAX_TRANSACTION_BYTES / raw.len(), 122);
    assert_eq!(MAX_TRANSACTION_BYTES / 9272, 56);
    assert_eq!(MAX_TRANSACTION_BYTES / MAX_BYTES, 55);
}

#[test]
fn joint_core_binds_context_generation_every_descriptor_and_full_new_key() {
    let (common, payload, keys) = case(ROTATE);
    let raw = encode(
        &common,
        ROTATE,
        &payload,
        &keys,
        &frames(&common, ROTATE, &payload, &keys),
    )
    .unwrap();
    let witness_start = PREFIX_BYTES + COMMON_BYTES + payload.len();
    for at in [
        16,
        48,
        80,
        112,
        144,
        152,
        160,
        168,
        176,
        184,
        witness_start,
        witness_start + 4,
        witness_start + 12,
        witness_start + RESOLVED_WITNESS_BYTES + 12,
        witness_start + RESOLVED_WITNESS_BYTES + WITNESS_DESCRIPTOR_BYTES + 100,
    ] {
        let mut mutated = raw.clone();
        mutated[at] ^= 1;
        assert!(UnverifiedEnvelope::decode(&mutated).is_err(), "field {at}");
    }
    let mut swapped = raw[..witness_start].to_vec();
    swapped.extend(&raw[witness_start + RESOLVED_WITNESS_BYTES..]);
    swapped.extend(&raw[witness_start..witness_start + RESOLVED_WITNESS_BYTES]);
    assert!(UnverifiedEnvelope::decode(&swapped).is_err());
    let mut fake_signature = raw.clone();
    *fake_signature.last_mut().unwrap() ^= 1;
    let a = UnverifiedEnvelope::decode(&raw).unwrap();
    let b = UnverifiedEnvelope::decode(&fake_signature).unwrap();
    assert_eq!(a.statement_id(), b.statement_id());
    assert_ne!(a.wire_id(), b.wire_id());
    // Both remain unverified. M01 must reject these fabricated signature bytes.
    assert_ne!(
        owner_context(&common, ROTATE, 3),
        owner_context(&common, ROTATE, 4)
    );
}

#[test]
fn closed_roles_lengths_reserved_bytes_and_old_namespaces_refuse() {
    let (common, payload, keys) = case(3);
    let raw = encode(
        &common,
        3,
        &payload,
        &keys,
        &frames(&common, 3, &payload, &keys),
    )
    .unwrap();
    for at in [0, 4, 5, 6, 7, 8, 12, 15] {
        let mut mutated = raw.clone();
        mutated[at] ^= 1;
        assert!(UnverifiedEnvelope::decode(&mutated).is_err());
    }
    for length in [0, MIN_BYTES - 1, MAX_BYTES + 1, raw.len() + 1] {
        let mut mutated = raw.clone();
        mutated.resize(length, 0);
        assert!(UnverifiedEnvelope::decode(&mutated).is_err());
    }
    let mut hinted = keys.clone();
    hinted[0].spki = Some(SPKI.to_vec());
    assert!(signing_core(&common, 3, &payload, &hinted).is_err());
    let (common, payload, mut keys) = case(REGISTER);
    keys[0].spki = None;
    assert!(signing_core(&common, REGISTER, &payload, &keys).is_err());
    let old = crate::pq_native_transfer_v1::encode(
        include_bytes!("../../tests/fixtures/pq_transfer/transfer.bin"),
        SPKI,
    )
    .unwrap();
    assert!(UnverifiedEnvelope::decode(&old).is_err());
}

#[test]
fn new_roles_require_exact_branch_generation_and_anchored_source_identity() {
    let (mut common, payload, keys) = case(REGISTER);
    common.generation = 1;
    assert!(signing_core(&common, REGISTER, &payload, &keys).is_err());
    let (mut common, payload, keys) = case(ROTATE);
    common.generation = u64::MAX;
    assert!(signing_core(&common, ROTATE, &payload, &keys).is_err());
    let (common, mut payload, keys) = case(CLAIM);
    payload[112] ^= 1;
    assert!(signing_core(&common, CLAIM, &payload, &keys).is_err());
    let (common, payload, mut keys) = case(CLAIM);
    keys[0].role = 1;
    assert!(signing_core(&common, CLAIM, &payload, &keys).is_err());
}

#[test]
fn quota_successor_has_fresh_exact_roles_and_full_dual_proof_bytes() {
    let (common, _, mut keys) = case(3);
    let payload = vec![9; 112];
    assert!(signing_core(&common, 10, &payload, &keys).is_err());
    let profile = AccountProfile::QuotaV3;
    for (kind, payload, expected) in [(10, payload, 3821), (11, vec![9; 72], 7314)] {
        if kind == 11 {
            let mut consumer = keys[0].clone();
            consumer.role = 2;
            consumer.generation = 7;
            keys.push(consumer);
        }
        let frames: Vec<_> = (0..keys.len())
            .map(|i| {
                let mut frame =
                    signing_statement_for_profile(profile, &common, kind, &payload, &keys, i)
                        .unwrap()
                        .to_vec();
                frame.extend((ML_DSA_65_SIGNATURE_BYTES as u16).to_be_bytes());
                frame.extend([0x73; ML_DSA_65_SIGNATURE_BYTES]);
                frame
            })
            .collect();
        let raw = encode_for_profile(profile, &common, kind, &payload, &keys, &frames).unwrap();
        assert_eq!(raw.len(), expected);
        assert_eq!(&raw[..5], b"NPQ3\x03");
        assert!(UnverifiedEnvelope::decode(&raw).is_err());
        let parsed = UnverifiedEnvelope::decode_for_profile(&raw, profile).unwrap();
        assert_eq!(parsed.common, common);
        assert_eq!(parsed.witnesses().len(), keys.len());
        if kind == 11 {
            assert_eq!(parsed.witnesses()[1].generation, 7);
            assert_eq!(MAX_TRANSACTION_BYTES / raw.len(), 71);
            let mut old = raw.clone();
            old[..5].copy_from_slice(b"NPQ2\x02");
            assert!(UnverifiedEnvelope::decode(&old).is_err());
            let mut hinted = keys.clone();
            hinted[1].spki = Some(SPKI.to_vec());
            assert!(signing_core_for_profile(profile, &common, kind, &payload, &hinted).is_err());
        }
    }
}
