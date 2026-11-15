//! Compare borrowed canonical wire hashes with the retained encoding methods.
use super::*;
use trnm_crypto_primitives::{public_key_hex, sign_hex, signing_key_from_hex};
use trnm_protocol::{funded_service_task_v1 as funded, qualified_work_task as work};

fn payloads() -> Vec<(u8, Vec<u8>)> {
    let mut out = vec![
        (1, vec![1; 40]),
        (2, vec![2; 80]),
        (3, vec![3; 32]),
        (4, vec![4; 64]),
        (5, vec![5; 64]),
        (6, vec![6; 176]),
        (7, vec![7; 104]),
        (10, vec![10; 112]),
        (11, vec![11; 136]),
        (12, vec![12; 32]),
        (13, vec![13; work::SIGNED_TASK_BYTES]),
        (14, vec![14; 96]),
        (15, vec![15; 168]),
        (17, vec![17; 128]),
        (18, vec![18; work::lifecycle_v2::DEMAND_LEASE_BYTES]),
        (19, vec![19; work::lifecycle_v2::DEMAND_LEASE_BYTES]),
        (20, vec![20; work::lifecycle_v2::DEMAND_REVOCATION_BYTES]),
        (21, vec![21; work::lifecycle_v2::LIFECYCLE_TASK_BYTES]),
        (22, vec![22; work::lifecycle_v3::ATOMIC_RENEW_BYTES]),
    ];
    for count in [1, 16] {
        let mut bytes = vec![0; 145 + count * 40];
        bytes[144] = count as u8;
        for index in 0..count {
            bytes[145 + index * 40] = index as u8;
        }
        out.push((8, bytes));
    }
    for count in [0, 8] {
        let mut bytes = vec![0; 73 + count * 32];
        bytes[72] = count as u8;
        out.push((9, bytes));
    }
    for (first, second) in [(159usize, 159usize), (159, 512), (512, 512)] {
        let mut bytes = vec![0; 36 + first + second];
        bytes[32..34].copy_from_slice(&(first as u16).to_le_bytes());
        bytes[34 + first..36 + first].copy_from_slice(&(second as u16).to_le_bytes());
        out.push((16, bytes));
    }
    for rank in [1, 2] {
        let mut bytes = vec![0; 242 + 520 * rank];
        bytes[..4].copy_from_slice(b"ILF2");
        bytes[4..6].copy_from_slice(&2u16.to_le_bytes());
        bytes[6] = rank as u8;
        bytes[8..10].copy_from_slice(&1024u16.to_le_bytes());
        out.push((23, bytes));
    }
    for ranks in [&[][..], &[1][..], &[1, 2][..], &[1, 1, 1][..]] {
        let mut bytes = vec![0; 242];
        bytes[..4].copy_from_slice(b"ILF3");
        bytes[4..6].copy_from_slice(&3u16.to_le_bytes());
        bytes[6] = 7;
        bytes[7] = ranks.len() as u8;
        bytes[8..10].copy_from_slice(&1024u16.to_le_bytes());
        for (target, &rank) in ranks.iter().enumerate() {
            bytes.extend([target as u8, rank]);
            bytes.resize(bytes.len() + 520 * usize::from(rank), 0);
        }
        out.push((24, bytes));
    }
    out.push((
        2,
        funded::FundedServiceReservationV1 {
            task: [1; 32],
            contract: funded::FundedServiceContractV1 {
                request: [2; 32],
                provider: [3; 32],
                model: [4; 32],
                input: [5; 32],
                output_spec: [6; 32],
                qualified_work: [7; 32],
                evaluation_protocol: [8; 32],
                fee_schedule: [9; 32],
                dispute_policy: [10; 32],
                arbitrator: [11; 32],
                budget: 1,
                delivery_deadline: 2,
                dispute_deadline: 3,
            },
        }
        .encode()
        .unwrap(),
    ));
    out.push((
        5,
        funded::FundedServiceDecisionV1 {
            task: [1; 32],
            contract_digest: [2; 32],
            output: [3; 32],
            evidence: [4; 32],
            verdict: funded::FundedServiceVerdictV1::PayProvider,
        }
        .encode()
        .unwrap(),
    ));
    out
}

fn envelope(tag: u8, payload: Vec<u8>) -> Envelope {
    Envelope {
        network: [17; 32],
        sender: [29; 32],
        nonce: 1,
        expiry: u64::MAX,
        fee_limit: 10_000_000,
        tag,
        payload,
        signature: [37; 64],
    }
}

fn compare(raw: &[u8]) {
    let original = Envelope::decode(raw);
    let actual = DecodedLegacyEnvelope::decode(raw);
    match (original, actual) {
        (Ok(original), Ok(actual)) => {
            assert_eq!(actual.envelope, original);
            assert_eq!(original.encode().unwrap(), raw);
            assert_eq!(original.unsigned().unwrap(), raw[..raw.len() - 64]);
            assert_eq!(actual.signing_digest(), original.signing_digest().unwrap());
            assert_eq!(actual.id(), original.id().unwrap());
        }
        (Err(_), Err(error)) => assert_eq!(error, "ENCODING"),
        _ => panic!("borrowed wire accepted a different grammar"),
    }
}

#[test]
fn canonical_wire_hashes_match_original_all_tags_and_variable_payload_boundaries() {
    let corpus = payloads();
    assert_eq!(
        corpus.iter().map(|(tag, _)| *tag).collect::<BTreeSet<_>>(),
        (1..=24).collect(),
    );
    for (tag, payload) in corpus {
        for (nonce, expiry, fee) in [(1, 0, 0), (u64::MAX, u64::MAX, 10_000_000)] {
            let mut tx = envelope(tag, payload.clone());
            tx.nonce = nonce;
            tx.expiry = expiry;
            tx.fee_limit = fee;
            let raw = tx.encode().unwrap();
            compare(&raw);
            // Complete every changed input before considering its hashes. Both
            // valid and rejected mutations retain the original decoder verdict.
            for position in 0..raw.len() {
                let mut changed = raw.clone();
                changed[position] ^= 0x80;
                compare(&changed);
            }
        }
    }
}

#[test]
fn malformed_wire_never_reaches_borrowed_hashes() {
    for (tag, payload) in payloads() {
        let raw = envelope(tag, payload).encode().unwrap();
        for length in 0..raw.len() {
            compare(&raw[..length]);
            assert!(DecodedLegacyEnvelope::decode(&raw[..length]).is_err());
        }
        let mut extra = raw.clone();
        extra.push(0);
        compare(&extra);
        assert!(DecodedLegacyEnvelope::decode(&extra).is_err());
        for position in [0, 1, 2, 3, 93, 94] {
            let mut changed = raw.clone();
            changed[position] ^= 1;
            compare(&changed);
            assert!(DecodedLegacyEnvelope::decode(&changed).is_err());
        }
        let mut nonce = raw.clone();
        nonce[68..76].fill(0);
        compare(&nonce);
        assert!(DecodedLegacyEnvelope::decode(&nonce).is_err());
        let mut fee = raw;
        fee[84..92].copy_from_slice(&10_000_001u64.to_le_bytes());
        compare(&fee);
        assert!(DecodedLegacyEnvelope::decode(&fee).is_err());
    }
    compare(&vec![0; 2049]);
}

fn signed_transfer(cfg: &Config) -> Vec<u8> {
    let key = signing_key_from_hex(&hex::encode([17; 32])).unwrap();
    let mut tx = envelope(1, vec![1; 40]);
    tx.network = cfg.network;
    tx.sender = hex::decode(public_key_hex(&key))
        .unwrap()
        .try_into()
        .unwrap();
    tx.expiry = 20;
    tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    tx.encode().unwrap()
}

// Exact earlier transfer preparation steps. Profile-independent transfer cases
// let this oracle stay small while using the original serializer and verifier.
fn original_transfer(
    raw: &[u8],
    cfg: &Config,
    signatures: &AtomicUsize,
) -> Result<(Envelope, Hash)> {
    let tx = Envelope::decode(raw).map_err(|_| "ENCODING")?;
    assert_eq!(tx.tag, 1);
    require(tx.network == cfg.network, "NETWORK")?;
    require(10 <= tx.expiry, "EXPIRED")?;
    let sender = hex::encode(tx.sender);
    signatures.fetch_add(1, Ordering::Relaxed);
    verify_hex_strict(
        &sender,
        &tx.signing_digest().map_err(|_| "ENCODING")?,
        &hex::encode(tx.signature),
    )
    .map_err(|_| "SIGNATURE")?;
    let id = tx.id().map_err(|_| "ENCODING")?;
    Ok((tx, id))
}

#[test]
fn actual_preparation_keeps_strict_signatures_error_order_and_attempt_counts() {
    let cfg = Config::installed().unwrap();
    let raw = signed_transfer(&cfg);
    let mut cases = vec![raw.clone()];
    // Every key and signature bit, plus network/nonce/expiry/fee boundary bytes.
    for position in (4..92).chain(raw.len() - 64..raw.len()) {
        for bit in 0..8 {
            let mut changed = raw.clone();
            changed[position] ^= 1 << bit;
            cases.push(changed);
        }
    }
    for position in [4, 76, 84] {
        let mut changed = raw.clone();
        changed[position] = 0;
        changed[raw.len() - 64..].fill(0);
        cases.push(changed);
    }
    let mut identity = [0; 32];
    identity[0] = 1;
    let mut negative_zero = identity;
    negative_zero[31] = 128;
    let mut field_modulus = [255; 32];
    field_modulus[0] = 237;
    field_modulus[31] = 127;
    for point in [[0; 32], identity, negative_zero, field_modulus] {
        let mut key = raw.clone();
        key[36..68].copy_from_slice(&point);
        cases.push(key);
        let mut signature = raw.clone();
        signature[raw.len() - 64..raw.len() - 32].copy_from_slice(&point);
        cases.push(signature);
    }
    for input in cases {
        let before = input.clone();
        let old_signatures = AtomicUsize::new(0);
        let new_signatures = AtomicUsize::new(0);
        let old = original_transfer(&input, &cfg, &old_signatures);
        let new = prepare(&input, 10, None, &cfg, &new_signatures, None);
        assert_eq!(
            old_signatures.load(Ordering::Relaxed),
            new_signatures.load(Ordering::Relaxed),
        );
        match (old, new) {
            (Ok((tx, id)), Ok(prepared)) => {
                assert_eq!(prepared.command.sender, tx.sender);
                assert_eq!(prepared.command.nonce, tx.nonce);
                assert_eq!(prepared.command.fee_limit, tx.fee_limit);
                assert_eq!(prepared.command.tag, tx.tag);
                assert_eq!(prepared.command.payload, tx.payload);
                assert_eq!(prepared.transaction_id, id);
                assert_eq!(prepared.sender, hex::encode(tx.sender));
                assert_eq!(prepared.encoded_len, input.len());
                assert_eq!(prepared.legacy, Some(tx));
                assert!(prepared.native_pq.is_none());
            }
            (Err(old), Err(new)) => assert_eq!(old, new),
            _ => panic!("actual preparation changed the original transfer verdict"),
        }
        assert_eq!(input, before);
    }
    let mut disabled = envelope(13, vec![0; work::SIGNED_TASK_BYTES]);
    disabled.network = [0; 32];
    disabled.expiry = 0;
    let signatures = AtomicUsize::new(0);
    assert_eq!(
        prepare(
            &disabled.encode().unwrap(),
            10,
            None,
            &cfg,
            &signatures,
            None
        )
        .err()
        .unwrap(),
        "WORK_TASK_PROFILE",
    );
    assert_eq!(signatures.load(Ordering::Relaxed), 0);
}

#[test]
#[ignore = "explicit paired mathematical-preparation cost; not whole-request or confirmation throughput"]
fn borrowed_legacy_hash_pair_cost_observation() {
    assert!(
        std::hint::black_box(!cfg!(debug_assertions)),
        "release comparison required"
    );
    let cfg = Config::installed().unwrap();
    let raw = signed_transfer(&cfg);
    let parsed = DecodedLegacyEnvelope::decode(&raw).unwrap();
    let expected = (
        parsed.envelope.signing_digest().unwrap(),
        parsed.envelope.id().unwrap(),
    );
    for pair in 0..12 {
        for arm in if pair % 2 == 0 { [0, 1] } else { [1, 0] } {
            let start = std::time::Instant::now();
            for _ in 0..20_000 {
                let input = std::hint::black_box(&parsed);
                let result = if arm == 0 {
                    (
                        input.envelope.signing_digest().unwrap(),
                        input.envelope.id().unwrap(),
                    )
                } else {
                    (input.signing_digest(), input.id())
                };
                assert_eq!(std::hint::black_box(result), expected);
            }
            println!(
                "{}",
                json!({
                    "schema":"pon-legacy-hash-pair-observation-v1",
                    "pair":pair,"arm":if arm == 0 {"original"} else {"borrowed"},
                    "iterations":20_000,"packet_bytes":raw.len(),
                    "wall_ns":start.elapsed().as_nanos(),
                    "scope":"two mathematical hashes after unchanged complete decode; includes digest equality assertion; excludes signature crypto, state, Host and confirmation",
                    "end_to_end_throughput_qualified":false
                })
            );
        }
    }
}
