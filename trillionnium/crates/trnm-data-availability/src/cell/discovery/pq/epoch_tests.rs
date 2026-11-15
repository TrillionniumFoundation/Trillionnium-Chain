use super::*;
use crate::cell::pq::CellPqKeyPinV2;
use std::time::{Duration, Instant};
use trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki;
use zeroize::Zeroizing;

fn time(now: u64) -> CellDiscoveryTimeV3 {
    CellDiscoveryTimeV3::for_test(Duration::from_secs(now), Instant::now())
}
fn request() -> CellDiscoveryRequestV3 {
    CellDiscoveryRequestV3 {
        base: CellDiscoveryRequestV1 {
            context: CellDiscoveryContextV1 {
                namespace: [11; 32],
                network: [12; 32],
                parameters: [13; 32],
                genesis: [14; 32],
            },
            cell_context: [15; 32],
            manifest: [16; 32],
        },
        epoch: 2,
    }
}
fn key_and_pin() -> (PqNativeSigningKey, CellPqKeyPinV2) {
    let seed = Zeroizing::new([61; 32]);
    let spki = PqNativeSigningKey::public_spki_from_seed(&seed);
    let key_id = ml_dsa_65_key_id_from_spki(&spki).unwrap();
    (
        PqNativeSigningKey::from_owned_seed(seed, key_id).unwrap(),
        CellPqKeyPinV2 {
            key_id,
            generation: 7,
            spki,
            not_before: 1,
            expires_at: u64::MAX,
            revoked_at: None,
        },
    )
}
fn policy() -> CellDiscoveryAddressPolicyV1 {
    CellDiscoveryAddressPolicyV1::LoopbackDevOnly { ports: vec![19003] }
}
fn record() -> CellProviderRecordV3 {
    let (key, pin) = key_and_pin();
    CellProviderRecordV3::sign(
        CellProviderStatementV3 {
            request: request(),
            owner: pin.key_id,
            owner_generation: pin.generation,
            endpoint: "127.0.0.1:19003".parse().unwrap(),
            sequence: 19,
            issued_unix_seconds: 700,
            expires_unix_seconds: 880,
            withdrawn: false,
        },
        &key,
    )
    .unwrap()
}

#[test]
fn v3_epoch_request_has_exact_canonical_bytes_and_closed_epoch_rules() {
    let value = request();
    assert_eq!(value.encode().len(), CELL_DISCOVERY_REQUEST_BYTES_V3);
    assert_eq!(&value.encode()[192..], &2u64.to_be_bytes());
    assert_eq!(
        CellDiscoveryRequestV3::decode(&value.encode()).unwrap(),
        value
    );
    assert_eq!(value.epoch_bounds().unwrap(), (600, 900));
    assert!(value.validate_at(599).is_err());
    assert!(value.validate_at(600).is_ok());
    assert!(value.validate_at(899).is_ok());
    assert!(value.validate_at(900).is_err());
    for length in [0, 192, 199, 201] {
        let mut wire = value.encode().to_vec();
        wire.resize(length, 0);
        assert!(CellDiscoveryRequestV3::decode(&wire).is_err());
    }
    let mut overflow = value;
    overflow.epoch = u64::MAX / CELL_DISCOVERY_EPOCH_SECONDS_V3;
    assert!(overflow.epoch_bounds().is_err());
    assert!(CellDiscoveryRequestV3::decode(&overflow.encode()).is_err());
}

#[test]
fn v3_actual_mldsa_binds_every_statement_byte_epoch_and_signature() {
    let record = record();
    let keys = CellPqKeyPinsV2::new(vec![key_and_pin().1]).unwrap();
    let wire = record.encode();
    assert_eq!(wire.len(), 3600);
    let verified = record
        .verify_at(request(), time(700), &policy(), &keys)
        .unwrap();
    assert_eq!(verified.valid_until(), 880);
    assert_eq!(verified.verified_at(), 700);
    assert_eq!(verified.record(), &record);
    for index in 0..291 {
        let mut changed = wire.clone();
        changed[index] ^= 1;
        assert!(
            CellProviderRecordV3::decode(&changed)
                .and_then(|candidate| candidate.verify_at(request(), time(700), &policy(), &keys))
                .is_err(),
            "accepted changed statement byte {index}"
        );
    }
    for index in [291, 900, 3599] {
        let mut changed = wire.clone();
        changed[index] ^= 1;
        assert!(CellProviderRecordV3::decode(&changed)
            .unwrap()
            .verify_at(request(), time(700), &policy(), &keys)
            .is_err());
    }
    for length in [0, 335, 3592, 3599, 3601] {
        let mut changed = wire.clone();
        changed.resize(length, 0);
        assert!(CellProviderRecordV3::decode(&changed).is_err());
    }
    assert!(record
        .verify_at(request(), time(694), &policy(), &keys)
        .is_err());
    assert!(record
        .verify_at(request(), time(695), &policy(), &keys)
        .is_ok());
    assert!(record
        .verify_at(request(), time(880), &policy(), &keys)
        .is_err());
    assert!(record
        .verify_at(request(), time(900), &policy(), &keys)
        .is_err());
}

#[test]
fn v3_epoch_lifetime_cannot_cross_either_signed_boundary() {
    let original = record();
    let key = key_and_pin().0;
    for (issued, expires) in [(599, 700), (700, 901), (700, 700), (700, 699)] {
        let mut statement = original.statement().clone();
        statement.issued_unix_seconds = issued;
        statement.expires_unix_seconds = expires;
        assert!(CellProviderRecordV3::sign(statement, &key).is_err());
    }
    let mut statement = original.statement().clone();
    statement.issued_unix_seconds = 600;
    statement.expires_unix_seconds = 900;
    let complete_epoch = CellProviderRecordV3::sign(statement, &key).unwrap();
    let keys = CellPqKeyPinsV2::new(vec![key_and_pin().1]).unwrap();
    assert!(complete_epoch
        .verify_at(request(), time(600), &policy(), &keys)
        .is_ok());
    assert!(complete_epoch
        .verify_at(request(), time(899), &policy(), &keys)
        .is_ok());
    assert!(complete_epoch
        .verify_at(request(), time(900), &policy(), &keys)
        .is_err());
}

#[test]
fn v3_and_v2_domains_cannot_be_relabelled_or_transplanted() {
    let record = record();
    let keys = CellPqKeyPinsV2::new(vec![key_and_pin().1]).unwrap();
    let v3_wire = record.encode();
    assert!(CellProviderRecordV2::decode(&v3_wire).is_err());
    assert!(super::super::super::CellProviderRecordV1::decode(&v3_wire).is_err());
    let mut v2_wire = v3_wire;
    v2_wire[3] = b'2';
    v2_wire[4] = 2;
    v2_wire.drain(200..208);
    let transplanted = CellProviderRecordV2::decode(&v2_wire).unwrap();
    assert!(transplanted
        .verify_at(request().base, 700, &policy(), &keys)
        .is_err());
    let statement = record.statement();
    let old = CellProviderRecordV2::sign(
        CellProviderStatementV2 {
            request: statement.request.base,
            owner: statement.owner,
            owner_generation: statement.owner_generation,
            endpoint: statement.endpoint,
            sequence: statement.sequence,
            issued_unix_seconds: statement.issued_unix_seconds,
            expires_unix_seconds: statement.expires_unix_seconds,
            withdrawn: statement.withdrawn,
        },
        &key_and_pin().0,
    )
    .unwrap();
    assert!(CellProviderRecordV3::decode(&old.encode()).is_err());
    let mut lifted = old.encode();
    lifted[3] = b'3';
    lifted[4] = 3;
    lifted.splice(200..200, 2u64.to_be_bytes());
    assert!(CellProviderRecordV3::decode(&lifted)
        .unwrap()
        .verify_at(request(), time(700), &policy(), &keys)
        .is_err());
}

#[test]
fn v3_verification_receipt_seals_roster_clock_authority_and_monotonic_lease() {
    let record = record();
    let mut pin = key_and_pin().1;
    pin.revoked_at = Some(730);
    let keys = CellPqKeyPinsV2::new(vec![pin.clone()]).unwrap();
    let mut verified = record
        .verify_at(request(), time(700), &policy(), &keys)
        .unwrap();
    assert_eq!(verified.valid_until(), 730);
    assert!(verified.check_at(700, keys.digest()).is_ok());
    assert!(verified.check_at(699, keys.digest()).is_err());
    assert!(verified.check_at(730, keys.digest()).is_err());
    pin.revoked_at = Some(731);
    let other = CellPqKeyPinsV2::new(vec![pin]).unwrap();
    assert!(verified.check_at(700, other.digest()).is_err());
    assert_eq!(
        verified.monotonic_expiry(),
        verified.clone().monotonic_expiry()
    );
    verified.monotonic_expiry = Instant::now() - Duration::from_millis(1);
    assert!(verified.check_at(700, keys.digest()).is_err());
    assert!(record
        .verify_at(request(), time(730), &policy(), &keys)
        .is_err());
}

#[test]
fn v3_precise_clock_sample_never_renews_fractional_or_delayed_verification_lease() {
    let mut statement = record().statement().clone();
    statement.expires_unix_seconds = 701;
    let record = CellProviderRecordV3::sign(statement, &key_and_pin().0).unwrap();
    let keys = CellPqKeyPinsV2::new(vec![key_and_pin().1]).unwrap();
    let at = Instant::now();
    let clock = CellDiscoveryTimeV3::for_test(Duration::from_millis(700_900), at);
    let receipt = record
        .verify_at(request(), clock, &policy(), &keys)
        .unwrap();
    assert_eq!(receipt.monotonic_expiry(), at + Duration::from_millis(100));
    let old = CellDiscoveryTimeV3::for_test(
        Duration::from_millis(700_900),
        Instant::now() - Duration::from_millis(200),
    );
    let historical = record.verify_at(request(), old, &policy(), &keys).unwrap();
    assert_eq!(
        historical.monotonic_expiry(),
        old.monotonic() + Duration::from_millis(100)
    );
    assert!(historical.check_at(700, keys.digest()).is_err());
}

#[test]
fn v3_rust_unsigned_encoding_matches_independent_python_vector() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../formal/pon-nakamoto-v1/vectors/cell-discovery-epoch-v3.json"
    )))
    .unwrap();
    let expected = &vector["provider"];
    let unsigned = hex::decode(expected["unsigned_record"]["hex"].as_str().unwrap()).unwrap();
    let mut wire = unsigned.clone();
    wire.extend([0; ML_DSA_65_SIGNATURE_BYTES]);
    let record = CellProviderRecordV3::decode(&wire).unwrap();
    assert_eq!(
        record.statement(),
        &CellProviderStatementV3 {
            request: CellDiscoveryRequestV3 {
                base: CellDiscoveryRequestV1 {
                    context: CellDiscoveryContextV1 {
                        namespace: [1; 32],
                        network: [2; 32],
                        parameters: [3; 32],
                        genesis: [4; 32],
                    },
                    cell_context: [5; 32],
                    manifest: [6; 32],
                },
                epoch: 6_000_000,
            },
            owner: [7; 32],
            owner_generation: 9,
            endpoint: "192.0.2.20:4060".parse().unwrap(),
            sequence: 42,
            issued_unix_seconds: 1_800_000_001,
            expires_unix_seconds: 1_800_000_120,
            withdrawn: false,
        }
    );
    assert_eq!(record.unsigned(), unsigned);
    assert_eq!(
        hex::encode(record.statement().request.encode()),
        expected["request"]["hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(record.message()),
        expected["signature_message"]["hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(record.digest()),
        expected["statement_digest_sha256"].as_str().unwrap()
    );
    assert_eq!(
        wire.len(),
        expected["record_wire_bytes_with_ml_dsa_65_signature"]
            .as_u64()
            .unwrap() as usize
    );
    // Zero signature bytes are only an encoding fixture. This test performs
    // no signature acceptance; the other controls use actual ML-DSA keys.
}
