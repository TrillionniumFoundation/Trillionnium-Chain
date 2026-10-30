//! M09 receive-side verification boundary for the compact PCP2 research wire.
//! Does NOT select a network protocol, persist replay floors, change CDP1
//! directory/transport, or authorize Cell bytes, custody, release or FinalUse.
//! Every expected input must come from an independent owner, not from the wire.
use super::{
    cell_discovery_context_digest, check_deadline, decode_endpoint, wall_now,
    CellDiscoveryAddressPolicyV1, CellDiscoveryRequestV1, MAX_DISCOVERED_PROVIDERS,
    MAX_DISCOVERY_RESPONSE_BYTES,
};
use crate::cell::{
    network::{self, RequestContext, ResponseBudget},
    CellErrorV1, CellFetchReportV1, CellManifestV1, CellPeerLimitsV1, CellResultV1, CellStoreV1,
};
use std::{
    net::SocketAddr,
    path::Path,
    sync::atomic::AtomicU64,
    time::{Duration, Instant},
};
use trnm_crypto_primitives::pq_cell_provider::{
    PqCellProviderExpectationV2, SignedPqCellProviderRecordV2, PQ_CELL_PROVIDER_RECORD_V2_BYTES,
};

/// An eight-provider PCP2 reply fits the original 32-KiB envelope.
/// This is arithmetic only: the actual transport still speaks classical CDP1.
const PCP2_MAX_REPLY_BYTES: usize = 1 + MAX_DISCOVERED_PROVIDERS * PQ_CELL_PROVIDER_RECORD_V2_BYTES;
const _: () = assert!(PCP2_MAX_REPLY_BYTES <= MAX_DISCOVERY_RESPONSE_BYTES as usize);

/// Never construct expectations by copying request/key/replay from a peer hint.
pub struct PqCellProviderExpectationM09V2<'a> {
    pub request: CellDiscoveryRequestV1,
    pub trusted_ml_dsa65_public_key: &'a [u8],
    /// Externally maintained monotonic floor; rolled-back SQLite is unsafe.
    pub last_accepted_sequence: u64,
    pub now_unix_seconds: u64,
    pub addresses: &'a CellDiscoveryAddressPolicyV1,
}

/// Inert, verified routing hint, not release or FinalUse authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedPqCellProviderHintM09V2 {
    endpoint: SocketAddr,
    sequence: u64,
    expires_unix_seconds: u64,
}

impl VerifiedPqCellProviderHintM09V2 {
    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn expires_unix_seconds(&self) -> u64 {
        self.expires_unix_seconds
    }
}

/// Verify canonical PCP2 with independent owner pins and the M09 IP policy.
/// CDP1, competing CDP2, forged keys and malformed records never fall back.
pub fn verify_pcp2_provider_hint_v2(
    wire: &[u8],
    expectation: &PqCellProviderExpectationM09V2<'_>,
) -> CellResultV1<VerifiedPqCellProviderHintM09V2> {
    expectation.request.validate()?;
    expectation.addresses.validate()?;
    let pinned_request: [u8; 192] = expectation
        .request
        .encode()
        .try_into()
        .map_err(|_| CellErrorV1::Invalid("PQ Cell owner request length"))?;
    let record = SignedPqCellProviderRecordV2::from_wire(wire)
        .map_err(|_| CellErrorV1::Invalid("PQ Cell provider wire"))?;
    let verified = record
        .verify_for_pinned_context(&PqCellProviderExpectationV2 {
            pinned_request: &pinned_request,
            trusted_ml_dsa65_public_key: expectation.trusted_ml_dsa65_public_key,
            last_accepted_sequence: expectation.last_accepted_sequence,
            now_unix_seconds: expectation.now_unix_seconds,
        })
        .map_err(|_| CellErrorV1::Invalid("PQ Cell provider authority/signature"))?;
    let endpoint = decode_endpoint(*verified.endpoint_bytes())?;
    expectation.addresses.check(endpoint)?;
    Ok(VerifiedPqCellProviderHintM09V2 {
        endpoint,
        sequence: verified.sequence(),
        expires_unix_seconds: verified.expires_unix_seconds(),
    })
}

/// Explicit owner-selected PCP2 -> real content-addressed Cell byte fetch.
///
/// This does NOT discover providers on the network or grant authority by itself:
/// the owner supplies the raw signed hint plus independent pinned key, request,
/// external replay floor and time. The existing CDP1 rendezvous remains isolated.
/// Auth, manifest, all chunks and final create-only payload are checked within
/// the SAME ordinary connection/response/absolute-time budget.
pub fn fetch_pcp2_authenticated_cell_to_file(
    store: &CellStoreV1,
    signed_hint_wire: &[u8],
    expectation: &PqCellProviderExpectationM09V2<'_>,
    limits: CellPeerLimitsV1,
    original_deadline: Instant,
    output: &Path,
) -> CellResultV1<(CellManifestV1, CellFetchReportV1)> {
    limits.validate()?;
    // Do not allow the caller to replay a previously trusted timestamp when
    // the local wall clock has passed the signed hint's expiration.
    let wall = wall_now()?.as_secs();
    if wall.abs_diff(expectation.now_unix_seconds) > 5 {
        return Err(CellErrorV1::Invalid("PQ provider trusted time stale"));
    }
    let hint = verify_pcp2_provider_hint_v2(signed_hint_wire, expectation)?;
    let lifetime = hint
        .expires_unix_seconds()
        .checked_sub(wall)
        .filter(|seconds| *seconds > 0)
        .ok_or(CellErrorV1::Invalid("PQ provider lease expired"))?;
    let started = Instant::now();
    let overall = original_deadline
        .min(started + limits.overall_timeout)
        .min(started + Duration::from_secs(lifetime));
    check_deadline(overall)?;
    let requests_left = AtomicU64::new(limits.max_connections);
    let responses = ResponseBudget::new(limits.max_response_bytes);
    let transport = RequestContext {
        timeout: limits.request_timeout,
        overall,
        requests_left: &requests_left,
        responses: &responses,
        peer_failures: Default::default(),
    };
    let peers = [hint.endpoint()];
    let (manifest, initial_rejected, _) = network::fetch_manifest_observed(
        store,
        expectation.request.manifest,
        &peers,
        limits,
        &transport,
    )?;
    // The ordinary immutable manifest is checked BEFORE publication. A peer
    // must not exchange one valid manifest ID for a different Cell context.
    if cell_discovery_context_digest(manifest.context())? != expectation.request.cell_context {
        return Err(CellErrorV1::Invalid("PQ provider Cell context mismatch"));
    }
    let (complete, mut report) = network::fetch_cell_in_session(
        store,
        expectation.request.manifest,
        &peers,
        limits,
        &transport,
        Some(output),
    )?;
    report.rejected_responses += initial_rejected;
    Ok((complete, report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cell::discovery::CellDiscoveryContextV1;
    use ml_dsa::{KeyExport, KeyInit, Keypair, MlDsa65, SigningKey};
    use trnm_crypto_primitives::pq_cell_provider::PqCellProviderStatementV2;

    fn request() -> CellDiscoveryRequestV1 {
        let mut six = [[0u8; 32]; 6];
        for (i, digest) in six.iter_mut().enumerate() {
            digest.fill((i + 1) as u8);
        }
        CellDiscoveryRequestV1 {
            context: CellDiscoveryContextV1 {
                namespace: six[0],
                network: six[1],
                parameters: six[2],
                genesis: six[3],
            },
            cell_context: six[4],
            manifest: six[5],
        }
    }

    fn signed_wire(request: CellDiscoveryRequestV1) -> (Vec<u8>, Vec<u8>) {
        let signer = SigningKey::<MlDsa65>::new_from_slice(&[54; 32]).unwrap();
        let mut endpoint = [0u8; 19];
        endpoint[0] = 4;
        endpoint[13..17].copy_from_slice(&[127, 0, 0, 1]);
        endpoint[17..19].copy_from_slice(&31234u16.to_be_bytes());
        let record = SignedPqCellProviderRecordV2::sign(
            PqCellProviderStatementV2 {
                pinned_request: request.encode().try_into().unwrap(),
                endpoint,
                sequence: 5,
                issued_unix_seconds: 1000,
                expires_unix_seconds: 1200,
            },
            &signer,
        )
        .unwrap();
        (record.to_wire(), signer.verifying_key().to_bytes().to_vec())
    }

    #[test]
    fn pcp2_pinned_owner_fetches_actual_verified_cell_bytes_without_classic_discovery() {
        use crate::cell::{serve_cells, CellCacheConfigV4, CellContextV1};
        use std::{
            fs,
            net::TcpListener,
            sync::{
                atomic::{AtomicBool, Ordering},
                Arc,
            },
            thread,
        };

        fn config() -> CellCacheConfigV4 {
            CellCacheConfigV4 {
                max_database_bytes: 128 * 1024 * 1024,
                max_logical_bytes: 64 * 1024 * 1024,
                max_chunk_rows: 4096,
                max_manifest_rows: 256,
            }
        }
        fn limits() -> CellPeerLimitsV1 {
            CellPeerLimitsV1 {
                request_timeout: Duration::from_millis(250),
                overall_timeout: Duration::from_secs(10),
                max_cell_bytes: 1_048_576,
                parallelism: 2,
                max_connections: 64,
                max_response_bytes: 4 * 1_048_576,
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let raw = dir.path().join("source-weights");
        let bytes = vec![17u8; 40_000];
        fs::write(&raw, &bytes).unwrap();
        let source_path = dir.path().join("owner.sqlite");
        let source = CellStoreV1::open(&source_path, config()).unwrap();
        let manifest = source
            .pack_file(
                &raw,
                CellContextV1 {
                    family: "pcp2-m09-e2e-v1".into(),
                    base: [51; 32],
                    parent: [52; 32],
                    tokenizer: [53; 32],
                    layout: [54; 32],
                    runtime: [55; 32],
                },
                16_384,
            )
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let active = shutdown.clone();
        let origin = source_path.clone();
        let server = thread::spawn(move || {
            let owner = CellStoreV1::open(&origin, config()).unwrap();
            serve_cells(&listener, &owner, &active, limits()).unwrap()
        });
        let six = [[1u8; 32], [2; 32], [3; 32], [4; 32]];
        let request = CellDiscoveryRequestV1 {
            context: CellDiscoveryContextV1 {
                namespace: six[0],
                network: six[1],
                parameters: six[2],
                genesis: six[3],
            },
            cell_context: cell_discovery_context_digest(manifest.context()).unwrap(),
            manifest: manifest.id(),
        };
        let signer = SigningKey::<MlDsa65>::new_from_slice(&[64; 32]).unwrap();
        let pk = signer.verifying_key().to_bytes();
        let now = wall_now().unwrap().as_secs();
        let record = SignedPqCellProviderRecordV2::sign(
            PqCellProviderStatementV2 {
                pinned_request: request.encode().try_into().unwrap(),
                endpoint: super::super::endpoint_bytes(endpoint),
                sequence: 7,
                issued_unix_seconds: now - 1,
                expires_unix_seconds: now + 120,
            },
            &signer,
        )
        .unwrap();
        let policy = CellDiscoveryAddressPolicyV1::LoopbackDevOnly {
            ports: vec![endpoint.port()],
        };
        let trust = PqCellProviderExpectationM09V2 {
            request,
            trusted_ml_dsa65_public_key: &pk,
            last_accepted_sequence: 6,
            now_unix_seconds: now,
            addresses: &policy,
        };
        let consumer = CellStoreV1::open(&dir.path().join("consumer.sqlite"), config()).unwrap();
        let output = dir.path().join("verified-weights");
        let mut tampered = record.to_wire();
        tampered[3550] ^= 1;
        assert!(fetch_pcp2_authenticated_cell_to_file(
            &consumer,
            &tampered,
            &trust,
            limits(),
            Instant::now() + Duration::from_secs(10),
            &output,
        )
        .is_err());
        assert!(!output.exists());
        let (actual, report) = fetch_pcp2_authenticated_cell_to_file(
            &consumer,
            &record.to_wire(),
            &trust,
            limits(),
            Instant::now() + Duration::from_secs(10),
            &output,
        )
        .unwrap();
        assert_eq!(actual, manifest);
        assert_eq!(fs::read(&output).unwrap(), bytes);
        assert_eq!(report.downloaded_bytes, bytes.len() as u64);
        assert_eq!(report.manifest_id, manifest.id());
        assert!(report.connection_attempts > 0);
        shutdown.store(true, Ordering::Relaxed);
        assert!(server.join().unwrap() > 0);
    }
    #[test]
    fn authentic_pcp2_uses_existing_m09_request_and_address_policy() {
        let request = request();
        let (wire, key) = signed_wire(request);
        let addresses = CellDiscoveryAddressPolicyV1::LoopbackDevOnly { ports: vec![31234] };
        let expectation = PqCellProviderExpectationM09V2 {
            request,
            trusted_ml_dsa65_public_key: &key,
            last_accepted_sequence: 4,
            now_unix_seconds: 1100,
            addresses: &addresses,
        };
        let hint = verify_pcp2_provider_hint_v2(&wire, &expectation).unwrap();
        assert_eq!(hint.endpoint(), "127.0.0.1:31234".parse().unwrap());
        assert_eq!(hint.sequence(), 5);
        assert_eq!(hint.expires_unix_seconds(), 1200);
        assert_eq!(wire.len(), PQ_CELL_PROVIDER_RECORD_V2_BYTES);
        assert_eq!(PCP2_MAX_REPLY_BYTES, 28641);
        assert!(PCP2_MAX_REPLY_BYTES <= MAX_DISCOVERY_RESPONSE_BYTES as usize);
    }

    #[test]
    fn rejects_replay_wrong_request_key_address_and_expired_record() {
        let request = request();
        let (wire, key) = signed_wire(request);
        let addresses = CellDiscoveryAddressPolicyV1::LoopbackDevOnly { ports: vec![31234] };
        let mut expectation = PqCellProviderExpectationM09V2 {
            request,
            trusted_ml_dsa65_public_key: &key,
            last_accepted_sequence: 4,
            now_unix_seconds: 1100,
            addresses: &addresses,
        };
        expectation.last_accepted_sequence = 5;
        assert!(verify_pcp2_provider_hint_v2(&wire, &expectation).is_err());
        expectation.last_accepted_sequence = 4;
        expectation.now_unix_seconds = 1200;
        assert!(verify_pcp2_provider_hint_v2(&wire, &expectation).is_err());
        expectation.now_unix_seconds = 1100;
        expectation.request.manifest = [99; 32];
        assert!(verify_pcp2_provider_hint_v2(&wire, &expectation).is_err());
        expectation.request = request;
        let wrong = SigningKey::<MlDsa65>::new_from_slice(&[55; 32]).unwrap();
        let wrong_key = wrong.verifying_key().to_bytes();
        expectation.trusted_ml_dsa65_public_key = &wrong_key;
        assert!(verify_pcp2_provider_hint_v2(&wire, &expectation).is_err());
        expectation.trusted_ml_dsa65_public_key = &key;
        let denied = CellDiscoveryAddressPolicyV1::LoopbackDevOnly { ports: vec![31235] };
        expectation.addresses = &denied;
        assert!(verify_pcp2_provider_hint_v2(&wire, &expectation).is_err());
    }

    #[test]
    fn competing_cdp2_classic_cdp1_and_tamper_have_no_fallback() {
        let request = request();
        let (wire, key) = signed_wire(request);
        let addresses = CellDiscoveryAddressPolicyV1::LoopbackDevOnly { ports: vec![31234] };
        let expectation = PqCellProviderExpectationM09V2 {
            request,
            trusted_ml_dsa65_public_key: &key,
            last_accepted_sequence: 4,
            now_unix_seconds: 1100,
            addresses: &addresses,
        };
        assert!(verify_pcp2_provider_hint_v2(&[0; 335], &expectation).is_err());
        let mut competing = vec![0; 5532];
        competing[..4].copy_from_slice(b"CDP2");
        assert!(verify_pcp2_provider_hint_v2(&competing, &expectation).is_err());
        let mut tampered = wire.clone();
        tampered[3540] ^= 1;
        assert!(verify_pcp2_provider_hint_v2(&tampered, &expectation).is_err());
        let mut extended = wire;
        extended.push(0);
        assert!(verify_pcp2_provider_hint_v2(&extended, &expectation).is_err());
    }
}
