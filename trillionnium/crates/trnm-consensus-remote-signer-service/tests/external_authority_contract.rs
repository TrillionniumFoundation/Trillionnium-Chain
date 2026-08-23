//! Public black-box contract for the not-yet-wired external authority seam.
//!
//! The service's local fixture path must never be silently reused when a
//! caller asks for external watermark authority.  This test proves the
//! external entry point decodes request facts but fails closed before local
//! reservation, signing, or adapter side effects.  Cross-process CAS,
//! response replay, and crash reconciliation are supplied by the independent
//! `trnm-consensus-external-watermark` authority tests; this crate deliberately
//! does not claim that integration yet.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use tempfile::TempDir;
use trnm_consensus_remote_signer_service::{
    fixture_request, fixture_service_config, ExternalAuthorityAdapterV1, ExternalAuthorityErrorV1,
    ExternalAuthorityRequestV1, ExternalAuthorityReservationV1, Fixture, PurposePolicyV1,
    RemoteSignerService,
};

#[derive(Clone)]
struct NeverCalledAuthority {
    calls: Arc<AtomicUsize>,
}

impl NeverCalledAuthority {
    fn new() -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl ExternalAuthorityAdapterV1 for NeverCalledAuthority {
    fn replay_response_v1(
        &mut self,
        _request: ExternalAuthorityRequestV1,
    ) -> Result<Option<Vec<u8>>, ExternalAuthorityErrorV1> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(ExternalAuthorityErrorV1::Unavailable)
    }

    fn reserve_v1(
        &mut self,
        _request: ExternalAuthorityRequestV1,
    ) -> Result<ExternalAuthorityReservationV1, ExternalAuthorityErrorV1> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(ExternalAuthorityErrorV1::Unavailable)
    }

    fn bind_response_v1(
        &mut self,
        _reservation: ExternalAuthorityReservationV1,
        _response: &[u8],
    ) -> Result<(), ExternalAuthorityErrorV1> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(ExternalAuthorityErrorV1::Unavailable)
    }
}

#[test]
fn external_entrypoint_fails_closed_without_local_sqlite_fallback() {
    let temporary = TempDir::new().expect("external seam temp root");
    let path = temporary.path().join("watermark.sqlite3");
    let fixture = Fixture::new();
    let mut service =
        RemoteSignerService::open(fixture_service_config(&path, PurposePolicyV1::both()))
            .expect("open local fixture for contract probe");
    let request = fixture_request(&fixture, "timeout", 3, b"external-seam")
        .expect("build exact timeout request")
        .try_exact_bytes()
        .expect("encode exact timeout request");
    let facts = service
        .external_authority_request_v1(&request)
        .expect("decode external authority facts");
    assert_eq!(
        facts.process_generation,
        fixture.binding.process_generation().get()
    );
    assert_eq!(facts.lease_id, *fixture.binding.lease_id().as_bytes());
    assert_eq!(facts.epoch, fixture.validator_set.epoch().get());
    assert_eq!(facts.view, 3);

    let authority = NeverCalledAuthority::new();
    let calls = Arc::clone(&authority.calls);
    let mut authority = authority;
    let error = service
        .process_request_with_external_authority_v1(&request, &mut authority)
        .expect_err("unwired external authority must fail closed");
    assert!(error.is_external_authority_required());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        service
            .watermark_snapshot()
            .expect("read untouched local watermark")
            .sequence,
        0
    );
}
