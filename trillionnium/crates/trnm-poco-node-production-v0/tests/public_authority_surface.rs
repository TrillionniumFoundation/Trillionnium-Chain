//! External behavioral checks complement the compiler-checked token contract.
//!
//! The reference coordinator/source are fixtures, not commissioned production
//! producers. No source-string match counts as authorization or type safety.

use trnm_node_boundary_v0::{
    AuthorityReceiptV0, BoundIngressV0, BoundaryErrorV0, Digest32V0, IngressFrameV0,
    NodeIdentityV0, ReferenceAuthorityCoordinatorV0,
};
use trnm_poco_node_production_v0::{
    AuthorityIngressSourceV0, AuthorityIngressVerificationErrorV0, AuthoritySessionErrorV0,
    AuthoritySessionReadinessV0, ProductionAuthoritySessionV0,
};

fn d(byte: u8) -> Digest32V0 {
    Digest32V0([byte; 32])
}
fn identity() -> NodeIdentityV0 {
    NodeIdentityV0 {
        chain_id: d(1),
        validator_id: d(2),
        application_id: d(3),
        generation: 1,
    }
}
fn ingress() -> BoundIngressV0 {
    let frame = IngressFrameV0::new(d(4), d(5), 1, vec![20]).unwrap();
    BoundIngressV0::derive(identity(), 1, 1, d(10), d(9), frame).unwrap()
}
type Session = ProductionAuthoritySessionV0<
    ReferenceAuthorityCoordinatorV0,
    fn(&ReferenceAuthorityCoordinatorV0) -> Option<AuthorityReceiptV0>,
>;
fn session() -> Session {
    ProductionAuthoritySessionV0::new(
        ReferenceAuthorityCoordinatorV0::new(identity()),
        ReferenceAuthorityCoordinatorV0::current
            as fn(&ReferenceAuthorityCoordinatorV0) -> Option<AuthorityReceiptV0>,
    )
    .unwrap()
}
#[derive(Default)]
struct Source {
    calls: usize,
    reject: bool,
}
impl AuthorityIngressSourceV0 for Source {
    type Error = &'static str;
    fn verify_ingress(
        &mut self,
        observed: NodeIdentityV0,
        prior: Option<AuthorityReceiptV0>,
        value: &BoundIngressV0,
    ) -> Result<(), Self::Error> {
        assert_eq!(observed, identity());
        assert!(prior.is_none());
        value.validate(observed).unwrap();
        self.calls += 1;
        if self.reject {
            Err("source rejected")
        } else {
            Ok(())
        }
    }
}

#[test]
fn production_session_exports_verified_tokens_not_naked_digest_mutators() {
    let mut session = session();
    let mut source = Source::default();
    assert!(matches!(
        session.verify_ingress(ingress(), &mut source),
        Err(AuthorityIngressVerificationErrorV0::NotReady)
    ));
    assert_eq!(source.calls, 0);
    assert_eq!(session.current_receipt(), None);

    assert_eq!(
        session.recover().unwrap(),
        AuthoritySessionReadinessV0::Ready
    );
    let accepted = session.verify_ingress(ingress(), &mut source).unwrap();
    let stale = session.verify_ingress(ingress(), &mut source).unwrap();
    assert_eq!(source.calls, 2);
    // Verification alone does not create a durable receipt.
    assert_eq!(session.current_receipt(), None);
    let prepared = session.begin_verified(accepted).unwrap();
    assert!(matches!(
        session.begin_verified(stale),
        Err(AuthoritySessionErrorV0::Boundary(
            BoundaryErrorV0::ReceiptSubstitution
        ))
    ));
    assert_eq!(session.current_receipt(), Some(prepared));
}

#[test]
fn rejected_ingress_never_advances_authoritative_state() {
    let mut session = session();
    session.recover().unwrap();
    let mut source = Source {
        calls: 0,
        reject: true,
    };
    assert!(matches!(
        session.verify_ingress(ingress(), &mut source),
        Err(AuthorityIngressVerificationErrorV0::Source(
            "source rejected"
        ))
    ));
    assert_eq!(source.calls, 1);
    assert_eq!(session.current_receipt(), None);
    assert_eq!(session.readiness(), AuthoritySessionReadinessV0::Ready);
}
