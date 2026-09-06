//! Named orchestration over the verified-only production authority session.
//!
//! The driver owns no domain fact. Each transition remains gated by the
//! corresponding authenticated source port, while the public API removes the
//! caller's ability to select an arbitrary successor stage.

use std::{error::Error, fmt};

use trnm_node_boundary_v0::{
    AuthorityCoordinatorV0, AuthorityReceiptV0, AuthorityStageV0, BoundIngressV0,
};

use crate::{
    AuthorityFactClaimV0, AuthorityFactSourceV0, AuthorityFactVerificationErrorV0,
    AuthorityIngressSourceV0, AuthorityIngressVerificationErrorV0, AuthoritySessionErrorV0,
    AuthoritySessionReadinessV0, ProductionAuthoritySessionV0,
};

pub struct ProductionAuthorityDriverV0<C, R> {
    session: ProductionAuthoritySessionV0<C, R>,
}

impl<C, R> ProductionAuthorityDriverV0<C, R>
where
    C: AuthorityCoordinatorV0,
    R: Fn(&C) -> Option<AuthorityReceiptV0>,
{
    pub const fn new(session: ProductionAuthoritySessionV0<C, R>) -> Self {
        Self { session }
    }

    #[must_use]
    pub const fn session(&self) -> &ProductionAuthoritySessionV0<C, R> {
        &self.session
    }

    pub fn session_mut(&mut self) -> &mut ProductionAuthoritySessionV0<C, R> {
        &mut self.session
    }

    pub fn into_session(self) -> ProductionAuthoritySessionV0<C, R> {
        self.session
    }

    pub fn recover(
        &mut self,
    ) -> Result<AuthoritySessionReadinessV0, AuthoritySessionErrorV0<C::Error>> {
        self.session.recover()
    }

    pub fn admit_ingress<S>(
        &mut self,
        ingress: BoundIngressV0,
        source: &mut S,
    ) -> Result<AuthorityReceiptV0, AuthorityDriverIngressErrorV0<S::Error, C::Error>>
    where
        S: AuthorityIngressSourceV0,
    {
        let verified = self
            .session
            .verify_ingress(ingress, source)
            .map_err(AuthorityDriverIngressErrorV0::Verification)?;
        self.session
            .begin_verified(verified)
            .map_err(AuthorityDriverIngressErrorV0::Session)
    }

    pub fn seal_application<S>(
        &mut self,
        claim: AuthorityFactClaimV0,
        source: &mut S,
    ) -> Result<AuthorityReceiptV0, AuthorityDriverFactErrorV0<S::Error, C::Error>>
    where
        S: AuthorityFactSourceV0,
    {
        self.apply_named_stage(AuthorityStageV0::ApplicationSealed, claim, source)
    }

    pub fn persist_safety<S>(
        &mut self,
        claim: AuthorityFactClaimV0,
        source: &mut S,
    ) -> Result<AuthorityReceiptV0, AuthorityDriverFactErrorV0<S::Error, C::Error>>
    where
        S: AuthorityFactSourceV0,
    {
        self.apply_named_stage(AuthorityStageV0::SafetyPersisted, claim, source)
    }

    pub fn persist_sign_intent<S>(
        &mut self,
        claim: AuthorityFactClaimV0,
        source: &mut S,
    ) -> Result<AuthorityReceiptV0, AuthorityDriverFactErrorV0<S::Error, C::Error>>
    where
        S: AuthorityFactSourceV0,
    {
        self.apply_named_stage(AuthorityStageV0::SignIntentPersisted, claim, source)
    }

    pub fn confirm_signature<S>(
        &mut self,
        claim: AuthorityFactClaimV0,
        source: &mut S,
    ) -> Result<AuthorityReceiptV0, AuthorityDriverFactErrorV0<S::Error, C::Error>>
    where
        S: AuthorityFactSourceV0,
    {
        self.apply_named_stage(AuthorityStageV0::SignatureConfirmed, claim, source)
    }

    pub fn apply_finality<S>(
        &mut self,
        claim: AuthorityFactClaimV0,
        source: &mut S,
    ) -> Result<AuthorityReceiptV0, AuthorityDriverFactErrorV0<S::Error, C::Error>>
    where
        S: AuthorityFactSourceV0,
    {
        self.apply_named_stage(AuthorityStageV0::FinalityApplied, claim, source)
    }

    pub fn confirm_checkpoint<S>(
        &mut self,
        claim: AuthorityFactClaimV0,
        source: &mut S,
    ) -> Result<AuthorityReceiptV0, AuthorityDriverFactErrorV0<S::Error, C::Error>>
    where
        S: AuthorityFactSourceV0,
    {
        self.apply_named_stage(AuthorityStageV0::CheckpointConfirmed, claim, source)
    }

    pub fn publish_outbound<S>(
        &mut self,
        claim: AuthorityFactClaimV0,
        source: &mut S,
    ) -> Result<AuthorityReceiptV0, AuthorityDriverFactErrorV0<S::Error, C::Error>>
    where
        S: AuthorityFactSourceV0,
    {
        self.apply_named_stage(AuthorityStageV0::OutboundPublished, claim, source)
    }

    fn apply_named_stage<S>(
        &mut self,
        required_stage: AuthorityStageV0,
        claim: AuthorityFactClaimV0,
        source: &mut S,
    ) -> Result<AuthorityReceiptV0, AuthorityDriverFactErrorV0<S::Error, C::Error>>
    where
        S: AuthorityFactSourceV0,
    {
        if claim.stage() != required_stage {
            return Err(AuthorityDriverFactErrorV0::WrongStage {
                required: required_stage,
                observed: claim.stage(),
            });
        }
        let verified = self
            .session
            .verify_fact(claim, source)
            .map_err(AuthorityDriverFactErrorV0::Verification)?;
        self.session
            .advance_verified(verified)
            .map_err(AuthorityDriverFactErrorV0::Session)
    }
}

#[derive(Debug)]
pub enum AuthorityDriverIngressErrorV0<S, C> {
    Verification(AuthorityIngressVerificationErrorV0<S>),
    Session(AuthoritySessionErrorV0<C>),
}

impl<S: fmt::Display, C: fmt::Display> fmt::Display for AuthorityDriverIngressErrorV0<S, C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Verification(error) => write!(formatter, "ingress verification failed: {error}"),
            Self::Session(error) => write!(formatter, "ingress persistence failed: {error}"),
        }
    }
}

impl<S: Error + 'static, C: Error + 'static> Error for AuthorityDriverIngressErrorV0<S, C> {}

#[derive(Debug)]
pub enum AuthorityDriverFactErrorV0<S, C> {
    WrongStage {
        required: AuthorityStageV0,
        observed: AuthorityStageV0,
    },
    Verification(AuthorityFactVerificationErrorV0<S>),
    Session(AuthoritySessionErrorV0<C>),
}

impl<S: fmt::Display, C: fmt::Display> fmt::Display for AuthorityDriverFactErrorV0<S, C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongStage { required, observed } => write!(
                formatter,
                "named authority transition requires {required:?}, observed {observed:?}"
            ),
            Self::Verification(error) => write!(formatter, "fact verification failed: {error}"),
            Self::Session(error) => write!(formatter, "fact persistence failed: {error}"),
        }
    }
}

impl<S: Error + 'static, C: Error + 'static> Error for AuthorityDriverFactErrorV0<S, C> {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;
    use trnm_node_boundary_v0::{
        Digest32V0, IngressFrameV0, NodeIdentityV0, OperationBindingV0,
        ReferenceAuthorityCoordinatorV0,
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

    fn ingress(height: u64, block: u8, parent: u8) -> BoundIngressV0 {
        let frame = IngressFrameV0::new(d(4), d(5), height, vec![block]).unwrap();
        BoundIngressV0::derive(identity(), height, height, d(block), d(parent), frame).unwrap()
    }

    fn claim(binding: OperationBindingV0, stage: AuthorityStageV0) -> AuthorityFactClaimV0 {
        AuthorityFactClaimV0::new(
            identity(),
            binding,
            stage,
            d(100u8.wrapping_add(stage as u8)),
            u64::from(stage as u8) + 1,
            d(150u8.wrapping_add(stage as u8)),
        )
        .unwrap()
    }

    struct IngressSource;

    impl AuthorityIngressSourceV0 for IngressSource {
        type Error = Infallible;

        fn verify_ingress(
            &mut self,
            observed_identity: NodeIdentityV0,
            _prior: Option<AuthorityReceiptV0>,
            observed: &BoundIngressV0,
        ) -> Result<(), Self::Error> {
            assert_eq!(observed_identity, identity());
            observed.validate(identity()).unwrap();
            Ok(())
        }
    }

    #[derive(Default)]
    struct FactSource(usize);

    impl AuthorityFactSourceV0 for FactSource {
        type Error = Infallible;

        fn verify_fact(
            &mut self,
            observed_identity: NodeIdentityV0,
            prior: AuthorityReceiptV0,
            observed: &AuthorityFactClaimV0,
        ) -> Result<(), Self::Error> {
            assert_eq!(observed_identity, identity());
            assert_eq!(prior.binding, observed.binding());
            self.0 += 1;
            Ok(())
        }
    }

    fn driver() -> ProductionAuthorityDriverV0<
        ReferenceAuthorityCoordinatorV0,
        fn(&ReferenceAuthorityCoordinatorV0) -> Option<AuthorityReceiptV0>,
    > {
        let session = ProductionAuthoritySessionV0::new(
            ReferenceAuthorityCoordinatorV0::new(identity()),
            ReferenceAuthorityCoordinatorV0::current,
        )
        .unwrap();
        ProductionAuthorityDriverV0::new(session)
    }

    #[test]
    fn named_driver_executes_only_the_exact_stage_order() {
        let mut driver = driver();
        assert_eq!(
            driver.recover().unwrap(),
            AuthoritySessionReadinessV0::Ready
        );
        let first = ingress(1, 10, 9);
        let binding = first.binding;
        driver.admit_ingress(first, &mut IngressSource).unwrap();
        let mut source = FactSource::default();
        driver
            .seal_application(
                claim(binding, AuthorityStageV0::ApplicationSealed),
                &mut source,
            )
            .unwrap();
        driver
            .persist_safety(
                claim(binding, AuthorityStageV0::SafetyPersisted),
                &mut source,
            )
            .unwrap();
        driver
            .persist_sign_intent(
                claim(binding, AuthorityStageV0::SignIntentPersisted),
                &mut source,
            )
            .unwrap();
        driver
            .confirm_signature(
                claim(binding, AuthorityStageV0::SignatureConfirmed),
                &mut source,
            )
            .unwrap();
        driver
            .apply_finality(
                claim(binding, AuthorityStageV0::FinalityApplied),
                &mut source,
            )
            .unwrap();
        driver
            .confirm_checkpoint(
                claim(binding, AuthorityStageV0::CheckpointConfirmed),
                &mut source,
            )
            .unwrap();
        let terminal = driver
            .publish_outbound(
                claim(binding, AuthorityStageV0::OutboundPublished),
                &mut source,
            )
            .unwrap();
        assert_eq!(terminal.durable_stage, AuthorityStageV0::OutboundPublished);
        assert_eq!(source.0, 7);
    }

    #[test]
    fn named_method_rejects_wrong_claim_before_source_authority() {
        let mut driver = driver();
        driver.recover().unwrap();
        let first = ingress(1, 10, 9);
        let binding = first.binding;
        let prepared = driver.admit_ingress(first, &mut IngressSource).unwrap();
        let mut source = FactSource::default();
        let error = driver
            .seal_application(
                claim(binding, AuthorityStageV0::SafetyPersisted),
                &mut source,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            AuthorityDriverFactErrorV0::WrongStage {
                required: AuthorityStageV0::ApplicationSealed,
                observed: AuthorityStageV0::SafetyPersisted,
            }
        ));
        assert_eq!(source.0, 0);
        assert_eq!(driver.session().current_receipt(), Some(prepared));
    }
}
