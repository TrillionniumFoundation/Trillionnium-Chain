#![forbid(unsafe_code)]
//! Wiring-only host composition for the production-shaped PoCO node.
//!
//! The host can now bind the explicit candidate authority-journal owner and
//! delegate recovery, exact ingress preparation, and strict stage advances.
//! It still contains no consensus transition, application fact production,
//! signature operation, network binding, timer, retry policy, finality
//! authority, or release promotion. The I/O side remains deliberately inert,
//! so this candidate composition can never satisfy the production start gate.

use std::{error::Error, fmt};
#[cfg(feature = "persistent-authority-candidate")]
use std::path::Path;

#[cfg(feature = "persistent-authority-candidate")]
use trnm_poco_node_authority::{
    AuthorityReceiptV0, BoundIngressV0, Digest32V0, NodeIdentityV0,
    OperationBindingV0, RecoveryDispositionV0,
};
use trnm_poco_node_authority::{
    AuthorityStageV0, NodeAuthorityCoordinatorV0, NodeAuthorityReadinessV0,
};
#[cfg(feature = "persistent-authority-candidate")]
use trnm_poco_node_authority::NodeAuthorityErrorV0;
use trnm_poco_node_io::{NodeIoRuntimeV0, REQUIRED_NODE_IO_SURFACES_V0};

/// Compile-time binding to the reviewed pure repository-core composition.
/// This does not open activation or instantiate domain state.
pub const REPOSITORY_CORE_COMPOSITION_VERSION_V0: u16 =
    trnm_poco_node_production_v0::PRODUCTION_COMPOSITION_VERSION_V0;

/// Sanitized composition status. It contains no key, block, vote, transaction,
/// peer, path, or credential material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeHostStatusV0 {
    authority: NodeAuthorityReadinessV0,
    required_io_surface_count: usize,
    enabled_io_surface_count: usize,
    authority_gate_open: bool,
    production_activation: bool,
}

impl NodeHostStatusV0 {
    pub const fn authority(self) -> NodeAuthorityReadinessV0 {
        self.authority
    }

    pub const fn required_io_surface_count(self) -> usize {
        self.required_io_surface_count
    }

    pub const fn enabled_io_surface_count(self) -> usize {
        self.enabled_io_surface_count
    }

    pub const fn authority_gate_open(self) -> bool {
        self.authority_gate_open
    }

    pub const fn production_activation(self) -> bool {
        self.production_activation
    }

    pub const fn persistent_authority_bound(self) -> bool {
        self.authority.persistent_authority_bound()
    }

    pub const fn recovery_barrier_satisfied(self) -> bool {
        self.authority.recovery_barrier_satisfied()
    }

    pub const fn durable_stage(self) -> Option<AuthorityStageV0> {
        self.authority.durable_stage()
    }

    pub const fn start_permitted(self) -> bool {
        self.authority_gate_open
            && self.authority.activation_permitted()
            && self.required_io_surface_count == self.enabled_io_surface_count
            && self.production_activation
    }
}

/// The production-shaped host composition. Its fields remain private, so an
/// authority-bearing callback or I/O implementation cannot be smuggled into
/// the wiring layer.
#[derive(Debug, Default)]
#[cfg_attr(
    not(feature = "persistent-authority-candidate"),
    doc = "```compile_fail\nuse trnm_poco_node_host::PocoNodeHostV0;\nlet _ = PocoNodeHostV0::recover_authority;\n```"
)]
pub struct PocoNodeHostV0 {
    authority: NodeAuthorityCoordinatorV0,
    io: NodeIoRuntimeV0,
}

impl PocoNodeHostV0 {
    pub const fn inert() -> Self {
        Self {
            authority: NodeAuthorityCoordinatorV0::new(),
            io: NodeIoRuntimeV0::inert(),
        }
    }

    /// Bind an existing absolute non-symlink authority root while retaining an
    /// inert I/O runtime and a closed production gate.
    #[cfg(feature = "persistent-authority-candidate")]
    pub fn open_candidate_persistent_authority(
        root: impl AsRef<Path>,
        identity: NodeIdentityV0,
    ) -> Result<Self, NodeAuthorityErrorV0> {
        Ok(Self {
            authority: NodeAuthorityCoordinatorV0::open_candidate(root, identity)?,
            io: NodeIoRuntimeV0::inert(),
        })
    }

    pub fn status(&self) -> NodeHostStatusV0 {
        NodeHostStatusV0 {
            authority: self.authority.readiness(),
            required_io_surface_count: REQUIRED_NODE_IO_SURFACES_V0.len(),
            enabled_io_surface_count: self.io.enabled_surface_count(),
            authority_gate_open: self.authority.production_activation_gate().is_ok(),
            production_activation: self.io.production_activation(),
        }
    }

    #[cfg(feature = "persistent-authority-candidate")]
    pub fn recover_authority(&mut self) -> Result<RecoveryDispositionV0, NodeAuthorityErrorV0> {
        self.authority.recover()
    }

    #[cfg(feature = "persistent-authority-candidate")]
    pub fn current_authority_receipt(&self) -> Option<AuthorityReceiptV0> {
        self.authority.current_receipt()
    }

    #[cfg(feature = "persistent-authority-candidate")]
    pub fn prepare_bound_ingress(
        &mut self,
        ingress: &BoundIngressV0,
    ) -> Result<AuthorityReceiptV0, NodeAuthorityErrorV0> {
        self.authority.prepare_bound_ingress(ingress)
    }

    /// Delegate one exact successor append after a domain owner has returned a
    /// trusted non-zero fact digest. This host does not create or interpret the
    /// represented fact.
    #[cfg(feature = "persistent-authority-candidate")]
    pub fn advance_authority_exact(
        &mut self,
        binding: OperationBindingV0,
        expected_stage: AuthorityStageV0,
        next_stage: AuthorityStageV0,
        facts_digest: Digest32V0,
    ) -> Result<AuthorityReceiptV0, NodeAuthorityErrorV0> {
        self.authority
            .advance_exact(binding, expected_stage, next_stage, facts_digest)
    }

    pub fn start(&self) -> Result<(), NodeHostStartBlockedV0> {
        let status = self.status();
        if status.start_permitted() {
            Ok(())
        } else {
            Err(NodeHostStartBlockedV0 { status })
        }
    }
}

/// Exact fail-closed result returned by the composition start boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeHostStartBlockedV0 {
    status: NodeHostStatusV0,
}

impl NodeHostStartBlockedV0 {
    pub const fn status(self) -> NodeHostStatusV0 {
        self.status
    }
}

impl fmt::Display for NodeHostStartBlockedV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "node host start blocked: production_candidate={} host_complete={} unwired_contracts={} persistent_authority_bound={} recovery_barrier_satisfied={} durable_stage={:?} authority_gate_open={} io_enabled={}/{} production_activation={}",
            self.status.authority.production_candidate(),
            self.status.authority.host_implementation_complete(),
            self.status.authority.unwired_contract_count(),
            self.status.persistent_authority_bound(),
            self.status.recovery_barrier_satisfied(),
            self.status.durable_stage(),
            self.status.authority_gate_open,
            self.status.enabled_io_surface_count,
            self.status.required_io_surface_count,
            self.status.production_activation,
        )
    }
}

impl Error for NodeHostStartBlockedV0 {}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "persistent-authority-candidate")]
    use trnm_poco_node_authority::IngressFrameV0;

    #[cfg(feature = "persistent-authority-candidate")]
    fn identity() -> NodeIdentityV0 {
        NodeIdentityV0 {
            chain_id: Digest32V0([1; 32]),
            validator_id: Digest32V0([2; 32]),
            application_id: Digest32V0([3; 32]),
            generation: 1,
        }
    }

    #[cfg(feature = "persistent-authority-candidate")]
    fn ingress() -> BoundIngressV0 {
        let frame = IngressFrameV0::new(
            Digest32V0([4; 32]),
            Digest32V0([5; 32]),
            1,
            b"candidate proposal".to_vec(),
        )
        .expect("frame");
        BoundIngressV0::derive(
            identity(),
            1,
            0,
            Digest32V0([6; 32]),
            Digest32V0([7; 32]),
            frame,
        )
        .expect("bound ingress")
    }

    #[test]
    fn composition_is_wiring_only_and_fail_closed() {
        let host = PocoNodeHostV0::inert();
        let status = host.status();
        assert!(!status.start_permitted());
        assert!(!status.authority_gate_open());
        assert!(!status.production_activation());
        assert!(!status.persistent_authority_bound());
        assert!(!status.recovery_barrier_satisfied());
        assert_eq!(status.durable_stage(), None);
        assert_eq!(status.enabled_io_surface_count(), 0);
        assert_eq!(
            status.required_io_surface_count(),
            REQUIRED_NODE_IO_SURFACES_V0.len()
        );
        let blocked = host.start().expect_err("inert host must not start");
        assert_eq!(blocked.status(), status);
    }

    #[test]
    #[cfg(feature = "persistent-authority-candidate")]
    fn persistent_candidate_delegates_authority_but_cannot_start() {
        let directory = tempfile::tempdir().expect("tempdir");
        let mut host =
            PocoNodeHostV0::open_candidate_persistent_authority(directory.path(), identity())
                .expect("open host");
        assert!(host.status().persistent_authority_bound());
        assert!(!host.status().recovery_barrier_satisfied());
        assert_eq!(
            host.recover_authority().expect("recover"),
            RecoveryDispositionV0::Clean
        );
        let prepared = host
            .prepare_bound_ingress(&ingress())
            .expect("prepare ingress");
        assert_eq!(host.current_authority_receipt(), Some(prepared));
        assert_eq!(
            host.status().durable_stage(),
            Some(AuthorityStageV0::Prepared)
        );

        let application_facts = Digest32V0::hash(
            b"trnm.host-test-application-seal.v0",
            &[&prepared.record_digest.0],
        );
        let sealed = host
            .advance_authority_exact(
                prepared.binding,
                AuthorityStageV0::Prepared,
                AuthorityStageV0::ApplicationSealed,
                application_facts,
            )
            .expect("seal application fact");
        assert_eq!(sealed.durable_stage, AuthorityStageV0::ApplicationSealed);
        assert_eq!(
            host.status().durable_stage(),
            Some(AuthorityStageV0::ApplicationSealed)
        );
        assert!(host.status().recovery_barrier_satisfied());
        assert!(!host.status().start_permitted());
        assert!(host.start().is_err());
    }
}
