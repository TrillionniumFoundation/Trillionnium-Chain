#![forbid(unsafe_code)]
//! Wiring-only host composition for the production-shaped PoCO node.
//!
//! The host joins an authority-readiness reporter to an inert I/O boundary. It
//! contains no consensus transition, storage mutation, signature operation,
//! network binding, timer, retry policy, or release promotion.

use std::{error::Error, fmt};

use trnm_poco_node_authority::{NodeAuthorityCoordinatorV0, NodeAuthorityReadinessV0};
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

    pub const fn start_permitted(self) -> bool {
        self.authority_gate_open
            && self.authority.activation_permitted()
            && self.required_io_surface_count == self.enabled_io_surface_count
            && self.production_activation
    }
}

/// The production-shaped host composition. Its fields are private and it has no
/// adapter registration API, so this revision cannot be used to smuggle an
/// authority-bearing callback into the wiring layer.
#[derive(Debug, Default)]
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

    pub fn status(&self) -> NodeHostStatusV0 {
        NodeHostStatusV0 {
            authority: self.authority.readiness(),
            required_io_surface_count: REQUIRED_NODE_IO_SURFACES_V0.len(),
            enabled_io_surface_count: self.io.enabled_surface_count(),
            authority_gate_open: self.authority.production_activation_gate().is_ok(),
            production_activation: self.io.production_activation(),
        }
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
            "node host start blocked: production_candidate={} host_complete={} unwired_contracts={} authority_gate_open={} io_enabled={}/{} production_activation={}",
            self.status.authority.production_candidate(),
            self.status.authority.host_implementation_complete(),
            self.status.authority.unwired_contract_count(),
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

    #[test]
    fn composition_is_wiring_only_and_fail_closed() {
        let host = PocoNodeHostV0::inert();
        let status = host.status();
        assert!(!status.start_permitted());
        assert!(!status.authority_gate_open());
        assert!(!status.production_activation());
        assert_eq!(status.enabled_io_surface_count(), 0);
        assert_eq!(
            status.required_io_surface_count(),
            REQUIRED_NODE_IO_SURFACES_V0.len()
        );
        let blocked = host.start().expect_err("inert host must not start");
        assert_eq!(blocked.status(), status);
    }
}
