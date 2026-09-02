#![forbid(unsafe_code)]
//! Inert I/O boundary for the production-shaped PoCO node composition.
//!
//! No socket, filesystem, thread, timer, RPC, state-sync, or telemetry backend
//! is constructed here. A later adapter must be explicit, bounded, authenticated,
//! and independently accepted before any surface can become active.

/// I/O surfaces that a complete validator host must eventually bind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeIoSurfaceV0 {
    AuthenticatedP2p,
    PacemakerTimer,
    StateSync,
    Rpc,
    Indexer,
    Telemetry,
}

pub const REQUIRED_NODE_IO_SURFACES_V0: &[NodeIoSurfaceV0] = &[
    NodeIoSurfaceV0::AuthenticatedP2p,
    NodeIoSurfaceV0::PacemakerTimer,
    NodeIoSurfaceV0::StateSync,
    NodeIoSurfaceV0::Rpc,
    NodeIoSurfaceV0::Indexer,
    NodeIoSurfaceV0::Telemetry,
];

/// A deliberately inert runtime boundary.
///
/// There is no public constructor for an enabled surface and no callback that
/// can reach consensus authority.
#[derive(Debug, Default)]
pub struct NodeIoRuntimeV0 {
    _private: (),
}

impl NodeIoRuntimeV0 {
    pub const fn inert() -> Self {
        Self { _private: () }
    }

    pub const fn is_enabled(&self, _surface: NodeIoSurfaceV0) -> bool {
        false
    }

    pub const fn enabled_surface_count(&self) -> usize {
        0
    }

    pub const fn production_activation(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_surface_is_inert() {
        let runtime = NodeIoRuntimeV0::inert();
        for surface in REQUIRED_NODE_IO_SURFACES_V0 {
            assert!(!runtime.is_enabled(*surface));
        }
        assert_eq!(runtime.enabled_surface_count(), 0);
        assert!(!runtime.production_activation());
    }
}
