#![forbid(unsafe_code)]
//! Inert I/O boundary for the production-shaped PoCO node composition.
//!
//! No socket, filesystem, thread, timer, RPC, state-sync, or telemetry backend
//! is constructed by the default build. Explicit candidate adapters remain
//! bounded, non-activating, and independently qualified before composition use.

#[cfg(feature = "candidate-pacemaker")]
use std::{error::Error, fmt};

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
/// There is no public constructor for an enabled production surface and no
/// callback that can reach consensus authority.
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

/// Maximum candidate timer horizon. This is a local safety budget, not a
/// protocol timeout parameter or a production liveness claim.
#[cfg(feature = "candidate-pacemaker")]
pub const MAX_CANDIDATE_PACEMAKER_DELAY_MILLIS_V0: u64 = 60_000;

/// Exact epoch/view/generation identity for one timer effect.
#[cfg(feature = "candidate-pacemaker")]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PacemakerIdentityV0 {
    epoch: u64,
    view: u64,
    generation: u64,
}

#[cfg(feature = "candidate-pacemaker")]
impl PacemakerIdentityV0 {
    pub fn new(epoch: u64, view: u64, generation: u64) -> Result<Self, PacemakerErrorV0> {
        if epoch == 0 || generation == 0 {
            return Err(PacemakerErrorV0::InvalidIdentity);
        }
        Ok(Self {
            epoch,
            view,
            generation,
        })
    }

    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    #[must_use]
    pub const fn view(self) -> u64 {
        self.view
    }

    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

/// Absolute monotonic deadline for one candidate timer effect.
#[cfg(feature = "candidate-pacemaker")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacemakerArmV0 {
    identity: PacemakerIdentityV0,
    deadline_millis: u64,
}

#[cfg(feature = "candidate-pacemaker")]
impl PacemakerArmV0 {
    pub fn new(
        identity: PacemakerIdentityV0,
        deadline_millis: u64,
    ) -> Result<Self, PacemakerErrorV0> {
        if deadline_millis == 0 {
            return Err(PacemakerErrorV0::InvalidDeadline);
        }
        Ok(Self {
            identity,
            deadline_millis,
        })
    }

    #[must_use]
    pub const fn identity(self) -> PacemakerIdentityV0 {
        self.identity
    }

    #[must_use]
    pub const fn deadline_millis(self) -> u64 {
        self.deadline_millis
    }
}

/// Injected monotonic clock. A production implementation must bind a real
/// monotonic source and preserve generation across process restart.
#[cfg(feature = "candidate-pacemaker")]
pub trait MonotonicClockV0 {
    fn now_millis(&self) -> u64;
}

/// Replay-safe poll result. `Fired` repeats unchanged until explicitly
/// acknowledged, so response loss cannot silently consume the timer effect.
#[cfg(feature = "candidate-pacemaker")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacemakerPollV0 {
    Idle,
    Armed(PacemakerArmV0),
    Fired(PacemakerArmV0),
}

#[cfg(feature = "candidate-pacemaker")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacemakerErrorV0 {
    InvalidIdentity,
    InvalidDeadline,
    ClockRegressed,
    Poisoned,
    PendingFire,
    StaleArm,
    ConflictingArm,
    UnexpectedAcknowledgement,
}

#[cfg(feature = "candidate-pacemaker")]
impl fmt::Display for PacemakerErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidIdentity => "pacemaker identity is invalid",
            Self::InvalidDeadline => "pacemaker deadline is invalid or outside the local budget",
            Self::ClockRegressed => "pacemaker monotonic clock regressed",
            Self::Poisoned => "pacemaker is poisoned and requires replacement/recovery",
            Self::PendingFire => "a fired timer must be acknowledged before rearming",
            Self::StaleArm => "pacemaker arm is stale or reordered",
            Self::ConflictingArm => "pacemaker identity was replayed with a different deadline",
            Self::UnexpectedAcknowledgement => "pacemaker acknowledgement does not match pending fire",
        };
        formatter.write_str(message)
    }
}

#[cfg(feature = "candidate-pacemaker")]
impl Error for PacemakerErrorV0 {}

/// Bounded, polling-only pacemaker candidate.
///
/// This object creates no thread, socket or consensus message. It only owns the
/// local ordering and response-loss semantics of one timer effect at a time.
/// Clock regression poisons the instance. A fired effect remains pending until
/// exact acknowledgement; a later epoch/view/generation cannot bypass it.
#[cfg(feature = "candidate-pacemaker")]
pub struct CandidatePacemakerV0<C> {
    clock: C,
    last_observed_millis: Option<u64>,
    armed: Option<PacemakerArmV0>,
    pending_fire: Option<PacemakerArmV0>,
    last_acknowledged: Option<PacemakerIdentityV0>,
    poisoned: bool,
}

#[cfg(feature = "candidate-pacemaker")]
impl<C> CandidatePacemakerV0<C>
where
    C: MonotonicClockV0,
{
    pub const fn new(clock: C) -> Self {
        Self {
            clock,
            last_observed_millis: None,
            armed: None,
            pending_fire: None,
            last_acknowledged: None,
            poisoned: false,
        }
    }

    #[must_use]
    pub const fn clock(&self) -> &C {
        &self.clock
    }

    pub fn clock_mut(&mut self) -> &mut C {
        &mut self.clock
    }

    #[must_use]
    pub const fn pending_fire(&self) -> Option<PacemakerArmV0> {
        self.pending_fire
    }

    #[must_use]
    pub const fn last_acknowledged(&self) -> Option<PacemakerIdentityV0> {
        self.last_acknowledged
    }

    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    fn observe_now(&mut self) -> Result<u64, PacemakerErrorV0> {
        if self.poisoned {
            return Err(PacemakerErrorV0::Poisoned);
        }
        let now = self.clock.now_millis();
        if self
            .last_observed_millis
            .is_some_and(|previous| now < previous)
        {
            self.poisoned = true;
            self.armed = None;
            self.pending_fire = None;
            return Err(PacemakerErrorV0::ClockRegressed);
        }
        self.last_observed_millis = Some(now);
        Ok(now)
    }

    pub fn arm(&mut self, arm: PacemakerArmV0) -> Result<PacemakerArmV0, PacemakerErrorV0> {
        let now = self.observe_now()?;
        let delay = arm
            .deadline_millis
            .checked_sub(now)
            .ok_or(PacemakerErrorV0::InvalidDeadline)?;
        if delay == 0 || delay > MAX_CANDIDATE_PACEMAKER_DELAY_MILLIS_V0 {
            return Err(PacemakerErrorV0::InvalidDeadline);
        }
        if self.pending_fire.is_some() {
            return Err(PacemakerErrorV0::PendingFire);
        }
        if self
            .last_acknowledged
            .is_some_and(|last| arm.identity <= last)
        {
            return Err(PacemakerErrorV0::StaleArm);
        }
        if let Some(current) = self.armed {
            if arm.identity == current.identity {
                return if arm == current {
                    Ok(current)
                } else {
                    Err(PacemakerErrorV0::ConflictingArm)
                };
            }
            if arm.identity < current.identity {
                return Err(PacemakerErrorV0::StaleArm);
            }
        }
        self.armed = Some(arm);
        Ok(arm)
    }

    pub fn poll(&mut self) -> Result<PacemakerPollV0, PacemakerErrorV0> {
        let now = self.observe_now()?;
        if let Some(fired) = self.pending_fire {
            return Ok(PacemakerPollV0::Fired(fired));
        }
        match self.armed {
            None => Ok(PacemakerPollV0::Idle),
            Some(armed) if now < armed.deadline_millis => {
                Ok(PacemakerPollV0::Armed(armed))
            }
            Some(armed) => {
                self.armed = None;
                self.pending_fire = Some(armed);
                Ok(PacemakerPollV0::Fired(armed))
            }
        }
    }

    pub fn acknowledge_fired(
        &mut self,
        identity: PacemakerIdentityV0,
    ) -> Result<(), PacemakerErrorV0> {
        if self.poisoned {
            return Err(PacemakerErrorV0::Poisoned);
        }
        let pending = self
            .pending_fire
            .ok_or(PacemakerErrorV0::UnexpectedAcknowledgement)?;
        if pending.identity != identity {
            return Err(PacemakerErrorV0::UnexpectedAcknowledgement);
        }
        self.pending_fire = None;
        self.last_acknowledged = Some(identity);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_default_surface_is_inert() {
        let runtime = NodeIoRuntimeV0::inert();
        for surface in REQUIRED_NODE_IO_SURFACES_V0 {
            assert!(!runtime.is_enabled(*surface));
        }
        assert_eq!(runtime.enabled_surface_count(), 0);
        assert!(!runtime.production_activation());
    }
}

#[cfg(all(test, feature = "candidate-pacemaker"))]
mod pacemaker_tests {
    use super::*;
    use std::cell::Cell;

    struct TestClock(Cell<u64>);

    impl TestClock {
        fn new(now: u64) -> Self {
            Self(Cell::new(now))
        }

        fn set(&self, now: u64) {
            self.0.set(now);
        }
    }

    impl MonotonicClockV0 for TestClock {
        fn now_millis(&self) -> u64 {
            self.0.get()
        }
    }

    fn identity(view: u64) -> PacemakerIdentityV0 {
        PacemakerIdentityV0::new(1, view, 1).unwrap()
    }

    fn arm(view: u64, deadline: u64) -> PacemakerArmV0 {
        PacemakerArmV0::new(identity(view), deadline).unwrap()
    }

    #[test]
    fn exact_arm_replay_is_idempotent_and_conflicts_fail_closed() {
        let mut pacemaker = CandidatePacemakerV0::new(TestClock::new(100));
        let first = arm(1, 120);
        assert_eq!(pacemaker.arm(first).unwrap(), first);
        assert_eq!(pacemaker.arm(first).unwrap(), first);
        assert_eq!(
            pacemaker.arm(arm(1, 121)),
            Err(PacemakerErrorV0::ConflictingArm)
        );
        assert_eq!(
            pacemaker.arm(arm(0, 119)),
            Err(PacemakerErrorV0::StaleArm)
        );
        assert_eq!(pacemaker.poll().unwrap(), PacemakerPollV0::Armed(first));
    }

    #[test]
    fn fired_effect_replays_until_exact_acknowledgement() {
        let mut pacemaker = CandidatePacemakerV0::new(TestClock::new(100));
        let first = arm(1, 120);
        pacemaker.arm(first).unwrap();
        pacemaker.clock().set(120);
        assert_eq!(pacemaker.poll().unwrap(), PacemakerPollV0::Fired(first));
        assert_eq!(pacemaker.poll().unwrap(), PacemakerPollV0::Fired(first));
        assert_eq!(
            pacemaker.arm(arm(2, 140)),
            Err(PacemakerErrorV0::PendingFire)
        );
        assert_eq!(
            pacemaker.acknowledge_fired(identity(2)),
            Err(PacemakerErrorV0::UnexpectedAcknowledgement)
        );
        pacemaker.acknowledge_fired(identity(1)).unwrap();
        assert_eq!(pacemaker.poll().unwrap(), PacemakerPollV0::Idle);
        assert_eq!(
            pacemaker.arm(arm(1, 130)),
            Err(PacemakerErrorV0::StaleArm)
        );
        assert_eq!(pacemaker.arm(arm(2, 140)).unwrap(), arm(2, 140));
    }

    #[test]
    fn invalid_deadlines_do_not_replace_the_current_arm() {
        let mut pacemaker = CandidatePacemakerV0::new(TestClock::new(100));
        let first = arm(1, 120);
        pacemaker.arm(first).unwrap();
        assert_eq!(
            pacemaker.arm(arm(2, 100)),
            Err(PacemakerErrorV0::InvalidDeadline)
        );
        assert_eq!(
            pacemaker.arm(arm(
                2,
                101 + MAX_CANDIDATE_PACEMAKER_DELAY_MILLIS_V0,
            )),
            Err(PacemakerErrorV0::InvalidDeadline)
        );
        assert_eq!(pacemaker.poll().unwrap(), PacemakerPollV0::Armed(first));
    }

    #[test]
    fn clock_regression_poisoning_is_sticky_and_clears_pending_authority() {
        let mut pacemaker = CandidatePacemakerV0::new(TestClock::new(100));
        pacemaker.arm(arm(1, 120)).unwrap();
        pacemaker.clock().set(110);
        assert!(matches!(pacemaker.poll(), Ok(PacemakerPollV0::Armed(_))));
        pacemaker.clock().set(109);
        assert_eq!(pacemaker.poll(), Err(PacemakerErrorV0::ClockRegressed));
        assert!(pacemaker.is_poisoned());
        assert_eq!(pacemaker.pending_fire(), None);
        assert_eq!(pacemaker.poll(), Err(PacemakerErrorV0::Poisoned));
        assert_eq!(
            pacemaker.acknowledge_fired(identity(1)),
            Err(PacemakerErrorV0::Poisoned)
        );
    }
}
