//! Generation-aware bounded pacemaker for the G3 LAN runtime.
//!
//! The pacemaker owns only process-local scheduling state.  It never advances
//! PoCO Core by itself: an expiry produces one exact `(epoch, view,
//! generation)` observation that the authority owner must validate before it
//! may construct a Timeout statement.  Re-arm, restart, QC/TC progress and
//! cancellation invalidate all older generations.

use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use trnm_consensus_types::{Epoch, View};

const MAX_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_GENERATION: u64 = u64::MAX - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacemakerGenerationV0(u64);

impl PacemakerGenerationV0 {
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacemakerExpiryV0 {
    epoch: Epoch,
    view: View,
    generation: PacemakerGenerationV0,
}

impl PacemakerExpiryV0 {
    pub const fn epoch(self) -> Epoch {
        self.epoch
    }

    pub const fn view(self) -> View {
        self.view
    }

    pub const fn generation(self) -> PacemakerGenerationV0 {
        self.generation
    }
}

#[derive(Debug, Clone, Copy)]
struct ArmedTimeoutV0 {
    epoch: Epoch,
    view: View,
    generation: PacemakerGenerationV0,
    deadline: Instant,
    emitted: bool,
}

/// Bounded 3/2 exponential-backoff pacemaker.
pub struct GenerationAwarePacemakerV0 {
    base_timeout: Duration,
    maximum_timeout: Duration,
    next_generation: u64,
    consecutive_timeouts: u32,
    armed: Option<ArmedTimeoutV0>,
}

impl GenerationAwarePacemakerV0 {
    pub fn new(base_timeout: Duration, maximum_timeout: Duration) -> Result<Self> {
        if base_timeout < Duration::from_millis(100)
            || base_timeout > MAX_TIMEOUT
            || maximum_timeout < base_timeout
            || maximum_timeout > MAX_TIMEOUT
        {
            bail!("pacemaker timeout bounds are invalid");
        }
        Ok(Self {
            base_timeout,
            maximum_timeout,
            next_generation: 1,
            consecutive_timeouts: 0,
            armed: None,
        })
    }

    pub fn arm(&mut self, epoch: Epoch, view: View, now: Instant) -> Result<PacemakerGenerationV0> {
        let timeout = scaled_timeout(
            self.base_timeout,
            self.maximum_timeout,
            self.consecutive_timeouts,
        )?;
        let generation = PacemakerGenerationV0(self.next_generation);
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .filter(|value| *value <= MAX_GENERATION)
            .ok_or_else(|| anyhow!("pacemaker generation exhausted"))?;
        let deadline = now
            .checked_add(timeout)
            .ok_or_else(|| anyhow!("pacemaker deadline overflow"))?;
        self.armed = Some(ArmedTimeoutV0 {
            epoch,
            view,
            generation,
            deadline,
            emitted: false,
        });
        Ok(generation)
    }

    /// Arms the current `(epoch, view)` only when no generation is active.
    ///
    /// This is deliberately different from [`Self::observe_progress`] followed
    /// by [`Self::arm`]: a phase-only certificate transition can restore a
    /// Ready owner without changing any authoritative Core fact.  In that
    /// case the old timeout has already been consumed, so liveness needs a
    /// fresh timer, but the bounded exponential backoff must remain intact.
    /// Calling this while a generation is active is an idempotent no-op, which
    /// also prevents duplicate stale certificates from moving its deadline.
    pub fn arm_if_unarmed(
        &mut self,
        epoch: Epoch,
        view: View,
        now: Instant,
    ) -> Result<Option<PacemakerGenerationV0>> {
        if self.armed.is_some() {
            return Ok(None);
        }
        self.arm(epoch, view, now).map(Some)
    }

    /// Returns an expiry at most once for the active generation.
    pub fn poll(&mut self, now: Instant) -> Option<PacemakerExpiryV0> {
        let armed = self.armed.as_mut()?;
        if armed.emitted || now < armed.deadline {
            return None;
        }
        armed.emitted = true;
        Some(PacemakerExpiryV0 {
            epoch: armed.epoch,
            view: armed.view,
            generation: armed.generation,
        })
    }

    /// Confirms that an effect still belongs to the active generation.
    pub fn validate_generation(
        &self,
        epoch: Epoch,
        view: View,
        generation: PacemakerGenerationV0,
    ) -> bool {
        self.armed.is_some_and(|armed| {
            armed.epoch == epoch && armed.view == view && armed.generation == generation
        })
    }

    /// Records a locally emitted timeout and increases bounded backoff.  The
    /// exact generation must still be active and already expired.
    pub fn confirm_timeout_emitted(&mut self, expiry: PacemakerExpiryV0) -> Result<()> {
        let active = self
            .armed
            .ok_or_else(|| anyhow!("pacemaker has no active generation"))?;
        if !active.emitted
            || active.epoch != expiry.epoch
            || active.view != expiry.view
            || active.generation != expiry.generation
        {
            bail!("timeout effect belongs to a stale pacemaker generation");
        }
        self.consecutive_timeouts = self
            .consecutive_timeouts
            .checked_add(1)
            .ok_or_else(|| anyhow!("pacemaker timeout counter overflow"))?;
        self.armed = None;
        Ok(())
    }

    /// QC/TC/finality progress invalidates the current timer and resets
    /// exponential backoff.  Any queued expiry from the old generation is
    /// rejected by `validate_generation`.
    pub fn observe_progress(&mut self) {
        self.armed = None;
        self.consecutive_timeouts = 0;
    }

    pub fn cancel(&mut self) {
        self.armed = None;
    }

    pub const fn consecutive_timeouts(&self) -> u32 {
        self.consecutive_timeouts
    }
}

fn scaled_timeout(base: Duration, maximum: Duration, consecutive: u32) -> Result<Duration> {
    let mut nanos = base.as_nanos();
    let maximum_nanos = maximum.as_nanos();
    for _ in 0..consecutive.min(128) {
        nanos = nanos
            .checked_mul(3)
            .ok_or_else(|| anyhow!("pacemaker timeout multiplication overflow"))?
            .checked_add(1)
            .ok_or_else(|| anyhow!("pacemaker timeout rounding overflow"))?
            / 2;
        if nanos >= maximum_nanos {
            nanos = maximum_nanos;
            break;
        }
    }
    nanos = nanos.min(maximum_nanos);
    let seconds = nanos / 1_000_000_000;
    let subsecond = nanos % 1_000_000_000;
    Ok(Duration::new(
        u64::try_from(seconds).map_err(|_| anyhow!("pacemaker seconds overflow"))?,
        u32::try_from(subsecond).map_err(|_| anyhow!("pacemaker nanos overflow"))?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_generation_is_rejected_and_expiry_is_single_shot() {
        let now = Instant::now();
        let mut pacemaker =
            GenerationAwarePacemakerV0::new(Duration::from_millis(100), Duration::from_secs(1))
                .unwrap();
        let first = pacemaker.arm(Epoch::new(0), View::new(1), now).unwrap();
        let second = pacemaker.arm(Epoch::new(0), View::new(2), now).unwrap();
        assert!(!pacemaker.validate_generation(Epoch::new(0), View::new(1), first));
        assert!(pacemaker.validate_generation(Epoch::new(0), View::new(2), second));
        assert!(pacemaker.poll(now + Duration::from_millis(99)).is_none());
        let expiry = pacemaker.poll(now + Duration::from_millis(100)).unwrap();
        assert_eq!(expiry.generation(), second);
        assert!(pacemaker.poll(now + Duration::from_secs(1)).is_none());
        pacemaker.confirm_timeout_emitted(expiry).unwrap();
        assert_eq!(pacemaker.consecutive_timeouts(), 1);
    }

    #[test]
    fn backoff_is_bounded_and_progress_resets_it() {
        let now = Instant::now();
        let mut pacemaker =
            GenerationAwarePacemakerV0::new(Duration::from_millis(100), Duration::from_millis(225))
                .unwrap();
        for view in 1..=4 {
            pacemaker.arm(Epoch::new(0), View::new(view), now).unwrap();
            let expiry = pacemaker.poll(now + Duration::from_secs(1)).unwrap();
            pacemaker.confirm_timeout_emitted(expiry).unwrap();
        }
        assert_eq!(pacemaker.consecutive_timeouts(), 4);
        pacemaker.observe_progress();
        assert_eq!(pacemaker.consecutive_timeouts(), 0);
        assert!(pacemaker.poll(now + Duration::from_secs(2)).is_none());
    }

    #[test]
    fn arm_if_unarmed_preserves_backoff_and_is_idempotent_when_armed() {
        let now = Instant::now();
        let mut pacemaker =
            GenerationAwarePacemakerV0::new(Duration::from_millis(100), Duration::from_secs(1))
                .unwrap();

        let first = pacemaker
            .arm(Epoch::new(0), View::new(1), now)
            .expect("initial generation");
        assert_eq!(
            pacemaker
                .arm_if_unarmed(Epoch::new(0), View::new(1), now + Duration::from_millis(50))
                .unwrap(),
            None,
            "an active generation must not be moved by a duplicate certificate"
        );
        let expiry = pacemaker
            .poll(now + Duration::from_millis(100))
            .expect("the active generation is a single-shot expiry");
        assert_eq!(expiry.generation(), first);
        pacemaker
            .confirm_timeout_emitted(expiry)
            .expect("confirm initial timeout");
        assert_eq!(pacemaker.consecutive_timeouts(), 1);

        let rearmed = pacemaker
            .arm_if_unarmed(Epoch::new(0), View::new(1), now)
            .unwrap()
            .expect("phase-only transition must restore a timer");
        assert_ne!(rearmed, first);
        assert!(
            pacemaker.poll(now + Duration::from_millis(149)).is_none(),
            "the second generation must retain the one-timeout backoff"
        );
        assert_eq!(
            pacemaker
                .poll(now + Duration::from_millis(150))
                .expect("backoff uses the second-generation deadline")
                .generation(),
            rearmed,
            "the timer should expire after the 3/2 backoff, not immediately"
        );
        assert_eq!(pacemaker.consecutive_timeouts(), 1);
    }
}
