#![cfg(feature = "candidate-pacemaker")]

use std::cell::Cell;

use trnm_poco_node_io::{
    CandidatePacemakerV0, MonotonicClockV0, PacemakerArmV0, PacemakerErrorV0, PacemakerIdentityV0,
    PacemakerPollV0,
};

struct Clock(Cell<u64>);

impl MonotonicClockV0 for Clock {
    fn now_millis(&self) -> u64 {
        self.0.get()
    }
}

fn arm(view: u64, deadline: u64) -> PacemakerArmV0 {
    PacemakerArmV0::new(PacemakerIdentityV0::new(0, view, 1).unwrap(), deadline).unwrap()
}

fn timer() -> CandidatePacemakerV0<Clock> {
    CandidatePacemakerV0::new(Clock(Cell::new(100)))
}

fn fire_and_ack(timer: &mut CandidatePacemakerV0<Clock>, request: PacemakerArmV0) {
    timer.arm(request).unwrap();
    timer.clock().0.set(request.deadline_millis());
    assert_eq!(timer.poll().unwrap(), PacemakerPollV0::Fired(request));
    timer.acknowledge_fired(request.identity()).unwrap();
}

#[test]
fn lost_arm_reply_retries_at_and_after_the_original_deadline() {
    for now in [120, 121, u64::MAX] {
        let mut timer = timer();
        let first = arm(1, 120);
        timer.arm(first).unwrap();
        timer.clock().0.set(now);
        assert_eq!(timer.arm(first), Ok(first));
        assert_eq!(timer.poll().unwrap(), PacemakerPollV0::Fired(first));
        assert_eq!(timer.poll().unwrap(), PacemakerPollV0::Fired(first));
    }
}

#[test]
fn late_conflicting_retry_does_not_replace_the_original_deadline() {
    let mut timer = timer();
    let first = arm(1, 120);
    timer.arm(first).unwrap();
    timer.clock().0.set(121);
    for deadline in [119, 121, 140] {
        assert_eq!(
            timer.arm(arm(1, deadline)),
            Err(PacemakerErrorV0::ConflictingArm)
        );
    }
    assert_eq!(timer.poll().unwrap(), PacemakerPollV0::Fired(first));
}

#[test]
fn expired_new_arm_is_still_rejected() {
    let mut timer = timer();
    let first = arm(1, 120);
    timer.arm(first).unwrap();
    timer.clock().0.set(121);
    assert_eq!(timer.arm(arm(2, 120)), Err(PacemakerErrorV0::InvalidDeadline));
    assert_eq!(timer.poll().unwrap(), PacemakerPollV0::Fired(first));
}

#[test]
fn pending_fire_cannot_be_bypassed_by_replaying_an_arm() {
    let mut timer = timer();
    let first = arm(1, 120);
    timer.arm(first).unwrap();
    timer.clock().0.set(120);
    assert_eq!(timer.poll().unwrap(), PacemakerPollV0::Fired(first));
    assert_eq!(timer.arm(first), Err(PacemakerErrorV0::PendingFire));
    assert_eq!(timer.pending_fire(), Some(first));
}

#[test]
fn lost_ack_reply_is_idempotent_while_idle_or_new_arm_exists() {
    let mut timer = timer();
    let first = arm(1, 120);
    fire_and_ack(&mut timer, first);
    assert_eq!(timer.acknowledge_fired(first.identity()), Ok(()));
    assert_eq!(timer.poll().unwrap(), PacemakerPollV0::Idle);
    let next = arm(2, 140);
    timer.arm(next).unwrap();
    assert_eq!(timer.acknowledge_fired(first.identity()), Ok(()));
    assert_eq!(timer.poll().unwrap(), PacemakerPollV0::Armed(next));
    assert_eq!(timer.last_acknowledged(), Some(first.identity()));
}

#[test]
fn old_ack_retry_cannot_consume_a_new_pending_fire() {
    let mut timer = timer();
    let first = arm(1, 120);
    fire_and_ack(&mut timer, first);
    let next = arm(2, 140);
    timer.arm(next).unwrap();
    timer.clock().0.set(140);
    assert_eq!(timer.poll().unwrap(), PacemakerPollV0::Fired(next));
    assert_eq!(timer.acknowledge_fired(first.identity()), Ok(()));
    assert_eq!(timer.pending_fire(), Some(next));
    assert_eq!(timer.poll().unwrap(), PacemakerPollV0::Fired(next));
    timer.acknowledge_fired(next.identity()).unwrap();
    assert_eq!(
        timer.acknowledge_fired(first.identity()),
        Err(PacemakerErrorV0::UnexpectedAcknowledgement)
    );
    assert_eq!(timer.last_acknowledged(), Some(next.identity()));
}

#[test]
fn future_ack_is_not_a_retry_and_cannot_consume_a_pending_fire() {
    let mut timer = timer();
    let first = arm(1, 120);
    timer.arm(first).unwrap();
    timer.clock().0.set(120);
    timer.poll().unwrap();
    assert_eq!(
        timer.acknowledge_fired(arm(2, 140).identity()),
        Err(PacemakerErrorV0::UnexpectedAcknowledgement)
    );
    assert_eq!(timer.pending_fire(), Some(first));
    assert_eq!(timer.last_acknowledged(), None);
}

#[test]
fn exact_retries_never_bypass_sticky_clock_regression() {
    let mut timer = timer();
    let first = arm(1, 120);
    fire_and_ack(&mut timer, first);
    let next = arm(2, 140);
    timer.arm(next).unwrap();
    timer.clock().0.set(119);
    assert_eq!(timer.arm(next), Err(PacemakerErrorV0::ClockRegressed));
    assert_eq!(
        timer.acknowledge_fired(first.identity()),
        Err(PacemakerErrorV0::Poisoned)
    );
    assert_eq!(timer.poll(), Err(PacemakerErrorV0::Poisoned));
}
