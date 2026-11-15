//! Actual ordinary Submit/W1/M06 boundaries for retained future ancestry.
//! These finite native controls do not establish public service or work-cost bounds.
use super::*;
use std::sync::atomic::AtomicUsize;
use trnm_mvcc_fee::pon_executor::{ExecutionControl, ExecutionProgress};

struct Fixture {
    _directory: tempfile::TempDir,
    owner: Mutex<Node>,
    settings: Settings,
    packet: Packet,
    clock: u64,
    future: u64,
}

fn retained_branch(authenticated: bool, future_ancestor: bool) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let clock = now().unwrap();
    let settings = Settings::development(Some(clock - 100)).unwrap();
    let future = clock + settings.limit("future_skew_seconds").unwrap() + 3600;
    let mut node = if authenticated {
        Node::open_with_authenticated_state(directory.path(), settings.clone(), 2).unwrap()
    } else {
        Node::open(directory.path(), settings.clone(), 2).unwrap()
    };
    let mut parent = settings.genesis();
    // The ordinary MTP rule permits nonmonotone timestamps. These retained
    // blocks were valid under the explicitly supplied, later observation clock.
    for timestamp in [
        clock - 90,
        clock - 80,
        if future_ancestor { future } else { clock - 50 },
        clock - 70,
        clock - 60,
    ] {
        let packet = node
            .make(
                parent,
                vec![],
                crate::development_public(3).unwrap(),
                timestamp,
                4096,
            )
            .unwrap();
        parent = node.admit(&packet, future).unwrap();
    }
    let packet = node
        .make(
            parent,
            vec![],
            crate::development_public(4).unwrap(),
            clock - 40,
            4096,
        )
        .unwrap();
    assert!(node
        .check_admission_context(&packet, clock)
        .unwrap()
        .is_none());
    Fixture {
        _directory: directory,
        owner: Mutex::new(node),
        settings,
        packet,
        clock,
        future,
    }
}

fn observed_submit(
    fixture: &Fixture,
    packet: &Packet,
    public_order: bool,
    work_calls: &AtomicUsize,
    m06_calls: &AtomicUsize,
) -> Result<Value> {
    let execution_progress = |point| {
        if point == ExecutionProgress::BeforeStateClone {
            m06_calls.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    };
    dispatch_shared_with_execution_observation(
        &fixture.owner,
        Request::Submit {
            packet: hex::encode(packet.encode().unwrap()),
        },
        &mut |_| Ok(()),
        |packet| {
            work_calls.fetch_add(1, Ordering::SeqCst);
            WorkCheckedPacket::verify(packet)
        },
        &ExecutionControl::new(&execution_progress, &()),
        SubmitDispatchContext {
            packet_settings: Some(&fixture.settings),
            public_proof_before_unowned_task: public_order,
            ..SubmitDispatchContext::default()
        },
    )
}

#[test]
fn submit_future_ancestor_is_checked_after_full_work_before_m06() {
    for authenticated in [false, true] {
        for public_order in [false, true] {
            let fixture = retained_branch(authenticated, true);
            let id = fixture.packet.id().unwrap();
            let before = fixture.owner.lock().unwrap().stats().unwrap();
            assert_eq!(
                fixture
                    .owner
                    .lock()
                    .unwrap()
                    .check_observed_history(fixture.packet.header.parent, fixture.clock)
                    .unwrap_err()
                    .to_string(),
                "TIME_DEFERRED"
            );
            let work_calls = AtomicUsize::new(0);
            let m06_calls = AtomicUsize::new(0);
            let error = observed_submit(
                &fixture,
                &fixture.packet,
                public_order,
                &work_calls,
                &m06_calls,
            )
            .unwrap_err();
            assert_eq!(error.to_string(), "TIME_DEFERRED");
            assert_eq!(
                work_calls.load(Ordering::SeqCst),
                1,
                "ordinary Submit must pay complete W1 before its ancestry scan"
            );
            let owner = fixture.owner.lock().unwrap();
            let candidate_durable = owner.parent_height(id).is_ok();
            assert_eq!(
                m06_calls.load(Ordering::SeqCst),
                0,
                "a currently ineligible ancestor must stop before M06; candidate_durable={candidate_durable}"
            );
            assert!(!candidate_durable);
            assert_eq!(owner.stats().unwrap(), before);
            // Failure releases the original detached slot, not a replacement
            // owner or account. A later explicit operation may acquire it.
            assert!(owner.reserve_detached_execution().is_ok());
        }
    }
}
