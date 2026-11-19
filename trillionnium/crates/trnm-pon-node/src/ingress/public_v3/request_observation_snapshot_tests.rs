//! A live reader must not retain the reactor row while waiting on other owners.
//! These deterministic controls run the actual original update/snapshot path.
use super::*;
use std::cell::RefCell;
use std::sync::mpsc::sync_channel;
use std::time::Duration;

thread_local! {
    static AFTER_ROW_COPY: RefCell<Option<Box<dyn FnMut()>>> = const { RefCell::new(None) };
}

pub(super) fn after_row_copy() {
    AFTER_ROW_COPY.with(|hook| {
        if let Some(run) = hook.borrow_mut().as_mut() {
            run();
        }
    });
}

fn snapshot_copy_releases_reactor_row(hold_phase: bool, close_before_snapshot: bool) {
    let observer = PublicRequestObserver::new(1).unwrap();
    let connection = observer.connection().unwrap();
    connection.identity(393);
    let cell = Arc::clone(&connection.cell);
    let task_guard = (!hold_phase).then(|| cell.task.lock().unwrap());
    let phase_guard = hold_phase.then(|| cell.phases.0.rows.lock().unwrap());
    let (copied_tx, copied_rx) = sync_channel(1);
    let reader = observer.clone();
    let snapshot_thread = thread::spawn(move || {
        AFTER_ROW_COPY.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || copied_tx.send(()).unwrap()));
        });
        let result = reader.snapshot();
        AFTER_ROW_COPY.with(|hook| {
            hook.borrow_mut().take();
        });
        result
    });
    // The real snapshot has copied this row. It cannot finish the subsequent
    // task/phase snapshot while this original owner still holds that mutex.
    copied_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(!snapshot_thread.is_finished());
    connection.frame(4, 7, 0, false);
    let connection = if close_before_snapshot {
        drop(connection);
        None
    } else {
        Some(connection)
    };
    drop(task_guard);
    drop(phase_guard);
    let live = snapshot_thread.join().unwrap();
    assert!(
        !live.coverage_complete(),
        "a live request remains incomplete"
    );
    drop(connection);
    let complete = observer.snapshot();
    println!(
        "snapshot_copy hold_phase={hold_phase} read_bytes={} failures={} complete={}",
        complete.records[0].frames[4].bytes_read,
        complete.measurement_failures,
        complete.coverage_complete()
    );
    assert_eq!(complete.records[0].connection_id, Some(393));
    assert_eq!(complete.records[0].frames[4].bytes_read, 7);
    assert_eq!(complete.measurement_failures, 0);
    assert!(complete.coverage_complete());
}

#[test]
fn snapshot_copy_releases_row_before_task_snapshot() {
    snapshot_copy_releases_reactor_row(false, false);
}

#[test]
fn snapshot_copy_releases_row_before_phase_snapshot() {
    snapshot_copy_releases_reactor_row(true, false);
}

#[test]
fn closure_after_row_copy_stays_incomplete_until_next_snapshot() {
    snapshot_copy_releases_reactor_row(false, true);
}
