//! Explicit cfg(test) provisioning/fault hooks; absent from all product builds.
use super::frontier::Result;
use std::cell::{Cell, RefCell};
use std::path::PathBuf;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Point {
    Clock,
    Prepared,
    Admitted,
    Published,
}
type Action = Box<dyn FnOnce() -> Result<()>>;
thread_local! {
    static PROVISIONING: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
    static FAULT: RefCell<Option<(Point, Action)>> = const { RefCell::new(None) };
    static ADMISSIONS: Cell<usize> = const { Cell::new(0) };
}
pub(super) fn provisioning() -> Option<PathBuf> {
    PROVISIONING.with(|v| v.borrow().clone())
}
pub(super) fn with_provisioning<T>(path: PathBuf, run: impl FnOnce() -> T) -> T {
    assert!(PROVISIONING
        .with(|v| v.borrow_mut().replace(path))
        .is_none());
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            PROVISIONING.with(|v| v.borrow_mut().take());
            FAULT.with(|v| v.borrow_mut().take());
            ADMISSIONS.with(|v| v.set(0));
        }
    }
    let _reset = Reset;
    run()
}
pub(super) fn once(point: Point, action: impl FnOnce() -> Result<()> + 'static) {
    assert!(FAULT
        .with(|v| v.borrow_mut().replace((point, Box::new(action))))
        .is_none());
}
pub(super) fn hit(point: Point) -> Result<()> {
    let action = FAULT.with(|value| {
        let mut slot = value.borrow_mut();
        if slot.as_ref().is_some_and(|(wanted, _)| *wanted == point) {
            slot.take().map(|(_, f)| f)
        } else {
            None
        }
    });
    if let Some(action) = action {
        action()?;
    }
    Ok(())
}
pub(super) fn admitted(cas: bool) -> Result<()> {
    if cas {
        ADMISSIONS.with(|v| v.set(v.get() + 1));
    }
    hit(Point::Admitted)
}
pub(super) fn admissions() -> usize {
    ADMISSIONS.with(Cell::get)
}
