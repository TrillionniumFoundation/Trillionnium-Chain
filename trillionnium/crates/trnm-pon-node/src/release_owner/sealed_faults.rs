//! Test-only deterministic source mutation, never a production callback.
use std::cell::RefCell;
thread_local! { static AFTER_COPY: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None); }
pub(super) fn set(callback: impl FnOnce() + 'static) {
    AFTER_COPY.with(|slot| {
        assert!(slot.borrow().is_none());
        *slot.borrow_mut() = Some(Box::new(callback));
    });
}
pub(super) fn after_copy() {
    let callback = AFTER_COPY.with(|slot| slot.borrow_mut().take());
    if let Some(callback) = callback {
        callback();
    }
}
