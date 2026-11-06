//! One-shot test-only mutation after an actual bounded read from the held FD.
use std::cell::RefCell;

type AfterRead = (&'static str, Box<dyn FnOnce()>);

thread_local! {
    static AFTER_READ: RefCell<Option<AfterRead>> = const { RefCell::new(None) };
}

pub(super) fn once(name: &'static str, action: impl FnOnce() + 'static) {
    AFTER_READ.with(|pending| *pending.borrow_mut() = Some((name, Box::new(action))));
}

pub(super) fn after_read(name: &str) {
    let action = AFTER_READ.with(|pending| {
        let mut pending = pending.borrow_mut();
        if pending.as_ref().is_some_and(|(wanted, _)| *wanted == name) {
            pending.take().map(|(_, action)| action)
        } else {
            None
        }
    });
    if let Some(action) = action {
        action();
    }
}
