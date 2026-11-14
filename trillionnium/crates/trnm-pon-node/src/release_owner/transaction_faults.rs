//! Test-only faults occur after real file and parent-directory sync/readback.
use super::frontier::Result;
use std::cell::RefCell;
use std::io;

type AfterWrite = (&'static str, Box<dyn FnOnce()>);

thread_local! {
    static CUT: RefCell<Option<(&'static str, bool)>> = const { RefCell::new(None) };
    static AFTER_WRITE: RefCell<Option<AfterWrite>> = const { RefCell::new(None) };
}

pub(super) fn after_write_once(name: &'static str, action: impl FnOnce() + 'static) {
    AFTER_WRITE.with(|pending| *pending.borrow_mut() = Some((name, Box::new(action))));
}

pub(super) fn cut_once(name: &'static str, tombstone: bool) {
    CUT.with(|cut| *cut.borrow_mut() = Some((name, tombstone)));
}

pub(super) fn after_synced_write(name: &str, bytes: &[u8]) -> Result<()> {
    let action = AFTER_WRITE.with(|pending| {
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
    let matched = CUT.with(|cut| {
        let mut pending = cut.borrow_mut();
        if pending
            .as_ref()
            .is_some_and(|(wanted, null)| *wanted == name && *null == (bytes == b"null"))
        {
            pending.take();
            true
        } else {
            false
        }
    });
    if matched {
        return Err(io::Error::other(
            "qualification cut after actual durable write",
        ));
    }
    Ok(())
}
