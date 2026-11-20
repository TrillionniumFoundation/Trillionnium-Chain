// Appended only as a private cfg(test) child of the complete original public_v3.
// No production function body is changed or copied into this bridge.
pub(crate) fn alive(
    deadline: std::time::Instant,
    stop: &std::sync::atomic::AtomicBool,
    cancelled: &std::sync::atomic::AtomicBool,
) -> crate::Result<()> {
    super::task_alive(deadline, stop, cancelled)
}

pub(crate) fn finish<T>(
    native: crate::Result<T>,
    deadline: std::time::Instant,
    resource: impl FnOnce() -> crate::Result<()>,
) -> crate::Result<T> {
    super::super::history_import::finish_with_resource(native, deadline, resource)
}
