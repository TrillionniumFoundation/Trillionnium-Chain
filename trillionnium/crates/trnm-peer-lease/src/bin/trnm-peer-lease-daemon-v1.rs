// Keep a versioned executable name for deployment scripts.  The implementation
// and argument contract are shared with the unversioned binary so they cannot
// drift into different authority semantics.
include!("trnm-peer-lease-daemon.rs");
