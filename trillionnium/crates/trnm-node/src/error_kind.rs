pub(crate) fn classify_apply_error(err: &anyhow::Error) -> &'static str {
    if let Some(pouw) = err.downcast_ref::<trnm_pouw::PouwError>() {
        return match pouw {
            trnm_pouw::PouwError::VersionConflict => "version_conflict",
            trnm_pouw::PouwError::InvalidTransition => "invalid_transition",
            trnm_pouw::PouwError::DeadlineExceeded => "deadline_exceeded",
            trnm_pouw::PouwError::ResolveApprovalStaged => "resolve_approval_staged",
            _ => "semantic_fail",
        };
    }

    let e = err.to_string().to_ascii_lowercase();
    if e.contains("version conflict") {
        "version_conflict"
    } else if e.contains("invalid transition") {
        "invalid_transition"
    } else if e.contains("deadline exceeded") {
        "deadline_exceeded"
    } else if e.contains("preexec") {
        "preexec_conflict_miss"
    } else {
        "semantic_fail"
    }
}
