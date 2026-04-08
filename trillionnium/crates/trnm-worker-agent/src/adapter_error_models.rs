#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdapterErrorKind {
    Retriable,
    NonRetriable,
}

#[derive(Debug, Clone)]
pub(crate) struct AdapterError {
    pub(crate) kind: AdapterErrorKind,
    pub(crate) context: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReputationSignal {
    Accepted,
    VerifierRejected,
    AdapterRetryExhausted,
    AdapterNonRetriable,
}
