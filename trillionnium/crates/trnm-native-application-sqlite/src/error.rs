use core::fmt;

pub type ValidationStoreResultV0<T> = Result<T, ValidationStoreErrorV0>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationStoreErrorCodeV0 {
    Empty,
    ZeroValue,
    InvalidBinding,
    Duplicate,
    NotFound,
    ForeignToken,
    InvalidTransition,
    BindingMismatch,
    CommitUncertain,
    RollbackDetected,
    ReplacedStore,
    InvalidPermissions,
    CorruptStore,
    Storage,
    Overflow,
    UnsupportedPlatform,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationStoreErrorV0 {
    code: ValidationStoreErrorCodeV0,
    context: &'static str,
}

impl ValidationStoreErrorV0 {
    pub const fn new(code: ValidationStoreErrorCodeV0, context: &'static str) -> Self {
        Self { code, context }
    }

    pub const fn code(&self) -> ValidationStoreErrorCodeV0 {
        self.code
    }

    pub const fn context(&self) -> &'static str {
        self.context
    }
}

impl fmt::Display for ValidationStoreErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.context)
    }
}

impl std::error::Error for ValidationStoreErrorV0 {}

pub(crate) const fn error(
    code: ValidationStoreErrorCodeV0,
    context: &'static str,
) -> ValidationStoreErrorV0 {
    ValidationStoreErrorV0::new(code, context)
}
