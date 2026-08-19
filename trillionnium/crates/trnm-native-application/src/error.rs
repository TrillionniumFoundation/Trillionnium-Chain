use core::fmt;

/// Stable error classes for malformed boundary values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeBoundaryErrorCodeV0 {
    Empty,
    TooLong,
    TooMany,
    NotCanonical,
    ZeroValue,
    Duplicate,
    Overflow,
    NonContiguous,
    BindingMismatch,
    InvalidTransition,
}

/// A fail-closed validation error with a stable field label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeBoundaryErrorV0 {
    code: NativeBoundaryErrorCodeV0,
    field: &'static str,
}

impl NativeBoundaryErrorV0 {
    pub const fn new(code: NativeBoundaryErrorCodeV0, field: &'static str) -> Self {
        Self { code, field }
    }

    pub const fn code(self) -> NativeBoundaryErrorCodeV0 {
        self.code
    }

    pub const fn field(self) -> &'static str {
        self.field
    }
}

impl fmt::Display for NativeBoundaryErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid native application field {}: {:?}",
            self.field, self.code
        )
    }
}

impl std::error::Error for NativeBoundaryErrorV0 {}

pub type NativeBoundaryResultV0<T> = Result<T, NativeBoundaryErrorV0>;

pub(crate) const fn error(
    code: NativeBoundaryErrorCodeV0,
    field: &'static str,
) -> NativeBoundaryErrorV0 {
    NativeBoundaryErrorV0::new(code, field)
}
